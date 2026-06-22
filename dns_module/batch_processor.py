# dns_module/batch_processor.py
from __future__ import annotations
import asyncio
import json
import time
import os
import re
from pathlib import Path
import polars as pl
import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.flight as flight

from datetime import datetime
from typing import Iterable, List, Tuple, Dict, Any, Optional

# Import DNSRecord from dns_records and fetch_batch from dns_fetcher
from .entity_hasher import hash_domain, hash_ip
from .dns_records import DNSRecord
from .dns_fetcher import fetch_batch, DEFAULT_BATCH_WORKERS
from .dns_utils import ip_to_int
from kv.lmdb_store import LMDBActivity
from .change_tracker import annotate_change_flags_arrow, write_activity_delta_csv

from .logger import get_child_logger
log = get_child_logger("batch_processor")



# Default configuration
DEFAULT_WORKERS = DEFAULT_BATCH_WORKERS
def _normalize_ns_value(ns_in: Any) -> str:
    """Normalize NS hosts to a '|' joined lowercase string without trailing dots.
    Accepts list or string; splits on common separators and deduplicates while preserving order.
    """
    tokens: List[str] = []
    try:
        if isinstance(ns_in, list):
            raw = [str(x) for x in ns_in if x]
        elif isinstance(ns_in, str):
            # split on pipe, comma, whitespace
            raw = []
            for part in ns_in.replace("\n", " ").split("|"):
                for sub in part.split(","):
                    for w in sub.split():
                        raw.append(w)
        else:
            raw = []
        # normalize
        seen = set()
        for r in raw:
            s = r.strip().rstrip('.').lower()
            if s and s not in seen:
                seen.add(s)
                tokens.append(s)
    except Exception:
        tokens = []
    return "|".join(tokens)

def _normalize_ns_list(ns_in: Any) -> List[str]:
    """Return a normalized list of NS hosts: lowercase, no trailing dots, deduped."""
    try:
        if isinstance(ns_in, list):
            raw = [str(x) for x in ns_in if x]
        elif isinstance(ns_in, str):
            raw = []
            for part in ns_in.replace("\n", " ").split("|"):
                for sub in part.split(","):
                    for w in sub.split():
                        raw.append(w)
        else:
            raw = []
        seen = set()
        out: List[str] = []
        for r in raw:
            s = r.strip().rstrip('.').lower()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
        return out
    except Exception:
        return []


DEFAULT_SEMAPHORE_LIMIT = 800
NFS_BASE = Path(os.getenv("NFS_BASE", "/mnt/shared/"))
#SCORE_CONFIG = NFS_BASE / "config" / "score_config.yaml"

def _load_brand_ns_catalog(db_path: str | Path) -> Optional[pa.Table]:
    """Load brand NS catalog from DuckDB."""
    try:
        import duckdb
        # Use read_only=True to allow multiple readers
        with duckdb.connect(str(db_path), read_only=True) as con:
            return con.execute("SELECT * FROM brand_ns_catalog").arrow()
    except Exception:
        return None

def _load_brand_mx_catalog(db_path: str | Path) -> Optional[pa.Table]:
    """Load brand MX catalog from DuckDB."""
    try:
        import duckdb
        with duckdb.connect(str(db_path), read_only=True) as con:
            return con.execute("SELECT * FROM brand_mx_catalog").arrow()
    except Exception:
        return None

def _load_brand_cname_catalog(db_path: str | Path) -> Optional[pa.Table]:
    """Load brand CNAME catalog from DuckDB."""
    try:
        import duckdb
        with duckdb.connect(str(db_path), read_only=True) as con:
            return con.execute("SELECT * FROM brand_cname_catalog").arrow()
    except Exception:
        return None

def _load_brand_ip_ranges_catalog(db_path: str | Path) -> Optional[pa.Table]:
    """Load brand IP ranges catalog from DuckDB."""
    try:
        import duckdb
        with duckdb.connect(str(db_path), read_only=True) as con:
            return con.execute("SELECT * FROM brand_ip_ranges_catalog").arrow()
    except Exception:
        return None
def _ensure_enricher_columns(table: pa.Table) -> pa.Table:
    """Ensure required columns for LabelEnricher exist with correct types.
    Adds missing columns with safe defaults and fixes Null-typed columns.
    Required: domain(str), registered_domain(str), mx_host_norm(str), mx_regdom_norm(str), ns(str), ip_int(int64).
    """
    try:
        cols = set(table.column_names)
        nrows = table.num_rows
        required = {
            "domain": pa.string(),
            "registered_domain": pa.string(),
            "mx_host_norm": pa.string(),
            "mx_regdom_norm": pa.string(),
            "ns": pa.string(),
            "ip_int": pa.int64(),
            "ns_ips": pa.string(),
            "ns_ip_int": pa.int64(),
        }
        for name, dtype in required.items():
            if name not in cols:
                if pa.types.is_string(dtype):
                    arr = pa.array([""] * nrows, type=pa.string())
                elif pa.types.is_int64(dtype):
                    arr = pa.nulls(nrows, type=pa.int64())
                else:
                    arr = pa.nulls(nrows, type=dtype)
                table = table.append_column(name, arr)
            else:
                # If column type is Null, replace with typed nulls/empty strings
                try:
                    idx = table.schema.get_field_index(name)
                    col = table.column(name)
                    if str(col.type) == "null":
                        if name == "ip_int" or name == "ns_ip_int":
                            new_arr = pa.nulls(nrows, type=pa.int64())
                        elif name == "domain" or name == "registered_domain" or name == "mx_host_norm" or name == "mx_regdom_norm" or name == "ns" or name == "ns_ips":
                            new_arr = pa.array([""] * nrows, type=pa.string())
                        else:
                            new_arr = pa.nulls(nrows, type=dtype)
                        table = table.set_column(idx, name, new_arr)
                except Exception:
                    pass
        return table
    except Exception:
        return table



def _safe_serialize(obj):
    """
    Safely serialize objects to JSON-compatible primitives.
    Handles nested dicts, lists, and unknown types.
    """
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, dict):
        return {str(k): _safe_serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_safe_serialize(v) for v in obj]
    # Fallback: convert to string
    return str(obj)


def _dnsrecord_to_row(rec: DNSRecord) -> Dict[str, Any]:
    """
    Convert DNSRecord to pyarrow-safe row with JSON-encoded nested dicts.
    
    Args:
        rec: DNSRecord instance to convert.
    
    Returns:
        Dictionary with domain, status, and JSON-encoded fields.
    """
    try:
        records_json = json.dumps(
            rec.records,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str
        )
    except Exception:
        try:
            records_json = json.dumps(
                _safe_serialize(rec.records),
                ensure_ascii=False,
                separators=(",", ":")
            )
        except Exception:
            records_json = "{}"
    
    try:
        errors_json = json.dumps(
            rec.errors,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str
        )
    except Exception:
        try:
            errors_json = json.dumps(
                _safe_serialize(rec.errors),
                ensure_ascii=False,
                separators=(",", ":")
            )
        except Exception:
            errors_json = "{}"
    
    try:
        meta_json = json.dumps(
            rec.meta,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str
        )
    except Exception:
        try:
            meta_json = json.dumps(
                _safe_serialize(rec.meta),
                ensure_ascii=False,
                separators=(",", ":")
            )
        except Exception:
            meta_json = "{}"
    
    return {
        "domain": str(rec.domain),
        "status": str(rec.status),
        "records_json": records_json,
        "errors_json": errors_json,
        "meta_json": meta_json,
    }


def get_dns_schema():
    """Get PyArrow schema for DNS records table."""
    return pa.schema([
        pa.field("domain", pa.string()),
        pa.field("status", pa.string()),
        pa.field("records_json", pa.string()),
        pa.field("errors_json", pa.string()),
        pa.field("meta_json", pa.string()),
    ])

def get_graph_domain_schema():
    return pa.schema([
        pa.field("domain_id", pa.uint64()),
        pa.field("domain", pa.string()),
        pa.field("apex", pa.string()),
        pa.field("tld", pa.string()),
        pa.field("first_seen_ts", pa.timestamp('us')),
        pa.field("last_seen_ts", pa.timestamp('us')),
        pa.field("source_flags", pa.string())
    ])

def get_graph_ip_schema():
    return pa.schema([
        pa.field("ip_id", pa.uint64()),
        pa.field("ip", pa.string()),
        pa.field("ip_version", pa.uint8()),
        pa.field("first_seen_ts", pa.timestamp('us')),
        pa.field("last_seen_ts", pa.timestamp('us'))
    ])

def get_graph_edge_schema():
    return pa.schema([
        pa.field("src_type", pa.string()),
        pa.field("src_id", pa.uint64()),
        pa.field("dst_type", pa.string()),
        pa.field("dst_id", pa.uint64()),
        pa.field("edge_type", pa.string()),
        pa.field("first_seen_ts", pa.timestamp('us')),
        pa.field("last_seen_ts", pa.timestamp('us')),
        pa.field("last_observed_ts", pa.timestamp('us')),
        pa.field("attrs", pa.string())
    ])

def _join_list(val: Any) -> str:
    try:
        if isinstance(val, list):
            return "|".join([str(x) for x in val if x is not None])
        if val is None:
            return ""
        return str(val)
    except Exception:
        return ""

def _dnsrecord_to_expanded_row(rec: DNSRecord) -> Dict[str, Any]:
    """Flatten common DNS record fields into top-level columns for Parquet.

    Captures a broad set of fields commonly produced by dns_fetcher into
    string columns, joining list values with '|'.
    """
    rd = getattr(rec, "records", {}) or {}
    meta = getattr(rec, "meta", {}) or {}
    errors = getattr(rec, "errors", {}) or {}
    def g(key: str) -> Any:
        return rd.get(key)

    # Serialize meta/errors for completeness
    try:
        meta_json = json.dumps(_safe_serialize(meta), ensure_ascii=False, separators=(",", ":"))
    except Exception:
        meta_json = "{}"
    try:
        errors_json = json.dumps(_safe_serialize(errors), ensure_ascii=False, separators=(",", ":"))
    except Exception:
        errors_json = "{}"

    # Serialize full records for completeness
    try:
        records_json = json.dumps(_safe_serialize(rd), ensure_ascii=False, separators=(",", ":"))
    except Exception:
        records_json = "{}"

    def _split_tokens(v: Any) -> List[str]:
        try:
            if isinstance(v, list):
                out = [str(x).strip() for x in v if x is not None]
            elif isinstance(v, str):
                tmp: List[str] = []
                for part in v.replace("\n", " ").split("|"):
                    for sub in part.split(","):
                        for w in sub.split():
                            tmp.append(w)
                out = [w.strip() for w in tmp if w.strip()]
            else:
                out = []
            return [s.rstrip('.') for s in out]
        except Exception:
            return []

    def _parse_mx_list(v: Any) -> List[Dict[str, Any]]:
        items = _split_tokens(v)
        out: List[Dict[str, Any]] = []
        for s in items:
            try:
                if ":" in s:
                    pref_str, exch = s.split(":", 1)
                    pref = int(pref_str)
                    out.append({"preference": pref, "exchange": exch.rstrip('.')})
                else:
                    out.append({"preference": None, "exchange": s.rstrip('.')})
            except Exception:
                out.append({"preference": None, "exchange": s})
        return out

    def _parse_srv_list(v: Any) -> List[Dict[str, Any]]:
        items = _split_tokens(v)
        out: List[Dict[str, Any]] = []
        for s in items:
            try:
                m = re.match(r"^(\d+)\s+(\d+)\s+(\d+)\s+([^\s]+)$", s)
                if m:
                    prio = int(m.group(1))
                    weight = int(m.group(2))
                    port = int(m.group(3))
                    target = m.group(4).rstrip('.')
                    out.append({"priority": prio, "weight": weight, "port": port, "target": target, "service": None, "proto": None, "ttl": None})
                else:
                    out.append({"priority": None, "weight": None, "port": None, "target": s.rstrip('.'), "service": None, "proto": None, "ttl": None})
            except Exception:
                out.append({"priority": None, "weight": None, "port": None, "target": s, "service": None, "proto": None, "ttl": None})
        return out

    def _parse_caa_list(v: Any) -> List[Dict[str, Any]]:
        items = _split_tokens(v)
        out: List[Dict[str, Any]] = []
        for s in items:
            try:
                m = re.match(r"^(\d+)\s+(\w+)\s+\"?(.*?)\"?$", s)
                if m:
                    flags = int(m.group(1))
                    tag = m.group(2)
                    value = m.group(3)
                    out.append({"flags": flags, "tag": tag, "value": value})
                else:
                    out.append({"flags": None, "tag": "", "value": s})
            except Exception:
                out.append({"flags": None, "tag": "", "value": s})
        return out

    def _parse_naptr_list(v: Any) -> List[Dict[str, Any]]:
        items = _split_tokens(v)
        out: List[Dict[str, Any]] = []
        for s in items:
            try:
                m = re.match(r"^(\d+)\s+(\d+)\s+\"(.*?)\"\s+\"(.*?)\"\s+\"(.*?)\"\s+([^\s]+)$", s)
                if m:
                    order = int(m.group(1))
                    pref = int(m.group(2))
                    flags = m.group(3)
                    services = m.group(4)
                    regexp = m.group(5)
                    replacement = m.group(6).rstrip('.')
                    out.append({
                        "order": order,
                        "preference": pref,
                        "flags": flags,
                        "services": services,
                        "regexp": regexp,
                        "replacement": replacement,
                    })
                else:
                    out.append({
                        "order": None,
                        "preference": None,
                        "flags": "",
                        "services": "",
                        "regexp": "",
                        "replacement": s.rstrip('.'),
                    })
            except Exception:
                out.append({
                    "order": None,
                    "preference": None,
                    "flags": "",
                    "services": "",
                    "regexp": "",
                    "replacement": s,
                })
        return out

    return {
        "domain": str(getattr(rec, "domain", "") or ""),
        "status": str(getattr(rec, "status", "") or ""),
        "registered_domain": _join_list(g("registered_domain")),
        "ns": _join_list(g("ns") or g("ns1")),
        "ns_list": _split_tokens(g("ns") or g("ns1")),
        "soa": _join_list(g("soa")),
        "a": _join_list(g("a")),
        "a_list": _split_tokens(g("a")),
        "aaaa": _join_list(g("aaaa")),
        "aaaa_list": _split_tokens(g("aaaa")),
        "mx": _join_list(g("mx") or g("mail_mx")),
        "mx_records": _parse_mx_list(g("mx") or g("mail_mx")),
        "txt": _join_list(g("txt")),
        "txt_list": _split_tokens(g("txt")),
        "cname": _join_list(g("cname")),
        "caa": _join_list(g("caa")),
        "caa_records": (meta.get("caa_struct") if isinstance(meta.get("caa_struct"), list) else getattr(rec, "caa_records", None)) or _parse_caa_list(g("caa")),
        "naptr": _join_list(g("naptr")),
        "naptr_records": (meta.get("naptr_struct") if isinstance(meta.get("naptr_struct"), list) else getattr(rec, "naptr_records", None)) or _parse_naptr_list(g("naptr")),
        "srv": _join_list(g("srv")),
        "srv_records": getattr(rec, "srv_records", None) or _parse_srv_list(g("srv")),
        "a_ttl": meta.get("a_ttl") or getattr(rec, "a_ttl", None),
        "aaaa_ttl": meta.get("aaaa_ttl") or getattr(rec, "aaaa_ttl", None),
        "mx_ttl": meta.get("mx_ttl") or getattr(rec, "mx_ttl", None),
        "txt_ttl": meta.get("txt_ttl") or getattr(rec, "txt_ttl", None),
        "caa_ttl": meta.get("caa_ttl") or getattr(rec, "caa_ttl", None),
        "naptr_ttl": meta.get("naptr_ttl") or getattr(rec, "naptr_ttl", None),
        "ptr": _join_list(g("ptr")),
        "ptr_list": _split_tokens(g("ptr")),
        "www": _join_list(g("www")),
        "www_cname": _join_list(g("www_cname")),
        "mail_mx": _join_list(g("mail_mx")),
        "mx_host_final": _join_list(g("mx_host_final")),
        "mx_regdom_final": _join_list(g("mx_regdom_final") or g("mx_domain")),
        "mx_ips": _join_list(g("mx_ips")),
        "mx_ptr": _join_list(g("mx_ptr")),
        "mx_ptr_regdom": _join_list(g("mx_ptr_regdom")),
        "ns_ips": _join_list(g("ns_ips")),
        "ns_ip_int": getattr(rec, "ns_ip_int", None) or g("ns_ip_int"),
        "ns_ptr": _join_list(g("ns_ptr")),
        "ns_ptr_regdom": _join_list(g("ns_ptr_regdom")),
        "records_json": records_json,
        "errors_json": errors_json,
        "meta_json": meta_json,
    }

def get_dns_expanded_schema():
    """Schema for expanded DNS records parquet."""
    return pa.schema([
        pa.field("domain", pa.string()),
        pa.field("status", pa.string()),
        pa.field("records_json", pa.string()),
        pa.field("registered_domain", pa.string()),
        pa.field("ns", pa.string()),
        pa.field("ns_list", pa.list_(pa.string())),
        pa.field("soa", pa.string()),
        pa.field("a", pa.string()),
        pa.field("a_list", pa.list_(pa.string())),
        pa.field("aaaa", pa.string()),
        pa.field("aaaa_list", pa.list_(pa.string())),
        pa.field("mx", pa.string()),
        pa.field("mx_records", pa.list_(pa.struct([
            pa.field("preference", pa.int32()),
            pa.field("exchange", pa.string()),
        ]))),
        pa.field("txt", pa.string()),
        pa.field("txt_list", pa.list_(pa.string())),
        pa.field("cname", pa.string()),
        pa.field("caa", pa.string()),
        pa.field("caa_records", pa.list_(pa.struct([
            pa.field("flags", pa.int32()),
            pa.field("tag", pa.string()),
            pa.field("value", pa.string()),
        ]))),
        pa.field("naptr", pa.string()),
        pa.field("naptr_records", pa.list_(pa.struct([
            pa.field("order", pa.int32()),
            pa.field("preference", pa.int32()),
            pa.field("flags", pa.string()),
            pa.field("services", pa.string()),
            pa.field("regexp", pa.string()),
            pa.field("replacement", pa.string()),
        ]))),
        pa.field("srv", pa.string()),
        pa.field("srv_records", pa.list_(pa.struct([
            pa.field("priority", pa.int32()),
            pa.field("weight", pa.int32()),
            pa.field("port", pa.int32()),
            pa.field("target", pa.string()),
            pa.field("service", pa.string()),
            pa.field("proto", pa.string()),
            pa.field("ttl", pa.int32()),
        ]))),
        pa.field("a_ttl", pa.int32()),
        pa.field("aaaa_ttl", pa.int32()),
        pa.field("mx_ttl", pa.int32()),
        pa.field("txt_ttl", pa.int32()),
        pa.field("caa_ttl", pa.int32()),
        pa.field("naptr_ttl", pa.int32()),
        pa.field("ptr", pa.string()),
        pa.field("ptr_list", pa.list_(pa.string())),
        pa.field("www", pa.string()),
        pa.field("www_cname", pa.string()),
        pa.field("mail_mx", pa.string()),
        pa.field("mx_host_final", pa.string()),
        pa.field("mx_regdom_final", pa.string()),
        pa.field("mx_ips", pa.string()),
        pa.field("mx_ptr", pa.string()),
        pa.field("mx_ptr_regdom", pa.string()),
        pa.field("ns_ips", pa.string()),
        pa.field("ns_ip_int", pa.int64()),
        pa.field("ns_ptr", pa.string()),
        pa.field("ns_ptr_regdom", pa.string()),
        pa.field("errors_json", pa.string()),
        pa.field("meta_json", pa.string()),
    ])




class BatchProcessor:
    """
    BatchProcessor for DNS record fetching and persistence.
    
    This class coordinates batch DNS fetching with:
    - Configurable worker pool for domain-level parallelism
    - Shared semaphore-based throttling
    - Edge extraction for DuckDB Entity Graph
    - Robust PyArrow serialization
    - Parquet file output with separate results and retries
    """
    
    def __init__(
        self,
        file_key: str,
        output_dir: str,
        retry_dir: str,
        lookups_db_path: Optional[str] = None,
        flight_server_url: Optional[str] = None,
        workers: int = DEFAULT_WORKERS,
        semaphore: Optional[asyncio.Semaphore] = None,
        logger: Optional[Any] = None,
        lmdb_path: Optional[str] = None,
    ):
        """
        Initialize BatchProcessor.
        
        Args:
            file_key: Base name for output files (without extension).
            output_dir: Directory for results parquet files.
            retry_dir: Directory for retry parquet files.
            workers: Number of concurrent domain workers.
            semaphore: Shared semaphore for throttling.
            logger: Optional logger instance (supports stdlib logging or loguru with bind()).
            logger_override: Optional legacy parameter name for logger injection.
        """
        self.file_key = file_key
        self.output_dir = Path(output_dir)
        self.retry_dir = Path(retry_dir)
        # Normalize LOOKUPS_DB_PATH: accept either a directory (ending with /lookups/) or a full .duckdb path
        raw_lookups = lookups_db_path if lookups_db_path is not None else (NFS_BASE / "lookups")
        try:
            p = Path(str(raw_lookups))
            if p.suffix == ".duckdb":
                self.lookups_db_path = str(p)
            else:
                self.lookups_db_path = str(p / "lookups.duckdb")
        except Exception:
            # Fallback to default
            self.lookups_db_path = str(NFS_BASE / "lookups" / "lookups.duckdb")
        
        self.flight_server_url = flight_server_url
        
        # Allow environment to override worker count and semaphore limit for stability
        try:
            env_workers = int(os.getenv("DNS_BATCH_WORKERS", "0"))
        except Exception:
            env_workers = 0
        self.workers = env_workers if env_workers > 0 else workers

        try:
            sem_limit = int(os.getenv("DNS_SEMAPHORE_LIMIT", "100"))
        except Exception:
            sem_limit = 100
        # Prefer injected semaphore; otherwise create a local semaphore with env limit
        self.semaphore = semaphore or asyncio.Semaphore(max(1, sem_limit))
        # Use injected logger if provided, otherwise module-level log
        if logger is None:
            # Use module-level child logger; bind extra context when supported
            try:
                if hasattr(log, "bind"):
                    self.log = log.bind(module="batch_processor", file_key=self.file_key)
                else:
                    self.log = log
            except Exception:
                self.log = log
        else:
            # If injected loguru logger, bind additional context; if stdlib logger, keep as-is
            try:
                if hasattr(logger, "bind"):
                    self.log = logger.bind(module="batch_processor", file_key=self.file_key)
                else:
                    self.log = logger
            except Exception:
                # Fallback to module-level child logger
                try:
                    if hasattr(log, "bind"):
                        self.log = log.bind(module="batch_processor", file_key=self.file_key)
                    else:
                        self.log = log
                except Exception:
                    self.log = log

        self.log.info("BatchProcessor initialized (file_key={}, workers={}, sem_limit={})", self.file_key, self.workers, sem_limit)
        self.lmdb_path = lmdb_path       
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.retry_dir.mkdir(parents=True, exist_ok=True)
    
    def _build_graph_tables(self, results: List[DNSRecord]) -> Tuple[pa.Table, pa.Table, pa.Table]:
        """
        Shreds the flat DNSRecords into normalized Entity Graph tables.
        """
        
        now = datetime.utcnow()
        domains_data, ips_data, edges_data = [], [], []
        
        # Track seen IPs in this batch to avoid duplicate IP nodes
        seen_ips = set()

        for rec in results:
            domain_str = getattr(rec, "domain", "")
            if not domain_str:
                continue
                
            # 1. Generate Domain Node
            domain_id = hash_domain(domain_str)
            regdom = getattr(rec, "registered_domain", "") or domain_str
            
            domains_data.append({
                "domain_id": domain_id,
                "domain": domain_str.lower(),
                "apex": regdom.lower(),
                "tld": regdom.split('.')[-1] if '.' in regdom else "",
                "first_seen_ts": now,
                "last_seen_ts": now,
                "source_flags": json.dumps({"status": getattr(rec, "status", "")})
            })

            # Helper to extract IPs safely
            def _extract_ips(record_attr) -> List[str]:
                val = getattr(rec, record_attr, [])
                if not val: return []
                if isinstance(val, str): return val.split('|')
                return [str(x) for x in val if x]

            # 2. Extract IPv4 (A Records) & Build Edges
            for ip_str in _extract_ips("a"):
                ip_str = ip_str.strip()
                if not ip_str: continue
                
                ip_id = hash_ip(ip_str)
                
                # Add IP Node (if not already added in this batch)
                if ip_id not in seen_ips:
                    ips_data.append({
                        "ip_id": ip_id,
                        "ip": ip_str,
                        "ip_version": 4,
                        "first_seen_ts": now,
                        "last_seen_ts": now
                    })
                    seen_ips.add(ip_id)
                
                # Add Domain -> IP Edge
                edges_data.append({
                    "src_type": "domain", "src_id": domain_id,
                    "dst_type": "ip",     "dst_id": ip_id,
                    "edge_type": "A",
                    "first_seen_ts": now, "last_seen_ts": now, "last_observed_ts": now,
                    "attrs": json.dumps({"ttl": getattr(rec, "a_ttl", 300) or 300})
                })

            # 3. Extract IPv6 (AAAA Records) & Build Edges
            for ip_str in _extract_ips("aaaa"):
                ip_str = ip_str.strip()
                if not ip_str: continue
                
                ip_id = hash_ip(ip_str)
                
                if ip_id not in seen_ips:
                    ips_data.append({
                        "ip_id": ip_id,
                        "ip": ip_str,
                        "ip_version": 6,
                        "first_seen_ts": now,
                        "last_seen_ts": now
                    })
                    seen_ips.add(ip_id)
                
                edges_data.append({
                    "src_type": "domain", "src_id": domain_id,
                    "dst_type": "ip",     "dst_id": ip_id,
                    "edge_type": "AAAA",
                    "first_seen_ts": now, "last_seen_ts": now, "last_observed_ts": now,
                    "attrs": json.dumps({"ttl": getattr(rec, "aaaa_ttl", 300) or 300})
                })
                
            # You can repeat this exact pattern for NS and MX records!

        # Construct the strict PyArrow Tables
        domain_table = pa.Table.from_pylist(domains_data, schema=get_graph_domain_schema())
        ip_table = pa.Table.from_pylist(ips_data, schema=get_graph_ip_schema())
        edge_table = pa.Table.from_pylist(edges_data, schema=get_graph_edge_schema())
        
        return domain_table, ip_table, edge_table

    async def write_flight(self, table: pa.Table, dataset_name: str):
        def _do_write():
            client = flight.FlightClient(self.flight_server_url)
            descriptor = flight.FlightDescriptor.for_path(dataset_name)
            writer, _ = client.do_put(descriptor, table.schema)
            writer.write_table(table)
            writer.close()
        await asyncio.to_thread(_do_write)
        self.log.info(f"Streamed {dataset_name} to Flight Server at {self.flight_server_url}")

    async def write_output(self, table: pa.Table, path: str | Path, dataset_name: str):
        if self.flight_server_url:
            try:
                await self.write_flight(table, dataset_name)
                return
            except Exception as e:
                self.log.error(f"Flight stream failed for {dataset_name}: {e}. Falling back to Parquet...")
        
        path_str = str(path)
        await asyncio.to_thread(pq.write_table, table, path_str)
        self.log.info(f"Written to {path_str}")

    async def write_parquet(self, table: pa.Table, path: str | Path):
        path_str = str(path)
        await asyncio.to_thread(pq.write_table, table, path_str)
        self.log.info(f"Written to {path_str}")
    
    async def process(
        self,
        domains: Iterable[str],
        retry_limit: int = 1
    ) -> Tuple[str, Optional[str]]:
        """
        Process a batch of domains and write results to parquet files.
        
        Workflow:
        1. Call fetch_batch to retrieve DNS records
        2. Apply scoring and labeling to results
        3. Serialize records to pyarrow-safe rows
        4. Write results parquet to output_dir
        5. Write retries parquet to retry_dir (if any)
        6. Log throughput metrics
        7. Return file paths
        
        Args:
            domains: Iterable of domain names to process.
            retry_limit: Maximum retries for failed core lookups.
        
        Returns:
            Tuple of (results_path, retries_path) where:
            - results_path: Path to results parquet file
            - retries_path: Path to retries parquet file (None if no retries)
        """
        start_time = time.time()
        
        # Convert to list for counting
        domain_list = list(domains)
        domain_count = len(domain_list)
        
        self.log.info(
            f"Starting batch processing: {domain_count} domains, "
            f"{self.workers} workers, file_key={self.file_key}"
        )
        
        # Step 1: Fetch DNS records using fetch_batch
        results, retries = await fetch_batch(
            domain_list,
            semaphore=self.semaphore,
            workers=self.workers,
            retry_limit=retry_limit
        )

        if not self.lmdb_path:
            raise RuntimeError("LMDB path not configured on BatchProcessor")

        kv = LMDBActivity(str(self.lmdb_path), readonly=True)

        # Immediately write initial retry shard (snapshot before enrichment)
        if retries:
            initial_retries_path = self.retry_dir / f"{self.file_key}_initial_retries.parquet"
            initial_retries_table = self.join_tables(retries)
            await self.write_parquet(initial_retries_table, initial_retries_path)
            self.log.info(f"Wrote initial retries snapshot to {initial_retries_path}")
        
        self.log.info(
            f"Fetch complete: {len(results)} results, {len(retries)} retries"
        )

        # Build signature rows with ALL attributes for downstream processing
        signature_rows: List[Dict[str, Any]] = []
        for rec in results:
            try:
                domain = str(getattr(rec, "domain", "") or "").lower()
                status = str(getattr(rec, "status", "") or "")
                regdom_val = str(getattr(rec, "registered_domain", "") or "").lower()
                
                # Base attributes
                row = {
                    "domain": domain,
                    "status": status,
                    "registered_domain": regdom_val,
                }

                # Helper to get value from records dict or attribute
                records_dict = getattr(rec, "records", None)
                if not isinstance(records_dict, dict):
                    records_dict = {}
                    # Try to populate dict from attributes if it's not a dict
                    # (This handles the case where rec is a flat DNSRecords object)
                    for field_name in [
                        "ns", "ns1", "a", "aaaa", "mx", "txt", "cname", "soa", "srv", 
                        "naptr", "caa", "ptr", "spf", "dmarc", "bimi", 
                        "www", "www_cname", "www_a", "www_ptr",
                        "mail_a", "mail_mx", "mail_spf", "mail_dmarc", "mail_cname",
                        "mail_mx_domain", "mail_mx_tld", 
                        "mx_domain", "mx_host_final", "mx_regdom_final"
                    ]:
                        val = getattr(rec, field_name, None)
                        if val is not None:
                            records_dict[field_name] = val
                    
                    # Also map TTLs if available as attributes
                    for ttl_field in ["a_ttl", "aaaa_ttl", "mx_ttl", "txt_ttl", "caa_ttl", "naptr_ttl"]:
                         val = getattr(rec, ttl_field, None)
                         if val is not None:
                             row[ttl_field] = val

                def g(key: str) -> Any:
                    return records_dict.get(key)
                
                # --- Core DNS ---
                # NS Special Handling (normalization)
                ns_candidate = g("ns") or g("ns1")
                row["ns"] = _normalize_ns_value(ns_candidate)
                row["ns_raw"] = _join_list(ns_candidate)
                row["ns_list_norm"] = _normalize_ns_list(ns_candidate)
                
                # A Record Special Handling (IP int conversion)
                a_candidate = g("a")
                row["a"] = _join_list(a_candidate)
                
                # Extract first IP for integer conversion
                first_ip = ""
                if isinstance(a_candidate, list):
                    first_ip = next((str(x) for x in a_candidate if isinstance(x, str) and x), "")
                elif isinstance(a_candidate, str):
                    first_ip = a_candidate.split("|")[0] if a_candidate else ""
                
                ip_int_val = getattr(rec, "ip_int", None)
                if ip_int_val is None and first_ip:
                    try:
                        ip_int_val = ip_to_int(first_ip)
                    except Exception:
                        ip_int_val = None
                row["ip_int"] = ip_int_val

                # Simple string/list joins for other records
                # Core
                row["aaaa"] = _join_list(g("aaaa"))
                row["soa"] = _join_list(g("soa"))
                row["ptr"] = _join_list(g("ptr"))
                row["cname"] = _join_list(g("cname"))
                
                # TXT / Policy
                row["txt"] = _join_list(g("txt"))
                row["spf"] = _join_list(g("spf"))
                row["dmarc"] = _join_list(g("dmarc"))
                row["bimi"] = _join_list(g("bimi"))
                
                # Extended Types
                row["caa"] = _join_list(g("caa"))
                row["srv"] = _join_list(g("srv"))
                row["naptr"] = _join_list(g("naptr"))
                
                # MX details
                row["mx_host_norm"] = _join_list(g("mx_host_final") or g("mx") or g("mail_mx")) # normalized for enrichment
                row["mx_regdom_norm"] = _join_list(g("mx_regdom_final") or g("mx_domain")) # normalized for enrichment
                row["mx_regdom_final"] = _join_list(g("mx_regdom_final") or g("mx_domain"))
                row["mx"] = _join_list(g("mx"))
                row["mx_domain"] = _join_list(g("mx_domain"))
                row["mx_host_final"] = _join_list(g("mx_host_final"))
                row["mx_ips"] = _join_list(g("mx_ips"))
                row["mx_ptr"] = _join_list(g("mx_ptr"))
                
                # NS specific details
                row["ns_host_final"] = _join_list(g("ns_host_final"))
                row["ns_regdom_final"] = _join_list(g("ns_regdom_final"))
                row["ns_ips"] = _join_list(g("ns_ips"))
                row["ns_ptr"] = _join_list(g("ns_ptr"))
                row["ns_ptr_regdom"] = _join_list(g("ns_ptr_regdom"))
                
                ns_ip_int_val = getattr(rec, "ns_ip_int", None)
                if ns_ip_int_val is None and g("ns_ips"):
                    ns_ips_list = g("ns_ips")
                    first_ns_ip = ns_ips_list[0] if isinstance(ns_ips_list, list) and len(ns_ips_list) > 0 else ""
                    if first_ns_ip:
                         try:
                             ns_ip_int_val = ip_to_int(first_ns_ip)
                         except Exception:
                             pass
                row["ns_ip_int"] = ns_ip_int_val
                
                # WWW Subdomain
                row["www"] = _join_list(g("www"))
                row["www_cname"] = _join_list(g("www_cname"))
                row["www_a"] = _join_list(g("www_a"))
                row["www_ptr"] = _join_list(g("www_ptr"))
                
                # Mail Subdomain
                row["mail_a"] = _join_list(g("mail_a"))
                row["mail_mx"] = _join_list(g("mail_mx"))
                row["mail_cname"] = _join_list(g("mail_cname"))
                row["mail_spf"] = _join_list(g("mail_spf"))
                row["mail_dmarc"] = _join_list(g("mail_dmarc"))
                
                # Pass through TTLs if they were in the record but not yet in row
                # (DNSRecord might have them in .meta or as attributes, not always in .records)
                for ttl_attr in ["a_ttl", "aaaa_ttl", "mx_ttl", "txt_ttl", "caa_ttl", "naptr_ttl"]:
                    if ttl_attr not in row:
                        val = getattr(rec, ttl_attr, None)
                        if val is not None:
                             row[ttl_attr] = val

                signature_rows.append(row)
            except Exception as e:
                self.log.error(f"Failed to build signature row for domain {getattr(rec, 'domain', '<unknown>')}: {e}")

        # Annotate change flags using the minimal table; do not overwrite results list
        change_table, deltas = annotate_change_flags_arrow(
            signature_rows,
            kv,
            domain_col="domain",
            ns_col="ns_raw",  # use raw NS for signature stability vs historical LMDB
            a_col="a",
            mx_regdom_col="mx_regdom_final",   # or "mx_domain" in your old schema
            status_col="status",
            mx_ips_col="mx_ips",
        )

        # Emit deltas for the master aggregator
        delta_path = str(NFS_BASE / "deltas" / f"delta_{self.file_key}.csv")
        write_activity_delta_csv(deltas, delta_path)

        # Step 2: (Scoring and labeling removed - consolidated to DuckDB graph logic)
        
        # Step 3: Serialize to pyarrow-safe rows
        result_rows = []
        for rec in results:
            try:
                row = _dnsrecord_to_row(rec)
                result_rows.append(row)
            except Exception as e:
                self.log.error(
                    f"Failed to serialize result for {rec.domain}: {e}",
                    exc_info=True
                )
                # Add fallback row
                result_rows.append({
                    "domain": rec.domain,
                    "status": "error",
                    "records_json": "{}",
                    "errors_json": json.dumps({"serialization": str(e)}),
                    "meta_json": "{}",
                })
        
        retry_rows = []
        for rec in retries:
            try:
                row = _dnsrecord_to_row(rec)
                retry_rows.append(row)
            except Exception as e:
                self.log.error(
                    f"Failed to serialize retry for {rec.domain}: {e}",
                    exc_info=True
                )
                retry_rows.append({
                    "domain": rec.domain,
                    "status": "needs_retry",
                    "records_json": "{}",
                    "errors_json": json.dumps({"serialization": str(e)}),
                    "meta_json": "{}",
                })
        
        # Step 4: Write results parquet
        results_path = self.output_dir / f"{self.file_key}_results.parquet"
        expanded_path = self.output_dir / f"{self.file_key}_expanded.parquet"

        # Results file
        try:
            schema = get_dns_schema()
            results_table = pa.Table.from_pylist(result_rows, schema=schema)
            await self.write_output(results_table, results_path, "dns_results")
            self.log.info("Results table written: rows={}", len(result_rows))
        except Exception as e:
            self.log.error("Failed to write results table: {}", e, exc_info=True)
            raise

        # Expanded results file (flattened columns for direct analytics)
        try:
            expanded_rows = []
            for rec in results:
                try:
                    expanded_rows.append(_dnsrecord_to_expanded_row(rec))
                except Exception:
                    # ensure row exists even on error
                    expanded_rows.append({
                        "domain": str(getattr(rec, "domain", "") or ""),
                        "status": str(getattr(rec, "status", "") or "error"),
                        "registered_domain": "",
                        "ns": "",
                        "soa": "",
                        "a": "",
                        "aaaa": "",
                        "mx": "",
                        "txt": "",
                        "cname": "",
                        "caa": "",
                        "naptr": "",
                        "srv": "",
                        "ptr": "",
                        "www": "",
                        "www_cname": "",
                        "mail_mx": "",
                        "mx_host_final": "",
                        "mx_regdom_final": "",
                        "errors_json": "{}",
                        "meta_json": "{}",
                    })
            exp_schema = get_dns_expanded_schema()
            expanded_table = pa.Table.from_pylist(expanded_rows, schema=exp_schema)
            await self.write_output(expanded_table, expanded_path, "dns_expanded")
            try:
                self.log.info("Expanded table written: rows={}", len(expanded_rows))
            except Exception:
                pass
        except Exception as e:
            self.log.error("Failed to write expanded table: {}", e, exc_info=True)
            # Do not raise; JSON results are already written


        
        try:
            domain_table, ip_table, edge_table = self._build_graph_tables(results)
            
            # Write them to the output directory or stream to flight server
            graph_domain_path = self.output_dir / f"{self.file_key}_graph_domain.parquet"
            graph_ip_path = self.output_dir / f"{self.file_key}_graph_ip.parquet"
            graph_edge_path = self.output_dir / f"{self.file_key}_graph_edge.parquet"
            
            await self.write_output(domain_table, graph_domain_path, "entity_domain")
            await self.write_output(ip_table, graph_ip_path, "entity_ip")
            await self.write_output(edge_table, graph_edge_path, "entity_edge")
            
            self.log.info(f"Graph tables written: {domain_table.num_rows} domains, {ip_table.num_rows} IPs, {edge_table.num_rows} edges.")
        except Exception as e:
            self.log.error(f"Failed to write Graph parquets: {e}", exc_info=True)

        # Step 5: Write retries parquet (if any)
        retries_path = None
        if retry_rows:
            retries_path = self.retry_dir / f"{self.file_key}_retries.parquet"
            try:
                schema = get_dns_schema()
                retries_table = pa.Table.from_pylist(retry_rows, schema=schema)
                pq.write_table(retries_table, retries_path)
                self.log.info(f"Wrote {len(retry_rows)} retries to {retries_path}")
            except Exception as e:
                self.log.error(f"Failed to write retries parquet: {e}", exc_info=True)
                raise
        
        # Step 6: Log throughput metrics
        elapsed = time.time() - start_time
        throughput = domain_count / elapsed if elapsed > 0 else 0
        self.log.info(
            f"Batch processing complete: {domain_count} domains in {elapsed:.2f}s "
            f"({throughput:.1f} domains/s)"
        )
        
        # Step 7: Return file paths
        return str(results_path), str(retries_path) if retries_path else None
    
    def join_tables(self, dns_records: List[DNSRecord]) -> pa.Table:
        """
        Convert list of DNSRecord to PyArrow Table for compatibility.
        
        This method provides compatibility with existing code that expects
        a PyArrow table from DNS records.
        
        Args:
            dns_records: List of DNSRecord instances.
        
        Returns:
            PyArrow Table with serialized DNS records.
        """
        rows = []
        for rec in dns_records:
            try:
                row = _dnsrecord_to_row(rec)
                rows.append(row)
            except Exception as e:
                self.log.error(
                    f"Failed to convert DNSRecord for domain {rec.domain}: {e}",
                    exc_info=True
                )
                # Add fallback row
                rows.append({
                    "domain": getattr(rec, "domain", "<unknown>"),
                    "status": "error",
                    "records_json": "{}",
                    "errors_json": json.dumps({"serialization": str(e)}),
                    "meta_json": "{}",
                })
        
        schema = get_dns_schema()
        try:
            table = pa.Table.from_pylist(rows, schema=schema)
            return table
        except Exception as e:
            self.log.error(f"Failed to build pyarrow table: {e}", exc_info=True)
            # Return empty table with correct schema
            return pa.Table.from_pylist([], schema=schema)
