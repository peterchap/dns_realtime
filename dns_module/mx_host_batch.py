from __future__ import annotations
import asyncio
from typing import Iterable, List, Dict, Any, Optional

import pyarrow as pa
import pyarrow.parquet as pq

from . import dns_lookup
from .logger import get_child_logger

log = get_child_logger("mx_host_batch")


async def _lookup_a_aaaa(host: str, *, resolver=None, semaphore=None) -> Dict[str, Any]:
    """Resolve A and AAAA for a hostname; return combined result.

    Uses dns_lookup helpers to benefit from LMDB + in-memory cache.
    """
    host_q = (host or "").strip().rstrip(".").lower()
    if not host_q:
        return {
            "host": host or "",
            "a_ips": [], "a_rcode": "ERROR", "a_ttl": 0,
            "aaaa_ips": [], "aaaa_rcode": "ERROR", "aaaa_ttl": 0,
        }
    try:
        a_rcode, a_ips, a_ttl = await dns_lookup.lookup_a(host_q, resolver=resolver, semaphore=semaphore)
    except Exception as e:
        try:
            log.warning("A lookup error for {}: {}", host_q, e)
        except Exception:
            pass
        a_rcode, a_ips, a_ttl = "ERROR", [], 0

    try:
        aaaa_rcode, aaaa_ips, aaaa_ttl = await dns_lookup.lookup_aaaa(host_q, resolver=resolver, semaphore=semaphore)
    except Exception as e:
        try:
            log.warning("AAAA lookup error for {}: {}", host_q, e)
        except Exception:
            pass
        aaaa_rcode, aaaa_ips, aaaa_ttl = "ERROR", [], 0

    return {
        "host": host_q,
        "a_ips": a_ips, "a_rcode": a_rcode, "a_ttl": int(a_ttl or 0),
        "aaaa_ips": aaaa_ips, "aaaa_rcode": aaaa_rcode, "aaaa_ttl": int(aaaa_ttl or 0),
    }


async def resolve_mx_hosts_batch(hosts: Iterable[str], *, concurrency: int = 500) -> List[Dict[str, Any]]:
    """Resolve A/AAAA for a batch of unique MX exchange hostnames.

    This warms caches and yields a compact result set for later joins.
    """
    resolver = dns_lookup.get_default_resolver()
    sem = dns_lookup.default_semaphore()
    host_list = [str(h) for h in hosts if h]
    results: List[Dict[str, Any]] = []

    batch_sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def _worker(h: str):
        async with batch_sem:
            return await _lookup_a_aaaa(h, resolver=resolver, semaphore=sem)

    tasks = [asyncio.create_task(_worker(h)) for h in host_list]
    for t in asyncio.as_completed(tasks):
        try:
            res = await t
            results.append(res)
        except Exception:
            pass
    return results


def write_mx_hosts_parquet(rows: List[Dict[str, Any]], out_path: str) -> None:
    """Write MX host resolution results to Parquet."""
    try:
        # Flatten arrays to pipe-joined strings for compact storage
        flat_rows = []
        for r in rows:
            flat_rows.append({
                "host": r.get("host", ""),
                "a_ips": "|".join(r.get("a_ips", []) or []),
                "a_rcode": r.get("a_rcode", ""),
                "a_ttl": r.get("a_ttl", 0),
                "aaaa_ips": "|".join(r.get("aaaa_ips", []) or []),
                "aaaa_rcode": r.get("aaaa_rcode", ""),
                "aaaa_ttl": r.get("aaaa_ttl", 0),
            })
        table = pa.Table.from_pylist(flat_rows)
        pq.write_table(table, out_path)
        try:
            log.info("Wrote MX host batch results: {} rows -> {}", len(rows), out_path)
        except Exception:
            pass
    except Exception as e:
        try:
            log.error("Failed to write MX host results: {}", e)
        except Exception:
            pass


async def process_mx_hosts_and_write(hosts: Iterable[str], out_path: str, *, concurrency: int = 500) -> str:
    """High-level helper: resolve MX exchange hosts and write to Parquet.

    Returns the output path.
    """
    rows = await resolve_mx_hosts_batch(hosts, concurrency=concurrency)
    write_mx_hosts_parquet(rows, out_path)
    return out_path
