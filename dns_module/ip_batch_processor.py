from __future__ import annotations
import asyncio
from typing import Iterable, List, Dict, Any, Optional

import pyarrow as pa
import pyarrow.parquet as pq

from . import dns_lookup
from .logger import get_child_logger

log = get_child_logger("ip_batch_processor")


async def _lookup_ptr_for_ip(ip: str, *, resolver=None, semaphore=None) -> Dict[str, Any]:
    """Resolve PTR for a single IP, returning a simple dict.

    Uses dns_lookup.lookup_ptr via reverse pointer and benefits from LMDB/in-memory caches.
    """
    try:
        # Build reverse name via ipaddress
        import ipaddress
        try:
            rev = ipaddress.ip_address(ip).reverse_pointer
        except Exception:
            return {"ip": ip, "ptr": "", "rcode": "ERROR", "ttl": 0}

        rcode, answers, ttl = await dns_lookup.lookup_ptr(rev, resolver=resolver, semaphore=semaphore)
        ptr = answers[0] if (rcode == "NOERROR" and answers) else ""
        return {"ip": ip, "ptr": ptr, "rcode": rcode, "ttl": int(ttl or 0)}
    except Exception as e:
        try:
            log.warning("PTR lookup error for {}: {}", ip, e)
        except Exception:
            pass
        return {"ip": ip, "ptr": "", "rcode": "ERROR", "ttl": 0}


async def resolve_ptr_batch(ips: Iterable[str], *, concurrency: int = 500) -> List[Dict[str, Any]]:
    """Resolve PTR for a batch of unique IPs with bounded concurrency.

    This warms LMDB and in-memory caches so later per-domain lookups skip PTR work.
    """
    resolver = dns_lookup.get_default_resolver()
    sem = dns_lookup.default_semaphore()

    ips_list = [str(i) for i in ips if i]
    results: List[Dict[str, Any]] = []

    # Semaphore to bound this batch beyond dns_lookup's global semaphore
    batch_sem = asyncio.Semaphore(max(1, int(concurrency)))

    async def _worker(ip: str):
        async with batch_sem:
            return await _lookup_ptr_for_ip(ip, resolver=resolver, semaphore=sem)

    tasks = [asyncio.create_task(_worker(ip)) for ip in ips_list]
    for t in asyncio.as_completed(tasks):
        try:
            res = await t
            results.append(res)
        except Exception:
            pass
    return results


def write_ptr_results_parquet(rows: List[Dict[str, Any]], out_path: str) -> None:
    """Write PTR results to a Parquet file."""
    try:
        table = pa.Table.from_pylist(rows)
        pq.write_table(table, out_path)
        try:
            log.info("Wrote PTR batch results: {} rows -> {}", len(rows), out_path)
        except Exception:
            pass
    except Exception as e:
        try:
            log.error("Failed to write PTR results: {}", e)
        except Exception:
            pass


async def process_unique_ips_and_write(ips: Iterable[str], out_path: str, *, concurrency: int = 500) -> str:
    """High-level helper: resolve PTR for unique IPs and write to Parquet.

    Returns the output path.
    """
    rows = await resolve_ptr_batch(ips, concurrency=concurrency)
    write_ptr_results_parquet(rows, out_path)
    return out_path
