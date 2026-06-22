# /root/dnsproject/dns_module/smtp_banner_batch.py
from __future__ import annotations
import asyncio
import datetime as dt
from typing import Dict, Iterable

from aiolimiter import AsyncLimiter

from .smtp_banner_fetcher import fetch_smtp_banner
from annotations_module.lmdb_cache import LMDBCache

def _is_fresh(ts_epoch: float, ttl_days: int) -> bool:
    if not ts_epoch:
        return False
    age_days = (dt.datetime.utcnow() - dt.datetime.utcfromtimestamp(ts_epoch)).days
    return age_days <= ttl_days

async def fetch_banners_with_cache(
    hosts: Iterable[str],
    cache: LMDBCache,
    ttl_days: int = 30,
    concurrency: int = 100
) -> Dict[str, str]:
    """
    Returns { host: banner } for successfully fetched or cached banners.
    """
    limiter = AsyncLimiter(concurrency, 1)
    uniq = sorted({h.strip().lower() for h in hosts if h})
    results: Dict[str, str] = {}

    # 1) Warm cache
    cached = cache.get_many(uniq)
    to_fetch = []
    for h in uniq:
        val_ts = cached.get(h)
        if val_ts:
            val, ts = val_ts
            banner = (val or {}).get("banner")
            if banner and _is_fresh(ts, ttl_days):
                results[h] = banner
                continue
        to_fetch.append(h)

    # 2) Fetch missing/stale
    async def _task(host: str):
        async with limiter:
            b = await fetch_smtp_banner(host)
            if b:
                results[host] = b

    await asyncio.gather(*[asyncio.create_task(_task(h)) for h in to_fetch])

    # 3) Write-through cache for newly fetched
    to_store = {h: {"banner": b} for h, b in results.items() if h in to_fetch}
    if to_store:
        cache.put_many(to_store)

    return results

