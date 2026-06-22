"""
DNS lookup module using dnspython with LMDB persistence and in-memory caching.

This module provides:
- Single resolver per process (configurable by application)
- Per-process semaphore-based throttling (default 800, configurable by application)
- In-memory TTL caching with inflight dedupe
- LMDB persistent cache with background writer
- Change detection to skip unchanged domains
- Setter API for application to inject resolver/semaphore and logger
"""
from __future__ import annotations

import asyncio
import logging
import lmdb
import os
import pickle
import zlib
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from dotenv import load_dotenv
from typing import Optional, List, Tuple, Dict, Any
import re

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver  # Added to allow dns.resolver.NXDOMAIN / NoAnswer / Timeout exception references
from .config import CONFIG  # Centralized config

load_dotenv()
# Module-level logger (fallback to stdlib). Can be replaced by set_logger().
logger: Any = logging.getLogger("dns_lookup")

# --- Optional Loguru adapter + set_logger function ---
class _LoguruAdapter:
    """
    Wrap a loguru logger to provide subset of stdlib logging API used by this module.
    Exposes: debug, info, warning, error, exception, getChild.
    """
    def __init__(self, loguru_logger: Any):
        self._lg = loguru_logger

    def debug(self, *args, **kwargs):
        try:
            self._lg.debug(*args, **kwargs)
        except Exception:
            # fallback to string formatting
            msg = args[0] if args else ""
            self._lg.debug(str(msg))

    def info(self, *args, **kwargs):
        try:
            self._lg.info(*args, **kwargs)
        except Exception:
            msg = args[0] if args else ""
            self._lg.info(str(msg))

    def warning(self, *args, **kwargs):
        try:
            self._lg.warning(*args, **kwargs)
        except Exception:
            msg = args[0] if args else ""
            self._lg.warning(str(msg))

    def error(self, *args, **kwargs):
        try:
            self._lg.error(*args, **kwargs)
        except Exception:
            msg = args[0] if args else ""
            self._lg.error(str(msg))

    def exception(self, *args, **kwargs):
        try:
            self._lg.exception(*args, **kwargs)
        except Exception:
            msg = args[0] if args else ""
            self._lg.exception(str(msg))

    def getChild(self, name: str):
        try:
            child = self._lg.bind(module=name)
            return _LoguruAdapter(child)
        except Exception:
            return self

def set_logger(new_logger: Any) -> None:
    """
    Inject an application logger into dns_lookup.
    Accepts either a stdlib logging.Logger or a loguru logger (from loguru import logger).
    After calling this, dns_lookup's internal `logger` will forward to the provided logger.
    """
    global logger
    try:
        if hasattr(new_logger, "bind") and hasattr(new_logger, "info"):
            logger = _LoguruAdapter(new_logger)
        elif isinstance(new_logger, logging.Logger):
            logger = new_logger.getChild("dns_lookup")
        else:
            logger = logging.getLogger("dns_lookup")
    except Exception:
        logger = logging.getLogger("dns_lookup")

# --------------------------------------------------------------------
# Default configuration and application-settable backing stores
# --------------------------------------------------------------------
# Allow environment override for global semaphore limit to prevent resolver overload
DEFAULT_SEMAPHORE_LIMIT = CONFIG.semaphore_limit
INMEM_CACHE_MAX = 150_000
NEGATIVE_TTL_SECONDS = 60
POSITIVE_MIN_TTL_SECONDS = 5
DEFAULT_QPS_LIMIT = CONFIG.global_qps


# Backing store for application-injected resolver / semaphore
_default_resolver: Optional[dns.asyncresolver.Resolver] = None
_default_semaphore: Optional[asyncio.Semaphore] = None
_default_semaphore_limit: int = DEFAULT_SEMAPHORE_LIMIT
_rate_limiter: Optional["TokenBucket"] = None
_lmdb_env: Optional[lmdb.Environment] = None
_lmdb_readonly: bool = True
_lmdb_writer_task: Optional[asyncio.Task] = None
_lmdb_write_queue: Optional[asyncio.Queue] = None
_executor: Optional[ThreadPoolExecutor] = None

# Optional secondary LMDB environment for precomputed caches (e.g., PTR)
_lmdb_env_ptr: Optional[lmdb.Environment] = None
_lmdb_ptr_readonly: bool = True

# In-memory cache: key -> (rcode, answers, ttl, timestamp)
_inmem_cache: Dict[str, Tuple[str, List[str], int, float]] = {}
_inmem_cache_order: List[str] = []  # LRU tracking

# Inflight dedupe: key -> Future
_inflight: Dict[str, asyncio.Future] = {}

class TokenBucket:
    def __init__(self, rate: float, capacity: Optional[float] = None):
        self.rate = max(0.0001, float(rate))
        self.capacity = float(capacity if capacity is not None else rate)
        self.tokens = self.capacity
        self._last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self._last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                needed = (1.0 - self.tokens) / self.rate
            await asyncio.sleep(max(0.0, needed))

def configure_rate_limiter(qps: int, capacity: Optional[int] = None) -> None:
    global _rate_limiter
    q = max(1, int(qps))
    c = int(capacity) if capacity is not None else q
    _rate_limiter = TokenBucket(rate=q, capacity=c)
    try:
        logger.info(f"Configured global QPS limiter: qps={q} capacity={c}")
    except Exception:
        pass

@dataclass
class DNSResult:
    """Result of a DNS lookup."""
    rcode: str  # NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT, etc.
    answers: List[str]
    ttl: int

# --------------------------------------------------------------------
# Setter API for application to centrally configure resolver & semaphore
# --------------------------------------------------------------------
def set_default_resolver(resolver: dns.asyncresolver.Resolver) -> None:
    """
    Set a custom default resolver instance to be used by get_default_resolver().
    Call this from dns_application at startup to centralize resolver configuration.
    """
    global _default_resolver
    _default_resolver = resolver
    try:
        logger.info("Default resolver injected by application (nameservers={})", getattr(resolver, "nameservers", None))
    except Exception:
        # If logger is loguru adapter, it may expect different formatting; keep it safe
        try:
            logger.info(f"Default resolver injected by application (nameservers={getattr(resolver, 'nameservers', None)})")
        except Exception:
            pass

def set_default_semaphore(semaphore: Optional[asyncio.Semaphore] = None, *, limit: Optional[int] = None) -> None:
    """
    Configure the default semaphore used by default_semaphore().

    Usage:
      - pass an asyncio.Semaphore instance: set_default_semaphore(semaphore=my_sem)
      - or pass a numeric limit to set the desired limit (semaphore creation may be deferred until an event loop is available):
            set_default_semaphore(limit=500)
    """
    global _default_semaphore, _default_semaphore_limit
    if semaphore is not None:
        _default_semaphore = semaphore
        try:
            logger.info("Default semaphore injected by application")
        except Exception:
            try:
                logger.info("Default semaphore injected by application")
            except Exception:
                pass
    elif limit is not None:
        _default_semaphore_limit = int(limit)
        try:
            if _default_semaphore is None:
                logger.info("Default semaphore limit set to %d (creation deferred until event loop available)", _default_semaphore_limit)
            else:
                logger.warning("Default semaphore already exists; updated limit stored but existing semaphore not replaced")
        except Exception:
            pass

# --------------------------------------------------------------------
# Internal helpers and main API (mostly unchanged)
# --------------------------------------------------------------------
def _cache_key(rtype: str, name: str) -> str:
    """Generate cache key for a DNS query."""
    return f"{rtype.upper()}:{name.lower()}"

def _serialize_value(rcode: str, answers: List[str], ttl: int) -> bytes:
    """Serialize and compress DNS result for LMDB storage."""
    raw = pickle.dumps((rcode, answers, ttl, time.time()))
    try:
        return zlib.compress(raw, level=6)
    except Exception:
        return raw

def _deserialize_value(data: bytes) -> Optional[Tuple[str, List[str], int, float]]:
    """Deserialize DNS result from LMDB storage, handling optional compression."""
    try:
        try:
            decompressed = zlib.decompress(data)
        except Exception:
            decompressed = data
        return pickle.loads(decompressed)
    except Exception as e:
        try:
            logger.error(f"Failed to deserialize LMDB value: {e}")
        except Exception:
            pass
        return None
# --------------------------------------------------------------------
# Internal helpers and main API (mostly unchanged)
# --------------------------------------------------------------------
def _env_list(name: str) -> Optional[List[str]]:
    try:
        val = os.getenv(name)
        if not val:
            return None
        return [s.strip().upper() for s in val.split(',') if s.strip()]
    except Exception:
        return None

def _cache_enabled_for_type(rtype: str) -> bool:
    """Determine if LMDB caching is enabled for the given record type via env.

    Controls:
      - DNS_CACHE_TYPES: CSV of types to cache (e.g., "NS,SOA,A,AAAA,MX")
      - DNS_CACHE_TXT: if set to 0/false, disables TXT caching
    """
    rt = (rtype or '').upper()
    types = _env_list('DNS_CACHE_TYPES')
    if types is not None:
        if rt not in types:
            return False
    # Special TXT toggle
    if rt == 'TXT':
        try:
            txt_toggle = os.getenv('DNS_CACHE_TXT', '1').strip().lower()
            if txt_toggle in ('0', 'false', 'no', 'off'):
                return False
        except Exception:
            pass
    return True

def _bypass_negative_for_type(rtype: str) -> bool:
    """Check if negative-cache bypass is enabled for this type via env.

    Control: DNS_BYPASS_NEGATIVE_CACHE_TYPES (CSV), or DNS_BYPASS_NEGATIVE_CACHE global.
    """
    rt = (rtype or '').upper()
    list_types = _env_list('DNS_BYPASS_NEGATIVE_CACHE_TYPES')
    if list_types is not None and rt in list_types:
        return True
    try:
        global_toggle = os.getenv('DNS_BYPASS_NEGATIVE_CACHE', '0').strip().lower() in ('1','true','yes','on')
    except Exception:
        global_toggle = False
    return global_toggle

def _min_ttl_for_type(rtype: str, positive_default: int) -> int:
    """Return environment-configured minimum TTL for a record type.

    Env controls (seconds):
      - DNS_MIN_TTL_DEFAULT_S
      - DNS_MIN_TTL_A_S, DNS_MIN_TTL_AAAA_S, DNS_MIN_TTL_NS_S, DNS_MIN_TTL_SOA_S,
        DNS_MIN_TTL_MX_S, DNS_MIN_TTL_PTR_S, DNS_MIN_TTL_TXT_S, DNS_MIN_TTL_CAA_S,
        DNS_MIN_TTL_NAPTR_S, DNS_MIN_TTL_SRV_S
    """
    try:
        # Type-specific
        key = f"DNS_MIN_TTL_{(rtype or '').upper()}_S"
        val = os.getenv(key)
        if val:
            return max(positive_default, int(val))
        # Default
        dval = os.getenv('DNS_MIN_TTL_DEFAULT_S')
        if dval:
            return max(positive_default, int(dval))
    except Exception:
        pass
    return positive_default

def get_default_resolver(nameservers: Optional[List[str]] = None) -> dns.asyncresolver.Resolver:
    """
    Get or create the default resolver for this process.
    
    Args:
        nameservers: List of nameserver IPs. Defaults to ['127.0.0.1'].
    
    Returns:
        Configured dnspython async resolver.
    """
    global _default_resolver
    
    if _default_resolver is None:
        _default_resolver = dns.asyncresolver.Resolver()
        _default_resolver.nameservers = nameservers or ['127.0.0.1']
        _default_resolver.timeout = CONFIG.timeout_s
        _default_resolver.lifetime = CONFIG.lifetime_s
        try:
            logger.info(f"Created default resolver with nameservers: {_default_resolver.nameservers}")
        except Exception:
            pass
    
    return _default_resolver

def default_semaphore(limit: int = DEFAULT_SEMAPHORE_LIMIT) -> asyncio.Semaphore:
    """
    Get or create the default semaphore for throttling.

    Uses an injected semaphore if provided via set_default_semaphore(semaphore=...),
    otherwise uses injected limit (_default_semaphore_limit) or the provided `limit` argument.
    """
    global _default_semaphore, _default_semaphore_limit
    if _default_semaphore is None:
        chosen = limit if limit != DEFAULT_SEMAPHORE_LIMIT else _default_semaphore_limit
        try:
            _default_semaphore = asyncio.Semaphore(chosen)
            try:
                logger.info("Created default semaphore with limit: %d", chosen)
            except Exception:
                pass
        except RuntimeError:
            # No running loop or semaphore creation issue: store limit and create a new Semaphore as best-effort
            _default_semaphore_limit = chosen
            try:
                logger.info("Deferred creation of default semaphore until event loop is available (limit=%d)", chosen)
            except Exception:
                pass
            _default_semaphore = asyncio.Semaphore(chosen)
    return _default_semaphore

def _get_executor() -> ThreadPoolExecutor:
    """Get or create the thread pool executor for LMDB operations."""
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="lmdb")
        try:
            logger.info("Created thread pool executor for LMDB operations")
        except Exception:
            pass
    return _executor

def init_lmdb(
    path: str,
    map_size: int = 10 * 1024 * 1024 * 1024,  # 10GB default
    readonly: bool = False,
    lock: bool = True
) -> lmdb.Environment:
    """
    Initialize LMDB environment for persistent DNS caching.
    """
    global _lmdb_env, _lmdb_readonly
    if _lmdb_env is not None:
        try:
            logger.warning("LMDB already initialized, returning existing environment")
        except Exception:
            pass
        return _lmdb_env  # _lmdb_env is guaranteed non-None here

    os.makedirs(path, exist_ok=True)
    # Allow env to override default mapsize when not explicitly provided
    try:
        if map_size == 10 * 1024 * 1024 * 1024:  # default sentinel
            gb = os.getenv('DNS_LMDB_MAPSIZE_GB')
            if gb:
                map_size = int(gb) * 1024 * 1024 * 1024
    except Exception:
        pass
    env = lmdb.open(
        path,
        map_size=map_size,
        readonly=readonly,
        lock=lock,
        max_dbs=0
    )
    _lmdb_env = env
    _lmdb_readonly = readonly
    try:
        logger.info(f"Initialized LMDB at {path} (readonly={readonly}, map_size={map_size})")
    except Exception:
        pass
    return env

def init_lmdb_ptr(
    path: str,
    map_size: int = 10 * 1024 * 1024 * 1024,
    readonly: bool = False,
    lock: bool = True
) -> lmdb.Environment:
    """
    Initialize secondary LMDB environment for PTR (or other precomputed) cache.
    """
    global _lmdb_env_ptr, _lmdb_ptr_readonly
    if _lmdb_env_ptr is not None:
        try:
            logger.warning("PTR LMDB already initialized, returning existing environment")
        except Exception:
            pass
        return _lmdb_env_ptr

    os.makedirs(path, exist_ok=True)
    # Allow env override for mapsize
    try:
        gb = os.getenv('DNS_LMDB_PTR_MAPSIZE_GB')
        if gb:
            map_size = int(gb) * 1024 * 1024 * 1024
    except Exception:
        pass
    env = lmdb.open(
        path,
        map_size=map_size,
        readonly=readonly,
        lock=lock,
        max_dbs=0
    )
    _lmdb_env_ptr = env
    _lmdb_ptr_readonly = readonly
    try:
        logger.info(f"Initialized PTR LMDB at {path} (readonly={readonly}, map_size={map_size})")
    except Exception:
        pass
    return env

def _grow_lmdb_mapsize(factor: float = 2.0, minimum: int = 5 * 1024 * 1024 * 1024) -> bool:
    """Attempt to grow the LMDB environment map size to accommodate larger DB contents.

    Returns True if mapsize was adjusted, False otherwise.
    """
    global _lmdb_env
    env = _lmdb_env
    if env is None:
        return False
    try:
        info = env.info()
        cur = int(info.get('map_size', 0)) if isinstance(info, dict) else 0
        new_size = max(minimum, int(cur * factor) if cur > 0 else minimum)
        env.set_mapsize(new_size)
        try:
            logger.info(f"LMDB mapsize adjusted from {cur} to {new_size}")
        except Exception:
            pass
        return True
    except Exception as e:
        try:
            logger.warning(f"Failed to adjust LMDB mapsize: {e}")
        except Exception:
            pass
        return False

async def _lmdb_writer_loop():
    """Background task that batches and writes DNS records to LMDB."""
    global _lmdb_write_queue, _lmdb_env
    if _lmdb_write_queue is None or _lmdb_env is None:
        try:
            logger.error("LMDB writer loop started without queue or environment")
        except Exception:
            pass
        return

    batch: Dict[bytes, bytes] = {}
    batch_size = 100
    batch_timeout = 1.0  # seconds
    last_write = time.time()

    try:
        logger.info("LMDB writer loop started")
    except Exception:
        pass

    try:
        while True:
            try:
                timeout = max(0.1, batch_timeout - (time.time() - last_write))
                try:
                    key, value = await asyncio.wait_for(
                        _lmdb_write_queue.get(),
                        timeout=timeout
                    )
                    batch[key] = value
                except asyncio.TimeoutError:
                    pass

                now = time.time()
                should_write = (
                    len(batch) >= batch_size or
                    (batch and (now - last_write) >= batch_timeout)
                )

                if should_write and batch:
                    def _write_batch():
                        env = _lmdb_env
                        if env is None:
                            return 0
                        with env.begin(write=True) as txn:
                            for k, v in batch.items():
                                txn.put(k, v)
                        return len(batch)

                    count = await asyncio.get_event_loop().run_in_executor(
                        _get_executor(),
                        _write_batch
                    )
                    try:
                        logger.debug(f"Wrote {count} entries to LMDB")
                    except Exception:
                        pass
                    batch.clear()
                    last_write = now

            except Exception as e:
                try:
                    logger.error(f"Error in LMDB writer loop: {e}")
                except Exception:
                    pass
                await asyncio.sleep(1.0)

    except asyncio.CancelledError:
        try:
            logger.info("LMDB writer loop cancelled")
        except Exception:
            pass
        raise

def start_lmdb_writer() -> Optional[asyncio.Task]:
    """
    Start the background LMDB writer task.
    """
    global _lmdb_writer_task, _lmdb_write_queue
    if _lmdb_env is None:
        raise RuntimeError("LMDB not initialized. Call init_lmdb() first.")

    if _lmdb_readonly:
        try:
            logger.warning("LMDB is read-only, writer will not start")
        except Exception:
            pass
        return None

    if _lmdb_writer_task is not None and not _lmdb_writer_task.done():
        return _lmdb_writer_task

    _lmdb_write_queue = asyncio.Queue()
    _lmdb_writer_task = asyncio.create_task(_lmdb_writer_loop())
    try:
        logger.info("Started LMDB writer task")
    except Exception:
        pass
    return _lmdb_writer_task

async def _read_from_lmdb(key: str) -> Optional[Tuple[str, List[str], int, float]]:
    """Read a cached DNS result from LMDB (in executor thread)."""
    env = _lmdb_env
    if env is None:
        return None

    def _read(env_local=env, key_local=key):
        try:
            with env_local.begin() as txn:
                data = txn.get(key_local.encode('utf-8'))
                if data is None:
                    return None
                # txn.get may return a buffer-compatible object; convert to bytes for deserialization
                return _deserialize_value(bytes(data))
        except lmdb.MapResizedError:
            # Try to grow mapsize and retry once
            _grow_lmdb_mapsize()
            with env_local.begin() as txn:
                data = txn.get(key_local.encode('utf-8'))
                if data is None:
                    return None
                return _deserialize_value(bytes(data))

    try:
        return await asyncio.get_event_loop().run_in_executor(
            _get_executor(),
            _read
        )
    except Exception as e:
        try:
            logger.error(f"Error reading from LMDB: {e}")
        except Exception:
            pass
        return None

async def _read_from_lmdb_ptr(key: str) -> Optional[Tuple[str, List[str], int, float]]:
    """Read a cached DNS result from secondary PTR LMDB."""
    env = _lmdb_env_ptr
    if env is None:
        return None

    def _read(env_local=env, key_local=key):
        try:
            with env_local.begin() as txn:
                data = txn.get(key_local.encode('utf-8'))
                if data is None:
                    return None
                return _deserialize_value(bytes(data))
        except lmdb.MapResizedError:
            try:
                info = env_local.info()
                cur = int(info.get('map_size', 0)) if isinstance(info, dict) else 0
                new_size = max(5 * 1024 * 1024 * 1024, int(cur * 2) if cur > 0 else 5 * 1024 * 1024 * 1024)
                env_local.set_mapsize(new_size)
            except Exception:
                pass
            with env_local.begin() as txn:
                data = txn.get(key_local.encode('utf-8'))
                if data is None:
                    return None
                return _deserialize_value(bytes(data))

    try:
        return await asyncio.get_event_loop().run_in_executor(
            _get_executor(),
            _read
        )
    except Exception as e:
        try:
            logger.error(f"Error reading from PTR LMDB: {e}")
        except Exception:
            pass
        return None

async def _write_to_lmdb(key: str, rcode: str, answers: List[str], ttl: int):
    """Enqueue a DNS result to be written to LMDB."""
    if _lmdb_env is None or _lmdb_readonly or _lmdb_write_queue is None:
        return

    try:
        value = _serialize_value(rcode, answers, ttl)
        await _lmdb_write_queue.put((key.encode('utf-8'), value))
    except lmdb.MapResizedError:
        # Attempt to grow mapsize and re-enqueue
        _grow_lmdb_mapsize()
        value = _serialize_value(rcode, answers, ttl)
        await _lmdb_write_queue.put((key.encode('utf-8'), value))
    except Exception as e:
        try:
            logger.error(f"Error enqueueing LMDB write: {e}")
        except Exception:
            pass

def _get_from_inmem_cache(key: str) -> Optional[Tuple[str, List[str], int]]:
    """Get a cached DNS result from in-memory cache, respecting TTL."""
    if key not in _inmem_cache:
        return None

    rcode, answers, ttl, timestamp = _inmem_cache[key]
    age = time.time() - timestamp

    if age > ttl:
        # Expired
        del _inmem_cache[key]
        if key in _inmem_cache_order:
            _inmem_cache_order.remove(key)
        return None

    return rcode, answers, ttl

def _put_in_inmem_cache(key: str, rcode: str, answers: List[str], ttl: int):
    """Put a DNS result in in-memory cache with LRU eviction."""
    global _inmem_cache_order
    if key in _inmem_cache:
        if key in _inmem_cache_order:
            _inmem_cache_order.remove(key)
        _inmem_cache_order.append(key)
        _inmem_cache[key] = (rcode, answers, ttl, time.time())
        return

    while len(_inmem_cache) >= INMEM_CACHE_MAX:
        if not _inmem_cache_order:
            break
        oldest_key = _inmem_cache_order.pop(0)
        _inmem_cache.pop(oldest_key, None)

    _inmem_cache[key] = (rcode, answers, ttl, time.time())
    _inmem_cache_order.append(key)

async def get_cached_result(
    rtype: str,
    name: str,
    *,
    only_positive: bool = True,
    include_expired: bool = False,
    env_name: Optional[str] = None
) -> Optional[Tuple[str, List[str], int]]:
    """
    Public helper to read a cached DNS result for `rtype:name` from LMDB.

    Returns (rcode, answers, ttl) if a cached entry exists and meets the
    provided constraints. When `only_positive` is True, requires rcode==NOERROR
    and non-empty answers. When `include_expired` is False, respects TTL and
    returns None for expired entries.
    """
    key = _cache_key(rtype, name)
    # Choose environment: 'ptr' uses secondary LMDB
    if (env_name or '').lower() == 'ptr':
        lmdb_result = await _read_from_lmdb_ptr(key)
    else:
        lmdb_result = await _read_from_lmdb(key)
    if lmdb_result is None:
        return None
    rcode, answers, ttl, timestamp = lmdb_result
    try:
        age = time.time() - timestamp
    except Exception:
        age = ttl + 1
    if not include_expired and age >= ttl:
        return None
    if only_positive and (rcode != 'NOERROR' or not answers):
        return None
    return rcode, (answers or []), ttl

async def perform_lookup(
    rtype: str,
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[str], int]:
    """
    Perform a DNS lookup with caching and inflight dedupe.
    """
    key = _cache_key(rtype, name)

    # Check in-memory cache first
    cached = _get_from_inmem_cache(key)
    if cached is not None:
        return cached

    # Gate LMDB usage by type
    persist_type = _cache_enabled_for_type(rtype) if use_lmdb else False

    # Check LMDB cache
    if persist_type:
        lmdb_result = await _read_from_lmdb(key)
        if lmdb_result is not None:
            rcode, answers, ttl, timestamp = lmdb_result
            age = time.time() - timestamp
            if age < ttl:
                # Optionally bypass negative cache to allow refreshed data to amend LMDB
                is_negative = (rcode != 'NOERROR') or (not answers)
                if _bypass_negative_for_type(rtype) and is_negative:
                    pass  # proceed to actual lookup
                else:
                    _put_in_inmem_cache(key, rcode, answers, ttl)
                    return rcode, answers, ttl

    # Check if lookup is already inflight
    if key in _inflight:
        try:
            return await _inflight[key]
        except Exception:
            pass

    # Create future for inflight dedupe
    future = asyncio.Future()
    _inflight[key] = future

    try:
        # Perform actual lookup
        result = await _do_lookup(rtype, name, resolver, semaphore)

        # Cache result
        rcode, answers, ttl = result
        _put_in_inmem_cache(key, rcode, answers, ttl)

        if persist_type:
            await _write_to_lmdb(key, rcode, answers, ttl)

        # Resolve future for waiting coroutines
        if not future.done():
            future.set_result(result)

        return result

    except Exception as e:
        if not future.done():
            future.set_exception(e)
        raise

    finally:
        _inflight.pop(key, None)

async def _do_lookup(
    rtype: str,
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver],
    semaphore: Optional[asyncio.Semaphore]
) -> Tuple[str, List[str], int]:
    """Perform the actual DNS lookup."""
    if resolver is None:
        resolver = get_default_resolver()

    if semaphore is None:
        semaphore = default_semaphore()

    rdtype = dns.rdatatype.from_text(rtype)

    if _rate_limiter is None:
        try:
            if CONFIG.enable_global_rate_limit and CONFIG.global_qps > 0:
                configure_rate_limiter(CONFIG.global_qps)
                try:
                    logger.info("Global QPS limiter enabled at {}", CONFIG.global_qps)
                except Exception:
                    pass
            else:
                try:
                    logger.info("Global QPS limiter disabled")
                except Exception:
                    pass
        except Exception:
            pass
    if _rate_limiter is not None and CONFIG.enable_global_rate_limit:
        await _rate_limiter.acquire()
        
    async with semaphore:
        try:
            answer = await resolver.resolve(name, rdtype)

            # Extract answers based on type
            answers = []
            if rtype == 'A' or rtype == 'AAAA':
                answers = [str(rdata.address) for rdata in answer]
            elif rtype == 'NS':
                answers = [str(rdata.target).rstrip('.') for rdata in answer]
            elif rtype == 'SOA':
                if len(answer) > 0:
                    answers = [str(answer[0]).split()[0].rstrip('.')]
            elif rtype == 'MX':
                answers = [f"{rdata.preference}:{str(rdata.exchange).rstrip('.')}" for rdata in answer]
            elif rtype == 'TXT':
                # Robust TXT decoding: handle multi-string RDATA and fall back to to_text()/str()
                txt_list: List[str] = []
                for rdata in answer:
                    try:
                        if hasattr(rdata, "strings") and isinstance(rdata.strings, (list, tuple)):
                            parts: List[str] = []
                            for s in rdata.strings:
                                if isinstance(s, (bytes, bytearray)):
                                    parts.append(s.decode("utf-8", errors="ignore"))
                                else:
                                    parts.append(str(s))
                            txt_val = " ".join([p for p in parts if p is not None])
                        else:
                            # dnspython provides to_text(); strip surrounding quotes if present
                            try:
                                txt_val = rdata.to_text().strip('"')
                            except Exception:
                                txt_val = str(rdata).strip('"')
                    except Exception:
                        txt_val = str(rdata)
                    txt_list.append(txt_val)
                answers = txt_list
            elif rtype == 'PTR':
                answers = [str(rdata.target).rstrip('.') for rdata in answer]
            else:
                answers = [str(rdata) for rdata in answer]

            # Get TTL and apply per-type minimum floors to reduce re-lookups
            ttl_raw = int(answer.rrset.ttl) if answer.rrset else POSITIVE_MIN_TTL_SECONDS
            ttl = max(POSITIVE_MIN_TTL_SECONDS, ttl_raw)
            ttl = _min_ttl_for_type(rtype, ttl)

            return 'NOERROR', answers, ttl

        except dns.resolver.NXDOMAIN:
            try:
                neg_ttl = int(os.getenv('DNS_NEGATIVE_TTL_S', str(NEGATIVE_TTL_SECONDS)))
            except Exception:
                neg_ttl = NEGATIVE_TTL_SECONDS
            return 'NXDOMAIN', [], neg_ttl
        except dns.resolver.NoAnswer:
            try:
                neg_ttl = int(os.getenv('DNS_NEGATIVE_TTL_S', str(NEGATIVE_TTL_SECONDS)))
            except Exception:
                neg_ttl = NEGATIVE_TTL_SECONDS
            return 'NODATA', [], neg_ttl
        except dns.resolver.Timeout:
            try:
                neg_ttl = int(os.getenv('DNS_NEGATIVE_TTL_S', str(NEGATIVE_TTL_SECONDS)))
            except Exception:
                neg_ttl = NEGATIVE_TTL_SECONDS
            return 'TIMEOUT', [], neg_ttl
        except dns.exception.DNSException as e:
            if 'SERVFAIL' in str(e):
                try:
                    neg_ttl = int(os.getenv('DNS_NEGATIVE_TTL_S', str(NEGATIVE_TTL_SECONDS)))
                except Exception:
                    neg_ttl = NEGATIVE_TTL_SECONDS
                return 'SERVFAIL', [], neg_ttl
            try:
                neg_ttl = int(os.getenv('DNS_NEGATIVE_TTL_S', str(NEGATIVE_TTL_SECONDS)))
            except Exception:
                neg_ttl = NEGATIVE_TTL_SECONDS
            return 'ERROR', [], neg_ttl

# Typed lookup helpers

async def lookup_a(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[str], int]:
    """Lookup A records."""
    return await perform_lookup('A', name, resolver, semaphore, use_lmdb)

async def lookup_aaaa(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[str], int]:
    """Lookup AAAA records."""
    return await perform_lookup('AAAA', name, resolver, semaphore, use_lmdb)

async def lookup_ns(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[str], int]:
    """Lookup NS records."""
    return await perform_lookup('NS', name, resolver, semaphore, use_lmdb)

async def lookup_soa(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[str], int]:
    """Lookup SOA records with fallback to parent zones.

    Many hostnames (e.g., "www.example.com") do not have an SOA RR at that label.
    DNS responses for SOA at such names often return NODATA with the zone's SOA
    only in the authority section. To make SOA retrieval practical for arbitrary
    hostnames, we fall back to querying parent labels until we find a zone apex
    SOA (e.g., "example.com").

    Returns (rcode, answers, ttl) where answers contain the mname string(s).
    """
    # First, try the name itself
    rcode, answers, ttl = await perform_lookup('SOA', name, resolver, semaphore, use_lmdb)
    if rcode == 'NOERROR' and answers:
        return rcode, answers, ttl

    # If no SOA found at the name (NODATA or empty answers), walk up parent labels
    try:
        labels = name.rstrip('.').split('.')
    except Exception:
        labels = [name]

    for i in range(1, len(labels)):
        candidate = '.'.join(labels[i:])
        r2, a2, t2 = await perform_lookup('SOA', candidate, resolver, semaphore, use_lmdb)
        if r2 == 'NOERROR' and a2:
            return r2, a2, t2

    # Final attempt: query the TLD/root candidate if not already covered
    if labels:
        candidate = labels[-1]
        if candidate and candidate != name:
            r3, a3, t3 = await perform_lookup('SOA', candidate, resolver, semaphore, use_lmdb)
            if r3 == 'NOERROR' and a3:
                return r3, a3, t3

    # Fall back to the original result (likely NODATA/NXDOMAIN/SERVFAIL)
    return rcode, answers, ttl

async def lookup_mx(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[str], int]:
    """Lookup MX records."""
    return await perform_lookup('MX', name, resolver, semaphore, use_lmdb)

async def lookup_txt(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[str], int]:
    """Lookup TXT records."""
    # Allow disabling LMDB cache for TXT via env var to avoid negative-cache issues during batch runs
    try:
        env_val = os.getenv("DNS_CACHE_TXT", "1").strip().lower()
        if env_val in ("0", "false", "no", "off"):
            use_lmdb = False
    except Exception:
        pass
    
    # Debug logging for TXT
    try:
        logger.info(f"lookup_txt for {name} (use_lmdb={use_lmdb})")
    except Exception:
        pass

    result = await perform_lookup('TXT', name, resolver, semaphore, use_lmdb)
    
    try:
        rcode, answers, ttl = result
        logger.info(f"lookup_txt result for {name}: rcode={rcode}, answers={answers}")
    except Exception:
        pass
        
    return result

async def lookup_ptr(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[str], int]:
    """Lookup PTR records."""
    return await perform_lookup('PTR', name, resolver, semaphore, use_lmdb)

# --- Structured parsers for CAA/NAPTR/SRV ---

def _parse_caa_answers(answers: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in answers:
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

def _parse_naptr_answers(answers: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in answers:
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

def _parse_srv_answers(answers: List[str], service: Optional[str] = None, proto: Optional[str] = None, ttl: Optional[int] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for s in answers:
        try:
            m = re.match(r"^(\d+)\s+(\d+)\s+(\d+)\s+([^\s]+)$", s)
            if m:
                prio = int(m.group(1))
                weight = int(m.group(2))
                port = int(m.group(3))
                target = m.group(4).rstrip('.')
                out.append({
                    "priority": prio,
                    "weight": weight,
                    "port": port,
                    "target": target,
                    "service": service,
                    "proto": proto,
                    "ttl": ttl,
                })
            else:
                out.append({
                    "priority": None,
                    "weight": None,
                    "port": None,
                    "target": s.rstrip('.'),
                    "service": service,
                    "proto": proto,
                    "ttl": ttl,
                })
        except Exception:
            out.append({
                "priority": None,
                "weight": None,
                "port": None,
                "target": s,
                "service": service,
                "proto": proto,
                "ttl": ttl,
            })
    return out

async def lookup_caa_struct(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[Dict[str, Any]], int]:
    """Lookup CAA and return structured entries."""
    rcode, answers, ttl = await perform_lookup('CAA', name, resolver, semaphore, use_lmdb)
    return rcode, _parse_caa_answers(answers), ttl

async def lookup_naptr_struct(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[Dict[str, Any]], int]:
    """Lookup NAPTR and return structured entries."""
    rcode, answers, ttl = await perform_lookup('NAPTR', name, resolver, semaphore, use_lmdb)
    return rcode, _parse_naptr_answers(answers), ttl

async def lookup_srv_struct(
    service_fqdn: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[Dict[str, Any]], int]:
    """Lookup SRV and return structured entries including service/proto and TTL."""
    rcode, answers, ttl = await perform_lookup('SRV', service_fqdn, resolver, semaphore, use_lmdb)
    try:
        parts = service_fqdn.split('.')
        service = parts[0] if parts else None
        proto = parts[1] if len(parts) > 1 else None
    except Exception:
        service, proto = None, None
    return rcode, _parse_srv_answers(answers, service=service, proto=proto, ttl=ttl), ttl

async def lookup_soa_struct(
    name: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    use_lmdb: bool = True
) -> Tuple[str, List[Dict[str, Any]], int]:
    """Lookup SOA and return structured fields with parent-zone fallback.

    Fields: mname, rname, serial, refresh, retry, expire, minimum.
    Returns (rcode, [struct], ttl). If SOA is not at the queried label,
    walks up parent labels to find the zone apex SOA.
    """
    def _parse_soa_string(s: str) -> Dict[str, Any]:
        parts = s.split()
        out: Dict[str, Any] = {}
        try:
            out["mname"] = parts[0].rstrip('.') if len(parts) > 0 else ""
            out["rname"] = parts[1].rstrip('.') if len(parts) > 1 else ""
            out["serial"] = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
            out["refresh"] = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else None
            out["retry"] = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else None
            out["expire"] = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else None
            out["minimum"] = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else None
        except Exception:
            pass
        return out

    # First attempt: SOA at the name
    rcode, answers, ttl = await perform_lookup('SOA', name, resolver, semaphore, use_lmdb)
    if rcode == 'NOERROR' and answers:
        return rcode, [_parse_soa_string(answers[0])], ttl

    # Walk parent labels to find zone apex SOA
    try:
        labels = name.rstrip('.').split('.')
    except Exception:
        labels = [name]
    for i in range(1, len(labels)):
        candidate = '.'.join(labels[i:])
        r2, a2, t2 = await perform_lookup('SOA', candidate, resolver, semaphore, use_lmdb)
        if r2 == 'NOERROR' and a2:
            return r2, [_parse_soa_string(a2[0])], t2

    # Final attempt: TLD label
    if labels:
        candidate = labels[-1]
        if candidate and candidate != name:
            r3, a3, t3 = await perform_lookup('SOA', candidate, resolver, semaphore, use_lmdb)
            if r3 == 'NOERROR' and a3:
                return r3, [_parse_soa_string(a3[0])], t3

    return rcode, [], ttl

async def check_changed_and_enqueue_update(
    rtype: str,
    name: str,
    rcode: str,
    answers: List[str],
    ttl: int
) -> bool:
    """
    Check if DNS result has changed compared to LMDB cache and enqueue update.
    """
    key = _cache_key(rtype, name)

    # Read from LMDB
    lmdb_result = await _read_from_lmdb(key)

    if lmdb_result is None:
        # Not in cache, consider it changed
        await _write_to_lmdb(key, rcode, answers, ttl)
        return True

    cached_rcode, cached_answers, cached_ttl, timestamp = lmdb_result

    # Normalize None and strings to list for robust comparison
    if cached_answers is None:
        cached_answers = []
    if answers is None:
        answers = []
    if isinstance(cached_answers, str):
        cached_answers = [cached_answers]
    if isinstance(answers, str):
        answers = [answers]

    # Compare results: changed if rcode differs or answers content differs
    try:
        changed = (
            rcode != cached_rcode or
            sorted(answers) != sorted(cached_answers)
        )
    except Exception:
        changed = True

    if changed:
        # Enqueue update to LMDB
        await _write_to_lmdb(key, rcode, answers, ttl)

    return changed

def inmem_cache_clear():
    """Clear the in-memory cache. Useful for testing."""
    global _inmem_cache, _inmem_cache_order
    _inmem_cache.clear()
    _inmem_cache_order.clear()
    try:
        logger.info("Cleared in-memory DNS cache")
    except Exception:
        pass

async def shutdown():
    """Shutdown DNS lookup module, flushing caches and stopping background tasks."""
    global _lmdb_writer_task, _lmdb_write_queue, _lmdb_env, _executor
    global _default_resolver, _default_semaphore
    try:
        logger.info("Shutting down DNS lookup module")
    except Exception:
        pass

    if _lmdb_writer_task is not None and not _lmdb_writer_task.done():
        _lmdb_writer_task.cancel()
        try:
            await _lmdb_writer_task
        except asyncio.CancelledError:
            pass
        _lmdb_writer_task = None

    if _lmdb_write_queue is not None:
        while not _lmdb_write_queue.empty():
            try:
                _lmdb_write_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        _lmdb_write_queue = None

    if _lmdb_env is not None:
        _lmdb_env.close()
        _lmdb_env = None
        try:
            logger.info("Closed LMDB environment")
        except Exception:
            pass

    if _executor is not None:
        _executor.shutdown(wait=True)
        _executor = None
        try:
            logger.info("Shutdown thread pool executor")
        except Exception:
            pass

    inmem_cache_clear()
    _inflight.clear()

    _default_resolver = None
    _default_semaphore = None

    try:
        logger.info("DNS lookup module shutdown complete")
    except Exception:
        pass

# --- Small helpers for cross-module coordination ---
def is_lmdb_readonly() -> bool:
    """Return True if the current LMDB environment is read-only or not initialized."""
    try:
        return bool(_lmdb_env is None or _lmdb_readonly)
    except Exception:
        return True