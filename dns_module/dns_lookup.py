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
DEFAULT_SEMAPHORE_LIMIT = int(os.getenv("DNS_SEMAPHORE_LIMIT", "16"))
INMEM_CACHE_MAX = 150_000
NEGATIVE_TTL_SECONDS = 60
POSITIVE_MIN_TTL_SECONDS = 5

# Backing store for application-injected resolver / semaphore
_default_resolver: Optional[dns.asyncresolver.Resolver] = None
_default_semaphore: Optional[asyncio.Semaphore] = None
_default_semaphore_limit: int = DEFAULT_SEMAPHORE_LIMIT

_lmdb_env: Optional[lmdb.Environment] = None
_lmdb_readonly: bool = True
_lmdb_writer_task: Optional[asyncio.Task] = None
_lmdb_write_queue: Optional[asyncio.Queue] = None
_executor: Optional[ThreadPoolExecutor] = None

# In-memory cache: key -> (rcode, answers, ttl, timestamp)
_inmem_cache: Dict[str, Tuple[str, List[str], int, float]] = {}
_inmem_cache_order: List[str] = []  # LRU tracking

# Inflight dedupe: key -> Future
_inflight: Dict[str, asyncio.Future] = {}

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
    """Serialize DNS result for LMDB storage."""
    return pickle.dumps((rcode, answers, ttl, time.time()))

def _deserialize_value(data: bytes) -> Optional[Tuple[str, List[str], int, float]]:
    """Deserialize DNS result from LMDB storage."""
    try:
        return pickle.loads(data)
    except Exception as e:
        try:
            logger.error(f"Failed to deserialize LMDB value: {e}")
        except Exception:
            pass
        return None

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
        _default_resolver.timeout = 3.0
        _default_resolver.lifetime = 5.0
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
        with env_local.begin() as txn:
            data = txn.get(key_local.encode('utf-8'))
            if data is None:
                return None
            # txn.get may return a buffer-compatible object; convert to bytes for deserialization
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

async def _write_to_lmdb(key: str, rcode: str, answers: List[str], ttl: int):
    """Enqueue a DNS result to be written to LMDB."""
    if _lmdb_env is None or _lmdb_readonly or _lmdb_write_queue is None:
        return

    try:
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

    # Check LMDB cache
    if use_lmdb:
        lmdb_result = await _read_from_lmdb(key)
        if lmdb_result is not None:
            rcode, answers, ttl, timestamp = lmdb_result
            age = time.time() - timestamp
            if age < ttl:
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

        if use_lmdb:
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
                answers = [b''.join(rdata.strings).decode('utf-8', errors='ignore') for rdata in answer]
            elif rtype == 'PTR':
                answers = [str(rdata.target).rstrip('.') for rdata in answer]
            else:
                answers = [str(rdata) for rdata in answer]

            # Get TTL
            ttl = max(POSITIVE_MIN_TTL_SECONDS, int(answer.rrset.ttl) if answer.rrset else POSITIVE_MIN_TTL_SECONDS)

            return 'NOERROR', answers, ttl

        except dns.resolver.NXDOMAIN:
            return 'NXDOMAIN', [], NEGATIVE_TTL_SECONDS
        except dns.resolver.NoAnswer:
            return 'NODATA', [], NEGATIVE_TTL_SECONDS
        except dns.resolver.Timeout:
            return 'TIMEOUT', [], NEGATIVE_TTL_SECONDS
        except dns.exception.DNSException as e:
            if 'SERVFAIL' in str(e):
                return 'SERVFAIL', [], NEGATIVE_TTL_SECONDS
            return 'ERROR', [], NEGATIVE_TTL_SECONDS

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
    """Lookup SOA records."""
    return await perform_lookup('SOA', name, resolver, semaphore, use_lmdb)

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
    return await perform_lookup('TXT', name, resolver, semaphore, use_lmdb)

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

    # Compare results
    changed = (
        rcode != cached_rcode or
        sorted(answers) != sorted(cached_answers)
    )

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
