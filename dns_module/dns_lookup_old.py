from __future__ import annotations
import asyncio
import aiodns
import random
import os
import ipaddress
import logging
import warnings
from typing import Optional, Tuple, List, Callable, Dict, Any
import sys

Logger = Callable[[str], None]
logger = logging.getLogger("dns.dns_lookup")

# Suppress aiodns inotify warnings - these are informational only
class AiodnsInotifyWarningFilter(logging.Filter):
    """Filter out aiodns c-ares inotify warnings which are informational only."""
    def filter(self, record):
        msg = record.getMessage()
        return not (
            "Failed to initialize c-ares channel" in msg or
            "Failed to create DNS resolver channel" in msg or
            "inotify" in msg.lower()
        )

# Apply filter to aiodns logger
aiodns_logger = logging.getLogger("aiodns")
aiodns_logger.addFilter(AiodnsInotifyWarningFilter())

# Also suppress Python warnings with similar messages
warnings.filterwarnings("ignore", message=".*Failed to initialize c-ares channel.*")
warnings.filterwarnings("ignore", message=".*Failed to create DNS resolver channel.*")

GLOBAL_NAMESERVERS = ["127.0.0.1"]
FALLBACK_NAMESERVERS = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]


class DNSLookup:
    """
    DNSLookup: a high-level wrapper around aiodns with:
      - robust retry/fallback logic (_retry_resolve)
      - core-first probe flow (NS -> SOA -> A) with short-circuiting
      - expand_probes for optional heavier probes (MX/TXT/DNSKEY/RRSIG, subhosts)
      - per-instance (or shared) PTR, host and core caches to dedupe reverse/host/domain lookups
      - utilities to extract A/AAAA/NS/MX/PTR/SOA etc.
    """

    def __init__(
        self,
        dns_timeout_s: float = 2.0,
        retries: int = 2,
        per_domain_max_concurrency: int = 6,
        logger: Optional[Callable[[str], None]] = None,  # Simplified logger type
        nameservers: Optional[List[str]] = None,
        ptr_cache: Optional[Dict[str, Optional[str]]] = None,
        host_cache: Optional[Dict[str, Dict[str, Any]]] = None,
        core_cache: Optional[Dict[str, Dict[str, Any]]] = None,
        fallback_resolvers: Optional[List[str]] = None,
    ):
        self._dns_timeout_s = dns_timeout_s
        self._retries = retries
        self._gate = asyncio.Semaphore(per_domain_max_concurrency)
        # use provided logger callable or a no-op
        self.log: Callable[[str], None] = logger or (lambda _msg: None)
        self.nameservers = list(nameservers) if nameservers else []
        # PTR cache: ip -> ptr_name or None
        self._ptr_cache: Dict[str, Optional[str]] = ptr_cache if ptr_cache is not None else {}
        # Host cache: hostname -> dict of probe results
        self._host_cache: Dict[str, Dict[str, Any]] = host_cache if host_cache is not None else {}
        # Track hostnames seen within a single fetch run (cleared per fetch if needed)
        self._seen_host_probes = set()
        # Core cache: domain -> merged probe results (core + expanded)
        # Can be shared across batch by passing core_cache in constructor
        self._core_cache: Dict[str, Dict[str, Any]] = core_cache if core_cache is not None else {}
        # Use provided fallback_resolvers, or default
        self.fallback_nameservers = fallback_resolvers if fallback_resolvers is not None else FALLBACK_NAMESERVERS

        # Instance-specific resolver and PID to handle forking
        self._resolver: Optional[aiodns.DNSResolver] = None
        self._resolver_pid: Optional[int] = None

        # Pre-created fallback resolvers (to avoid inotify exhaustion)
        self._fallback_resolvers: List[aiodns.DNSResolver] = []
        self._fallback_pid: Optional[int] = None

    async def _ensure_resolver(self) -> aiodns.DNSResolver:
        """
        Ensure we have an instance-level resolver, recreating it if the PID changes.
        """
        current_pid = os.getpid()
        if self._resolver is None or self._resolver_pid != current_pid:
            tries = max(1, int(self._retries or 1))
            try:
                if self.nameservers:
                    self._resolver = aiodns.DNSResolver(
                        nameservers=self.nameservers, timeout=self._dns_timeout_s, tries=tries
                    )
                else:
                    self._resolver = aiodns.DNSResolver(timeout=self._dns_timeout_s, tries=tries)
                self._resolver_pid = current_pid
                self.log(f"[DNSLookup] created per-instance aiodns resolver (timeout={self._dns_timeout_s}, tries={tries})")
            except Exception as e:
                self.log(f"[DNSLookup] failed to create resolver: {e}, trying fallback")
                try:
                    self._resolver = aiodns.DNSResolver(nameservers=["127.0.0.1", "::1"], timeout=self._dns_timeout_s, tries=tries)
                    self._resolver_pid = current_pid
                    self.log(f"[DNSLookup] created fallback per-instance resolver (127.0.0.1, timeout={self._dns_timeout_s}, tries={tries})")
                except Exception as fallback_e:
                    self.log(f"[DNSLookup] fallback resolver creation failed: {fallback_e}")
                    raise
        return self._resolver

    async def _ensure_fallback_resolvers(self) -> List[aiodns.DNSResolver]:
        """
        Ensure pre-created fallback resolvers for fallback nameservers; recreate on fork.
        """
        current_pid = os.getpid()
        if not self._fallback_resolvers or self._fallback_pid != current_pid:
            self._fallback_resolvers = []
            tries = 1
            for ns in self.fallback_nameservers:
                try:
                    resolver = aiodns.DNSResolver(nameservers=[ns], timeout=self._dns_timeout_s, tries=tries)
                    self._fallback_resolvers.append(resolver)
                    self.log(f"[DNSLookup] Created fallback resolver for {ns}")
                except Exception as e:
                    self.log(f"[DNSLookup] Failed to create fallback resolver for {ns}: {e}")
            self._fallback_pid = current_pid
        return self._fallback_resolvers

    async def _retry_resolve(self, name: str, rtype: str, retries: Optional[int] = None, timeout_s: Optional[float] = None):
        """
        Perform a DNS query with retries and fallback resolvers, protected by the instance-level semaphore.
        Returns (answer, status) where status is one of "NOERROR","NXDOMAIN","NODATA","SERVFAIL","TIMEOUT","REFUSED","ERROR".
        """
        name = name.strip().lower()
        r = await self._ensure_resolver()
        effective_retries = retries if retries is not None else self._retries or 2
        effective_timeout = timeout_s if timeout_s is not None else self._dns_timeout_s or 2.0
        last_status = ""
        try:
            for i in range(effective_retries + 1):
                method = getattr(r, "query", getattr(r, "resolve", None))
                if method is None:
                    self.log("[DNSLookup] resolver has no query/resolve method")
                    return None, "ERROR"
                try:
                    self.log(f"[DNSLookup] starting {rtype} lookup for {name} (attempt {i+1}/{effective_retries+1})")
                    async with self._gate:
                        ans = await asyncio.wait_for(method(name, rtype), timeout=effective_timeout)
                    self.log(f"[DNSLookup] {rtype} lookup succeeded for {name}")
                    return ans, "NOERROR"
                except Exception as e:
                    msg = str(e).upper()
                    error_code = None
                    error_msg = msg
                    if hasattr(e, "args") and len(e.args) >= 2:
                        try:
                            error_code = int(e.args[0])
                            error_msg = str(e.args[1]).upper()
                            msg = f"Code {error_code}: {error_msg}"
                        except (ValueError, TypeError):
                            pass

                    # Definitive negative answers
                    if "NXDOMAIN" in msg or ("NAME" in msg and "NOTFOUND" in msg):
                        self.log(f"[DNSLookup] NXDOMAIN for {name}")
                        return None, "NXDOMAIN"

                    if "INVALID QUERY TYPE" in msg or (rtype in ["RRSIG", "DNSKEY"] and ("NO DATA" in msg or error_code == 1)):
                        self.log(f"[DNSLookup] {rtype} query not supported or no data for {name}")
                        return None, "NODATA"

                    if "SERVFAIL" in msg:
                        last_status = "SERVFAIL"
                    elif "TIMEOUT" in msg or "TIME OUT" in msg:
                        last_status = "TIMEOUT"
                    elif "REFUSED" in msg:
                        last_status = "REFUSED"
                    elif "NO DATA" in msg or error_code == 1:
                        last_status = "NODATA"
                        self.log(f"[DNSLookup] No {rtype} records found for {name}")
                    else:
                        last_status = "ERROR"
                        self.log(f"[DNSLookup] Error for {name} ({rtype}): {msg}")

                    # Do not retry on definitive answers
                    if last_status in {"NODATA", "NXDOMAIN"}:
                        return None, last_status

                    if i < effective_retries and (last_status in {"SERVFAIL", "TIMEOUT", "REFUSED", "TRY_AGAIN"}):
                        delay = 0.25 * (2 ** i) * (0.6 + 0.8 * random.random())
                        self.log(f"[DNSLookup] {rtype} retry {i+1}/{effective_retries} for {name} after {delay:.2f}s ({last_status})")
                        await asyncio.sleep(delay)
                        continue

                    if last_status not in {"NODATA"}:
                        self.log(f"[DNSLookup] Final attempt failed for {name} with status: {last_status}")
                    return None, last_status or "ERROR"
            return None, last_status or "ERROR"
        except Exception as e:
            msg = f"Unexpected error: {str(e)}"
            self.log(f"[DNSLookup] {msg} for {name}")
            return None, "ERROR"

    # -------------------- Reusable extractors --------------------
    @staticmethod
    def _extract_a(ans) -> List[str]:
        try:
            return [r.host for r in ans] if ans else []
        except Exception:
            try:
                return [ans.host] if hasattr(ans, "host") else []
            except Exception:
                return []

    @staticmethod
    def _extract_aaaa(ans) -> List[str]:
        try:
            return [r.host for r in ans] if ans else []
        except Exception:
            try:
                return [ans.host] if hasattr(ans, "host") else []
            except Exception:
                return []

    @staticmethod
    def _extract_ns(ans) -> List[str]:
        try:
            return [r.host for r in ans] if ans else []
        except Exception:
            try:
                return [ans.host] if hasattr(ans, "host") else []
            except Exception:
                return []

    @staticmethod
    def _extract_mx(ans) -> List[Tuple[int, str]]:
        try:
            return [(r.preference if hasattr(r, "preference") else getattr(r, "priority", 0),
                     str(getattr(r, "exchange", getattr(r, "host", getattr(r, "name", r)))).rstrip(".").lower()
                     ) for r in ans] if ans else []
        except Exception:
            return []

    @staticmethod
    def _extract_ptr(ans) -> Optional[str]:
        try:
            if isinstance(ans, list) and len(ans) > 0:
                r = ans[0]
                return getattr(r, "name", None) or getattr(r, "host", None) or getattr(r, "target", None)
            if hasattr(ans, "name"):
                return getattr(ans, "name")
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_soa(ans) -> Optional[str]:
        try:
            if not ans:
                return None
            if hasattr(ans, "mname"):
                return getattr(ans, "mname")
            if isinstance(ans, list) and len(ans) > 0 and hasattr(ans[0], "mname"):
                return getattr(ans[0], "mname")
        except Exception:
            pass
        return None

    @staticmethod
    def _derive_status_from_responses(responses: List[Any]) -> Optional[str]:
        for r in responses:
            if r is None:
                continue
            if isinstance(r, Exception):
                msg = str(r).lower()
                if "nxdomain" in msg:
                    return "NXDOMAIN"
                if "refused" in msg or "refuse" in msg:
                    return "REFUSED"
                if "servfail" in msg or "server failure" in msg or "general failure" in msg:
                    return "SERVFAIL"
        return "NOERROR"

    # -------------------- PTR cache helper (dedupe) --------------------
    async def resolve_ptr_once(self, ip_addr: str) -> Optional[str]:
        """
        Resolve PTR for ip_addr using per-instance (or shared) cache.
        Returns PTR value string or None if no PTR / NXDOMAIN.
        Always caches negative results to avoid repeated failing PTR queries.
        """
        if not ip_addr:
            return None
        ip_norm = str(ip_addr)
        if ip_norm in self._ptr_cache:
            self.log(f"[DNSLookup] PTR cache hit for {ip_norm} -> {self._ptr_cache[ip_norm]!r}")
            return self._ptr_cache[ip_norm]

        try:
            ip = ipaddress.ip_address(ip_norm)
            rev_name = ip.reverse_pointer
        except Exception:
            parts = ip_norm.split(".")
            rev_name = ".".join(reversed(parts)) + ".in-addr.arpa"

        try:
            # Use a single retry and modest timeout for PTR to avoid long delays
            ans, status = await self._retry_resolve(rev_name, "PTR", retries=1, timeout_s=min(3.0, self._dns_timeout_s))
            if ans:
                ptr_val = self._extract_ptr(ans)
            else:
                # No answer or explicit negative status -> treat as no PTR
                ptr_val = None
            # Cache result (including None) to avoid repeated queries
            self._ptr_cache[ip_norm] = ptr_val
            self.log(f"[DNSLookup] PTR lookup for {ip_norm} -> {ptr_val!r} (status={status})")
            return ptr_val
        except Exception as e:
            # On unexpected errors, cache negative to avoid hammering
            self.log(f"[DNSLookup] PTR error for {rev_name}: {e}")
            self._ptr_cache[ip_norm] = None
            return None

    # Backwards-compatible: keep resolve_ptr_first but delegate to resolve_ptr_once
    async def resolve_ptr_first(self, ip: str, timeout_s: float = 3.0) -> str:
        res = await self.resolve_ptr_once(ip)
        return res or ""

    # -------------------- Existing utilities preserved and slightly adapted --------------------
    async def resolve_txt_join(self, name: str) -> List[str]:
        resp = await self._retry_resolve(name, "TXT")
        if not resp:
            return []
        ans, _ = resp
        if not ans:
            return []
        out: List[str] = []
        try:
            for rr in ans:
                text = getattr(rr, "text", None)
                if text is None:
                    strings = getattr(rr, "strings", None) or getattr(rr, "strings_", None) or []
                    s = "".join([b.decode() if isinstance(b, (bytes, bytearray)) else str(b) for b in strings])
                    out.append(s)
                    continue
                out.append(text.decode() if isinstance(text, (bytes, bytearray)) else str(text))
        except TypeError:
            rr = ans
            text = getattr(rr, "text", None)
            if text is None:
                strings = getattr(rr, "strings", None) or getattr(rr, "strings_", None) or []
                s = "".join([b.decode() if isinstance(b, (bytes, bytearray)) else str(b) for b in strings])
                out.append(s)
            else:
                out.append(text.decode() if isinstance(text, (bytes, bytearray)) else str(text))
        return out

    async def resolve_txt_joined(self, name: str) -> str:
        parts = await self.resolve_txt_join(name)
        return " | ".join(parts) if parts else ""

    async def resolve_a_aaaa(self, name: str, want_ipv6: bool = True) -> Tuple[List[str], List[str], Optional[int], str]:
        a_list: List[str] = []
        aaaa_list: List[str] = []
        ttl_min: Optional[int] = None
        a_status: str = "NOERROR"
        aaaa_status: str = "NOERROR"

        async def _one(qtype: str):
            nonlocal ttl_min, a_status, aaaa_status
            resp = await self._retry_resolve(name, qtype)
            if not resp:
                status = "ERROR"
                if qtype == "A":
                    a_status = status
                else:
                    aaaa_status = status
                return []
            ans, status = resp
            if qtype == "A":
                a_status = status
            else:
                aaaa_status = status
            if not ans:
                return []
            records = []
            try:
                for rr in ans:
                    records.append(rr)
            except TypeError:
                records = [ans]

            t = None
            try:
                rrset = getattr(ans, "rrset", None)
                if rrset is not None:
                    t = getattr(rrset, "ttl", None)
                if t is None:
                    t = getattr(ans, "ttl", None)
                if t is None:
                    first_rr = records[0] if records else None
                    if first_rr is not None:
                        t = getattr(first_rr, "ttl", None) or getattr(first_rr, "expiration", None)
                try:
                    t = int(t) if t is not None else None
                except Exception:
                    t = None
                if t is not None and t <= 0:
                    t = None
                if t:
                    ttl_min = t if ttl_min is None else min(ttl_min, t)
            except Exception:
                pass

            for rr in records:
                ip = None
                for attr in ("address", "host", "name"):
                    val = getattr(rr, attr, None)
                    if isinstance(val, (bytes, bytearray)):
                        try:
                            val = val.decode()
                        except Exception:
                            continue
                    if val:
                        ip = str(val).strip()
                        break
                if not ip:
                    for attr in ("to_text",):
                        val = getattr(rr, attr, None)
                        if val:
                            ip = str(val).strip()
                            break
                if not ip:
                    try:
                        ip = str(rr)
                    except Exception:
                        ip = None
                if not ip:
                    continue
                try:
                    ipaddress.ip_address(ip)
                    if qtype == "A":
                        a_list.append(ip)
                    else:
                        aaaa_list.append(ip)
                except Exception:
                    continue

        await asyncio.gather(
            _one("A"),
            _one("AAAA") if want_ipv6 else asyncio.sleep(0),
        )
        return sorted(set(a_list)), sorted(set(aaaa_list)), ttl_min, a_status

    async def resolve_ptr_first(self, ip: str, timeout_s: float = 3.0) -> str:
        if not ip:
            return ""
        try:
            resp = await self._retry_resolve(ipaddress.ip_address(ip).reverse_pointer, "PTR", timeout_s=timeout_s)
            if not resp:
                return ""
            ans, _ = resp
            for rr in ans or []:
                host = str(getattr(rr, "target", getattr(rr, "name", rr))).rstrip(".").lower()
                if host:
                    return host
        except Exception:
            pass
        return ""

    async def resolve_ns_first(self, name: str) -> Tuple[str, Optional[int], str]:
        resp = await self._retry_resolve(name, "NS")
        if not resp:
            return "", None, "NXDOMAIN"
        ans, status = resp
        if not ans:
            return "", None, status or "NXDOMAIN"
        ttl = getattr(ans, "ttl", None)
        records = []
        try:
            for rr in ans:
                records.append(rr)
        except TypeError:
            records = [ans]
        if ttl is None and records:
            ttl = getattr(records[0], "ttl", None)
        try:
            ttl = int(ttl) if ttl is not None else None
        except Exception:
            ttl = None
        if ttl is not None and ttl <= 0:
            ttl = None
        if records:
            hosts = [str(getattr(r, "host", str(r))).rstrip(".").lower() for r in records]
            return ", ".join(hosts), int(ttl or 0), status or "NOERROR"
        return "", int(ttl or 0), status or "NOERROR"

    async def resolve_soa(self, name: str) -> Tuple[str, Optional[int], Optional[int], str]:
        resp = await self._retry_resolve(name, "SOA")
        if not resp:
            return "", None, None, "NXDOMAIN"
        ans, status = resp
        if not ans:
            return "", None, None, status or "NXDOMAIN"
        ttl = getattr(ans, "ttl", None)
        records = []
        try:
            for rr in ans:
                records.append(rr)
        except TypeError:
            records = [ans]
        for rr in records:
            mname = str(getattr(rr, "mname", getattr(rr, "name", rr))).rstrip(".").lower()
            serial = getattr(rr, "serial", None)
            if ttl is None:
                ttl = getattr(rr, "ttl", None)
            try:
                ttl = int(ttl) if ttl is not None else None
            except Exception:
                ttl = None
            if ttl is not None and ttl <= 0:
                ttl = None
            return mname, int(ttl or 0), serial, "NOERROR"
        try:
            ttl = int(ttl) if ttl is not None else None
        except Exception:
            ttl = None
        if ttl is not None and ttl <= 0:
            ttl = None
        return "", int(ttl or 0), None, "NOERROR"

    async def resolve_mx_primary(self, name: str) -> Tuple[str, Optional[int], str]:
        resp = await self._retry_resolve(name, "MX")
        if not resp:
            return "", None, "ERROR"
        ans, status = resp
        if not ans:
            return "", None, status or "NODATA"
        records = []
        try:
            for rr in ans:
                records.append(rr)
        except TypeError:
            records = [ans]
        mx_pairs = []
        for rr in records:
            pref = int(getattr(rr, "preference", getattr(rr, "priority", 0)))
            host = getattr(rr, "exchange", getattr(rr, "host", getattr(rr, "name", rr)))
            if isinstance(host, (bytes, bytearray)):
                try:
                    host = host.decode()
                except Exception:
                    host = str(host)
            host = str(host).rstrip(".").lower()
            mx_pairs.append((pref, host))
        if not mx_pairs:
            return "", None, status or "NODATA"
        mx_pairs.sort(key=lambda x: x[0])
        return mx_pairs[0][1], mx_pairs[0][0], status or "NOERROR"

    async def cname_chain(self, name: str, limit: int = 5) -> Tuple[str, List[str]]:
        host = name
        chain: List[str] = []
        for _ in range(limit):
            resp = await self._retry_resolve(host, "CNAME")
            if not resp:
                break
            ans, _ = resp
            if not ans:
                break
            try:
                rr = next(iter(ans), None)
            except TypeError:
                rr = ans
            if not rr:
                break
            nxt = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
            if not nxt or nxt == host:
                break
            chain.append(f"{host}->{nxt}")
            host = nxt
        return host, chain

    async def dnssec_flag(self, name: str) -> bool:
        """
        Check DNSSEC presence by trying DNSKEY or RRSIG queries.
        """
        try:
            resp = await self._retry_resolve(name, "DNSKEY")
            if resp and resp[0] and resp[1] == "NOERROR":
                return True
        except Exception:
            pass
        try:
            resp = await self._retry_resolve(name, "RRSIG")
            if resp and resp[0] and resp[1] == "NOERROR":
                return True
        except Exception:
            pass
        return False

    async def run_core_probes(self, domain: str) -> Dict[str, Any]:
        """
        Run essential probes: NS, SOA, A/AAAA.
        Returns a dictionary with raw results and status.
        """
        # Check core cache first
        if domain in self._core_cache:
            # return a copy so we don't mutate cache
            return dict(self._core_cache[domain])

        # Parallelize NS, SOA, A lookups
        async def _ns():
            try:
                return await self.resolve_ns_first(domain)
            except Exception:
                return "", None, "ERROR"

        async def _soa():
            try:
                return await self.resolve_soa(domain)
            except Exception:
                return "", None, None, "ERROR"

        async def _a():
            try:
                return await self.resolve_a_aaaa(domain, want_ipv6=True)
            except Exception:
                return [], [], None, "ERROR"

        results = await asyncio.gather(_ns(), _soa(), _a())
        
        ns_res, soa_res, a_res = results
        ns_ans, ns_ttl, ns_status = ns_res
        soa_mname, soa_ttl, soa_serial, soa_status = soa_res
        a_ips, aaaa_ips, a_ttl, a_status = a_res

        # Determine overall status
        # Priority: NXDOMAIN > SERVFAIL/REFUSED > NOERROR
        statuses = [ns_status, soa_status, a_status]
        final_status = "NOERROR"
        if any("NXDOMAIN" in s for s in statuses):
            final_status = "NXDOMAIN"
        elif any(s in ("SERVFAIL", "REFUSED", "ERROR") for s in statuses):
            # pick the first error
            for s in statuses:
                if s in ("SERVFAIL", "REFUSED", "ERROR"):
                    final_status = s
                    break
        
        return {
            "domain": domain,
            "status": final_status,
            "ns": ns_ans,
            "ns_error": ns_status if ns_status != "NOERROR" else "",
            "soa": soa_mname,
            "soa_serial": soa_serial,
            "soa_error": soa_status if soa_status != "NOERROR" else "",
            "a": a_ips,
            "aaaa": aaaa_ips,
            "a_error": a_status if a_status != "NOERROR" else "",
            "ttl": min(filter(None, [ns_ttl, soa_ttl, a_ttl])) if any([ns_ttl, soa_ttl, a_ttl]) else 0
        }

    # Removed erroneous duplicate expand_probes implementation (contained undefined variable 'resp').

    async def resolve_ns_first(self, name: str) -> Tuple[str, Optional[int], str]:
        resp = await self._retry_resolve(name, "NS")
        if not resp:
            return "", None, "NXDOMAIN"
        ans, status = resp
        if not ans:
            return "", None, status or "NXDOMAIN"
        ttl = getattr(ans, "ttl", None)
        records = []
        try:
            for rr in ans:
                records.append(rr)
        except TypeError:
            records = [ans]
        if ttl is None and records:
            ttl = getattr(records[0], "ttl", None)
        try:
            ttl = int(ttl) if ttl is not None else None
        except Exception:
            ttl = None
        if ttl is not None and ttl <= 0:
            ttl = None
        if records:
            hosts = [str(getattr(r, "host", str(r))).rstrip(".").lower() for r in records]
            return ", ".join(hosts), int(ttl or 0), status or "NOERROR"
        return "", int(ttl or 0), status or "NOERROR"

    async def resolve_soa(self, name: str) -> Tuple[str, Optional[int], Optional[int], str]:
        resp = await self._retry_resolve(name, "SOA")
        if not resp:
            return "", None, None, "NXDOMAIN"
        ans, status = resp
        if not ans:
            return "", None, None, status or "NXDOMAIN"
        ttl = getattr(ans, "ttl", None)
        records = []
        try:
            for rr in ans:
                records.append(rr)
        except TypeError:
            records = [ans]
        for rr in records:
            mname = str(getattr(rr, "mname", getattr(rr, "name", rr))).rstrip(".").lower()
            serial = getattr(rr, "serial", None)
            if ttl is None:
                ttl = getattr(rr, "ttl", None)
            try:
                ttl = int(ttl) if ttl is not None else None
            except Exception:
                ttl = None
            if ttl is not None and ttl <= 0:
                ttl = None
            return mname, int(ttl or 0), serial, "NOERROR"
        try:
            ttl = int(ttl) if ttl is not None else None
        except Exception:
            ttl = None
        if ttl is not None and ttl <= 0:
            ttl = None
        return "", int(ttl or 0), None, "NOERROR"

    async def resolve_mx_primary(self, name: str) -> Tuple[str, Optional[int], str]:
        resp = await self._retry_resolve(name, "MX")
        if not resp:
            return "", None, "ERROR"
        ans, status = resp
        if not ans:
            return "", None, status or "NODATA"
        records = []
        try:
            for rr in ans:
                records.append(rr)
        except TypeError:
            records = [ans]
        mx_pairs = []
        for rr in records:
            pref = int(getattr(rr, "preference", getattr(rr, "priority", 0)))
            host = getattr(rr, "exchange", getattr(rr, "host", getattr(rr, "name", rr)))
            if isinstance(host, (bytes, bytearray)):
                try:
                    host = host.decode()
                except Exception:
                    host = str(host)
            host = str(host).rstrip(".").lower()
            mx_pairs.append((pref, host))
        if not mx_pairs:
            return "", None, status or "NODATA"
        mx_pairs.sort(key=lambda x: x[0])
        return mx_pairs[0][1], mx_pairs[0][0], status or "NOERROR"

    async def cname_chain(self, name: str, limit: int = 5) -> Tuple[str, List[str]]:
        host = name
        chain: List[str] = []
        for _ in range(limit):
            resp = await self._retry_resolve(host, "CNAME")
            if not resp:
                break
            ans, _ = resp
            if not ans:
                break
            try:
                rr = next(iter(ans), None)
            except TypeError:
                rr = ans
            if not rr:
                break
            nxt = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
            if not nxt or nxt == host:
                break
            chain.append(f"{host}->{nxt}")
            host = nxt
        return host, chain

    async def dnssec_flag(self, name: str) -> bool:
        """
        Check DNSSEC presence by trying DNSKEY or RRSIG queries.
        """
        try:
            resp = await self._retry_resolve(name, "DNSKEY")
            if resp and resp[0] and resp[1] == "NOERROR":
                return True
        except Exception:
            pass
        try:
            resp = await self._retry_resolve(name, "RRSIG")
            if resp and resp[0] and resp[1] == "NOERROR":
                return True
        except Exception:
            pass
        return False

    async def expand_probes(self, domain: str, core: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run additional, heavier probes that are not part of the core set.
        These include MX, TXT, DNSKEY, RRSIG, and subdomain probes (www, mail).
        """
        merged = dict(core)
        status = (merged.get("status") or "").upper()
        if status in ("NXDOMAIN",):
            merged["skipped_heavy"] = "NXDOMAIN"
            return merged
        if any(tok in status.lower() for tok in ("servfail", "refused", "error")):
            merged["skipped_heavy"] = f"SERVER_{status}"
            return merged

        # prepare probe tasks
        tasks = []

        async def _mx():
            try:
                ans, st = await self._retry_resolve(domain, "MX")
                merged["mx"] = self._extract_mx(ans) if ans else []
            except Exception as e:
                merged["mx_error"] = str(e)
                self.log(f"[DNSLookup] MX lookup failed for {domain}: {e}")

        async def _txt():
            try:
                ans, st = await self._retry_resolve(domain, "TXT")
                if ans:
                    # aiodns returns bytes/tuples; attempt to normalize
                    merged["txt"] = [getattr(rr, "text", getattr(rr, "strings", None) or "") for rr in ans] if ans else []
                else:
                    merged["txt"] = []
            except Exception as e:
                merged["txt_error"] = str(e)
                self.log(f"[DNSLookup] TXT lookup failed for {domain}: {e}")

        async def _dnskey():
            try:
                ans, st = await self._retry_resolve(domain, "DNSKEY")
                merged["dnskey"] = True if ans else False
            except Exception as e:
                merged["dnskey_error"] = str(e)

        async def _rrsig():
            try:
                ans, st = await self._retry_resolve(domain, "RRSIG")
                merged["rrsig"] = True if ans else False
            except Exception as e:
                merged["rrsig_error"] = str(e)

        tasks.extend([_mx(), _txt(), _dnskey(), _rrsig()])

        # Subdomain probes (www, mail) - use host_cache to dedupe
        subhosts = [f"www.{domain}", f"mail.{domain}"]
        host_probes = []

        async def _probe_host(hostname: str):
            if hostname in self._host_cache:
                merged.setdefault("hosts", {})[hostname] = self._host_cache[hostname]
                self.log(f"[DNSLookup] host cache hit for {hostname}")
                return
            info: Dict[str, Any] = {}
            try:
                a, aaaa, ttl, astatus = await self.resolve_a_aaaa(hostname, want_ipv6=True)
                info["a"] = a
                info["aaaa"] = aaaa
            except Exception as e:
                info["a_error"] = str(e)
            try:
                resp, st = await self._retry_resolve(hostname, "CNAME")
                if resp:
                    info["cname"] = getattr(resp, "cname", getattr(resp, "host", getattr(resp, "name", None)))
            except Exception as e:
                info["cname_error"] = str(e)
            self._host_cache[hostname] = info
            merged.setdefault("hosts", {})[hostname] = info

        for h in subhosts:
            host_probes.append(_probe_host(h))

        tasks.extend(host_probes)

        # Run the collected tasks concurrently (BatchProcessor limits across domains)
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            self.log(f"[DNSLookup] expand_probes gather had exception: {e}")

        # PTR: dedupe unique IPs from apex and host results
        ips = set()
        for ip in merged.get("a", []) or []:
            ips.add(ip)
        hosts_dict = merged.get("hosts", {})
        for hinfo in hosts_dict.values():
            for ip in hinfo.get("a", []) or []:
                ips.add(ip)
            for ip in hinfo.get("aaaa", []) or []:
                ips.add(ip)
        
        unique_ips = list(ips)
        ptr_tasks = [self.resolve_ptr_once(ip) for ip in unique_ips]
        ptr_results_list = await asyncio.gather(*ptr_tasks)
        
        ptr_results: Dict[str, Optional[str]] = {}
        for ip, res in zip(unique_ips, ptr_results_list):
            ptr_results[ip] = res
        merged["ptrs"] = ptr_results

        return merged

    async def fetch_domain(self, domain: str) -> Dict[str, Any]:
        """
        Convenience wrapper: run core probes, then expand_probes if core OK.
        Returns a dict of collected fields (suitable for mapping into your DNSRecords).
        """
        core = await self.run_core_probes(domain)
        expanded = await self.expand_probes(domain, core)
        # store merged/expanded into core cache so subsequent calls reuse results
        try:
            # store a shallow copy to be safe
            self._core_cache[domain] = dict(expanded)
        except Exception:
            # don't let caching failures break fetch flow
            self.log(f"[DNSLookup] failed to cache core result for {domain}")
        return expanded