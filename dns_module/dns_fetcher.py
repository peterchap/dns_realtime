from __future__ import annotations
import asyncio
import datetime
import inspect
import os
import ipaddress
from .logger import get_child_logger
from typing import Optional, List, Any, Dict, cast, Iterable, Tuple
from dotenv import load_dotenv
from .dns_records import DNSRecords, DNSRecord
from . import dns_lookup
from .probes import probe_https_cert, probe_smtp_starttls_cert
from .policy import detect_mta_sts, fetch_tlsrpt_rua
from .dns_utils import (
    to_ascii_hostname, reg_domain, ip_to_int,
    parse_smtp_banner, infer_mbp_from_banner,
    list_to_string
)

load_dotenv()

# Default workers for batch mode
DEFAULT_BATCH_WORKERS = 200

log = get_child_logger("dns_fetcher")

# Simple free CA detection for CAA records
FREE_CA_KEYWORDS = ["letsencrypt", "zerossl"]

class DNSLookup:
    """
    Compatibility wrapper that provides a minimal shim for the legacy DNSLookup class
    used by DNSFetcher. It delegates to the new dns_lookup module functions.
    """

    def __init__(
        self,
        dns_timeout_s: float = 5.0,
        retries: int = 1,
        per_domain_max_concurrency: int = 20,
        logger: Optional[Any] = None,
        nameservers: Optional[List[str]] = None,
        semaphore: Optional[asyncio.Semaphore] = None,
    ):
        self.dns_timeout_s = dns_timeout_s
        self.retries = retries
        self.per_domain_max_concurrency = per_domain_max_concurrency
        self.log = logger if logger is not None else (lambda *a, **k: None)
        # allow optional override of resolver via dns_lookup.set_default_resolver from application
        # nameservers handled by dns_lookup.get_default_resolver(nameservers=...)
        # Prefer local Unbound by default; allow env override via DNS_NAMESERVERS (comma-separated)
        if nameservers is None:
            ns_env = os.getenv("DNS_NAMESERVERS", "127.0.0.1")
            self.nameservers = [s.strip() for s in ns_env.split(",") if s.strip()]
        else:
            self.nameservers = nameservers
        # Build a resolver upfront so we pass it consistently to all lookups
        try:
            self.resolver = dns_lookup.get_default_resolver(nameservers=self.nameservers)
        except Exception:
            # Fallback to module default resolver
            self.resolver = dns_lookup.get_default_resolver()

        # Shared semaphore for throttling all lookups from this instance
        self.semaphore = semaphore or dns_lookup.default_semaphore()

    # --- Basic lookups return shapes compatible with existing callers ---

    async def resolve_ns_first(self, name: str) -> Tuple[List[str], int, Optional[str]]:
        """Return (ns_answers_list, ttl, error_code_or_empty)."""
        try:
            rcode, answers, ttl = await dns_lookup.lookup_ns(name, resolver=self.resolver, semaphore=self.semaphore)
            if rcode == "NOERROR" and answers:
                return answers, ttl, None
            return [], ttl, rcode
        except Exception:
            return [], 0, "ERROR"

    async def resolve_soa(self, name: str) -> Tuple[Optional[str], int, Optional[int], Optional[str]]:
        """
        Return (mname, ttl, soa_serial, error_code_or_none)
        If SOA not present, return (None, 0, None, rcode)
        """
        try:
            rcode, answers, ttl = await dns_lookup.lookup_soa(name, resolver=self.resolver, semaphore=self.semaphore)
            serial: Optional[int] = None
            if rcode == "NOERROR" and answers:
                first = answers[0] if isinstance(answers, list) and answers else None
                mname = str(first) if first else None
                # Try structured SOA to capture serial
                try:
                    r_s, soa_struct_list, _ = await dns_lookup.lookup_soa_struct(name, resolver=self.resolver, semaphore=self.semaphore)
                    if r_s == "NOERROR" and soa_struct_list:
                        serial = soa_struct_list[0].get("serial")
                except Exception:
                    serial = None
                return mname, ttl, serial, None
            return None, ttl, None, rcode
        except Exception:
            return None, 0, None, "ERROR"

    async def resolve_a_aaaa(self, name: str, want_ipv6: bool = True) -> Tuple[List[str], List[str], int, Optional[str]]:
        """
        Return (a_list, aaaa_list, ttl_min, error_code_or_none)
        """
        a_list: List[str] = []
        aaaa_list: List[str] = []
        ttl_min = 0
        err = None
        try:
            rcode_a, answers_a, ttl_a = await dns_lookup.lookup_a(name, resolver=self.resolver, semaphore=self.semaphore)
            if rcode_a == "NOERROR" and answers_a:
                a_list = answers_a
                ttl_min = ttl_a
            else:
                err = rcode_a

            if want_ipv6:
                rcode_aaaa, answers_aaaa, ttl_aaaa = await dns_lookup.lookup_aaaa(name, resolver=self.resolver, semaphore=self.semaphore)
                if rcode_aaaa == "NOERROR" and answers_aaaa:
                    aaaa_list = answers_aaaa
                    ttl_min = ttl_min or ttl_aaaa
                else:
                    if err is None:
                        err = rcode_aaaa
            return a_list, aaaa_list, ttl_min, err
        except Exception:
            return [], [], 0, "ERROR"

    async def dnssec_flag(self, name: str) -> Optional[bool]:
        """Simple probe for DNSSEC: attempt to lookup DNSKEY and return True if present."""
        try:
            rcode, answers, ttl = await dns_lookup.perform_lookup("DNSKEY", name, resolver=self.resolver, semaphore=self.semaphore)
            return bool(rcode == "NOERROR" and answers)
        except Exception:
            return None

    async def _retry_resolve(self, name: str, rtype: str):
        """
        Minimal retry wrapper used by legacy code for CNAME checks etc.
        Returns a tuple whose first item is an iterable of rrset-like objects (we provide raw answers list).
        """
        try:
            rcode, answers, ttl = await dns_lookup.perform_lookup(rtype, name, resolver=self.resolver, semaphore=self.semaphore)
            # return a tuple with first element answers (so calling code using resp[0] works)
            return (answers if answers else [],)
        except Exception:
            return ([],)

    async def resolve_mx_primary(self, name: str) -> Tuple[Optional[str], int, Optional[str]]:
        """
        Return (mx_host_input, mx_pref, err_code)
        dns_lookup.lookup_mx returns strings like "10:mx.example.com"
        """
        try:
            rcode, answers, ttl = await dns_lookup.lookup_mx(name, resolver=self.resolver, semaphore=self.semaphore)
            if rcode == "NOERROR" and answers:
                # choose first MX entry and parse "pref:host" or "pref:host."
                first = answers[0]
                parts = str(first).split(":", 1)
                if len(parts) == 2:
                    pref = int(parts[0])
                    host = parts[1].rstrip(".")
                    return host, pref, None
                else:
                    return str(first).rstrip("."), 0, None
            return None, 0, rcode
        except Exception:
            return None, 0, "ERROR"

    async def resolve_txt_join(self, name: str) -> List[str]:
        """
        Return a list of TXT strings (joined components).
        """
        try:
            rcode, answers, ttl = await dns_lookup.lookup_txt(name, resolver=self.resolver, semaphore=self.semaphore)
            if answers:
                return [str(a) for a in answers]
            return []
        except Exception:
            return []

    async def resolve_txt_joined(self, name: str) -> str:
        """
        Return joined TXT string (used by policy.detect_mta_sts style helpers).
        """
        try:
            txts = await self.resolve_txt_join(name)
            return "".join(txts)
        except Exception:
            return ""

    async def resolve_ptr_first(self, ip: str) -> str:
        """
        Return first PTR target for an IPv4/IPv6 string (or empty string on error).
        """
        try:
            # construct reverse pointer from ipaddress lib
            try:
                ptr_name = ipaddress.ip_address(ip).reverse_pointer
            except Exception:
                # fallback to direct PTR lookup if ip isn't parseable
                return ""
            rcode, answers, ttl = await dns_lookup.lookup_ptr(ptr_name, resolver=self.resolver, semaphore=self.semaphore)
            if rcode == "NOERROR" and answers:
                return answers[0]
            return ""
        except Exception:
            return ""

    async def resolve_ptr_once(self, ip: str) -> str:
        """Alias to resolve_ptr_first"""
        return await self.resolve_ptr_first(ip)

    async def resolve_ptr_first_raw(self, reverse_name: str):
        """Return raw ptr answers for a reverse name"""
        try:
            rcode, answers, ttl = await dns_lookup.lookup_ptr(reverse_name, resolver=self.resolver, semaphore=self.semaphore)
            return answers if answers else []
        except Exception:
            return []

    async def cname_chain(self, name: str, limit: int = 8) -> Tuple[str, List[str]]:
        """
        Try to follow CNAMEs up to `limit`. Returns (final_name, chain_list).
        Uses perform_lookup('CNAME', ...) to find next hop.
        """
        chain: List[str] = []
        cur = name
        hops = 0
        try:
            while hops < limit:
                rcode, answers, ttl = await dns_lookup.perform_lookup("CNAME", cur, resolver=self.resolver, semaphore=self.semaphore)
                # answers will be list of CNAME targets as strings (depending on resolver)
                if not answers:
                    break
                next_host = str(answers[0]).rstrip(".")
                if next_host == cur or not next_host:
                    break
                chain.append(next_host)
                cur = next_host
                hops += 1
            return cur, chain
        except Exception:
            return name, chain

    async def fetch_domain(self, domain: str, retry_limit: int = 1) -> DNSRecord:
        """
        Provide a shim that delegates to module-level fetch_domain using this instance's resolver.
        """
        return await fetch_domain(domain, resolver=self.resolver, semaphore=self.semaphore, retry_limit=retry_limit)

async def fetch_domain(
    domain: str,
    resolver: Optional[Any] = None,
    semaphore: Optional[asyncio.Semaphore] = None,
    retry_limit: int = 1
) -> DNSRecord:
    """
    Fetch DNS records for a domain using the new dns_lookup module.
    
    This function implements the operational design:
    - Fetches core records (NS, SOA, A) concurrently
    - Uses check_changed_and_enqueue_update to detect changes
    - Retries failed core lookups up to retry_limit
    - Fetches grouped records (AAAA, MX, TXT) if core succeeds
    - Batches PTR lookups for discovered IPs
    - Checks www/mail subdomain presence before fetching
    
    Args:
        domain: Domain name to fetch.
        resolver: DNS resolver (uses default if None).
        semaphore: Throttling semaphore (uses default if None).
        retry_limit: Maximum retries for failed core lookups.
    
    Returns:
        DNSRecord with status, records, errors, and meta.
    """
    domain = domain.rstrip('.').lower()
    record = DNSRecord(domain=domain, status='error')
    
    # Get defaults if not provided: prefer local Unbound by default
    if resolver is None:
        try:
            ns_env = os.getenv("DNS_NAMESERVERS", "127.0.0.1")
            ns_list = [s.strip() for s in ns_env.split(",") if s.strip()]
            resolver = dns_lookup.get_default_resolver(nameservers=ns_list)
        except Exception:
            resolver = dns_lookup.get_default_resolver()
    if semaphore is None:
        semaphore = dns_lookup.default_semaphore()
    
    try:
        # Phase 1: Fetch core records (NS, SOA) concurrently; A from cache (source of truth)
        ns_task = dns_lookup.lookup_ns(domain, resolver, semaphore)
        soa_task = dns_lookup.lookup_soa(domain, resolver, semaphore)
        ns_res, soa_res = await asyncio.gather(ns_task, soa_task, return_exceptions=True)

        ns_rcode, ns_answers, ns_ttl = ns_res if not isinstance(ns_res, BaseException) else ('ERROR', [], 0)
        soa_rcode, soa_answers, soa_ttl = soa_res if not isinstance(soa_res, BaseException) else ('ERROR', [], 0)

        # A record: read from LMDB cache first; rare network fallback on miss
        a_cached = await dns_lookup.get_cached_result('A', domain, only_positive=True)
        if a_cached:
            a_rcode, a_answers, a_ttl = ('NOERROR', a_cached[1], a_cached[2])
        else:
            a_rcode, a_answers, a_ttl = ('NODATA', [], 0)
            # Minimal live lookup when cache has no A; persist and flag risk
            try:
                rcode_live, answers_live, ttl_live = await dns_lookup.lookup_a(domain, resolver, semaphore)
                if rcode_live == 'NOERROR' and answers_live:
                    a_rcode, a_answers, a_ttl = (rcode_live, answers_live, ttl_live)
                    try:
                        record.meta['risk_cache_miss_a'] = 'true'
                    except Exception:
                        pass
                    # If LMDB is read-only, report update to master; else write locally
                    try:
                        if dns_lookup.is_lmdb_readonly():
                            try:
                                from kv.update_reporter import report_dns_update
                                report_dns_update('A', domain, rcode_live, answers_live, ttl_live)
                            except Exception:
                                pass
                        else:
                            await dns_lookup.check_changed_and_enqueue_update('A', domain, rcode_live, answers_live, ttl_live)
                    except Exception:
                        pass
            except Exception:
                pass
        
        # Store core rcodes in meta
        record.meta['ns_rcode'] = ns_rcode
        record.meta['soa_rcode'] = soa_rcode
        record.meta['a_rcode'] = a_rcode
        
        # Check if domain is dormant or needs retry depending on core rcodes
        all_nxdomain = all(rc == 'NXDOMAIN' for rc in [ns_rcode, soa_rcode, a_rcode])
        all_servfail = all(rc == 'SERVFAIL' for rc in [ns_rcode, soa_rcode, a_rcode])
        all_timeout = all(rc == 'TIMEOUT' for rc in [ns_rcode, soa_rcode, a_rcode])

        if all_nxdomain:
            record.status = 'dormant'
            record.errors['core'] = 'All core lookups failed (NXDOMAIN)'
            return record
        if all_servfail:
            record.status = 'needs_retry'
            record.errors['core'] = 'All core lookups SERVFAIL'
            return record
        if all_timeout:
            record.status = 'needs_retry'
            record.errors['core'] = 'All core lookups timed out'
            return record
        
        # Check which core lookups succeeded
        core_ok = {
            'ns': ns_rcode == 'NOERROR' and ns_answers,
            'soa': soa_rcode == 'NOERROR' and soa_answers,
            'a': a_rcode == 'NOERROR' and a_answers,
        }
        
        # Log core rcodes to aid diagnosis
        try:
            log.info("core rcodes for {}: ns={} soa={} a={}", domain, ns_rcode, soa_rcode, a_rcode)
        except Exception:
            pass

        # If some core lookups failed, retry NS/SOA only (A stays cache-only)
        if not all(core_ok.values()):
            for attempt in range(retry_limit):
                retry_tasks = []
                retry_types = []
                
                if not core_ok['ns']:
                    retry_tasks.append(dns_lookup.lookup_ns(domain, resolver, semaphore))
                    retry_types.append('ns')
                if not core_ok['soa']:
                    retry_tasks.append(dns_lookup.lookup_soa(domain, resolver, semaphore))
                    retry_types.append('soa')
                
                if not retry_tasks:
                    break
                
                # Small backoff between retries
                if attempt > 0:
                    await asyncio.sleep(0.2 * (attempt + 1))
                
                retry_results = await asyncio.gather(*retry_tasks, return_exceptions=True)
                
                # Update results
                for i, rtype in enumerate(retry_types):
                    result = retry_results[i]
                    # Skip if an exception was returned
                    if isinstance(result, BaseException):
                        continue
                    # Ensure result is an iterable with at least 3 elements before unpacking
                    if not (isinstance(result, (tuple, list)) and len(result) >= 3):
                        log.debug(f"{domain} unexpected retry result type for {rtype}: {type(result)}")
                        continue
                    rcode, answers, ttl = result[0], result[1], result[2]
                    if rtype == 'ns' and rcode == 'NOERROR' and answers:
                        ns_rcode, ns_answers, ns_ttl = rcode, answers, ttl
                        core_ok['ns'] = True
                    elif rtype == 'soa' and rcode == 'NOERROR' and answers:
                        soa_rcode, soa_answers, soa_ttl = rcode, answers, ttl
                        core_ok['soa'] = True
        
        # If no core records succeeded after retries, mark as needs_retry
        if not any(core_ok.values()):
            record.status = 'needs_retry'
            record.errors['core'] = 'All core lookups failed after retries'
            return record
        
        # At least one core lookup succeeded - mark as alive
        record.status = 'alive'
        
        # Store core results
        if ns_answers:
            record.records['NS'] = ns_answers
            # Provide lowercase alias keys expected by downstream enrichers
            try:
                record.records['ns'] = [str(x).rstrip('.').lower() for x in ns_answers]
            except Exception:
                record.records['ns'] = ns_answers
        else:
            record.errors['NS'] = ns_rcode
        
        if soa_answers:
            record.records['SOA'] = soa_answers
            try:
                record.records['soa'] = [str(x) for x in soa_answers]
            except Exception:
                record.records['soa'] = soa_answers
            
            # Also fetch structured SOA for serial tracking
            try:
                r_s, soa_struct_list, _ = await dns_lookup.lookup_soa_struct(domain, resolver, semaphore)
                if r_s == 'NOERROR' and soa_struct_list:
                    record.meta['soa_struct'] = soa_struct_list[0]
                    if 'serial' in soa_struct_list[0]:
                        record.meta['soa_serial'] = soa_struct_list[0]['serial']
            except Exception:
                pass
        else:
            record.errors['SOA'] = soa_rcode
        
        if a_answers:
            record.records['A'] = a_answers
            try:
                record.records['a'] = [str(x) for x in a_answers]
            except Exception:
                record.records['a'] = a_answers
        else:
            record.errors['A'] = a_rcode

        try:
            record.meta['a_ttl'] = int(a_ttl) if a_ttl is not None else None
        except Exception:
            pass
        
        # Phase 2: Check if any core record changed
        change_tasks = [
            dns_lookup.check_changed_and_enqueue_update('NS', domain, ns_rcode, ns_answers, ns_ttl),
            dns_lookup.check_changed_and_enqueue_update('SOA', domain, soa_rcode, soa_answers, soa_ttl),
            # A is cache-authoritative; skip change enqueue here
        ]
        
        change_results = await asyncio.gather(*change_tasks, return_exceptions=True)
        any_changed = any(r for r in change_results if not isinstance(r, BaseException) and r)

        record.meta['changed'] = str(any_changed)
        # Always fetch grouped records so outputs contain full DNS set
        
        # Phase 3.5: Process NS Host IP
        try:
            ns_answers_list = record.records.get('ns', [])
            if ns_answers_list:
                first_ns = str(ns_answers_list[0]).rstrip('.')
                record.records['ns_host_final'] = first_ns
                record.records['ns_regdom_final'] = reg_domain(first_ns) or ''
                
                # Resolve NS host IPs via cache
                try:
                    ns_a_cached = await dns_lookup.get_cached_result('A', first_ns, only_positive=True)
                except Exception:
                    ns_a_cached = None
                try:
                    ns_aaaa_cached = await dns_lookup.get_cached_result('AAAA', first_ns, only_positive=True)
                except Exception:
                    ns_aaaa_cached = None
                
                if ns_a_cached and ns_a_cached[1]:
                    try:
                        record.records['ns_host_a'] = [str(x) for x in ns_a_cached[1]]
                    except Exception:
                        record.records['ns_host_a'] = ns_a_cached[1]
                if ns_aaaa_cached and ns_aaaa_cached[1]:
                    try:
                        record.records['ns_host_aaaa'] = [str(x) for x in ns_aaaa_cached[1]]
                    except Exception:
                        record.records['ns_host_aaaa'] = ns_aaaa_cached[1]
                
                # Minimal live fallback for A on cache miss
                if not record.records.get('ns_host_a'):
                    try:
                        r_ns_a, ans_ns_a, ttl_ns_a = await dns_lookup.lookup_a(first_ns, resolver, semaphore)
                        if r_ns_a == 'NOERROR' and ans_ns_a:
                            try:
                                record.records['ns_host_a'] = [str(x) for x in ans_ns_a]
                            except Exception:
                                record.records['ns_host_a'] = ans_ns_a
                            try:
                                if dns_lookup.is_lmdb_readonly():
                                    try:
                                        from kv.update_reporter import report_dns_update
                                        report_dns_update('A', first_ns, r_ns_a, ans_ns_a, ttl_ns_a)
                                    except Exception:
                                        pass
                                else:
                                    await dns_lookup.check_changed_and_enqueue_update('A', first_ns, r_ns_a, ans_ns_a, ttl_ns_a)
                            except Exception:
                                pass
                    except Exception:
                        pass
        except Exception:
            pass

        # Phase 3: Fetch grouped records concurrently (AAAA, MX, TXT, CAA, NAPTR)
        try:
            logger.info(f"Starting Phase 3 lookups (AAAA, MX, TXT...) for {domain}")
        except Exception:
            pass

        grouped_tasks = [
            dns_lookup.lookup_aaaa(domain, resolver, semaphore),
            dns_lookup.lookup_mx(domain, resolver, semaphore),
            dns_lookup.lookup_txt(domain, resolver, semaphore),
            dns_lookup.lookup_caa_struct(domain, resolver, semaphore),
            dns_lookup.lookup_naptr_struct(domain, resolver, semaphore),
        ]
        
        grouped_results = await asyncio.gather(*grouped_tasks, return_exceptions=True)
        
        # Process AAAA
        if not isinstance(grouped_results[0], BaseException):
            aaaa_rcode, aaaa_answers, aaaa_ttl = grouped_results[0]
            if aaaa_rcode == 'NOERROR' and aaaa_answers:
                record.records['aaaa'] = aaaa_answers
            else:
                record.errors['AAAA'] = aaaa_rcode
            try:
                record.meta['aaaa_ttl'] = int(aaaa_ttl) if aaaa_ttl is not None else None
            except Exception:
                pass
        
        # Process MX
        if not isinstance(grouped_results[1], BaseException):
            mx_rcode, mx_answers, mx_ttl = grouped_results[1]
            if mx_rcode == 'NOERROR' and mx_answers:
                record.records['mx'] = mx_answers
                # Derive primary mx_host_final and its registered domain for downstream norms
                try:
                    first = mx_answers[0]
                    parts = str(first).split(':', 1)
                    host = parts[1] if len(parts) == 2 else str(first)
                    host = host.rstrip('.')
                    # record.records['mx'] = host  <-- REMOVED to avoid overwriting list
                    record.records['mx_host_final'] = host
                    record.records['mx_domain'] = reg_domain(host) or ''
                    record.records['mx_regdom_final'] = reg_domain(host) or ''
                except Exception:
                    pass
                # Resolve MX host IPs via cache; fallback to live on miss
                try:
                    mx_host = record.records.get('mx_host_final')
                except Exception:
                    mx_host = None
                if mx_host:
                    try:
                        mx_a_cached = await dns_lookup.get_cached_result('A', mx_host, only_positive=True)
                    except Exception:
                        mx_a_cached = None
                    try:
                        mx_aaaa_cached = await dns_lookup.get_cached_result('AAAA', mx_host, only_positive=True)
                    except Exception:
                        mx_aaaa_cached = None
                    if mx_a_cached and mx_a_cached[1]:
                        try:
                            record.records['mx_host_a'] = [str(x) for x in mx_a_cached[1]]
                        except Exception:
                            record.records['mx_host_a'] = mx_a_cached[1]
                        try:
                            if mx_a_cached[2] is not None:
                                record.meta['mx_host_a_ttl'] = int(mx_a_cached[2])
                        except Exception:
                            pass
                    if mx_aaaa_cached and mx_aaaa_cached[1]:
                        try:
                            record.records['mx_host_aaaa'] = [str(x) for x in mx_aaaa_cached[1]]
                        except Exception:
                            record.records['mx_host_aaaa'] = mx_aaaa_cached[1]
                        try:
                            if mx_aaaa_cached[2] is not None:
                                record.meta['mx_host_aaaa_ttl'] = int(mx_aaaa_cached[2])
                        except Exception:
                            pass
                    # Minimal live fallback for A on cache miss; persist and flag risk
                    if not record.records.get('mx_host_a'):
                        try:
                            r_a, ans_a, ttl_a = await dns_lookup.lookup_a(mx_host, resolver, semaphore)
                            if r_a == 'NOERROR' and ans_a:
                                try:
                                    record.records['mx_host_a'] = [str(x) for x in ans_a]
                                except Exception:
                                    record.records['mx_host_a'] = ans_a
                                try:
                                    record.meta['risk_cache_miss_mx_a'] = 'true'
                                except Exception:
                                    pass
                                # Report update if read-only; else write locally
                                try:
                                    if dns_lookup.is_lmdb_readonly():
                                        try:
                                            from kv.update_reporter import report_dns_update
                                            report_dns_update('A', mx_host, r_a, ans_a, ttl_a)
                                        except Exception:
                                            pass
                                    else:
                                        await dns_lookup.check_changed_and_enqueue_update('A', mx_host, r_a, ans_a, ttl_a)
                                except Exception:
                                    pass
                        except Exception:
                            pass
            else:
                record.errors['MX'] = mx_rcode
            try:
                record.meta['mx_ttl'] = int(mx_ttl) if mx_ttl is not None else None
            except Exception:
                pass
        
        # Process TXT (with apex fallback when label has no TXT)
        if not isinstance(grouped_results[2], BaseException):
            txt_rcode, txt_answers, txt_ttl = grouped_results[2]
            try:
                # DEBUG: Log initial TXT result
                logger.info(f"[TXT] Initial result for {domain}: rcode={txt_rcode}, answers={txt_answers}")
                record.meta['txt_rcode'] = txt_rcode
            except Exception:
                pass
            stored = False
            if txt_rcode == 'NOERROR' and txt_answers:
                record.records['txt'] = txt_answers
                stored = True
            else:
                record.errors['TXT'] = txt_rcode
            # If no TXT at the queried label, try registered domain as a practical fallback
            try:
                if (not stored) or (not txt_answers):
                    try:
                        registered_txt = reg_domain(domain) or domain
                    except Exception:
                        registered_txt = domain
                    
                    # DEBUG: Log fallback attempt
                    logger.info(f"[TXT] Attempting fallback for {domain} -> {registered_txt}")

                    if registered_txt and registered_txt != domain:
                        r_reg, a_reg, ttl_reg = await dns_lookup.lookup_txt(registered_txt, resolver, semaphore)
                        
                        # DEBUG: Log fallback result
                        logger.info(f"[TXT] Fallback result for {registered_txt}: rcode={r_reg}, answers={a_reg}")

                        if r_reg == 'NOERROR' and a_reg:
                            existing = record.records.get('txt') or []
                            try:
                                record.records['txt'] = existing + a_reg if not isinstance(existing, list) else list(existing) + a_reg
                            except Exception:
                                record.records['txt'] = a_reg
                            stored = True
                            # Prefer apex TXT TTL if available
                            txt_ttl = ttl_reg if ttl_reg is not None else txt_ttl
            except Exception:
                pass
            except Exception:
                pass
            try:
                record.meta['txt_ttl'] = int(txt_ttl) if txt_ttl is not None else None
            except Exception:
                pass

        # Process CAA (structured helper) and flag free CAs
        if not isinstance(grouped_results[3], BaseException):
            caa_rcode, caa_struct, caa_ttl = grouped_results[3]
            if caa_rcode == 'NOERROR' and caa_struct:
                # store string form for compatibility
                caa_list = []
                try:
                    for e in caa_struct:
                        fl = e.get('flags')
                        tag = e.get('tag')
                        val = e.get('value')
                        caa_list.append(f"{fl} {tag} \"{val}\"")
                except Exception:
                    caa_list = [str(e) for e in caa_struct]
                record.records['caa'] = caa_list
                record.meta['caa_struct'] = caa_struct
                try:
                    issuers: List[str] = []
                    for entry in caa_list:
                        s = str(entry).lower()
                        if "letsencrypt" in s:
                            issuers.append("letsencrypt")
                        if "zerossl" in s:
                            issuers.append("zerossl")
                    record.meta['caa_free_ca_detected'] = str(bool(issuers))
                    if issuers:
                        record.meta['caa_issuers'] = list(set(issuers))
                except Exception:
                    pass
            else:
                record.errors['CAA'] = caa_rcode
            try:
                record.meta['caa_ttl'] = int(caa_ttl) if caa_ttl is not None else None
            except Exception:
                pass

        # Process NAPTR (structured helper)
        if not isinstance(grouped_results[4], BaseException):
            naptr_rcode, naptr_struct, naptr_ttl = grouped_results[4]
            if naptr_rcode == 'NOERROR' and naptr_struct:
                # store string form for compatibility
                naptr_list = []
                try:
                    for e in naptr_struct:
                        naptr_list.append(
                            f"{e.get('order')} {e.get('preference')} \"{e.get('flags')}\" \"{e.get('services')}\" \"{e.get('regexp')}\" {e.get('replacement')}"
                        )
                except Exception:
                    naptr_list = [str(e) for e in naptr_struct]
                record.records['naptr'] = naptr_list
                record.meta['naptr_struct'] = naptr_struct
            else:
                record.errors['NAPTR'] = naptr_rcode
            try:
                record.meta['naptr_ttl'] = int(naptr_ttl) if naptr_ttl is not None else None
            except Exception:
                pass

        # SOA structured: capture full SOA fields for change tracking
        try:
            r_s, soa_struct_list, soa_struct_ttl = await dns_lookup.lookup_soa_struct(domain, resolver, semaphore)
            if r_s == 'NOERROR' and soa_struct_list:
                record.meta['soa_struct'] = soa_struct_list
                try:
                    record.meta['soa_serial'] = soa_struct_list[0].get('serial')
                except Exception:
                    pass
                try:
                    record.meta['soa_ttl'] = int(soa_struct_ttl) if soa_struct_ttl is not None else None
                except Exception:
                    pass
        except Exception:
            pass

        # SRV: Only for new domains (or when configured to always collect), focusing on high-risk services
        try:
            srv_mode = os.getenv('DNS_COLLECT_SRV', 'new_only').strip().lower()
        except Exception:
            srv_mode = 'new_only'
        should_collect_srv = (srv_mode == 'always') or (srv_mode == 'new_only' and any_changed)
        if should_collect_srv:
            srv_services = ["_xmpp._tcp", "_sip._tcp"]
            srv_records: Dict[str, Any] = {}
            srv_errors: Dict[str, str] = {}
            srv_tasks = [dns_lookup.lookup_srv_struct(f"{svc}.{domain}", resolver, semaphore) for svc in srv_services]
            srv_results = await asyncio.gather(*srv_tasks, return_exceptions=True)
            srv_ttl_map: Dict[str, int] = {}
            for idx, svc in enumerate(srv_services):
                res = srv_results[idx]
                if isinstance(res, BaseException):
                    continue
                if not (isinstance(res, (tuple, list)) and len(res) >= 3):
                    continue
                rcode, srv_struct_list, ttl = res[0], res[1], res[2]
                if rcode == 'NOERROR' and srv_struct_list:
                    # Build compatibility string list and store structured entries in meta
                    str_list = []
                    try:
                        for e in srv_struct_list:
                            str_list.append(f"{e.get('priority')} {e.get('weight')} {e.get('port')} {e.get('target')}")
                    except Exception:
                        str_list = [str(e) for e in srv_struct_list]
                    srv_records[svc] = str_list
                    existing = record.meta.get('srv_struct', [])
                    try:
                        if isinstance(existing, list):
                            record.meta['srv_struct'] = existing + srv_struct_list
                        else:
                            record.meta['srv_struct'] = srv_struct_list
                    except Exception:
                        record.meta['srv_struct'] = srv_struct_list
                    try:
                        if ttl is not None:
                            srv_ttl_map[svc] = int(ttl)
                    except Exception:
                        pass
                else:
                    srv_errors[svc] = rcode
            if srv_records:
                record.records['SRV'] = srv_records
                record.records['srv'] = srv_records
            if srv_errors:
                # Store detailed SRV errors under meta; summarize under errors
                record.meta['srv_errors'] = srv_errors
                record.errors['SRV'] = ", ".join([f"{svc}:{rcode}" for svc, rcode in srv_errors.items()])
            if srv_ttl_map:
                record.meta['srv_ttl'] = srv_ttl_map
        
        # Phase 4: PTR lookups prefer LMDB cache; optionally skip network
        all_ips = set()
        for ip in a_answers:
            all_ips.add(str(ip))
        if 'aaaa' in record.records:
            for ip in record.records['aaaa']:
                all_ips.add(str(ip))
        elif 'AAAA' in record.records:
            for ip in record.records['AAAA']:
                all_ips.add(str(ip))
        
        # Track MX IPs specifically to enforce fill-on-miss
        mx_ips = set()
        try:
            for ip in record.records.get('mx_host_a', []) or []:
                s_ip = str(ip)
                all_ips.add(s_ip)
                mx_ips.add(s_ip)
            for ip in record.records.get('mx_host_aaaa', []) or []:
                s_ip = str(ip)
                all_ips.add(s_ip)
                mx_ips.add(s_ip)
        except Exception:
            pass
        
        # Also store flattened MX IPs for convenience
        if mx_ips:
             record.records['mx_ips'] = list(mx_ips)

        # Track NS IPs specifically to enforce fill-on-miss
        ns_ips = set()
        try:
            for ip in record.records.get('ns_host_a', []) or []:
                s_ip = str(ip)
                all_ips.add(s_ip)
                ns_ips.add(s_ip)
            for ip in record.records.get('ns_host_aaaa', []) or []:
                s_ip = str(ip)
                all_ips.add(s_ip)
                ns_ips.add(s_ip)
        except Exception:
            pass

        if ns_ips:
             record.records['ns_ips'] = list(ns_ips)

        ptr_map: Dict[str, str] = {}
        if all_ips:
            # Prefer dedicated PTR LMDB; optionally perform live PTR on miss
            try:
                ptr_dir = os.getenv('DNS_LMDB_PTR_DIR')
                if ptr_dir:
                    dns_lookup.init_lmdb_ptr(ptr_dir, readonly=True, lock=True)
            except Exception:
                ptr_dir = None
            
            for ip in all_ips:
                try:
                    reverse_name = ipaddress.ip_address(ip).reverse_pointer
                except Exception:
                    continue
                try:
                    cached = await dns_lookup.get_cached_result('PTR', reverse_name, only_positive=True, env_name='ptr')
                except Exception:
                    cached = None
                
                if cached and cached[1]:
                    try:
                        val = str(cached[1][0]).rstrip('.')
                        ptr_map[ip] = val
                    except Exception:
                        ptr_map[ip] = str(cached[1][0])
                else:
                    # Optional live PTR on miss
                    try:
                        do_ptr_miss = os.getenv('DNS_PTR_ON_MISS', '0').strip().lower() in ('1','true','yes','on')
                    except Exception:
                        do_ptr_miss = False
                    
                    # Force fill-on-miss for MX IPs per user instruction matches "main domain A/PTR logic"
                    if ip in mx_ips or (ns_ips and ip in ns_ips):
                        do_ptr_miss = True

                    if do_ptr_miss:
                        try:
                            r_ptr, a_ptr, ttl_ptr = await dns_lookup.lookup_ptr(reverse_name, resolver, semaphore)
                            if r_ptr == 'NOERROR' and a_ptr:
                                try:
                                    val = str(a_ptr[0]).rstrip('.')
                                    ptr_map[ip] = val
                                except Exception:
                                    ptr_map[ip] = str(a_ptr[0])
                                
                                # Report PTR update to master or write locally
                                try:
                                    if dns_lookup.is_lmdb_readonly():
                                        try:
                                            from kv.update_reporter import report_ptr_update
                                            report_ptr_update(reverse_name, r_ptr, a_ptr, ttl_ptr)
                                        except Exception:
                                            pass
                                    else:
                                        # Write directly to PTR LMDB if available
                                        try:
                                            dns_lookup.init_lmdb_ptr(ptr_dir or os.getenv('DNS_LMDB_PTR_DIR', '/mnt/shared/dns_lmdb_ptr'), readonly=False, lock=True)
                                            env_ptr = dns_lookup._lmdb_env_ptr
                                            if env_ptr is not None:
                                                key = dns_lookup._cache_key('PTR', reverse_name)
                                                val = dns_lookup._serialize_value(r_ptr, a_ptr, ttl_ptr)
                                                with env_ptr.begin(write=True) as txn:
                                                    txn.put(key.encode('utf-8'), val)
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
                        except Exception:
                            pass
            if ptr_map:
                record.records['PTR'] = ptr_map
                record.records['ptr'] = ptr_map
                
                # Populate MX-specific PTRs for batch processor
                if mx_ips:
                    mx_ptrs = []
                    mx_ptr_regdoms = []
                    for ip in mx_ips:
                        val = ptr_map.get(ip)
                        if val:
                            mx_ptrs.append(val)
                            rd = reg_domain(val)
                            if rd:
                                mx_ptr_regdoms.append(rd)
                    if mx_ptrs:
                        record.records['mx_ptr'] = mx_ptrs
                    if mx_ptr_regdoms:
                        record.records['mx_ptr_regdom'] = list(set(mx_ptr_regdoms))

                # Populate NS-specific PTRs for batch processor
                if ns_ips:
                    ns_ptrs = []
                    ns_ptr_regdoms = []
                    for ip in ns_ips:
                        val = ptr_map.get(ip)
                        if val:
                            ns_ptrs.append(val)
                            rd = reg_domain(val)
                            if rd:
                                ns_ptr_regdoms.append(rd)
                    if ns_ptrs:
                        record.records['ns_ptr'] = ns_ptrs
                    if ns_ptr_regdoms:
                        record.records['ns_ptr_regdom'] = list(set(ns_ptr_regdoms))
        
        # Phase 5: Check www and mail subdomains
        registered = reg_domain(domain) or domain
        # Include registered domain for downstream processing
        record.records['registered_domain'] = registered
        www_domain = f"www.{registered}"
        mail_domain = f"mail.{registered}"
        
        # Check if www exists
        www_check_rcode, www_check_answers, _ = await dns_lookup.lookup_a(www_domain, resolver, semaphore)
        if www_check_rcode == 'NOERROR' and www_check_answers:
            # www exists, fetch its records
            www_a_task = dns_lookup.lookup_a(www_domain, resolver, semaphore)
            www_aaaa_task = dns_lookup.lookup_aaaa(www_domain, resolver, semaphore)
            www_results = await asyncio.gather(www_a_task, www_aaaa_task, return_exceptions=True)
            
            www_records = {}
            if not isinstance(www_results[0], BaseException):
                rcode, answers, ttl = www_results[0]
                if rcode == 'NOERROR' and answers:
                    www_records['A'] = answers
            if not isinstance(www_results[1], BaseException):
                rcode, answers, ttl = www_results[1]
                if rcode == 'NOERROR' and answers:
                    www_records['AAAA'] = answers
            
            if www_records:
                record.records['www'] = www_records
        
        # Check if mail exists
        mail_check_rcode, mail_check_answers, _ = await dns_lookup.lookup_a(mail_domain, resolver, semaphore)
        if mail_check_rcode == 'NOERROR' and mail_check_answers:
            # mail exists, fetch its records
            mail_a_task = dns_lookup.lookup_a(mail_domain, resolver, semaphore)
            mail_aaaa_task = dns_lookup.lookup_aaaa(mail_domain, resolver, semaphore)
            mail_results = await asyncio.gather(mail_a_task, mail_aaaa_task, return_exceptions=True)
            
            mail_records = {}
            if not isinstance(mail_results[0], BaseException):
                rcode, answers, ttl = mail_results[0]
                if rcode == 'NOERROR' and answers:
                    mail_records['A'] = answers
            if not isinstance(mail_results[1], BaseException):
                rcode, answers, ttl = mail_results[1]
                if rcode == 'NOERROR' and answers:
                    mail_records['AAAA'] = answers
            
            if mail_records:
                record.records['mail'] = mail_records
        
            # Cache-backfill: use LMDB cached answers when live lookups returned empty
            try:
                _fallback_toggle = os.getenv('DNS_OUTPUT_USE_CACHE_FALLBACK', '1').strip().lower() in ('1','true','yes','on')
            except Exception:
                _fallback_toggle = True
            if _fallback_toggle:
                async def _backfill(rtype: str, ttl_meta_key: Optional[str] = None):
                    try:
                        has_vals = record.records.get(rtype)
                        if not has_vals:
                            cached = await dns_lookup.get_cached_result(rtype, domain, only_positive=True)
                            if cached:
                                _rc, _ans, _ttl = cached
                                record.records[rtype] = _ans
                                record.records[rtype.lower()] = _ans
                                if ttl_meta_key and (_ttl is not None):
                                    try:
                                        record.meta[ttl_meta_key] = int(_ttl)
                                    except Exception:
                                        record.meta[ttl_meta_key] = _ttl
                    except Exception:
                        pass
                await asyncio.gather(
                    _backfill('NS', 'ns_ttl'),
                    _backfill('SOA', 'soa_ttl'),
                    _backfill('A', 'a_ttl'),
                    _backfill('AAAA', 'aaaa_ttl'),
                    _backfill('TXT', 'txt_ttl'),
                )

        return record
        
    except Exception as e:
        record.status = 'error'
        record.errors['exception'] = str(e)
        log.error(f"Error fetching {domain}: {e}")
        return record


class DNSFetcher:
    def __init__(
        self,
        domain: str,
        smtp_banner_client: Optional[Any] = None,
        logger=None,
        run_blocking_probes: bool = False,
        fetch_mta_sts_policy: bool = True,
        domain_timeout_s: float = 5.0,
        lookup: Optional[DNSLookup] = None,
    ):
        self.domain = domain.rstrip(".").lower()
        if logger is None:
            logger = log.bind(component="dns_fetcher").info
        self.log = logger
        self.smtp_banner_client = smtp_banner_client
        self._run_blocking_probes = bool(run_blocking_probes)
        self._fetch_mta_sts_policy = bool(fetch_mta_sts_policy)
        self._domain_timeout_s = domain_timeout_s

        # Ensure we always have a DNSLookup instance with required methods
        if lookup is None or not hasattr(lookup, "resolve_a_aaaa"):
            lookup = DNSLookup()
        self.lookup = lookup
    @staticmethod
    def _core_noerror_exists(
        a_list: Optional[List[str]],
        a_err: Optional[str],
        ns_list: Optional[List[str] | str],
        ns_err: Optional[str],
        soa_mname: Optional[str],
        soa_err: Optional[str],
    ) -> bool:
        try:
            a_ok = (not a_err) and bool(a_list)
        except Exception:
            a_ok = False
        try:
            ns_ok = (not ns_err) and bool(ns_list)
        except Exception:
            ns_ok = False
        try:
            soa_ok = (not soa_err) and bool(soa_mname)
        except Exception:
            soa_ok = False
        return a_ok or ns_ok or soa_ok

    async def fetch_records(self) -> Optional[DNSRecords]:
        try:
            return await asyncio.wait_for(self._fetch_records_inner(), timeout=self._domain_timeout_s)
        except asyncio.TimeoutError:
            try:
                self.log(f"[{self.domain}] fetch_records overall timeout after {self._domain_timeout_s}s - returning partial/None")
            except Exception:
                pass
            return None

    async def _fetch_records_inner(self) -> Optional[DNSRecords]:
        now = datetime.datetime.now(datetime.timezone.utc)

        # Normalize domain and get registered domain
        try:
            domain_ascii = to_ascii_hostname(self.domain)
        except Exception:
            domain_ascii = self.domain
        registered = reg_domain(domain_ascii) or domain_ascii

        expanded: Optional[Dict[str, Any]] = None
        fetch_domain = getattr(self.lookup, "fetch_domain", None)
        if callable(fetch_domain):
            self.log(f"[{self.domain}] using lookup.fetch_domain()")
            try:
                fetch_result = fetch_domain(domain_ascii)
                if inspect.isawaitable(fetch_result):
                    # Allow a slightly higher ceiling than per-record timeout
                    expanded = await asyncio.wait_for(fetch_result, timeout=self._domain_timeout_s)
                else:
                    # Run synchronous implementation in thread
                    raw_result = await asyncio.wait_for(asyncio.to_thread(fetch_domain, domain_ascii), timeout=self._domain_timeout_s)
                    expanded = cast(Dict[str, Any], raw_result) if isinstance(raw_result, dict) else None
            except asyncio.TimeoutError:
                self.log(f"[{self.domain}] fetch_domain timeout after {self._domain_timeout_s}s")
            except Exception as e:
                self.log(f"[{self.domain}] fetch_domain failed: {e}")
                expanded = None

        # If we got an expanded dict, use its cached results; otherwise fall back to legacy probes.
        if expanded:
            # Normalize result from lookup.fetch_domain into a dict-like map
            exp_map: Dict[str, Any] = {}
            if isinstance(expanded, DNSRecord):
                rec_obj = expanded
                recs = rec_obj.records or {}
                errs = rec_obj.errors or {}
                meta = rec_obj.meta or {}
                # ns
                exp_map["ns"] = recs.get("ns") or recs.get("NS") or []
                # soa: prefer lowercase if provided; otherwise parse mname from first SOA rr
                if "soa" in recs and recs.get("soa"):
                    exp_map["soa"] = recs.get("soa")
                else:
                    soa_answers = recs.get("SOA") or []
                    try:
                        first = soa_answers[0] if isinstance(soa_answers, list) and soa_answers else None
                        if first:
                            val = str(first)
                            # mname is the first token; strip trailing dot
                            mname = val.split()[0].rstrip(".")
                            exp_map["soa"] = mname
                        else:
                            exp_map["soa"] = ""
                    except Exception:
                        exp_map["soa"] = ""
                # a/aaaa
                exp_map["a"] = recs.get("a") or recs.get("A") or []
                exp_map["aaaa"] = recs.get("aaaa") or recs.get("AAAA") or []
                # errors
                exp_map["a_error"] = errs.get("A") or ""
                exp_map["ns_error"] = errs.get("NS") or ""
                exp_map["soa_error"] = errs.get("SOA") or ""
                # status and ttl
                exp_map["status"] = (rec_obj.status or "")
                exp_map["ttl"] = meta.get("a_ttl") or meta.get("ttl") or 0
                # optional datasets used later
                exp_map["txt"] = recs.get("TXT") or []
                exp_map["cname"] = recs.get("CNAME") or ""
                exp_map["caa"] = recs.get("CAA") or []
                exp_map["naptr"] = recs.get("NAPTR") or []
                exp_map["srv"] = recs.get("SRV") or []
                exp_map["dnskey"] = meta.get("dnssec") or False
                # expose SOA serial from meta, if available
                try:
                    exp_map["soa_serial"] = meta.get("soa_serial")
                except Exception:
                    pass
                # Build a simple ptrs map from any PTR answers if present
                ptrs_map = {}
                if "PTR" in recs and isinstance(recs.get("PTR"), dict):
                    ptrs_map = recs.get("PTR") or {}
                exp_map["ptrs"] = ptrs_map
                # No host cache is available from DNSRecord; keep empty to trigger fallbacks
                exp_map["hosts"] = {}
            elif isinstance(expanded, dict):
                exp_map = expanded
            else:
                exp_map = {}

            # Core fields
            ns_list = exp_map.get("ns") or []
            if isinstance(ns_list, list) and ns_list:
                ns1_str = list_to_string([str(x) for x in ns_list])
            elif isinstance(ns_list, str) and ns_list:
                ns1_str = list_to_string([ns_list])
            else:
                ns1_str = ""
            soa_mname = exp_map.get("soa") or ""
            a_list = exp_map.get("a") or []
            aaaa_list = exp_map.get("aaaa") or []
            a_err = exp_map.get("a_error") or ""
            ns_err = exp_map.get("ns_error") or ""
            soa_err = exp_map.get("soa_error") or ""
            status = (exp_map.get("status") or "").upper()
            hosts = exp_map.get("hosts") or {}
            ptrs = exp_map.get("ptrs") or {}

            # If domain is dormant (NXDOMAIN on A, NS, SOA) - skip further lookups
            if a_err == "NXDOMAIN" and ns_err == "NXDOMAIN" and soa_err == "NXDOMAIN":
                self.log(f"[{self.domain}] Domain is dormant (NXDOMAIN on A, NS, SOA) - skipping further lookups")
                return None

            # Gate: require at least one of A/NS/SOA to exist and be NOERROR
            if not self._core_noerror_exists(a_list, a_err, ns_list, ns_err, soa_mname, soa_err):
                self.log(f"[{self.domain}] No core NOERROR records (A/NS/SOA) with data - aborting further lookups")
                return None

            # If NOERROR for at least one core record, retry the core records one time (only the ones missing/errored)
            need_retry_a = bool(a_err or not a_list)
            need_retry_ns = bool(ns_err or not ns_list)
            need_retry_soa = bool(soa_err or not soa_mname)
            if need_retry_ns:
                ns1_retry, _, ns_err_retry = await self.lookup.resolve_ns_first(domain_ascii)
                if not ns_err_retry and ns1_retry:
                    ns_list = ns1_retry
                    ns_err = ""
                    ns1_str = list_to_string([str(x) for x in ns_list]) if isinstance(ns_list, list) else list_to_string([str(ns_list)])
            if need_retry_soa:
                soa_mname_retry, _, _, soa_err_retry = await self.lookup.resolve_soa(domain_ascii)
                if not soa_err_retry and soa_mname_retry:
                    soa_mname = soa_mname_retry
                    soa_err = ""
            if need_retry_a:
                try:
                    a_retry, aaaa_retry, ttl_retry, a_err_retry = await self.lookup.resolve_a_aaaa(domain_ascii)
                    if not a_err_retry and a_retry:
                        a_list = a_retry
                        aaaa_list = aaaa_retry or aaaa_list
                        a_err = ""
                        expanded["ttl"] = ttl_retry or expanded.get("ttl", 0)
                except Exception as e:
                    self.log(f"[{self.domain}] core retry failed: {e}")

            # If core probes show SERVFAIL/REFUSED/ERROR, allow one retry then give up
            if status in ("SERVFAIL", "REFUSED", "ERROR"):
                self.log(f"[{self.domain}] Core probes returned {status}, retrying once after backoff")
                try:
                    await asyncio.sleep(0.5)
                    # Simple re-resolve of core records
                    ns1_retry, _, ns_err_retry = await self.lookup.resolve_ns_first(domain_ascii)
                    if not ns_err_retry and ns1_retry:
                        ns_list = ns1_retry
                        ns_err = ""
                        ns1_str = list_to_string([str(x) for x in ns_list]) if isinstance(ns_list, list) else list_to_string([str(ns_list)])
                    soa_mname_retry, _, _, soa_err_retry = await self.lookup.resolve_soa(domain_ascii)
                    if not soa_err_retry and soa_mname_retry:
                        soa_mname = soa_mname_retry
                        soa_err = ""
                    a_retry, aaaa_retry, ttl_retry, a_err_retry = await self.lookup.resolve_a_aaaa(domain_ascii)
                    if not a_err_retry and a_retry:
                        a_list = a_retry
                        aaaa_list = aaaa_retry or aaaa_list
                        a_err = ""
                        expanded["ttl"] = ttl_retry or expanded.get("ttl", 0)
                    status = "NOERROR" if self._core_noerror_exists(a_list, a_err, ns_list, ns_err, soa_mname, soa_err) else status
                except Exception as e:
                    self.log(f"[{self.domain}] retry core probes failed: {e}")
                    return None

            # Determine MX info
            mx_list = expanded.get("mx") or []
            mx_host_input = ""
            mx_pref = 0
            if isinstance(mx_list, list) and mx_list:
                # mx_list expected as list of (pref, host) tuples from DNSLookup._extract_mx
                first = mx_list[0]
                if isinstance(first, (list, tuple)) and len(first) >= 2:
                    mx_pref = int(first[0]) if first[0] is not None else 0
                    mx_host_input = first[1] or ""
                else:
                    # fallback if mx_list is list of hosts or strings
                    mx_host_input = str(first)
            elif isinstance(mx_list, str) and mx_list:
                mx_host_input = mx_list

            # If mx_host_input present, try to obtain its resolved IPs from hosts cache
            mx_host_final = mx_host_input or ""
            mx_cname_chain = []
            mx_ips: List[str] = []
            mx_ptr_first = ""
            mx_ptr_regdom_first = ""
            mx_regdom_final = ""
            mx_under_customer = False

            if mx_host_final:
                host_info = hosts.get(mx_host_final, {}) if hosts else {}
                mx_ips = host_info.get("a", []) + host_info.get("aaaa", []) if host_info else []
                # if missing, use cache-only A/AAAA for MX host
                if not mx_ips:
                    try:
                        mx_a_cached = await dns_lookup.get_cached_result('A', mx_host_final, only_positive=True)
                        mx_ips = (mx_a_cached[1] if mx_a_cached else [])
                        # Optional AAAA from cache
                        mx_aaaa_cached = await dns_lookup.get_cached_result('AAAA', mx_host_final, only_positive=True)
                        if mx_aaaa_cached and mx_aaaa_cached[1]:
                            mx_ips = mx_ips + mx_aaaa_cached[1]
                    except Exception:
                        mx_ips = []

                if mx_ips:
                    mx_ptr_first = ptrs.get(mx_ips[0]) if ptrs and mx_ips[0] in ptrs else await self.lookup.resolve_ptr_once(mx_ips[0])
                    mx_ptr_regdom_first = reg_domain(mx_ptr_first) if mx_ptr_first else ""
                mx_regdom_final = reg_domain(mx_host_final) if mx_host_final else ""
                mx_under_customer = bool(mx_regdom_final and mx_regdom_final == registered)

            # TXT/SPF/DMARC and MTA-STS/TLSRPT
            spf_txt = ""
            dmarc_txt = ""
            bimi_txt = ""
            try:
                # expand may have txt entries for apex; if not, fall back to lookup helpers
                txts = expanded.get("txt") or []
                if txts:
                    # normalize bytes/objects to strings
                    txt_norm = []
                    for t in txts:
                        if isinstance(t, (bytes, bytearray)):
                            txt_norm.append(t.decode(errors="ignore"))
                        else:
                            txt_norm.append(str(t))
                    # find spf/dmarc/bimi among returned texts
                    spf_txt = next((t for t in txt_norm if "v=spf1" in t.lower()), "")
                    dmarc_txt = next((t for t in txt_norm if t.lower().startswith("v=dmarc")), "")
                    bimi_txt = next((t for t in txt_norm if "v=bimi" in t.lower()), "")
                else:
                    # fallback queries
                    try:
                        dmarc_txt = next((t for t in (await self.lookup.resolve_txt_join(f"_dmarc.{registered}")) if "v=dmarc" in t.lower()), "")
                    except Exception:
                        dmarc_txt = ""
                    try:
                        spf_txt = next((t for t in (await self.lookup.resolve_txt_join(registered)) if "v=spf1" in t.lower()), "")
                    except Exception:
                        spf_txt = ""
                    try:
                        bimi_txt = next((t for t in (await self.lookup.resolve_txt_join(f"default._bimi.{registered}")) if "v=bimi" in t.lower()), "")
                    except Exception:
                        bimi_txt = ""
            except Exception:
                spf_txt = dmarc_txt = bimi_txt = ""

            # MTA-STS and TLS-RPT using existing helpers
            try:
                mta_info = await detect_mta_sts(registered, self.lookup, fetch_policy=self._fetch_mta_sts_policy)
                has_mta_sts = bool(mta_info.get("has_mta_sts"))
                mta_sts_txt = mta_info.get("raw_txt") or ""
                mta_sts_mode = mta_info.get("mode") or ""
                mta_sts_max_age = mta_info.get("max_age")
                mta_sts_id = mta_info.get("id") or ""
            except Exception:
                has_mta_sts = False
                mta_sts_txt = ""
                mta_sts_mode = ""
                mta_sts_max_age = None
                mta_sts_id = ""

            try:
                tlsrpt_rua = await fetch_tlsrpt_rua(registered, self.lookup) or ""
            except Exception:
                tlsrpt_rua = ""

            # Optional blocking probes (HTTPS/SNTP cert) for under-customer MX
            https_ok = https_days = https_issuer = https_san = None
            smtp_ok = smtp_days = smtp_issuer = None
            want_probes = self._run_blocking_probes and mx_host_final and (mx_under_customer or has_mta_sts)
            if want_probes:
                try:
                    results = await asyncio.gather(
                        probe_https_cert(registered, ips=mx_ips or None, probe_timeout=5.0),
                        probe_smtp_starttls_cert(mx_host_final, ips=mx_ips or None, probe_timeout=5.0),
                        return_exceptions=True,
                    )
                except Exception:
                    results = []
                if results:
                    val = results[0] if len(results) > 0 else None
                    if not isinstance(val, BaseException) and val:
                        try:
                            https_ok, https_days, https_issuer, https_san = val
                        except Exception:
                            https_ok = https_days = https_issuer = https_san = None
                    val = results[1] if len(results) > 1 else None
                    if not isinstance(val, BaseException) and val:
                        try:
                            smtp_ok, smtp_days, smtp_issuer = val
                        except Exception:
                            smtp_ok = smtp_days = smtp_issuer = None

            # Hosts (www/mail) from expanded host cache; fallback to resolve_a_aaaa
            www_host = f"www.{registered}" if registered else ""
            www_a_first = ""
            www_ptr = ""
            www_cname = ""
            www_info = hosts.get(www_host, {}) if hosts else {}
            if www_info:
                www_a_list = www_info.get("a", []) or []
                www_a_first = www_a_list[0] if www_a_list else ""
                # ptr available from ptrs mapping
                if www_a_first:
                    www_ptr = ptrs.get(www_a_first) if ptrs and www_a_first in ptrs else await self.lookup.resolve_ptr_once(www_a_first)
                www_cname = www_info.get("cname") or ""
            else:
                try:
                    www_a_list, _, _, _ = await self.lookup.resolve_a_aaaa(www_host)
                    www_a_first = www_a_list[0] if www_a_list else ""
                except Exception:
                    www_a_first = ""
                if www_a_first:
                    try:
                        www_ptr = await self.lookup.resolve_ptr_first(www_a_first)
                    except Exception:
                        www_ptr = ""
                # try CNAME
                try:
                    resp = await self.lookup._retry_resolve(www_host, "CNAME")
                    if resp and resp[0]:
                        rr = next(iter(resp[0]), None)
                        if rr:
                            www_cname = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
                except Exception:
                    www_cname = ""

            # mail host
            mail_host = f"mail.{registered}" if registered else ""
            mail_a_first = ""
            mail_ptr = ""
            mail_cname = ""
            mail_info = hosts.get(mail_host, {}) if hosts else {}
            if mail_info:
                mail_a_list = mail_info.get("a", []) or []
                mail_a_first = mail_a_list[0] if mail_a_list else ""
                if mail_a_first:
                    mail_ptr = ptrs.get(mail_a_first) if ptrs and mail_a_first in ptrs else await self.lookup.resolve_ptr_once(mail_a_first)
                mail_cname = mail_info.get("cname") or ""
            else:
                try:
                    mail_a_list, _, _, _ = await self.lookup.resolve_a_aaaa(mail_host, want_ipv6=True)
                    mail_a_first = mail_a_list[0] if mail_a_list else ""
                except Exception:
                    mail_a_first = ""
                if mail_a_first:
                    try:
                        mail_ptr = await self.lookup.resolve_ptr_first(mail_a_first)
                    except Exception:
                        mail_ptr = ""
                try:
                    resp_mail_cname = await self.lookup._retry_resolve(mail_host, "CNAME")
                    if resp_mail_cname and resp_mail_cname[0]:
                        rr = next(iter(resp_mail_cname[0]), None)
                        if rr:
                            mail_cname = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
                except Exception:
                    mail_cname = ""

            # Derived/aggregate values
            https_san_count = len(https_san.split("|")) if (isinstance(https_san, str) and https_san) else 0
            ip_int = ip_to_int(a_list[0]) if a_list else 0
            a_ttl = expanded.get("ttl", 0) or 0
            ns1_list = ns_list if isinstance(ns_list, list) else ([ns_list] if ns_list else [])
            ns1_str = list_to_string(ns1_list) if ns1_list else ""
            a_str = list_to_string(a_list) if a_list else ""
            aaaa_str = list_to_string(aaaa_list) if aaaa_list else ""

            # CAA / NAPTR / SRV (flatten and normalize)
            try:
                raw_caa = expanded.get("caa") or expanded.get("CAA") or []
            except Exception:
                raw_caa = []
            try:
                raw_naptr = expanded.get("naptr") or expanded.get("NAPTR") or []
            except Exception:
                raw_naptr = []
            # SRV can be a dict of service -> list or a flat list
            try:
                raw_srv = expanded.get("srv") or expanded.get("SRV") or []
            except Exception:
                raw_srv = []

            # Normalize to lists of strings
            caa_list = []
            try:
                if isinstance(raw_caa, list):
                    caa_list = [str(x) for x in raw_caa]
                elif raw_caa:
                    caa_list = [str(raw_caa)]
            except Exception:
                caa_list = raw_caa if isinstance(raw_caa, list) else ([raw_caa] if raw_caa else [])

            naptr_list = []
            try:
                if isinstance(raw_naptr, list):
                    naptr_list = [str(x) for x in raw_naptr]
                elif raw_naptr:
                    naptr_list = [str(raw_naptr)]
            except Exception:
                naptr_list = raw_naptr if isinstance(raw_naptr, list) else ([raw_naptr] if raw_naptr else [])

            srv_list = []
            try:
                if isinstance(raw_srv, dict):
                    flat_srv = []
                    for v in raw_srv.values():
                        if isinstance(v, list):
                            flat_srv.extend(v)
                        elif v:
                            flat_srv.append(v)
                    srv_list = [str(x) for x in flat_srv]
                elif isinstance(raw_srv, list):
                    srv_list = [str(x) for x in raw_srv]
                elif raw_srv:
                    srv_list = [str(raw_srv)]
            except Exception:
                srv_list = []

            # Build structured forms for downstream consumers
            caa_struct = []
            try:
                for item in (raw_caa if isinstance(raw_caa, list) else ([] if not raw_caa else [raw_caa])):
                    if isinstance(item, dict):
                        caa_struct.append({
                            "flags": item.get("flags"),
                            "tag": item.get("tag"),
                            "value": item.get("value"),
                        })
                    else:
                        caa_struct.append({"raw": str(item)})
            except Exception:
                caa_struct = [{"raw": s} for s in caa_list]

            naptr_struct = []
            try:
                for item in (raw_naptr if isinstance(raw_naptr, list) else ([] if not raw_naptr else [raw_naptr])):
                    if isinstance(item, dict):
                        naptr_struct.append({
                            "order": item.get("order"),
                            "preference": item.get("preference"),
                            "flags": item.get("flags"),
                            "services": item.get("services"),
                            "regexp": item.get("regexp"),
                            "replacement": item.get("replacement"),
                        })
                    else:
                        naptr_struct.append({"raw": str(item)})
            except Exception:
                naptr_struct = [{"raw": s} for s in naptr_list]

            srv_struct = []
            try:
                # Flatten raw_srv for struct building
                items = []
                # Track service/proto when available
                svc_pairs: List[Tuple[str, str]] = []
                if isinstance(raw_srv, dict):
                    for k, v in raw_srv.items():
                        # k like "_xmpp._tcp" or "_sip._tcp"
                        try:
                            svc, proto = (k.split(".")[0], k.split(".")[1]) if "." in k else (k, "")
                        except Exception:
                            svc, proto = (k, "")
                        count_before = len(items)
                        if isinstance(v, list):
                            items.extend(v)
                        elif v:
                            items.append(v)
                        # Add matching service/proto for appended items
                        added = len(items) - count_before
                        svc_pairs.extend([(svc, proto)] * max(added, 0))
                elif isinstance(raw_srv, list):
                    items = raw_srv
                elif raw_srv:
                    items = [raw_srv]
                for idx, item in enumerate(items):
                    if isinstance(item, dict):
                        srv_struct.append({
                            "priority": item.get("priority"),
                            "weight": item.get("weight"),
                            "port": item.get("port"),
                            "target": item.get("target"),
                            "service": (svc_pairs[idx][0] if idx < len(svc_pairs) else None),
                            "proto": (svc_pairs[idx][1] if idx < len(svc_pairs) else None),
                            "ttl": None,
                        })
                    else:
                        srv_struct.append({
                            "raw": str(item),
                            "service": (svc_pairs[idx][0] if idx < len(svc_pairs) else None),
                            "proto": (svc_pairs[idx][1] if idx < len(svc_pairs) else None),
                            "ttl": None,
                        })
            except Exception:
                srv_struct = [{"raw": s, "service": None, "proto": None, "ttl": None} for s in srv_list]

            # Compose record
            rec = DNSRecords(
                domain=self.domain,
                registered_domain=registered,
                ns1=ns1_str,
                soa=soa_mname or "",
                status=status or "",
                ns_error=ns_err or "",
                soa_error=soa_err or "",
                a_error=a_err or "",
                a=a_str,
                aaaa=aaaa_str,
                ip_int=ip_int,
                a_ttl=a_ttl,
                ptr=ptrs.get(a_list[0], "") if a_list and ptrs else (ptrs.get(a_list[0], "") if ptrs else ""),
                cname=expanded.get("cname", "") or "",
                mx=mx_host_input or "",
                mx_priority=mx_pref or 0,
                mx_host_final=mx_host_final or "",
                mx_regdom_final=mx_regdom_final or "",
                mx_cname_chain=mx_cname_chain or [],
                mx_under_customer=bool(mx_under_customer),
                mx_banner_raw="",
                mx_banner_host="",
                mx_banner_details="",
                mx_banner_provider="",
                mx_banner_category="",
                mx_domain=mx_regdom_final or "",
                mx_tld=(mx_regdom_final.split(".")[-1] if mx_regdom_final else ""),
                mx_ips=mx_ips or [],
                mx_ptr=mx_ptr_first or "",
                mx_ptr_regdom=mx_ptr_regdom_first or "",
                spf=spf_txt or "",
                dmarc=dmarc_txt or "",
                bimi=bimi_txt or "",
                www=www_host or "",
                www_a=www_a_first or "",
                www_int=ip_to_int(www_a_first) if www_a_first else 0,
                www_ptr=www_ptr or "",
                www_cname=www_cname or "",
                mail_a=mail_a_first or "",
                mail_int=ip_to_int(mail_a_first) if mail_a_first else 0,
                mail_ptr=mail_ptr or "",
                mail_cname=mail_cname or "",
                mail_mx=mx_host_final or "",
                mail_mx_domain=mx_regdom_final or "",
                mail_mx_tld=(mx_regdom_final.split(".")[-1] if mx_regdom_final else ""),
                mail_spf=spf_txt or "",
                mail_dmarc=dmarc_txt or "",
                mail_mx_banner_raw="",
                mail_mx_banner_host="",
                mail_mx_banner_details="",
                mail_mx_banner_provider="",
                mail_mx_banner_category="",
                smtp_cert_ok=smtp_ok,
                smtp_cert_days_left=smtp_days,
                smtp_cert_issuer=smtp_issuer or "",
                https_cert_ok=https_ok,
                https_cert_days_left=https_days,
                https_cert_issuer=https_issuer or "",
                https_cert_san_count=https_san_count,
                has_mta_sts=bool(has_mta_sts),
                mta_sts_txt=mta_sts_txt or "",
                mta_sts_mode=mta_sts_mode or "",
                mta_sts_max_age=mta_sts_max_age,
                mta_sts_id=mta_sts_id or "",
                tlsrpt_rua=tlsrpt_rua or "",
                dnssec=bool(exp_map.get("dnskey") or False),
                soa_serial=exp_map.get("soa_serial") or 0,
                # New record fields
                caa=list_to_string(caa_list) if caa_list else "",
                naptr=list_to_string(naptr_list) if naptr_list else "",
                srv=list_to_string(srv_list) if srv_list else "",
                caa_records=caa_struct,
                naptr_records=naptr_struct,
                srv_records=srv_struct,
                soa_records=(record.meta.get('soa_struct') or []),
                aaaa_ttl=None,
                mx_ttl=None,
                txt_ttl=None,
                caa_ttl=None,
                naptr_ttl=None,
                refresh_date=now,
            )

            # Normalize empty strings to None (post-creation)
            try:
                for f in getattr(rec, "__dataclass_fields__", {}).values():
                    if f.type in (str, Optional[str]):
                        v = getattr(rec, f.name)
                        if isinstance(v, str) and v == "":
                            setattr(rec, f.name, None)
            except Exception:
                pass

            # If MX banner probing desired and under-customer, do the blocking probes and fill banner fields
            if self._run_blocking_probes and mx_host_final and (mx_under_customer or has_mta_sts):
                try:
                    results = await asyncio.gather(
                        probe_https_cert(registered, ips=mx_ips or None, probe_timeout=5.0),
                        probe_smtp_starttls_cert(mx_host_final, ips=mx_ips or None, probe_timeout=5.0),
                        return_exceptions=True,
                    )
                    if results:
                        # HTTPS
                        val = results[0] if len(results) > 0 else None
                        if not isinstance(val, BaseException) and val:
                            try:
                                https_ok, https_days, https_issuer, https_san = val
                                rec.https_cert_ok = https_ok
                                rec.https_cert_days_left = https_days
                                rec.https_cert_issuer = https_issuer or ""
                                rec.https_cert_san_count = (
                                    len(https_san.split("|")) if (isinstance(https_san, str) and https_san) else 0
                                )
                            except Exception:
                                pass
                        # SMTP
                        val = results[1] if len(results) > 1 else None
                        if not isinstance(val, BaseException) and val:
                            try:
                                smtp_ok, smtp_days, smtp_issuer = val
                                rec.smtp_cert_ok = smtp_ok
                                rec.smtp_cert_days_left = smtp_days
                                rec.smtp_cert_issuer = smtp_issuer or ""
                            except Exception:
                                pass
                except Exception:
                    pass

            return rec

        # If expanded not available, fall back to legacy behavior (existing probe flow)
        # We keep the original implementation in an internal helper to avoid duplicating code here.
        return await self._legacy_fetch(domain_ascii, registered, now)

    async def _legacy_fetch(self, domain_ascii: str, registered: str, now: datetime.datetime) -> Optional[DNSRecords]:
        """
        Legacy fetch path preserved for compatibility - identical to the prior implementation.
        This function mirrors your original logic: run base queries in parallel,
        then run MX enrichment, www/mail probes, PTRs, etc.
        """
        # Kick off base DNS work
        ns_task = asyncio.create_task(self.lookup.resolve_ns_first(domain_ascii))
        soa_task = asyncio.create_task(self.lookup.resolve_soa(domain_ascii))
        a_task = asyncio.create_task(self.lookup.resolve_a_aaaa(domain_ascii))
        dnssec_task = asyncio.create_task(self.lookup.dnssec_flag(domain_ascii))
        cname_apex_task = asyncio.create_task(self.lookup._retry_resolve(domain_ascii, "CNAME"))

        # MX primary
        mx_host_input, mx_pref, mx_err = await self.lookup.resolve_mx_primary(domain_ascii)

        # Await base results
        ns1_val, _, ns_err = await ns_task
        soa_mname, _, soa_serial, soa_err = await soa_task
        a_list, aaaa_list, ttl_min, a_err = await a_task

        # Check if domain is dormant (NXDOMAIN on all base records)
        if a_err == "NXDOMAIN" and ns_err == "NXDOMAIN" and soa_err == "NXDOMAIN":
            self.log(f"[{self.domain}] Domain is dormant (NXDOMAIN on A, NS, SOA) - skipping further lookups")
            return None

        # Gate: require at least one of A/NS/SOA to exist and be NOERROR
        if not self._core_noerror_exists(a_list, a_err, ns1_val, ns_err, soa_mname, soa_err):
            self.log(f"[{self.domain}] No core NOERROR records (A/NS/SOA) with data - aborting further lookups")
            return None

        # If NOERROR for at least one of these then retry the core records one time (only missing/errored)
        need_retry_a = bool(a_err or not a_list)
        need_retry_ns = bool(ns_err or not ns1_val)
        need_retry_soa = bool(soa_err or not soa_mname)
        if need_retry_a or need_retry_ns or need_retry_soa:
            self.log(f"[{self.domain}] Core records partial; retrying missing/errored A/NS/SOA once")
            try:
                await asyncio.sleep(0.2)
                if need_retry_ns:
                    ns1_retry, _, ns_err_retry = await self.lookup.resolve_ns_first(domain_ascii)
                    if not ns_err_retry and ns1_retry:
                        ns1_val = ns1_retry
                        ns_err = ""
                if need_retry_soa:
                    soa_mname_retry, _, soa_serial_retry, soa_err_retry = await self.lookup.resolve_soa(domain_ascii)
                    if not soa_err_retry and soa_mname_retry:
                        soa_mname = soa_mname_retry
                        soa_serial = soa_serial_retry or soa_serial
                        soa_err = ""
                if need_retry_a:
                    a_retry, aaaa_retry, ttl_retry, a_err_retry = await self.lookup.resolve_a_aaaa(domain_ascii)
                    if not a_err_retry and a_retry:
                        a_list = a_retry
                        aaaa_list = aaaa_retry or aaaa_list
                        ttl_min = ttl_retry or ttl_min
                        a_err = ""
            except Exception as e:
                self.log(f"[{self.domain}] core retry failed: {e}")

        try:
            dnssec = await dnssec_task
        except Exception:
            dnssec = None

        # PTR for apex (first A only)
        ptr_apex = ""
        if a_list:
            try:
                ptr_apex = await self.lookup.resolve_ptr_first(a_list[0])
            except Exception:
                ptr_apex = ""

        # Apex CNAME (rare, but handle defensively)
        apex_cname = ""
        try:
            resp = await cname_apex_task
            if resp:
                ans = resp[0]
                if ans:
                    rr = next(iter(ans), None)
                    if rr:
                        apex_cname = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
        except Exception:
            apex_cname = ""

        # MX enrichment (reuse your existing helper logic)
        async def _gather_mx_data(host_input: Optional[str]):
            # This function is intentionally identical to your prior implementation;
            # copy/paste the logic from your original function above to keep behavior.
            # For brevity here, we call existing code paths similar to before.
            return await self._gather_mx_data_compat(host_input, registered)

        (
            mx_host_final,
            mx_regdom_final,
            mx_cname_chain,
            mx_under_customer,
            mx_ips,
            mx_ptr_first,
            mx_ptr_regdom_first,
            mx_banner_raw,
            mx_banner_host,
            mx_banner_details,
            mx_banner_provider,
            mx_banner_category,
            mx_domain,
            mx_tld,
            spf_txt,
            dmarc_txt,
            bimi_txt,
            status,
            mta_sts_txt,
            mta_sts_mode,
            mta_sts_max_age,
            mta_sts_id,
            has_mta_sts,
            tlsrpt_rua,
            https_ok,
            https_days,
            https_issuer,
            https_san,
            smtp_ok,
            smtp_days,
            smtp_issuer,
        ) = await _gather_mx_data(mx_host_input)

        # WWW host
        www_host = f"www.{registered}" if registered else ""
        try:
            www_a_list, _, _, _ = await self.lookup.resolve_a_aaaa(www_host)
        except Exception:
            www_a_list = []
        www_a_first = www_a_list[0] if www_a_list else ""
        www_int = ip_to_int(www_a_first) if www_a_first else 0
        www_ptr = ""
        # MAIL host
        mail_host = f"mail.{registered}" if registered else ""
        try:
            mail_a_list, _, _, _ = await self.lookup.resolve_a_aaaa(mail_host, want_ipv6=True)
        except Exception:
            mail_a_list = []
        mail_a_first = mail_a_list[0] if mail_a_list else ""
        mail_int = ip_to_int(mail_a_first) if mail_a_first else 0
        mail_ptr = ""
        try:
            if mail_a_first:
                mail_ptr = await self.lookup.resolve_ptr_first(mail_a_first)
        except Exception:
            mail_ptr = ""
        mail_cname = ""
        try:
            resp_mail_cname = await self.lookup._retry_resolve(mail_host, "CNAME")
            if resp_mail_cname and resp_mail_cname[0]:
                rr = next(iter(resp_mail_cname[0]), None)
                if rr:
                    mail_cname = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
        except Exception:
            mail_cname = ""
        mail_ptr = ""
        try:
            if mail_a_list:
                mail_ptr = await self.lookup.resolve_ptr_first(mail_a_list[0])
        except Exception:
            mail_ptr = ""
        mail_cname = ""
        try:
            resp_mail_cname = await self.lookup._retry_resolve(mail_host, "CNAME")
            if resp_mail_cname and resp_mail_cname[0]:
                rr = next(iter(resp_mail_cname[0]), None)
                if rr:
                    mail_cname = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
        except Exception:
            mail_cname = ""

        # Compose record with the same fields as your original implementation
        a_ttl = ttl_min or 0
        ns1_list = ns1_val if isinstance(ns1_val, list) else ([ns1_val] if ns1_val else [])
        ns1_list_str = [str(x) for x in ns1_list] if ns1_list else []
        ns1_str = list_to_string(ns1_list_str) if ns1_list_str else ""
        a_str = list_to_string(a_list) if a_list else ""
        aaaa_str = list_to_string(aaaa_list) if aaaa_list else ""

        # SOA structured fields for legacy path
        soa_struct_list: List[Dict[str, Any]] = []
        try:
            r_s, s_list, _ = await dns_lookup.lookup_soa_struct(domain_ascii, resolver=self.lookup.resolver, semaphore=self.lookup.semaphore)
            if r_s == 'NOERROR' and s_list:
                soa_struct_list = s_list
        except Exception:
            soa_struct_list = []

        rec = DNSRecords(
            domain=self.domain,
            registered_domain=registered,
            ns1=ns1_str,
            soa=soa_mname or "",
            status=status or "",
            ns_error=ns_err or "",
            soa_error=soa_err or "",
            a_error=a_err or "",
            a=a_str,
            aaaa=aaaa_str,
            ip_int=ip_to_int(a_list[0]) if a_list else 0,
            a_ttl=a_ttl,
            ptr=ptr_apex or "",
            cname=apex_cname or "",
            mx=mx_host_input or "",
            mx_priority=mx_pref or 0,
            mx_host_final=mx_host_final or "",
            mx_regdom_final=mx_regdom_final or "",
            mx_cname_chain=mx_cname_chain or [],
            mx_under_customer=bool(mx_under_customer),
            mx_banner_raw=mx_banner_raw or "",
            mx_banner_host=mx_banner_host or "",
            mx_banner_details=mx_banner_details or "",
            mx_banner_provider=mx_banner_provider or "",
            mx_banner_category=mx_banner_category or "",
            mx_domain=mx_domain or "",
            mx_tld=mx_tld or "",
            mx_ips=mx_ips or [],
            mx_ptr=mx_ptr_first or "",
            mx_ptr_regdom=mx_ptr_regdom_first or "",
            spf=spf_txt or "",
            dmarc=dmarc_txt or "",
            bimi=bimi_txt or "",
            www=www_host or "",
            www_a=www_a_first or "",
            www_int=www_int,
            www_ptr=www_ptr or "",
            www_cname="",
            mail_a=mail_a_first or "",
            mail_int=mail_int,
            mail_ptr=mail_ptr or "",
            mail_cname=mail_cname or "",
            mail_mx=mx_host_final or "",
            mail_mx_domain=mx_domain or "",
            mail_mx_tld=mx_tld or "",
            mail_spf=spf_txt or "",
            mail_dmarc=dmarc_txt or "",
            mail_mx_banner_raw=mx_banner_raw or "",
            mail_mx_banner_host=mx_banner_host or "",
            mail_mx_banner_details=mx_banner_details or "",
            mail_mx_banner_provider=mx_banner_provider or "",
            mail_mx_banner_category=mx_banner_category or "",
            smtp_cert_ok=smtp_ok,
            smtp_cert_days_left=smtp_days,
            smtp_cert_issuer=smtp_issuer or "",
            https_cert_ok=https_ok,
            https_cert_days_left=https_days,
            https_cert_issuer=https_issuer or "",
            https_cert_san_count=(len(https_san.split("|")) if (isinstance(https_san, str) and https_san) else 0),
            has_mta_sts=bool(has_mta_sts),
            mta_sts_txt=mta_sts_txt or "",
            mta_sts_mode=mta_sts_mode or "",
            mta_sts_max_age=mta_sts_max_age,
            mta_sts_id=mta_sts_id or "",
            tlsrpt_rua=tlsrpt_rua or "",
            dnssec=bool(dnssec),
            soa_serial=soa_serial or 0,
            soa_records=soa_struct_list,
            refresh_date=now,
        )

        try:
            for f in getattr(rec, "__dataclass_fields__", {}).values():
                if f.type in (str, Optional[str]):
                    v = getattr(rec, f.name)
                    if isinstance(v, str) and v == "":
                        setattr(rec, f.name, None)
        except Exception:
            pass

        return rec

    async def _gather_mx_data_compat(self, host_input: Optional[str], registered: str):
        """
        Compatibility helper to replicate the original _gather_mx_data behaviour when falling back to legacy path.
        We extracted this so legacy flow can call it without duplicating code.
        """
        # This function mirrors the original logic you had inside DNSFetcher._gather_mx_data
        # For brevity keep the implementation concise but functionally equivalent.
        mx_host_final = ""
        mx_regdom_final = ""
        mx_cname_chain: List[str] = []
        mx_under_customer = False
        mx_ips: List[str] = []
        mx_ptr_first = ""
        mx_ptr_regdom_first = ""
        mx_banner_raw = mx_banner_host = mx_banner_details = None
        mx_banner_provider = mx_banner_category = None
        mx_domain = ""
        mx_tld = ""
        spf_txt = ""
        dmarc_txt = ""
        bimi_txt = ""
        status = "NOERROR"
        mta_sts_txt = ""
        mta_sts_mode = ""
        mta_sts_max_age = None
        mta_sts_id = ""
        has_mta_sts = False
        tlsrpt_rua = ""
        https_ok = https_days = https_issuer = https_san = None
        smtp_ok = smtp_days = smtp_issuer = None

        if host_input:
            try:
                mx_host_final, chain = await self.lookup.cname_chain(host_input, limit=5)
                mx_cname_chain = chain or []
                mx_host_final = mx_host_final or host_input
            except Exception:
                mx_host_final = host_input
                mx_cname_chain = []

            try:
                mx_a, mx_aaaa, _, _ = await self.lookup.resolve_a_aaaa(mx_host_final)
            except Exception:
                mx_a, mx_aaaa = [], []
            mx_ips = (mx_a or []) + (mx_aaaa or [])

            if mx_ips:
                try:
                    mx_ptr_first = await self.lookup.resolve_ptr_first(mx_ips[0])
                except Exception:
                    mx_ptr_first = ""
                mx_ptr_regdom_first = reg_domain(mx_ptr_first) if mx_ptr_first else ""

            mx_regdom_final = reg_domain(mx_host_final) if mx_host_final else ""
            mx_under_customer = bool(mx_regdom_final and mx_regdom_final == registered)

            if mx_host_final:
                mx_domain = reg_domain(mx_host_final) or ""
                if mx_domain:
                    parts = mx_domain.split(".")
                    mx_tld = parts[-1] if parts else ""

            # Optional SMTP banner for under-customer MX
            if mx_host_final and mx_under_customer and self.smtp_banner_client:
                try:
                    banner = await asyncio.wait_for(self.smtp_banner_client(mx_host_final, 25), timeout=2.0)
                    if banner:
                        mx_banner_raw = banner
                        try:
                            bh, bd = parse_smtp_banner(banner) or (None, None)
                        except Exception:
                            bh, bd = None, None
                        mx_banner_host = bh
                        mx_banner_details = bd
                        try:
                            prov, cat = infer_mbp_from_banner(bh or "", bd or "")
                        except Exception:
                            prov, cat = None, None
                        mx_banner_provider = prov
                        mx_banner_category = cat
                except Exception:
                    mx_banner_raw = mx_banner_host = mx_banner_details = None
                    mx_banner_provider = mx_banner_category = None

            # Safe TXT lookups (self.lookup may be None or lack resolve_txt_join)
            try:
                if self.lookup and hasattr(self.lookup, "resolve_txt_join"):
                    dmarc_candidates = await self.lookup.resolve_txt_join(f"_dmarc.{registered}")
                    dmarc_txt = next((t for t in dmarc_candidates if isinstance(t, str) and "v=dmarc" in t.lower()), "")
                else:
                    dmarc_txt = ""
            except Exception:
                dmarc_txt = ""
            try:
                if self.lookup and hasattr(self.lookup, "resolve_txt_join"):
                    spf_candidates = await self.lookup.resolve_txt_join(registered)
                    spf_txt = next((t for t in spf_candidates if isinstance(t, str) and "v=spf1" in t.lower()), "")
                else:
                    spf_txt = ""
            except Exception:
                spf_txt = ""
            try:
                if self.lookup and hasattr(self.lookup, "resolve_txt_join"):
                    bimi_candidates = await self.lookup.resolve_txt_join(f"default._bimi.{registered}")
                    bimi_txt = next((t for t in bimi_candidates if isinstance(t, str) and "v=bimi" in t.lower()), "")
                else:
                    bimi_txt = ""
            except Exception:
                bimi_txt = ""
            try:
                mta_info = await detect_mta_sts(registered, self.lookup, fetch_policy=self._fetch_mta_sts_policy)
                has_mta_sts = bool(mta_info.get("has_mta_sts"))
                mta_sts_txt = mta_info.get("raw_txt") or ""
                mta_sts_mode = mta_info.get("mode") or ""
                mta_sts_max_age = mta_info.get("max_age")
                mta_sts_id = mta_info.get("id") or ""
            except Exception:
                has_mta_sts = False
                mta_sts_txt = ""
                mta_sts_mode = ""
                mta_sts_max_age = None
                mta_sts_id = ""

            try:
                tlsrpt_rua = await fetch_tlsrpt_rua(registered, self.lookup) or ""
            except Exception:
                tlsrpt_rua = ""

            # Optional blocking probes
            want_probes = self._run_blocking_probes and mx_host_final and (mx_under_customer or has_mta_sts)
            if want_probes:
                try:
                    results = await asyncio.gather(
                        probe_https_cert(registered, ips=mx_ips or None, probe_timeout=5.0),
                        probe_smtp_starttls_cert(mx_host_final, ips=mx_ips or None, probe_timeout=5.0),
                        return_exceptions=True,
                    )
                except Exception:
                    results = []

                if results:
                    val = results[0] if len(results) > 0 else None
                    if not isinstance(val, BaseException) and val:
                        try:
                            https_ok, https_days, https_issuer, https_san = val
                        except Exception:
                            https_ok = https_days = https_issuer = https_san = None
                    val = results[1] if len(results) > 1 else None
                    if not isinstance(val, BaseException) and val:
                        try:
                            smtp_ok, smtp_days, smtp_issuer = val
                        except Exception:
                            smtp_ok = smtp_days = smtp_issuer = None

        return (
            mx_host_final,
            mx_regdom_final,
            mx_cname_chain,
            mx_under_customer,
            mx_ips,
            mx_ptr_first,
            mx_ptr_regdom_first,
            mx_banner_raw,
            mx_banner_host,
            mx_banner_details,
            mx_banner_provider,
            mx_banner_category,
            mx_domain,
            mx_tld,
            spf_txt,
            dmarc_txt,
            bimi_txt,
            status,
            mta_sts_txt,
            mta_sts_mode,
            mta_sts_max_age,
            mta_sts_id,
            has_mta_sts,
            tlsrpt_rua,
            https_ok,
            https_days,
            https_issuer,
            https_san,
            smtp_ok,
            smtp_days,
            smtp_issuer,

        )


async def fetch_batch(
    domains: Iterable[str],
    semaphore: Optional[asyncio.Semaphore] = None,
    workers: int = DEFAULT_BATCH_WORKERS,
    retry_limit: int = 1,
    logger_obj: Optional[Any] = None,
) -> Tuple[List[DNSRecord], List[DNSRecord]]:
    """
    Batch-mode DNS fetcher. Returns (results, retries).
    """

    # Prefer an injected logger (e.g. app logger bound in DNSApplication), otherwise use module log
    local_log = logger_obj if logger_obj is not None else log
    # If injected logger is loguru-like, bind additional context
    try:
        if hasattr(local_log, "bind"):
            local_log = local_log.bind(workers=workers)
    except Exception:
        pass

    local_log.info("Starting fetch_batch: workers={} retry_limit={}", workers, retry_limit)

    # Ensure fetch_domain exists
    try:
        fetch_domain  # type: ignore[name-defined]
    except NameError:
        raise RuntimeError("fetch_domain not defined in dns_fetcher module")

    if semaphore is None:
        semaphore = dns_lookup.default_semaphore()

    # Create queue and enqueue domains
    queue: asyncio.Queue = asyncio.Queue()
    count = 0
    for d in domains:
        await queue.put(d)
        count += 1
    local_log.info("Enqueued {} domains for batch fetch", count)

    results: List[DNSRecord] = []
    retries: List[DNSRecord] = []

    async def _worker(worker_id: int):
        local_log.debug("Worker {} started", worker_id)
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                local_log.debug("Worker {} received sentinel and will exit", worker_id)
                break
            domain = item
            try:
                rec = await fetch_domain(domain, semaphore=semaphore, retry_limit=retry_limit)
                if getattr(rec, "status", None) == "needs_retry":
                    retries.append(rec)
                    local_log.debug("Domain {} marked needs_retry", domain)
                else:
                    results.append(rec)
                    local_log.debug("Domain {} fetched OK", domain)
            except Exception as e:
                # Log exception with traceback
                try:
                    local_log.exception("fetch_domain failed for {} (worker {})", domain, worker_id)
                except Exception:
                    # fallback minimal log
                    local_log.exception("fetch_domain failed for {} (worker {})", domain, worker_id)
                fallback = DNSRecord(domain=domain, status="needs_retry", records={}, errors={"exception": str(e)}, meta={})
                retries.append(fallback)
            finally:
                queue.task_done()

    # Start workers
    worker_tasks = [asyncio.create_task(_worker(i)) for i in range(workers)]

    # Push sentinel for each worker
    for _ in worker_tasks:
        await queue.put(None)

    # Wait until all tasks processed
    await queue.join()

    # Wait for workers to finish
    await asyncio.gather(*worker_tasks, return_exceptions=True)

    local_log.info("fetch_batch complete: results={} retries={}", len(results), len(retries))
    return results, retries