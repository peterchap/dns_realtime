from __future__ import annotations
import asyncio
import datetime
import inspect
import sys
import os
import traceback
import ipaddress
from .logger import get_child_logger
from typing import Optional, List, Any, Dict, cast, Iterable, Tuple
from dotenv import load_dotenv

load_dotenv()

try:
    from .dns_records import DNSRecords, DNSRecord
except Exception:
    # Print helpful debug info to stderr (will appear in container logs / celery worker logs)
    sys.stderr.write("Failed to import dns_module.dns_records\n")
    sys.stderr.write(f"CWD: {os.getcwd()}\n")
    sys.stderr.write("sys.path:\n")
    for p in sys.path:
        sys.stderr.write(f"  {p}\n")
    sys.stderr.write("Traceback:\n")
    traceback.print_exc(file=sys.stderr)
    # Re-raise so the original ImportError is preserved (so your process stops)
    raise

# Import the dns_lookup module used throughout this file
try:
    from . import dns_lookup
except Exception:
    # Print helpful debug info to stderr (will appear in container logs / celery worker logs)
    sys.stderr.write("Failed to import dns_module.dns_lookup\n")
    sys.stderr.write(f"CWD: {os.getcwd()}\n")
    sys.stderr.write("sys.path:\n")
    for p in sys.path:
        sys.stderr.write(f"  {p}\n")
    sys.stderr.write("Traceback:\n")
    traceback.print_exc(file=sys.stderr)
    # Re-raise so the original ImportError is preserved (so your process stops)
    raise


from .probes import probe_https_cert, probe_smtp_starttls_cert
from .policy import detect_mta_sts, fetch_tlsrpt_rua
from .dns_utils import (
    to_ascii_hostname, reg_domain, ip_to_int,
    parse_smtp_banner, infer_mbp_from_banner,
    list_to_string
)

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
        retries: int = 2,
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
            if rcode == "NOERROR" and answers:
                # answers list contains SOA objects or mname; normalize to string first entry
                first = answers[0] if isinstance(answers, list) and answers else None
                # We cannot reliably parse serial here from dnspython-lite answers; return None for serial
                return str(first) if first else None, ttl, None, None
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
        # Phase 1: Fetch core records concurrently (NS, SOA, A)
        core_tasks = [
            dns_lookup.lookup_ns(domain, resolver, semaphore),
            dns_lookup.lookup_soa(domain, resolver, semaphore),
            dns_lookup.lookup_a(domain, resolver, semaphore),
        ]
        
        core_results = await asyncio.gather(*core_tasks, return_exceptions=True)
        
        # Unpack core results
        ns_rcode, ns_answers, ns_ttl = core_results[0] if not isinstance(core_results[0], BaseException) else ('ERROR', [], 0)
        soa_rcode, soa_answers, soa_ttl = core_results[1] if not isinstance(core_results[1], BaseException) else ('ERROR', [], 0)
        a_rcode, a_answers, a_ttl = core_results[2] if not isinstance(core_results[2], BaseException) else ('ERROR', [], 0)
        
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

        # If some core lookups failed, retry them
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
                if not core_ok['a']:
                    retry_tasks.append(dns_lookup.lookup_a(domain, resolver, semaphore))
                    retry_types.append('a')
                
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
                    elif rtype == 'a' and rcode == 'NOERROR' and answers:
                        a_rcode, a_answers, a_ttl = rcode, answers, ttl
                        core_ok['a'] = True
        
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
        
        # Phase 2: Check if any core record changed
        change_tasks = [
            dns_lookup.check_changed_and_enqueue_update('NS', domain, ns_rcode, ns_answers, ns_ttl),
            dns_lookup.check_changed_and_enqueue_update('SOA', domain, soa_rcode, soa_answers, soa_ttl),
            dns_lookup.check_changed_and_enqueue_update('A', domain, a_rcode, a_answers, a_ttl),
        ]
        
        change_results = await asyncio.gather(*change_tasks, return_exceptions=True)
        any_changed = any(r for r in change_results if not isinstance(r, BaseException) and r)

        record.meta['changed'] = str(any_changed)
        # Always fetch grouped records so outputs contain full DNS set
        
        # Phase 3: Fetch grouped records concurrently (AAAA, MX, TXT, CAA, NAPTR)
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
                record.records['AAAA'] = aaaa_answers
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
                record.records['MX'] = mx_answers
                # Derive primary mx_host_final and its registered domain for downstream norms
                try:
                    first = mx_answers[0]
                    parts = str(first).split(':', 1)
                    host = parts[1] if len(parts) == 2 else str(first)
                    host = host.rstrip('.')
                    record.records['mx'] = host
                    record.records['mx_host_final'] = host
                    record.records['mx_domain'] = reg_domain(host) or ''
                    record.records['mx_regdom_final'] = reg_domain(host) or ''
                except Exception:
                    pass
            else:
                record.errors['MX'] = mx_rcode
            try:
                record.meta['mx_ttl'] = int(mx_ttl) if mx_ttl is not None else None
            except Exception:
                pass
        
        # Process TXT
        if not isinstance(grouped_results[2], BaseException):
            txt_rcode, txt_answers, txt_ttl = grouped_results[2]
            if txt_rcode == 'NOERROR' and txt_answers:
                record.records['TXT'] = txt_answers
            else:
                record.errors['TXT'] = txt_rcode
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
                record.records['CAA'] = caa_list
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
                record.records['NAPTR'] = naptr_list
                record.meta['naptr_struct'] = naptr_struct
            else:
                record.errors['NAPTR'] = naptr_rcode
            try:
                record.meta['naptr_ttl'] = int(naptr_ttl) if naptr_ttl is not None else None
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
            if srv_errors:
                # Store detailed SRV errors under meta; summarize under errors
                record.meta['srv_errors'] = srv_errors
                record.errors['SRV'] = ", ".join([f"{svc}:{rcode}" for svc, rcode in srv_errors.items()])
            if srv_ttl_map:
                record.meta['srv_ttl'] = srv_ttl_map
        
        # Phase 4: Batch PTR lookups for all discovered IPs
        all_ips = set()
        for ip in a_answers:
            all_ips.add(ip)
        if 'AAAA' in record.records:
            for ip in record.records['AAAA']:
                all_ips.add(ip)
        
        if all_ips:
            # Convert IPs to reverse DNS names
            ptr_tasks = []
            ptr_ips = []
            for ip in all_ips:
                try:
                    # Create reverse DNS name
                    ip_obj = ipaddress.ip_address(ip)
                    reverse_name = ip_obj.reverse_pointer
                    ptr_tasks.append(dns_lookup.lookup_ptr(reverse_name, resolver, semaphore))
                    ptr_ips.append(ip)
                except Exception:
                    pass
            
            if ptr_tasks:
                ptr_results = await asyncio.gather(*ptr_tasks, return_exceptions=True)
                ptr_map = {}
                for i, ip in enumerate(ptr_ips):
                    entry = ptr_results[i]
                    if isinstance(entry, BaseException):
                        continue
                    if not (isinstance(entry, (tuple, list)) and len(entry) >= 3):
                        continue
                    # Unpack only rcode and answers; TTL unused
                    ptr_rcode, ptr_answers = entry[0], entry[1]
                    if ptr_rcode == 'NOERROR' and ptr_answers:
                        try:
                            ptr_map[ip] = ptr_answers[0]  # Take first PTR
                        except Exception:
                            pass
                if ptr_map:
                    record.records['PTR'] = ptr_map
        
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
                    raw_obj = await asyncio.wait_for(fetch_result, timeout=self._domain_timeout_s)
                else:
                    # Run synchronous implementation in thread
                    raw_obj = await asyncio.wait_for(asyncio.to_thread(fetch_domain, domain_ascii), timeout=self._domain_timeout_s)
                
                # Convert DNSRecord object to dict compatible with legacy logic
                if raw_obj and hasattr(raw_obj, "records"):
                    expanded = {}
                    # 1. Flatten records
                    expanded.update(raw_obj.records)
                    # 2. Add status
                    expanded["status"] = raw_obj.status
                    # 3. Flatten errors (legacy expects 'ns_error', 'a_error', etc.)
                    for k, v in raw_obj.errors.items():
                        expanded[f"{k.lower()}_error"] = v
                    # 4. Flatten meta
                    expanded.update(raw_obj.meta)
                else:
                    expanded = cast(Dict[str, Any], raw_obj) if isinstance(raw_obj, dict) else None

            except asyncio.TimeoutError:
                self.log(f"[{self.domain}] fetch_domain timeout after {self._domain_timeout_s}s")
            except Exception as e:
                self.log(f"[{self.domain}] fetch_domain failed: {e}")
                expanded = None

        # If we got an expanded dict, use its cached results; otherwise fall back to legacy probes.
        if expanded:
            # Core fields
            ns_list = expanded.get("ns") or []
            if isinstance(ns_list, list) and ns_list:
                ns1_str = list_to_string([str(x) for x in ns_list])
            elif isinstance(ns_list, str) and ns_list:
                ns1_str = list_to_string([ns_list])
            else:
                ns1_str = ""
            soa_mname = expanded.get("soa") or ""
            a_list = expanded.get("a") or []
            aaaa_list = expanded.get("aaaa") or []
            a_err = expanded.get("a_error") or ""
            ns_err = expanded.get("ns_error") or ""
            soa_err = expanded.get("soa_error") or ""
            status = (expanded.get("status") or "").upper()
            hosts = expanded.get("hosts") or {}
            ptrs = expanded.get("ptrs") or {}

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
                # if missing, fallback to lookup.cname_chain + resolve_a_aaaa
                if not mx_ips:
                    try:
                        mx_host_final_try, chain = await self.lookup.cname_chain(mx_host_final, limit=5)
                        mx_cname_chain = chain or []
                        mx_host_final = mx_host_final_try or mx_host_final
                    except Exception:
                        mx_cname_chain = []
                    try:
                        mx_a, mx_aaaa, _, _ = await self.lookup.resolve_a_aaaa(mx_host_final)
                        mx_ips = (mx_a or []) + (mx_aaaa or [])
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
                dnssec=bool(expanded.get("dnskey") or False),
                soa_serial=expanded.get("soa_serial") or 0,
                # New record fields
                caa=list_to_string(caa_list) if caa_list else "",
                naptr=list_to_string(naptr_list) if naptr_list else "",
                srv=list_to_string(srv_list) if srv_list else "",
                caa_records=caa_struct,
                naptr_records=naptr_struct,
                srv_records=srv_struct,
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
            mx_domain,
            mx_ips,
            mx_under_customer,
            mx_ptr_first,
            mx_ptr_regdom_first,
            mx_regdom_final,
            mx_cname_chain,
            spf_txt,
            dmarc_txt,
            has_mta_sts,
            mta_sts_txt,
            mta_sts_mode,
            mta_sts_max_age,
            mta_sts_id,
            tlsrpt_rua,
            mx_banner_raw,
            mx_banner_host,
            mx_banner_details,
            https_ok,
            https_days,
            https_issuer,
            https_san,
            smtp_ok,
            smtp_days,
            smtp_issuer,

        ) = await _gather_mx_data(mx_host_input)

        # www and mail subdomains
        www_host = f"www.{registered}"
        mail_host = f"mail.{registered}"
        
        # Parallel fetch for www/mail
        # We use lookup helper for convenience
        try:
             www_a, _, _, _ = await self.lookup.resolve_a_aaaa(www_host)
             www_a_first = www_a[0] if www_a else ""
        except Exception:
             www_a_first = ""
        try:
             mail_a, _, _, _ = await self.lookup.resolve_a_aaaa(mail_host)
             mail_a_first = mail_a[0] if mail_a else ""
        except Exception:
             mail_a_first = ""
        
        # Resolve PTRs for them
        www_ptr = ""
        if www_a_first:
             try:
                 www_ptr = await self.lookup.resolve_ptr_first(www_a_first)
             except Exception:
                 www_ptr = ""
        mail_ptr = ""
        if mail_a_first:
             try:
                 mail_ptr = await self.lookup.resolve_ptr_first(mail_a_first)
             except Exception:
                 mail_ptr = ""

        # CNAMEs for www/mail
        try:
             www_cname = ""
             resp = await self.lookup._retry_resolve(www_host, "CNAME")
             if resp and resp[0]:
                 rr = next(iter(resp[0]), None)
                 if rr:
                     www_cname = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
        except Exception:
             www_cname = ""
        try:
             mail_cname = ""
             resp = await self.lookup._retry_resolve(mail_host, "CNAME")
             if resp and resp[0]:
                 rr = next(iter(resp[0]), None)
                 if rr:
                     mail_cname = str(getattr(rr, "cname", getattr(rr, "target", getattr(rr, "name", rr)))).rstrip(".").lower()
        except Exception:
             mail_cname = ""

        # Build final record
        rec = DNSRecords(
            domain=self.domain,
            registered_domain=registered,
            ns1=list_to_string(ns1_val) if ns1_val else "",
            soa=soa_mname or "",
            status="alive",
            ns_error=ns_err or "",
            soa_error=soa_err or "",
            a_error=a_err or "",
            a=list_to_string(a_list) if a_list else "",
            aaaa=list_to_string(aaaa_list) if aaaa_list else "",
            ip_int=ip_to_int(a_list[0]) if a_list else 0,
            a_ttl=ttl_min or 0,
            ptr=ptr_apex or "",
            cname=apex_cname or "",
            mx=mx_host_input or "",
            mx_priority=mx_pref or 0,
            mx_host_final=mx_host_final or "",
            mx_regdom_final=mx_regdom_final or "",
            mx_cname_chain=mx_cname_chain,
            mx_under_customer=bool(mx_under_customer),
            mx_banner_raw=mx_banner_raw or "",
            mx_banner_details=mx_banner_details or "",
            mx_banner_provider="",
            mx_banner_category="",
            mx_domain=mx_regdom_final or "",
            mx_tld=(mx_regdom_final.split(".")[-1] if mx_regdom_final else ""),
            mx_ips=mx_ips or [],
            mx_ptr=mx_ptr_first or "",
            mx_ptr_regdom=mx_ptr_regdom_first or "",
            spf=spf_txt or "",
            dmarc=dmarc_txt or "",
            bimi="",
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
            mail_mx_banner_raw=mx_banner_raw or "",
            mail_mx_banner_host=mx_banner_host or "",
            mail_mx_banner_details=mx_banner_details or "",
            mail_mx_banner_provider="",
            mail_mx_banner_category="",
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
            # new fields empty for legacy path unless we backfill them (skipped for brevity)
            caa="", naptr="", srv="",
            caa_records=[], naptr_records=[], srv_records=[],
            aaaa_ttl=None, mx_ttl=None, txt_ttl=None, caa_ttl=None, naptr_ttl=None,
            refresh_date=now,
        )

        # Normalize empty strings for legacy result too
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
        Helper method that implements the MX discovery & probing logic used by both
        legacy fetch and new fetch_domain wrapper.
        Returns a tuple matching the unpacking signature.
        """
        # Resolve MX IP(s)
        mx_host_final = ""
        mx_pref = 0
        if host_input:
            parts = host_input.split(":")
            if len(parts) == 2:
                mx_host_final = parts[1]
            else:
                mx_host_final = host_input
        mx_host_final = mx_host_final.rstrip(".").lower()
        
        mx_cname_chain = []
        if mx_host_final:
            try:
                mx_host_final_try, chain = await self.lookup.cname_chain(mx_host_final, limit=5)
                mx_cname_chain = chain or []
                mx_host_final = mx_host_final_try or mx_host_final
            except Exception:
                 pass
        
        mx_ips = []
        mx_a_list = []
        if mx_host_final:
            try:
                mx_a, mx_aaaa, _, _ = await self.lookup.resolve_a_aaaa(mx_host_final)
                mx_a_list = mx_a or []
                mx_ips = (mx_a or []) + (mx_aaaa or [])
            except Exception:
                pass
        
        mx_regdom_final = reg_domain(mx_host_final) if mx_host_final else ""
        mx_domain = mx_regdom_final # alias
        mx_under_customer = bool(mx_regdom_final and mx_regdom_final == registered)
        
        # Reverse PTR for first MX IP
        mx_ptr_first = ""
        if mx_ips:
            try:
                mx_ptr_first = await self.lookup.resolve_ptr_first(mx_ips[0])
            except Exception:
                mx_ptr_first = ""
        mx_ptr_regdom_first = reg_domain(mx_ptr_first) if mx_ptr_first else ""

        # Banner / SMTP probing
        mx_banner_raw = ""
        mx_banner_host = ""
        mx_banner_details = ""
        smtp_issuer = None
        
        # Only probe if configured (legacy path implies we might want banner if ip exists)
        # But we rely on self.smtp_banner_client being present
        if self.smtp_banner_client and mx_ips:
             try:
                 banner_future = self.smtp_banner_client.get_banner(mx_ips[0], port=25)
                 banner_res = await asyncio.wait_for(banner_future, timeout=4.0)
                 if banner_res:
                     mx_banner_raw = str(banner_res).strip()
                     parsed = parse_smtp_banner(mx_banner_raw)
                     mx_banner_host = parsed.get("hostname") or ""
                     software = parsed.get("software") or ""
                     version = parsed.get("version") or ""
                     mx_banner_details = f"{software} {version}".strip()
                     
                     # Check for google/outlook/etc from banner logic if needed
                     # inferred = infer_mbp_from_banner(...)
             except Exception:
                 pass

        # Text records (SPF/DMARC/MTA-STS)
        spf_txt = ""
        dmarc_txt = ""
        try:
             # SPF on apex
             txts = await self.lookup.resolve_txt_join(registered)
             spf_txt = next((t for t in txts if "v=spf1" in t.lower()), "")
        except Exception:
             spf_txt = ""
        try:
             # DMARC on _dmarc
             txts = await self.lookup.resolve_txt_join(f"_dmarc.{registered}")
             dmarc_txt = next((t for t in txts if t.lower().startswith("v=dmarc")), "")
        except Exception:
             dmarc_txt = ""

        # MTA-STS / TLS-RPT
        has_mta_sts = False
        mta_sts_txt = ""
        mta_sts_mode = ""
        mta_sts_max_age = None
        mta_sts_id = ""
        try:
             # Start with TXT check
             txt_mta = await self.lookup.resolve_txt_joined(f"_mta-sts.{registered}")
             if "v=STSv1" in txt_mta:
                 mta_sts_txt = txt_mta
                 # parse mode/id/max_age from txt? 
                 # simplistic parse for compat:
                 for part in txt_mta.split(";"):
                     p = part.strip()
                     if p.startswith("id="): mta_sts_id = p[3:]
                     if p.startswith("mode="): mta_sts_mode = p[5:]
                 # To fully detect, we'd fetch the policy HTTPS, but let's stick to TXT signal for basic check
                 # or use policy.detect_mta_sts helper if available
                 has_mta_sts = True
                 if self._fetch_mta_sts_policy:
                     pol = await detect_mta_sts(registered, self.lookup, fetch_policy=True)
                     if pol.get("has_mta_sts"):
                         mta_sts_mode = pol.get("mode") or mta_sts_mode
                         mta_sts_max_age = pol.get("max_age")
        except Exception:
             pass

        tlsrpt_rua = ""
        try:
             # simple TXT lookup for _smtp._tls
             txt_rpt = await self.lookup.resolve_txt_joined(f"_smtp._tls.{registered}")
             if "v=TLSRPTv1" in txt_rpt:
                  # extract rua
                  import re
                  m = re.search(r"rua=([^;]+)", txt_rpt)
                  if m:
                      tlsrpt_rua = m.group(1)
        except Exception:
             pass
        
        # Cert placeholders (populated by probes in caller if desired)
        https_ok = None
        https_days = None
        https_issuer = None
        https_san = None
        smtp_ok = None
        smtp_days = None
        
        return (
            mx_host_final, mx_domain, mx_ips, mx_under_customer,
            mx_ptr_first, mx_ptr_regdom_first, mx_regdom_final, mx_cname_chain,
            spf_txt, dmarc_txt, has_mta_sts, mta_sts_txt, mta_sts_mode, mta_sts_max_age, mta_sts_id,
            tlsrpt_rua, mx_banner_raw, mx_banner_host, mx_banner_details,
            https_ok, https_days, https_issuer, https_san,
            smtp_ok, smtp_days, smtp_issuer
        )

async def fetch_batch(domains: List[str], max_workers: int = 50) -> List[DNSRecords]:
    """
    Convenience function to fetch a batch of domains concurrently.
    """
    semaphore = asyncio.Semaphore(max_workers)
    # Use a single shared resolver for the batch
    lookup_shim = DNSLookup()
    
    async def _sem_fetch(d: str):
        async with semaphore:
            fetcher = DNSFetcher(d, lookup=lookup_shim)
            return await fetcher.fetch_records()

    tasks = [_sem_fetch(d) for d in domains]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    final = []
    for r in results:
        if isinstance(r, DNSRecords):
            final.append(r)
        else:
            # handle error or exception
            pass
    return final
