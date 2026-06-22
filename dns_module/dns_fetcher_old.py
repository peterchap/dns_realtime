from __future__ import annotations
import asyncio
import datetime
import logging
import inspect
from typing import Optional, List, Any, Dict, cast

from .dns_lookup import DNSLookup
from .probes import probe_https_cert, probe_smtp_starttls_cert
from .policy import detect_mta_sts, fetch_tlsrpt_rua
from .dns_records import DNSRecords
from .dns_utils import (
    to_ascii_hostname, reg_domain, ip_to_int,
    parse_smtp_banner, infer_mbp_from_banner,
    list_to_string
)


class DNSFetcher:
    def __init__(
        self,
        domain: str,
        smtp_banner_client: Optional[Any] = None,
        logger=None,
        per_domain_max_concurrency: int = 20,
        dns_timeout_s: float = 5.0,
        retries: int = 2,
        run_blocking_probes: bool = False,
        fetch_mta_sts_policy: bool = True,
        domain_timeout_s: float = 5.0,
        lookup: Optional[DNSLookup] = None,
    ):
        self.domain = domain.rstrip(".").lower()
        if logger is None:
            logger = logging.getLogger("dns_fetcher").info
        self.log = logger
        self.smtp_banner_client = smtp_banner_client
        self._run_blocking_probes = bool(run_blocking_probes)
        self._fetch_mta_sts_policy = bool(fetch_mta_sts_policy)
        self._domain_timeout_s = domain_timeout_s

        # Use shared DNSLookup instance if provided, otherwise create a new one
        if lookup is not None:
            self.lookup = lookup
        else:
            self.lookup = DNSLookup(
                dns_timeout_s=dns_timeout_s,
                retries=retries,
                per_domain_max_concurrency=per_domain_max_concurrency,
                logger=self.log,
                nameservers=["127.0.0.1"],
            )

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
                                rec.https_cert_san_count = len(https_san.split("|")) if https_san else 0
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
        ns1_str = list_to_string(ns1_list) if ns1_list else ""
        a_str = list_to_string(a_list) if a_list else ""
        aaaa_str = list_to_string(aaaa_list) if aaaa_list else ""

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
            https_cert_san_count=len(https_san.split("|")) if (isinstance(https_san, str) and https_san) else 0,
            has_mta_sts=bool(has_mta_sts),
            mta_sts_txt=mta_sts_txt or "",
            mta_sts_mode=mta_sts_mode or "",
            mta_sts_max_age=mta_sts_max_age,
            mta_sts_id=mta_sts_id or "",
            tlsrpt_rua=tlsrpt_rua or "",
            dnssec=bool(dnssec),
            soa_serial=soa_serial or 0,
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
