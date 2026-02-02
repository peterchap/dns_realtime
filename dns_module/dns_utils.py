# /root/dnsproject/dns_utils.py
from __future__ import annotations
import asyncio
import ipaddress
import re
import inspect
from typing import Optional, List, Dict, Any, Iterable, Tuple, Set, cast

import idna
import tldextract

# --------------------------------------------------------------------
# PSL extractor (shared, fast). If you manage PSL updates centrally,
# set suffix_list_urls=None and pre-seed cache_dir.
# --------------------------------------------------------------------
_EXTRACTOR = tldextract.TLDExtract(
    cache_dir="/srv/nfs/shared/.tldextract",
    suffix_list_urls=[],  # disable auto-download if you premanage PSL
)

# --------------------------------------------------------------------
# Basic utilities and normalization
# --------------------------------------------------------------------
def to_ascii_hostname(name: Optional[str]) -> str:
    """
    Lowercase + IDNA (punycode) each label + strip trailing dot.
    Returns "" if input is falsy.
    """
    if not name:
        return ""
    name = str(name).strip().strip(".")
    if not name:
        return ""
    labels: List[str] = []
    for lbl in name.split("."):
        if not lbl:
            continue
        try:
            # Use UTS46 processing which is more forgiving and handles most real-world inputs.
            labels.append(idna.encode(lbl, uts46=True, std3_rules=False).decode("ascii"))
        except idna.IDNAError:
            # As a last resort, strip invalid characters and keep only LDH labels.
            safe = re.sub(r"[^A-Za-z0-9\-]", "", lbl).strip("-")[:63].strip("-")
            if safe:
                labels.append(safe)
        except Exception:
            safe = re.sub(r"[^A-Za-z0-9\-]", "", lbl).strip("-")[:63].strip("-")
            if safe:
                labels.append(safe)
    return ".".join(labels).lower()


def normalize_name(value: Optional[str]) -> str:
    """Alias: normalize DNS names/hosts → ascii, lowercase, no trailing dot."""
    return to_ascii_hostname(value)


def normalize_name_legacy(value: Optional[str]) -> str:
    """
    Legacy shim: returns literal 'None' for falsy (to match older pipelines).
    Prefer normalize_name() elsewhere.
    """
    out = to_ascii_hostname(value)
    return out if out else "None"


def normalize_list(items: List[str]) -> List[str]:
    """Normalize a list of DNS names/hosts."""
    return [normalize_name(i) for i in items]


def normalize_txt(text: Optional[str]) -> str:
    """
    Normalize a TXT-like string:
      - strip wrapping quotes
      - DO NOT lowercase (TXT records can be case-sensitive for keys/values)
    Returns "" for falsy.
    """
    if not text:
        return ""
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] == '"':
        t = t[1:-1]
    return t


def normalize_mx_host(host: Optional[str]) -> str:
    """Normalize MX host specifically (same as normalize_name)."""
    return normalize_name(host)


def list_to_string(lst: List[str]) -> str:
    """
    Join a list of hostnames as a CSV-safe single string:
    - normalize each
    - replace commas inside items to avoid collisions
    """
    if not lst:
        return ""
    return ",".join(normalize_name(s).replace(",", ":") for s in lst)


def mx_to_string(mx_records: List[tuple]) -> str:
    """
    Convert [(priority, host), ...] into "prio:host,prio:host".
    """
    if not mx_records:
        return ""
    return ",".join(f"{int(priority)}:{normalize_mx_host(host)}" for priority, host in mx_records)


def ip_to_int(ip: str) -> int:
    """IPv4/IPv6 to integer; returns 0 on falsy/invalid."""
    try:
        return int(ipaddress.ip_address(ip)) if ip else 0
    except Exception:
        return 0


def extract_registered_domain(domain: str) -> tuple[str, str]:
    """
    Return (registered_domain, tld_suffix) using PSL.
    For compound public suffixes like 'co.uk' or 'co.br' the returned tld_suffix
    will be the last label (e.g. 'uk' or 'br'). Empty strings if not available.
    """
    if not domain:
        return "", ""
    ext = _EXTRACTOR(domain.lower().strip("."))
    registered_domain = ".".join(p for p in (ext.domain, ext.suffix) if p)
    tld_full = ext.suffix or ""
    tld = tld_full.split(".")[-1] if tld_full else ""
    return registered_domain, tld


def reg_domain(domain: Optional[str]) -> str:
    """
    Return the registered domain (eTLD+1) for a hostname, or "" if unavailable.
    """
    if not domain:
        return ""
    rd, _ = extract_registered_domain(domain)
    return rd

# --------------------------------------------------------------------
# --------------------------------------------------------------------
# Optional blocklist placeholder (HTTP). Keep or replace with your source.
# --------------------------------------------------------------------
def is_blocked(domain: str) -> bool:
    """
    Placeholder: replace with your real blocklist lookup.
    Keep network I/O out of hot paths if possible (cache upstream).
    """
    _ = domain  # mark parameter as intentionally unused to satisfy linters
    return False

# --------------------------------------------------------------------
# DNS answer normalization helpers (work with dnspython answers or plain strings)
# --------------------------------------------------------------------
def _as_hostnames(answer: Iterable[Any]) -> List[str]:
    """Extract hostname strings from resolver answer objects."""
    out: List[str] = []
    for a in answer or []:
        s = None
        for attr in ("host", "target", "name", "exchange"):
            if hasattr(a, attr):
                s = getattr(a, attr)
                break
        if s is None:
            s = str(a)
        out.append(to_ascii_hostname(str(s)))
    return out


def _as_ips(answer: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for a in answer or []:
        ip = getattr(a, "address", str(a))
        ip = str(ip).strip()
        try:
            ipaddress.ip_address(ip)
            out.append(ip)
        except Exception:
            continue
    return out

# --------------------------------------------------------------------
# SMTP banner parsing and minimal provider inference
# --------------------------------------------------------------------
ROBUST_BANNER_REGEX = re.compile(r"^220\s+([\S]+)(?:\s+(?:E?SMTP)\s*(.*))?$", re.IGNORECASE)

def parse_smtp_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (announced_hostname, software_details) or (None, None)."""
    if not banner:
        return None, None
    m = ROBUST_BANNER_REGEX.match(banner.strip())
    if not m:
        return None, None
    host, details = m.groups()
    return (host or "").strip(), (details or "").strip()


# High-precision hints (keep tiny here; put the big rules in provider tables)
_BANNER_MAP: List[Tuple[re.Pattern, Tuple[str, str]]] = [
    (re.compile(r"\bgoogle\b|\bgsmtp\b|\baspmx\b", re.I), ("Google Workspace", "EnterpriseMail")),
    (re.compile(r"\b(outlook|protection\.outlook|mail\.mailprotect\.microsoft)\b", re.I), ("Microsoft 365", "EnterpriseMail")),
    (re.compile(r"\bpphosted\.com\b|\bproofpoint\b", re.I), ("Proofpoint", "SEG")),
    (re.compile(r"\bmimecast\b", re.I), ("Mimecast", "SEG")),
    (re.compile(r"\bzoho\b", re.I), ("Zoho Mail", "EnterpriseMail")),
    (re.compile(r"\bmailgun\b|\bmailgun\.org\b", re.I), ("Mailgun", "TransactionalMail")),
    (re.compile(r"\bsendgrid\b|\bsendgrid\.net\b", re.I), ("SendGrid", "TransactionalMail")),
    (re.compile(r"\bamazonses\.com\b|\bses\b", re.I), ("Amazon SES", "TransactionalMail")),
]

def infer_mbp_from_banner(host: Optional[str], details: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    text = " ".join([host or "", details or ""])
    for pat, (prov, cat) in _BANNER_MAP:
        if pat.search(text):
            return prov, cat
    return None, None

# --------------------------------------------------------------------
# MX normalization (CNAME → A/AAAA → PTR). Resolver contract:
#   await resolve(name, "CNAME"/"A"/"AAAA"/"PTR") -> iterable
#   optional await reverse(ip) -> iterable PTR
# --------------------------------------------------------------------
async def normalize_mx_target(
    mx_host: str,
    customer_regdom: str,
    resolver,
    *,
    max_cname_hops: int = 8,
    dns_timeout_s: float = 1.5,
    reverse_timeout_s: float = 1.5,
    want_ipv6: bool = True,
) -> Dict[str, Any]:
    """
    Normalize an MX FQDN by:
      1) Following CNAME chain to a final host
      2) Resolving A/AAAA
      3) Reversing PTR for the IPs
    Returns fields used by downstream classification.
    """
    mx_host_input = to_ascii_hostname(mx_host)
    customer_regdom = (customer_regdom or "").lower()

    # 1) CNAME chase
    cname_chain: List[str] = [mx_host_input] if mx_host_input else []
    cur = mx_host_input
    hops = 0
    has_cname = False

    while cur and hops < max_cname_hops:
        try:
            ans = await asyncio.wait_for(resolver.resolve(cur, "CNAME"), timeout=dns_timeout_s)
        except Exception:
            break
        names = _as_hostnames(ans)
        if not names:
            break
        next_host = names[0]
        if next_host == cur:
            break
        has_cname = True
        cname_chain.append(next_host)
        cur = next_host
        hops += 1

    mx_host_final = cur
    mx_regdom_final = reg_domain(mx_host_final) if mx_host_final else ""

    # 2) A/AAAA
    ips: List[str] = []
    if mx_host_final:
        try:
            ans_a = await asyncio.wait_for(resolver.resolve(mx_host_final, "A"), timeout=dns_timeout_s)
            ips.extend(_as_ips(ans_a))
        except Exception:
            pass
        if want_ipv6:
            try:
                ans_aaaa = await asyncio.wait_for(resolver.resolve(mx_host_final, "AAAA"), timeout=dns_timeout_s)
                ips.extend(_as_ips(ans_aaaa))
            except Exception:
                pass

    async def _reverse(ip: str) -> Optional[str]:
        try:
            if hasattr(resolver, "reverse") and callable(resolver.reverse):
                maybe = resolver.reverse(ip)
                if inspect.isawaitable(maybe):
                    ans = await asyncio.wait_for(maybe, timeout=reverse_timeout_s)
                else:
                    ans = await asyncio.wait_for(asyncio.to_thread(resolver.reverse, ip), timeout=reverse_timeout_s)
                hosts = _as_hostnames(cast(Iterable[Any], ans))
                return hosts[0] if hosts else None
        except Exception:
            pass
        # synthesize in-addr/ip6.arpa
        try:
            ptr_name = ipaddress.ip_address(ip).reverse_pointer
            res = resolver.resolve(ptr_name, "PTR")
            if inspect.isawaitable(res):
                ans = await asyncio.wait_for(res, timeout=reverse_timeout_s)
            else:
                ans = await asyncio.wait_for(asyncio.to_thread(resolver.resolve, ptr_name, "PTR"), timeout=reverse_timeout_s)
            hosts = _as_hostnames(cast(Iterable[Any], ans))
            return hosts[0] if hosts else None
        except Exception:
            return None

    ptr_hosts: Set[str] = set()
    if ips:
        revs = await asyncio.gather(*[_reverse(ip) for ip in ips], return_exceptions=True)
        for r in revs:
            if isinstance(r, BaseException) or r is None:
                continue
            ptr_hosts.add(cast(str, r))

    ptr_hosts_list = sorted(ptr_hosts)
    ptr_regdoms = sorted({reg_domain(h) for h in ptr_hosts_list if h})

    return {
        "mx_host_input": mx_host_input,
        "mx_host_final": mx_host_final,
        "mx_regdom_final": mx_regdom_final,
        "mx_cname_chain": cname_chain,
        "mx_cname_hops": hops,
        "mx_has_cname": has_cname,
        "mx_ips": ips,
        "mx_ptr_hosts": ptr_hosts_list,
        "mx_ptr_regdoms": ptr_regdoms,
        "mx_ptr_host_first": ptr_hosts_list[0] if ptr_hosts_list else None,
        "mx_ptr_regdom_first": ptr_regdoms[0] if ptr_regdoms else None,
        "mx_under_customer": (mx_regdom_final == customer_regdom) if mx_regdom_final else False,
        "mx_ptr_missing": (len(ips) > 0 and not ptr_hosts_list),
    }
