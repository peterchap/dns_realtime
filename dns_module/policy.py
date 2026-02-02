"""
dns_module/policy.py

Policy-related helpers: detect MTA-STS presence, fetch mta-sts policy over HTTPS,
and extract TLS-RPT rua from _smtp._tls TXT.

Public API:
- async detect_mta_sts(regdom: str, lookup, fetch_policy: bool = False, http_timeout: float = 2.5)
    -> dict(has_mta_sts: bool, raw_txt: str, mode: str, max_age: Optional[int], id: Optional[str], policy_text: Optional[str])

- async fetch_tlsrpt_rua(regdom: str, lookup) -> str

Notes:
- `lookup` should offer async method `resolve_txt_joined(name)` returning joined TXT string.
  You can pass an instance of DNSLookup or any object with that method.
- HTTP fetch of the mta-sts policy (/.well-known/mta-sts.txt) is optional and bounded by timeout.
"""
from __future__ import annotations
import re
import aiohttp
from typing import Optional, Any, Dict

MTASTS_TXT_RE = re.compile(r"v\s*=\s*(?:stsv1|mta[-_]?sts)", re.I)
MTASTS_ID_RE = re.compile(r"^v\s*=\s*mta-sts:\s*id=(?P<id>[^;\s]+)", re.I)
MTASTS_MODE_RE = re.compile(r"(?mi)^mode\s*:\s*(?P<mode>\S+)")
MTASTS_MAXAGE_RE = re.compile(r"(?mi)^max_age\s*:\s*(?P<max>\d+)")
TLSRPT_RE = re.compile(r"^v=tlsrpt1;\s*rua=([^;]+)", re.I)


async def detect_mta_sts(
    regdom: str,
    lookup: Any,
    fetch_policy: bool = False,
    http_timeout: float = 2.5,
) -> Dict[str, Optional[Any]]:
    """
    Detect presence of MTA-STS via TXT record and optionally fetch the HTTP policy.

    Returns a dict:
      {
        "has_mta_sts": bool,
        "raw_txt": str,
        "mode": str or "",
        "max_age": int or None,
        "id": str or None,
        "policy_text": str or None
      }
    """
    raw_txt = ""
    mode = ""
    max_age = None
    sts_id = None
    policy_text = None
    has_mta = False

    try:
        raw_txt = await lookup.resolve_txt_joined(f"_mta-sts.{regdom}")
    except Exception:
        raw_txt = ""

    if raw_txt:
        if MTASTS_TXT_RE.search(raw_txt):
            has_mta = True
        m_id = MTASTS_ID_RE.search(raw_txt)
        if m_id:
            sts_id = m_id.group("id")

    # Optionally fetch the HTTPS policy file if TXT exists or fetch_policy True
    if fetch_policy and regdom:
        url = f"https://mta-sts.{regdom}/.well-known/mta-sts.txt"
        try:
            timeout = aiohttp.ClientTimeout(total=http_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as s:
                async with s.get(url, allow_redirects=True, ssl=False) as r:  # allow ssl False to avoid cert failures
                    if r.status == 200:
                        txt = await r.text()
                        policy_text = txt
                        # parse mode and max_age heuristically from policy body
                        m_mode = MTASTS_MODE_RE.search(txt)
                        if m_mode:
                            mode = m_mode.group("mode").strip().lower()
                        m_max = MTASTS_MAXAGE_RE.search(txt)
                        if m_max:
                            try:
                                max_age = int(m_max.group("max"))
                            except Exception:
                                max_age = None
        except Exception:
            # swallow network errors and return what we have
            policy_text = None

    return {
        "has_mta_sts": bool(has_mta),
        "raw_txt": raw_txt or "",
        "mode": mode or "",
        "max_age": max_age,
        "id": sts_id or None,
        "policy_text": policy_text,
    }


async def fetch_tlsrpt_rua(regdom: str, lookup: Any) -> str:
    """
    Read the _smtp._tls TXT and return the raw rua string (or empty string).
    """
    try:
        raw = await lookup.resolve_txt_joined(f"_smtp._tls.{regdom}")
    except Exception:
        return ""
    if not raw:
        return ""
    m = TLSRPT_RE.search(raw)
    return m.group(1).strip() if m else raw
