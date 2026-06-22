#!/usr/bin/env python3
from __future__ import annotations
import asyncio
import csv
import re
import sys
import time
import argparse
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple

import pyarrow as pa
import pyarrow.parquet as pq
from aiolimiter import AsyncLimiter

# ------------------------------
# Parsing: 220 <host> [ESMTP] <details...>
# ------------------------------
ROBUST_BANNER_REGEX = re.compile(r"^220\s+([\S]+)(?:\s+(?:E?SMTP)\s*(.*))?", re.IGNORECASE)

def parse_smtp_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (announced_hostname, software_details) or (None, None) if not parseable.
    """
    if not banner:
        return None, None
    line = banner.strip()
    m = ROBUST_BANNER_REGEX.match(line)
    if not m:
        return None, None
    host, details = m.groups()
    details = (details or "").strip()
    return host, details

# ------------------------------
# Classification via mapping CSV
# ------------------------------

@dataclass
class BannerRule:
    host_re: Optional[re.Pattern]
    details_re: Optional[re.Pattern]
    provider: str
    category: str
    confidence: int

class BannerClassifier:
    """
    Loads a regex mapping CSV and classifies (host, details) → provider/category/confidence.
    CSV schema (headers, case-insensitive):
      host_regex, details_regex, provider, category, confidence
    - Either regex may be blank to mean "match anything".
    - confidence is 0..100
    """
    def __init__(self, rules: List[BannerRule]):
        self.rules = rules

    @classmethod
    def from_csv(cls, path: Optional[str]) -> "BannerClassifier":
        rules: List[BannerRule] = []
        if path:
            with open(path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    host_rx = row.get("host_regex", "") or ""
                    details_rx = row.get("details_regex", "") or ""
                    provider = (row.get("provider", "") or "").strip()
                    category = (row.get("category", "") or "").strip()
                    conf_str = (row.get("confidence", "80") or "80").strip()
                    try:
                        conf = max(0, min(100, int(conf_str)))
                    except Exception:
                        conf = 80
                    host_re = re.compile(host_rx, re.IGNORECASE) if host_rx else None
                    details_re = re.compile(details_rx, re.IGNORECASE) if details_rx else None
                    rules.append(BannerRule(host_re, details_re, provider, category, conf))

        # Fallback built-ins (only used if CSV is empty/missing)
        if not rules:
            builtin = [
                # Google Workspace
                BannerRule(re.compile(r"(mx|smtp)\.google\.com|googlemail\.com", re.I), None, "Google", "Mailbox Provider", 95),
                BannerRule(None, re.compile(r"gsmtp", re.I), "Google", "Mailbox Provider", 85),

                # Microsoft 365 / Exchange Online
                BannerRule(re.compile(r"(outlook|office365|protection\.outlook)\.com", re.I), None, "Microsoft", "Mailbox Provider", 95),
                BannerRule(None, re.compile(r"microsoft", re.I), "Microsoft", "Mailbox Provider", 85),

                # Proofpoint / Mimecast / Barracuda (common fronting)
                BannerRule(None, re.compile(r"proofpoint", re.I), "Proofpoint", "Security Gateway", 90),
                BannerRule(None, re.compile(r"mimecast", re.I), "Mimecast", "Security Gateway", 90),
                BannerRule(None, re.compile(r"barracuda", re.I), "Barracuda", "Security Gateway", 85),

                # Transactional
                BannerRule(None, re.compile(r"mailgun", re.I), "Mailgun", "Transactional", 90),
                BannerRule(None, re.compile(r"sendgrid", re.I), "SendGrid", "Transactional", 90),
                BannerRule(None, re.compile(r"amazonses", re.I), "Amazon SES", "Transactional", 90),

                # Popular self-hosted MTAs
                BannerRule(None, re.compile(r"\bpostfix\b", re.I), "Postfix", "Self-hosted MTA", 80),
                BannerRule(None, re.compile(r"\bexim\b", re.I), "Exim", "Self-hosted MTA", 75),
                BannerRule(None, re.compile(r"\bharaka\b", re.I), "Haraka", "Self-hosted MTA", 70),
                BannerRule(None, re.compile(r"\bqmail\b", re.I), "Qmail", "Self-hosted MTA", 70),
            ]
            rules.extend(builtin)

        return cls(rules)

    def classify(self, host: Optional[str], details: Optional[str]) -> Tuple[str, str, int]:
        h = host or ""
        d = details or ""
        for rule in self.rules:
            host_ok = True if rule.host_re is None else bool(rule.host_re.search(h))
            details_ok = True if rule.details_re is None else bool(rule.details_re.search(d))
            if host_ok and details_ok:
                return (rule.provider, rule.category, rule.confidence)
        return ("Unknown", "Unknown", 0)

# ------------------------------
# Async banner fetcher
# ------------------------------

async def fetch_banner_once(host: str, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    """
    Opens TCP to host:25, returns (first_line, error). No EHLO; read greeting then close.
    """
    reader = writer = None
    try:
        # DNS happens in getaddrinfo within open_connection; if you want to avoid that
        # and feed IPs directly, pre-resolve upstream and connect to IP.
        fut = asyncio.open_connection(host, 25)
        reader, writer = await asyncio.wait_for(fut, timeout)
        line = await asyncio.wait_for(reader.readline(), timeout)
        banner = line.decode(errors="ignore").strip()
        return banner, None
    except Exception as e:
        return None, type(e).__name__
    finally:
        try:
            if writer:
                writer.close()
                await writer.wait_closed()
        except Exception:
            pass

async def probe_host(host: str, timeout: float, retries: int, limiter: AsyncLimiter) -> Dict[str, Optional[str]]:
    """
    Apply limiter, retry policy, and return a dict with banner & error info.
    """
    async with limiter:
        for i in range(retries + 1):
            banner, err = await fetch_banner_once(host, timeout)
            if banner:
                return {"mx_host": host, "banner_raw": banner, "error": None, "tries": i+1}
            # retry only on transient-ish errors
            if i < retries and err in {"TimeoutError", "Timeout", "ConnectionRefusedError", "ConnectionResetError"}:
                await asyncio.sleep(0.15 * (i + 1))
                continue
            return {"mx_host": host, "banner_raw": None, "error": err, "tries": i+1}

# ------------------------------
# Orchestration
# ------------------------------

def read_mx_hosts(input_path: str, column: str) -> List[str]:
    """
    Load MX hosts from Parquet/CSV. Deduplicate + basic cleanup.
    """
    if input_path.lower().endswith(".parquet"):
        table = pq.read_table(input_path, columns=[column])
        hosts = [h for h in table[column].to_pylist() if isinstance(h, str) and h]
    else:
        # CSV fallback
        import pandas as pd
        df = pd.read_csv(input_path, usecols=[column])
        hosts = [str(h) for h in df[column].dropna().astype(str).tolist() if h]
    # normalize: lowercase, strip trailing dot
    norm = []
    seen = set()
    for h in hosts:
        hh = h.rstrip(".").lower()
        if hh and hh not in seen:
            seen.add(hh)
            norm.append(hh)
    return norm

def make_output_table(rows: List[Dict], cls: BannerClassifier) -> pa.Table:
    """
    Convert raw probe rows to Arrow with parsed + classified fields.
    """
    out = []
    ts = int(time.time())
    for r in rows:
        host = r["mx_host"]
        raw = r.get("banner_raw") or ""
        err = r.get("error")
        tries = int(r.get("tries") or 0)

        b_host, b_details = parse_smtp_banner(raw)
        provider, category, conf = cls.classify(b_host, b_details)

        out.append({
            "ts_unix": ts,
            "mx_host": host,
            "banner_raw": raw,
            "banner_host": b_host or "",
            "banner_details": b_details or "",
            "provider": provider,
            "category": category,
            "confidence": conf,
            "error": err or "",
            "tries": tries,
        })

    schema = pa.schema([
        pa.field("ts_unix", pa.int64()),
        pa.field("mx_host", pa.string()),
        pa.field("banner_raw", pa.string()),
        pa.field("banner_host", pa.string()),
        pa.field("banner_details", pa.string()),
        pa.field("provider", pa.string()),
        pa.field("category", pa.string()),
        pa.field("confidence", pa.int32()),
        pa.field("error", pa.string()),
        pa.field("tries", pa.int32()),
    ])
    return pa.Table.from_pylist(out, schema=schema)

async def run(
    input_path: str,
    output_path: str,
    host_column: str,
    mapping_csv: Optional[str],
    qps: int,
    concurrency: int,
    timeout: float,
    retries: int
):
    mx_hosts = read_mx_hosts(input_path, host_column)
    if not mx_hosts:
        print("No MX hosts found in input.")
        return

    limiter = AsyncLimiter(qps, 1)
    sem = asyncio.Semaphore(concurrency)
    classifier = BannerClassifier.from_csv(mapping_csv)

    async def _one(h):
        async with sem:
            return await probe_host(h, timeout=timeout, retries=retries, limiter=limiter)

    tasks = [asyncio.create_task(_one(h)) for h in mx_hosts]
    rows = await asyncio.gather(*tasks)

    table = make_output_table(rows, classifier)
    pq.write_table(table, output_path)
    print(f"Wrote {table.num_rows} rows → {output_path}")

def main():
    ap = argparse.ArgumentParser(description="SMTP Banner Analyzer for MX hosts")
    ap.add_argument("--input", required=True, help="Input file (Parquet or CSV)")
    ap.add_argument("--column", default="mx_host", help="Column name containing MX FQDNs (default: mx_host)")
    ap.add_argument("--output", required=True, help="Output Parquet path")
    ap.add_argument("--mapping", default=None, help="Optional mapping CSV (regex → provider/category/confidence)")
    ap.add_argument("--qps", type=int, default=20, help="Limiter: connections per second (default: 20)")
    ap.add_argument("--concurrency", type=int, default=200, help="Max concurrent sockets (default: 200)")
    ap.add_argument("--timeout", type=float, default=3.0, help="Socket + read timeout seconds (default: 3.0)")
    ap.add_argument("--retries", type=int, default=1, help="Transient retries (default: 1)")
    args = ap.parse_args()

    asyncio.run(run(
        input_path=args.input,
        output_path=args.output,
        host_column=args.column,
        mapping_csv=args.mapping,
        qps=args.qps,
        concurrency=args.concurrency,
        timeout=args.timeout,
        retries=args.retries,
    ))

if __name__ == "__main__":
    main()
