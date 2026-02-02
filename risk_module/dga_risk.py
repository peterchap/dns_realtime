# dga_risk.py
from __future__ import annotations

import math
from collections import Counter
from typing import Optional, Tuple

import pyarrow as pa
import polars as pl

DGA_FEATURES_VERSION = "2025.10.20-rc1"


# ---------- Small, safe string utils ----------

_VOWELS = set("aeiou")

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    e = 0.0
    for c in counts.values():
        p = c / n
        e -= p * math.log(p, 2)
    return e

def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(ch.isdigit() for ch in s) / len(s)

def _vowel_ratio(s: str) -> float:
    if not s:
        return 0.0
    s2 = s.lower()
    return sum(ch in _VOWELS for ch in s2) / len(s)

def _safe_lower(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _labels(host: str) -> list[str]:
    """Return split labels, excluding empties and trailing dots."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return []
    return [p for p in host.split(".") if p]


# ---------- Core extraction helpers ----------

def _extract_sld_from_registered_domain(registered_domain: str) -> str:
    """
    We assume `registered_domain` is already PSL-normalized upstream, e.g. 'example.co.uk'.
    SLD is the leftmost label of registered_domain: 'example'.
    """
    rd = _safe_lower(registered_domain)
    parts = _labels(rd)
    if len(parts) >= 2:
        return parts[0]
    elif parts:
        return parts[0]
    return ""

def _subdomain_depth_vs_regdom(host: str, registered_domain: str) -> int:
    """
    Count labels in host that appear BEFORE the registered_domain suffix.
    'a.b.example.com' vs 'example.com' => depth 2 ('a','b').
    """
    h = _safe_lower(host)
    rd = _safe_lower(registered_domain)
    if not h or not rd:
        return 0

    if not h.endswith(rd):
        # If the host doesn't end with the registered domain, treat entire host as subdomain part.
        return max(0, len(_labels(h)) - 2)  # rough: assume regdom ~ 2 labels

    # Strip the regdom from the end
    if h == rd:
        return 0
    # Remove the regdom suffix and trailing dot if present
    prefix = h[: -len(rd)].rstrip(".")
    return len([p for p in prefix.split(".") if p])

def _max_label_len_outside_regdom(host: str, registered_domain: str) -> int:
    """
    Long random-looking labels are suspicious. Measure the longest label BEFORE regdom.
    """
    h = _safe_lower(host)
    rd = _safe_lower(registered_domain)
    if not h:
        return 0

    if h.endswith(rd):
        # isolate the subdomain prefix
        if h == rd:
            return 0
        prefix = h[: -len(rd)].rstrip(".")
        cand = [p for p in prefix.split(".") if p]
    else:
        cand = _labels(h)

    return max((len(p) for p in cand), default=0)


def _dga_points_heuristic(
    sld_entropy: float,
    sld_len: int,
    digit_ratio: float,
    vowel_ratio: float,
    sub_depth: int,
    max_label_len: int,
) -> Tuple[int, bool]:
    """
    Turn features into a compact 0–10 risk score usable by the YAML config.
    Also return a boolean is_dga_suspect for quick filters.
    """
    points = 0

    # Entropy: strong signal
    if sld_entropy > 4.0:
        points += 5
    elif sld_entropy > 3.5:
        points += 3

    # Length: very long SLDs look synthetic
    if sld_len > 20:
        points += 3
    elif sld_len > 15:
        points += 2

    # Digits & vowels: abnormal ratios
    if digit_ratio > 0.30:
        points += 2
    if vowel_ratio < 0.20 and sld_len > 6:
        points += 1

    # Subdomain depth: deep trees are common in abuse infra
    if sub_depth >= 5:
        points += 4
    elif sub_depth >= 3:
        points += 2

    # Really long single label in subdomain
    if max_label_len >= 25:
        points += 2
    elif max_label_len >= 18:
        points += 1

    points = max(0, min(10, points))
    is_sus = points >= 6
    return points, is_sus


# ---------- Public API ----------

def add_dga_features_arrow(table: pa.Table) -> pa.Table:
    """
    Add DGA/subdomain features to an Arrow table (vectorized via Polars).
    Expects (best effort):
      - registered_domain (string)  ← already normalized upstream
      - domain (string)             ← fallback if registered_domain missing
      - www, www_cname, cname, mx_host_norm, mail_mx  (optional hosts)

    Adds columns:
      - dga_features_version : str
      - dga_sld              : str
      - dga_sld_length       : int
      - dga_sld_entropy      : float
      - dga_sld_digit_ratio  : float
      - dga_sld_vowel_ratio  : float
      - subdomain_depth      : int     (max across known hosts vs regdom)
      - subdomain_max_label  : int     (max label length in subdomain area)
      - subdomain_points     : int [0..10]
      - is_dga_suspect       : bool
    """
    # Ensure a DataFrame (pl.from_arrow may return a Series for non-Table inputs)
    df = pl.DataFrame(pl.from_arrow(table))

    # Ensure required base columns
    has_regdom = "registered_domain" in df.columns
    if not has_regdom:
        if "domain" in df.columns:
            df = df.with_columns(pl.col("domain").str.to_lowercase().alias("registered_domain"))
        else:
            df = df.with_columns(pl.lit("").alias("registered_domain"))

    # Extract SLD from registered_domain
    def _get_sld(rd: str) -> str:
        return _extract_sld_from_registered_domain(rd or "")

    df = df.with_columns(
        pl.col("registered_domain").map_elements(_get_sld, return_dtype=pl.Utf8).alias("dga_sld")
    )

    # SLD feature columns
    df = df.with_columns([
        pl.col("dga_sld").str.len_chars().alias("dga_sld_length"),
        pl.col("dga_sld").map_elements(_entropy, return_dtype=pl.Float64).alias("dga_sld_entropy"),
        pl.col("dga_sld").map_elements(_digit_ratio, return_dtype=pl.Float64).alias("dga_sld_digit_ratio"),
        pl.col("dga_sld").map_elements(_vowel_ratio, return_dtype=pl.Float64).alias("dga_sld_vowel_ratio"),
    ])

    # Candidate hosts to inspect for subdomain structure
    candidates = []
    for c in ("www", "www_cname", "cname", "mx_host_norm", "mail_mx"):
        if c in df.columns:
            candidates.append(c)
    if not candidates:
        # No subdomain-bearing columns; create empty placeholders
        df = df.with_columns([
            pl.lit(0).alias("subdomain_depth"),
            pl.lit(0).alias("subdomain_max_label"),
        ])
    else:
        # Compute per-candidate depth and max label, then take row-wise max.
        def make_depth_expr(colname: str) -> pl.Expr:
            return pl.struct(["registered_domain", colname]).map_elements(
                lambda s: _subdomain_depth_vs_regdom(s[""+ "registered_domain"], s[colname]),
                return_dtype=pl.Int64
            ).alias(f"__depth_{colname}")

        def make_maxlab_expr(colname: str) -> pl.Expr:
            return pl.struct(["registered_domain", colname]).map_elements(
                lambda s: _max_label_len_outside_regdom(s[colname], s[""+ "registered_domain"]),
                return_dtype=pl.Int64
            ).alias(f"__maxlab_{colname}")

        depth_cols = [make_depth_expr(c) for c in candidates]
        maxlab_cols = [make_maxlab_expr(c) for c in candidates]
        df = df.with_columns(depth_cols + maxlab_cols)

        depth_colnames = [f"__depth_{c}" for c in candidates]
        maxlab_colnames = [f"__maxlab_{c}" for c in candidates]

        df = df.with_columns([
            pl.max_horizontal([pl.col(x) for x in depth_colnames]).alias("subdomain_depth"),
            pl.max_horizontal([pl.col(x) for x in maxlab_colnames]).alias("subdomain_max_label"),
        ]).drop(depth_colnames + maxlab_colnames)

    # Final heuristic points + suspect flag
    def _points_row(sld_e, sld_len, dig, vow, depth, maxlab):
        pts, sus = _dga_points_heuristic(
            float(sld_e or 0.0),
            int(sld_len or 0),
            float(dig or 0.0),
            float(vow or 0.0),
            int(depth or 0),
            int(maxlab or 0),
        )
        return {"points": int(pts), "sus": bool(sus)}

    df = df.with_columns(
        pl.struct([
            "dga_sld_entropy", "dga_sld_length", "dga_sld_digit_ratio", "dga_sld_vowel_ratio",
            "subdomain_depth", "subdomain_max_label"
        ]).map_elements(
            lambda s: _points_row(
                s["dga_sld_entropy"], s["dga_sld_length"],
                s["dga_sld_digit_ratio"], s["dga_sld_vowel_ratio"],
                s["subdomain_depth"], s["subdomain_max_label"]
            ),
            return_dtype=pl.Struct({"points": pl.Int64, "sus": pl.Boolean})
        ).alias("__dga")
    )

    df = df.with_columns([
        pl.col("__dga").struct.field("points").alias("subdomain_points"),
        pl.col("__dga").struct.field("sus").alias("is_dga_suspect"),
        pl.lit(DGA_FEATURES_VERSION).alias("dga_features_version"),
    ]).drop(["__dga"])

    return df.to_arrow()
