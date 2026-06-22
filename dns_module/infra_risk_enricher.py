from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Dict, Any, cast

import polars as pl
import pyarrow as pa


@dataclass(frozen=True)
class InfraRiskPaths:
    # Produced by your RouteViews/MOAS jobs
    asn_moas_enriched_parquet: Path           # asn, moas_prefix_count, asn_total_prefix_count, asn_moas_ratio, built_at_utc
    asn_prefix_churn_parquet: Path            # asn, prefixes_added/removed/..., prefixes_churn_total, built_at_utc

    # Optional tables (plumbing you may already have, or will add next)
    asn_risk_parquet: Optional[Path] = None   # asn, asn_risk_level, in_drop, ... (optional)
    tld_risk_parquet: Optional[Path] = None   # tld, tld_risk_points (optional)

    # Optional DNSBL counters (if you have them)
    mx_ip_dnsbl_domains_parquet: Optional[Path] = None  # mx_ip_int, flagged_domains_30d, ... (optional)


class InfraRiskEnricher:
    """
    Enriches a harmonized Arrow table with routing/infra risk signals:
      - IP -> ASN (for A and MX)
      - Join ASN churn and MOAS ratio
      - Optional join to ASN risk (DROP / reputation)
      - Optional join to TLD risk
      - Optional join to MX IP DNSBL domain-density counters

    Output columns (core):
      - a_asn, mx_asn
      - asn (primary_asn = mx_asn if present else a_asn)
      - asn_moas_ratio
      - asn_churn_total
      - asn_risk_level (if asn_risk_parquet present)
      - in_drop (if asn_risk_parquet present)
      - tld_risk_points (if tld_risk_parquet present)
      - mx_ip_flagged_domains_30d (if mx dnsbl table present)
    """

    def __init__(
        self,
        paths: InfraRiskPaths,
        *,
        ipasn_latest_dat: Path,           # ipasn_latest.dat
        prefer_mx_as_primary: bool = True,
    ):
        self.paths = paths
        self.ipasn_latest_dat = Path(ipasn_latest_dat)
        self.prefer_mx_as_primary = prefer_mx_as_primary

        # Lazy-load lookup tables once
        self._moas = pl.read_parquet(paths.asn_moas_enriched_parquet)
        self._churn = pl.read_parquet(paths.asn_prefix_churn_parquet)

        self._asn_risk = pl.read_parquet(paths.asn_risk_parquet) if paths.asn_risk_parquet else None
        self._tld_risk = pl.read_parquet(paths.tld_risk_parquet) if paths.tld_risk_parquet else None
        self._mx_dnsbl = pl.read_parquet(paths.mx_ip_dnsbl_domains_parquet) if paths.mx_ip_dnsbl_domains_parquet else None

        # Normalize join keys to Int64 where possible
        self._moas = self._moas.with_columns(pl.col("asn").cast(pl.Int64, strict=False))
        self._churn = self._churn.with_columns(pl.col("asn").cast(pl.Int64, strict=False))

        if self._asn_risk is not None:
            self._asn_risk = self._asn_risk.with_columns(pl.col("asn").cast(pl.Int64, strict=False))
            # Expect columns: asn_risk_level (str) and in_drop (bool) but we’ll default if missing

        if self._tld_risk is not None:
            # Expect: tld (str), tld_risk_points (numeric)
            pass

        if self._mx_dnsbl is not None:
            # Expect: mx_ip_int (Int64), flagged_domains_30d (Int64) etc.
            pass

        # Load pyasn mapping
        import pyasn  # local import to keep module import light
        self._pyasn = pyasn.pyasn(str(self.ipasn_latest_dat))

    def enrich(self, table: pa.Table) -> pa.Table:
        df = cast(pl.DataFrame, pl.from_arrow(table))

        df = self._ensure_base_cols(df)

        # Parse mx_ip_int from mx_ips string (pipe delimited), if available
        df = self._add_mx_ip_int(df)

        # Map IPs to ASNs
        df = self._add_asns(df)

        # Choose primary ASN (this is what you’ll score on in YAML)
        df = self._add_primary_asn(df)

        # Join routing tables (MOAS + churn) on primary ASN
        df = self._join_routing(df)

        # Optional joins
        df = self._join_optional(df)

        return df.to_arrow()

    # -----------------------------
    # Internal steps
    # -----------------------------

    def _ensure_base_cols(self, df: pl.DataFrame) -> pl.DataFrame:
        # Your pipeline already sets these, but keep safe defaults
        if "ip_int" not in df.columns:
            df = df.with_columns(pl.lit(None).cast(pl.Int64).alias("ip_int"))

        if "mx_ips" not in df.columns:
            df = df.with_columns(pl.lit("").alias("mx_ips"))

        if "registered_domain" not in df.columns:
            df = df.with_columns(pl.lit("").alias("registered_domain"))

        # Derive tld (cheap, good enough for plumbing)
        if "tld" not in df.columns:
            df = df.with_columns(
                pl.when(pl.col("registered_domain").str.contains(r"\."))
                .then(pl.col("registered_domain").str.split(".").list.last())
                .otherwise(pl.lit(""))
                .alias("tld")
            )

        return df

    def _add_mx_ip_int(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        mx_ips is currently a joined string, often like "1.2.3.4|5.6.7.8".
        Extract first IP and convert to int.
        """
        if "mx_ip_int" in df.columns:
            return df

        # Extract first token before '|'
        first_ip = (
            pl.col("mx_ips")
            .fill_null("")
            .cast(pl.Utf8)
            .str.split("|")
            .list.first()
            .fill_null("")
            .alias("__mx_ip_first")
        )

        df = df.with_columns(first_ip)

        # Convert to int using map_elements (fast enough for batch sizes; can vectorize later)
        import ipaddress

        def ip_to_int_safe(s: str) -> Optional[int]:
            s = (s or "").strip()
            if not s:
                return None
            try:
                ip = ipaddress.ip_address(s)
                # Only IPv4 in your current ip_int pipeline; keep IPv6 as None for now
                if ip.version != 4:
                    return None
                return int(ip)
            except Exception:
                return None

        df = df.with_columns(
            pl.col("__mx_ip_first")
            .map_elements(ip_to_int_safe, return_dtype=pl.Int64)
            .alias("mx_ip_int")
        ).drop(["__mx_ip_first"])

        return df

    def _add_asns(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Add:
          - a_asn from ip_int (A record primary IP)
          - mx_asn from mx_ip_int (primary MX IP)
        """
        if "a_asn" not in df.columns:
            df = df.with_columns(pl.lit(None).cast(pl.Int64).alias("a_asn"))
        if "mx_asn" not in df.columns:
            df = df.with_columns(pl.lit(None).cast(pl.Int64).alias("mx_asn"))

        def ipint_to_asn(ip_int: Optional[int]) -> Optional[int]:
            if ip_int is None:
                return None
            try:
                asn, _prefix = self._pyasn.lookup(int(ip_int))
                return int(asn) if asn is not None else None
            except Exception:
                return None

        df = df.with_columns(
            pl.col("ip_int").map_elements(ipint_to_asn, return_dtype=pl.Int64).alias("a_asn"),
            pl.col("mx_ip_int").map_elements(ipint_to_asn, return_dtype=pl.Int64).alias("mx_asn"),
        )

        return df

    def _add_primary_asn(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        primary ASN = mx_asn if available, else a_asn (typical email-security bias).
        """
        if "asn" in df.columns:
            return df

        if self.prefer_mx_as_primary:
            df = df.with_columns(
                pl.when(pl.col("mx_asn").is_not_null())
                .then(pl.col("mx_asn"))
                .otherwise(pl.col("a_asn"))
                .alias("asn")
            )
        else:
            df = df.with_columns(
                pl.when(pl.col("a_asn").is_not_null())
                .then(pl.col("a_asn"))
                .otherwise(pl.col("mx_asn"))
                .alias("asn")
            )

        df = df.with_columns(pl.col("asn").cast(pl.Int64, strict=False))
        return df

    def _join_routing(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Join MOAS + churn on primary asn.
        Adds unified columns:
          - asn_moas_ratio (Float64)
          - asn_churn_total (Int64)
        """
        # MOAS enriched
        moas_cols = [c for c in ["asn", "asn_moas_ratio", "moas_prefix_count", "asn_total_prefix_count"] if c in self._moas.columns]
        moas = self._moas.select(moas_cols)

        df = df.join(moas, on="asn", how="left")

        if "asn_moas_ratio" not in df.columns:
            df = df.with_columns(pl.lit(0.0).alias("asn_moas_ratio"))
        else:
            df = df.with_columns(pl.col("asn_moas_ratio").fill_null(0.0).cast(pl.Float64))

        # Churn
        churn_src_col = "prefixes_churn_total" if "prefixes_churn_total" in self._churn.columns else None
        if churn_src_col:
            churn = self._churn.select(["asn", churn_src_col]).rename({churn_src_col: "asn_churn_total"})
            df = df.join(churn, on="asn", how="left")
            df = df.with_columns(pl.col("asn_churn_total").fill_null(0).cast(pl.Int64))
        else:
            df = df.with_columns(pl.lit(0).cast(pl.Int64).alias("asn_churn_total"))

        return df

    def _join_optional(self, df: pl.DataFrame) -> pl.DataFrame:
        # ASN risk (DROP, etc.)
        if self._asn_risk is not None:
            cols = [c for c in ["asn", "asn_risk_level", "in_drop"] if c in self._asn_risk.columns]
            asn_risk = self._asn_risk.select(cols)

            df = df.join(asn_risk, on="asn", how="left")

            if "asn_risk_level" not in df.columns:
                df = df.with_columns(pl.lit("").alias("asn_risk_level"))
            else:
                df = df.with_columns(pl.col("asn_risk_level").fill_null(""))

            if "in_drop" not in df.columns:
                df = df.with_columns(pl.lit(False).alias("in_drop"))
            else:
                df = df.with_columns(pl.col("in_drop").fill_null(False).cast(pl.Boolean))
        else:
            # keep schema stable for scorer
            if "asn_risk_level" not in df.columns:
                df = df.with_columns(pl.lit("").alias("asn_risk_level"))
            if "in_drop" not in df.columns:
                df = df.with_columns(pl.lit(False).alias("in_drop"))

        # TLD risk
        if self._tld_risk is not None:
            if "tld" in self._tld_risk.columns and "tld_risk_points" in self._tld_risk.columns:
                df = df.join(self._tld_risk.select(["tld", "tld_risk_points"]), on="tld", how="left")
                df = df.with_columns(pl.col("tld_risk_points").fill_null(0.0).cast(pl.Float64))
        else:
            if "tld_risk_points" not in df.columns:
                df = df.with_columns(pl.lit(0.0).alias("tld_risk_points"))

        # MX IP DNSBL domain-density counters (if you have them)
        if self._mx_dnsbl is not None:
            # Expect at least: mx_ip_int, flagged_domains_30d
            join_cols = []
            if "mx_ip_int" in self._mx_dnsbl.columns:
                join_cols.append("mx_ip_int")
            if join_cols and "flagged_domains_30d" in self._mx_dnsbl.columns:
                df = df.join(
                    self._mx_dnsbl.select(["mx_ip_int", "flagged_domains_30d"]),
                    on="mx_ip_int",
                    how="left",
                )
                df = df.with_columns(pl.col("flagged_domains_30d").fill_null(0).cast(pl.Int64))
        else:
            if "flagged_domains_30d" not in df.columns:
                df = df.with_columns(pl.lit(0).cast(pl.Int64).alias("flagged_domains_30d"))

        return df
