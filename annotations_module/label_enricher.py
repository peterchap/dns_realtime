from __future__ import annotations
from typing import Optional
import duckdb
import pyarrow as pa

"""
LabelEnricher (DuckDB-backed)
- Accepts a PyArrow table (already has dns + normalized helper columns)
- Registers it as a temp view `t`
- Runs a single SQL to LEFT JOIN lookups and compute nudges/flags
- Returns enriched PyArrow table
"""

# Expected lookup tables in DuckDB (read-only):
#   provider_catalog (
#       key_type TEXT,            -- e.g. 'ns_brand' | 'mx_host' | 'mx_regdom' | 'cdn_root' | 'dyndns_root' | ...
#       key TEXT,                 -- normalized key to match (lowercase)
#       provider_key TEXT,        -- stable id e.g. 'google', 'microsoft', 'cloudflare'
#       provider_name TEXT,
#       category TEXT,            -- e.g. 'Mailbox Provider','Security','Hosting','Registrar','DynamicDNS','CDN/UGC',...
#       country TEXT,
#       risk_bias DOUBLE,         -- + = more risk, - = more trust
#       trust_points DOUBLE,      -- optional legacy; we derive nudge from risk_bias
#       notes TEXT
#   )
#
#   mx_provider_domains (
#       mx_domain TEXT,           -- registered domain (lowercase)
#       provider_key TEXT,
#       provider_name TEXT,
#       category TEXT,
#       country TEXT,
#       risk_bias DOUBLE
#   )
#
#   mx_providers_hosts (
#       mx_host_pattern TEXT,     -- wildcard/regex-ish pattern (but we store normalized host roots)
#       provider_key TEXT,
#       provider_name TEXT,
#       category TEXT,
#       country TEXT,
#       risk_bias DOUBLE
#   )
#
#   asn_ip4 (optional):
#       start_int BIGINT, end_int BIGINT, asn INT, isp_country TEXT, isp TEXT, asn_risk_level TEXT
#
#   parked_indicators (optional):
#       indicator_type TEXT, pattern TEXT  -- used upstream; included here for completeness


class LabelEnricher:
    def __init__(self, db_path: str):
        # open read-only; DuckDB allows PRAGMA disable_object_cache to avoid lock contention in many readers
        self.db_path = db_path

    def enrich(self, table: pa.Table) -> pa.Table:
        # Defensive: ensure helper columns exist (created earlier in BatchProcessor)
        required = {"domain", "registered_domain", "mx_host_norm", "mx_regdom_norm", "ns", "ip_int"}
        missing = required - set(table.column_names)
        # If only ip_int is missing, create a nullable int64 ip_int column so downstream SQL can run;
        # otherwise raise as before.
        if missing:
            if missing == {"ip_int"}:
                nrows = table.num_rows
                ip_col = pa.nulls(nrows, type=pa.int64())
                table = table.append_column("ip_int", ip_col)
            else:
                raise ValueError(f"LabelEnricher: missing columns {sorted(missing)}")

        con = duckdb.connect(self.db_path, read_only=True)
        try:
            con.execute("PRAGMA disable_object_cache;")
            con.register("t", table)

            # Build SQL dynamically: prefer exact NS matches via ns_list_norm when available.
            has_ns_list = "ns_list_norm" in table.column_names

            if has_ns_list:
                sql = """
                    WITH base AS (
                        SELECT
                            t.*,
                            lower(coalesce(t.mx_host_norm, ''))  AS _mx_host,
                            lower(coalesce(t.mx_regdom_norm, '')) AS _mx_regdom,
                            lower(coalesce(t.ns, ''))             AS _ns,
                            t.ns_list_norm                        AS _ns_list
                        FROM t
                    ),
                    
                    mx_reg AS (
                        SELECT
                            b.*,
                            vr.key   AS mx_provider_key_reg,
                            vr.provider_name  AS mx_provider_name_reg,
                            vr.category       AS mx_provider_category_reg,
                            vr.risk_bias      AS mx_provider_risk_reg
                        FROM base b
                        LEFT JOIN v_mx_catalog vr
                        ON b._mx_regdom = vr.key AND vr.src = 'regdom'
                    ),
                    
                    mx_host AS (
                        SELECT
                            r.*,
                            vh.key   AS mx_provider_key_host,
                            vh.provider_name  AS mx_provider_name_host,
                            vh.category       AS mx_provider_category_host,
                            vh.risk_bias      AS mx_provider_risk_host
                        FROM mx_reg r
                        LEFT JOIN v_mx_catalog vh
                        ON r._mx_host = vh.key AND vh.src = 'host'
                    ),
                    
                    mx_final AS (
                        SELECT
                            m.*,
                            COALESCE(mx_provider_key_host,  mx_provider_key_reg)   AS mx_provider_key,
                            COALESCE(mx_provider_name_host, mx_provider_name_reg)  AS mx_provider_name,
                            COALESCE(mx_provider_category_host, mx_provider_category_reg) AS mx_mbp_category,
                            COALESCE(CAST(mx_provider_risk_host AS DOUBLE), CAST(mx_provider_risk_reg AS DOUBLE), 0.0)   AS mx_risk_bias
                        FROM mx_host m
                    ),

                    ns_explode AS (
                        SELECT domain, UNNEST(_ns_list) AS ns_item FROM mx_final
                    ),

                    ns_brand_exact AS (
                        SELECT
                            e.domain,
                            pc.key      AS ns_provider_key,
                            pc.provider AS ns_provider_name,
                            pc.notes    AS ns_provider_category,
                            COALESCE(CAST(pc.risk_bias AS DOUBLE), 0.0) AS ns_risk_bias
                        FROM ns_explode e
                        LEFT JOIN provider_catalog pc
                        ON pc.key_type = 'ns_brand'
                        AND lower(pc.key) = lower(CAST(e.ns_item AS VARCHAR))
                    ),

                    ns_brand_reduced AS (
                        SELECT
                            domain,
                            MAX(ns_provider_key)       AS ns_provider_key,
                            MAX(ns_provider_name)      AS ns_provider_name,
                            MAX(ns_provider_category)  AS ns_provider_category,
                            CASE
                                WHEN ABS(MAX(COALESCE(CAST(ns_risk_bias AS DOUBLE), 0.0))) >= ABS(MIN(COALESCE(CAST(ns_risk_bias AS DOUBLE), 0.0)))
                                    THEN MAX(COALESCE(CAST(ns_risk_bias AS DOUBLE), 0.0))
                                ELSE MIN(COALESCE(CAST(ns_risk_bias AS DOUBLE), 0.0))
                            END AS ns_risk_bias
                        FROM ns_brand_exact
                        GROUP BY domain
                    ),

                    ns_brand_joined AS (
                        SELECT
                            m.*,
                            r.ns_provider_key,
                            r.ns_provider_name,
                            r.ns_provider_category,
                            r.ns_risk_bias
                        FROM mx_final m
                        LEFT JOIN ns_brand_reduced r
                        ON m.domain = r.domain
                    ),

                    asn_join AS (
                        SELECT
                            n.*,
                            a.asn,
                            a.isp AS isp_name,
                            a.isp_country,
                            a.risk_bias AS asn_risk_level
                        FROM ns_brand_joined n
                        LEFT JOIN asn_ip4 a
                        ON n.ip_int BETWEEN a.start_int AND a.end_int
                    )
                    
                    SELECT
                        domain,
                        ip_int,
                        mx_host_norm,
                        mx_regdom_norm,
                        ns,
                        mx_provider_key,
                        mx_provider_name,
                        mx_mbp_category,
                        mx_risk_bias,
                        ns_provider_key,
                        ns_provider_name,
                        ns_provider_category,
                        ns_risk_bias,
                        asn,
                        isp_name,
                        isp_country,
                        asn_risk_level,
                        CAST(-mx_risk_bias AS DOUBLE) AS mx_trust_nudge,
                        CAST(-COALESCE(ns_risk_bias,0) AS DOUBLE) AS provider_trust_nudge,
                        CASE WHEN mx_mbp_category IN ('DynamicDNS','CDN/UGC','Platform','Redirect') THEN TRUE ELSE FALSE END AS is_cdn_ugc
                    FROM asn_join
                """
            else:
                # Fallback to substring-based NS brand detection when list column not available
                sql = """
                    WITH base AS (
                        SELECT
                            t.*,
                            lower(coalesce(t.mx_host_norm, ''))  AS _mx_host,
                            lower(coalesce(t.mx_regdom_norm, '')) AS _mx_regdom,
                            lower(coalesce(t.ns, ''))             AS _ns
                        FROM t
                    ),
                    
                    mx_reg AS (
                        SELECT
                            b.*,
                            vr.key   AS mx_provider_key_reg,
                            vr.provider_name  AS mx_provider_name_reg,
                            vr.category       AS mx_provider_category_reg,
                            vr.risk_bias      AS mx_provider_risk_reg
                        FROM base b
                        LEFT JOIN v_mx_catalog vr
                        ON b._mx_regdom = vr.key AND vr.src = 'regdom'
                    ),
                    
                    mx_host AS (
                        SELECT
                            r.*,
                            vh.key   AS mx_provider_key_host,
                            vh.provider_name  AS mx_provider_name_host,
                            vh.category       AS mx_provider_category_host,
                            vh.risk_bias      AS mx_provider_risk_host
                        FROM mx_reg r
                        LEFT JOIN v_mx_catalog vh
                        ON r._mx_host = vh.key AND vh.src = 'host'
                    ),
                    
                    mx_final AS (
                        SELECT
                            m.*,
                            COALESCE(mx_provider_key_host,  mx_provider_key_reg)   AS mx_provider_key,
                            COALESCE(mx_provider_name_host, mx_provider_name_reg)  AS mx_provider_name,
                            COALESCE(mx_provider_category_host, mx_provider_category_reg) AS mx_mbp_category,
                            COALESCE(CAST(mx_provider_risk_host AS DOUBLE), CAST(mx_provider_risk_reg AS DOUBLE), 0.0)   AS mx_risk_bias
                        FROM mx_host m
                    ),

                    ns_brand AS (
                        SELECT
                            f.*,
                            pc.key    AS ns_provider_key,
                            pc.provider   AS ns_provider_name,
                            pc.notes        AS ns_provider_category,
                            COALESCE(CAST(pc.risk_bias AS DOUBLE), 0.0) AS ns_risk_bias,
                            CASE 
                                WHEN pc.key IS NOT NULL AND pc.key <> '' AND INSTR(f._ns, pc.key) > 0 THEN TRUE 
                                else FALSE 
                            END AS ns_brand_hit
                        FROM mx_final f
                        LEFT JOIN provider_catalog pc
                        ON pc.key_type = 'ns_brand'
                        AND pc.key <> ''
                        AND INSTR(f._ns, pc.key) > 0
                    ),

                    ns_brand_reduced AS (
                        SELECT
                            domain,
                            MAX(CASE WHEN ns_brand_hit THEN ns_provider_key ELSE NULL END) AS ns_provider_key,
                            MAX(CASE WHEN ns_brand_hit THEN ns_provider_name ELSE NULL END) AS ns_provider_name,
                            MAX(CASE WHEN ns_brand_hit THEN ns_provider_category ELSE NULL END) AS ns_provider_category,
                            CASE
                                WHEN ABS(MAX(COALESCE(CAST(ns_risk_bias AS DOUBLE), 0.0))) >= ABS(MIN(COALESCE(CAST(ns_risk_bias AS DOUBLE), 0.0)))
                                    THEN MAX(COALESCE(CAST(ns_risk_bias AS DOUBLE), 0.0))
                                ELSE MIN(COALESCE(CAST(ns_risk_bias AS DOUBLE), 0.0))
                            END AS ns_risk_bias
                        FROM ns_brand
                        GROUP BY domain
                    ),

                    ns_brand_joined AS (
                        SELECT
                            m.*,
                            r.ns_provider_key,
                            r.ns_provider_name,
                            r.ns_provider_category,
                            r.ns_risk_bias
                        FROM mx_final m
                        LEFT JOIN ns_brand_reduced r
                        ON m.domain = r.domain
                    ),

                    asn_join AS (
                        SELECT
                            n.*,
                            a.asn,
                            a.isp AS isp_name,
                            a.isp_country,
                            a.risk_bias AS asn_risk_level
                        FROM ns_brand_joined n
                        LEFT JOIN asn_ip4 a
                        ON n.ip_int BETWEEN a.start_int AND a.end_int
                    )
                    
                    SELECT
                        domain,
                        ip_int,
                        mx_host_norm,
                        mx_regdom_norm,
                        ns,
                        mx_provider_key,
                        mx_provider_name,
                        mx_mbp_category,
                        mx_risk_bias,
                        ns_provider_key,
                        ns_provider_name,
                        ns_provider_category,
                        ns_risk_bias,
                        asn,
                        isp_name,
                        isp_country,
                        asn_risk_level,
                        CAST(-mx_risk_bias AS DOUBLE) AS mx_trust_nudge,
                        CAST(-COALESCE(ns_risk_bias,0) AS DOUBLE) AS provider_trust_nudge,
                        CASE WHEN mx_mbp_category IN ('DynamicDNS','CDN/UGC','Platform','Redirect') THEN TRUE ELSE FALSE END AS is_cdn_ugc
                    FROM asn_join
                """

            enriched = con.execute(sql).fetch_arrow_table()

            return enriched
        finally:
            con.close()
