# risk_scoring.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, cast

import pyarrow as pa
import polars as pl
import yaml

class RiskScorer:
    """
    Config-driven risk scoring with explainability and versioning.

    Inputs:
      - Arrow table with labeled/harmonized columns (from LabelEnricher + LabelHarmonizer).
      - YAML config (score_config.yaml) containing profiles, thresholds, weights, version.

    Outputs (added columns):
      - risk_score (int, 0–100)
      - risk_level (critical, high, medium, low)
      - risk_reasons (list[str] or stringified JSON of triggering rules)
      - risk_breakdown (json details)
      - score_version (str)
    """

    def __init__(self, config_path: str = "config/score_config.yaml"):
        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)
        
        self.version = self.config.get("version", "v1.0")
        self.profiles = self.config.get("profiles", {})
        if "default" not in self.profiles:
            raise ValueError("Score config must have a 'default' profile.")

    def score(self, table: pa.Table, profile_name: str = "default") -> pa.Table:
        """
        Apply risk scoring rules using vectorized Polars expressions.
        """
        profile = self.profiles.get(profile_name) or self.profiles["default"]
        
        df = pl.DataFrame(pl.from_arrow(table))
        
        # 1. Start with a base score of 0
        df = df.with_columns(pl.lit(0).alias("__score"))
        
        # We will collect reason strings in a list column "__reasons"
        # Since Polars list building in expressions can be tricky if not all rows trigger,
        # we'll build a boolean mask per rule, then combine them at the end.
        
        rules = []
        rules.extend(profile.get("positive_rules", []))
        rules.extend(profile.get("trust_rules", [])) # trust rules might subtract points or add 0 but we want reasons
        
        rule_cols = []
        
        for idx, rule in enumerate(rules):
            rname = rule["name"]
            points = rule.get("points", 0)
            
            # Condition builder
            # Simple form: "column": "col_name" (implies implicit boolean check if no "equals")
            # Complex form: "when": { "column": ..., "equals": ..., "in": ... }
            
            predicate = None
            
            if "when" in rule:
                cond = rule["when"]
                c = cond["column"]
                if c not in df.columns:
                    # Missing column -> rule false
                    predicate = pl.lit(False)
                else:
                    if "equals" in cond:
                        predicate = pl.col(c) == cond["equals"]
                    elif "in" in cond:
                        predicate = pl.col(c).is_in(cond["in"])
                    elif "gt" in cond:
                        predicate = pl.col(c) > cond["gt"]
                    elif "lt" in cond:
                        predicate = pl.col(c) < cond["lt"]
                    # Add more ops as needed
            elif "column" in rule:
                c = rule["column"]
                if c not in df.columns:
                    predicate = pl.lit(False)
                else:
                    # Boolean check or truthy check
                    # If column is boolean, use it directly. If int/str, check != 0 or != null
                    predicate = pl.col(c).cast(pl.Boolean).fill_null(False)
            
            if predicate is None:
                continue
                
            # Create a mask column for this rule
            mask_col = f"__r_{idx}_{rname}"
            df = df.with_columns(predicate.alias(mask_col))
            rule_cols.append((rname, points, mask_col))
            
            # Apply points
            if points != 0:
                df = df.with_columns(
                    pl.when(pl.col(mask_col))
                    .then(pl.col("__score") + points)
                    .otherwise(pl.col("__score"))
                    .alias("__score")
                )

        # Mapped rules (e.g. asn_risk_level -> points)
        mapped_rules = profile.get("mapped_rules", [])
        for mrule in mapped_rules:
            rname = mrule["name"]
            c = mrule["column"]
            mapping = mrule["map"] # dict {val: points}
            
            if c in df.columns:
                # Build a mapping expression (e.g. replace)
                # Polars replace/map_dict? 
                # For safety/simplicity with possibly mixed types, use replace strict=False
                
                # construct case-when expression or use replace
                # replace: {k: v}
                
                # We need to compute the points added
                # cast column to string to match mapping keys usually?
                # or ensure mapping keys match column type
                
                # Let's assume string values in column
                pts_expr = pl.col(c).replace(mapping, default=0, return_dtype=pl.Int64)
                
                # We only want to add points if result is numeric and > 0 (or != 0)
                # But replace might leave original strings if default not set or...
                # Actually, replace(..., default=0) is good. 
                # Be careful if column is null.
                
                # We add the points
                df = df.with_columns(
                    (pl.col("__score") + pts_expr).alias("__score")
                )
                
                # For explainability, checking if points > 0
                mask_col = f"__m_{rname}"
                df = df.with_columns(
                    (pts_expr != 0).alias(mask_col)
                )
                # We need to store the points value for later breakdown?
                # For now just binary "did it trigger" or store format "network_risk(points)"
                
                # Let's execute the mapping again for reason string construction later?
                # Or store "points_added" column
                pts_col = f"__pts_{rname}"
                df = df.with_columns(pts_expr.alias(pts_col))
                rule_cols.append((rname, "dynamic", mask_col, pts_col))

        # Direct add/sub columns
        for c in profile.get("direct_add_columns", []):
            if c in df.columns:
                df = df.with_columns(
                    (pl.col("__score") + pl.col(c).fill_null(0)).alias("__score")
                )

        for c in profile.get("direct_sub_columns", []):
            if c in df.columns:
                df = df.with_columns(
                    (pl.col("__score") - pl.col(c).fill_null(0)).alias("__score")
                )

        # Clamping
        max_score = profile.get("max_score", 100)
        min_score = profile.get("min_score", 0)
        df = df.with_columns(
            pl.col("__score").clip(min_score, max_score)
        )

        # Thresholds -> risk_level
        thresholds = profile.get("thresholds", {})
        crit = thresholds.get("critical", 80)
        high = thresholds.get("high", 60)
        med = thresholds.get("medium", 30)
        
        df = df.with_columns(
            pl.when(pl.col("__score") >= crit).then(pl.lit("critical"))
            .when(pl.col("__score") >= high).then(pl.lit("high"))
            .when(pl.col("__score") >= med).then(pl.lit("medium"))
            .otherwise(pl.lit("low"))
            .alias("risk_level")
        )

        # Explainability: concat triggered rule names
        # Efficient approach: use concat_list with filtering
        # We have mask columns
        
        reason_exprs = []
        for rc in rule_cols:
            if len(rc) == 3:
                rname, points, mask_col = rc
                # format: "name(pts)"
                txt = f"{rname}({points})"
                # if mask true, return txt, else null
                reason_exprs.append(
                    pl.when(pl.col(mask_col)).then(pl.lit(txt)).otherwise(pl.lit(None))
                )
            elif len(rc) == 4:
                rname, _, mask_col, pts_col = rc
                # dynamic points
                # format: "name(pts_val)"
                # concat string
                txt_expr = pl.format("{}({})", pl.lit(rname), pl.col(pts_col))
                reason_exprs.append(
                    pl.when(pl.col(mask_col)).then(txt_expr).otherwise(pl.lit(None))
                )

        df = df.with_columns(
            pl.concat_list(reason_exprs).list.drop_nulls().alias("risk_reasons_list")
        )
        
        # Convert list to comma-joined string
        df = df.with_columns(
            pl.col("risk_reasons_list").list.join(", ").alias("risk_reasons")
        )

        # Add version
        df = df.with_columns(pl.lit(self.version).alias("score_version"))
        
        # Cleanup temp columns
        cols_to_drop = [c for c in df.columns if c.startswith("__")]
        # Keep risk_reasons_list? user wants list or json? Doc says list[str] or stringified json.
        # we provided string "name(pts), name(pts)".
        # let's drop the list obj to keep it simple arrow-compatible (strings)
        cols_to_drop.append("risk_reasons_list")
        
        df = df.drop(cols_to_drop)

        # Rename __score to risk_score
        # Wait, I did aliases logic inside. But __score is the final col name?
        # Check if I aliased it back to risk_score? No. 
        # Rename now.
        if "__score" in df.columns: # it is there
            df = df.rename({"__score": "risk_score"})
            
        return df.to_arrow()
