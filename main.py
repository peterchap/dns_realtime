import asyncio
import sys
import os
import json
import argparse
import time
from dataclasses import asdict
from typing import Optional, Dict, Any, List

# Ensure the current directory is in sys.path so we can import modules
sys.path.insert(0, os.getcwd())

import pyarrow as pa
from dotenv import load_dotenv

# Import our modules
from dns_module.dns_fetcher import DNSFetcher, DNSRecords
from dns_module.logger import configure_logging, get_child_logger
from risk_module.dga_risk import add_dga_features_arrow
from risk_module.risk_scoring import RiskScorer

try:
    from annotations_module.label_enricher import LabelEnricher
except ImportError:
    LabelEnricher = None

load_dotenv()

# Configure logging
configure_logging()
log = get_child_logger("main")

def _record_to_arrow(rec: DNSRecords) -> pa.Table:
    """Convert a single DNSRecords object to a PyArrow Table (1 row)."""
    data = asdict(rec)
    # Convert datetime objects to strings or timestamps if needed
    # PyArrow handles datetime objects, but let's ensure compatibility
    # Explicitly wrapping in a list creates a table with 1 row
    # We might need to handle None values for some fields if pyarrow infers types strictly
    # But usually from_pylist handles it well.
    return pa.Table.from_pylist([data])

async def process_domain(
    domain: str,
    risk_scorer: RiskScorer,
    label_enricher: Optional[LabelEnricher] = None,
    timeout: float = 5.0
) -> Dict[str, Any]:
    """
    Full processing pipeline for a single domain:
    1. Fetch DNS records
    2. Add DGA/feature extraction
    3. Enrich with labels (if available)
    4. Score risk
    """
    log.info(f"Processing domain: {domain}")
    t0 = time.time()
    
    # 1. Fetch
    fetcher = DNSFetcher(domain, domain_timeout_s=timeout)
    # Note: run_blocking_probes=True if you want active probes (slower)
    fetcher._run_blocking_probes = False 
    
    records = await fetcher.fetch_records()
    if not records:
        log.warning(f"Failed to fetch records for {domain}")
        return {"domain": domain, "status": "failed", "error": "Fetch returned None"}
    
    t_fetch = time.time()
    
    # 2. Conversion & DGA
    try:
        table = _record_to_arrow(records)
        # Normalize columns expected by downstream
        # dga_risk expects 'registered_domain'
        table = add_dga_features_arrow(table)
    except Exception as e:
        log.error(f"Error in DGA/Feature extraction: {e}")
        return {"domain": domain, "status": "error", "message": f"DGA error: {e}"}
        
    t_dga = time.time()
    
    # 3. Enrichment
    if label_enricher:
        try:
            table = label_enricher.enrich(table)
        except Exception as e:
            log.warning(f"Enrichment failed (skipping): {e}")
            # Continue without enrichment? Or fail? 
            # RiskScorer might depend on enriched columns.
            # If RiskScorer handles missing columns gracefully, we proceed.
            # If not, we might need to add placeholders.
            pass
            
    t_enrich = time.time()
    
    # 4. Risk Scoring
    try:
        table = risk_scorer.score(table)
    except Exception as e:
        log.error(f"Risk scoring failed: {e}")
        # Return what we have so far
    
    t_score = time.time()
    
    # Convert result to dict
    result_list = table.to_pylist()
    result = result_list[0] if result_list else {}
    
    # Add timing info
    timings = {
        "fetch_ms": round((t_fetch - t0) * 1000, 2),
        "dga_ms": round((t_dga - t_fetch) * 1000, 2),
        "enrich_ms": round((t_enrich - t_dga) * 1000, 2),
        "score_ms": round((t_score - t_enrich) * 1000, 2),
        "total_ms": round((t_score - t0) * 1000, 2),
    }
    result["_meta"] = {"timings": timings}
    
    return result

async def main():
    parser = argparse.ArgumentParser(description="Real-time DNS Processor")
    parser.add_argument("domain", nargs="?", help="Domain to process")
    parser.add_argument("--db-path", help="Path to DuckDB for label enrichment", default=os.getenv("DUCKDB_PATH"))
    parser.add_argument("--score-config", help="Path to score_config.yaml", default="risk_module/score_config.yaml")
    parser.add_argument("--pretty", action="store_true", help="Pretty print JSON output")
    args = parser.parse_args()
    
    if not args.domain:
        print("Error: Domain argument is required.")
        sys.exit(1)

    # Init RiskScorer
    config_path = args.score_config
    if not os.path.exists(config_path):
        # Try relative to current script
        fallback = os.path.join(os.path.dirname(__file__), "risk_module", "score_config.yaml")
        if os.path.exists(fallback):
            config_path = fallback
        else:
            log.warning(f"Could not find score_config.yaml at {config_path}")
            
    scorer = RiskScorer(config_path=config_path)
    
    # Init Enricher
    enricher = None
    if LabelEnricher and args.db_path and os.path.exists(args.db_path):
        try:
            enricher = LabelEnricher(db_path=args.db_path)
            log.info(f"Loaded LabelEnricher with DB: {args.db_path}")
        except Exception as e:
            log.error(f"Failed to load LabelEnricher: {e}")
    
    result = await process_domain(args.domain, scorer, enricher)
    
    if args.pretty:
        print(json.dumps(result, indent=2, default=str))
    else:
        print(json.dumps(result, default=str))

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        log.critical(f"Unhandled exception: {e}")
        sys.exit(1)
