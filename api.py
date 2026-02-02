from fastapi import FastAPI, HTTPException, Query
from typing import Optional
import os
import sys

# Add current directory to path
sys.path.insert(0, os.getcwd())

from main import process_domain, RiskScorer, LabelEnricher, configure_logging
from dns_module.logger import get_child_logger

app = FastAPI(title="Realtime DNS Risk Scorer")
log = get_child_logger("api")

# Global instances
scorer: Optional[RiskScorer] = None
enricher: Optional[LabelEnricher] = None

@app.on_event("startup")
async def startup_event():
    global scorer, enricher
    configure_logging()
    log.info("Starting up API...")
    
    # Init RiskScorer
    # In Cloud Run, secrets/config might be mounted or env vars
    # We'll expect the config file to be in the container
    config_path = os.getenv("SCORE_CONFIG_PATH", "risk_module/score_config.yaml")
    if os.path.exists(config_path):
        scorer = RiskScorer(config_path=config_path)
        log.info(f"Loaded RiskScorer from {config_path}")
    else:
        log.error(f"Score config not found at {config_path}")
        # Fail startup or fallback? Better to fail if critical.
        raise RuntimeError("Risk scorer config missing")

    # Init LabelEnricher (optional)
    db_path = os.getenv("DUCKDB_PATH")
    if db_path and os.path.exists(db_path):
        try:
            if LabelEnricher:
                enricher = LabelEnricher(db_path=db_path)
                log.info(f"Loaded LabelEnricher with DB: {db_path}")
            else:
                log.warning("LabelEnricher class not available (missing imports?)")
        except Exception as e:
            log.error(f"Failed to load LabelEnricher: {e}")
    else:
        log.info("No LabelEnricher DB configured (DUCKDB_PATH unset or missing)")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/lookup")
async def lookup_domain(domain: str, timeout: float = 5.0):
    if not scorer:
        raise HTTPException(status_code=503, detail="Risk scorer not initialized")
        
    result = await process_domain(
        domain=domain,
        risk_scorer=scorer,
        label_enricher=enricher,
        timeout=timeout
    )
    
    status = result.get("status")
    if status == "error":
        # We still return 200 usually as it's a valid application result, 
        # but you could change to 500 if preferred. 
        pass
        
    return result
