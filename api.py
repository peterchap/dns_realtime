from fastapi import FastAPI, HTTPException, Query, Security, Depends, Request
from fastapi.security import APIKeyHeader
from starlette.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any
import os
import sys

# Rate Limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Add current directory to path
sys.path.insert(0, os.getcwd())

from main import process_domain, RiskScorer, LabelEnricher, configure_logging
from dns_module.logger import get_child_logger

# Setup Limiter (using X-Forwarded-For if available via ProxyHeaders)
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="Realtime DNS Risk Scorer")

# Add Rate Limit Exception Handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS (Allow browser access if needed)
origins = os.getenv("CORS_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

log = get_child_logger("api")

# Global instances
scorer: Optional[RiskScorer] = None
enricher: Optional[LabelEnricher] = None

# Security Scheme
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def check_api_key(api_key: str = Security(api_key_header)):
    """
    Validates API Key if 'API_KEY' env var is set.
    If 'API_KEY' is NOT set, allows open access (with warning logs).
    """
    expected_key = os.getenv("API_KEY")
    if expected_key:
        if api_key != expected_key:
            raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

@app.on_event("startup")
async def startup_event():
    global scorer, enricher
    configure_logging()
    log.info("Starting up API...")
    
    if not os.getenv("API_KEY"):
        log.warning("No API_KEY configured! API is accessible without authentication (Rate Limits apply).")

    # Init RiskScorer
    config_path = os.getenv("SCORE_CONFIG_PATH", "risk_module/score_config.yaml")
    if os.path.exists(config_path):
        scorer = RiskScorer(config_path=config_path)
        log.info(f"Loaded RiskScorer from {config_path}")
    else:
        log.error(f"Score config not found at {config_path}")
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
@limiter.exempt
def health_check():
    return {"status": "ok"}

@app.get("/lookup", dependencies=[Depends(check_api_key)])
@limiter.limit(lambda request: os.getenv("RATE_LIMIT", "60/minute"))
async def lookup_domain(request: Request, domain: str, timeout: float = 5.0):
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
        pass
        
    return result
