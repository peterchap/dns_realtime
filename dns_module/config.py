# dns_module/config.py
from __future__ import annotations
import os, json
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root (celery_app_clean/.env) or fallback to CWD
try:
    _ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
    if _ENV_PATH.exists():
        load_dotenv(str(_ENV_PATH))
    else:
        load_dotenv()
except Exception:
    load_dotenv()

def _parse_nameservers(val: Optional[str]) -> List[str]:
    if not val:
        return ["127.0.0.1"]
    parts = [p.strip() for p in val.split(",")]
    return [p for p in parts if p]

def _parse_tld_limits(val: Optional[str]) -> Dict[str, int]:
    # Accept JSON ({"com":128,"rest":64}) or CSV "com:128; net:64; rest:64"
    if not val:
        return {}
    try:
        obj = json.loads(val)
        return {str(k).lower(): int(v) for k, v in obj.items()}
    except Exception:
        limits: Dict[str, int] = {}
        for seg in val.split(";"):
            seg = seg.strip()
            if not seg:
                continue
            if ":" in seg:
                k, v = seg.split(":", 1)
                limits[k.strip().lower()] = int(v.strip())
        return limits

@dataclass
class DNSConfig:
    nameservers: List[str] = field(default_factory=lambda: ["127.0.0.1"])
    timeout_s: float = 4.0
    lifetime_s: float = 12.0

    global_qps: int = 500
    semaphore_limit: int = 500
    workers_default: int = 64

    tld_rate_limits: Dict[str, int] = field(default_factory=lambda: {
        "com": 500,
        "net": 500,
        "xyz": 128,
        "highrisk": 128,
        "uk": 12,
        "de": 12,
    })

    enable_global_rate_limit: bool = True
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> DNSConfig:
        cfg = cls()
        cfg.nameservers = _parse_nameservers(os.getenv("DNS_NAMESERVERS"))
        cfg.timeout_s = float(os.getenv("DNS_TIMEOUT_S", os.getenv("DNS_TIMEOUT", "4.0")))
        cfg.lifetime_s = float(os.getenv("DNS_LIFETIME_S", os.getenv("DNS_LIFETIME", "12.0")))
        cfg.global_qps = int(os.getenv("DNS_QPS_LIMIT", os.getenv("GLOBAL_QPS_LIMIT", str(cfg.global_qps))))
        cfg.semaphore_limit = int(os.getenv("DNS_SEMAPHORE_LIMIT", os.getenv("DEFAULT_SEMAPHORE_LIMIT", str(cfg.semaphore_limit))))
        cfg.workers_default = int(os.getenv("DNS_WORKERS_DEFAULT", str(cfg.workers_default)))
        # Allow override via JSON/CSV; merge into defaults
        tld_env = _parse_tld_limits(os.getenv("DNS_TLD_RATE_LIMITS"))
        if tld_env:
            cfg.tld_rate_limits.update(tld_env)
        cfg.enable_global_rate_limit = os.getenv("DNS_ENABLE_GLOBAL_RATE_LIMIT", "true").lower() in ("1", "true", "yes", "on")
        cfg.log_level = os.getenv("DNS_LOG_LEVEL", cfg.log_level)
        return cfg

    def rate_for_tld(self, tld: str) -> int:
        tld = (tld or "").lower()
        return self.tld_rate_limits.get(tld, self.tld_rate_limits.get("rest", self.global_qps))

    def effective_qps_for_tld(self, tld: str, chunk_qps: Optional[int] = None) -> int:
        # Authoritative cap is min(TLD map, global), then optionally cap by chunk config
        base = min(self.rate_for_tld(tld), self.global_qps)
        return min(base, chunk_qps) if chunk_qps is not None else base

    def effective_concurrency_for_tld(self, tld: str, chunk_qps: Optional[int] = None) -> int:
        # Concurrency bound never exceeds semaphore_limit
        return min(self.semaphore_limit, self.effective_qps_for_tld(tld, chunk_qps))

    def log_config(self, logger) -> None:
        logger.info(f"DNS config: nameservers={self.nameservers}, timeout={self.timeout_s}s, lifetime={self.lifetime_s}s")
        logger.info(f"Limits: global_qps={self.global_qps}, semaphore_limit={self.semaphore_limit}, workers_default={self.workers_default}")
        logger.info(f"TLD limits: {self.tld_rate_limits}, rate_limit_enabled={self.enable_global_rate_limit}, log_level={self.log_level}")

# Singleton used across the app
CONFIG = DNSConfig.from_env()