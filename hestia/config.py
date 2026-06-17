"""
Configuration for Hestia Shield v1.1.0
"""

import os
from typing import Dict, Any


def load_config() -> Dict[str, Any]:
    return {
        "database_url": os.getenv("HESTIA_DATABASE_URL", ""),
        "redis_url": os.getenv("HESTIA_REDIS_URL", ""),
        "jwt_secret": os.getenv("HESTIA_JWT_SECRET", "hst_dev_secret"),
        "data_dir": os.getenv("HESTIA_DATA_DIR", "./data"),
        "store_raw_inputs": os.getenv("HESTIA_STORE_RAW_INPUTS", "false").lower() == "true",
        "rate_limit_window": int(os.getenv("HESTIA_RATE_LIMIT_WINDOW", "60")),
        "rate_limit_max": int(os.getenv("HESTIA_RATE_LIMIT_MAX", "100")),
        "log_level": os.getenv("HESTIA_LOG_LEVEL", "INFO"),
    }