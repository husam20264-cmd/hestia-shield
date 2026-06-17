"""
Database Configuration for Hestia Shield v1.1.0

Factory that selects storage backend based on HESTIA_DATABASE_URL.
"""

import os
import logging
from typing import Union
from .storage_base import StorageBackend

logger = logging.getLogger(__name__)


def get_storage() -> StorageBackend:
    """
    Factory function that returns the appropriate storage backend.
    
    Selection logic:
    - HESTIA_DATABASE_URL starting with "postgresql" → PostgresStorage
    - Otherwise → SQLiteStorage (existing Storage class)
    """
    database_url = os.getenv("HESTIA_DATABASE_URL", "")

    if database_url.startswith("postgresql"):
        from .storage_postgres import PostgresStorage
        logger.info(f"Using PostgreSQL storage backend")
        return PostgresStorage(database_url)
    else:
        from .storage import Storage
        data_dir = os.getenv("HESTIA_DATA_DIR", "./data")
        store_raw = os.getenv("HESTIA_STORE_RAW_INPUTS", "false").lower() == "true"
        logger.info(f"Using SQLite storage backend (data_dir={data_dir})")
        return Storage(data_dir=data_dir, store_raw_inputs=store_raw)