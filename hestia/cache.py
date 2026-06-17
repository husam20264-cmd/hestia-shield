"""
Redis Cache for Hestia Shield v1.0.0
"""

import json
import os
import logging
from typing import Optional, Any, Dict, Union

logger = logging.getLogger(__name__)


class NullCache:
    """ذاكرة تخزين مؤقت فارغة (عند عدم توفر Redis)"""

    async def get(self, key: str) -> Optional[Any]:
        return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        pass

    async def delete(self, key: str):
        pass

    async def flush(self):
        pass


class RedisCache:
    """ذاكرة تخزين مؤقت باستخدام Redis - اختياري"""

    def __init__(self):
        self.redis_url = os.getenv("HESTIA_REDIS_URL", "")
        self.client = None
        self.pool = None
        self.default_ttl = 300

        if not self.redis_url:
            logger.warning("No Redis URL provided. Using NullCache.")
            self._enabled = False
        else:
            logger.info(f"Redis configured at {self.redis_url}")
            self._enabled = True

    async def connect(self):
        if not self._enabled:
            return None

        try:
            import redis.asyncio as redis
            self.pool = redis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=20,
                decode_responses=True
            )
            self.client = redis.Redis(connection_pool=self.pool)
            await self.client.ping()
            logger.info(f"✅ Connected to Redis at {self.redis_url}")
            return self.client
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Using NullCache.")
            self._enabled = False
            self.client = None
            return None

    async def _ensure_connection(self) -> bool:
        if not self._enabled:
            return False
        if self.client is None:
            await self.connect()
        return self.client is not None

    async def get(self, key: str) -> Optional[Any]:
        if not await self._ensure_connection():
            return None

        try:
            data = await self.client.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.debug(f"Redis get failed: {e}")
        return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None):
        if not await self._ensure_connection():
            return

        try:
            ttl = ttl or self.default_ttl
            await self.client.setex(key, ttl, json.dumps(value))
        except Exception as e:
            logger.debug(f"Redis set failed: {e}")

    async def delete(self, key: str):
        if not await self._ensure_connection():
            return

        try:
            await self.client.delete(key)
        except Exception as e:
            logger.debug(f"Redis delete failed: {e}")

    async def flush(self):
        if not await self._ensure_connection():
            return

        try:
            await self.client.flushdb()
        except Exception as e:
            logger.debug(f"Redis flush failed: {e}")


def get_cache() -> Union[RedisCache, NullCache]:
    redis_url = os.getenv("HESTIA_REDIS_URL", "")
    if redis_url:
        return RedisCache()
    return NullCache()