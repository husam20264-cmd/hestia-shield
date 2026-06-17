"""
Authentication Manager for Hestia Shield v1.1.0
"""

import os
import jwt
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict

from .storage_base import StorageBackend

logger = logging.getLogger(__name__)


class AuthManager:
    def __init__(self, storage: StorageBackend):
        self.storage = storage
        self.jwt_secret = os.getenv(
            "HESTIA_JWT_SECRET",
            "hst_dev_secret_change_in_production"
        )
        self.token_expiry_hours = 24

    def create_token(self, tenant_id: str, role: str = "admin") -> str:
        payload = {
            "tenant_id": tenant_id,
            "role": role,
            "exp": datetime.now() + timedelta(hours=self.token_expiry_hours),
            "iat": datetime.now()
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        logger.info(f"Created token for tenant: {tenant_id}")
        return token

    async def validate_token(self, token: str) -> Optional[Dict]:
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return {
                "tenant_id": payload["tenant_id"],
                "role": payload["role"]
            }
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None

    async def validate_api_key(self, api_key: str) -> Optional[Dict]:
        return await self.storage.validate_api_key(api_key)

    async def exchange_api_key_for_token(self, api_key: str) -> Optional[str]:
        key_data = await self.validate_api_key(api_key)

        if not key_data:
            return None

        tenant_id = key_data["tenant_id"]
        role = key_data.get("role", "admin")

        return self.create_token(tenant_id, role)