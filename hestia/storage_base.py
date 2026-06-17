"""
Storage Base Interface for Hestia Shield v1.1.0

Defines the abstract interface that all storage backends must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime


class StorageBackend(ABC):
    """
    Abstract base class for Hestia Shield storage backends.
    
    Implementations: SQLiteStorage, PostgresStorage
    """
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize database connection and create tables if needed."""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close database connections."""
        pass
    
    # Tenant Management
    @abstractmethod
    async def create_tenant(self, tenant_id: str, name: str, config: Optional[Dict] = None) -> Dict:
        """Create a new tenant."""
        pass
    
    @abstractmethod
    async def get_tenant(self, tenant_id: str) -> Optional[Dict]:
        """Get tenant by ID."""
        pass
    
    @abstractmethod
    async def list_tenants(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """List all tenants."""
        pass
    
    # API Keys
    @abstractmethod
    async def create_api_key(self, tenant_id: str, role: str) -> Dict:
        """Create API key for tenant."""
        pass
    
    @abstractmethod
    async def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """Validate API key and return key data."""
        pass
    
    @abstractmethod
    async def revoke_api_key(self, api_key: str) -> bool:
        """Revoke an API key."""
        pass
    
    # Security Events
    @abstractmethod
    async def store_event(self, event_data: Dict) -> str:
        """Store security event, returns event ID."""
        pass
    
    @abstractmethod
    async def get_events(
        self,
        tenant_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict]:
        """Query security events."""
        pass
    
    @abstractmethod
    async def count_events(self, tenant_id: str, hours: int = 24) -> int:
        """Count events for a tenant in last N hours."""
        pass
    
    # Audit Logs
    @abstractmethod
    async def store_audit_log(self, audit_data: Dict) -> str:
        """Store audit log entry."""
        pass
    
    @abstractmethod
    async def get_audit_logs(
        self,
        tenant_id: str,
        user_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Query audit logs."""
        pass
    
    # Webhooks
    @abstractmethod
    async def create_webhook(
        self,
        tenant_id: str,
        url: str,
        events: List[str],
        secret: Optional[str] = None
    ) -> Dict:
        """Create webhook subscription."""
        pass
    
    @abstractmethod
    async def get_webhooks_for_tenant(self, tenant_id: str) -> List[Dict]:
        """Get active webhooks for tenant."""
        pass
    
    @abstractmethod
    async def update_webhook(self, webhook_id: str, updates: Dict) -> bool:
        """Update webhook configuration."""
        pass
    
    @abstractmethod
    async def delete_webhook(self, webhook_id: str) -> bool:
        """Delete webhook subscription."""
        pass
    
    # Agent Profiles
    @abstractmethod
    async def create_agent_profile(self, agent_data: Dict) -> Dict:
        """Create agent profile."""
        pass
    
    @abstractmethod
    async def get_agent_profile(self, agent_id: str) -> Optional[Dict]:
        """Get agent profile by ID."""
        pass
    
    @abstractmethod
    async def update_agent_profile(self, agent_id: str, updates: Dict) -> bool:
        """Update agent profile."""
        pass
    
    # Alerts
    @abstractmethod
    async def create_alert(self, alert_data: Dict) -> str:
        """Create security alert."""
        pass
    
    @abstractmethod
    async def get_alerts(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """Query alerts."""
        pass
    
    @abstractmethod
    async def update_alert(self, alert_id: str, updates: Dict) -> bool:
        """Update alert status."""
        pass
    
    # Statistics
    @abstractmethod
    async def get_daily_stats(self, tenant_id: str, date: datetime) -> Dict:
        """Get daily statistics for tenant."""
        pass
    
    @abstractmethod
    async def update_daily_stats(self, tenant_id: str, date: datetime, stats: Dict) -> None:
        """Update daily statistics."""
        pass
    
    # Health Check
    @abstractmethod
    async def health_check(self) -> Dict:
        """Check database health and return status."""
        pass