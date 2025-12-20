"""Redis-based caching for alert deduplication and storage."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ai_siem.models import CacheEntry, EnrichedAlert, SIEMConfig


class AlertCache:
    """Redis-based cache for alert deduplication and storage."""

    def __init__(self, config: SIEMConfig) -> None:
        """Initialize the cache.

        Args:
            config: SIEM configuration
        """
        self.config = config
        self.mock_mode = config.enable_mock_mode
        self._client = None
        self._mock_store: dict[str, Any] = {}

    @property
    def client(self):
        """Get or create Redis client."""
        if self._client is None and not self.mock_mode:
            import redis

            self._client = redis.Redis(
                host=self.config.redis_host,
                port=self.config.redis_port,
                db=self.config.redis_db,
                password=self.config.redis_password or None,
                decode_responses=True,
            )
        return self._client

    def is_duplicate(self, alert_hash: str) -> bool:
        """Check if an alert is a duplicate.

        Args:
            alert_hash: Hash of the alert

        Returns:
            True if alert has been seen recently
        """
        key = f"siem:seen:{alert_hash}"

        if self.mock_mode:
            return key in self._mock_store

        try:
            return self.client.exists(key) > 0
        except Exception:
            return False

    def mark_seen(self, alert_hash: str) -> None:
        """Mark an alert as seen.

        Args:
            alert_hash: Hash of the alert
        """
        key = f"siem:seen:{alert_hash}"

        if self.mock_mode:
            self._mock_store[key] = {
                "first_seen": datetime.now().isoformat(),
                "count": 1,
            }
            return

        try:
            self.client.setex(key, self.config.alert_cache_ttl, datetime.now().isoformat())
        except Exception:
            pass

    def increment_count(self, alert_hash: str) -> int:
        """Increment the count for a seen alert.

        Args:
            alert_hash: Hash of the alert

        Returns:
            New count
        """
        key = f"siem:count:{alert_hash}"

        if self.mock_mode:
            count = self._mock_store.get(key, 0) + 1
            self._mock_store[key] = count
            return count

        try:
            return self.client.incr(key)
        except Exception:
            return 1

    def store_enriched(self, alert: EnrichedAlert) -> bool:
        """Store an enriched alert.

        Args:
            alert: Enriched alert to store

        Returns:
            True if stored successfully
        """
        key = f"siem:alert:{alert.alert_id}"
        data = alert.model_dump_json()

        if self.mock_mode:
            self._mock_store[key] = data
            return True

        try:
            self.client.setex(key, self.config.alert_cache_ttl * 24, data)
            # Also add to sorted set for time-based retrieval
            self.client.zadd(
                "siem:alerts:timeline",
                {alert.alert_id: alert.timestamp.timestamp()},
            )
            return True
        except Exception:
            return False

    def get_enriched(self, alert_id: str) -> EnrichedAlert | None:
        """Retrieve an enriched alert.

        Args:
            alert_id: Alert ID

        Returns:
            EnrichedAlert or None if not found
        """
        key = f"siem:alert:{alert_id}"

        if self.mock_mode:
            data = self._mock_store.get(key)
            if data:
                return EnrichedAlert.model_validate_json(data)
            return None

        try:
            data = self.client.get(key)
            if data:
                return EnrichedAlert.model_validate_json(data)
        except Exception:
            pass
        return None

    def get_recent_alerts(
        self, limit: int = 100, severity: str | None = None
    ) -> list[EnrichedAlert]:
        """Get recent enriched alerts.

        Args:
            limit: Maximum number of alerts to return
            severity: Optional severity filter

        Returns:
            List of recent enriched alerts
        """
        if self.mock_mode:
            alerts = []
            for key, data in self._mock_store.items():
                if key.startswith("siem:alert:"):
                    try:
                        alert = EnrichedAlert.model_validate_json(data)
                        if severity is None or alert.severity.value == severity:
                            alerts.append(alert)
                    except Exception:
                        pass
            return sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:limit]

        try:
            # Get recent alert IDs from timeline
            alert_ids = self.client.zrevrange("siem:alerts:timeline", 0, limit - 1)

            alerts = []
            for alert_id in alert_ids:
                alert = self.get_enriched(alert_id)
                if alert:
                    if severity is None or alert.severity.value == severity:
                        alerts.append(alert)

            return alerts
        except Exception:
            return []

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary of cache stats
        """
        if self.mock_mode:
            return {
                "total_keys": len(self._mock_store),
                "seen_alerts": sum(1 for k in self._mock_store if k.startswith("siem:seen:")),
                "stored_alerts": sum(1 for k in self._mock_store if k.startswith("siem:alert:")),
                "connected": True,
            }

        try:
            info = self.client.info()
            return {
                "total_keys": info.get("db0", {}).get("keys", 0),
                "memory_used": info.get("used_memory_human", "0B"),
                "connected_clients": info.get("connected_clients", 0),
                "connected": True,
            }
        except Exception:
            return {"connected": False}

    def clear(self) -> bool:
        """Clear all SIEM-related keys.

        Returns:
            True if cleared successfully
        """
        if self.mock_mode:
            self._mock_store.clear()
            return True

        try:
            # Use SCAN to find and delete SIEM keys
            cursor = 0
            while True:
                cursor, keys = self.client.scan(cursor, match="siem:*", count=100)
                if keys:
                    self.client.delete(*keys)
                if cursor == 0:
                    break
            return True
        except Exception:
            return False

    def close(self) -> None:
        """Close the Redis connection."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None


def create_cache(config: SIEMConfig | None = None) -> AlertCache:
    """Create an AlertCache instance.

    Args:
        config: Optional SIEM configuration

    Returns:
        AlertCache instance
    """
    if config is None:
        config = SIEMConfig(enable_mock_mode=True)
    return AlertCache(config)
