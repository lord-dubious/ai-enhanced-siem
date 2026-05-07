"""Redis-based caching for alert deduplication and storage."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, cast

from ai_siem.models import EnrichedAlert, SIEMConfig

logger = logging.getLogger(__name__)


class AlertCache:
    """Redis-based cache for alert deduplication and storage."""

    def __init__(self, config: SIEMConfig) -> None:
        """Initialize the cache.

        Args:
            config: SIEM configuration
        """
        self.config = config
        self.mock_mode = config.enable_mock_mode
        self._client: Any | None = None
        self._mock_store: dict[str, Any] = {}
        self.degraded = False
        self.last_error = ""
        self.last_failure_reason = "mock_mode" if self.mock_mode else ""

    def _record_failure(self, operation: str, error: Exception) -> None:
        """Record and log a cache failure without changing method return types."""
        self.degraded = True
        self.last_error = str(error)
        self.last_failure_reason = f"{operation}: {type(error).__name__}: {error}"
        logger.warning("Redis cache %s failed: %s", operation, error)

    def _record_success(self) -> None:
        """Clear degraded state after a successful Redis operation."""
        if not self.mock_mode:
            self.degraded = False
            self.last_error = ""
            self.last_failure_reason = ""

    def _mark_alert_cache_failure(self, alert: EnrichedAlert) -> None:
        alert.cache_status = "degraded"
        alert.cache_error = self.last_failure_reason
        alert.warnings.append(f"Cache degraded: {self.last_failure_reason}")

    @property
    def client(self) -> Any:
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
            client = self.client
            is_seen = cast(bool, client.exists(key) > 0)
            self._record_success()
            return is_seen
        except Exception as e:
            self._record_failure("duplicate check", e)
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
            client = self.client
            client.setex(key, self.config.alert_cache_ttl, datetime.now().isoformat())
            self._record_success()
        except Exception as e:
            self._record_failure("mark seen", e)

    def increment_count(self, alert_hash: str) -> int:
        """Increment the count for a seen alert.

        Args:
            alert_hash: Hash of the alert

        Returns:
            New count
        """
        key = f"siem:count:{alert_hash}"

        if self.mock_mode:
            count = int(self._mock_store.get(key, 0)) + 1
            self._mock_store[key] = count
            return count

        try:
            client = self.client
            count = cast(int, client.incr(key))
            self._record_success()
            return count
        except Exception as e:
            self._record_failure("increment count", e)
            return 1

    def store_enriched(self, alert: EnrichedAlert) -> bool:
        """Store an enriched alert.

        Args:
            alert: Enriched alert to store

        Returns:
            True if stored successfully
        """
        key = f"siem:alert:{alert.alert_id}"

        if self.mock_mode:
            alert.cache_status = "mock_stored"
            alert.cache_error = ""
            data = alert.model_dump_json()
            self._mock_store[key] = data
            return True

        try:
            alert.cache_status = "stored"
            alert.cache_error = ""
            data = alert.model_dump_json()
            client = self.client
            client.setex(key, self.config.alert_cache_ttl * 24, data)
            # Also add to sorted set for time-based retrieval
            client.zadd(
                "siem:alerts:timeline",
                {alert.alert_id: alert.timestamp.timestamp()},
            )
            self._record_success()
            return True
        except Exception as e:
            self._record_failure("store enriched alert", e)
            self._mark_alert_cache_failure(alert)
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
            client = self.client
            data = client.get(key)
            self._record_success()
            if data:
                return EnrichedAlert.model_validate_json(data)
        except Exception as e:
            self._record_failure("retrieve enriched alert", e)
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
                    except Exception as e:
                        logger.warning("Skipping malformed mock cache entry %s: %s", key, e)
            return sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:limit]

        try:
            # Get recent alert IDs from timeline
            client = self.client
            alert_ids = client.zrevrange("siem:alerts:timeline", 0, limit - 1)

            redis_alerts = []
            for alert_id in alert_ids:
                retrieved = self.get_enriched(alert_id)
                if retrieved:
                    if severity is None or retrieved.severity.value == severity:
                        redis_alerts.append(retrieved)

            self._record_success()
            return redis_alerts
        except Exception as e:
            self._record_failure("get recent alerts", e)
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
                "degraded": False,
                "mode": "mock",
                "last_error": self.last_error,
                "last_failure_reason": self.last_failure_reason,
            }

        try:
            client = self.client
            info = client.info()
            self._record_success()
            return {
                "total_keys": info.get("db0", {}).get("keys", 0),
                "memory_used": info.get("used_memory_human", "0B"),
                "connected_clients": info.get("connected_clients", 0),
                "connected": True,
                "degraded": False,
                "mode": "redis",
                "last_error": "",
                "last_failure_reason": "",
            }
        except Exception as e:
            self._record_failure("get stats", e)
            return {
                "connected": False,
                "degraded": True,
                "mode": "redis",
                "last_error": self.last_error,
                "last_failure_reason": self.last_failure_reason,
            }

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
            client = self.client
            while True:
                cursor, keys = client.scan(cursor, match="siem:*", count=100)
                if keys:
                    client.delete(*keys)
                if cursor == 0:
                    break
            self._record_success()
            return True
        except Exception as e:
            self._record_failure("clear", e)
            return False

    def close(self) -> None:
        """Close the Redis connection."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception as e:
                self._record_failure("close", e)
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
