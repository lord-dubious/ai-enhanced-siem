"""Tests for the alert cache."""

import pytest


class TestAlertCache:
    """Tests for AlertCache class."""

    def test_create_cache(self, mock_config):
        """Test creating a cache."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        assert cache is not None
        assert cache.mock_mode is True

    def test_create_cache_default(self):
        """Test creating cache with defaults."""
        from ai_siem.cache import create_cache

        cache = create_cache()
        assert cache is not None
        assert cache.mock_mode is True

    def test_is_duplicate_new_alert(self, mock_config):
        """Test checking new alert is not duplicate."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        result = cache.is_duplicate("new-hash-123")
        assert result is False

    def test_is_duplicate_seen_alert(self, mock_config):
        """Test checking seen alert is duplicate."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        cache.mark_seen("seen-hash-456")
        result = cache.is_duplicate("seen-hash-456")
        assert result is True

    def test_mark_seen(self, mock_config):
        """Test marking alert as seen."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        cache.mark_seen("test-hash")
        assert cache.is_duplicate("test-hash") is True

    def test_increment_count(self, mock_config):
        """Test incrementing alert count."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        count1 = cache.increment_count("hash-1")
        count2 = cache.increment_count("hash-1")

        assert count1 == 1
        assert count2 == 2

    def test_store_enriched(self, mock_config):
        """Test storing enriched alert."""
        from ai_siem.cache import create_cache
        from ai_siem.models import EnrichedAlert

        cache = create_cache(mock_config)
        alert = EnrichedAlert(alert_id="alert-123", original_description="Test")

        result = cache.store_enriched(alert)
        assert result is True

    def test_get_enriched(self, mock_config):
        """Test retrieving enriched alert."""
        from ai_siem.cache import create_cache
        from ai_siem.models import EnrichedAlert

        cache = create_cache(mock_config)
        original = EnrichedAlert(
            alert_id="alert-456",
            original_description="Test alert",
            risk_score=75.0,
        )
        cache.store_enriched(original)

        retrieved = cache.get_enriched("alert-456")
        assert retrieved is not None
        assert retrieved.alert_id == "alert-456"
        assert retrieved.risk_score == 75.0

    def test_get_enriched_not_found(self, mock_config):
        """Test retrieving non-existent alert."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        result = cache.get_enriched("non-existent")
        assert result is None

    def test_get_recent_alerts(self, mock_config):
        """Test getting recent alerts."""
        from ai_siem.cache import create_cache
        from ai_siem.models import EnrichedAlert, AlertSeverity

        cache = create_cache(mock_config)

        # Store some alerts
        for i in range(5):
            alert = EnrichedAlert(
                alert_id=f"alert-{i}",
                severity=AlertSeverity.HIGH if i % 2 == 0 else AlertSeverity.LOW,
            )
            cache.store_enriched(alert)

        alerts = cache.get_recent_alerts(limit=10)
        assert len(alerts) == 5

    def test_get_recent_alerts_with_severity_filter(self, mock_config):
        """Test filtering recent alerts by severity."""
        from ai_siem.cache import create_cache
        from ai_siem.models import EnrichedAlert, AlertSeverity

        cache = create_cache(mock_config)

        # Store mixed severity alerts
        for i in range(4):
            alert = EnrichedAlert(
                alert_id=f"alert-{i}",
                severity=AlertSeverity.HIGH if i % 2 == 0 else AlertSeverity.LOW,
            )
            cache.store_enriched(alert)

        high_alerts = cache.get_recent_alerts(limit=10, severity="high")
        assert all(a.severity == AlertSeverity.HIGH for a in high_alerts)

    def test_get_stats(self, mock_config):
        """Test getting cache stats."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        cache.mark_seen("hash-1")
        cache.mark_seen("hash-2")

        stats = cache.get_stats()
        assert "total_keys" in stats
        assert stats["connected"] is True

    def test_clear(self, mock_config):
        """Test clearing cache."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        cache.mark_seen("hash-1")
        cache.mark_seen("hash-2")

        result = cache.clear()
        assert result is True

        # Verify cleared
        assert cache.is_duplicate("hash-1") is False

    def test_close(self, mock_config):
        """Test closing cache connection."""
        from ai_siem.cache import create_cache

        cache = create_cache(mock_config)
        cache.close()
        # Should not raise
