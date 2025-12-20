"""Tests for Pydantic and msgspec models."""

import pytest
from datetime import datetime


class TestSIEMConfig:
    """Tests for SIEMConfig model."""

    def test_default_config(self, monkeypatch):
        """Test default configuration values."""
        monkeypatch.delenv("ENABLE_MOCK_MODE", raising=False)
        from ai_siem.models import SIEMConfig

        config = SIEMConfig()
        assert config.gemini_model == "gemini-2.0-flash"
        assert config.redis_host == "localhost"
        assert config.redis_port == 6379
        assert config.batch_size == 100

    def test_config_with_overrides(self):
        """Test configuration with custom values."""
        from ai_siem.models import SIEMConfig

        config = SIEMConfig(
            gemini_api_key="test-key",
            redis_host="redis.example.com",
            batch_size=50,
        )
        assert config.gemini_api_key == "test-key"
        assert config.redis_host == "redis.example.com"
        assert config.batch_size == 50

    def test_create_config_factory(self):
        """Test create_config factory function."""
        from ai_siem.models import create_config

        config = create_config(enable_mock_mode=True)
        assert config.enable_mock_mode is True


class TestAlertSeverity:
    """Tests for AlertSeverity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        from ai_siem.models import AlertSeverity

        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.CRITICAL.value == "critical"


class TestMitreTactic:
    """Tests for MitreTactic enum."""

    def test_tactic_values(self):
        """Test MITRE tactic enum values."""
        from ai_siem.models import MitreTactic

        assert MitreTactic.INITIAL_ACCESS.value == "initial-access"
        assert MitreTactic.EXECUTION.value == "execution"
        assert MitreTactic.PERSISTENCE.value == "persistence"


class TestWazuhAlertStruct:
    """Tests for msgspec Wazuh alert structs."""

    def test_wazuh_alert_struct_creation(self):
        """Test creating a WazuhAlertStruct."""
        from ai_siem.models import WazuhAlertStruct

        alert = WazuhAlertStruct(
            timestamp="2024-01-15T10:30:00Z",
            id="test-123",
            location="/var/log/secure",
        )
        assert alert.timestamp == "2024-01-15T10:30:00Z"
        assert alert.id == "test-123"

    def test_wazuh_rule_struct(self):
        """Test WazuhRuleStruct defaults."""
        from ai_siem.models import WazuhRuleStruct

        rule = WazuhRuleStruct()
        assert rule.level == 0
        assert rule.description == ""
        assert rule.groups == []

    def test_wazuh_agent_struct(self):
        """Test WazuhAgentStruct."""
        from ai_siem.models import WazuhAgentStruct

        agent = WazuhAgentStruct(
            id="001",
            name="web-server",
            ip="192.168.1.100",
        )
        assert agent.name == "web-server"


class TestEnrichedAlert:
    """Tests for EnrichedAlert model."""

    def test_enriched_alert_creation(self):
        """Test creating an EnrichedAlert."""
        from ai_siem.models import EnrichedAlert, AlertSeverity

        alert = EnrichedAlert(
            alert_id="test-123",
            severity=AlertSeverity.HIGH,
            original_description="Test alert",
        )
        assert alert.alert_id == "test-123"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.risk_score == 0.0

    def test_create_enriched_alert_factory(self):
        """Test create_enriched_alert factory."""
        from ai_siem.models import create_enriched_alert

        alert = create_enriched_alert("alert-456", ai_summary="Test summary")
        assert alert.alert_id == "alert-456"
        assert alert.ai_summary == "Test summary"


class TestMitreMapping:
    """Tests for MitreMapping model."""

    def test_mitre_mapping_creation(self):
        """Test creating a MitreMapping."""
        from ai_siem.models import MitreMapping

        mapping = MitreMapping(
            tactic="Initial Access",
            tactic_id="TA0001",
            technique="Phishing",
            technique_id="T1566",
        )
        assert mapping.tactic_id == "TA0001"
        assert mapping.technique_id == "T1566"


class TestFirewallRule:
    """Tests for FirewallRule model."""

    def test_firewall_rule_creation(self):
        """Test creating a FirewallRule."""
        from ai_siem.models import FirewallRule

        rule = FirewallRule(
            action="block",
            direction="inbound",
            protocol="tcp",
            port="22",
            description="Block SSH",
        )
        assert rule.action == "block"
        assert rule.port == "22"

    def test_firewall_rule_defaults(self):
        """Test FirewallRule defaults."""
        from ai_siem.models import FirewallRule

        rule = FirewallRule()
        assert rule.action == "block"
        assert rule.direction == "inbound"
        assert rule.protocol == "any"


class TestAlertBatch:
    """Tests for AlertBatch model."""

    def test_alert_batch_creation(self):
        """Test creating an AlertBatch."""
        from ai_siem.models import AlertBatch

        batch = AlertBatch(
            batch_id="batch-123",
            total_count=100,
            enriched_count=95,
            error_count=5,
        )
        assert batch.batch_id == "batch-123"
        assert batch.total_count == 100


class TestAlertStats:
    """Tests for AlertStats model."""

    def test_alert_stats_creation(self):
        """Test creating AlertStats."""
        from ai_siem.models import AlertStats

        stats = AlertStats(
            total_alerts=1000,
            avg_risk_score=45.5,
        )
        assert stats.total_alerts == 1000
        assert stats.avg_risk_score == 45.5


class TestCacheEntry:
    """Tests for CacheEntry model."""

    def test_cache_entry_creation(self):
        """Test creating a CacheEntry."""
        from ai_siem.models import CacheEntry

        entry = CacheEntry(
            alert_hash="abc123",
            count=5,
            enriched=True,
        )
        assert entry.alert_hash == "abc123"
        assert entry.count == 5
        assert entry.enriched is True
