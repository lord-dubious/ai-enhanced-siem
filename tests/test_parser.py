"""Tests for the alert parser."""

import pytest
import msgspec


class TestAlertParser:
    """Tests for AlertParser class."""

    def test_create_parser(self, mock_config):
        """Test creating a parser."""
        from ai_siem.parser import create_parser

        parser = create_parser(mock_config)
        assert parser is not None
        assert parser.mock_mode is True

    def test_create_parser_default(self):
        """Test creating parser with defaults."""
        from ai_siem.parser import create_parser

        parser = create_parser()
        assert parser is not None
        assert parser.mock_mode is True

    def test_parse_line_valid(self, mock_config, sample_wazuh_alert):
        """Test parsing a valid JSON line."""
        from ai_siem.parser import create_parser

        parser = create_parser(mock_config)
        parser.mock_mode = False  # Test actual parsing

        alert = parser.parse_line(sample_wazuh_alert)
        assert alert is not None
        assert alert.rule.level == 10
        assert alert.agent.name == "web-server"

    def test_parse_line_invalid(self, mock_config):
        """Test parsing invalid JSON."""
        from ai_siem.parser import create_parser

        parser = create_parser(mock_config)
        parser.mock_mode = False

        result = parser.parse_line("not valid json")
        assert result is None

    def test_parse_line_empty(self, mock_config):
        """Test parsing empty line."""
        from ai_siem.parser import create_parser

        parser = create_parser(mock_config)
        result = parser.parse_line("")
        assert result is None

    def test_parse_file_mock_mode(self, mock_config):
        """Test parsing file in mock mode."""
        from ai_siem.parser import create_parser

        parser = create_parser(mock_config)
        alerts = list(parser.parse_file("/fake/path"))

        assert len(alerts) == 5
        assert alerts[0].agent.name == "mock-agent"

    def test_to_enriched_alert(self, mock_config, sample_wazuh_alert):
        """Test converting to EnrichedAlert."""
        from ai_siem.parser import create_parser
        from ai_siem.models import AlertSeverity

        parser = create_parser(mock_config)
        parser.mock_mode = False

        wazuh_alert = parser.parse_line(sample_wazuh_alert)
        enriched = parser.to_enriched_alert(wazuh_alert)

        assert enriched.alert_id == "1705312200.12345"
        assert enriched.severity == AlertSeverity.HIGH
        assert enriched.agent_name == "web-server"

    def test_to_enriched_alert_low_severity(self, mock_config, sample_wazuh_alert_low):
        """Test converting low severity alert."""
        from ai_siem.parser import create_parser
        from ai_siem.models import AlertSeverity

        parser = create_parser(mock_config)
        parser.mock_mode = False

        wazuh_alert = parser.parse_line(sample_wazuh_alert_low)
        enriched = parser.to_enriched_alert(wazuh_alert)

        assert enriched.severity == AlertSeverity.LOW

    def test_compute_hash(self, mock_config, sample_wazuh_alert):
        """Test computing alert hash."""
        from ai_siem.parser import create_parser

        parser = create_parser(mock_config)
        parser.mock_mode = False

        alert = parser.parse_line(sample_wazuh_alert)
        hash1 = parser.compute_hash(alert)
        hash2 = parser.compute_hash(alert)

        assert hash1 == hash2
        assert len(hash1) == 16

    def test_level_to_severity_critical(self, mock_config):
        """Test level 12+ maps to critical."""
        from ai_siem.parser import create_parser
        from ai_siem.models import AlertSeverity

        parser = create_parser(mock_config)
        assert parser._level_to_severity(12) == AlertSeverity.CRITICAL
        assert parser._level_to_severity(15) == AlertSeverity.CRITICAL

    def test_level_to_severity_high(self, mock_config):
        """Test level 9-11 maps to high."""
        from ai_siem.parser import create_parser
        from ai_siem.models import AlertSeverity

        parser = create_parser(mock_config)
        assert parser._level_to_severity(9) == AlertSeverity.HIGH
        assert parser._level_to_severity(11) == AlertSeverity.HIGH

    def test_level_to_severity_medium(self, mock_config):
        """Test level 6-8 maps to medium."""
        from ai_siem.parser import create_parser
        from ai_siem.models import AlertSeverity

        parser = create_parser(mock_config)
        assert parser._level_to_severity(6) == AlertSeverity.MEDIUM
        assert parser._level_to_severity(8) == AlertSeverity.MEDIUM

    def test_level_to_severity_low(self, mock_config):
        """Test level 0-5 maps to low."""
        from ai_siem.parser import create_parser
        from ai_siem.models import AlertSeverity

        parser = create_parser(mock_config)
        assert parser._level_to_severity(0) == AlertSeverity.LOW
        assert parser._level_to_severity(5) == AlertSeverity.LOW


class TestMsgspecDecoding:
    """Tests for msgspec decoding performance."""

    def test_decode_wazuh_alert(self, sample_wazuh_alert):
        """Test decoding with msgspec."""
        from ai_siem.models import WazuhAlertStruct

        decoder = msgspec.json.Decoder(WazuhAlertStruct)
        alert = decoder.decode(sample_wazuh_alert.encode())

        assert alert.rule.level == 10
        assert alert.agent.id == "001"

    def test_decode_partial_alert(self):
        """Test decoding alert with missing fields."""
        from ai_siem.models import WazuhAlertStruct

        partial = '{"timestamp": "2024-01-01T00:00:00Z", "id": "test"}'
        decoder = msgspec.json.Decoder(WazuhAlertStruct)
        alert = decoder.decode(partial.encode())

        assert alert.timestamp == "2024-01-01T00:00:00Z"
        assert alert.rule.level == 0  # Default value
