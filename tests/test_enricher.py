"""Tests for the alert enricher."""


class FailingGeminiModel:
    """Gemini-like model that raises during content generation."""

    def generate_content(self, prompt):
        raise RuntimeError(f"gemini unavailable for {prompt[:10]}")


class SuccessfulGeminiModel:
    """Gemini-like model that returns deterministic enrichment JSON."""

    def generate_content(self, prompt):
        class Response:
            text = """{
                "source": "gemini",
                "ai_summary": "Gemini summary",
                "risk_score": 80,
                "suggested_rules": [
                    {
                        "action": "block",
                        "direction": "inbound",
                        "protocol": "tcp",
                        "source_ip": "10.0.0.50",
                        "port": "22",
                        "description": "Review SSH source"
                    }
                ],
                "recommendations": ["Review SSH logs"]
            }"""

        return Response()


class TestAlertEnricher:
    """Tests for AlertEnricher class."""

    def test_create_enricher(self, mock_config):
        """Test creating an enricher."""
        from ai_siem.enricher import create_enricher

        enricher = create_enricher(mock_config)
        assert enricher is not None
        assert enricher.mock_mode is True

    def test_create_enricher_default(self):
        """Test creating enricher with defaults."""
        from ai_siem.enricher import create_enricher

        enricher = create_enricher()
        assert enricher is not None
        assert enricher.mock_mode is True

    def test_enrich_mock_mode(self, mock_config):
        """Test enriching alert in mock mode."""
        from ai_siem.enricher import create_enricher
        from ai_siem.models import EnrichedAlert

        enricher = create_enricher(mock_config)
        alert = EnrichedAlert(
            alert_id="test-123",
            original_description="sshd: Multiple authentication failures",
        )

        enriched = enricher.enrich(alert)
        assert enriched.ai_summary != ""
        assert enriched.risk_score > 0
        assert len(enriched.mitre_mappings) > 0
        assert len(enriched.recommendations) > 0
        assert enriched.enrichment_source == "mock"
        assert enriched.enrichment_status == "mock"

    def test_enrich_ssh_alert(self, mock_config):
        """Test enriching SSH-related alert."""
        from ai_siem.enricher import create_enricher
        from ai_siem.models import EnrichedAlert

        enricher = create_enricher(mock_config)
        alert = EnrichedAlert(
            alert_id="ssh-123",
            original_description="SSH brute force attempt",
            agent_ip="10.0.0.50",
        )

        enriched = enricher.enrich(alert)
        assert len(enriched.suggested_rules) > 0
        assert enriched.suggested_rules[0].port == "22"
        assert "10.0.0.50" in enriched.iocs

    def test_batch_enrich(self, mock_config):
        """Test batch enrichment."""
        from ai_siem.enricher import create_enricher
        from ai_siem.models import EnrichedAlert

        enricher = create_enricher(mock_config)
        alerts = [
            EnrichedAlert(alert_id=f"alert-{i}", original_description=f"Alert {i}")
            for i in range(3)
        ]

        enriched = enricher.batch_enrich(alerts)
        assert len(enriched) == 3
        assert all(a.ai_summary != "" for a in enriched)

    def test_analyze_threat(self, mock_config):
        """Test threat analysis."""
        from ai_siem.enricher import create_enricher
        from ai_siem.models import EnrichedAlert

        enricher = create_enricher(mock_config)
        alert = EnrichedAlert(
            alert_id="threat-123",
            original_description="Suspicious login activity",
        )

        analysis = enricher.analyze_threat(alert)
        assert "threat_type" in analysis
        assert "confidence" in analysis
        assert "recommended_actions" in analysis

    def test_extract_json_valid(self, mock_config):
        """Test JSON extraction from valid text."""
        from ai_siem.enricher import create_enricher

        enricher = create_enricher(mock_config)
        text = '{"key": "value", "number": 42}'

        result = enricher._extract_json(text)
        assert result["key"] == "value"
        assert result["number"] == 42

    def test_extract_json_from_markdown(self, mock_config):
        """Test JSON extraction from markdown code block."""
        from ai_siem.enricher import create_enricher

        enricher = create_enricher(mock_config)
        text = """Here is the response:
```json
{"key": "value"}
```
End of response."""

        result = enricher._extract_json(text)
        assert result["key"] == "value"

    def test_extract_json_invalid(self, mock_config):
        """Test JSON extraction from invalid text."""
        from ai_siem.enricher import create_enricher

        enricher = create_enricher(mock_config)
        text = "No JSON here"

        result = enricher._extract_json(text)
        assert result == {}

    def test_gemini_error_uses_visible_fallback_metadata(self, monkeypatch):
        """Test Gemini errors leave explicit fallback provenance on alerts."""
        monkeypatch.delenv("ENABLE_MOCK_MODE", raising=False)
        from ai_siem.enricher import create_enricher
        from ai_siem.models import EnrichedAlert, SIEMConfig

        enricher = create_enricher(SIEMConfig(enable_mock_mode=False, gemini_api_key="test"))
        enricher._model = FailingGeminiModel()
        alert = EnrichedAlert(alert_id="gemini-down", original_description="Suspicious login")

        enriched = enricher.enrich(alert)

        assert enriched.enrichment_source == "fallback"
        assert enriched.enrichment_status == "fallback"
        assert "gemini enrichment failed" in enriched.enrichment_error
        assert enriched.warnings
        assert "gemini enrichment failed" in enricher.last_failure_reason

    def test_gemini_firewall_rule_records_source_and_review(self, monkeypatch):
        """Test Gemini firewall suggestions carry source and review metadata."""
        monkeypatch.delenv("ENABLE_MOCK_MODE", raising=False)
        from ai_siem.enricher import create_enricher
        from ai_siem.models import EnrichedAlert, SIEMConfig

        enricher = create_enricher(SIEMConfig(enable_mock_mode=False, gemini_api_key="test"))
        enricher._model = SuccessfulGeminiModel()
        alert = EnrichedAlert(alert_id="gemini-ok", original_description="SSH brute force")

        enriched = enricher.enrich(alert)

        assert enriched.enrichment_source == "gemini"
        rule = enriched.suggested_rules[0]
        assert rule.source == "gemini"
        assert rule.requires_human_review is True
        assert "Suggestion only" in rule.safety_note


class TestMitreMapping:
    """Tests for MITRE ATT&CK mapping."""

    def test_mitre_mapping_applied(self, mock_config):
        """Test MITRE mappings are applied."""
        from ai_siem.enricher import create_enricher
        from ai_siem.models import EnrichedAlert

        enricher = create_enricher(mock_config)
        alert = EnrichedAlert(
            alert_id="mitre-test",
            original_description="Credential theft attempt",
        )

        enriched = enricher.enrich(alert)
        assert len(enriched.mitre_mappings) > 0
        assert enriched.mitre_mappings[0].tactic_id != ""


class TestFirewallRules:
    """Tests for firewall rule suggestions."""

    def test_firewall_rule_suggested(self, mock_config):
        """Test firewall rules are suggested."""
        from ai_siem.enricher import create_enricher
        from ai_siem.models import EnrichedAlert

        enricher = create_enricher(mock_config)
        alert = EnrichedAlert(
            alert_id="fw-test",
            original_description="SSH brute force",
            agent_ip="192.168.1.100",
        )

        enriched = enricher.enrich(alert)
        assert len(enriched.suggested_rules) > 0

        rule = enriched.suggested_rules[0]
        assert rule.action == "block"
        assert rule.protocol == "tcp"
        assert rule.source == "mock"
        assert rule.requires_human_review is True
