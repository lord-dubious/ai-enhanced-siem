"""AI enrichment using Gemini for MITRE ATT&CK mapping and analysis."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, cast

from ai_siem.models import (
    EnrichedAlert,
    FirewallRule,
    MitreMapping,
    SIEMConfig,
)

logger = logging.getLogger(__name__)


class AlertEnricher:
    """AI-powered alert enrichment using Gemini."""

    def __init__(self, config: SIEMConfig) -> None:
        """Initialize the enricher.

        Args:
            config: SIEM configuration
        """
        self.config = config
        self.mock_mode = config.enable_mock_mode
        self._model: Any | None = None
        self.last_error = ""
        self.last_failure_reason = "mock_mode" if self.mock_mode else ""

    @property
    def model(self) -> Any:
        """Get or create the Gemini model."""
        if self._model is None and not self.mock_mode:
            import google.generativeai as genai

            genai.configure(api_key=self.config.gemini_api_key)
            self._model = genai.GenerativeModel(self.config.gemini_model)
        return self._model

    def enrich(self, alert: EnrichedAlert) -> EnrichedAlert:
        """Enrich an alert with AI analysis.

        Args:
            alert: Alert to enrich

        Returns:
            Enriched alert with MITRE mappings, firewall rules, etc.
        """
        if self.mock_mode:
            return self._mock_enrich(alert)

        prompt = self._build_prompt(alert)

        try:
            response = self.model.generate_content(prompt)
            enrichment = self._parse_response(response.text)
            return self._apply_enrichment(alert, enrichment)
        except Exception as e:
            self.last_error = str(e)
            self.last_failure_reason = f"gemini enrichment failed: {type(e).__name__}: {e}"
            logger.warning("Gemini enrichment failed for alert %s: %s", alert.alert_id, e)
            self._apply_fallback_metadata(alert, self.last_failure_reason)
            return alert

    def batch_enrich(self, alerts: list[EnrichedAlert]) -> list[EnrichedAlert]:
        """Enrich multiple alerts.

        Args:
            alerts: List of alerts to enrich

        Returns:
            List of enriched alerts
        """
        return [self.enrich(alert) for alert in alerts]

    def analyze_threat(self, alert: EnrichedAlert) -> dict[str, Any]:
        """Perform deep threat analysis on an alert.

        Args:
            alert: Alert to analyze

        Returns:
            Threat analysis results
        """
        if self.mock_mode:
            return {
                "threat_type": "Brute Force Attack",
                "confidence": 0.85,
                "attack_stage": "Initial Access",
                "related_techniques": ["T1110", "T1078"],
                "recommended_actions": [
                    "Block source IP",
                    "Enable account lockout",
                    "Review authentication logs",
                ],
            }

        prompt = f"""Perform a deep threat analysis on this security alert:

Alert: {alert.original_description}
Severity: {alert.severity.value}
Agent: {alert.agent_name} ({alert.agent_ip})
Raw Data: {json.dumps(alert.raw_data, default=str)}

Analyze and provide:
1. Threat type classification
2. Confidence level (0-1)
3. Attack stage in kill chain
4. Related MITRE techniques
5. Recommended immediate actions

Respond with JSON only."""

        try:
            response = self.model.generate_content(prompt)
            return self._extract_json(response.text)
        except Exception as e:
            self.last_error = str(e)
            self.last_failure_reason = f"gemini analysis failed: {type(e).__name__}: {e}"
            logger.warning("Gemini threat analysis failed for alert %s: %s", alert.alert_id, e)
            return {
                "error": "Analysis failed",
                "source": "fallback",
                "requires_human_review": True,
                "failure_reason": self.last_failure_reason,
            }

    def _build_prompt(self, alert: EnrichedAlert) -> str:
        """Build the enrichment prompt."""
        return f"""You are a security analyst. Analyze this Wazuh security alert and provide enrichment.

Alert Description: {alert.original_description}
Current Severity: {alert.severity.value}
Source Agent: {alert.agent_name} ({alert.agent_ip})
Raw Data: {json.dumps(alert.raw_data, default=str)}

Provide a JSON response with:
{{
    "ai_summary": "Brief summary of the security event",
    "risk_score": 0-100 numeric score,
    "mitre_mappings": [
        {{
            "tactic": "tactic name",
            "tactic_id": "TA00XX",
            "technique": "technique name",
            "technique_id": "T1XXX"
        }}
    ],
    "suggested_rules": [
        {{
            "action": "block",
            "direction": "inbound",
            "protocol": "tcp",
            "source_ip": "x.x.x.x or any",
            "port": "22",
            "description": "rule description"
        }}
    ],
    "iocs": ["indicator1", "indicator2"],
    "recommendations": ["action1", "action2"]
}}

Return ONLY valid JSON."""

    def _parse_response(self, text: str) -> dict[str, Any]:
        """Parse the AI response."""
        return self._extract_json(text)

    def _extract_json(self, text: str) -> dict[str, Any]:
        """Extract JSON from response text."""
        try:
            parsed = json.loads(text)
            return cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            pass

        # Try to find JSON block
        json_match = re.search(r"\{[\s\S]*\}", text)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                return cast(dict[str, Any], parsed) if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                pass

        return {}

    def _apply_enrichment(self, alert: EnrichedAlert, enrichment: dict[str, Any]) -> EnrichedAlert:
        """Apply enrichment data to alert."""
        alert.enrichment_source = enrichment.get("source", "gemini")
        alert.enrichment_status = "success"
        alert.enrichment_error = ""

        if "ai_summary" in enrichment:
            alert.ai_summary = enrichment["ai_summary"]

        if "risk_score" in enrichment:
            alert.risk_score = float(enrichment["risk_score"])

        if "mitre_mappings" in enrichment:
            for mapping in enrichment["mitre_mappings"]:
                alert.mitre_mappings.append(
                    MitreMapping(
                        tactic=mapping.get("tactic", ""),
                        tactic_id=mapping.get("tactic_id", ""),
                        technique=mapping.get("technique", ""),
                        technique_id=mapping.get("technique_id", ""),
                    )
                )

        if "suggested_rules" in enrichment:
            for rule in enrichment["suggested_rules"]:
                alert.suggested_rules.append(
                    FirewallRule(
                        action=rule.get("action", "block"),
                        direction=rule.get("direction", "inbound"),
                        protocol=rule.get("protocol", "any"),
                        source_ip=rule.get("source_ip", "any"),
                        port=rule.get("port", "any"),
                        description=rule.get("description", ""),
                        source=rule.get("source", alert.enrichment_source),
                        requires_human_review=rule.get("requires_human_review", True),
                        safety_note=rule.get(
                            "safety_note",
                            "Suggestion only; validate context before applying.",
                        ),
                    )
                )

        if "iocs" in enrichment:
            alert.iocs.extend(enrichment["iocs"])

        if "recommendations" in enrichment:
            alert.recommendations.extend(enrichment["recommendations"])

        return alert

    def _apply_fallback_metadata(self, alert: EnrichedAlert, reason: str) -> None:
        """Mark alert enrichment as degraded without raising to callers."""
        alert.enrichment_source = "fallback"
        alert.enrichment_status = "fallback"
        alert.enrichment_error = reason
        alert.warnings.append(reason)
        alert.recommendations.append(f"Enrichment failed; review alert manually: {reason}")

    def _mock_enrich(self, alert: EnrichedAlert) -> EnrichedAlert:
        """Generate mock enrichment for testing."""
        alert.ai_summary = f"Mock analysis: {alert.original_description}"
        alert.risk_score = 65.0
        alert.enrichment_source = "mock"
        alert.enrichment_status = "mock"

        alert.mitre_mappings.append(
            MitreMapping(
                tactic="Initial Access",
                tactic_id="TA0001",
                technique="Valid Accounts",
                technique_id="T1078",
            )
        )

        if "ssh" in alert.original_description.lower():
            alert.suggested_rules.append(
                FirewallRule(
                    action="block",
                    direction="inbound",
                    protocol="tcp",
                    source_ip=alert.agent_ip,
                    port="22",
                    description="Block SSH brute force source",
                    source="mock",
                    requires_human_review=True,
                    safety_note="Mock suggestion only; do not apply without analyst review.",
                )
            )
            alert.iocs.append(alert.agent_ip)

        alert.recommendations.extend(
            [
                "Review authentication logs",
                "Consider implementing rate limiting",
                "Enable multi-factor authentication",
            ]
        )

        return alert


def create_enricher(config: SIEMConfig | None = None) -> AlertEnricher:
    """Create an AlertEnricher instance.

    Args:
        config: Optional SIEM configuration

    Returns:
        AlertEnricher instance
    """
    if config is None:
        config = SIEMConfig(enable_mock_mode=True)
    return AlertEnricher(config)
