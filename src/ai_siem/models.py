"""Models for the AI-Enhanced SIEM using msgspec for high-performance parsing."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

import msgspec
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MitreTactic(str, Enum):
    """MITRE ATT&CK Tactics."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class SIEMConfig(BaseSettings):
    """Configuration for the AI-Enhanced SIEM."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    gemini_api_key: str = Field(default="", description="Gemini API key")
    gemini_model: str = Field(default="gemini-2.0-flash", description="Gemini model")
    redis_host: str = Field(default="localhost", description="Redis host")
    redis_port: int = Field(default=6379, description="Redis port")
    redis_db: int = Field(default=0, description="Redis database")
    redis_password: str = Field(default="", description="Redis password")
    wazuh_alerts_path: str = Field(
        default="/var/ossec/logs/alerts/alerts.json",
        description="Path to Wazuh alerts file",
    )
    wazuh_api_url: str = Field(
        default="https://localhost:55000",
        description="Wazuh API URL",
    )
    wazuh_api_user: str = Field(default="wazuh", description="Wazuh API user")
    wazuh_api_password: str = Field(default="wazuh", description="Wazuh API password")
    alert_cache_ttl: int = Field(default=3600, description="Alert cache TTL in seconds")
    enable_mock_mode: bool = Field(default=False, description="Enable mock mode")
    batch_size: int = Field(default=100, description="Batch size for processing")
    log_level: str = Field(default="INFO", description="Logging level")


# msgspec structs for ultra-fast JSON parsing
class WazuhAgentStruct(msgspec.Struct):
    """Wazuh agent information (msgspec struct for speed)."""

    id: str = ""
    name: str = ""
    ip: str = ""


class WazuhRuleStruct(msgspec.Struct):
    """Wazuh rule information (msgspec struct for speed)."""

    level: int = 0
    description: str = ""
    id: str = ""
    groups: list[str] = msgspec.field(default_factory=list)
    mitre: dict = msgspec.field(default_factory=dict)


class WazuhAlertStruct(msgspec.Struct):
    """Wazuh alert structure (msgspec struct for ultra-fast parsing)."""

    timestamp: str = ""
    rule: WazuhRuleStruct = msgspec.field(default_factory=WazuhRuleStruct)
    agent: WazuhAgentStruct = msgspec.field(default_factory=WazuhAgentStruct)
    manager: dict = msgspec.field(default_factory=dict)
    id: str = ""
    full_log: str = ""
    decoder: dict = msgspec.field(default_factory=dict)
    data: dict = msgspec.field(default_factory=dict)
    location: str = ""


# Pydantic models for enriched data
class MitreMapping(BaseModel):
    """MITRE ATT&CK mapping for an alert."""

    tactic: str = Field(default="", description="MITRE tactic")
    tactic_id: str = Field(default="", description="MITRE tactic ID (e.g., TA0001)")
    technique: str = Field(default="", description="MITRE technique")
    technique_id: str = Field(default="", description="MITRE technique ID (e.g., T1566)")
    subtechnique: str = Field(default="", description="MITRE subtechnique")
    subtechnique_id: str = Field(default="", description="MITRE subtechnique ID")


class FirewallRule(BaseModel):
    """Suggested firewall rule."""

    action: str = Field(default="block", description="Rule action (block, allow, drop)")
    direction: str = Field(default="inbound", description="Traffic direction")
    protocol: str = Field(default="any", description="Protocol (tcp, udp, icmp, any)")
    source_ip: str = Field(default="any", description="Source IP or CIDR")
    dest_ip: str = Field(default="any", description="Destination IP or CIDR")
    port: str = Field(default="any", description="Port or port range")
    description: str = Field(default="", description="Rule description")
    priority: int = Field(default=100, description="Rule priority")
    source: str = Field(default="unspecified", description="Source of the rule suggestion")
    requires_human_review: bool = Field(
        default=True,
        description="Whether the suggestion requires human review before use",
    )
    safety_note: str = Field(
        default="Suggestion only; review before applying in any firewall.",
        description="Safety note for operators reviewing the suggestion",
    )


class EnrichedAlert(BaseModel):
    """Alert enriched with AI analysis."""

    alert_id: str = Field(..., description="Original alert ID")
    timestamp: datetime = Field(default_factory=datetime.now, description="Alert timestamp")
    severity: AlertSeverity = Field(default=AlertSeverity.LOW, description="Alert severity")
    original_description: str = Field(default="", description="Original rule description")
    ai_summary: str = Field(default="", description="AI-generated summary")
    mitre_mappings: list[MitreMapping] = Field(
        default_factory=list, description="MITRE ATT&CK mappings"
    )
    suggested_rules: list[FirewallRule] = Field(
        default_factory=list, description="Suggested firewall rules"
    )
    risk_score: float = Field(default=0.0, description="Risk score (0-100)")
    iocs: list[str] = Field(default_factory=list, description="Indicators of Compromise")
    recommendations: list[str] = Field(
        default_factory=list, description="Remediation recommendations"
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-fatal processing warnings or degraded-mode notes",
    )
    enrichment_source: str = Field(
        default="not_enriched",
        description="Source used for enrichment metadata",
    )
    enrichment_status: str = Field(
        default="pending",
        description="Enrichment status such as success, mock, or fallback",
    )
    enrichment_error: str = Field(
        default="",
        description="Last enrichment error when fallback metadata was used",
    )
    cache_status: str = Field(
        default="not_stored",
        description="Last cache storage status for this alert",
    )
    cache_error: str = Field(
        default="",
        description="Last cache error observed while handling this alert",
    )
    agent_name: str = Field(default="", description="Source agent name")
    agent_ip: str = Field(default="", description="Source agent IP")
    raw_data: dict[str, Any] = Field(default_factory=dict, description="Raw alert data")
    enriched_at: datetime = Field(default_factory=datetime.now, description="Enrichment timestamp")


class AlertBatch(BaseModel):
    """Batch of alerts for processing."""

    alerts: list[EnrichedAlert] = Field(default_factory=list, description="List of alerts")
    batch_id: str = Field(default="", description="Batch identifier")
    processed_at: datetime = Field(default_factory=datetime.now, description="Processing timestamp")
    total_count: int = Field(default=0, description="Total alerts in batch")
    enriched_count: int = Field(default=0, description="Successfully enriched alerts")
    error_count: int = Field(default=0, description="Alerts with errors")
    warning_count: int = Field(default=0, description="Alerts with warnings")
    warnings: list[str] = Field(default_factory=list, description="Batch processing warnings")


class AlertStats(BaseModel):
    """Statistics for alert processing."""

    total_alerts: int = Field(default=0, description="Total alerts processed")
    alerts_by_severity: dict[str, int] = Field(
        default_factory=dict, description="Alerts by severity"
    )
    alerts_by_tactic: dict[str, int] = Field(
        default_factory=dict, description="Alerts by MITRE tactic"
    )
    avg_risk_score: float = Field(default=0.0, description="Average risk score")
    top_agents: list[tuple[str, int]] = Field(
        default_factory=list, description="Top agents by alert count"
    )
    processing_time_ms: float = Field(default=0.0, description="Processing time in ms")


class CacheEntry(BaseModel):
    """Cache entry for deduplication."""

    alert_hash: str = Field(..., description="Alert hash for deduplication")
    first_seen: datetime = Field(default_factory=datetime.now, description="First seen time")
    last_seen: datetime = Field(default_factory=datetime.now, description="Last seen time")
    count: int = Field(default=1, description="Occurrence count")
    enriched: bool = Field(default=False, description="Whether alert was enriched")


def create_config(**kwargs) -> SIEMConfig:
    """Create a SIEMConfig with optional overrides."""
    return SIEMConfig(**kwargs)


def create_enriched_alert(alert_id: str, **kwargs) -> EnrichedAlert:
    """Create an EnrichedAlert."""
    return EnrichedAlert(alert_id=alert_id, **kwargs)
