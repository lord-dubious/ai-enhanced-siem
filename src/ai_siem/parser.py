"""High-performance alert parser using msgspec."""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Iterator

import msgspec

from ai_siem.models import (
    AlertSeverity,
    EnrichedAlert,
    SIEMConfig,
    WazuhAlertStruct,
)


class AlertParser:
    """High-performance alert parser using msgspec."""

    def __init__(self, config: SIEMConfig) -> None:
        """Initialize the parser.

        Args:
            config: SIEM configuration
        """
        self.config = config
        self.mock_mode = config.enable_mock_mode
        self._decoder = msgspec.json.Decoder(WazuhAlertStruct)

    def parse_line(self, line: str) -> WazuhAlertStruct | None:
        """Parse a single JSON line using msgspec.

        Args:
            line: JSON line from Wazuh alerts file

        Returns:
            Parsed WazuhAlertStruct or None if parsing fails
        """
        if not line.strip():
            return None

        try:
            return self._decoder.decode(line.encode())
        except msgspec.DecodeError:
            return None

    def parse_file(self, file_path: str | Path) -> Iterator[WazuhAlertStruct]:
        """Parse a Wazuh alerts file.

        Args:
            file_path: Path to the alerts JSON file

        Yields:
            Parsed WazuhAlertStruct objects
        """
        if self.mock_mode:
            yield from self._generate_mock_alerts(5)
            return

        path = Path(file_path)
        if not path.exists():
            return

        with open(path, "r") as f:
            for line in f:
                alert = self.parse_line(line)
                if alert:
                    yield alert

    def tail_file(self, file_path: str | Path) -> Iterator[WazuhAlertStruct]:
        """Tail a Wazuh alerts file for new entries.

        Args:
            file_path: Path to the alerts JSON file

        Yields:
            Parsed WazuhAlertStruct objects as they appear
        """
        if self.mock_mode:
            yield from self._generate_mock_alerts(3)
            return

        path = Path(file_path)
        if not path.exists():
            return

        # Start from end of file
        with open(path, "r") as f:
            f.seek(0, 2)  # Seek to end
            while True:
                line = f.readline()
                if line:
                    alert = self.parse_line(line)
                    if alert:
                        yield alert

    def to_enriched_alert(self, alert: WazuhAlertStruct) -> EnrichedAlert:
        """Convert a WazuhAlertStruct to an EnrichedAlert.

        Args:
            alert: Parsed Wazuh alert

        Returns:
            EnrichedAlert ready for AI enrichment
        """
        # Determine severity from rule level
        severity = self._level_to_severity(alert.rule.level)

        # Parse timestamp
        try:
            timestamp = datetime.fromisoformat(alert.timestamp.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            timestamp = datetime.now()

        return EnrichedAlert(
            alert_id=alert.id or self._generate_id(alert),
            timestamp=timestamp,
            severity=severity,
            original_description=alert.rule.description,
            agent_name=alert.agent.name,
            agent_ip=alert.agent.ip,
            raw_data={
                "rule": {
                    "id": alert.rule.id,
                    "level": alert.rule.level,
                    "groups": alert.rule.groups,
                    "mitre": alert.rule.mitre,
                },
                "location": alert.location,
                "full_log": alert.full_log,
                "data": alert.data,
            },
        )

    def compute_hash(self, alert: WazuhAlertStruct) -> str:
        """Compute a hash for deduplication.

        Args:
            alert: Wazuh alert

        Returns:
            SHA256 hash of key alert fields
        """
        key_data = f"{alert.rule.id}:{alert.agent.id}:{alert.rule.description}"
        return hashlib.sha256(key_data.encode()).hexdigest()[:16]

    def _level_to_severity(self, level: int) -> AlertSeverity:
        """Convert Wazuh rule level to severity.

        Args:
            level: Wazuh rule level (0-15)

        Returns:
            AlertSeverity enum value
        """
        if level >= 12:
            return AlertSeverity.CRITICAL
        elif level >= 9:
            return AlertSeverity.HIGH
        elif level >= 6:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

    def _generate_id(self, alert: WazuhAlertStruct) -> str:
        """Generate an alert ID if none exists."""
        return f"alert-{self.compute_hash(alert)}-{datetime.now().timestamp()}"

    def _generate_mock_alerts(self, count: int) -> Iterator[WazuhAlertStruct]:
        """Generate mock alerts for testing.

        Args:
            count: Number of mock alerts to generate

        Yields:
            Mock WazuhAlertStruct objects
        """
        mock_rules = [
            ("5710", 7, "sshd: Attempt to login using a non-existent user"),
            ("5503", 10, "PAM: User login failed"),
            ("5715", 12, "sshd: Multiple authentication failures"),
            ("87105", 5, "Suricata: Alert - ET MALWARE"),
            ("100002", 9, "File integrity changed"),
        ]

        for i in range(count):
            rule_id, level, desc = mock_rules[i % len(mock_rules)]
            alert = WazuhAlertStruct(
                timestamp=datetime.now().isoformat(),
                id=f"mock-{i}-{datetime.now().timestamp()}",
                location="/var/log/secure",
                full_log=f"Mock alert: {desc}",
            )
            alert.rule.id = rule_id
            alert.rule.level = level
            alert.rule.description = desc
            alert.rule.groups = ["syslog", "sshd"]
            alert.agent.id = "001"
            alert.agent.name = "mock-agent"
            alert.agent.ip = "192.168.1.100"
            yield alert


def create_parser(config: SIEMConfig | None = None) -> AlertParser:
    """Create an AlertParser instance.

    Args:
        config: Optional SIEM configuration

    Returns:
        AlertParser instance
    """
    if config is None:
        config = SIEMConfig(enable_mock_mode=True)
    return AlertParser(config)
