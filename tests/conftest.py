"""Test configuration and fixtures."""

import pytest


@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    """Set up environment for tests."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-api-key")
    monkeypatch.setenv("ENABLE_MOCK_MODE", "true")


@pytest.fixture
def mock_config():
    """Create a mock configuration."""
    from ai_siem.models import SIEMConfig

    return SIEMConfig(
        gemini_api_key="test-api-key",
        enable_mock_mode=True,
    )


@pytest.fixture
def sample_wazuh_alert():
    """Sample Wazuh alert JSON."""
    return """{
  "timestamp": "2024-01-15T10:30:00Z",
  "rule": {
    "level": 10,
    "description": "sshd: Multiple authentication failures",
    "id": "5715",
    "groups": ["syslog", "sshd", "authentication_failures"],
    "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}
  },
  "agent": {
    "id": "001",
    "name": "web-server",
    "ip": "192.168.1.100"
  },
  "manager": {"name": "wazuh-manager"},
  "id": "1705312200.12345",
  "full_log": "Jan 15 10:30:00 web-server sshd[12345]: Failed password for invalid user admin",
  "decoder": {"name": "sshd"},
  "data": {"srcip": "10.0.0.50", "srcport": "45678"},
  "location": "/var/log/secure"
}"""


@pytest.fixture
def sample_wazuh_alert_low():
    """Sample low severity Wazuh alert."""
    return """{
  "timestamp": "2024-01-15T10:35:00Z",
  "rule": {
    "level": 3,
    "description": "Successful sudo to root",
    "id": "5401",
    "groups": ["syslog", "sudo"]
  },
  "agent": {
    "id": "002",
    "name": "db-server",
    "ip": "192.168.1.101"
  },
  "id": "1705312500.12346",
  "full_log": "Jan 15 10:35:00 db-server sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root",
  "location": "/var/log/secure"
}"""
