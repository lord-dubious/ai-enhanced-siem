# AI-Enhanced SIEM

A Security Information and Event Management (SIEM) pipeline that parses Wazuh alerts with `msgspec`, uses Redis for deduplication/storage when available, and can call Gemini for optional alert enrichment. When Redis or Gemini is unavailable, the pipeline records degraded-mode metadata on alerts and cache stats instead of hiding the failure.

## Features

- **Structured Parsing**: Uses `msgspec` for JSON deserialization of Wazuh alerts
- **Redis Deduplication**: Redis-backed alert deduplication with explicit degraded-state reporting
- **Optional Gemini Enrichment**: Gemini can map alerts to MITRE ATT&CK tactics and suggest remediation when configured
- **Streaming Processing**: Stream processing of Wazuh `alerts.json`
- **IOC Extraction**: Automatic extraction of IP addresses, domains, file hashes, and other indicators
- **Firewall Rule Suggestions**: Suggested firewall rules include source metadata and require human review before use

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Wazuh Agent   │────▶│  Wazuh Manager   │────▶│  alerts.json    │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                                                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     SIEM Alert Pipeline                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐  │
│  │   msgspec   │───▶│    Redis    │───▶│   Optional Gemini       │  │
│  │   Parser    │    │   Deduper   │    │  (MITRE, IOCs, Hints)   │  │
│  └─────────────┘    └─────────────┘    └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                                          │
                                                          ▼
                              ┌──────────────────────────────────────┐
                              │  OpenSearch / Elasticsearch / SIEM   │
                              └──────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.11+
- Redis (for production deduplication)
- Wazuh Manager (for alert ingestion)
- Gemini API key

### Quick Start

```bash
# Clone the repository
git clone https://github.com/lord-dubious/ai-enhanced-siem.git
cd ai-enhanced-siem

# Create virtual environment
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -e ".[dev]"

# Set up environment variables
cp .env.example .env
# Edit .env with your GEMINI_API_KEY

# Run tests
pytest tests/ -v
```

### Docker Deployment

```bash
# Start the full stack (Redis + Pipeline)
docker-compose up -d

# Or with Wazuh and OpenSearch
docker-compose --profile full-stack up -d
```

## Usage

### CLI Commands

```bash
# Process a single alert file
ai-siem process alerts.json

# Watch and process alerts in real-time
ai-siem process --watch /var/ossec/logs/alerts/alerts.json

# Process with custom output
ai-siem process alerts.json --output enriched-alerts.json

# Analyze a specific alert
ai-siem analyze '{"rule": {"id": "100001", "level": 12, ...}}'
```

### Python API

```python
from ai_siem import Pipeline, WazuhAlertParser, AlertCache, AIEnricher

# Initialize components
parser = WazuhAlertParser()
cache = AlertCache(redis_url="redis://localhost:6379")
enricher = AIEnricher(api_key="your-gemini-api-key")

# Create pipeline
pipeline = Pipeline(parser=parser, cache=cache, enricher=enricher)

# Process alerts
with open("alerts.json") as f:
    for line in f:
        result = await pipeline.process_alert(line)
        if result:
            print(f"Enriched: {result.mitre_tactics}")
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `CACHE_TTL` | Alert deduplication TTL (seconds) | `3600` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `BATCH_SIZE` | Alerts to process per batch | `100` |

## Severity Mapping

| Wazuh Level | Severity | Action |
|-------------|----------|--------|
| 12+ | CRITICAL | Immediate response, Gemini enrichment |
| 9-11 | HIGH | Priority enrichment |
| 6-8 | MEDIUM | Standard enrichment |
| 0-5 | LOW | Log only, minimal enrichment |

## MITRE ATT&CK and Rule-Suggestion Metadata

Gemini or mock enrichment can add MITRE ATT&CK mappings and remediation suggestions. Treat firewall rules as reviewable suggestions, not production-ready commands:

```json
{
  "alert_id": "1234567890.123",
  "original_rule": "SSH brute force attack",
  "severity": "HIGH",
  "mitre_mapping": {
    "tactics": ["Initial Access", "Credential Access"],
    "techniques": ["T1110.001 - Password Guessing"],
    "sub_techniques": ["T1110.001"]
  },
  "iocs": {
    "ip_addresses": ["192.168.1.100"],
    "usernames": ["admin", "root"]
  },
  "enrichment_source": "gemini",
  "enrichment_status": "success",
  "recommendations": [
    "Review SSH access logs",
    "Validate source IP reputation"
  ],
  "suggested_rules": [
    {
      "action": "block",
      "source_ip": "192.168.1.100",
      "port": "22",
      "source": "gemini",
      "requires_human_review": true,
      "safety_note": "Suggestion only; validate context before applying."
    }
  ]
}
```

## Performance

Performance depends on alert shape, Redis availability, hardware, and Gemini API latency. The project does not currently publish reproducible benchmarks; measure in your environment before making capacity claims.

| Metric | Value |
|--------|-------|
| JSON Parsing | Environment dependent |
| Deduplication Check | Redis/network dependent |
| Gemini Enrichment | API and quota dependent |
| Memory Usage | Alert-volume dependent |

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=ai_siem --cov-report=html

# Run specific test module
pytest tests/test_parser.py -v

# Run performance tests
pytest tests/ -v -k "performance"
```

## Project Structure

```
ai-enhanced-siem/
├── src/ai_siem/
│   ├── __init__.py      # Package exports
│   ├── models.py        # Pydantic + msgspec data models
│   ├── parser.py        # Wazuh alert parser
│   ├── cache.py         # Redis deduplication cache
│   ├── enricher.py      # Optional Gemini enrichment engine
│   ├── pipeline.py      # Main processing orchestrator
│   └── cli.py           # Typer CLI interface
├── tests/
│   ├── conftest.py      # Pytest fixtures
│   ├── test_models.py   # Model validation tests
│   ├── test_parser.py   # Parser tests
│   ├── test_cache.py    # Cache tests
│   ├── test_enricher.py # AI enricher tests
│   └── test_pipeline.py # Integration tests
├── docker-compose.yml   # Full stack deployment
├── Dockerfile          # Production container
└── pyproject.toml      # Project configuration
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`pytest tests/ -v`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Wazuh](https://wazuh.com/) - Open source security monitoring
- [msgspec](https://jcristharif.com/msgspec/) - Structured serialization
- [Google Gemini](https://ai.google.dev/) - Optional enrichment provider
- [MITRE ATT&CK](https://attack.mitre.org/) - Threat framework
