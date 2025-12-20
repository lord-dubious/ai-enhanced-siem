"""AI-Enhanced SIEM with Wazuh, msgspec, Redis, and Gemini AI."""

from ai_siem.models import (
    AlertBatch,
    AlertSeverity,
    AlertStats,
    CacheEntry,
    EnrichedAlert,
    FirewallRule,
    MitreMapping,
    MitreTactic,
    SIEMConfig,
    WazuhAgentStruct,
    WazuhAlertStruct,
    WazuhRuleStruct,
    create_config,
    create_enriched_alert,
)
from ai_siem.parser import (
    AlertParser,
    create_parser,
)
from ai_siem.cache import (
    AlertCache,
    create_cache,
)
from ai_siem.enricher import (
    AlertEnricher,
    create_enricher,
)
from ai_siem.pipeline import (
    SIEMPipeline,
    create_pipeline,
)

__version__ = "0.1.0"

__all__ = [
    # Models
    "AlertBatch",
    "AlertSeverity",
    "AlertStats",
    "CacheEntry",
    "EnrichedAlert",
    "FirewallRule",
    "MitreMapping",
    "MitreTactic",
    "SIEMConfig",
    "WazuhAgentStruct",
    "WazuhAlertStruct",
    "WazuhRuleStruct",
    "create_config",
    "create_enriched_alert",
    # Parser
    "AlertParser",
    "create_parser",
    # Cache
    "AlertCache",
    "create_cache",
    # Enricher
    "AlertEnricher",
    "create_enricher",
    # Pipeline
    "SIEMPipeline",
    "create_pipeline",
]
