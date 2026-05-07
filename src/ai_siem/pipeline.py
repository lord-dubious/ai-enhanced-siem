"""Main SIEM pipeline orchestrator."""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Iterator

from ai_siem.cache import AlertCache, create_cache
from ai_siem.enricher import AlertEnricher, create_enricher
from ai_siem.models import (
    AlertBatch,
    AlertStats,
    EnrichedAlert,
    SIEMConfig,
)
from ai_siem.parser import AlertParser, create_parser

logger = logging.getLogger(__name__)


class SIEMPipeline:
    """Main SIEM pipeline for processing and enriching alerts."""

    def __init__(self, config: SIEMConfig | None = None) -> None:
        """Initialize the pipeline.

        Args:
            config: SIEM configuration
        """
        self.config = config or SIEMConfig(enable_mock_mode=True)
        self.mock_mode = self.config.enable_mock_mode

        self.parser: AlertParser = create_parser(self.config)
        self.cache: AlertCache = create_cache(self.config)
        self.enricher: AlertEnricher = create_enricher(self.config)

        self._stats = AlertStats()

    def process_file(self, file_path: str | None = None) -> AlertBatch:
        """Process a Wazuh alerts file.

        Args:
            file_path: Path to alerts file (uses config default if None)

        Returns:
            Batch of processed alerts
        """
        file_path = file_path or self.config.wazuh_alerts_path
        start_time = time.time()

        batch = AlertBatch(batch_id=f"batch-{datetime.now().timestamp()}")
        alerts = []

        for wazuh_alert in self.parser.parse_file(file_path):
            batch.total_count += 1

            # Check for duplicates
            alert_hash = self.parser.compute_hash(wazuh_alert)
            if self.cache.is_duplicate(alert_hash):
                self.cache.increment_count(alert_hash)
                continue

            # Mark as seen
            self.cache.mark_seen(alert_hash)

            # Convert to enriched alert
            alert = self.parser.to_enriched_alert(wazuh_alert)

            # Enrich with AI
            try:
                alert = self.enricher.enrich(alert)
                batch.enriched_count += 1
            except Exception as e:
                message = f"Pipeline enrichment failed for alert {alert.alert_id}: {e}"
                logger.warning(message)
                alert.enrichment_source = "pipeline_fallback"
                alert.enrichment_status = "fallback"
                alert.enrichment_error = message
                alert.warnings.append(message)
                batch.warnings.append(message)
                batch.error_count += 1

            # Store in cache
            if not self.cache.store_enriched(alert):
                message = f"Cache storage degraded for alert {alert.alert_id}: {alert.cache_error}"
                batch.warnings.append(message)
            alerts.append(alert)

            # Batch size limit
            if len(alerts) >= self.config.batch_size:
                break

        batch.alerts = alerts
        batch.processed_at = datetime.now()
        batch.warning_count = sum(1 for alert in alerts if alert.warnings) + len(batch.warnings)

        # Update stats
        self._update_stats(batch, time.time() - start_time)

        return batch

    def process_stream(self, file_path: str | None = None) -> Iterator[EnrichedAlert]:
        """Process alerts in streaming mode.

        Args:
            file_path: Path to alerts file (uses config default if None)

        Yields:
            Enriched alerts as they are processed
        """
        file_path = file_path or self.config.wazuh_alerts_path

        for wazuh_alert in self.parser.tail_file(file_path):
            # Check for duplicates
            alert_hash = self.parser.compute_hash(wazuh_alert)
            if self.cache.is_duplicate(alert_hash):
                self.cache.increment_count(alert_hash)
                continue

            # Mark as seen
            self.cache.mark_seen(alert_hash)

            # Convert and enrich
            alert = self.parser.to_enriched_alert(wazuh_alert)

            try:
                alert = self.enricher.enrich(alert)
            except Exception as e:
                message = f"Pipeline enrichment failed for alert {alert.alert_id}: {e}"
                logger.warning(message)
                alert.enrichment_source = "pipeline_fallback"
                alert.enrichment_status = "fallback"
                alert.enrichment_error = message
                alert.warnings.append(message)

            # Store
            if not self.cache.store_enriched(alert):
                logger.warning(
                    "Cache storage degraded for alert %s: %s", alert.alert_id, alert.cache_error
                )

            yield alert

    def get_recent_alerts(
        self, limit: int = 100, severity: str | None = None
    ) -> list[EnrichedAlert]:
        """Get recent enriched alerts.

        Args:
            limit: Maximum number of alerts
            severity: Optional severity filter

        Returns:
            List of recent alerts
        """
        return self.cache.get_recent_alerts(limit, severity)

    def get_alert(self, alert_id: str) -> EnrichedAlert | None:
        """Get a specific alert by ID.

        Args:
            alert_id: Alert ID

        Returns:
            EnrichedAlert or None
        """
        return self.cache.get_enriched(alert_id)

    def get_stats(self) -> AlertStats:
        """Get processing statistics.

        Returns:
            AlertStats object
        """
        return self._stats

    def analyze_alert(self, alert_id: str) -> dict:
        """Perform deep analysis on an alert.

        Args:
            alert_id: Alert ID

        Returns:
            Analysis results
        """
        alert = self.get_alert(alert_id)
        if not alert:
            return {"error": "Alert not found"}

        return self.enricher.analyze_threat(alert)

    def clear_cache(self) -> bool:
        """Clear the alert cache.

        Returns:
            True if successful
        """
        return self.cache.clear()

    def _update_stats(self, batch: AlertBatch, duration: float) -> None:
        """Update processing statistics."""
        self._stats.total_alerts += batch.total_count
        self._stats.processing_time_ms = duration * 1000

        for alert in batch.alerts:
            severity = alert.severity.value
            self._stats.alerts_by_severity[severity] = (
                self._stats.alerts_by_severity.get(severity, 0) + 1
            )

            for mapping in alert.mitre_mappings:
                tactic = mapping.tactic
                self._stats.alerts_by_tactic[tactic] = (
                    self._stats.alerts_by_tactic.get(tactic, 0) + 1
                )

        if batch.alerts:
            total_risk = sum(a.risk_score for a in batch.alerts)
            self._stats.avg_risk_score = total_risk / len(batch.alerts)

    def cleanup(self) -> None:
        """Clean up resources."""
        self.cache.close()


def create_pipeline(config: SIEMConfig | None = None) -> SIEMPipeline:
    """Create a SIEMPipeline instance.

    Args:
        config: Optional SIEM configuration

    Returns:
        SIEMPipeline instance
    """
    return SIEMPipeline(config)
