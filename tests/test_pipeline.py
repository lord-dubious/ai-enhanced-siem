"""Tests for the SIEM pipeline."""


class FailingPipelineCache:
    """Cache test double that fails stores but keeps dedupe permissive."""

    def is_duplicate(self, alert_hash):
        return False

    def mark_seen(self, alert_hash):
        return None

    def store_enriched(self, alert):
        alert.cache_status = "degraded"
        alert.cache_error = "store failed during test"
        alert.warnings.append("Cache degraded: store failed during test")
        return False


class TestSIEMPipeline:
    """Tests for SIEMPipeline class."""

    def test_create_pipeline(self, mock_config):
        """Test creating a pipeline."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        assert pipeline is not None
        assert pipeline.mock_mode is True

    def test_create_pipeline_default(self):
        """Test creating pipeline with defaults."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline()
        assert pipeline is not None
        assert pipeline.mock_mode is True

    def test_process_file_mock(self, mock_config):
        """Test processing file in mock mode."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        batch = pipeline.process_file()

        assert batch is not None
        assert batch.total_count > 0
        assert len(batch.alerts) > 0

    def test_process_file_enrichment(self, mock_config):
        """Test alerts are enriched during processing."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        batch = pipeline.process_file()

        # Check alerts are enriched
        for alert in batch.alerts:
            assert alert.ai_summary != "" or alert.risk_score > 0

    def test_process_file_propagates_cache_warnings(self, mock_config):
        """Test cache degradation is visible on alerts and the batch."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        pipeline.cache = FailingPipelineCache()
        batch = pipeline.process_file()

        assert batch.warning_count > 0
        assert batch.warnings
        assert all(alert.cache_status == "degraded" for alert in batch.alerts)
        assert all(alert.warnings for alert in batch.alerts)

    def test_process_file_deduplication(self, mock_config):
        """Test duplicate alerts are filtered."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)

        # Process twice
        pipeline.process_file()
        batch2 = pipeline.process_file()

        # Second batch should have no alerts (all duplicates)
        assert len(batch2.alerts) == 0

    def test_get_recent_alerts(self, mock_config):
        """Test getting recent alerts."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        pipeline.process_file()

        alerts = pipeline.get_recent_alerts(limit=10)
        assert len(alerts) > 0

    def test_get_alert_by_id(self, mock_config):
        """Test getting specific alert."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        batch = pipeline.process_file()

        if batch.alerts:
            alert_id = batch.alerts[0].alert_id
            retrieved = pipeline.get_alert(alert_id)
            assert retrieved is not None
            assert retrieved.alert_id == alert_id

    def test_get_stats(self, mock_config):
        """Test getting statistics."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        pipeline.process_file()

        stats = pipeline.get_stats()
        assert stats.total_alerts > 0
        assert stats.processing_time_ms >= 0

    def test_analyze_alert(self, mock_config):
        """Test deep alert analysis."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        batch = pipeline.process_file()

        if batch.alerts:
            alert_id = batch.alerts[0].alert_id
            analysis = pipeline.analyze_alert(alert_id)
            assert "threat_type" in analysis

    def test_analyze_alert_not_found(self, mock_config):
        """Test analyzing non-existent alert."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        analysis = pipeline.analyze_alert("non-existent-id")
        assert "error" in analysis

    def test_clear_cache(self, mock_config):
        """Test clearing cache."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        pipeline.process_file()

        result = pipeline.clear_cache()
        assert result is True

    def test_cleanup(self, mock_config):
        """Test cleanup."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        pipeline.cleanup()
        # Should not raise


class TestPipelineComponents:
    """Tests for pipeline component integration."""

    def test_pipeline_has_parser(self, mock_config):
        """Test pipeline has parser."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        assert pipeline.parser is not None

    def test_pipeline_has_cache(self, mock_config):
        """Test pipeline has cache."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        assert pipeline.cache is not None

    def test_pipeline_has_enricher(self, mock_config):
        """Test pipeline has enricher."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        assert pipeline.enricher is not None


class TestStatsUpdates:
    """Tests for statistics updates."""

    def test_stats_severity_breakdown(self, mock_config):
        """Test severity breakdown in stats."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        pipeline.process_file()

        stats = pipeline.get_stats()
        assert len(stats.alerts_by_severity) > 0

    def test_stats_mitre_breakdown(self, mock_config):
        """Test MITRE tactic breakdown in stats."""
        from ai_siem.pipeline import create_pipeline

        pipeline = create_pipeline(mock_config)
        pipeline.process_file()

        stats = pipeline.get_stats()
        # May have MITRE mappings
        assert isinstance(stats.alerts_by_tactic, dict)
