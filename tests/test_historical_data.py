"""Tests for historical data service and automatic fetching."""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from soc_triage_bot.adapters.mock_historical import MockHistoricalAdapter
from soc_triage_bot.models import Signal, SignalSource, SignalType
from soc_triage_bot.models.signal import (
    ArtifactContext,
    DetectionContext,
    EntityBehaviorContext,
)
from soc_triage_bot.services.historical_data import HistoricalDataService


@pytest.mark.asyncio
async def test_mock_historical_adapter():
    """Test that mock historical adapter generates realistic data."""
    adapter = MockHistoricalAdapter()
    
    assert adapter.name == "mock_historical"
    assert adapter.supports_historical_query() is True
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=7)
    
    result = await adapter.query_time_series(
        entity_key="rule_id",
        entity_value="TEST-001",
        metric_name="alert_count",
        start_time=start_time,
        end_time=end_time,
        bucket_minutes=60,
    )
    
    assert result is not None
    assert len(result.points) > 0
    assert result.entity_key == "rule_id"
    assert result.entity_value == "TEST-001"
    assert result.metric_name == "alert_count"
    
    # Check that values are realistic (non-negative)
    for point in result.points:
        assert point.value >= 0
    
    # Check that average is reasonable for base_rate=2.0 per hour
    avg_value = sum(p.value for p in result.points) / len(result.points)
    assert 0.5 < avg_value < 5.0  # Should be in a reasonable range


@pytest.mark.asyncio
async def test_historical_data_service_fetch():
    """Test that historical data service can fetch data for a signal."""
    # Create a test signal with all context
    signal = Signal(
        signal_id="test-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(
            system="test", rule_id="RULE-001", rule_name="Test Rule"
        ),
        title="Test Alert",
        description="Test description",
        severity="high",
        entities={"hostname": ["workstation-01"], "username": ["test-user"]},
        indicators={"domain": "evil.com"},
        detection_context=DetectionContext(rule_id="RULE-001", rule_name="Test Rule"),
        artifact_context=ArtifactContext(domain="evil.com"),
        entity_context=EntityBehaviorContext(
            hostname="workstation-01", username="test-user"
        ),
    )
    
    # Create service with mock adapter
    service = HistoricalDataService([MockHistoricalAdapter()])
    
    # Fetch data
    result = await service.fetch_for_signal(signal)
    
    assert result is not None
    
    # Should have at least Track A (rule_id) and Track B (domain)
    assert result.track_a is not None
    assert result.track_a.entity_key == "rule_id"
    assert result.track_a.entity_value == "RULE-001"
    assert len(result.track_a.values) > 0
    
    assert result.track_b is not None
    assert result.track_b.entity_key == "domain"
    assert result.track_b.entity_value == "evil.com"
    assert len(result.track_b.values) > 0


@pytest.mark.asyncio
async def test_historical_data_service_no_adapters():
    """Test that service handles no adapters gracefully."""
    signal = Signal(
        signal_id="test-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="test", rule_name="Test Rule"),
        title="Test Alert",
        description="Test description",
        severity="high",
    )
    
    # Create service with no adapters
    service = HistoricalDataService([])
    
    # Should return None
    result = await service.fetch_for_signal(signal)
    assert result is None


@pytest.mark.asyncio
async def test_historical_data_service_no_entity_match():
    """Test that service handles missing entities gracefully."""
    # Signal with no entities that match YAML config
    signal = Signal(
        signal_id="test-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(system="test", rule_name="Test Rule"),
        title="Test Alert",
        description="Test description",
        severity="high",
        entities={},  # Empty entities
    )
    
    service = HistoricalDataService([MockHistoricalAdapter()])
    
    # Should return None or minimal data
    result = await service.fetch_for_signal(signal)
    # Result could be None or have some tracks missing
    if result:
        # At least some tracks should be None if no entities match
        assert result.track_a is None or result.track_b is None or result.track_c is None
