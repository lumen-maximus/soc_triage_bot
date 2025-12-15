"""Tests for data models."""

from datetime import datetime

import pytest

from soc_triage_bot.models import (
    Action,
    ActionType,
    Classification,
    ClassificationLabel,
    EnrichmentResult,
    EnrichmentStatus,
    Signal,
    SignalSource,
    SignalType,
)


def test_signal_creation():
    """Test creating a signal."""
    signal = Signal(
        signal_id="test-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test_siem", rule_id="rule-001"),
        title="Test Alert",
        description="Test description",
        severity="high",
        entities={"ip": ["192.168.1.1"]},
        tags=["test"],
    )

    assert signal.signal_id == "test-001"
    assert signal.signal_type == SignalType.SIEM_ALERT
    assert signal.severity == "high"
    assert "ip" in signal.entities


def test_enrichment_result():
    """Test enrichment result model."""
    result = EnrichmentResult(
        adapter="test_adapter",
        status=EnrichmentStatus.SUCCESS,
        data={"key": "value"},
        duration_ms=100.5,
    )

    assert result.adapter == "test_adapter"
    assert result.status == EnrichmentStatus.SUCCESS
    assert result.data["key"] == "value"


def test_classification():
    """Test classification model."""
    classification = Classification(
        label=ClassificationLabel.TRUE_POSITIVE,
        confidence=0.85,
        reasoning=["Reason 1", "Reason 2"],
        factors={"threat_intel": 0.9},
        forecast_data=None,
    )

    assert classification.label == ClassificationLabel.TRUE_POSITIVE
    assert classification.confidence == 0.85
    assert len(classification.reasoning) == 2


def test_action():
    """Test action model."""
    action = Action(
        action_id="act-001",
        action_type=ActionType.ISOLATE,
        priority=1,
        title="Test Action",
        description="Test description",
        steps=["Step 1", "Step 2"],
        reasoning="Test reasoning",
        source="template",
        confidence=0.9,
    )

    assert action.action_id == "act-001"
    assert action.action_type == ActionType.ISOLATE
    assert action.priority == 1
    assert len(action.steps) == 2
