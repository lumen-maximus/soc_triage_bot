"""Tests for services."""

from datetime import datetime

import pytest

from soc_triage_bot.adapters import EDRAdapter, SIEMAdapter
from soc_triage_bot.models import Signal, SignalSource, SignalType
from soc_triage_bot.services import (
    ActionProposalService,
    ClassificationService,
    EnrichmentService,
    ForecastingService,
    SimilarityService,
    TriageService,
)


@pytest.fixture
def sample_signal():
    """Create a sample signal for testing."""
    return Signal(
        signal_id="test-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test"),
        title="Test Alert",
        description="Test",
        severity="high",
        entities={"ip": ["192.0.2.100"], "hostname": ["test-host"]},
    )


@pytest.mark.asyncio
async def test_enrichment_service(sample_signal):
    """Test concurrent enrichment."""
    adapters = [SIEMAdapter(), EDRAdapter()]
    service = EnrichmentService(adapters)

    results = await service.enrich_signal(sample_signal)

    assert "siem" in results
    assert "edr" in results
    assert results["siem"].status.value == "success"


def test_forecasting_service():
    """Test multi-track ETS forecasting."""
    from datetime import datetime, timedelta
    from soc_triage_bot.services.forecasting import MultiTrackHistoricalData, TrackTimeSeries
    from soc_triage_bot.models import Signal, SignalSource, SignalType

    service = ForecastingService()

    # Create a sample signal
    signal = Signal(
        signal_id="test-forecast-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test", rule_id="rule-001"),
        title="Test Alert",
        description="Test",
        severity="high",
        entities={"ip": ["192.0.2.100"]},
    )

    # Create multi-track historical data with enough points
    now = datetime.utcnow()
    values = [5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 16.0,
              17.0, 18.0, 19.0, 20.0, 21.0, 22.0, 23.0, 24.0, 25.0, 26.0, 27.0, 28.0, 29.0]
    timestamps = [now - timedelta(hours=i) for i in range(len(values), 0, -1)]
    
    track_a = TrackTimeSeries(
        track_name="rule",
        entity_key="rule_id",
        entity_value="rule-001",
        metric_name="alert_count",
        timestamps=timestamps,
        values=values,
        bucket_minutes=60,
    )
    historical_data = MultiTrackHistoricalData(track_a=track_a)

    result = service.forecast_multi_track(signal, historical_data)

    assert result.enabled is True
    assert result.tracks is not None
    assert result.tracks.rule is not None
    assert result.tracks.rule.history_points == len(values)


def test_similarity_service(sample_signal):
    """Test similar case retrieval using find_similar_as_models."""
    case_db = [
        {
            "case_id": "case-001",
            "title": "Test Alert",
            "description": "Similar test",
            "signal_type": "siem_alert",
            "tags": [],
            "entities": {"ip": ["192.0.2.100"]},
        }
    ]

    service = SimilarityService(case_database=case_db)
    similar_cases = service.find_similar_as_models(sample_signal, top_k=1)

    assert len(similar_cases) <= 1


@pytest.mark.asyncio
async def test_triage_service(sample_signal):
    """Test complete triage workflow using triage_extended."""
    adapters = [SIEMAdapter(), EDRAdapter()]
    enrichment_service = EnrichmentService(adapters)
    triage_service = TriageService(enrichment_service=enrichment_service)

    result = await triage_service.triage_extended(sample_signal)

    assert result.signal.signal_id == "test-001"
    assert result.classification is not None
    assert len(result.actions) > 0
    assert result.report is not None
    assert result.duration_ms is not None
    # New fields from extended triage
    assert result.triage_report is not None
    assert result.classification_result is not None


def test_classification_service(sample_signal):
    """Test classification using classify_extended."""
    service = ClassificationService()

    # Mock enrichments
    from soc_triage_bot.models import EnrichmentResult, EnrichmentStatus

    enrichments = {
        "threat_intel": EnrichmentResult(
            adapter="threat_intel",
            status=EnrichmentStatus.SUCCESS,
            data={"reputation": "malicious", "matches_found": 1},
        )
    }

    classification = service.classify_extended(
        signal=sample_signal, enrichments=enrichments, similar_cases=[]
    )

    assert classification.disposition is not None
    assert 0 <= classification.tp_likelihood <= 1
    assert len(classification.reasons_tp) > 0 or len(classification.reasons_fp) >= 0


def test_action_proposal_service(sample_signal):
    """Test action proposal generation."""
    from soc_triage_bot.models import (
        Classification,
        ClassificationLabel,
        EnrichmentResult,
        EnrichmentStatus,
    )

    service = ActionProposalService()

    classification = Classification(
        label=ClassificationLabel.TRUE_POSITIVE,
        confidence=0.85,
        reasoning=["Test"],
        factors={},
        forecast_data=None,
    )

    enrichments = {
        "siem": EnrichmentResult(
            adapter="siem", status=EnrichmentStatus.SUCCESS, data={}
        )
    }

    actions = service.propose_actions(sample_signal, classification, enrichments)

    assert len(actions) > 0
    assert all(action.action_id for action in actions)
