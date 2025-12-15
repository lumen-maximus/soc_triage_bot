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
    """Test ETS forecasting."""
    service = ForecastingService()

    historical_data = [
        {"timestamp": "2025-12-01", "count": 5},
        {"timestamp": "2025-12-02", "count": 6},
        {"timestamp": "2025-12-03", "count": 15},
    ]

    result = service.forecast(historical_data, "siem_alert")

    assert result["forecast_available"] is True
    assert "forecast" in result
    assert "anomaly_score" in result


def test_similarity_service(sample_signal):
    """Test similar case retrieval."""
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
    similar_cases = service.find_similar(sample_signal, top_k=1)

    assert len(similar_cases) <= 1


@pytest.mark.asyncio
async def test_triage_service(sample_signal):
    """Test complete triage workflow."""
    adapters = [SIEMAdapter(), EDRAdapter()]
    enrichment_service = EnrichmentService(adapters)
    triage_service = TriageService(enrichment_service=enrichment_service)

    result = await triage_service.triage(sample_signal)

    assert result.signal.signal_id == "test-001"
    assert result.classification is not None
    assert len(result.actions) > 0
    assert result.report is not None
    assert result.duration_ms is not None


def test_classification_service(sample_signal):
    """Test classification."""
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

    classification = service.classify(
        signal=sample_signal, enrichments=enrichments, similar_cases=[]
    )

    assert classification.label is not None
    assert 0 <= classification.confidence <= 1
    assert len(classification.reasoning) > 0


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
