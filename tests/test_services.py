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

    from soc_triage_bot.models import Signal, SignalSource, SignalType
    from soc_triage_bot.services.forecasting import (
        MultiTrackHistoricalData,
        TrackTimeSeries,
    )

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
    assert len(classification.reasons_tp) > 0 or len(classification.reasons_fp) > 0


def test_action_proposal_service(sample_signal):
    """Test action proposal generation."""
    from soc_triage_bot.models import (
        ClassificationLabel,
        ClassificationResult,
        EnrichmentResult,
        EnrichmentStatus,
    )

    service = ActionProposalService()

    classification = ClassificationResult(
        disposition="TRUE_POSITIVE",
        tp_likelihood=0.85,
        severity="high",
        confidence="high",
        reasons_tp=["Test"],
        reasons_fp=[],
    )

    enrichments = {
        "siem": EnrichmentResult(
            adapter="siem", status=EnrichmentStatus.SUCCESS, data={}
        )
    }

    actions = service.propose_actions(sample_signal, classification, enrichments)

    assert len(actions) > 0
    assert all(action.action_id for action in actions)


# =============================================================================
# EXTENDED MULTI-TRACK TESTS
# =============================================================================


def test_forecasting_service_with_multiple_tracks():
    """Test multi-track forecasting with all three tracks populated."""
    from datetime import datetime, timedelta

    from soc_triage_bot.models import Signal, SignalSource, SignalType
    from soc_triage_bot.services.forecasting import (
        MultiTrackHistoricalData,
        TrackTimeSeries,
    )

    service = ForecastingService()

    signal = Signal(
        signal_id="test-multi-track-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test", rule_id="rule-multi-001"),
        title="Multi-track Test Alert",
        description="Test with all tracks",
        severity="high",
        entities={"ip": ["192.0.2.100"], "hostname": ["multi-host"]},
    )

    now = datetime.utcnow()
    values = [float(i) for i in range(1, 30)]  # 29 data points
    timestamps = [now - timedelta(hours=i) for i in range(len(values), 0, -1)]

    # Track A: Detection/Rule
    track_a = TrackTimeSeries(
        track_name="rule",
        entity_key="rule_id",
        entity_value="rule-multi-001",
        metric_name="alert_count",
        timestamps=timestamps,
        values=values,
        bucket_minutes=60,
    )

    # Track B: IOC/Indicator
    track_b = TrackTimeSeries(
        track_name="ioc",
        entity_key="domain",
        entity_value="test-domain.com",
        metric_name="sighting_count",
        timestamps=timestamps,
        values=[v * 0.5 for v in values],  # Different pattern
        bucket_minutes=60,
    )

    # Track C: Entity behavior
    track_c = TrackTimeSeries(
        track_name="entity",
        entity_key="hostname",
        entity_value="multi-host",
        metric_name="event_count",
        timestamps=timestamps,
        values=[v * 1.2 for v in values],  # Different pattern
        bucket_minutes=60,
    )

    historical_data = MultiTrackHistoricalData(
        track_a=track_a,
        track_b=track_b,
        track_c=track_c
    )

    result = service.forecast_multi_track(signal, historical_data)

    assert result.enabled is True
    assert result.tracks is not None
    assert result.tracks.rule is not None
    assert result.tracks.ioc is not None
    assert result.tracks.entity is not None
    assert result.tracks.rule.history_points == len(values)
    assert result.tracks.ioc.history_points == len(values)
    assert result.tracks.entity.history_points == len(values)


def test_forecasting_service_insufficient_data():
    """Test forecasting with insufficient historical data."""
    from datetime import datetime, timedelta

    from soc_triage_bot.models import Signal, SignalSource, SignalType
    from soc_triage_bot.services.forecasting import (
        MultiTrackHistoricalData,
        TrackTimeSeries,
    )

    service = ForecastingService()

    signal = Signal(
        signal_id="test-insufficient-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test", rule_id="rule-short-001"),
        title="Short Data Test",
        description="Test with insufficient data",
        severity="medium",
        entities={"ip": ["192.0.2.101"]},
    )

    now = datetime.utcnow()
    values = [1.0, 2.0, 3.0]  # Only 3 points - insufficient
    timestamps = [now - timedelta(hours=i) for i in range(len(values), 0, -1)]

    track_a = TrackTimeSeries(
        track_name="rule",
        entity_key="rule_id",
        entity_value="rule-short-001",
        metric_name="alert_count",
        timestamps=timestamps,
        values=values,
        bucket_minutes=60,
    )

    historical_data = MultiTrackHistoricalData(track_a=track_a)
    result = service.forecast_multi_track(signal, historical_data)

    # With insufficient data, track should be None
    assert result.enabled is True
    assert result.tracks.rule is None


def test_similarity_service_extended_matching(sample_signal):
    """Test extended similarity matching with entity overlap."""
    case_db = [
        {
            "case_id": "case-ext-001",
            "title": "Similar Alert",
            "description": "Very similar test",
            "signal_type": "siem_alert",
            "tags": ["malware"],
            "entities": {"ip": ["192.0.2.100"], "hostname": ["test-host"]},
            "outcome": "TP",
            "actions_taken": ["Isolated host", "Blocked IP"],
        },
        {
            "case_id": "case-ext-002",
            "title": "Different Alert",
            "description": "Unrelated incident",
            "signal_type": "siem_alert",
            "tags": ["phishing"],
            "entities": {"ip": ["10.0.0.1"]},
            "outcome": "FP",
        }
    ]

    service = SimilarityService(case_database=case_db)

    # Test find_similar_extended
    similar_extended = service.find_similar_extended(sample_signal, top_k=2)

    assert len(similar_extended) <= 2
    # Should rank the matching IP case higher
    if len(similar_extended) > 0:
        assert similar_extended[0].case_id == "case-ext-001"


@pytest.mark.asyncio
async def test_triage_service_with_historical_data():
    """Test triage service with multi-track historical data."""
    from datetime import datetime, timedelta

    from soc_triage_bot.services.forecasting import (
        MultiTrackHistoricalData,
        TrackTimeSeries,
    )

    adapters = [SIEMAdapter(), EDRAdapter()]
    enrichment_service = EnrichmentService(adapters)
    triage_service = TriageService(enrichment_service=enrichment_service)

    signal = Signal(
        signal_id="test-triage-hist-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test", rule_id="rule-hist-001"),
        title="Triage with History Test",
        description="Testing triage with historical data",
        severity="high",
        entities={"ip": ["192.0.2.102"], "hostname": ["hist-test-host"]},
    )

    now = datetime.utcnow()
    values = [float(i) for i in range(1, 30)]
    timestamps = [now - timedelta(hours=i) for i in range(len(values), 0, -1)]

    track_a = TrackTimeSeries(
        track_name="rule",
        entity_key="rule_id",
        entity_value="rule-hist-001",
        metric_name="alert_count",
        timestamps=timestamps,
        values=values,
        bucket_minutes=60,
    )

    historical_data = MultiTrackHistoricalData(track_a=track_a)

    result = await triage_service.triage_extended(signal, historical_data)

    assert result.signal.signal_id == "test-triage-hist-001"
    assert result.classification is not None
    assert result.triage_report is not None
    assert result.forecast_bundle is not None
    assert result.forecast_bundle.enabled is True


def test_classification_service_with_forecast():
    """Test classification with forecast data influence."""
    from soc_triage_bot.models import EnrichmentResult, EnrichmentStatus
    from soc_triage_bot.models.triage_report import (
        ForecastBundle,
        ForecastLatest,
        ForecastTrack,
        ForecastTracks,
    )

    service = ClassificationService()

    signal = Signal(
        signal_id="test-class-forecast-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test"),
        title="Classification with Forecast",
        description="Test classification influenced by forecast",
        severity="high",
        entities={"ip": ["192.0.2.103"]},
    )

    enrichments = {
        "threat_intel": EnrichmentResult(
            adapter="threat_intel",
            status=EnrichmentStatus.SUCCESS,
            data={"reputation": "suspicious", "matches_found": 1},
        ),
        "siem": EnrichmentResult(
            adapter="siem",
            status=EnrichmentStatus.SUCCESS,
            data={"historical_fp_rate": 0.3},
        )
    }

    # Create a forecast bundle with anomaly
    forecast = ForecastBundle(
        enabled=True,
        bucket_minutes=60,
        tracks=ForecastTracks(
            rule=ForecastTrack(
                metric_key="rule:test-rule",
                metric_name="Test Rule Alerts",
                series_window="24h",
                history_points=24,
                horizons={},
                reliability="HIGH",
                interpretation="Elevated activity detected",
                latest=ForecastLatest(
                    value=15.0,
                    percentile=95.0,
                    anomaly_score=0.85,  # High anomaly score
                    current_vs_expected="3x above expected"
                )
            )
        )
    )

    classification = service.classify_extended(
        signal=signal,
        enrichments=enrichments,
        similar_cases=[],
        forecast=forecast
    )

    assert classification.disposition is not None
    assert 0 <= classification.tp_likelihood <= 1
    # High anomaly should contribute to TP likelihood
    assert len(classification.reasons_tp) > 0


def test_classification_service_high_fp_rate():
    """Test classification with high historical FP rate."""
    from soc_triage_bot.models import EnrichmentResult, EnrichmentStatus

    service = ClassificationService()

    signal = Signal(
        signal_id="test-class-fp-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test"),
        title="High FP Rate Test",
        description="Test with noisy rule",
        severity="medium",
        entities={"ip": ["192.0.2.104"]},
    )

    enrichments = {
        "threat_intel": EnrichmentResult(
            adapter="threat_intel",
            status=EnrichmentStatus.SUCCESS,
            data={"reputation": "clean", "matches_found": 0},
        ),
        "siem": EnrichmentResult(
            adapter="siem",
            status=EnrichmentStatus.SUCCESS,
            data={"historical_fp_rate": 0.85},  # Very high FP rate
        )
    }

    classification = service.classify_extended(
        signal=signal,
        enrichments=enrichments,
        similar_cases=[]
    )

    assert classification.disposition is not None
    # High FP rate should show in reasons_fp
    assert len(classification.reasons_fp) > 0


def test_similarity_service_with_soar_artifacts(sample_signal):
    """Test similarity service returns SOAR artifacts (runbook refs)."""
    case_db = [
        {
            "case_id": "case-soar-001",
            "title": "Similar Alert with SOAR",
            "description": "Case with runbook references",
            "signal_type": "siem_alert",
            "tags": ["malware"],
            "entities": {"ip": ["192.0.2.100"]},
            "outcome": "TP",
            "actions_taken": ["Followed RB-001"],
            "runbook_refs": [
                {"ref_id": "RB-001", "ref_type": "runbook", "source": "soar", "title": "Malware Response"}
            ]
        }
    ]

    service = SimilarityService(case_database=case_db)
    similar_cases = service.find_similar_as_models(sample_signal, top_k=1)

    if len(similar_cases) > 0:
        case = similar_cases[0]
        assert case.case_id == "case-soar-001"
        assert len(case.runbook_refs) > 0
        assert case.runbook_refs[0].ref_id == "RB-001"


def test_report_service_full_format():
    """Test ReportService generates full format report."""
    from soc_triage_bot.models.triage_report import (
        ClassificationResult,
        MitreMapping,
        NormalizedSignal,
        ReportMeta,
        TriageReport,
    )
    from soc_triage_bot.services.report import ReportService
    
    # Create minimal TriageReport
    signal = NormalizedSignal(
        id="test-001",
        type="SIEM_ALERT",
        source="Test SIEM",
        name="Test Alert",
        timestamp_utc="2025-12-21T00:00:00Z"
    )
    
    classification = ClassificationResult(
        disposition="TRUE_POSITIVE",
        tp_likelihood=0.85,
        severity="high",
        confidence="high",
        incident_type="Malware",
        mitre=MitreMapping(
            tactics=["Execution"],
            techniques=["T1059"]
        ),
        reasons_tp=["Suspicious behavior detected"],
        reasons_fp=[],
        triage_judgment="High confidence TP"
    )
    
    report = TriageReport(
        signal=signal,
        meta=ReportMeta(triage_owner="Test Analyst"),
        classification=classification
    )
    
    service = ReportService()
    markdown = service.generate_report(report, format="full")
    
    assert "SOC Triage Report" in markdown
    assert signal.id in markdown
    assert "Decision Banner" in markdown
    assert classification.disposition in markdown


def test_report_service_compact_format():
    """Test ReportService generates compact format report."""
    from soc_triage_bot.models.triage_report import (
        ClassificationResult,
        MitreMapping,
        NormalizedSignal,
        ReportMeta,
        Recommendation,
        TriageReport,
    )
    from soc_triage_bot.services.report import ReportService
    
    # Create minimal TriageReport with recommendations
    signal = NormalizedSignal(
        id="test-002",
        type="SIEM_ALERT",
        source="Test SIEM",
        name="Test Alert",
        timestamp_utc="2025-12-21T00:00:00Z"
    )
    
    classification = ClassificationResult(
        disposition="TRUE POSITIVE",
        tp_likelihood=0.92,
        severity="critical",
        confidence="high",
        incident_type="Credential Theft",
        mitre=MitreMapping(
            tactics=["Credential Access"],
            techniques=["T1003"]
        ),
        reasons_tp=["Known malicious IP", "Encoded PowerShell detected"],
        reasons_fp=[],
        triage_judgment="Critical TP - immediate action required"
    )
    
    recommendations = [
        Recommendation(
            priority=1,
            description="Isolate affected host immediately",
            owner_team="SOC",
            auto_executable=True
        ),
        Recommendation(
            priority=2,
            description="Reset user credentials",
            owner_team="IT",
            auto_executable=False
        )
    ]
    
    report = TriageReport(
        signal=signal,
        meta=ReportMeta(
            triage_owner="Test Analyst",
            status="OPEN",
            playbook_ref="RB-MAL-003"
        ),
        classification=classification,
        recommendations=recommendations
    )
    
    service = ReportService()
    markdown = service.generate_report(report, format="compact")
    
    # Check for compact template elements
    assert "TRUE POSITIVE" in markdown or "🔴" in markdown
    assert "Case Metadata" in markdown
    assert "What Happened" in markdown
    assert "Actions Required" in markdown
    assert "IOCs" in markdown
    assert "Why TRUE POSITIVE" in markdown or "Why TP" in markdown
    assert "Business Impact" in markdown
    assert "MITRE ATT&CK" in markdown
    assert "Closure Criteria" in markdown
    # Check that full report is included in collapsed section
    assert "Full Audit Report" in markdown
    assert "<details>" in markdown
    assert "</details>" in markdown


def test_report_meta_new_fields():
    """Test ReportMeta accepts new fields."""
    from soc_triage_bot.models.triage_report import ReportMeta
    
    meta = ReportMeta(
        triage_owner="Analyst1",
        status="IN_PROGRESS",
        closed_utc="2025-12-21T10:00:00Z",
        playbook_ref="RB-MAL-005"
    )
    
    assert meta.status == "IN_PROGRESS"
    assert meta.closed_utc == "2025-12-21T10:00:00Z"
    assert meta.playbook_ref == "RB-MAL-005"


def test_tuning_recommendation_model():
    """Test TuningRecommendation model."""
    from soc_triage_bot.models.triage_report import TuningRecommendation
    
    tuning = TuningRecommendation(
        action="Adjust detection threshold for rule XYZ",
        priority="P2",
        owner="Detection Engineering",
        ticket="DET-1234"
    )
    
    assert tuning.action == "Adjust detection threshold for rule XYZ"
    assert tuning.priority == "P2"
    assert tuning.owner == "Detection Engineering"
    assert tuning.ticket == "DET-1234"


def test_triage_report_with_tuning_and_lessons():
    """Test TriageReport with tuning and lessons_learned fields."""
    from soc_triage_bot.models.triage_report import (
        ClassificationResult,
        NormalizedSignal,
        TuningRecommendation,
        TriageReport,
    )
    
    signal = NormalizedSignal(
        id="test-003",
        type="SIEM_ALERT",
        source="Test SIEM",
        name="Test Alert"
    )
    
    classification = ClassificationResult(
        disposition="FALSE POSITIVE",
        tp_likelihood=0.15,
        severity="low",
        confidence="high",
        reasons_fp=["Known benign behavior", "Authorized admin activity"]
    )
    
    tuning = [
        TuningRecommendation(
            action="Exclude admin accounts from rule",
            priority="P2",
            owner="Detection Eng"
        )
    ]
    
    lessons = [
        "Admin accounts generate many FPs for this rule",
        "Need to add context for privileged accounts"
    ]
    
    report = TriageReport(
        signal=signal,
        classification=classification,
        tuning=tuning,
        lessons_learned=lessons
    )
    
    assert report.tuning is not None
    assert len(report.tuning) == 1
    assert report.tuning[0].action == "Exclude admin accounts from rule"
    assert report.lessons_learned is not None
    assert len(report.lessons_learned) == 2


def test_compact_report_with_fp_and_tuning():
    """Test compact report with FP case and tuning recommendations."""
    from soc_triage_bot.models.triage_report import (
        ClassificationResult,
        NormalizedSignal,
        ReportMeta,
        TuningRecommendation,
        TriageReport,
    )
    from soc_triage_bot.services.report import ReportService
    
    signal = NormalizedSignal(
        id="test-fp-001",
        type="SIEM_ALERT",
        source="Test SIEM",
        name="False Positive Test Alert",
        timestamp_utc="2025-12-21T00:00:00Z"
    )
    
    classification = ClassificationResult(
        disposition="FALSE POSITIVE",
        tp_likelihood=0.10,
        severity="low",
        confidence="high",
        reasons_fp=["Authorized maintenance activity", "User confirmed benign"],
        triage_judgment="Confirmed FP - requires tuning"
    )
    
    tuning = [
        TuningRecommendation(
            action="Add maintenance window exclusion",
            priority="P2",
            owner="Detection Eng",
            ticket="TUNE-456"
        )
    ]
    
    lessons = [
        "Maintenance windows should be excluded from detections",
        "Need better context for scheduled activities"
    ]
    
    report = TriageReport(
        signal=signal,
        meta=ReportMeta(
            triage_owner="FP Analyst",
            status="CLOSED",
            closed_utc="2025-12-21T05:00:00Z"
        ),
        classification=classification,
        tuning=tuning,
        lessons_learned=lessons
    )
    
    service = ReportService()
    markdown = service.generate_report(report, format="compact")
    
    # Check FP-specific elements
    assert "FALSE POSITIVE" in markdown or "🟢" in markdown
    assert "Tuning Recommendation" in markdown
    assert "Add maintenance window exclusion" in markdown
    assert "Lessons Learned" in markdown
    assert "NO ACTION REQUIRED" in markdown
    assert "CLOSED" in markdown
