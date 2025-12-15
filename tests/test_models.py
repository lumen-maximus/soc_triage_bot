"""Tests for data models."""

from datetime import datetime

import pytest

from soc_triage_bot.models import (
    Action,
    ActionType,
    ClassificationLabel,
    ClassificationResult,
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


def test_classification_result():
    """Test ClassificationResult model."""
    from soc_triage_bot.models import ClassificationLabel, ClassificationResult

    classification = ClassificationResult(
        disposition="TRUE_POSITIVE",
        tp_likelihood=0.85,
        severity="high",
        confidence="high",
        reasons_tp=["Reason 1", "Reason 2"],
        reasons_fp=[],
    )

    assert classification.label == ClassificationLabel.TRUE_POSITIVE
    assert classification.confidence_score == 0.85
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


# =============================================================================
# TRIAGE REPORT MODEL TESTS
# =============================================================================


def test_classification_result_extended():
    """Test ClassificationResult model with extended fields."""
    from soc_triage_bot.models.triage_report import ClassificationResult, MitreMapping

    result = ClassificationResult(
        disposition="Likely True Positive",
        tp_likelihood=0.85,
        severity="high",
        confidence="high",
        reasons_tp=["Malicious IOC detected", "Critical asset involved"],
        reasons_fp=["Rule has some FP history"],
        mitre=MitreMapping(tactics=["TA0001"], techniques=["T1190"]),
        incident_type="Security Alert",
        triage_judgment="Recommend escalation to Tier 2",
    )

    assert result.disposition == "Likely True Positive"
    assert result.tp_likelihood == 0.85
    assert result.severity == "high"
    assert len(result.reasons_tp) == 2
    assert len(result.reasons_fp) == 1
    assert result.mitre.tactics == ["TA0001"]


def test_normalized_signal():
    """Test NormalizedSignal model."""
    from soc_triage_bot.models.triage_report import NormalizedSignal

    signal = NormalizedSignal(
        id="sig-001",
        type="SIEM_ALERT",
        source="splunk",
        name="Test Alert",
        category="Malware",
        timestamp_utc="2025-12-15T10:00:00Z",
        raw={"key": "value"},
    )

    assert signal.id == "sig-001"
    assert signal.type == "SIEM_ALERT"
    assert signal.source == "splunk"


def test_forecast_bundle():
    """Test ForecastBundle model."""
    from soc_triage_bot.models.triage_report import (
        ForecastBundle,
        ForecastLatest,
        ForecastSeasonality,
        ForecastTrack,
        ForecastTracks,
    )

    latest = ForecastLatest(
        value=15.0,
        percentile=95.0,
        anomaly_score=0.85,
        current_vs_expected="2x above expected",
    )

    track = ForecastTrack(
        metric_key="rule:test-rule",
        metric_name="Test Rule Alerts",
        series_window="24h",
        history_points=24,
        horizons={},
        reliability="HIGH",
        interpretation="Elevated activity",
        latest=latest,
    )

    bundle = ForecastBundle(
        enabled=True,
        bucket_minutes=60,
        seasonality=ForecastSeasonality(mode="auto"),
        tracks=ForecastTracks(rule=track),
    )

    assert bundle.enabled is True
    assert bundle.bucket_minutes == 60
    assert bundle.tracks.rule is not None
    assert bundle.tracks.rule.latest is not None
    assert bundle.tracks.rule.latest.anomaly_score == 0.85


def test_similar_case():
    """Test SimilarCase model."""
    from soc_triage_bot.models.triage_report import RunbookRef, SimilarCase

    runbook = RunbookRef(
        ref_id="RB-001",
        ref_type="runbook",
        source="soar",
        title="Malware Response",
        url="https://soar.example.com/runbooks/RB-001",
        whitelisted=False,
    )

    case = SimilarCase(
        case_id="case-001",
        similarity=0.92,
        signal_type="siem_alert",
        title="Similar Historical Case",
        outcome="TP",
        matched_entities=["hostname:server-01", "ip:192.0.2.100"],
        actions_taken=["Isolated host", "Blocked IP"],
        notes="Confirmed malware infection",
        runbook_refs=[runbook],
        tasks_template_id="TMPL-001",
    )

    assert case.case_id == "case-001"
    assert case.similarity == 0.92
    assert case.outcome == "TP"
    assert len(case.matched_entities) == 2
    assert len(case.runbook_refs) == 1
    assert case.runbook_refs[0].ref_id == "RB-001"


def test_recommendation():
    """Test Recommendation model."""
    from soc_triage_bot.models.triage_report import Recommendation

    rec = Recommendation(
        priority=1,
        description="Isolate affected host immediately",
        owner_team="SOC",
        auto_executable=True,
        status="Pending",
        rationale="Host is communicating with known C2 infrastructure",
    )

    assert rec.priority == 1
    assert rec.auto_executable is True
    assert rec.owner_team == "SOC"


def test_triage_report_full():
    """Test complete TriageReport model assembly."""
    from soc_triage_bot.models.triage_report import (
        ClassificationResult,
        EnrichmentBundle,
        ExecutiveSummary,
        ForecastBundle,
        NormalizedSignal,
        Recommendation,
        ReportMeta,
        SignalContext,
        SimilarCase,
        TriageReport,
    )

    signal = NormalizedSignal(
        id="sig-full-001",
        type="SIEM_ALERT",
        source="splunk",
        name="Full Test Alert",
        category="Malware",
        timestamp_utc="2025-12-15T10:00:00Z",
        raw={},
    )

    meta = ReportMeta(
        generated_utc="2025-12-15T10:05:00Z",
        triage_owner="Automated",
        tool_version="2.0.0",
    )

    ctx = SignalContext(
        signal_subtype="siem_alert",
        username="admin",
        hostname="workstation-01",
        src_ip="192.0.2.100",
        alert_rule="Suspicious PowerShell",
        alert_vendor="splunk",
    )

    classification = ClassificationResult(
        disposition="Likely True Positive",
        tp_likelihood=0.87,
        severity="high",
        confidence="high",
        reasons_tp=["Malicious indicators found"],
        reasons_fp=[],
        triage_judgment="Recommend escalation",
    )

    forecast = ForecastBundle(enabled=False)

    recommendations = [
        Recommendation(
            priority=1,
            description="Isolate host",
            owner_team="SOC",
            auto_executable=True,
            status="Pending",
        )
    ]

    report = TriageReport(
        signal=signal,
        meta=meta,
        ctx=ctx,
        classification=classification,
        forecast=forecast,
        enrich=EnrichmentBundle(),
        similar_cases=[],
        recommendations=recommendations,
    )

    assert report.signal.id == "sig-full-001"
    assert report.meta.tool_version == "2.0.0"
    assert report.classification.tp_likelihood == 0.87
    assert len(report.recommendations) == 1


def test_signal_track_helpers():
    """Test Signal model helper methods for track entity extraction."""
    from soc_triage_bot.models.signal import (
        ArtifactContext,
        DetectionContext,
        EntityBehaviorContext,
        Signal,
        SignalSource,
        SignalType,
    )

    signal = Signal(
        signal_id="test-helpers-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="test", rule_id="rule-helper-001"),
        title="Track Helper Test",
        description="Test track entity extraction",
        severity="high",
        entities={"ip": ["192.0.2.100"], "hostname": ["test-host"]},
        detection_context=DetectionContext(
            rule_id="DET-001", detection_name="Suspicious Activity"
        ),
        artifact_context=ArtifactContext(
            domain="test.example.com", ip="198.51.100.1", sha256="abc123def456"
        ),
        entity_context=EntityBehaviorContext(
            hostname="primary-host", username="testuser", src_ip="192.0.2.50"
        ),
    )

    # Test Track A key extraction
    track_a_key = signal.get_track_a_key()
    assert track_a_key == "DET-001"

    # Test Track B keys extraction
    track_b_keys = signal.get_track_b_keys()
    assert "domain" in track_b_keys
    assert "sha256" in track_b_keys
    assert track_b_keys["domain"] == "test.example.com"

    # Test Track C entity extraction
    track_c_entity = signal.get_track_c_entity()
    assert track_c_entity is not None
    assert track_c_entity[0] == "hostname"
    assert track_c_entity[1] == "primary-host"
    track_a_key = signal.get_track_a_key()
    assert track_a_key == "DET-001"

    # Test Track B keys extraction
    track_b_keys = signal.get_track_b_keys()
    assert "domain" in track_b_keys
    assert "sha256" in track_b_keys
    assert track_b_keys["domain"] == "test.example.com"

    # Test Track C entity extraction
    track_c_entity = signal.get_track_c_entity()
    assert track_c_entity is not None
    assert track_c_entity[0] == "hostname"
    assert track_c_entity[1] == "primary-host"
