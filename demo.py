#!/usr/bin/env python3
"""
Full SOC Triage Bot Demo - All Features of triage_extended Pipeline

This demo exercises the complete triage pipeline and populates ALL 13 report sections:

Header: Signal info, timestamps, metadata
Decision Banner: Classification verdict and rationale
§1 Summary: SOC + Stakeholder overview
§2 Action Plan: SOC Runbook actions (recommendations)
§3 Normalized Signal Context: Entities, indicators, CVEs
§4 Correlation & Scope: Local sightings, scope assessment
§5 Threat Intelligence: TI enrichment per indicator
§6 Exposure & Vulnerability: Asset context, host vulns, environment exposure
§7 Trend & Forecast: Multi-track ETS (Rule/IOC/Entity tracks)
§8 Evidence Timeline: Correlated events
§9 Triage Assessment: Disposition reasoning, MITRE mapping
§10 Similar Cases: Historical cases with SOAR artifacts
§11 Closure Criteria: TP/FP decision guidance
§12 Stakeholder Snapshot: Executive summary
§13 Data Quality & Gaps: Data gaps and assumptions
Appendix: Raw payload

"""

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

from soc_triage_bot.models import Signal, SignalSource, SignalType
from soc_triage_bot.models.ai_overlay import (
    AINextCheck,
    AIOverlay,
    AISimilarCaseNarrative,
    AIStatement,
    AITrackInterpretation,
    StatementType,
    TPFPLikelihood,
)
from soc_triage_bot.models.signal import (
    ArtifactContext,
    DetectionContext,
    EntityBehaviorContext,
    VulnerabilityContext,
)
from soc_triage_bot.models.triage_report import (
    AssetContext,
    AttachmentMetadata,
    ClassificationResult,
    EnrichmentBundle,
    EnrichmentNotes,
    EntityFocus,
    EnvironmentExposure,
    ExecutiveSummary,
    ForecastBacktest,
    ForecastBundle,
    ForecastHorizonMetrics,
    ForecastHorizonResult,
    ForecastHorizonThresholds,
    ForecastLatest,
    ForecastModelMeta,
    ForecastSeasonality,
    ForecastSeriesMeta,
    ForecastTrack,
    ForecastTracks,
    HostContext,
    HostVulnerability,
    LocalSighting,
    MitreMapping,
    NormalizedSignal,
    Recommendation,
    RelatedEvent,
    ReportMeta,
    RunbookRef,
    ScopeAssessment,
    SignalContext,
    SimilarCase,
    ThreatIntelEntry,
    TriageReport,
    UserContext,
)
from soc_triage_bot.services.report import ReportService


def create_sample_signal() -> Signal:
    """Create a realistic sample signal with all context fields."""
    return Signal(
        signal_id="DEMO-2024-001",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(  # type: ignore[call-arg]
            system="Splunk",
            rule_id="RULE-PS-ENCODED-001",
            rule_name="Suspicious PowerShell Encoded Command",
        ),
        title="PowerShell with Base64 Encoded Command Detected",
        description=(
            "A PowerShell process was observed executing with a base64 encoded "
            "command line argument. This technique is commonly used by attackers "
            "to obfuscate malicious commands and evade detection."
        ),
        severity="high",
        entities={
            "hostname": ["WORKSTATION-042"],
            "username": ["jsmith"],
            "ip": ["192.168.1.42", "10.0.0.5"],
            "process": ["powershell.exe"],
            "domain": ["suspicious-domain.com"],
        },
        tags=["malware", "powershell", "execution", "T1059.001"],
        raw_data={
            "command_line": "powershell.exe -enc SQBFAFgA...",
            "parent_process": "explorer.exe",
            "file_hash": "abc123def456789012345678901234567890abcdef",
            "process_id": 1234,
            "user_sid": "S-1-5-21-123456789-1234567890-123456789-1001",
            "event_id": 4688,
            "logon_type": 10,
        },
        # Track A: Detection context
        detection_context=DetectionContext(  # type: ignore[call-arg]
            rule_id="RULE-PS-ENCODED-001",
            rule_name="Suspicious PowerShell Encoded Command",
            analytic_family="Execution",
            detection_name="Encoded PowerShell",
        ),
        # Track B: Artifact/IOC context
        artifact_context=ArtifactContext(
            domain="suspicious-domain.com",
            process_name="powershell.exe",
            cmdline_hash="abc123",
        ),
        # Track C: Entity behavior context
        entity_context=EntityBehaviorContext(  # type: ignore[call-arg]
            hostname="WORKSTATION-042",
            username="jsmith",
            src_ip="192.168.1.42",
            dst_ip="10.0.0.5",
            primary_entity_type="hostname",
            primary_entity_value="WORKSTATION-042",
        ),
        # Vulnerability context
        vuln_context=VulnerabilityContext(cve="CVE-2024-1234"),  # type: ignore[call-arg]
    )


def create_full_triage_report(signal: Signal) -> TriageReport:
    """Create a TriageReport with all sections fully populated."""

    # =========================================================================
    # NORMALIZED SIGNAL (r.signal)
    # =========================================================================
    normalized_signal = NormalizedSignal(
        id=signal.signal_id,
        type=signal.signal_type.value.upper(),
        source=signal.source.system,
        name=signal.title,
        category="Execution / Defense Evasion",
        timestamp_utc=signal.timestamp.isoformat() + "Z" if signal.timestamp else "",
        raw=signal.raw_data or {},
    )

    # =========================================================================
    # REPORT METADATA (r.meta)
    # =========================================================================
    report_meta = ReportMeta(
        generated_utc=datetime.now(timezone.utc).isoformat() + "Z",
        triage_owner="Analyst Team Alpha",
        tool_version="2.0.0",
    )

    # =========================================================================
    # SIGNAL CONTEXT (r.ctx) - Section 3
    # =========================================================================
    signal_context = SignalContext(
        signal_subtype="SIEM_ALERT",
        entity_focus=EntityFocus(
            primary="hostname:WORKSTATION-042",
            secondary=["username:jsmith", "src_ip:192.168.1.42"],
        ),
        username="jsmith",
        hostname="WORKSTATION-042",
        src_ip="192.168.1.42",
        dst_ip="10.0.0.5",
        alert_rule="Suspicious PowerShell Encoded Command",
        alert_vendor="Splunk",
        indicators={
            "domain": "suspicious-domain.com",
            "ip": "10.0.0.5",
            "hash": "abc123def456789012345678901234567890abcdef",
            "process": "powershell.exe",
        },
        cves=["CVE-2024-1234", "CVE-2023-9876"],
    )

    # =========================================================================
    # CLASSIFICATION RESULT (r.classification) - Section 9
    # =========================================================================
    classification = ClassificationResult(
        disposition="TRUE_POSITIVE",
        tp_likelihood=0.87,
        severity="high",
        confidence="high",
        incident_type="Credential Theft / Lateral Movement",
        mitre=MitreMapping(
            tactics=["Execution", "Defense Evasion", "Credential Access"],
            techniques=["T1059.001", "T1027", "T1003.001", "T1055"],
        ),
        reasons_tp=[
            "IP 10.0.0.5 flagged malicious by 3 TI sources (VirusTotal, AbuseIPDB, OTX)",
            "Encoded PowerShell matches Cobalt Strike beacon signature",
            "Domain suspicious-domain.com registered within last 7 days",
            "Parent process explorer.exe spawning encoded powershell is anomalous",
            "ETS Track A shows 5x spike above historical baseline",
            "Similar case CASE-2024-0892 confirmed as Cobalt Strike compromise",
        ],
        reasons_fp=[
            "User jsmith is a developer with elevated privileges",
            "Host WORKSTATION-042 is a development workstation (may use encoded scripts)",
            "No confirmed data exfiltration observed yet",
        ],
        triage_judgment=(
            "High confidence TRUE POSITIVE based on multi-source TI matches, "
            "attack pattern consistency, and correlation with similar confirmed case. "
            "Immediate containment recommended."
        ),
        runbook_ref="RB-MAL-003 Malware/Cobalt Strike Response",
    )

    # =========================================================================
    # FORECAST BUNDLE (r.forecast) - Section 7
    # =========================================================================
    now = datetime.now(timezone.utc)
    history_start = (now - timedelta(days=7)).isoformat() + "Z"
    history_end = now.isoformat() + "Z"

    # Track A: Rule/Detection
    track_a = ForecastTrack(
        metric_key="rule:RULE-PS-ENCODED-001",
        metric_name="Encoded PowerShell Alerts (RULE-PS-ENCODED-001)",
        series_window="7d",
        history_points=168,
        series_meta=ForecastSeriesMeta(
            history_start_utc=history_start,
            history_end_utc=history_end,
            bucket_minutes=60,
            total_buckets=168,
            missing_buckets=2,
            missing_pct=1.2,
            data_completeness="COMPLETE",
        ),
        model_meta=ForecastModelMeta(
            ets_variant="ETS(A,Ad,N)",
            alpha=0.3,
            beta=0.1,
            damped=True,
        ),
        horizons={
            "H1": ForecastHorizonResult(total=4.2, lower=2.1, upper=6.8),
            "H6": ForecastHorizonResult(total=18.5, lower=12.3, upper=25.7),
            "H24": ForecastHorizonResult(total=65.2, lower=48.1, upper=85.9),
        },
        reliability="HIGH",
        interpretation="SPIKE - 5.2x above expected. Anomalous activity detected.",
        confidence="high",
        backtest=ForecastBacktest(
            status="ok",
            window_days=7,
            splits=5,
            step_buckets=24,
            metrics={
                "H1": ForecastHorizonMetrics(
                    smape=8.2, mase=0.65, rmse=1.2, coverage95=0.92
                ),
                "H6": ForecastHorizonMetrics(
                    smape=12.5, mase=0.78, rmse=3.4, coverage95=0.89
                ),
                "H24": ForecastHorizonMetrics(
                    smape=18.3, mase=0.92, rmse=8.7, coverage95=0.85
                ),
            },
            thresholds={
                "H1": ForecastHorizonThresholds(
                    spike_q=0.95,
                    drop_q=0.05,
                    spike_threshold_p95=8.5,
                    spike_threshold_p99=12.3,
                    drop_threshold_p05=0.5,
                ),
                "H6": ForecastHorizonThresholds(
                    spike_q=0.95,
                    drop_q=0.05,
                    spike_threshold_p95=35.2,
                    spike_threshold_p99=48.7,
                    drop_threshold_p05=3.2,
                ),
                "H24": ForecastHorizonThresholds(
                    spike_q=0.95,
                    drop_q=0.05,
                    spike_threshold_p95=95.0,
                    spike_threshold_p99=120.5,
                    drop_threshold_p05=15.8,
                ),
            },
            notes=[
                "Damped trend applied due to short history",
                "Weekday seasonality detected",
            ],
        ),
        latest=ForecastLatest(
            value=22.0,
            percentile=98.5,
            anomaly_score=0.92,
            current_vs_expected="5.2x above expected",
            current_bucket_count=22,
        ),
    )

    # Track B: IOC/Indicator
    track_b = ForecastTrack(
        metric_key="ioc:suspicious-domain.com",
        metric_name="Domain Sightings (suspicious-domain.com)",
        series_window="7d",
        history_points=168,
        series_meta=ForecastSeriesMeta(
            history_start_utc=history_start,
            history_end_utc=history_end,
            bucket_minutes=60,
            total_buckets=168,
            missing_buckets=5,
            missing_pct=3.0,
            data_completeness="COMPLETE",
        ),
        model_meta=ForecastModelMeta(
            ets_variant="ETS(A,N,N)",
            alpha=0.25,
        ),
        horizons={
            "H1": ForecastHorizonResult(total=2.1, lower=0.8, upper=3.9),
            "H6": ForecastHorizonResult(total=8.4, lower=4.2, upper=13.5),
            "H24": ForecastHorizonResult(total=28.7, lower=18.3, upper=42.1),
        },
        reliability="MEDIUM",
        interpretation="ELEVATED - 2.8x above baseline. New indicator emerging.",
        confidence="medium",
        backtest=ForecastBacktest(
            status="ok",
            window_days=7,
            splits=3,
            step_buckets=24,
            metrics={
                "H1": ForecastHorizonMetrics(
                    smape=15.3, mase=0.88, rmse=1.8, coverage95=0.85
                ),
                "H6": ForecastHorizonMetrics(
                    smape=22.1, mase=1.02, rmse=4.2, coverage95=0.82
                ),
                "H24": ForecastHorizonMetrics(
                    smape=28.7, mase=1.15, rmse=9.5, coverage95=0.78
                ),
            },
            thresholds={
                "H1": ForecastHorizonThresholds(
                    spike_threshold_p95=5.2,
                    spike_threshold_p99=7.8,
                    drop_threshold_p05=0.2,
                ),
                "H6": ForecastHorizonThresholds(
                    spike_threshold_p95=18.5,
                    spike_threshold_p99=25.3,
                    drop_threshold_p05=1.5,
                ),
                "H24": ForecastHorizonThresholds(
                    spike_threshold_p95=55.0,
                    spike_threshold_p99=72.8,
                    drop_threshold_p05=8.2,
                ),
            },
            notes=["Limited history for IOC (first seen 5 days ago)"],
        ),
        latest=ForecastLatest(
            value=8.0,
            percentile=89.2,
            anomaly_score=0.72,
            current_vs_expected="2.8x above expected",
        ),
    )

    # Track C: Entity Behavior
    track_c = ForecastTrack(
        metric_key="entity:hostname:WORKSTATION-042",
        metric_name="Suspicious Executions (WORKSTATION-042)",
        series_window="7d",
        history_points=168,
        series_meta=ForecastSeriesMeta(
            history_start_utc=history_start,
            history_end_utc=history_end,
            bucket_minutes=60,
            total_buckets=168,
            missing_buckets=0,
            missing_pct=0.0,
            data_completeness="COMPLETE",
        ),
        model_meta=ForecastModelMeta(
            ets_variant="ETS(A,Ad,A)",
            alpha=0.35,
            beta=0.08,
            gamma=0.15,
            seasonal_period=24,
            damped=True,
        ),
        horizons={
            "H1": ForecastHorizonResult(total=3.8, lower=1.5, upper=6.2),
            "H6": ForecastHorizonResult(total=15.2, lower=9.8, upper=21.5),
            "H24": ForecastHorizonResult(total=52.8, lower=38.2, upper=70.5),
        },
        reliability="HIGH",
        interpretation="SPIKE - 4.1x above expected. Entity anomaly detected.",
        confidence="high",
        backtest=ForecastBacktest(
            status="ok",
            window_days=7,
            splits=5,
            step_buckets=24,
            metrics={
                "H1": ForecastHorizonMetrics(
                    smape=6.8, mase=0.58, rmse=0.9, coverage95=0.94
                ),
                "H6": ForecastHorizonMetrics(
                    smape=10.2, mase=0.72, rmse=2.8, coverage95=0.91
                ),
                "H24": ForecastHorizonMetrics(
                    smape=14.5, mase=0.85, rmse=6.2, coverage95=0.88
                ),
            },
            thresholds={
                "H1": ForecastHorizonThresholds(
                    spike_threshold_p95=7.5,
                    spike_threshold_p99=10.2,
                    drop_threshold_p05=0.8,
                ),
                "H6": ForecastHorizonThresholds(
                    spike_threshold_p95=28.5,
                    spike_threshold_p99=38.2,
                    drop_threshold_p05=4.5,
                ),
                "H24": ForecastHorizonThresholds(
                    spike_threshold_p95=85.0,
                    spike_threshold_p99=105.2,
                    drop_threshold_p05=18.5,
                ),
            },
            notes=[
                "Daily seasonality detected (work hours pattern)",
                "Damped trend for stability",
            ],
        ),
        latest=ForecastLatest(
            value=18.0,
            percentile=97.2,
            anomaly_score=0.88,
            current_vs_expected="4.1x above expected",
        ),
    )

    forecast_bundle = ForecastBundle(
        enabled=True,
        bucket_minutes=60,
        seasonality=ForecastSeasonality(mode="auto", season_length_buckets=24),
        tracks=ForecastTracks(rule=track_a, ioc=track_b, entity=track_c),
    )

    # =========================================================================
    # ENRICHMENT BUNDLE (r.enrich) - Sections 4, 5, 6, 8
    # =========================================================================
    enrichment_bundle = EnrichmentBundle(
        # Section 4: Correlation summary
        correlation_summary=(
            "Alert correlates with 3 TI hits, 2 prior sightings of IOC, and 1 confirmed similar case. "
            "Scope appears limited to single host but lateral movement indicators present."
        ),
        # Section 4.1: Local sightings
        local_sightings=[
            LocalSighting(
                match_type="exact",
                where_seen="DNS logs",
                count=47,
                time_window="last 24h",
                notes="First seen 6 hours ago, accelerating pattern",
            ),
            LocalSighting(
                match_type="exact",
                where_seen="Proxy logs",
                count=23,
                time_window="last 24h",
                notes="HTTPS connections to suspicious-domain.com",
            ),
            LocalSighting(
                match_type="partial",
                where_seen="EDR telemetry",
                count=5,
                time_window="last 12h",
                notes="Related process hashes seen on 2 other hosts",
            ),
        ],
        # Section 4.2: Scope assessment
        scope=ScopeAssessment(
            impacted_hosts=["WORKSTATION-042", "WORKSTATION-089", "SERVER-DC01"],
            impacted_users=["jsmith", "admin_svc"],
            impacted_segments=["CORP-WORKSTATIONS", "CORP-SERVERS"],
            spread_assessment="limited",
        ),
        # Section 5: Threat intelligence per indicator
        threat_intel={
            "10.0.0.5": ThreatIntelEntry(
                type="ip",
                reputation="malicious",
                confidence="high",
                source="VirusTotal, AbuseIPDB, OTX",
                notes="Known C2 infrastructure, linked to APT29 campaigns",
            ),
            "suspicious-domain.com": ThreatIntelEntry(
                type="domain",
                reputation="malicious",
                confidence="high",
                source="VirusTotal, Mandiant",
                notes="Domain registered 5 days ago, DGA pattern detected",
            ),
            "abc123def456789012345678901234567890abcdef": ThreatIntelEntry(
                type="hash",
                reputation="malicious",
                confidence="medium",
                source="VirusTotal, Hybrid Analysis",
                notes="Identified as Cobalt Strike loader, 42/72 detections",
            ),
        },
        ti_summary=(
            "3/3 indicators flagged malicious with high confidence. "
            "Strong correlation with known APT29 infrastructure and Cobalt Strike tooling."
        ),
        # Section 6.1: Asset context
        asset_context=AssetContext(
            host=HostContext(
                hostname="WORKSTATION-042",
                os="Windows 11 Enterprise 23H2",
                criticality="medium",
                business_unit="Engineering",
                owner="John Smith",
                segment="CORP-WORKSTATIONS",
                business_process="Software Development",
                compliance="SOC2, GDPR (developer access)",
            ),
            user=UserContext(
                username="jsmith",
                role="Senior Developer",
                department="Engineering",
                risk_score=0.35,
            ),
        ),
        # Section 6.2: Host vulnerabilities
        host_vulns=[
            HostVulnerability(
                asset="WORKSTATION-042",
                cve="CVE-2024-1234",
                severity="high",
                exploited_in_the_wild=True,
                notes="PowerShell AMSI bypass, patch pending",
            ),
            HostVulnerability(
                asset="WORKSTATION-042",
                cve="CVE-2023-9876",
                severity="medium",
                exploited_in_the_wild=False,
                notes="Print spooler vulnerability, mitigated by policy",
            ),
        ],
        # Section 6.3: Environment exposure
        env_exposure=EnvironmentExposure(
            vulnerable_assets_count=127,
            highest_exposure_severity="high",
            known_exploited_exposure=True,
            summary="CVE-2024-1234 affects 127 Windows workstations; 15 are internet-facing",
            sample_assets=[
                "WORKSTATION-042",
                "WORKSTATION-089",
                "WORKSTATION-156",
                "LAPTOP-234",
            ],
        ),
        # Section 8: Related events timeline
        related_events=[
            RelatedEvent(
                timestamp_utc=(now - timedelta(hours=6, minutes=15)).isoformat() + "Z",
                source="DNS",
                summary="First DNS query to suspicious-domain.com from WORKSTATION-042",
                relevance="Initial contact with C2 infrastructure",
            ),
            RelatedEvent(
                timestamp_utc=(now - timedelta(hours=5, minutes=45)).isoformat() + "Z",
                source="Proxy",
                summary="HTTPS POST to suspicious-domain.com/beacon (4.2KB payload)",
                relevance="Likely Cobalt Strike beacon check-in",
            ),
            RelatedEvent(
                timestamp_utc=(now - timedelta(hours=4, minutes=30)).isoformat() + "Z",
                source="EDR",
                summary="explorer.exe spawned powershell.exe with encoded args",
                relevance="Primary detection event (this alert)",
            ),
            RelatedEvent(
                timestamp_utc=(now - timedelta(hours=3, minutes=15)).isoformat() + "Z",
                source="EDR",
                summary="powershell.exe accessed lsass.exe memory (Mimikatz pattern)",
                relevance="Credential dumping attempt detected",
            ),
            RelatedEvent(
                timestamp_utc=(now - timedelta(hours=2, minutes=45)).isoformat() + "Z",
                source="AD",
                summary="jsmith account used for RDP to SERVER-DC01 (unusual)",
                relevance="Potential lateral movement attempt",
            ),
            RelatedEvent(
                timestamp_utc=(now - timedelta(hours=1, minutes=30)).isoformat() + "Z",
                source="Network",
                summary="SMB connection from WORKSTATION-042 to WORKSTATION-089",
                relevance="Lateral movement confirmed to additional host",
            ),
        ],
        timeline_interpretation=(
            "Clear attack chain: Initial C2 contact -> Beacon deployment -> Credential harvesting -> "
            "Lateral movement. Timeline shows 6-hour progression from initial compromise."
        ),
        # Section 13: Data quality notes
        notes=EnrichmentNotes(
            data_gaps=[
                "Cloud SaaS logs (M365, Okta) not yet integrated - user cloud activity unknown",
                "EDR telemetry for SERVER-DC01 delayed by 15 minutes",
                "Email gateway logs unavailable (phishing initial vector not confirmed)",
            ],
            assumptions=[
                "Assuming initial access via phishing based on pattern similarity to CASE-2024-0892",
                "Lateral movement scope may be underestimated pending full EDR sync",
                "User account not yet confirmed as compromised (could be legitimate + malware)",
            ],
        ),
    )

    # =========================================================================
    # SIMILAR CASES (r.similar_cases) - Section 10
    # =========================================================================
    similar_cases = [
        SimilarCase(
            case_id="CASE-2024-0892",
            created_at_utc=(now - timedelta(days=12)).isoformat() + "Z",
            disposition="TRUE_POSITIVE",
            overlap="Same IOC (suspicious-domain.com) + Cobalt Strike pattern + Credential dumping",
            actions_taken=[
                "Isolated affected hosts via EDR",
                "Reset credentials for compromised accounts",
                "Blocked IOCs at firewall and proxy",
                "Forensic image captured for investigation",
                "Engaged IR team for full compromise assessment",
            ],
            notes_summary=(
                "Confirmed Cobalt Strike compromise via phishing. Full remediation took 72 hours. "
                "Root cause: user clicked malicious attachment in spoofed HR email."
            ),
            similarity=0.92,
            signal_type="SIEM_ALERT",
            title="Encoded PowerShell with C2 Beacon Detected",
            outcome="TP",
            matched_entities=["domain:suspicious-domain.com", "technique:T1059.001"],
            notes="Very similar attack pattern. Runbook RB-MAL-003 was effective.",
            runbook_refs=[
                RunbookRef(
                    ref_id="RB-MAL-003",
                    ref_type="runbook",
                    source="soar",
                    title="Malware/Cobalt Strike Response Runbook",
                    url="https://wiki.example.com/runbooks/RB-MAL-003",
                    whitelisted=True,
                ),
                RunbookRef(
                    ref_id="PB-CONTAIN-001",
                    ref_type="playbook",
                    source="soar",
                    title="Host Containment Playbook",
                    url="https://wiki.example.com/playbooks/PB-CONTAIN-001",
                ),
            ],
            tasks_template_id="TMPL-COBALT-001",
            attachments_metadata=[
                AttachmentMetadata(
                    attachment_id="ATT-2024-0892-001",
                    filename="forensic_timeline.md",
                    content_type="text/markdown",
                    size_bytes=45678,
                    uploaded_at=(now - timedelta(days=10)).isoformat() + "Z",
                    is_playbook=False,
                ),
            ],
        ),
        SimilarCase(
            case_id="CASE-2024-0756",
            created_at_utc=(now - timedelta(days=28)).isoformat() + "Z",
            disposition="TRUE_POSITIVE",
            overlap="Cobalt Strike beacon + Lateral movement pattern",
            actions_taken=[
                "EDR containment of affected hosts",
                "Password reset for affected accounts",
                "IOC blocking across perimeter",
            ],
            notes_summary="Different domain but same TTP. Contained within 24 hours.",
            similarity=0.78,
            signal_type="EDR_DETECTION",
            title="Suspicious Process Injection Detected",
            outcome="TP",
            matched_entities=["technique:T1055", "technique:T1003.001"],
            runbook_refs=[
                RunbookRef(
                    ref_id="RB-MAL-003",
                    ref_type="runbook",
                    source="soar",
                    title="Malware/Cobalt Strike Response Runbook",
                ),
            ],
        ),
        SimilarCase(
            case_id="CASE-2024-0634",
            created_at_utc=(now - timedelta(days=45)).isoformat() + "Z",
            disposition="FALSE_POSITIVE",
            overlap="Encoded PowerShell + Developer workstation",
            actions_taken=[
                "Verified script was legitimate build tool",
                "Added exclusion to detection rule",
            ],
            notes_summary="Developer using encoded scripts for CI/CD. Added to allowlist.",
            similarity=0.65,
            signal_type="SIEM_ALERT",
            title="Encoded PowerShell on Developer Workstation",
            outcome="FP",
            matched_entities=[
                "hostname_type:developer_workstation",
                "technique:T1059.001",
            ],
            notes="Different context - legitimate automation. Good comparison for FP decision.",
        ),
    ]

    # =========================================================================
    # RECOMMENDATIONS (r.recommendations) - Section 2
    # =========================================================================
    recommendations = [
        Recommendation(
            priority=1,
            description="IMMEDIATE: Isolate WORKSTATION-042 via EDR network containment",
            owner_team="SOC",
            auto_executable=True,
            status="In Progress",
            rationale="Confirmed C2 activity and credential theft - prevent further lateral movement",
        ),
        Recommendation(
            priority=1,
            description="IMMEDIATE: Reset credentials for jsmith and admin_svc accounts",
            owner_team="IAM",
            auto_executable=False,
            status="Open",
            rationale="Mimikatz activity detected - assume credentials compromised",
        ),
        Recommendation(
            priority=2,
            description="Block IOCs (suspicious-domain.com, 10.0.0.5) at firewall and proxy",
            owner_team="NetSec",
            auto_executable=True,
            status="Open",
            rationale="Prevent C2 communication from other potentially affected hosts",
        ),
        Recommendation(
            priority=2,
            description="Investigate WORKSTATION-089 and SERVER-DC01 for compromise",
            owner_team="SOC",
            auto_executable=False,
            status="Open",
            rationale="Lateral movement indicators present - timeline shows SMB/RDP connections",
        ),
        Recommendation(
            priority=3,
            description="Capture forensic image of WORKSTATION-042 for IR investigation",
            owner_team="IR",
            auto_executable=False,
            status="Open",
            rationale="Preserve evidence for root cause analysis and potential legal action",
        ),
        Recommendation(
            priority=3,
            description="Review phishing logs for jsmith to identify initial access vector",
            owner_team="Email Security",
            auto_executable=False,
            status="Open",
            rationale="Similar case CASE-2024-0892 was phishing-originated",
        ),
        Recommendation(
            priority=4,
            description="Deploy CVE-2024-1234 patch to remaining 126 affected workstations",
            owner_team="IT Ops",
            auto_executable=False,
            status="Open",
            rationale="AMSI bypass vulnerability may have facilitated attack persistence",
        ),
    ]

    # =========================================================================
    # EXECUTIVE SUMMARY (r.exec) - Section 12
    # =========================================================================
    executive_summary = ExecutiveSummary(
        business_process="Software Development - Engineering Team",
        potential_impact=(
            "HIGH IMPACT: Credential theft detected on developer workstation with access to source code "
            "repositories and internal systems. Potential for IP theft, supply chain compromise, or "
            "further lateral movement to production systems."
        ),
        external_impact=(
            "POTENTIAL: If attacker gained access to source code or CI/CD pipelines, customer-facing "
            "products could be compromised. No evidence of this yet, but investigation ongoing."
        ),
        compliance_notes=(
            "SOC2/GDPR implications: Developer account has access to customer data processing systems. "
            "May require breach notification if data access confirmed. Legal and Privacy teams notified."
        ),
    )

    # =========================================================================
    # ASSEMBLE COMPLETE TRIAGE REPORT
    # =========================================================================
    return TriageReport(
        signal=normalized_signal,
        meta=report_meta,
        ctx=signal_context,
        classification=classification,
        forecast=forecast_bundle,
        enrich=enrichment_bundle,
        similar_cases=similar_cases,
        recommendations=recommendations,
        exec=executive_summary,
    )


def create_ai_overlay(signal: Signal) -> AIOverlay:
    """Create a fully populated AI overlay for demo purposes."""
    now = datetime.now(timezone.utc)

    return AIOverlay(
        model_version="GPT-4o (2024-12-14)",
        generation_timestamp=now.isoformat() + "Z",
        tp_fp_likelihood=TPFPLikelihood.LIKELY_TP,
        tp_fp_rationale=(
            "Multi-source TI correlation (3/3 indicators malicious), Cobalt Strike signature match, "
            "and timeline consistency with known attack chain strongly support TRUE POSITIVE disposition. "
            "Developer context is the only FP driver, but does not explain C2 communication or Mimikatz activity."
        ),
        executive_summary_statements=[
            AIStatement(
                text="Active Cobalt Strike compromise detected on engineering workstation with confirmed credential theft.",
                statement_type=StatementType.EVIDENCE_BACKED,
                evidence_ids=["E-001", "E-003", "E-004"],
            ),
            AIStatement(
                text="Attack chain shows 6-hour progression from initial C2 contact to lateral movement.",
                statement_type=StatementType.EVIDENCE_BACKED,
                evidence_ids=["E-002", "E-005"],
            ),
            AIStatement(
                text="Initial access was likely via phishing email, consistent with similar case CASE-2024-0892.",
                statement_type=StatementType.HYPOTHESIS,
                evidence_ids=["E-006"],
            ),
            AIStatement(
                text="Scope may extend beyond 3 identified hosts - additional lateral movement possible.",
                statement_type=StatementType.ASSUMPTION,
                evidence_ids=[],
            ),
        ],
        next_checks=[
            AINextCheck(
                query_template_id="QT-DNS-001",
                description="Find all hosts communicating with suspicious-domain.com",
                target_system="Splunk",
                parameters={
                    "domain": "suspicious-domain.com",
                    "timeframe": "-24h",
                    "source": "dns",
                },
            ),
            AINextCheck(
                query_template_id="QT-EDR-002",
                description="Find all hosts with Cobalt Strike hash",
                target_system="CrowdStrike",
                parameters={
                    "hash": "abc123def456789012345678901234567890abcdef",
                    "timeframe": "-7d",
                },
            ),
            AINextCheck(
                query_template_id="QT-AD-003",
                description="Review jsmith account activity for anomalous logins",
                target_system="Active Directory",
                parameters={
                    "username": "jsmith",
                    "timeframe": "-72h",
                    "event_types": "4624,4625,4648",
                },
            ),
        ],
        scope_interpretation=(
            "Current evidence suggests limited scope (3 hosts), but lateral movement timeline indicates "
            "attacker had 6 hours of access. SMB connections to additional hosts not yet fully investigated."
        ),
        correlation_insights=[
            "C2 domain first seen in environment 6 hours ago - suggests fresh campaign",
            "Beacon pattern matches known Cobalt Strike malleable C2 profile",
            "Credential dump followed by RDP to DC suggests privilege escalation attempt",
        ],
        tp_fp_evidence_citations=[
            "[E-001] IP 10.0.0.5 malicious in VirusTotal (48/92), AbuseIPDB (100% confidence), OTX (APT29 campaign)",
            "[E-002] Domain suspicious-domain.com registered 5 days ago via NameCheap, WHOIS privacy enabled",
            "[E-003] File hash matches Cobalt Strike loader (Hybrid Analysis, 42/72 detections)",
            "[E-004] Process injection pattern matches T1055 (MITRE ATT&CK)",
            "[E-005] lsass.exe memory access matches Mimikatz credential dumping (T1003.001)",
        ],
        enrichment_interpretation=(
            "All three indicators (IP, domain, hash) confirmed malicious across multiple TI sources. "
            "This is not a new/unknown threat - infrastructure is linked to known APT29 campaigns."
        ),
        exposure_interpretation=(
            "WORKSTATION-042 has CVE-2024-1234 (AMSI bypass) which may have allowed the encoded PowerShell "
            "to execute without detection. This vulnerability affects 127 other workstations in the environment."
        ),
        exploit_likelihood_assessment=(
            "HIGH: CVE-2024-1234 is actively exploited in the wild and present on affected host. "
            "Likely contributed to attack success."
        ),
        trend_interpretation=(
            "All three ETS tracks show significant spikes: Rule (5.2x), IOC (2.8x), Entity (4.1x). "
            "This multi-track anomaly pattern strongly correlates with active attack in progress."
        ),
        track_interpretations=[
            AITrackInterpretation(
                track_name="rule",
                interpretation="5.2x spike above baseline indicates rule is triggering on active attack, not noise",
                concerns=["May need to hunt for similar alerts in last 6 hours"],
                evidence_ids=["E-001"],
            ),
            AITrackInterpretation(
                track_name="ioc",
                interpretation="IOC sightings accelerating - 8 in last hour vs 0 yesterday",
                concerns=["New campaign targeting organization?"],
                evidence_ids=["E-002"],
            ),
            AITrackInterpretation(
                track_name="entity",
                interpretation="Host behavior highly anomalous - 4.1x above typical developer activity",
                concerns=["Other developer workstations may be targeted"],
                evidence_ids=["E-003"],
            ),
        ],
        trend_concerns=[
            "Triple-track spike pattern is rare and historically correlates with 95% TP rate",
            "IOC is new to environment - no baseline, so spike thresholds may be conservative",
        ],
        timeline_narrative=(
            "Attack timeline reconstructed from correlated events shows clear kill chain progression:\n\n"
            "1. **T-6h15m**: Initial C2 contact via DNS to suspicious-domain.com\n"
            "2. **T-5h45m**: Beacon check-in via HTTPS POST (4.2KB payload)\n"
            "3. **T-4h30m**: Encoded PowerShell spawned from explorer.exe (detection event)\n"
            "4. **T-3h15m**: Credential harvesting via Mimikatz (lsass access)\n"
            "5. **T-2h45m**: Lateral movement attempt to DC via RDP\n"
            "6. **T-1h30m**: Confirmed lateral movement to WORKSTATION-089 via SMB"
        ),
        attack_chain_hypothesis=(
            "Based on timeline and TTP analysis, this appears to be a standard APT compromise pattern:\n\n"
            "**Initial Access**: Likely phishing email (similar to CASE-2024-0892)\n"
            "**Execution**: Encoded PowerShell (T1059.001) exploiting AMSI bypass\n"
            "**Persistence**: Cobalt Strike beacon (checking in every 30 min)\n"
            "**Credential Access**: Mimikatz (T1003.001) for domain credential theft\n"
            "**Lateral Movement**: RDP/SMB to additional hosts\n\n"
            "**Current Stage**: Active lateral movement - attacker likely has domain admin or is attempting to obtain."
        ),
        scorecard_explanation=(
            "TP likelihood of 87% is driven by:\n"
            "- TI match score: +35% (3/3 indicators malicious, high confidence)\n"
            "- Attack pattern match: +25% (Cobalt Strike signature confirmed)\n"
            "- ETS anomaly: +15% (triple-track spike, 95th percentile)\n"
            "- Similar case match: +12% (92% similarity to confirmed TP)\n\n"
            "FP discount: -13% for developer context and elevated privileges baseline."
        ),
        scorecard_evidence_ids=["E-001", "E-002", "E-003", "E-004", "E-005", "E-006"],
        hypotheses=[
            "Initial access was via phishing email with malicious attachment (consistent with similar case)",
            "Attacker may have domain admin credentials - RDP to DC is concerning",
            "Additional hosts beyond the 3 identified may be compromised",
            "Data exfiltration may have occurred but not yet detected",
        ],
        decision_checklist=[
            "Confirm jsmith did not intentionally run the encoded PowerShell (interview user)",
            "Verify WORKSTATION-089 and SERVER-DC01 are not already compromised",
            "Check for data exfiltration indicators in proxy/DLP logs",
            "Confirm no unauthorized access to source code repositories",
            "Validate that C2 domain is not a legitimate CDN or research infrastructure",
        ],
        similar_case_narratives=[
            AISimilarCaseNarrative(
                case_id="CASE-2024-0892",
                similarity_score=0.92,
                shared_traits=[
                    "Same C2 domain (suspicious-domain.com)",
                    "Identical attack chain (phishing -> Cobalt Strike -> Mimikatz -> lateral)",
                    "Same MITRE techniques (T1059.001, T1055, T1003.001)",
                    "Similar host type (developer workstation)",
                ],
                resolution_summary=(
                    "Confirmed TRUE POSITIVE. Contained via EDR isolation, credentials reset, IOCs blocked. "
                    "Full remediation took 72 hours. Root cause was phishing email from spoofed HR sender."
                ),
                relevance_explanation=(
                    "This is likely the same campaign or actor. The identical C2 infrastructure and TTP overlap "
                    "suggest reuse of attack toolkit. Runbook RB-MAL-003 from this case should be followed."
                ),
            ),
            AISimilarCaseNarrative(
                case_id="CASE-2024-0756",
                similarity_score=0.78,
                shared_traits=[
                    "Cobalt Strike beacon activity",
                    "Lateral movement pattern",
                    "Credential access TTPs",
                ],
                resolution_summary=(
                    "TRUE POSITIVE confirmed. Different domain but same actor TTP. Contained within 24 hours."
                ),
                relevance_explanation=(
                    "Same threat actor tactics but different infrastructure. Confirms this TTP pattern is "
                    "consistently malicious in our environment."
                ),
            ),
        ],
        business_impact_summary=(
            "**CRITICAL BUSINESS RISK**\n\n"
            "A developer workstation with access to source code and internal systems has been compromised. "
            "Credential theft has occurred, and lateral movement to a domain controller was attempted.\n\n"
            "**Immediate Risks:**\n"
            "- Intellectual property theft (source code)\n"
            "- Supply chain compromise if CI/CD access is obtained\n"
            "- Domain-wide compromise if DC credentials were harvested\n\n"
            "**Recommended Executive Action:**\n"
            "Authorize immediate containment and IR engagement. Consider notifying legal/privacy teams "
            "given SOC2/GDPR implications."
        ),
        risk_communication=(
            "For non-technical stakeholders: An attacker has gained access to an employee's computer and "
            "stolen login credentials. They are now trying to access other computers and systems in our network. "
            "We are taking immediate action to stop them and assess what information they may have accessed."
        ),
        data_quality_observations=[
            "Email gateway logs unavailable - cannot confirm phishing as initial access vector",
            "Cloud SaaS (M365, Okta) logs not integrated - user cloud activity is a blind spot",
            "SERVER-DC01 EDR telemetry is delayed by 15 minutes - lateral movement scope may be incomplete",
        ],
        confidence_caveats=[
            "Initial access vector is hypothesized (phishing) but not confirmed",
            "Full lateral movement scope pending EDR sync completion",
            "No data exfiltration evidence yet, but investigation ongoing",
        ],
    )


async def run_demo():
    """Execute the full triage demo with all sections populated."""
    print("=" * 80)
    print("SOC Triage Bot - Full Pipeline Demo (All 13 Sections)")
    print("=" * 80)

    # Create signal
    print("\n[1/4] Creating sample signal with full context...")
    signal = create_sample_signal()
    print(f"   ✓ Signal ID: {signal.signal_id}")
    print(f"   ✓ Type: {signal.signal_type.value}")
    print(f"   ✓ Rule: {signal.source.rule_name}")

    # Create full triage report with all sections
    print("\n[2/4] Building complete TriageReport with all 13 sections...")
    triage_report = create_full_triage_report(signal)
    print("   ✓ r.signal (Normalized Signal)")
    print("   ✓ r.meta (Report Metadata)")
    print("   ✓ r.ctx (Signal Context) - Section 3")
    print("   ✓ r.classification - Sections 9, Decision Banner")
    print("   ✓ r.forecast (Multi-track ETS) - Section 7")
    print("   ✓ r.enrich.local_sightings - Section 4.1")
    print("   ✓ r.enrich.scope - Section 4.2")
    print("   ✓ r.enrich.threat_intel - Section 5")
    print("   ✓ r.enrich.asset_context - Section 6.1")
    print("   ✓ r.enrich.host_vulns - Section 6.2")
    print("   ✓ r.enrich.env_exposure - Section 6.3")
    print("   ✓ r.enrich.related_events - Section 8")
    print("   ✓ r.enrich.notes - Section 13")
    print("   ✓ r.similar_cases - Section 10")
    print("   ✓ r.recommendations - Section 2")
    print("   ✓ r.exec (Executive Summary) - Section 12")

    # Create AI overlay
    print("\n[3/4] Creating AI overlay for all sections...")
    ai_overlay = create_ai_overlay(signal)
    print("   ✓ Decision Banner AI assessment")
    print("   ✓ Section 1 AI executive summary")
    print("   ✓ Section 2 AI next checks")
    print("   ✓ Section 4 AI scope interpretation")
    print("   ✓ Section 5 AI evidence citations")
    print("   ✓ Section 6 AI exposure assessment")
    print("   ✓ Section 7 AI trend interpretation")
    print("   ✓ Section 8 AI timeline narrative")
    print("   ✓ Section 9 AI scorecard explanation")
    print("   ✓ Section 10 AI similar case narratives")
    print("   ✓ Section 12 AI business impact summary")
    print("   ✓ Section 13 AI data quality observations")

    # Generate report
    print("\n[4/4] Rendering full markdown report...")
    report_service = ReportService()
    report = report_service.generate_report(triage_report, ai_overlay)
    print(f"   ✓ Report generated: {len(report.splitlines())} lines")

    # Save outputs
    output_dir = Path(__file__).parent / "soc_triage_bot" / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = output_dir / f"demo_report_{signal.signal_id}.md"
    with open(report_path, "w") as f:
        f.write(report)

    # Save JSON summary
    json_path = output_dir / f"demo_result_{signal.signal_id}.json"
    summary = {
        "signal_id": signal.signal_id,
        "signal_type": signal.signal_type.value,
        "timestamp": signal.timestamp.isoformat() if signal.timestamp else None,
        "classification": {
            "disposition": triage_report.classification.disposition,
            "tp_likelihood": triage_report.classification.tp_likelihood,
            "severity": triage_report.classification.severity,
            "confidence": triage_report.classification.confidence,
        },
        "forecast": {
            "enabled": triage_report.forecast.enabled,
            "bucket_minutes": triage_report.forecast.bucket_minutes,
            "tracks": {
                "rule": (
                    triage_report.forecast.tracks.rule.interpretation
                    if triage_report.forecast.tracks.rule
                    else None
                ),
                "ioc": (
                    triage_report.forecast.tracks.ioc.interpretation
                    if triage_report.forecast.tracks.ioc
                    else None
                ),
                "entity": (
                    triage_report.forecast.tracks.entity.interpretation
                    if triage_report.forecast.tracks.entity
                    else None
                ),
            },
        },
        "similar_cases_count": len(triage_report.similar_cases),
        "recommendations_count": len(triage_report.recommendations),
        "ai_overlay": {
            "model_version": ai_overlay.model_version,
            "tp_fp_likelihood": (
                ai_overlay.tp_fp_likelihood.value
                if ai_overlay.tp_fp_likelihood
                else None
            ),
        },
    }
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    print("\n" + "=" * 80)
    print("Demo Complete!")
    print("=" * 80)
    print(f"\n✓ Markdown report saved to: {report_path}")
    print(f"✓ JSON summary saved to: {json_path}")

    # Print section summary
    print("\n--- Report Sections Populated ---")
    print("  ✓ Header: Signal info, timestamps")
    print("  ✓ Decision Banner: TRUE_POSITIVE @ 87% TP likelihood")
    print("  ✓ §1 Summary: SOC + Stakeholder overview")
    print("  ✓ §2 Action Plan: 7 recommendations with AI next checks")
    print("  ✓ §3 Normalized Context: Entities, indicators, CVEs")
    print("  ✓ §4 Correlation & Scope: 3 sightings, 3 hosts impacted")
    print("  ✓ §5 Threat Intelligence: 3 indicators with TI enrichment")
    print("  ✓ §6 Exposure: Asset context, 2 host vulns, env exposure")
    print("  ✓ §7 Trend & Forecast: 3 tracks (Rule/IOC/Entity) with full backtest")
    print("  ✓ §8 Timeline: 6 correlated events + AI attack chain")
    print("  ✓ §9 Assessment: 6 TP drivers, 3 FP drivers, MITRE mapping")
    print("  ✓ §10 Similar Cases: 3 cases with SOAR artifacts + AI narratives")
    print("  ✓ §11 Closure Criteria: TP/FP decision guidance")
    print("  ✓ §12 Stakeholder Snapshot: Executive summary")
    print("  ✓ §13 Data Quality: 3 data gaps, 3 assumptions")
    print("  ✓ Appendix: Raw signal payload")

    # Show full report
    print("\n" + "=" * 80)
    print("FULL TRIAGE REPORT")
    print("=" * 80)
    print(report)


if __name__ == "__main__":
    asyncio.run(run_demo())
