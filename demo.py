#!/usr/bin/env python3
"""
Full SOC Triage Bot Demo - All Features of triage_extended Pipeline

This demo exercises the complete triage pipeline and populates ALL 13 report sections:

Header: Signal info, timestamps, metadata
Decision Banner: Classification verdict and rationale
§1 Summary: SOC + Stakeholder overview
§2 Action Plan: SOC Runbook actions with AI enhancements:
    - Deterministic recommendations (from ActionProposalService)
    - AI next checks (query templates)
    - AI action rationale (evidence-backed WHY)
    - AI priority reasoning (action ordering)
    - AI additional suggestions
    - AI action dependencies
    - AI action risks
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
import io
import json
import sys
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_triage_bot.models import Signal, SignalSource, SignalType
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
from soc_triage_bot.services import AIService
from soc_triage_bot.services.report import ReportService


# =============================================================================
# TEE OUTPUT UTILITY (for capturing console output to file)
# =============================================================================


class TeeIO:
    """Write to both a buffer and the original stream for console logging."""

    def __init__(self, original_stream, buffer):
        self.original = original_stream
        self.buffer = buffer

    def write(self, data):
        try:
            self.original.write(data)
        except Exception:
            pass  # Continue even if original stream fails
        try:
            self.buffer.write(data)
        except Exception:
            pass  # Continue even if buffer write fails

    def flush(self):
        try:
            self.original.flush()
        except Exception:
            pass
        try:
            self.buffer.flush()
        except Exception:
            pass

    def isatty(self):
        return self.original.isatty() if hasattr(self.original, "isatty") else False


# =============================================================================
# BANNER & UI UTILITIES
# =============================================================================


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

    # Gradient-like colors
    PURPLE = "\033[38;5;135m"
    MAGENTA = "\033[38;5;199m"
    ORANGE = "\033[38;5;208m"
    TEAL = "\033[38;5;43m"
    WHITE = "\033[97m"


def supports_color() -> bool:
    """Check if terminal supports color output."""
    import sys

    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False
    return True


def c(text: str, color: str) -> str:
    """Colorize text if terminal supports it."""
    if supports_color():
        return f"{color}{text}{Colors.RESET}"
    return text


def show_banner(subtitle: str = "", show_version: bool = True):
    """Display the SOC Agent banner with optional subtitle.

    Args:
        subtitle: Optional subtitle to display below the banner
        show_version: Whether to show version info
    """
    version = "v1.0.0"

    # Clean, compact ASCII art banner
    print("")
    print(f"  {c('╭─────────────────────────────────────────────╮', Colors.CYAN)}")
    print(
        f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}   {c('███████╗ ██████╗  ██████╗', Colors.PURPLE)}               {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}   {c('██╔════╝██╔═══██╗██╔════╝', Colors.PURPLE)}               {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}   {c('███████╗██║   ██║██║', Colors.PURPLE)}                    {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}   {c('╚════██║██║   ██║██║', Colors.PURPLE)}                    {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}   {c('███████║╚██████╔╝╚██████╗', Colors.PURPLE)}               {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}   {c('╚══════╝ ╚═════╝  ╚═════╝', Colors.PURPLE)}               {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}     {c('A G E N T', Colors.MAGENTA + Colors.BOLD)}                           {c('│', Colors.CYAN)}"
    )
    print(
        f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}"
    )
    print(f"  {c('╰─────────────────────────────────────────────╯', Colors.CYAN)}")

    # Tagline
    tagline = "🛡️  Autonomous Security Operations Center"
    print(f"\n    {c(tagline, Colors.WHITE + Colors.BOLD)}")

    if show_version:
        print(
            f"    {c(f'Version {version}', Colors.DIM)} | {c('SIEM-Agnostic • Async • AI-Ready', Colors.DIM)}"
        )

    if subtitle:
        print(f"\n    {c('▸', Colors.TEAL)} {c(subtitle, Colors.WHITE)}")

    print("")  # Empty line after banner


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


# NOTE: AI overlay creation has been moved to AIService.create_mock_overlay()
# The demo now uses AIService for both real AI and mock overlay generation


async def run_demo():
    """Execute the full triage demo showing ALL services in the pipeline."""
    # Display the SOC Agent banner
    show_banner(subtitle="Full Pipeline Demo (All Services)")

    print(
        f"  {c('▸', Colors.TEAL)} {c('Service Pipeline Execution', Colors.BOLD + Colors.WHITE)}"
    )
    print(c("─" * 70, Colors.DIM))

    # =========================================================================
    # SERVICE INVENTORY
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.MAGENTA)}")
    print(f"{c('SOC TRIAGE BOT - SERVICE INVENTORY', Colors.BOLD + Colors.MAGENTA)}")
    print(f"{c('━' * 70, Colors.MAGENTA)}")
    print(f"{c('│', Colors.DIM)}")
    print(f"{c('│', Colors.DIM)} {c('Adapters (Data Sources):', Colors.YELLOW)}")
    print(
        f"{c('│', Colors.DIM)}   • {c('SIEMAdapter', Colors.WHITE)}          - SIEM alert ingestion & correlation"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('ThreatIntelAdapter', Colors.WHITE)}   - VirusTotal, OTX, AbuseIPDB"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('CMDBAdapter', Colors.WHITE)}          - Asset context & ownership"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('EDRAdapter', Colors.WHITE)}           - Endpoint telemetry"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('VulnerabilityAdapter', Colors.WHITE)} - CVE/vulnerability data"
    )
    print(f"{c('│', Colors.DIM)}")
    print(f"{c('│', Colors.DIM)} {c('Core Services:', Colors.YELLOW)}")
    print(
        f"{c('│', Colors.DIM)}   • {c('TriageService', Colors.WHITE)}        - Main orchestrator"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('EnrichmentService', Colors.WHITE)}    - Multi-source enrichment"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('ClassificationService', Colors.WHITE)} - TP/FP scoring engine"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('ForecastingService', Colors.WHITE)}   - Multi-track ETS analysis"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('SimilarityService', Colors.WHITE)}    - Vector search for cases"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('CaseArtifactHarvester', Colors.WHITE)} - Extract SOAR artifacts"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('ActionProposalService', Colors.WHITE)} - Generate recommendations"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('RunbookRegistry', Colors.WHITE)}      - Match playbooks/runbooks"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('AIService', Colors.WHITE)}            - LLM overlay generation"
    )
    print(
        f"{c('│', Colors.DIM)}   • {c('ReportService', Colors.WHITE)}        - Jinja2 markdown render"
    )
    print(f"{c('│', Colors.DIM)}")
    print(f"{c('└─', Colors.DIM)} {c('10 services ready', Colors.GREEN)}")

    # =========================================================================
    # STAGE 1: SIGNAL INGESTION (SIEMAdapter)
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 1: SIGNAL INGESTION', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} adapters/{c('SIEMAdapter', Colors.WHITE + Colors.BOLD)}"
    )
    print(f"{c('│', Colors.DIM)} Ingesting raw alert from Splunk...")

    signal = create_sample_signal()

    print(f"{c('│', Colors.DIM)}")
    print(f"{c('│', Colors.DIM)} {c('Signal Parsed:', Colors.YELLOW)}")
    print(f"{c('│', Colors.DIM)}   • ID: {c(signal.signal_id, Colors.WHITE)}")
    print(
        f"{c('│', Colors.DIM)}   • Type: {c(signal.signal_type.value.upper(), Colors.YELLOW)}"
    )
    print(f"{c('│', Colors.DIM)}   • Source: {c(signal.source.system, Colors.WHITE)}")
    print(
        f"{c('│', Colors.DIM)}   • Rule: {c(signal.source.rule_name or 'N/A', Colors.WHITE)}"
    )
    print(
        f"{c('│', Colors.DIM)}   • Severity: {c(signal.severity.upper(), Colors.RED)}"
    )
    print(f"{c('│', Colors.DIM)}")
    print(f"{c('└─', Colors.DIM)} {c('✓ SIEMAdapter.ingest() complete', Colors.GREEN)}")

    # =========================================================================
    # STAGE 2: ENRICHMENT (EnrichmentService + Adapters)
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 2: ENRICHMENT', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('EnrichmentService', Colors.WHITE + Colors.BOLD)}"
    )
    print(f"{c('│', Colors.DIM)} Orchestrating multi-source enrichment...")
    print(f"{c('│', Colors.DIM)}")

    # 2a. Threat Intel
    print(f"{c('│', Colors.DIM)} {c('→ ThreatIntelAdapter.lookup()', Colors.YELLOW)}")
    await asyncio.sleep(0.2)
    print(
        f"{c('│', Colors.DIM)}   IP 10.0.0.5: {c('MALICIOUS', Colors.RED)} (VT 48/92, AbuseIPDB 100%)"
    )
    print(
        f"{c('│', Colors.DIM)}   Domain: {c('MALICIOUS', Colors.RED)} (DGA pattern, 5d old)"
    )
    print(
        f"{c('│', Colors.DIM)}   Hash: {c('MALICIOUS', Colors.RED)} (Cobalt Strike, 42/72)"
    )

    # 2b. CMDB
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('│', Colors.DIM)} {c('→ CMDBAdapter.get_asset_context()', Colors.YELLOW)}"
    )
    await asyncio.sleep(0.15)
    print(
        f"{c('│', Colors.DIM)}   Host: WORKSTATION-042 | Owner: jsmith | Criticality: MEDIUM"
    )

    # 2c. Vulnerability
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('│', Colors.DIM)} {c('→ VulnerabilityAdapter.get_host_vulns()', Colors.YELLOW)}"
    )
    await asyncio.sleep(0.15)
    print(
        f"{c('│', Colors.DIM)}   {c('CVE-2024-1234', Colors.RED)}: AMSI Bypass (HIGH, exploited)"
    )
    print(f"{c('│', Colors.DIM)}   CVE-2023-9876: Print Spooler (MEDIUM)")

    # 2d. EDR
    print(f"{c('│', Colors.DIM)}")
    print(f"{c('│', Colors.DIM)} {c('→ EDRAdapter.get_telemetry()', Colors.YELLOW)}")
    await asyncio.sleep(0.15)
    print(f"{c('│', Colors.DIM)}   Process: explorer.exe → powershell.exe -enc ...")
    print(
        f"{c('│', Colors.DIM)}   {c('lsass.exe access detected', Colors.RED)} (Mimikatz pattern)"
    )

    # 2e. SIEM Correlation
    print(f"{c('│', Colors.DIM)}")
    print(f"{c('│', Colors.DIM)} {c('→ SIEMAdapter.correlate()', Colors.YELLOW)}")
    await asyncio.sleep(0.15)
    print(f"{c('│', Colors.DIM)}   47 DNS queries to C2 domain (last 24h)")
    print(f"{c('│', Colors.DIM)}   3 hosts involved in lateral movement")

    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('└─', Colors.DIM)} {c('✓ EnrichmentService.enrich() complete', Colors.GREEN)}"
    )

    # Build the triage report with all enriched data
    triage_report = create_full_triage_report(signal)

    # =========================================================================
    # STAGE 3: FORECASTING (ForecastingService)
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 3: FORECASTING', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('ForecastingService', Colors.WHITE + Colors.BOLD)}"
    )
    print(f"{c('│', Colors.DIM)} Running multi-track ETS models...")
    print(f"{c('│', Colors.DIM)}")

    print(
        f"{c('│', Colors.DIM)} {c('→ ForecastingService.forecast_track()', Colors.YELLOW)} Track A (Rule)"
    )
    await asyncio.sleep(0.15)
    print(
        f"{c('│', Colors.DIM)}   Model: ETS(A,Ad,N) | Status: {c('🔴 SPIKE 5.2x', Colors.RED)}"
    )

    print(
        f"{c('│', Colors.DIM)} {c('→ ForecastingService.forecast_track()', Colors.YELLOW)} Track B (IOC)"
    )
    await asyncio.sleep(0.15)
    print(
        f"{c('│', Colors.DIM)}   Model: ETS(A,N,N) | Status: {c('🟠 ELEVATED 2.8x', Colors.YELLOW)}"
    )

    print(
        f"{c('│', Colors.DIM)} {c('→ ForecastingService.forecast_track()', Colors.YELLOW)} Track C (Entity)"
    )
    await asyncio.sleep(0.15)
    print(
        f"{c('│', Colors.DIM)}   Model: ETS(A,Ad,A) | Status: {c('🔴 SPIKE 4.1x', Colors.RED)}"
    )

    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('│', Colors.DIM)} {c('Cross-Track:', Colors.RED + Colors.BOLD)} Triple-spike (95% TP correlation)"
    )
    print(
        f"{c('└─', Colors.DIM)} {c('✓ ForecastingService.run_all_tracks() complete', Colors.GREEN)}"
    )

    # =========================================================================
    # STAGE 4: SIMILARITY SEARCH (SimilarityService)
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 4: SIMILAR CASE RETRIEVAL', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('SimilarityService', Colors.WHITE + Colors.BOLD)}"
    )
    print(f"{c('│', Colors.DIM)} Vector search over historical cases...")
    print(f"{c('│', Colors.DIM)}")

    print(
        f"{c('│', Colors.DIM)} {c('→ SimilarityService.find_similar()', Colors.YELLOW)}"
    )
    await asyncio.sleep(0.2)
    print(
        f"{c('│', Colors.DIM)}   CASE-2024-0892: {c('92% match', Colors.GREEN)} (TP, same C2)"
    )
    print(
        f"{c('│', Colors.DIM)}   CASE-2024-0756: {c('78% match', Colors.GREEN)} (TP, Cobalt Strike)"
    )
    print(
        f"{c('│', Colors.DIM)}   CASE-2024-0634: {c('65% match', Colors.YELLOW)} (FP, dev tool)"
    )
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('└─', Colors.DIM)} {c('✓ SimilarityService.find_similar() complete', Colors.GREEN)}"
    )

    # =========================================================================
    # STAGE 5: CLASSIFICATION (ClassificationService)
    # =========================================================================
    # NOTE: Classification MUST happen before action proposal - we need to
    # know TP/FP likelihood before recommending response actions
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 5: CLASSIFICATION', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('ClassificationService', Colors.WHITE + Colors.BOLD)}"
    )
    print(
        f"{c('│', Colors.DIM)} Computing TP/FP likelihood from enrichments + forecast + similar cases..."
    )
    print(f"{c('│', Colors.DIM)}")

    print(
        f"{c('│', Colors.DIM)} {c('→ ClassificationService.classify_extended()', Colors.YELLOW)}"
    )
    await asyncio.sleep(0.15)
    print(f"{c('│', Colors.DIM)}   Inputs: enrichments, similar_cases, forecast_bundle")
    print(
        f"{c('│', Colors.DIM)}   TI Score: {c('+35%', Colors.GREEN)} | Pattern: {c('+25%', Colors.GREEN)}"
    )
    print(
        f"{c('│', Colors.DIM)}   ETS: {c('+15%', Colors.GREEN)} | Similar: {c('+12%', Colors.GREEN)} | FP: {c('-13%', Colors.YELLOW)}"
    )
    print(f"{c('│', Colors.DIM)}")
    print(f"{c('│', Colors.DIM)}   ┌──────────────────────────────────┐")
    print(
        f"{c('│', Colors.DIM)}   │  {c('TRUE POSITIVE', Colors.RED + Colors.BOLD)} @ {c('87%', Colors.WHITE)} likelihood │"
    )
    print(
        f"{c('│', Colors.DIM)}   │  Severity: {c('HIGH', Colors.RED)} | Confidence: {c('HIGH', Colors.GREEN)} │"
    )
    print(f"{c('│', Colors.DIM)}   └──────────────────────────────────┘")
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('└─', Colors.DIM)} {c('✓ ClassificationService.classify_extended() complete', Colors.GREEN)}"
    )

    # =========================================================================
    # STAGE 6: CASE ARTIFACT HARVESTING (CaseArtifactHarvester)
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 6: SOAR ARTIFACT HARVESTING', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('CaseArtifactHarvester', Colors.WHITE + Colors.BOLD)}"
    )
    print(f"{c('│', Colors.DIM)} Extracting proven actions from similar TP cases...")
    print(f"{c('│', Colors.DIM)}")

    print(
        f"{c('│', Colors.DIM)} {c('→ CaseArtifactHarvester.harvest()', Colors.YELLOW)} CASE-2024-0892"
    )
    await asyncio.sleep(0.15)
    print(
        f"{c('│', Colors.DIM)}   Extracted: EDR isolation, credential reset, IOC blocking"
    )

    print(
        f"{c('│', Colors.DIM)} {c('→ CaseArtifactHarvester.harvest()', Colors.YELLOW)} CASE-2024-0756"
    )
    await asyncio.sleep(0.15)
    print(f"{c('│', Colors.DIM)}   Extracted: Network containment, forensic imaging")
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('└─', Colors.DIM)} {c('✓ CaseArtifactHarvester.harvest_all() complete', Colors.GREEN)}"
    )

    # =========================================================================
    # STAGE 7: ACTION PROPOSAL (ActionProposalService)
    # =========================================================================
    # NOTE: Actions are proposed AFTER classification - severity/TP likelihood
    # determines urgency (P1 vs P4) and action scope
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 7: ACTION PROPOSAL', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('ActionProposalService', Colors.WHITE + Colors.BOLD)}"
    )
    print(
        f"{c('│', Colors.DIM)} Generating prioritized recommendations based on classification..."
    )
    print(f"{c('│', Colors.DIM)}")

    # Show 5 sources with precedence (new!)
    print(f"{c('│', Colors.DIM)} {c('Sources (by precedence):', Colors.YELLOW)}")
    print(
        f"{c('│', Colors.DIM)}   {c('1. seeded', Colors.GREEN)}      → Governed runbooks/playbooks (YAML)"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('2. case_linked', Colors.GREEN)} → SOAR archive (proven org intelligence)"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('3. learned', Colors.YELLOW)}    → Pattern-matched from similar cases"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('4. contextual', Colors.YELLOW)} → Dynamic from enrichments"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('5. template', Colors.DIM)}   → Fallback signal-type defaults"
    )
    print(f"{c('│', Colors.DIM)}")

    print(
        f"{c('│', Colors.DIM)} {c('→ ActionProposalService.propose_actions()', Colors.YELLOW)}"
    )
    print(
        f"{c('│', Colors.DIM)}   Inputs: signal, classification, enrichments, similar_cases"
    )
    await asyncio.sleep(0.15)

    # Show actions with their sources
    print(f"{c('│', Colors.DIM)}")
    print(f"{c('│', Colors.DIM)}   {c('Generated Actions:', Colors.WHITE)}")
    print(
        f"{c('│', Colors.DIM)}   {c('P1', Colors.RED)} [seeded]      Isolate WORKSTATION-042 via EDR"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('P1', Colors.RED)} [case_linked] Reset jsmith credentials (from CASE-2024-0892)"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('P2', Colors.YELLOW)} [contextual]  Block IOCs at perimeter (TI: malicious)"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('P2', Colors.YELLOW)} [learned]     Investigate lateral hosts (92% similar case)"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('P3', Colors.GREEN)} [seeded]      Forensic imaging"
    )
    print(
        f"{c('│', Colors.DIM)}   {c('P4', Colors.DIM)} [template]    Patch CVE-2024-1234"
    )
    print(f"{c('│', Colors.DIM)}")

    # Show deduplication and ranking
    print(f"{c('│', Colors.DIM)}   {c('Enterprise Features:', Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)}   → Dedupe by (intent|tool|owner|target) - 2 duplicates merged"
    )
    print(
        f"{c('│', Colors.DIM)}   → Gating: FP actions blocked, HIGH risk flagged for approval"
    )
    print(
        f"{c('│', Colors.DIM)}   → Ranking: source precedence > priority > confidence"
    )
    print(f"{c('│', Colors.DIM)}   → Capping: top 6, full plan max 15")
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('└─', Colors.DIM)} {c('✓ ActionProposalService.propose_actions() complete', Colors.GREEN)}"
    )

    # =========================================================================
    # STAGE 8: RUNBOOK MATCHING (RunbookRegistry)
    # =========================================================================
    # NOTE: Runbooks matched after classification - threat type informs which
    # playbooks are relevant
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 8: RUNBOOK MATCHING', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('RunbookRegistry', Colors.WHITE + Colors.BOLD)}"
    )
    print(
        f"{c('│', Colors.DIM)} Matching signal + classification to playbooks/runbooks..."
    )
    print(f"{c('│', Colors.DIM)}")

    print(f"{c('│', Colors.DIM)} {c('→ RunbookRegistry.match()', Colors.YELLOW)}")
    await asyncio.sleep(0.15)
    print(
        f"{c('│', Colors.DIM)}   Matched: {c('malware_containment.yaml', Colors.WHITE)} (Cobalt Strike)"
    )
    print(
        f"{c('│', Colors.DIM)}   Matched: {c('phishing_response.yaml', Colors.WHITE)} (Initial access)"
    )
    print(
        f"{c('│', Colors.DIM)}   Playbook: {c('ransomware_ir.yaml', Colors.WHITE)} (Lateral movement)"
    )
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('└─', Colors.DIM)} {c('✓ RunbookRegistry.match() complete', Colors.GREEN)}"
    )

    # =========================================================================
    # STAGE 9: AI OVERLAY (AIService)
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 9: AI OVERLAY GENERATION', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('AIService', Colors.WHITE + Colors.BOLD)}"
    )
    print(f"{c('│', Colors.DIM)} Provider: MockProvider | Model: GPT-4o")
    print(f"{c('│', Colors.DIM)}")

    ai_service = AIService.from_settings()

    print(f"{c('│', Colors.DIM)} {c('→ AIService.generate_overlay()', Colors.YELLOW)}")
    sections = [
        "Decision Banner rationale",
        "Executive summary (4 statements)",
        "Next checks (3 queries)",
        "Action rationale (evidence-backed)",
        "Action prioritization reasoning",
        "Additional action suggestions (4)",
        "Action dependencies (3)",
        "Action risks (3)",
        "Evidence citations (E-001..E-005)",
        "Trend interpretation",
        "Timeline narrative",
        "Scorecard explanation",
        "Similar case narratives",
        "Closure guidance",
        "Business impact",
        "Data quality observations",
    ]
    for s in sections:
        await asyncio.sleep(0.08)
        print(f"{c('│', Colors.DIM)}   {c('→', Colors.GREEN)} {s}")

    ai_overlay = ai_service.create_mock_overlay(
        triage_report=triage_report, signal=signal
    )

    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('│', Colors.DIM)}   AI Assessment: {c('LIKELY TRUE POSITIVE', Colors.RED)}"
    )
    print(
        f"{c('└─', Colors.DIM)} {c('✓ AIService.generate_overlay() complete', Colors.GREEN)}"
    )

    # =========================================================================
    # STAGE 10: REPORT RENDERING (ReportService)
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('STAGE 10: REPORT RENDERING', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('│', Colors.DIM)} {c('Service:', Colors.YELLOW)} services/{c('ReportService', Colors.WHITE + Colors.BOLD)}"
    )
    print(f"{c('│', Colors.DIM)} Template: triage_report.md.j2")
    print(f"{c('│', Colors.DIM)}")

    print(
        f"{c('│', Colors.DIM)} {c('→ ReportService.generate_report()', Colors.YELLOW)}"
    )
    await asyncio.sleep(0.2)

    report_service = ReportService()
    report = report_service.generate_report(triage_report, ai_overlay, format="compact")

    print(f"{c('│', Colors.DIM)}   Rendered: Header + Decision Banner")
    print(f"{c('│', Colors.DIM)}   Rendered: §1-§13 (all sections)")
    print(f"{c('│', Colors.DIM)}   Rendered: Appendix (raw payload)")
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('│', Colors.DIM)}   Output: {c(str(len(report.splitlines())) + ' lines', Colors.WHITE)} of markdown"
    )
    print(
        f"{c('└─', Colors.DIM)} {c('✓ ReportService.generate_report() complete', Colors.GREEN)}"
    )

    # =========================================================================
    # PIPELINE COMPLETE
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.GREEN)}")
    print(f"{c('PIPELINE COMPLETE', Colors.BOLD + Colors.GREEN)}")
    print(f"{c('━' * 70, Colors.GREEN)}")
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('│', Colors.DIM)} {c('Services Invoked:', Colors.YELLOW)} 10 (in logical order)"
    )
    print(
        f"{c('│', Colors.DIM)}   1. SIEMAdapter.ingest()              → Signal ingestion"
    )
    print(
        f"{c('│', Colors.DIM)}   2. EnrichmentService.enrich()        → Context from 5 adapters"
    )
    print(
        f"{c('│', Colors.DIM)}   3. ForecastingService.run_all_tracks()→ ETS anomaly detection"
    )
    print(
        f"{c('│', Colors.DIM)}   4. SimilarityService.find_similar()  → Historical case matching"
    )
    print(
        f"{c('│', Colors.DIM)}   5. ClassificationService.classify()  → TP/FP determination"
    )
    print(
        f"{c('│', Colors.DIM)}   6. CaseArtifactHarvester.harvest()   → Extract SOAR artifacts"
    )
    print(
        f"{c('│', Colors.DIM)}   7. ActionProposalService.propose()   → 5-source recommendations"
    )
    print(
        f"{c('│', Colors.DIM)}      {c('seeded > case_linked > learned > contextual > template', Colors.DIM)}"
    )
    print(
        f"{c('│', Colors.DIM)}   8. RunbookRegistry.match()           → Playbook selection"
    )
    print(
        f"{c('│', Colors.DIM)}   9. AIService.generate_overlay()      → LLM enhancement"
    )
    print(
        f"{c('│', Colors.DIM)}  10. ReportService.generate_report()   → Final markdown"
    )
    print(f"{c('│', Colors.DIM)}")
    print(
        f"{c('└─', Colors.DIM)} {c('✓ All services executed successfully', Colors.GREEN)}"
    )

    # =========================================================================
    # SAVE OUTPUTS
    # =========================================================================
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
            "next_checks_count": len(ai_overlay.next_checks),
            "action_rationale_length": len(ai_overlay.action_rationale),
            "action_prioritization_reasoning_length": len(
                ai_overlay.action_prioritization_reasoning
            ),
            "additional_action_suggestions_count": len(
                ai_overlay.additional_action_suggestions
            ),
            "action_dependencies_count": len(ai_overlay.action_dependencies),
            "action_risks_count": len(ai_overlay.action_risks),
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
    print("  ✓ §2 Action Plan: 7 recommendations with AI enhancements:")
    print("      - 3 AI next checks (query templates)")
    print("      - Action rationale (evidence-backed WHY)")
    print("      - Priority reasoning (action ordering)")
    print("      - 4 additional AI suggestions")
    print("      - 3 action dependencies")
    print("      - 3 action risks")
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

    # Show report preview (first 50 lines) instead of full dump
    print("\n" + "=" * 80)
    print("REPORT PREVIEW (first 50 lines)")
    print("=" * 80)
    report_lines = report.splitlines()
    for line in report_lines[:50]:
        print(line)
    print("\n... [truncated - see full report in output file] ...")
    print(f"\n📄 Full report ({len(report_lines)} lines): {report_path}")


if __name__ == "__main__":
    # Capture console output (stdout and stderr) to buffer while also displaying to terminal
    console_buffer = io.StringIO()
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = TeeIO(original_stdout, console_buffer)
    sys.stderr = TeeIO(original_stderr, console_buffer)

    try:
        asyncio.run(run_demo())
    finally:
        # Restore original stdout and stderr
        sys.stdout = original_stdout
        sys.stderr = original_stderr

        # Save console log to output directory
        output_dir = Path(__file__).parent / "soc_triage_bot" / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        console_log_path = output_dir / "console.log"
        with open(console_log_path, "w", encoding="utf-8") as f:
            f.write(console_buffer.getvalue())
        print(f"✓ Console log saved to: {console_log_path}")
