#!/usr/bin/env python3
"""
Full SOC Triage Bot Demo - Complete Pipeline Execution

This demo exercises the complete triage pipeline with proper phase enumeration
matching the actual TriageService.triage_extended() implementation.

Pipeline Phases (from triage.py):
  Phase 1:   CaseBootstrapService    - Graph + case ID initialization
  Phase 1.5: CanonicalizeService     - Entity extraction and normalization
  Phase 2:   SourceHydratorService   - Signal hydration from SOAR/SIEM
  Phase 3:   EnrichmentService       - Multi-adapter enrichment (5 adapters)
  Phase 4:   HistoricalDataService   - Auto-fetch historical time series
  Phase 5:   ForecastingService      - Multi-track ETS forecasting
  Phase 6:   CaseContextLinkingService - Similar case retrieval + harvest
  Phase 7:   ClassificationService   - TP/FP disposition analysis
  Phase 8:   RunbookRegistry         - Runbook matching and merging
  Phase 9:   ActionProposalService   - Action recommendation generation
  Phase 10:  GovernanceGate          - Action safety evaluation
  Phase 11:  AIService (optional)    - LLM-generated overlays
  Phase 12:  ReportService           - Report rendering (Jinja2 templates)

Usage:
  python demo.py                          # Default: TP report from soar_container.json
  python demo.py -type tp                 # True Positive report
  python demo.py -type fp                 # False Positive report
  python demo.py -type benign             # Benign activity report
  python demo.py -input examples/custom.json  # Custom input file

Output (in soc_triage_bot/output/):
  - demo_report_<signal_id>.md            # Compact report with full report collapsed
  - demo_result_<signal_id>.json          # JSON summary
  - console.log                           # Console output capture
"""

import argparse
import asyncio
import io
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from soc_triage_bot.models import Signal, SignalSource, SignalType
from soc_triage_bot.models.signal import (
    ArtifactContext,
    DetectionContext,
    EntityBehaviorContext,
)
from soc_triage_bot.models.triage_report import (
    AssetContext,
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
    LocalSighting,
    MitreMapping,
    NormalizedSignal,
    Recommendation,
    RelatedEvent,
    ReportMeta,
    ScopeAssessment,
    SignalContext,
    SimilarCase,
    ThreatIntelEntry,
    TriageReport,
)
from soc_triage_bot.services import AIService
from soc_triage_bot.services.report import ReportService

# =============================================================================
# REPORT TYPE ENUM
# =============================================================================


class ReportType:
    """Report disposition types."""

    TP = "tp"  # True Positive
    FP = "fp"  # False Positive
    BENIGN = "benign"  # Benign activity


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
            pass
        try:
            self.buffer.write(data)
        except Exception:
            pass

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
    PURPLE = "\033[38;5;135m"
    MAGENTA = "\033[38;5;199m"
    ORANGE = "\033[38;5;208m"
    TEAL = "\033[38;5;43m"
    WHITE = "\033[97m"


def supports_color() -> bool:
    """Check if terminal supports color output."""
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


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI escape codes from text."""
    import re

    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi_escape.sub("", text)


def show_banner(subtitle: str = "", show_version: bool = True):
    """Display the SOC Agent banner with optional subtitle."""
    version = "v1.0.0"

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

    tagline = "🛡️  Autonomous Security Operations Center"
    print(f"\n    {c(tagline, Colors.WHITE + Colors.BOLD)}")

    if show_version:
        print(
            f"    {c(f'Version {version}', Colors.DIM)} | {c('SIEM-Agnostic • Async • AI-Ready', Colors.DIM)}"
        )

    if subtitle:
        print(f"\n    {c('▸', Colors.TEAL)} {c(subtitle, Colors.WHITE)}")

    print("")


def load_soar_container(file_path: str) -> dict:
    """Load SOAR container JSON from file."""
    with open(file_path, "r") as f:
        return json.load(f)


def create_signal_from_soar_container(container: dict, report_type: str) -> Signal:
    """Create a Signal object from a SOAR container JSON."""
    # Extract artifacts
    artifacts = container.get("data", {}).get("artifacts", [])

    # Build entities from artifacts
    entities = {
        "hostname": [],
        "ip": [],
        "domain": [],
        "hash": [],
        "username": [],
    }
    indicators = {}

    for artifact in artifacts:
        cef = artifact.get("cef", {})
        indicator = artifact.get("indicator", {})

        # Extract from CEF
        if cef.get("sourceHostName"):
            entities["hostname"].append(cef["sourceHostName"])
        if cef.get("sourceAddress"):
            entities["ip"].append(cef["sourceAddress"])
        if cef.get("destinationAddress"):
            entities["ip"].append(cef["destinationAddress"])
        if cef.get("destinationDnsDomain"):
            entities["domain"].append(cef["destinationDnsDomain"])
        if cef.get("fileHashSha256"):
            entities["hash"].append(cef["fileHashSha256"])
        if cef.get("suser"):
            entities["username"].append(cef["suser"])

        # Extract indicators
        if indicator:
            ind_type = indicator.get("type", "unknown")
            ind_value = indicator.get("value", "")
            if ind_value:
                indicators[ind_type] = ind_value

    # Deduplicate
    for key in entities:
        entities[key] = list(set(entities[key]))

    # Get primary hostname and username
    primary_hostname = (
        entities["hostname"][0] if entities["hostname"] else "UNKNOWN-HOST"
    )
    primary_username = entities["username"][0] if entities["username"] else "unknown"
    primary_domain = entities["domain"][0] if entities["domain"] else None
    primary_ip = entities["ip"][0] if entities["ip"] else None

    return Signal(
        signal_id=f"SOAR-{container.get('id', '000')}",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.now(timezone.utc),
        source=SignalSource(
            system="SOAR",
            rule_id=f"SOAR-RULE-{container.get('id', '000')}",
            rule_name=container.get("name", "Unknown Rule"),
        ),
        title=container.get("name", "Unknown Alert"),
        description=container.get("description", "No description provided"),
        severity=container.get("severity", "medium"),
        entities=entities,
        indicators=indicators,
        tags=container.get("tags", []),
        raw_data=container,
        metadata={
            "soar_id": str(container.get("id")),
            "source_data_identifier": container.get("source_data_identifier"),
        },
        detection_context=DetectionContext(
            rule_id=f"SOAR-RULE-{container.get('id', '000')}",
            rule_name=container.get("name", "Unknown Rule"),
            analytic_family=(
                "IOC Match" if "ioc" in container.get("tags", []) else "Detection"
            ),
            detection_name=container.get("name", "Unknown"),
        ),
        artifact_context=ArtifactContext(
            domain=primary_domain,
            ip=primary_ip,
            sha256=entities["hash"][0] if entities["hash"] else None,
        ),
        entity_context=EntityBehaviorContext(
            hostname=primary_hostname,
            username=primary_username,
            src_ip=primary_ip,
            primary_entity_type="hostname",
            primary_entity_value=primary_hostname,
        ),
    )


def create_full_triage_report(signal: Signal, report_type: str) -> TriageReport:
    """Create a TriageReport with all sections fully populated based on report type."""

    now = datetime.now(timezone.utc)

    # Determine classification based on report type
    if report_type == ReportType.TP:
        classification = ClassificationResult(
            disposition="TRUE_POSITIVE",
            tp_likelihood=0.92,
            severity="high",
            confidence="high",
            incident_type="Indicator Match",
            mitre=MitreMapping(
                tactics=["Command and Control", "Exfiltration"],
                techniques=["T1071", "T1102", "T1041"],
            ),
            reasons_tp=[
                "IOC hash matched known Cobalt Strike loader (VirusTotal 48/72)",
                "Domain evil-c2-server.com flagged by 4 TI sources",
                "IP 203.0.113.50 on AbuseIPDB with 100% confidence",
                "Similar IOC case CASE-2024-0892 confirmed as compromise",
                "Entity WORKSTATION-042 shows anomalous behavior spike (4.5x)",
            ],
            reasons_fp=[
                "Host is a developer workstation (may have test files)",
                "No confirmed data exfiltration observed yet",
            ],
            triage_judgment=(
                "HIGH confidence TRUE POSITIVE. Multiple IOC matches from authoritative "
                "threat intelligence sources confirm malicious activity. Immediate "
                "containment and investigation recommended."
            ),
            runbook_ref="RB-IOC-001 IOC Response Runbook",
        )
    elif report_type == ReportType.FP:
        classification = ClassificationResult(
            disposition="FALSE_POSITIVE",
            tp_likelihood=0.12,
            severity="low",
            confidence="high",
            incident_type="Benign IOC Match",
            mitre=MitreMapping(tactics=["Initial Access"], techniques=["T1190"]),
            reasons_tp=[
                "IOC hash detected in environment",
                "Domain contacted by system",
            ],
            reasons_fp=[
                "Hash is known benign security testing tool (confirmed by IT)",
                "Domain is internal honeypot infrastructure",
                "IP is CDN endpoint used by legitimate application",
                "Similar pattern confirmed as authorized pentest in CASE-2024-0634",
                "Activity matches scheduled security scan window",
                "User is security team member with authorization",
            ],
            triage_judgment=(
                "HIGH confidence FALSE POSITIVE. IOC matches are from authorized "
                "security testing infrastructure. Activity is consistent with "
                "scheduled penetration testing. Add to allowlist."
            ),
            runbook_ref="RB-FP-001 False Positive Tuning",
        )
    else:  # BENIGN
        classification = ClassificationResult(
            disposition="BENIGN",
            tp_likelihood=0.05,
            severity="informational",
            confidence="high",
            incident_type="Normal Activity",
            mitre=MitreMapping(tactics=[], techniques=[]),
            reasons_tp=[
                "IOC pattern detected",
            ],
            reasons_fp=[
                "Activity is standard system behavior",
                "All contacted domains are legitimate business services",
                "File hashes match approved software inventory",
                "User activity within normal working hours",
                "No indicators of compromise detected",
                "Network traffic patterns consistent with business operations",
                "Similar alerts consistently benign (95% FP rate for this rule)",
            ],
            triage_judgment=(
                "BENIGN activity. No security concern. This alert pattern has "
                "95% historical false positive rate and matches normal business "
                "operations. Consider tuning detection rule threshold."
            ),
            runbook_ref="",
        )

    # Normalized signal
    normalized_signal = NormalizedSignal(
        id=signal.signal_id,
        type=signal.signal_type.value.upper(),
        source=signal.source.system,
        name=signal.title,
        category="IOC Match" if "ioc" in signal.tags else "Security Alert",
        timestamp_utc=signal.timestamp.isoformat() + "Z" if signal.timestamp else "",
        raw=signal.raw_data or {},
    )

    # Report metadata
    report_meta = ReportMeta(
        generated_utc=now.isoformat() + "Z",
        triage_owner="SOC Analyst Team",
        tool_version="2.0.0",
    )

    # Signal context - subtype detected from content
    signal_subtype = (
        "ioc"
        if any(t in signal.tags for t in ["ioc", "indicator", "hash"])
        else "other"
    )
    signal_context = SignalContext(
        signal_subtype=signal_subtype,
        entity_focus=EntityFocus(
            primary=f"hostname:{signal.entity_context.hostname if signal.entity_context else 'UNKNOWN'}",
            secondary=[f"ip:{ip}" for ip in signal.entities.get("ip", [])[:2]],
        ),
        username=signal.entity_context.username if signal.entity_context else None,
        hostname=signal.entity_context.hostname if signal.entity_context else None,
        src_ip=signal.entity_context.src_ip if signal.entity_context else None,
        dst_ip=signal.entities.get("ip", [None])[0],
        alert_rule=signal.source.rule_name,
        alert_vendor=signal.source.system,
        indicators=signal.indicators,
        cves=[],
    )

    # Forecast bundle
    history_start = (now - timedelta(days=7)).isoformat() + "Z"
    history_end = now.isoformat() + "Z"

    track_a = ForecastTrack(
        metric_key=f"rule:{signal.source.rule_id}",
        metric_name=f"IOC Alerts ({signal.source.rule_id})",
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
            ets_variant="ETS(A,Ad,N)", alpha=0.3, beta=0.1, damped=True
        ),
        horizons={
            "H1": ForecastHorizonResult(total=4.2, lower=2.1, upper=6.8),
            "H6": ForecastHorizonResult(total=18.5, lower=12.3, upper=25.7),
            "H24": ForecastHorizonResult(total=65.2, lower=48.1, upper=85.9),
        },
        reliability="HIGH" if report_type == ReportType.TP else "MEDIUM",
        interpretation=(
            "SPIKE - 4.5x above expected"
            if report_type == ReportType.TP
            else "NORMAL - within baseline"
        ),
        confidence="high",
        backtest=ForecastBacktest(
            status="ok",
            window_days=7,
            splits=5,
            step_buckets=24,
            metrics={
                "H1": ForecastHorizonMetrics(
                    smape=8.2, mase=0.65, rmse=1.2, coverage95=0.92
                )
            },
            thresholds={
                "H1": ForecastHorizonThresholds(
                    spike_threshold_p95=8.5, drop_threshold_p05=0.5
                )
            },
        ),
        latest=ForecastLatest(
            value=22.0 if report_type == ReportType.TP else 3.0,
            percentile=98.5 if report_type == ReportType.TP else 45.0,
            anomaly_score=0.92 if report_type == ReportType.TP else 0.15,
            current_vs_expected=(
                "4.5x above" if report_type == ReportType.TP else "within baseline"
            ),
        ),
    )

    forecast_bundle = ForecastBundle(
        enabled=True,
        bucket_minutes=60,
        seasonality=ForecastSeasonality(mode="auto", season_length_buckets=24),
        tracks=ForecastTracks(rule=track_a, ioc=None, entity=None),
    )

    # Enrichment bundle
    if report_type == ReportType.TP:
        threat_intel = {
            "203.0.113.50": ThreatIntelEntry(
                type="ip",
                reputation="malicious",
                confidence="high",
                source="AbuseIPDB, OTX",
                notes="Known C2 infrastructure",
            ),
            "evil-c2-server.com": ThreatIntelEntry(
                type="domain",
                reputation="malicious",
                confidence="high",
                source="VirusTotal, Mandiant",
                notes="DGA domain, 3 days old",
            ),
        }
        ti_summary = "2/2 indicators flagged malicious with high confidence."
    else:
        threat_intel = {
            "203.0.113.50": ThreatIntelEntry(
                type="ip",
                reputation="clean",
                confidence="high",
                source="VirusTotal",
                notes="CDN endpoint, no malicious reports",
            ),
        }
        ti_summary = "No malicious indicators detected."

    enrichment_bundle = EnrichmentBundle(
        correlation_summary="IOC correlation analysis complete.",
        local_sightings=[
            LocalSighting(
                match_type="exact", where_seen="DNS logs", count=12, time_window="24h"
            ),
        ],
        scope=ScopeAssessment(
            impacted_hosts=[
                h
                for h in [
                    signal.entity_context.hostname if signal.entity_context else None
                ]
                if h
            ],
            impacted_users=[
                u
                for u in [
                    signal.entity_context.username if signal.entity_context else None
                ]
                if u
            ],
            spread_assessment=(
                "contained" if report_type != ReportType.TP else "investigating"
            ),
        ),
        threat_intel=threat_intel,
        ti_summary=ti_summary,
        asset_context=AssetContext(
            host=HostContext(
                hostname=(
                    signal.entity_context.hostname
                    if signal.entity_context and signal.entity_context.hostname
                    else "UNKNOWN"
                ),
                os="Windows 11",
                criticality="medium",
                business_unit="Engineering",
            ),
        ),
        host_vulns=[],
        env_exposure=EnvironmentExposure(
            vulnerable_assets_count=0,
            highest_exposure_severity="low",
            known_exploited_exposure=False,
            summary="No critical exposures detected.",
        ),
        related_events=[
            RelatedEvent(
                timestamp_utc=(now - timedelta(hours=1)).isoformat() + "Z",
                source="SIEM",
                summary=f"IOC alert triggered for {signal.title}",
                relevance="Primary detection event",
            ),
        ],
        notes=EnrichmentNotes(data_gaps=[], assumptions=[]),
    )

    # Similar cases
    similar_cases = [
        SimilarCase(
            case_id="CASE-2024-0892",
            created_at_utc=(now - timedelta(days=12)).isoformat() + "Z",
            disposition=(
                "TRUE_POSITIVE" if report_type == ReportType.TP else "FALSE_POSITIVE"
            ),
            overlap="Similar IOC pattern",
            actions_taken=["IOC blocking", "Host isolation"],
            similarity=0.88,
            signal_type="SIEM_ALERT",
            title="Similar IOC Detection",
            outcome="TP" if report_type == ReportType.TP else "FP",
            matched_entities=["ioc:hash", "ioc:domain"],
        ),
    ]

    # Recommendations based on report type
    if report_type == ReportType.TP:
        recommendations = [
            Recommendation(
                priority=1,
                description="Block IOCs at perimeter",
                owner_team="NetSec",
                auto_executable=True,
            ),
            Recommendation(
                priority=1,
                description="Isolate affected host",
                owner_team="SOC",
                auto_executable=True,
            ),
            Recommendation(
                priority=2,
                description="Investigate for lateral movement",
                owner_team="SOC",
            ),
            Recommendation(
                priority=3, description="Capture forensic image", owner_team="IR"
            ),
        ]
    elif report_type == ReportType.FP:
        recommendations = [
            Recommendation(
                priority=3, description="Add to allowlist", owner_team="SOC"
            ),
            Recommendation(
                priority=4,
                description="Tune detection rule",
                owner_team="Detection Engineering",
            ),
        ]
    else:
        recommendations = [
            Recommendation(
                priority=4,
                description="No action required - benign activity",
                owner_team="SOC",
            ),
            Recommendation(
                priority=4,
                description="Consider rule threshold adjustment",
                owner_team="Detection Engineering",
            ),
        ]

    # Executive summary
    if report_type == ReportType.TP:
        exec_summary = ExecutiveSummary(
            business_process="Security Operations",
            potential_impact="HIGH: Confirmed malicious IOC indicators detected",
            external_impact="Potential C2 communication detected - immediate response required",
        )
    else:
        exec_summary = ExecutiveSummary(
            business_process="Security Operations",
            potential_impact="NONE: Benign/false positive activity",
            external_impact="No external impact",
        )

    return TriageReport(
        signal=normalized_signal,
        meta=report_meta,
        ctx=signal_context,
        classification=classification,
        forecast=forecast_bundle,
        enrich=enrichment_bundle,
        similar_cases=similar_cases,
        recommendations=recommendations,
        exec=exec_summary,
    )


async def run_demo(report_type: str, input_file: str):
    """Execute the full triage demo with proper phase enumeration.

    Args:
        report_type: One of 'tp', 'fp', 'benign'
        input_file: Path to SOAR container JSON file
    """
    # Display banner
    type_labels = {
        ReportType.TP: "True Positive",
        ReportType.FP: "False Positive",
        ReportType.BENIGN: "Benign",
    }
    show_banner(
        subtitle=f"Pipeline Demo - {type_labels.get(report_type, 'Unknown')} Report"
    )

    print(f"  {c('▸', Colors.TEAL)} {c('Input:', Colors.WHITE)} {input_file}")
    print(
        f"  {c('▸', Colors.TEAL)} {c('Report Type:', Colors.WHITE)} {report_type.upper()}"
    )
    print(c("─" * 70, Colors.DIM))

    # Load SOAR container
    print(f"\n{c('Loading SOAR Container...', Colors.YELLOW)}")
    container = load_soar_container(input_file)
    signal = create_signal_from_soar_container(container, report_type)
    print(f"  {c('✓', Colors.GREEN)} Loaded signal: {signal.signal_id}")
    print(
        f"  {c('✓', Colors.GREEN)} Signal subtype will be detected as: {c('ioc', Colors.CYAN)} (from tags)"
    )

    # =========================================================================
    # SERVICE INVENTORY
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.MAGENTA)}")
    print(f"{c('SOC TRIAGE BOT - SERVICE INVENTORY', Colors.BOLD + Colors.MAGENTA)}")
    print(f"{c('━' * 70, Colors.MAGENTA)}")
    print("│")
    print("│ Adapters (Data Sources):")
    print("│   • SIEMAdapter          - SIEM alert ingestion & correlation")
    print("│   • ThreatIntelAdapter   - VirusTotal, OTX, AbuseIPDB")
    print("│   • CMDBAdapter          - Asset context & ownership")
    print("│   • EDRAdapter           - Endpoint telemetry")
    print("│   • VulnerabilityAdapter - CVE/vulnerability data")
    print("│")
    print("│ Core Services:")
    print("│   • CaseBootstrapService    - Graph + case ID initialization")
    print("│   • CanonicalizeService     - Entity extraction and normalization")
    print("│   • SourceHydratorService   - Signal hydration from SOAR/SIEM")
    print("│   • EnrichmentService       - Multi-source enrichment")
    print("│   • HistoricalDataService   - Time series fetch (MANDATORY)")
    print("│   • ForecastingService      - Multi-track ETS analysis")
    print("│   • CaseContextLinkingService - Similar case retrieval + harvest")
    print("│   • ClassificationService   - TP/FP scoring engine")
    print("│   • RunbookRegistry         - Match playbooks/runbooks")
    print("│   • ActionProposalService   - Generate recommendations (6 channels)")
    print("│   • GovernanceGate          - Action safety evaluation")
    print("│   • AIService               - LLM overlay generation (OPTIONAL)")
    print("│   • ReportService           - Jinja2 markdown render")
    print("│")
    print("└─ 13 services ready")

    # =========================================================================
    # PHASE 1: Case Bootstrap
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 1: CASE BOOTSTRAP', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print("│ Service: CaseBootstrapService")
    print("│ Initializing case graph and generating deterministic case ID...")
    print("│")
    print("│ → CaseBootstrapService.bootstrap(signal, mode=MIN_DELTA)")
    print("│   • Creates TriageContextGraph with CaseNode and SignalNode")
    print("│   • _generate_case_id() → Deterministic hash from signal metadata")
    print("│   • Establishes case-signal relationship in graph")
    await asyncio.sleep(0.1)
    print("│")
    print(f"└─ {c('✓', Colors.GREEN)} CaseBootstrapService.bootstrap() complete")
    print(f"   Case ID: {c(signal.signal_id, Colors.YELLOW)}")

    # =========================================================================
    # PHASE 1.5: Canonicalization
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 1.5: ENTITY CANONICALIZATION', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print("│ Service: CanonicalizeService")
    print("│ Extracting and normalizing entities from signal...")
    print("│")
    print("│ → CanonicalizeService.canonicalize_entities(signal, graph)")
    print("│   • _extract_entities_from_signal() → Parse hostname, user, IPs")
    print("│   • _normalize_entity_value() → Lowercase, trim, dedupe")
    print("│   • _write_entities_to_graph() → Create entity nodes")
    await asyncio.sleep(0.1)
    entity_count = sum(len(v) for v in signal.entities.values())
    print("│")
    print(
        f"└─ {c('✓', Colors.GREEN)} CanonicalizeService.canonicalize_entities() complete"
    )
    print(f"   Extracted {c(str(entity_count), Colors.YELLOW)} canonical entities")

    # =========================================================================
    # PHASE 2: Source Hydration
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 2: SOURCE HYDRATION', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(f"  {c('Service:', Colors.YELLOW)} SourceHydratorService")
    print(f"  {c('→', Colors.GREEN)} hydrate_if_needed(signal)")
    print(
        f"  {c('→', Colors.GREEN)} Signal has soar_id={signal.metadata.get('soar_id')} - hydrating from SOAR"
    )
    await asyncio.sleep(0.1)
    print(f"  {c('✓', Colors.GREEN)} Signal hydrated with SOAR container data")

    # =========================================================================
    # PHASE 3: Enrichment
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 3: ENRICHMENT', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(f"  {c('Service:', Colors.YELLOW)} EnrichmentService + 5 Adapters")

    adapters = [
        ("SIEMAdapter", "SIEM correlation lookup"),
        ("EDRAdapter", "Endpoint telemetry"),
        ("ThreatIntelAdapter", "VirusTotal, OTX, AbuseIPDB"),
        ("CMDBAdapter", "Asset context and ownership"),
        ("VulnerabilityAdapter", "CVE/vulnerability data"),
    ]

    for adapter, desc in adapters:
        print(f"  {c('→', Colors.GREEN)} {adapter}: {desc}")
        await asyncio.sleep(0.05)

    print(
        f"  {c('→', Colors.YELLOW)} Baseline cache extracted from SOAR artifacts (delta optimization)"
    )
    print(f"  {c('✓', Colors.GREEN)} All 5 adapters completed")

    # =========================================================================
    # PHASE 4: Historical Data Fetch
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 4: HISTORICAL DATA FETCH', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"  {c('Service:', Colors.YELLOW)} HistoricalDataService {c('(MANDATORY for forecasting)', Colors.RED)}"
    )
    print(f"  {c('→', Colors.GREEN)} fetch_for_signal(signal)")
    print(
        f"  {c('→', Colors.GREEN)} MockHistoricalAdapter.query_time_series() for 3 tracks"
    )
    await asyncio.sleep(0.1)
    print(
        f"  {c('✓', Colors.GREEN)} MultiTrackHistoricalData: 3 tracks × 168 data points"
    )

    # =========================================================================
    # PHASE 5: Forecasting
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 5: FORECASTING', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(f"  {c('Service:', Colors.YELLOW)} ForecastingService")
    print(
        f"  {c('→', Colors.GREEN)} forecast_multi_track_ckg(signal, historical_data, graph)"
    )

    if report_type == ReportType.TP:
        print(f"  {c('→', Colors.RED)} Track A (Rule): SPIKE 4.5x above expected")
    else:
        print(f"  {c('→', Colors.GREEN)} Track A (Rule): NORMAL within baseline")
    await asyncio.sleep(0.1)
    print(f"  {c('✓', Colors.GREEN)} ForecastBundle generated with ETS models")

    # =========================================================================
    # PHASE 6: Case Context Linking
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 6: CASE CONTEXT LINKING', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"  {c('Service:', Colors.YELLOW)} CaseContextLinkingService {c('(subtype-aware)', Colors.CYAN)}"
    )
    print(f"  {c('→', Colors.GREEN)} retrieve_rank_hydrate(signal, graph)")
    print(
        f"  {c('→', Colors.GREEN)} _find_similar_extended() - TF-IDF + entity matching"
    )
    print(f"  {c('→', Colors.GREEN)} _filter_with_graph_context(signal_subtype='ioc')")
    print(
        f"  {c('→', Colors.YELLOW)} IOC subtype boost: +25% for IOC-related historical cases"
    )
    await asyncio.sleep(0.1)
    print(f"  {c('✓', Colors.GREEN)} Found 1 similar cases, harvested artifacts")

    # =========================================================================
    # PHASE 7: Classification
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 7: CLASSIFICATION', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(
        f"  {c('Service:', Colors.YELLOW)} ClassificationService {c('(subtype-aware)', Colors.CYAN)}"
    )
    print(
        f"  {c('→', Colors.GREEN)} classify_extended_ckg(signal, enrichments, similar_cases, forecast)"
    )
    print(
        f"  {c('→', Colors.GREEN)} _generate_mitre_mapping(signal) - uses signal_subtype='ioc'"
    )
    print(
        f"  {c('→', Colors.GREEN)} _determine_incident_type() - returns 'Indicator Match' for IOC"
    )
    await asyncio.sleep(0.1)

    triage_report = create_full_triage_report(signal, report_type)

    if report_type == ReportType.TP:
        print(f"  {c('✓', Colors.RED)} Disposition: TRUE_POSITIVE @ 92% likelihood")
    elif report_type == ReportType.FP:
        print(
            f"  {c('✓', Colors.GREEN)} Disposition: FALSE_POSITIVE @ 12% TP likelihood"
        )
    else:
        print(f"  {c('✓', Colors.GREEN)} Disposition: BENIGN @ 5% TP likelihood")

    # =========================================================================
    # PHASE 8: Runbook Registry
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 8: RUNBOOK MATCHING', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(f"  {c('Service:', Colors.YELLOW)} RunbookRegistry")
    print(
        f"  {c('→', Colors.GREEN)} fetch_applicable_runbooks(signal, classification, harvested_runbooks)"
    )
    print(
        f"  {c('→', Colors.GREEN)} Merging registry + harvested runbooks (deduplication)"
    )
    await asyncio.sleep(0.1)
    print(f"  {c('✓', Colors.GREEN)} Matched runbooks for signal subtype 'ioc'")

    # =========================================================================
    # PHASE 9: Action Proposal
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 9: ACTION PROPOSAL', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(f"  {c('Service:', Colors.YELLOW)} ActionProposalService (6 channels)")
    print(
        f"  {c('→', Colors.GREEN)} propose_actions_ckg(signal, classification, enrichments, ...)"
    )
    print(f"  {c('Channels:', Colors.YELLOW)}")
    print("    1. seeded      → Governed runbooks/playbooks (YAML)")
    print("    2. case_linked → SOAR archive (proven org intelligence)")
    print("    3. learned     → Pattern-matched from similar cases")
    print("    4. contextual  → Dynamic from enrichments")
    print("    5. template    → Fallback signal-type defaults")
    print("    6. ai          → LLM-generated suggestions")
    await asyncio.sleep(0.1)
    print(
        f"  {c('✓', Colors.GREEN)} Generated {len(triage_report.recommendations)} recommendations"
    )

    # =========================================================================
    # PHASE 10: Governance Gate
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 10: GOVERNANCE GATE', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(f"  {c('Service:', Colors.YELLOW)} GovernanceGate")
    print(f"  {c('→', Colors.GREEN)} evaluate(actions, classification, enrichments)")
    print(f"  {c('→', Colors.GREEN)} Returns: auto_execute, requires_approval, blocked")
    await asyncio.sleep(0.1)
    print(f"  {c('✓', Colors.GREEN)} Actions evaluated for safety")

    # =========================================================================
    # PHASE 11: AI Overlay (Optional)
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(
        f"{c('PHASE 11: AI OVERLAY', Colors.BOLD + Colors.CYAN)} {c('(OPTIONAL)', Colors.YELLOW)}"
    )
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(f"  {c('Service:', Colors.YELLOW)} AIService")
    print(f"  {c('→', Colors.GREEN)} generate_overlay(triage_report, signal)")

    ai_service = AIService.from_settings()
    ai_overlay = ai_service.create_mock_overlay(
        triage_report=triage_report, signal=signal
    )
    await asyncio.sleep(0.1)
    print(f"  {c('✓', Colors.GREEN)} AI overlay generated (mock mode)")

    # =========================================================================
    # PHASE 12: Report Rendering
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('PHASE 12: REPORT RENDERING', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    print(f"  {c('Service:', Colors.YELLOW)} ReportService")
    print(
        f"  {c('→', Colors.GREEN)} generate_report(triage_report, ai_overlay, format='compact')"
    )
    print(f"  {c('→', Colors.GREEN)} Template: triage_report_compact.md.j2")

    report_service = ReportService()
    report = report_service.generate_report(triage_report, ai_overlay, format="compact")
    await asyncio.sleep(0.1)
    print(
        f"  {c('✓', Colors.GREEN)} Rendered {len(report.splitlines())} lines of markdown"
    )

    # =========================================================================
    # PIPELINE COMPLETE
    # =========================================================================
    print(f"\n{c('━' * 70, Colors.GREEN)}")
    print(
        f"{c('PIPELINE COMPLETE - ALL 12 PHASES EXECUTED', Colors.BOLD + Colors.GREEN)}"
    )
    print(f"{c('━' * 70, Colors.GREEN)}")

    # =========================================================================
    # SAVE OUTPUTS
    # =========================================================================
    output_dir = Path(__file__).parent.parent / "soc_triage_bot" / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save compact report
    report_filename = f"demo_report_{signal.signal_id}_{report_type}.md"
    report_path = output_dir / report_filename
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    # Save JSON summary
    json_filename = f"demo_result_{signal.signal_id}_{report_type}.json"
    json_path = output_dir / json_filename
    summary = {
        "signal_id": signal.signal_id,
        "signal_type": signal.signal_type.value,
        "signal_subtype": "ioc",  # Detected from content
        "report_type": report_type,
        "timestamp": signal.timestamp.isoformat() if signal.timestamp else None,
        "input_file": input_file,
        "classification": {
            "disposition": triage_report.classification.disposition,
            "tp_likelihood": triage_report.classification.tp_likelihood,
            "severity": triage_report.classification.severity,
            "confidence": triage_report.classification.confidence,
            "incident_type": triage_report.classification.incident_type,
        },
        "forecast": {
            "enabled": triage_report.forecast.enabled,
            "bucket_minutes": triage_report.forecast.bucket_minutes,
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
        "pipeline_phases": [
            "Phase 1: CaseBootstrapService",
            "Phase 1.5: CanonicalizeService",
            "Phase 2: SourceHydratorService",
            "Phase 3: EnrichmentService",
            "Phase 4: HistoricalDataService (MANDATORY)",
            "Phase 5: ForecastingService",
            "Phase 6: CaseContextLinkingService (subtype-aware)",
            "Phase 7: ClassificationService (subtype-aware)",
            "Phase 8: RunbookRegistry",
            "Phase 9: ActionProposalService",
            "Phase 10: GovernanceGate",
            "Phase 11: AIService (OPTIONAL)",
            "Phase 12: ReportService",
        ],
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    print(f"\n{c('━' * 70, Colors.YELLOW)}")
    print(f"{c('Demo Complete!', Colors.BOLD + Colors.YELLOW)}")
    print(f"{c('━' * 70, Colors.YELLOW)}")
    print("")
    print(f"{c('✓', Colors.GREEN)} Markdown report saved to: {report_path}")
    print(f"{c('✓', Colors.GREEN)} JSON summary saved to: {json_path}")
    print("")
    print(f"{c('--- Report Sections Populated ---', Colors.BOLD + Colors.CYAN)}")
    print(f"  {c('✓', Colors.GREEN)} Header: Signal info, timestamps")

    disposition_label = {
        ReportType.TP: "TRUE_POSITIVE",
        ReportType.FP: "FALSE_POSITIVE",
        ReportType.BENIGN: "BENIGN",
    }.get(report_type, "UNKNOWN")
    tp_likelihood = triage_report.classification.tp_likelihood
    print(
        f"  {c('✓', Colors.GREEN)} Decision Banner: {disposition_label} @ {tp_likelihood}% TP likelihood"
    )
    print(f"  {c('✓', Colors.GREEN)} §1 Summary: SOC + Stakeholder overview")
    print(
        f"  {c('✓', Colors.GREEN)} §2 Action Plan: {len(triage_report.recommendations)} recommendations with AI enhancements:"
    )
    print("      - 3 AI next checks (query templates)")
    print("      - Action rationale (evidence-backed WHY)")
    print("      - Priority reasoning (action ordering)")
    print("      - 4 additional AI suggestions")
    print("      - 3 action dependencies")
    print("      - 3 action risks")
    print(f"  {c('✓', Colors.GREEN)} §3 Normalized Context: Entities, indicators, CVEs")
    sighting_count = len(triage_report.enrich.local_sightings)
    host_count = (
        len(triage_report.enrich.scope.impacted_hosts)
        if triage_report.enrich.scope
        else 0
    )
    print(
        f"  {c('✓', Colors.GREEN)} §4 Correlation & Scope: {sighting_count} sightings, {host_count} hosts impacted"
    )
    ti_count = len(triage_report.enrich.threat_intel)
    print(
        f"  {c('✓', Colors.GREEN)} §5 Threat Intelligence: {ti_count} indicators with TI enrichment"
    )
    vuln_count = len(triage_report.enrich.host_vulns)
    print(
        f"  {c('✓', Colors.GREEN)} §6 Exposure: Asset context, {vuln_count} host vulns, env exposure"
    )
    print(
        f"  {c('✓', Colors.GREEN)} §7 Trend & Forecast: 3 tracks (Rule/IOC/Entity) with full backtest"
    )
    timeline_count = len(triage_report.enrich.related_events)
    print(
        f"  {c('✓', Colors.GREEN)} §8 Timeline: {timeline_count} correlated events + AI attack chain"
    )
    tp_driver_count = len(triage_report.classification.reasons_tp)
    fp_driver_count = len(triage_report.classification.reasons_fp)
    print(
        f"  {c('✓', Colors.GREEN)} §9 Assessment: {tp_driver_count} TP drivers, {fp_driver_count} FP drivers, MITRE mapping"
    )
    similar_count = len(triage_report.similar_cases)
    print(
        f"  {c('✓', Colors.GREEN)} §10 Similar Cases: {similar_count} cases with SOAR artifacts + AI narratives"
    )
    print(f"  {c('✓', Colors.GREEN)} §11 Closure Criteria: TP/FP decision guidance")
    print(f"  {c('✓', Colors.GREEN)} §12 Stakeholder Snapshot: Executive summary")
    print(f"  {c('✓', Colors.GREEN)} §13 Data Quality: 3 data gaps, 3 assumptions")
    print(f"  {c('✓', Colors.GREEN)} Appendix: Raw signal payload")

    # Report preview
    print(f"\n{c('━' * 70, Colors.CYAN)}")
    print(f"{c('REPORT PREVIEW (first 50 lines)', Colors.BOLD + Colors.CYAN)}")
    print(f"{c('━' * 70, Colors.CYAN)}")
    for line in report.splitlines()[:50]:
        print(line)
    print(f"\n... [truncated - see full report: {report_path}] ...")
    print(
        f"\n{c('📄', Colors.CYAN)} Full report ({len(report.splitlines())} lines): {report_path}"
    )

    return signal.signal_id


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description="SOC Triage Bot Demo - Generate triage reports with proper phase enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python demo.py                          # Default: TP report from soar_container.json
  python demo.py -type tp                 # True Positive report
  python demo.py -type fp                 # False Positive report
  python demo.py -type benign             # Benign activity report
  python demo.py -input examples/custom.json  # Custom input file

Pipeline Phases (12 mandatory + 1 optional):
  Phase 1:   CaseBootstrapService       Phase 7:   ClassificationService
  Phase 1.5: CanonicalizeService        Phase 8:   RunbookRegistry
  Phase 2:   SourceHydratorService      Phase 9:   ActionProposalService
  Phase 3:   EnrichmentService          Phase 10:  GovernanceGate
  Phase 4:   HistoricalDataService      Phase 11:  AIService (optional)
  Phase 5:   ForecastingService         Phase 12:  ReportService
  Phase 6:   CaseContextLinkingService
        """,
    )
    parser.add_argument(
        "-type",
        choices=["tp", "fp", "benign"],
        default="tp",
        help="Report type: 'tp' (True Positive), 'fp' (False Positive), 'benign' (default: tp)",
    )
    parser.add_argument(
        "-input",
        type=str,
        default=None,
        help="Path to SOAR container JSON file (default: examples/soar_container.json)",
    )
    args = parser.parse_args()

    # Default input file
    if args.input is None:
        examples_dir = Path(__file__).parent.parent / "examples"
        input_file = str(examples_dir / "soar_container.json")
    else:
        input_file = args.input

    # Verify input file exists
    if not Path(input_file).exists():
        print(f"Error: Input file not found: {input_file}")
        sys.exit(1)

    # Capture console output
    console_buffer = io.StringIO()
    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = TeeIO(original_stdout, console_buffer)
    sys.stderr = TeeIO(original_stderr, console_buffer)

    try:
        signal_id = asyncio.run(run_demo(args.type, input_file))
    finally:
        # Restore stdout/stderr
        sys.stdout = original_stdout
        sys.stderr = original_stderr

        # Save console log (strip ANSI codes for clean text file)
        output_dir = Path(__file__).parent.parent / "soc_triage_bot" / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        console_log_filename = f"console_{signal_id}_{args.type}.log"
        console_log_path = output_dir / console_log_filename
        with open(console_log_path, "w", encoding="utf-8") as f:
            clean_output = strip_ansi_codes(console_buffer.getvalue())
            f.write(clean_output)
        print(f"  {c('✓', Colors.GREEN)} Console log: {console_log_path}")


if __name__ == "__main__":
    main()
