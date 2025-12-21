"""Triage Report data models.

This module defines the complete data structure for SOC triage reports,
matching the enterprise template specification with multi-track ETS forecasting.

Key structures:
- ForecastTrack: Multi-horizon ETS with full backtest metrics
- ClassificationResult: Enhanced classification with MITRE, reasons_tp/fp
- SimilarCase: Structured historical case with actions/notes
- Recommendation: SOC runbook-oriented actions
- SignalContext: Entity focus and indicator extraction
- EnrichmentBundle: Full enrichment with scope, TI, assets, timeline
- ReportMeta: Report metadata
- TriageReport: Top-level container (the `r.*` structure)
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# =============================================================================
# CLASSIFICATION LABEL ENUM
# =============================================================================


class ClassificationLabel(str, Enum):
    """Classification labels for signal disposition."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"
    UNKNOWN = "unknown"


# =============================================================================
# SIGNAL TYPE EXTENSIONS
# =============================================================================


class ExtendedSignalType(str, Enum):
    """Extended signal types covering all enterprise use cases."""

    SIEM_ALERT = "SIEM_ALERT"
    IOC = "IOC"
    CVE = "CVE"
    HUNT = "HUNT"
    USER_REPORT = "USER_REPORT"
    EDR_DETECTION = "EDR_DETECTION"
    EMAIL_SECURITY_ALERT = "EMAIL_SECURITY_ALERT"
    TI_INDICATOR = "TI_INDICATOR"
    VULNERABILITY_ALERT = "VULNERABILITY_ALERT"
    HUNT_FINDING = "HUNT_FINDING"
    USER_REPORTED = "USER_REPORTED"


# =============================================================================
# FORECAST MODELS (Multi-Track ETS)
# =============================================================================


class ForecastHorizonMetrics(BaseModel):
    """Backtest metrics for a single horizon (H1, H6, H24)."""

    smape: Optional[float] = Field(default=None, description="Symmetric MAPE (%)")
    mase: Optional[float] = Field(
        default=None, description="Mean Absolute Scaled Error"
    )
    rmse: Optional[float] = Field(default=None, description="Root Mean Square Error")
    coverage95: Optional[float] = Field(
        default=None, description="95% prediction interval coverage"
    )


class ForecastHorizonThresholds(BaseModel):
    """Spike/drop thresholds for a single horizon.

    Calibrated from backtest residuals (p95/p99 quantiles).
    """

    spike_q: Optional[float] = Field(
        default=None, description="Spike quantile threshold"
    )
    drop_q: Optional[float] = Field(default=None, description="Drop quantile threshold")
    spike_threshold_p95: Optional[float] = Field(
        default=None, description="Spike threshold at p95 (forecast + residual_p95)"
    )
    spike_threshold_p99: Optional[float] = Field(
        default=None, description="Spike threshold at p99 (forecast + residual_p99)"
    )
    drop_threshold_p05: Optional[float] = Field(
        default=None, description="Drop threshold at p05 (forecast + residual_p05)"
    )


class ForecastHorizonResult(BaseModel):
    """Forecast result for a single horizon."""

    total: Optional[float] = Field(default=None, description="Point forecast")
    lower: Optional[float] = Field(default=None, description="Lower bound (95% CI)")
    upper: Optional[float] = Field(default=None, description="Upper bound (95% CI)")


class ForecastBacktest(BaseModel):
    """Backtest results for a forecast track."""

    status: str = Field(
        "pending", description="Backtest status: ok, insufficient_data, pending"
    )
    window_days: Optional[int] = Field(
        default=None, description="Backtest window in days"
    )
    splits: Optional[int] = Field(
        default=None, description="Number of cross-validation splits"
    )
    step_buckets: Optional[int] = Field(
        default=None, description="Step size in buckets"
    )

    metrics: Dict[str, ForecastHorizonMetrics] = Field(
        default_factory=dict,
        description="Metrics per horizon: {H1: {...}, H6: {...}, H24: {...}}",
    )
    thresholds: Dict[str, ForecastHorizonThresholds] = Field(
        default_factory=dict,
        description="Thresholds per horizon: {H1: {...}, H6: {...}, H24: {...}}",
    )
    notes: List[str] = Field(
        default_factory=list, description="Backtest notes/warnings"
    )


class ForecastLatest(BaseModel):
    """Latest state for a forecast track.

    Contains current value metrics including anomaly detection.
    """

    # Core value metrics (produced by _calculate_latest)
    value: Optional[float] = Field(
        default=None, description="Current value in latest bucket"
    )
    percentile: Optional[float] = Field(
        default=None, description="Current value percentile (0-100) relative to history"
    )
    anomaly_score: Optional[float] = Field(
        default=None, description="Anomaly score (0-1) based on deviation from forecast"
    )
    current_vs_expected: Optional[str] = Field(
        default=None,
        description="Current vs expected ratio (e.g., '1.5x above expected')",
    )

    # Optional additional context
    current_bucket_count: Optional[int] = Field(
        default=None, description="Count in current bucket (alias for value as int)"
    )
    ingestion_lag_buckets: Optional[int] = Field(
        default=None, description="Data ingestion lag in buckets"
    )


class ForecastSeriesMeta(BaseModel):
    """Series metadata for a forecast track.

    Captures data quality information per spec Section 2.
    """

    history_start_utc: Optional[str] = Field(
        default=None, description="Start of history window (ISO format)"
    )
    history_end_utc: Optional[str] = Field(
        default=None, description="End of history window (ISO format)"
    )
    bucket_minutes: int = Field(default=15, description="Bucket size in minutes")
    total_buckets: Optional[int] = Field(
        default=None, description="Total buckets in window"
    )
    missing_buckets: Optional[int] = Field(
        default=None, description="Number of missing/incomplete buckets"
    )
    missing_pct: Optional[float] = Field(
        default=None, description="Percentage of missing data (0-1)"
    )
    data_completeness: str = Field(
        default="COMPLETE", description="Data completeness: COMPLETE or PARTIAL"
    )
    late_arrival_backfill_supported: bool = Field(
        default=False, description="Whether adapter supports late arrival backfill"
    )


class ForecastModelMeta(BaseModel):
    """ETS model metadata.

    Captures which ETS variant was selected per spec Section 4.
    """

    ets_variant: str = Field(default="ETS(A,N,N)", description="ETS model variant used")
    alpha: Optional[float] = Field(
        default=None, description="Level smoothing parameter"
    )
    beta: Optional[float] = Field(default=None, description="Trend smoothing parameter")
    gamma: Optional[float] = Field(
        default=None, description="Seasonal smoothing parameter"
    )
    seasonal_period: Optional[int] = Field(
        default=None,
        description="Seasonal period in buckets (e.g., 96 for daily at 15min)",
    )
    damped: bool = Field(default=False, description="Whether trend is damped")


class ForecastTrack(BaseModel):
    """A single forecast track (rule, ioc, or entity).

    Each track has:
    - Metric identification (what we're forecasting)
    - Series metadata (history range, bucket size, missing_pct)
    - Model metadata (ETS config chosen)
    - Multi-horizon forecasts (H1, H6, H24)
    - Reliability level (LOW, MEDIUM, HIGH)
    - Interpretation and confidence
    - Full backtest metrics
    - Latest state
    """

    metric_key: Optional[str] = Field(
        default=None, description="Metric key (e.g., 'rule:powershell_encoded')"
    )
    metric_name: Optional[str] = Field(
        default=None, description="Human-readable metric name"
    )
    series_window: Optional[str] = Field(
        default=None, description="History window (e.g., '7d', '30d')"
    )
    history_points: Optional[int] = Field(
        default=None, description="Number of historical data points"
    )

    # Series metadata (spec Section 2)
    series_meta: Optional[ForecastSeriesMeta] = Field(
        default=None, description="Series metadata including data quality"
    )

    # Model metadata (spec Section 4)
    model_meta: Optional[ForecastModelMeta] = Field(
        default=None, description="ETS model configuration used"
    )

    # Multi-horizon forecasts
    horizons: Dict[str, ForecastHorizonResult] = Field(
        default_factory=dict,
        description="Forecasts per horizon: {H1: {...}, H6: {...}, H24: {...}}",
    )

    # Reliability level (spec Section 5)
    reliability: str = Field(
        default="LOW",
        description="Reliability level: LOW, MEDIUM, HIGH based on backtest quality",
    )

    # Interpretation
    interpretation: str = Field(
        default="",
        description="Plain-text interpretation: baseline, elevated, spike, declining",
    )
    confidence: str = Field(
        default="low", description="Confidence level: high, medium, low"
    )

    # Backtest results
    backtest: Optional[ForecastBacktest] = Field(
        default=None, description="Backtest metrics and thresholds"
    )

    # Latest state
    latest: Optional[ForecastLatest] = Field(
        default=None, description="Current state metrics"
    )


class ForecastSeasonality(BaseModel):
    """Seasonality configuration."""

    mode: str = Field(
        default="auto", description="Seasonality mode: auto, weekly, daily, none"
    )
    season_length_buckets: Optional[int] = Field(
        default=None, description="Season length in buckets"
    )


class ForecastTracks(BaseModel):
    """Container for all three forecast tracks."""

    rule: Optional[ForecastTrack] = Field(
        default=None, description="Track A: Rule/Detection frequency"
    )
    ioc: Optional[ForecastTrack] = Field(
        default=None, description="Track B: Indicator/IOC sightings"
    )
    entity: Optional[ForecastTrack] = Field(
        default=None, description="Track C: Entity behavior (dynamic by signal type)"
    )


class ForecastBundle(BaseModel):
    """Complete forecast bundle with all tracks."""

    enabled: bool = Field(default=False, description="Whether forecasting is enabled")
    bucket_minutes: int = Field(default=60, description="Bucket size in minutes")
    seasonality: Optional[ForecastSeasonality] = Field(
        default=None, description="Seasonality configuration"
    )
    tracks: ForecastTracks = Field(
        default_factory=lambda: ForecastTracks(), description="All forecast tracks"
    )


# =============================================================================
# CLASSIFICATION MODELS (Enhanced)
# =============================================================================


class MitreMapping(BaseModel):
    """MITRE ATT&CK mapping."""

    tactics: List[str] = Field(default_factory=list, description="MITRE tactics")
    techniques: List[str] = Field(default_factory=list, description="MITRE techniques")


class ClassificationResult(BaseModel):
    """Classification result with MITRE mapping and structured reasoning.

    This is `r.classification` in the template. Primary classification model
    used by ActionProposalService, RunbookRegistry, and TriageService.
    """

    disposition: str = Field(
        ...,
        description="Disposition: TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, NEEDS_REVIEW",
    )
    tp_likelihood: float = Field(..., ge=0.0, le=1.0, description="TP likelihood (0-1)")
    severity: str = Field(
        default="medium", description="Severity if TP: critical, high, medium, low"
    )
    confidence: str = Field(
        default="medium", description="Confidence level: high, medium, low"
    )

    incident_type: str = Field(
        default="",
        description="Proposed incident type (e.g., 'Credential Theft', 'Malware')",
    )
    mitre: MitreMapping = Field(
        default_factory=MitreMapping, description="MITRE ATT&CK mapping"
    )

    reasons_tp: List[str] = Field(
        default_factory=list, description="Drivers toward TRUE POSITIVE"
    )
    reasons_fp: List[str] = Field(
        default_factory=list, description="Drivers toward FALSE POSITIVE / Benign"
    )

    triage_judgment: str = Field(
        default="",
        description="Triage judgment summary (one-liner explaining the decision)",
    )
    runbook_ref: str = Field(
        default="RB-GEN-001 Generic Signal Triage",
        description="Reference runbook for this incident type",
    )

    # =========================================================================
    # Computed properties for downstream service consumption
    # =========================================================================

    @property
    def label(self) -> ClassificationLabel:
        """Get ClassificationLabel enum from disposition string.

        Maps disposition to ClassificationLabel for use with
        ActionProposalService, RunbookRegistry, and other downstream services.
        """
        disposition_upper = self.disposition.upper().replace(" ", "_")
        if "TRUE_POSITIVE" in disposition_upper or "TRUE POSITIVE" in self.disposition:
            return ClassificationLabel.TRUE_POSITIVE
        elif (
            "FALSE_POSITIVE" in disposition_upper
            or "FALSE POSITIVE" in self.disposition
        ):
            return ClassificationLabel.FALSE_POSITIVE
        elif "BENIGN" in disposition_upper:
            return ClassificationLabel.BENIGN_POSITIVE
        else:
            return ClassificationLabel.UNKNOWN

    @property
    def confidence_score(self) -> float:
        """Get numeric confidence score (alias for tp_likelihood).

        Note: This class has .confidence as str (high/medium/low).
        Use .confidence_score for numeric value, .confidence for categorical.
        """
        return self.tp_likelihood

    @property
    def reasoning(self) -> List[str]:
        """Get combined reasoning from TP and FP drivers."""
        return self.reasons_tp + self.reasons_fp

    @property
    def factors(self) -> Dict[str, float]:
        """Get empty factors dict (not used in this model).

        Classification factors are stored in reasons_tp/reasons_fp lists.
        """
        return {}

    @property
    def similar_cases(self) -> List[str]:
        """Get empty similar_cases list (stored at TriageReport level)."""
        return []

    @property
    def forecast_data(self) -> Optional[Dict[str, Any]]:
        """Get None (forecast data stored in ForecastBundle at TriageReport level)."""
        return None


# =============================================================================
# SIMILAR CASES (Structured)
# =============================================================================


class RunbookRef(BaseModel):
    """Reference to a runbook/playbook from SOAR or local registry."""

    ref_id: str = Field(..., description="Runbook/playbook ID or reference")
    ref_type: str = Field(
        default="runbook",
        description="Type: runbook, playbook, kb_article, workflow",
    )
    source: str = Field(
        default="soar",
        description="Source: soar, local, wiki, confluence",
    )
    title: Optional[str] = Field(
        default=None, description="Human-readable title if known"
    )
    url: Optional[str] = Field(
        default=None, description="URL to wiki/KB article if available"
    )
    whitelisted: bool = Field(
        default=False,
        description="If True, treat as authoritative (same as governed templates)",
    )


class AttachmentMetadata(BaseModel):
    """Metadata about case attachments (without fetching content)."""

    attachment_id: str = Field(..., description="Attachment ID in SOAR")
    filename: str = Field(..., description="Original filename")
    content_type: str = Field(
        default="application/octet-stream", description="MIME type"
    )
    size_bytes: Optional[int] = Field(default=None, description="File size in bytes")
    uploaded_at: Optional[str] = Field(
        default=None, description="Upload timestamp (ISO)"
    )
    is_playbook: bool = Field(
        default=False,
        description="True if attachment appears to be a playbook/runbook (e.g., .yaml, .md)",
    )


class SimilarCase(BaseModel):
    """Structured similar case from SOAR/historical data.

    Extended for CaseArtifactHarvester capability:
    - runbook_refs: References to runbooks/playbooks used in case
    - tasks_template_id: SOAR workflow/task template ID
    - attachments_metadata: Metadata about case attachments
    """

    case_id: str = Field(..., description="Historical case ID")
    created_at_utc: Optional[str] = Field(
        default=None, description="When case was created (ISO format)"
    )
    disposition: str = Field(
        default="", description="How the case was resolved (TP, FP, etc.)"
    )
    overlap: str = Field(
        default="",
        description="What overlaps with current signal (e.g., 'Same IOC + host')",
    )
    actions_taken: List[str] = Field(
        default_factory=list, description="Key actions taken on the case"
    )
    notes_summary: str = Field(default="", description="Summary of case notes")

    # --- Similarity matching fields (from SimilarityService) ---
    similarity: float = Field(
        default=0.0,
        description="Combined similarity score (0-1) from text and entity matching",
    )
    signal_type: str = Field(
        default="", description="Signal type of the historical case"
    )
    title: str = Field(default="", description="Title of the historical case")
    outcome: str = Field(
        default="unknown",
        description="Resolution outcome: 'TP', 'FP', or 'unknown'",
    )
    matched_entities: List[str] = Field(
        default_factory=list,
        description="Entities that matched between signal and case (e.g., 'ip:1.2.3.4')",
    )
    notes: str = Field(default="", description="Case notes or summary")

    # --- CaseArtifactHarvester fields ---
    runbook_refs: List[RunbookRef] = Field(
        default_factory=list,
        description="References to runbooks/playbooks followed in this case",
    )
    tasks_template_id: Optional[str] = Field(
        default=None,
        description="SOAR workflow/task template ID used for this case",
    )
    attachments_metadata: List[AttachmentMetadata] = Field(
        default_factory=list,
        description="Metadata about case attachments (PDFs, MDs, etc.)",
    )


# =============================================================================
# RECOMMENDATIONS (SOC Runbook Actions)
# =============================================================================


class Recommendation(BaseModel):
    """SOC runbook-oriented recommendation/action.

    This is `r.recommendations[]` in the template.
    """

    priority: int = Field(
        ..., ge=1, le=5, description="Priority 1 (highest) - 5 (lowest)"
    )
    description: str = Field(..., description="Action description")
    owner_team: str = Field(
        default="SOC", description="Team/owner responsible (SOC, IR, IT, etc.)"
    )
    auto_executable: bool = Field(default=False, description="Can this be automated?")
    status: str = Field(
        default="Open", description="Status: Open, In Progress, Completed, Blocked"
    )
    rationale: str = Field(default="", description="Why this action is recommended")


class TuningRecommendation(BaseModel):
    """Tuning recommendation for false positive cases."""
    
    action: str = Field(..., description="Detection change to make")
    priority: str = Field(default="P3", description="Priority level")
    owner: str = Field(default="Detection Eng", description="Team responsible")
    ticket: Optional[str] = Field(default=None, description="Ticket reference")


# =============================================================================
# SIGNAL CONTEXT (r.ctx)
# =============================================================================


class EntityFocus(BaseModel):
    """Entity focus for forecast Track C selection."""

    primary: Optional[str] = Field(
        None,
        description="Primary entity to focus on (e.g., 'user:admin', 'host:workstation-01')",
    )
    secondary: List[str] = Field(
        default_factory=list,
        description="Secondary entities of interest",
    )


class SignalContext(BaseModel):
    """Extracted signal context for template rendering.

    This is `r.ctx` in the template - normalized entities/indicators/cves.
    """

    # Signal subtype/focus
    signal_subtype: Optional[str] = Field(
        default=None, description="Derived signal subtype if applicable"
    )
    entity_focus: Optional[EntityFocus] = Field(
        default=None, description="Entity focus for Track C selection"
    )

    # Core entities (extracted from signal)
    username: Optional[str] = Field(default=None)
    hostname: Optional[str] = Field(default=None)
    src_ip: Optional[str] = Field(default=None)
    dst_ip: Optional[str] = Field(default=None)

    # SIEM-specific
    alert_rule: Optional[str] = Field(default=None, description="Alert rule name/ID")
    alert_vendor: Optional[str] = Field(
        default=None, description="Alert vendor (Splunk, Sentinel, etc.)"
    )

    # Indicators (any type, key/value)
    indicators: Dict[str, str] = Field(
        default_factory=dict,
        description="Extracted indicators: {type: value}",
    )

    # CVEs (for CVE-led or vulnerability signals)
    cves: List[str] = Field(default_factory=list, description="CVE identifiers")


# =============================================================================
# ENRICHMENT BUNDLE (r.enrich)
# =============================================================================


class LocalSighting(BaseModel):
    """A local sighting of an indicator in the environment."""

    match_type: str = Field(
        default="", description="Type of match (exact, partial, etc.)"
    )
    where_seen: str = Field(default="", description="Where the indicator was seen")
    count: int = Field(default=0, description="Number of sightings")
    time_window: str = Field(default="", description="Time window of sightings")
    notes: str = Field(default="", description="Additional notes")


class ScopeAssessment(BaseModel):
    """Scope/spread assessment."""

    impacted_hosts: List[str] = Field(default_factory=list)
    impacted_users: List[str] = Field(default_factory=list)
    impacted_segments: List[str] = Field(default_factory=list)
    spread_assessment: str = Field(
        default="isolated",
        description="Spread assessment: isolated, limited, widespread",
    )


class ThreatIntelEntry(BaseModel):
    """Threat intel enrichment for a single indicator."""

    type: str = Field(default="", description="Indicator type (ip, domain, hash, etc.)")
    reputation: str = Field(
        default="unknown",
        description="Reputation: malicious, suspicious, benign, unknown",
    )
    confidence: str = Field(default="low", description="Confidence: high, medium, low")
    source: str = Field(default="", description="TI source(s)")
    notes: str = Field(default="", description="Additional notes")


class HostContext(BaseModel):
    """Host asset context from CMDB."""

    hostname: str = Field(default="", description="Hostname/device name")
    os: str = Field(default="", description="Operating system")
    criticality: str = Field(default="", description="Asset criticality")
    business_unit: str = Field(default="", description="Business unit")
    owner: str = Field(default="", description="Asset owner")
    segment: str = Field(default="", description="Network segment")
    business_process: str = Field(default="", description="Business process")
    compliance: str = Field(default="", description="Compliance notes")


class UserContext(BaseModel):
    """User context from identity systems."""

    username: str = Field(default="", description="Username")
    role: str = Field(default="", description="User role")
    department: str = Field(default="", description="User department")
    risk_score: Optional[float] = Field(None, description="User risk score (0-1)")


class AssetContext(BaseModel):
    """Combined asset context."""

    host: Optional[HostContext] = None
    user: Optional[UserContext] = None


class HostVulnerability(BaseModel):
    """Vulnerability on a specific host."""

    asset: str = Field(default="", description="Asset name")
    cve: str = Field(default="", description="CVE identifier")
    severity: str = Field(
        default="", description="Severity (critical, high, medium, low)"
    )
    exploited_in_the_wild: bool = Field(default=False)
    notes: str = Field(default="")


class EnvironmentExposure(BaseModel):
    """Environment-wide exposure assessment (for CVE-led signals)."""

    vulnerable_assets_count: Optional[int] = None
    highest_exposure_severity: str = Field(default="")
    known_exploited_exposure: Optional[bool] = None
    summary: str = Field(default="")
    sample_assets: List[str] = Field(default_factory=list)


class RelatedEvent(BaseModel):
    """A correlated event for the timeline."""

    timestamp_utc: str = Field(default="", description="Event timestamp (ISO format)")
    source: str = Field(default="", description="Event source/system")
    summary: str = Field(default="", description="Event summary")
    relevance: str = Field(default="", description="Why this event is relevant")


class EnrichmentNotes(BaseModel):
    """Data gaps and assumptions from enrichment."""

    data_gaps: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)


class EnrichmentBundle(BaseModel):
    """Complete enrichment bundle for the report.

    This is `r.enrich` in the template.
    """

    # Correlation summary
    correlation_summary: str = Field(
        default="", description="One-line correlation summary"
    )

    # Local sightings (indicator correlation in environment)
    local_sightings: List[LocalSighting] = Field(default_factory=list)

    # Scope assessment
    scope: Optional[ScopeAssessment] = Field(
        default=None, description="Scope/spread assessment"
    )

    # Threat intelligence per indicator
    threat_intel: Dict[str, ThreatIntelEntry] = Field(
        default_factory=dict,
        description="TI per indicator: {indicator: ThreatIntelEntry}",
    )
    ti_summary: str = Field(default="", description="One-line TI summary")

    # Asset context
    asset_context: Optional[AssetContext] = Field(default=None)

    # Host vulnerabilities
    host_vulns: List[HostVulnerability] = Field(default_factory=list)

    # Environment exposure (CVE-led)
    env_exposure: Optional[EnvironmentExposure] = Field(default=None)

    # Related events timeline
    related_events: List[RelatedEvent] = Field(default_factory=list)
    timeline_interpretation: str = Field(
        default="", description="Timeline interpretation"
    )

    # Notes on data quality
    notes: Optional[EnrichmentNotes] = Field(default=None)


# =============================================================================
# EXECUTIVE SUMMARY (r.exec)
# =============================================================================


class ExecutiveSummary(BaseModel):
    """Executive/stakeholder summary context.

    This is `r.exec` in the template (optional).
    """

    business_process: str = Field(default="", description="Affected business process")
    potential_impact: str = Field(default="", description="Potential business impact")
    external_impact: str = Field(default="", description="External/customer impact")
    compliance_notes: str = Field(default="", description="Compliance implications")


# =============================================================================
# REPORT METADATA (r.meta)
# =============================================================================


class ReportMeta(BaseModel):
    """Report metadata.

    This is `r.meta` in the template.
    """

    generated_utc: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="Report generation timestamp (ISO format)",
    )
    triage_owner: str = Field(default="Automated", description="Triage owner/analyst")
    tool_version: str = Field(default="1.0.0", description="SOC Triage Bot version")
    status: Optional[str] = Field(
        default=None,
        description="Case status: OPEN, CLOSED, IN_PROGRESS"
    )
    closed_utc: Optional[str] = Field(
        default=None,
        description="Closure timestamp for resolved cases"
    )
    playbook_ref: Optional[str] = Field(
        default=None,
        description="Playbook ID used for triage (e.g., RB-MAL-003)"
    )


# =============================================================================
# NORMALIZED SIGNAL (r.signal)
# =============================================================================


class NormalizedSignal(BaseModel):
    """Normalized signal for template rendering.

    This is `r.signal` in the template - flattened for easy access.
    """

    id: str = Field(..., description="Signal ID")
    type: str = Field(..., description="Signal type (SIEM_ALERT, IOC, etc.)")
    source: str = Field(default="", description="Signal source system")
    name: str = Field(default="", description="Signal name/title")
    category: str = Field(default="", description="Signal category")
    timestamp_utc: str = Field(default="", description="Signal timestamp (ISO format)")
    raw: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw signal payload for audit",
    )


# =============================================================================
# TRIAGE REPORT (Top-Level Container)
# =============================================================================


class TriageReport(BaseModel):
    """Top-level triage report container.

    This is the `r` object passed to the template with all sections:
    - r.signal: Normalized signal
    - r.meta: Report metadata
    - r.ctx: Signal context (entities, indicators, CVEs)
    - r.classification: Classification result with MITRE
    - r.forecast: Multi-track ETS forecasts
    - r.enrich: Enrichment bundle (TI, scope, timeline, etc.)
    - r.similar_cases: Structured similar cases
    - r.recommendations: SOC runbook actions
    - r.exec: Executive summary (optional)
    """

    # Required sections
    signal: NormalizedSignal = Field(..., description="Normalized signal")
    meta: ReportMeta = Field(default_factory=ReportMeta, description="Report metadata")

    # Signal context
    ctx: SignalContext = Field(
        default_factory=lambda: SignalContext(), description="Extracted signal context"
    )

    # Classification
    classification: ClassificationResult = Field(
        ..., description="Classification result"
    )

    # Forecasting (multi-track ETS)
    forecast: ForecastBundle = Field(
        default_factory=lambda: ForecastBundle(),
        description="Multi-track forecast bundle",
    )

    # Enrichment
    enrich: EnrichmentBundle = Field(
        default_factory=lambda: EnrichmentBundle(), description="Enrichment bundle"
    )

    # Similar cases
    similar_cases: List[SimilarCase] = Field(
        default_factory=list, description="Similar historical cases"
    )

    # Recommendations
    recommendations: List[Recommendation] = Field(
        default_factory=list, description="SOC runbook recommendations"
    )

    # Executive summary (optional)
    exec: Optional[ExecutiveSummary] = Field(
        default=None, description="Executive/stakeholder summary"
    )
    
    # Tuning recommendations (for FP cases)
    tuning: Optional[List[TuningRecommendation]] = Field(
        default=None,
        description="Tuning recommendations for FP cases"
    )
    
    # Lessons learned
    lessons_learned: Optional[List[str]] = Field(
        default=None,
        description="Lessons learned for case closure"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "signal": {
                    "id": "sig-12345",
                    "type": "SIEM_ALERT",
                    "source": "Splunk",
                    "name": "Suspicious PowerShell Execution",
                    "category": "Malware",
                    "timestamp_utc": "2025-12-14T02:34:00Z",
                },
                "meta": {
                    "generated_utc": "2025-12-14T02:40:00Z",
                    "triage_owner": "Automated",
                    "tool_version": "1.0.0",
                },
                "classification": {
                    "disposition": "TRUE_POSITIVE",
                    "tp_likelihood": 0.87,
                    "severity": "high",
                    "confidence": "high",
                    "incident_type": "Credential Theft",
                    "mitre": {
                        "tactics": ["Execution", "Credential Access"],
                        "techniques": ["T1059.001", "T1003"],
                    },
                    "reasons_tp": [
                        "IP known malicious in 2 TI sources",
                        "Encoded PowerShell matches Cobalt Strike",
                    ],
                    "reasons_fp": ["User is admin with elevated privileges"],
                    "triage_judgment": "High confidence TP based on TI match and attack pattern.",
                },
            }
        }


# =============================================================================
# FORECAST ENTITY MAP (Signal Type -> Track Configuration)
# =============================================================================


class TrackEntityConfig(BaseModel):
    """Entity keys for a single track."""

    entity_keys: List[str] = Field(
        default_factory=list,
        description="Entity keys to extract for this track (e.g., ['rule_id', 'rule_name'])",
    )
    metric_prefix: str = Field(
        default="", description="Metric key prefix for this track"
    )


class SignalTypeTrackConfig(BaseModel):
    """Track configuration for a signal type."""

    track_a: TrackEntityConfig = Field(
        default_factory=TrackEntityConfig,
        description="Track A (Rule/Detection) config",
    )
    track_b: TrackEntityConfig = Field(
        default_factory=TrackEntityConfig,
        description="Track B (Indicator/IOC) config",
    )
    track_c: TrackEntityConfig = Field(
        default_factory=TrackEntityConfig,
        description="Track C (Entity Behavior) config",
    )
    preferred_entity_focus: str = Field(
        default="",
        description="Default entity focus for Track C (e.g., 'hostname', 'username')",
    )


# Default configurations per signal type
SIGNAL_TYPE_TRACK_CONFIGS: Dict[str, SignalTypeTrackConfig] = {
    "SIEM_ALERT": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["rule_id", "rule_name"],
            metric_prefix="rule",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["src_ip", "dst_ip", "domain", "hash"],
            metric_prefix="indicator",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["hostname", "username"],
            metric_prefix="entity",
        ),
        preferred_entity_focus="hostname",
    ),
    "IOC": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["ti_source", "feed_name"],
            metric_prefix="feed",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["ioc_type", "ioc_value"],
            metric_prefix="ioc",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["hostname", "src_ip"],
            metric_prefix="sighting_host",
        ),
        preferred_entity_focus="ioc_value",
    ),
    "CVE": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["cve_id", "scanner"],
            metric_prefix="cve",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["exploit_available", "epss_score"],
            metric_prefix="exploit",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["hostname", "asset_criticality"],
            metric_prefix="asset",
        ),
        preferred_entity_focus="hostname",
    ),
    "EDR_DETECTION": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["detection_id", "detection_name"],
            metric_prefix="detection",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["process_hash", "command_line_hash"],
            metric_prefix="behavior",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["hostname", "username"],
            metric_prefix="endpoint",
        ),
        preferred_entity_focus="hostname",
    ),
    "EMAIL_SECURITY_ALERT": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["rule_id", "rule_name"],
            metric_prefix="email_rule",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["sender_domain", "attachment_hash", "url"],
            metric_prefix="email_ioc",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["recipient", "sender"],
            metric_prefix="mailbox",
        ),
        preferred_entity_focus="recipient",
    ),
    "HUNT": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["hunt_id", "hypothesis"],
            metric_prefix="hunt",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["query_hash", "detection_logic"],
            metric_prefix="hunt_query",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["hostname", "username"],
            metric_prefix="hunt_entity",
        ),
        preferred_entity_focus="hostname",
    ),
    "USER_REPORT": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["report_type", "category"],
            metric_prefix="report",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["reported_ioc", "attachment_hash"],
            metric_prefix="reported_ioc",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["reporter", "affected_user"],
            metric_prefix="reporter",
        ),
        preferred_entity_focus="reporter",
    ),
    "VULNERABILITY_ALERT": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["scanner", "scan_policy"],
            metric_prefix="scan",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["cve_id", "plugin_id"],
            metric_prefix="vuln",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["hostname", "asset_group"],
            metric_prefix="vuln_asset",
        ),
        preferred_entity_focus="hostname",
    ),
    "TI_INDICATOR": SignalTypeTrackConfig(
        track_a=TrackEntityConfig(
            entity_keys=["feed_name", "ti_source"],
            metric_prefix="ti_feed",
        ),
        track_b=TrackEntityConfig(
            entity_keys=["indicator_type", "indicator_value"],
            metric_prefix="ti_ioc",
        ),
        track_c=TrackEntityConfig(
            entity_keys=["sighting_host", "sighting_user"],
            metric_prefix="ti_sighting",
        ),
        preferred_entity_focus="indicator_value",
    ),
}


def get_track_config(signal_type: str) -> SignalTypeTrackConfig:
    """Get track configuration for a signal type.

    Args:
        signal_type: Signal type (e.g., 'SIEM_ALERT', 'IOC')

    Returns:
        Track configuration for the signal type, or default SIEM_ALERT config.
    """
    return SIGNAL_TYPE_TRACK_CONFIGS.get(
        signal_type.upper(),
        SIGNAL_TYPE_TRACK_CONFIGS["SIEM_ALERT"],
    )
