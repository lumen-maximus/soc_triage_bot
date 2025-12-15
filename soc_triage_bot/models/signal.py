"""Signal data models for normalized security events.

Extended for multi-track ETS forecasting with structured context fields
for Track A (detection), Track B (indicators), and Track C (entity behavior).
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class SignalType(str, Enum):
    """Types of security signals.

    Extended to cover all enterprise use cases for multi-track forecasting.
    """

    # Core signal types
    SIEM_ALERT = "siem_alert"
    IOC = "ioc"
    CVE = "cve"
    HUNT = "hunt"
    USER_REPORT = "user_report"

    # Extended signal types
    EDR_DETECTION = "edr_detection"
    EMAIL_SECURITY_ALERT = "email_security_alert"
    TI_INDICATOR = "ti_indicator"
    VULNERABILITY_ALERT = "vulnerability_alert"
    HUNT_FINDING = "hunt_finding"


# =============================================================================
# CONTEXT MODELS FOR MULTI-TRACK FORECASTING
# =============================================================================


class DetectionContext(BaseModel):
    """Track A context: Detection/rule information.

    Used for forecasting rule-level trends (how often does this rule fire?).
    """

    rule_id: Optional[str] = Field(None, description="Detection rule ID")
    rule_name: Optional[str] = Field(None, description="Detection rule name")
    analytic_family: Optional[str] = Field(None, description="Analytic family/category")
    detection_name: Optional[str] = Field(
        None, description="Detection name (EDR-specific)"
    )
    policy_id: Optional[str] = Field(None, description="Policy ID for EDR/vuln scans")
    technique_id: Optional[str] = Field(None, description="MITRE technique ID if known")


class ArtifactContext(BaseModel):
    """Track B context: Indicator/artifact information.

    Used for forecasting IOC sighting trends.
    """

    # Hashes
    sha256: Optional[str] = None
    sha1: Optional[str] = None
    md5: Optional[str] = None

    # Network indicators
    domain: Optional[str] = None
    ip: Optional[str] = None
    url: Optional[str] = None

    # Process/execution indicators
    process_name: Optional[str] = None
    cmdline_hash: Optional[str] = Field(
        None, description="Hash of command line for dedup"
    )

    # Email indicators
    sender_domain: Optional[str] = None
    attachment_hash: Optional[str] = None

    # Generic indicator list (for any type)
    indicator_list: Dict[str, str] = Field(
        default_factory=dict,
        description="Additional indicators: {type: value}",
    )


class EntityBehaviorContext(BaseModel):
    """Track C context: Entity behavior information.

    Used for forecasting entity-level anomalies (is this host/user behaving unusually?).
    """

    # Host/device entities
    hostname: Optional[str] = None
    device_id: Optional[str] = None
    asset_id: Optional[str] = None

    # User entities
    username: Optional[str] = None
    service_account: Optional[str] = None
    upn: Optional[str] = Field(None, description="User Principal Name")

    # Network entities
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    # Email entities
    recipient: Optional[str] = None
    sender: Optional[str] = None

    # Primary entity for Track C focus
    primary_entity_type: Optional[str] = Field(
        None, description="Primary entity type for Track C (hostname, username, etc.)"
    )
    primary_entity_value: Optional[str] = Field(
        None, description="Primary entity value"
    )


class VulnerabilityContext(BaseModel):
    """Vulnerability-specific context for CVE/vuln signals."""

    cve: Optional[str] = Field(None, description="CVE identifier")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    product: Optional[str] = Field(None, description="Affected product")
    vendor: Optional[str] = Field(None, description="Vendor name")
    service: Optional[str] = Field(None, description="Affected service")
    exposure_class: Optional[str] = Field(
        None, description="internet, internal, isolated"
    )
    asset_group: Optional[str] = Field(None, description="Asset group/segment")
    known_exploited: bool = Field(default=False, description="In CISA KEV or similar")
    exploit_available: bool = Field(default=False, description="Public exploit exists")


class SignalSource(BaseModel):
    """Source information for a signal."""

    system: str = Field(..., description="Source system (splunk, crowdstrike, etc.)")
    instance: Optional[str] = Field(None, description="Instance/tenant name")
    rule_id: Optional[str] = Field(None, description="Rule ID (for SIEM/EDR)")
    rule_name: Optional[str] = Field(None, description="Rule name")
    feed_name: Optional[str] = Field(None, description="TI feed name (for TI signals)")
    scanner: Optional[str] = Field(None, description="Scanner name (for vuln signals)")


class Signal(BaseModel):
    """Normalized security signal schema.

    Extended with structured context for multi-track ETS forecasting:
    - detection_context: Track A (rule/detection frequency)
    - artifact_context: Track B (indicator/IOC sightings)
    - entity_context: Track C (entity behavior)
    - vuln_context: CVE/vulnerability-specific data
    """

    signal_id: str = Field(..., description="Unique identifier for the signal")
    signal_type: SignalType
    timestamp: datetime
    source: SignalSource

    # Core fields
    title: str
    description: str
    severity: str = Field(..., description="low, medium, high, critical")

    # =========================================================================
    # MULTI-TRACK FORECASTING CONTEXT
    # =========================================================================
    detection_context: Optional[DetectionContext] = Field(
        None, description="Track A: Detection/rule context"
    )
    artifact_context: Optional[ArtifactContext] = Field(
        None, description="Track B: Indicator/artifact context"
    )
    entity_context: Optional[EntityBehaviorContext] = Field(
        None, description="Track C: Entity behavior context"
    )
    vuln_context: Optional[VulnerabilityContext] = Field(
        None, description="Vulnerability-specific context"
    )

    # Entity and indicator fields (also used as fallback for multi-track)
    entities: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Entities involved (ip, hostname, user, process, file, etc.)",
    )
    indicators: Dict[str, str] = Field(
        default_factory=dict,
        description="Indicators/IOCs (ip, domain, hash, url, email, etc.)",
    )

    # Signal-specific data
    raw_data: Dict[str, Any] = Field(
        default_factory=dict, description="Original signal data"
    )

    # Metadata
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # =========================================================================
    # HELPER METHODS FOR TRACK ENTITY EXTRACTION
    # =========================================================================
    def get_track_a_key(self) -> Optional[str]:
        """Get primary key for Track A (rule/detection)."""
        if self.detection_context:
            return (
                self.detection_context.rule_id
                or self.detection_context.detection_name
                or self.detection_context.policy_id
            )
        return self.source.rule_id

    def get_track_b_keys(self) -> Dict[str, str]:
        """Get keys for Track B (indicators/IOCs)."""
        result = {}
        if self.artifact_context:
            if self.artifact_context.sha256:
                result["sha256"] = self.artifact_context.sha256
            if self.artifact_context.md5:
                result["md5"] = self.artifact_context.md5
            if self.artifact_context.domain:
                result["domain"] = self.artifact_context.domain
            if self.artifact_context.ip:
                result["ip"] = self.artifact_context.ip
            if self.artifact_context.url:
                result["url"] = self.artifact_context.url
            if self.artifact_context.process_name:
                result["process_name"] = self.artifact_context.process_name
            if self.artifact_context.cmdline_hash:
                result["cmdline_hash"] = self.artifact_context.cmdline_hash
            result.update(self.artifact_context.indicator_list)
        # Fallback to legacy indicators
        if not result and self.indicators:
            result = dict(self.indicators)
        return result

    def get_track_c_entity(self) -> Optional[tuple]:
        """Get primary entity for Track C (entity behavior).

        Returns:
            Tuple of (entity_type, entity_value) or None
        """
        if self.entity_context:
            if self.entity_context.primary_entity_type:
                return (
                    self.entity_context.primary_entity_type,
                    self.entity_context.primary_entity_value,
                )
            # Auto-select based on available data
            if self.entity_context.hostname:
                return ("hostname", self.entity_context.hostname)
            if self.entity_context.username:
                return ("username", self.entity_context.username)
            if self.entity_context.device_id:
                return ("device_id", self.entity_context.device_id)
            if self.entity_context.src_ip:
                return ("src_ip", self.entity_context.src_ip)
        # Fallback to legacy entities
        if self.entities:
            for entity_type in ["hostname", "user", "device", "ip"]:
                if entity_type in self.entities and self.entities[entity_type]:
                    return (entity_type, self.entities[entity_type][0])
        return None
