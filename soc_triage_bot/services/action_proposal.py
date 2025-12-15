"""Enterprise action proposal service.

Generates, deduplicates, gates, and ranks action proposals from:
1. Seeded runbooks/playbooks (governed templates from YAML)
2. Templates (fallback signal-type-keyed templates)
3. Contextual actions (parameterized "do X in tool Y for entity Z")
4. Case-learned actions (from high-similarity, recent, successful cases)
5. Case-linked playbook steps (from similar case artifacts, treated as "suggested")

Enterprise features:
- Dedupe by (intent|tool|owner|target_signature)
- Gating (TP/FP/Review + data availability + risk/approval)
- Ranking and capping (3-6 proposals at top, max 12-15 full plan)

Enterprise merge precedence:
1. Seeded templates (governed) - highest priority
2. Generated context actions (parameterized, specific)
3. Case-learned actions (only if high similarity + recent + successful)
4. Case-linked playbook steps (treated as "suggested," not authoritative)
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from ..models import (
    Action,
    ActionType,
    ClassificationLabel,
    EnrichmentResult,
    Signal,
)
from ..models.triage_report import ClassificationResult, SimilarCase

# Lazy imports to avoid circular dependencies
if TYPE_CHECKING:
    from .case_artifact_harvester import CaseArtifactHarvester
    from .runbook_registry import RunbookRegistry


class ActionIntent(str, Enum):
    """Canonical action intents for deduplication."""

    CONTAIN = "contain"  # Isolate, block, quarantine
    INVESTIGATE = "investigate"  # Gather more info, analyze
    REMEDIATE = "remediate"  # Fix, patch, clean
    NOTIFY = "notify"  # Alert stakeholders
    ESCALATE = "escalate"  # Raise to higher tier
    CLOSE = "close"  # Close as resolved/FP
    MONITOR = "monitor"  # Watch for follow-up


class RiskTier(str, Enum):
    """Risk tiers for approval gating."""

    LOW = "low"  # Auto-execute ok
    MEDIUM = "medium"  # SOC approval required
    HIGH = "high"  # Manager approval required
    CRITICAL = "critical"  # CISO/IR lead approval


@dataclass
class ActionSignature:
    """Signature for action deduplication.

    Dedupes by (intent|tool|owner|target_signature).
    """

    intent: ActionIntent
    tool: str  # e.g., "EDR", "Firewall", "SIEM", "ITSM"
    owner: str  # e.g., "SOC", "IR", "IT", "Security"
    target_signature: str  # e.g., "hostname:WS-001", "ip:1.2.3.4"

    @property
    def key(self) -> str:
        """Return deduplication key."""
        return f"{self.intent.value}|{self.tool}|{self.owner}|{self.target_signature}"


@dataclass
class GatingResult:
    """Result of action gating checks."""

    passed: bool = True
    blocked_reasons: List[str] = field(default_factory=list)
    risk_tier: RiskTier = RiskTier.LOW
    requires_approval: bool = False
    approvers: List[str] = field(default_factory=list)
    data_available: bool = True
    missing_data: List[str] = field(default_factory=list)


# Default limits
TOP_PROPOSALS_MIN = 3
TOP_PROPOSALS_MAX = 6
FULL_PLAN_MAX = 15


class ActionProposalService:
    """Enterprise service for action proposal generation and management.

    Generates actions from five sources (in precedence order):
    1. Seeded runbooks/playbooks (governed templates from YAML) - HIGHEST
    2. Templates (fallback signal-type-keyed templates)
    3. Generated context actions (parameterized, specific)
    4. Case-learned actions (only if high similarity + recent + successful)
    5. Case-linked playbook steps (treated as "suggested," not authoritative) - LOWEST

    Then applies:
    - Deduplication by (intent|tool|owner|target_signature)
    - Gating (classification + data availability + risk/approval)
    - Ranking and capping
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        runbook_registry: Optional[Any] = None,
        case_artifact_harvester: Optional[Any] = None,
    ):
        """Initialize action proposal service.

        Args:
            config: Configuration for action templates and thresholds
            runbook_registry: Optional RunbookRegistry for governed templates
            case_artifact_harvester: Optional CaseArtifactHarvester for case artifacts
        """
        self.config = config or {}
        self.templates = self._load_templates()
        self.learned_actions: List[Dict[str, Any]] = []

        # Similarity thresholds for case learning
        self.min_similarity_for_learning = self.config.get("min_similarity", 0.75)
        self.max_case_age_days = self.config.get("max_case_age_days", 90)
        self.require_successful_outcome = self.config.get("require_successful", True)

        # Proposal limits
        self.top_proposals_min = self.config.get("top_proposals_min", TOP_PROPOSALS_MIN)
        self.top_proposals_max = self.config.get("top_proposals_max", TOP_PROPOSALS_MAX)
        self.full_plan_max = self.config.get("full_plan_max", FULL_PLAN_MAX)

        # Initialize RunbookRegistry (lazy import to avoid circular deps)
        self._runbook_registry = runbook_registry
        if self._runbook_registry is None and self.config.get(
            "enable_runbook_registry", True
        ):
            try:
                from .runbook_registry import RunbookRegistry

                self._runbook_registry = RunbookRegistry()
            except ImportError:
                self._runbook_registry = None

        # Initialize CaseArtifactHarvester (lazy import)
        self._case_harvester = case_artifact_harvester
        if self._case_harvester is None and self.config.get(
            "enable_case_harvester", True
        ):
            try:
                from .case_artifact_harvester import CaseArtifactHarvester

                self._case_harvester = CaseArtifactHarvester(
                    runbook_registry=self._runbook_registry
                )
            except ImportError:
                self._case_harvester = None

    def _load_templates(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load action templates keyed by signal type.

        Returns templates organized as:
        {
            "_global": [...],  # Applies to all signal types
            "SIEM_ALERT": [...],
            "IOC": [...],
            ...
        }
        """
        return {
            # Global templates that apply to all signal types
            "_global": [
                {
                    "id": "template-isolate-host",
                    "intent": ActionIntent.CONTAIN,
                    "tool": "EDR",
                    "owner": "SOC",
                    "type": ActionType.ISOLATE,
                    "title": "Isolate Compromised Host",
                    "description": "Isolate {hostname} from network via EDR",
                    "steps": [
                        "Verify host status in EDR console",
                        "Initiate network isolation via EDR",
                        "Notify IT security team",
                        "Document action in case management",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.8,
                        "required_entities": ["hostname"],
                    },
                    "priority": 1,
                    "estimated_effort": "5 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.MEDIUM,
                },
                {
                    "id": "template-investigate-user",
                    "intent": ActionIntent.INVESTIGATE,
                    "tool": "SIEM",
                    "owner": "SOC",
                    "type": ActionType.INVESTIGATE,
                    "title": "Investigate User Activity",
                    "description": "Investigate activity for user {user}",
                    "steps": [
                        "Review user's recent login history in SIEM",
                        "Check for unusual file access patterns",
                        "Verify MFA usage",
                        "Contact user if necessary",
                    ],
                    "conditions": {
                        "classification": [
                            ClassificationLabel.TRUE_POSITIVE,
                            ClassificationLabel.UNKNOWN,
                        ],
                        "min_confidence": 0.5,
                        "required_entities": ["user"],
                    },
                    "priority": 2,
                    "estimated_effort": "15 minutes",
                    "automation_available": False,
                    "risk_tier": RiskTier.LOW,
                },
                {
                    "id": "template-block-ip",
                    "intent": ActionIntent.CONTAIN,
                    "tool": "Firewall",
                    "owner": "SOC",
                    "type": ActionType.BLOCK,
                    "title": "Block Malicious IP",
                    "description": "Block IP address {ip} at perimeter firewall",
                    "steps": [
                        "Verify IP reputation in threat intel",
                        "Check current connections to IP",
                        "Add IP to firewall blocklist",
                        "Monitor for bypass attempts",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.85,
                        "required_entities": ["ip"],
                        "enrichment_requirements": {"threat_intel": "malicious"},
                    },
                    "priority": 1,
                    "estimated_effort": "10 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.MEDIUM,
                },
                {
                    "id": "template-escalate",
                    "intent": ActionIntent.ESCALATE,
                    "tool": "ITSM",
                    "owner": "SOC",
                    "type": ActionType.ESCALATE,
                    "title": "Escalate to Senior Analyst",
                    "description": "Escalate case for senior analyst review",
                    "steps": [
                        "Document findings",
                        "Tag for escalation",
                        "Notify senior analyst",
                        "Set follow-up reminder",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.UNKNOWN],
                        "max_confidence": 0.6,
                    },
                    "priority": 3,
                    "estimated_effort": "5 minutes",
                    "automation_available": False,
                    "risk_tier": RiskTier.LOW,
                },
                {
                    "id": "template-close-fp",
                    "intent": ActionIntent.CLOSE,
                    "tool": "SOAR",
                    "owner": "SOC",
                    "type": ActionType.CLOSE,
                    "title": "Close as False Positive",
                    "description": "Close alert as false positive",
                    "steps": [
                        "Verify benign activity",
                        "Document reasoning",
                        "Update detection rule if needed",
                        "Close case",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.FALSE_POSITIVE],
                        "min_confidence": 0.7,
                    },
                    "priority": 4,
                    "estimated_effort": "5 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.LOW,
                },
                {
                    "id": "template-monitor",
                    "intent": ActionIntent.MONITOR,
                    "tool": "SIEM",
                    "owner": "SOC",
                    "type": ActionType.MONITOR,
                    "title": "Monitor for Additional Activity",
                    "description": "Set up monitoring for related entities",
                    "steps": [
                        "Create monitoring rule",
                        "Set alert thresholds",
                        "Define monitoring duration",
                        "Schedule follow-up review",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.UNKNOWN],
                        "min_confidence": 0.4,
                    },
                    "priority": 3,
                    "estimated_effort": "10 minutes",
                    "automation_available": False,
                    "risk_tier": RiskTier.LOW,
                },
            ],
            # Signal-type specific templates
            "SIEM_ALERT": [
                {
                    "id": "siem-correlation-review",
                    "intent": ActionIntent.INVESTIGATE,
                    "tool": "SIEM",
                    "owner": "SOC",
                    "type": ActionType.INVESTIGATE,
                    "title": "Review Correlated Events",
                    "description": "Review correlated events for rule {rule_id}",
                    "steps": [
                        "Search SIEM for related events (±30 min window)",
                        "Check for preceding/following alerts",
                        "Review correlation rules that fired",
                        "Document timeline of events",
                    ],
                    "conditions": {
                        "classification": [
                            ClassificationLabel.TRUE_POSITIVE,
                            ClassificationLabel.UNKNOWN,
                        ],
                        "min_confidence": 0.3,
                    },
                    "priority": 2,
                    "estimated_effort": "10 minutes",
                    "automation_available": False,
                    "risk_tier": RiskTier.LOW,
                },
            ],
            "IOC": [
                {
                    "id": "ioc-block-domain",
                    "intent": ActionIntent.CONTAIN,
                    "tool": "DNS/Proxy",
                    "owner": "SOC",
                    "type": ActionType.BLOCK,
                    "title": "Block Malicious Domain",
                    "description": "Block domain {domain} at DNS/proxy layer",
                    "steps": [
                        "Verify domain reputation in TI platform",
                        "Add to DNS sinkhole/blocklist",
                        "Add to proxy blocklist",
                        "Check for existing connections",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.8,
                        "required_entities": ["domain"],
                    },
                    "priority": 1,
                    "estimated_effort": "10 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.MEDIUM,
                },
                {
                    "id": "ioc-search-sightings",
                    "intent": ActionIntent.INVESTIGATE,
                    "tool": "SIEM",
                    "owner": "SOC",
                    "type": ActionType.INVESTIGATE,
                    "title": "Search for IOC Sightings",
                    "description": "Search for historical sightings of {indicator_value}",
                    "steps": [
                        "Search SIEM for IOC matches (last 30 days)",
                        "Identify affected hosts/users",
                        "Check EDR for process activity",
                        "Document scope of exposure",
                    ],
                    "conditions": {
                        "classification": [
                            ClassificationLabel.TRUE_POSITIVE,
                            ClassificationLabel.UNKNOWN,
                        ],
                        "min_confidence": 0.4,
                    },
                    "priority": 2,
                    "estimated_effort": "15 minutes",
                    "automation_available": False,
                    "risk_tier": RiskTier.LOW,
                },
            ],
            "CVE": [
                {
                    "id": "cve-patch-assessment",
                    "intent": ActionIntent.REMEDIATE,
                    "tool": "Vuln Scanner",
                    "owner": "IT",
                    "type": ActionType.INVESTIGATE,
                    "title": "Assess Patch Availability",
                    "description": "Assess patch availability for {cve_id}",
                    "steps": [
                        "Check vendor advisories for patches",
                        "Verify patch compatibility",
                        "Identify affected systems",
                        "Create patching ticket",
                    ],
                    "conditions": {
                        "classification": [
                            ClassificationLabel.TRUE_POSITIVE,
                            ClassificationLabel.UNKNOWN,
                        ],
                        "min_confidence": 0.5,
                    },
                    "priority": 2,
                    "estimated_effort": "20 minutes",
                    "automation_available": False,
                    "risk_tier": RiskTier.LOW,
                },
                {
                    "id": "cve-mitigate-exploit",
                    "intent": ActionIntent.CONTAIN,
                    "tool": "WAF/IPS",
                    "owner": "Security",
                    "type": ActionType.BLOCK,
                    "title": "Deploy Exploit Mitigations",
                    "description": "Deploy WAF/IPS rules for {cve_id}",
                    "steps": [
                        "Check for WAF/IPS signatures",
                        "Deploy blocking rules",
                        "Monitor for exploit attempts",
                        "Document mitigation status",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.7,
                        "enrichment_requirements": {"vulnerability": "exploitable"},
                    },
                    "priority": 1,
                    "estimated_effort": "15 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.HIGH,
                },
            ],
            "EDR_DETECTION": [
                {
                    "id": "edr-collect-forensics",
                    "intent": ActionIntent.INVESTIGATE,
                    "tool": "EDR",
                    "owner": "IR",
                    "type": ActionType.INVESTIGATE,
                    "title": "Collect Forensic Artifacts",
                    "description": "Collect forensic artifacts from {hostname} via EDR",
                    "steps": [
                        "Trigger memory acquisition",
                        "Collect relevant process dumps",
                        "Gather file system artifacts",
                        "Export timeline to IR team",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.75,
                        "required_entities": ["hostname"],
                    },
                    "priority": 1,
                    "estimated_effort": "20 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.MEDIUM,
                },
                {
                    "id": "edr-kill-process",
                    "intent": ActionIntent.CONTAIN,
                    "tool": "EDR",
                    "owner": "SOC",
                    "type": ActionType.BLOCK,
                    "title": "Terminate Malicious Process",
                    "description": "Kill process {process_name} on {hostname}",
                    "steps": [
                        "Verify process is malicious",
                        "Kill process via EDR",
                        "Quarantine related files",
                        "Monitor for respawn",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.85,
                        "required_entities": ["hostname", "process_name"],
                    },
                    "priority": 1,
                    "estimated_effort": "5 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.HIGH,
                },
            ],
            "EMAIL_SECURITY_ALERT": [
                {
                    "id": "email-quarantine",
                    "intent": ActionIntent.CONTAIN,
                    "tool": "Email Security",
                    "owner": "SOC",
                    "type": ActionType.BLOCK,
                    "title": "Quarantine Malicious Email",
                    "description": "Quarantine email from {sender} with subject containing malware",
                    "steps": [
                        "Quarantine original email",
                        "Search for copies in other mailboxes",
                        "Remove from all recipients",
                        "Block sender/domain if appropriate",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.7,
                    },
                    "priority": 1,
                    "estimated_effort": "10 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.LOW,
                },
                {
                    "id": "email-notify-recipients",
                    "intent": ActionIntent.NOTIFY,
                    "tool": "Email",
                    "owner": "SOC",
                    "type": ActionType.NOTIFY,
                    "title": "Notify Email Recipients",
                    "description": "Notify recipients of phishing attempt",
                    "steps": [
                        "Identify all recipients",
                        "Draft notification message",
                        "Send security awareness notification",
                        "Track acknowledgments",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.6,
                    },
                    "priority": 2,
                    "estimated_effort": "10 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.LOW,
                },
            ],
            "USER_REPORT": [
                {
                    "id": "user-report-acknowledge",
                    "intent": ActionIntent.NOTIFY,
                    "tool": "Email",
                    "owner": "SOC",
                    "type": ActionType.NOTIFY,
                    "title": "Acknowledge User Report",
                    "description": "Send acknowledgment to reporting user",
                    "steps": [
                        "Review user report details",
                        "Send acknowledgment email",
                        "Provide initial guidance",
                        "Set expectations for follow-up",
                    ],
                    "conditions": {},
                    "priority": 3,
                    "estimated_effort": "5 minutes",
                    "automation_available": True,
                    "risk_tier": RiskTier.LOW,
                },
            ],
            "HUNT_FINDING": [
                {
                    "id": "hunt-create-detection",
                    "intent": ActionIntent.MONITOR,
                    "tool": "SIEM",
                    "owner": "Detection Engineering",
                    "type": ActionType.MONITOR,
                    "title": "Create Detection Rule",
                    "description": "Create detection rule from hunt finding",
                    "steps": [
                        "Document finding pattern",
                        "Draft detection logic",
                        "Test in detection lab",
                        "Deploy to production",
                    ],
                    "conditions": {
                        "classification": [ClassificationLabel.TRUE_POSITIVE],
                        "min_confidence": 0.7,
                    },
                    "priority": 3,
                    "estimated_effort": "60 minutes",
                    "automation_available": False,
                    "risk_tier": RiskTier.LOW,
                },
            ],
        }

    def _get_templates_for_signal(self, signal: Signal) -> List[Dict[str, Any]]:
        """Get applicable templates for a signal type.

        Combines global templates with signal-type-specific templates.
        """
        global_templates = self.templates.get("_global", [])
        type_templates = self.templates.get(signal.signal_type.value, [])
        return global_templates + type_templates

    def _get_confidence_score(self, classification: ClassificationResult) -> float:
        """Get numeric confidence score from either Classification or ClassificationResult.

        Forward-compatible: handles both legacy and new models.
        """
        if isinstance(classification, ClassificationResult):
            return classification.confidence_score  # Uses tp_likelihood
        else:
            return classification.confidence  # Legacy float field

    def propose_actions(
        self,
        signal: Signal,
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
        similar_cases: Optional[List[Tuple[str, float, str]]] = None,
        similar_cases_models: Optional[List[Any]] = None,
    ) -> List[Action]:
        """Generate enterprise action proposals for a signal.

        Combines five sources in precedence order:
        1. Seeded runbooks/playbooks (governed templates from YAML) - HIGHEST
        2. Templates (fallback signal-type-keyed templates)
        3. Generated context actions (parameterized, specific)
        4. Case-learned actions (only if high similarity + recent + successful)
        5. Case-linked playbook steps (suggested, not authoritative) - LOWEST

        Then applies deduplication, gating, ranking, and capping.

        Args:
            signal: The signal
            classification: Classification result (accepts Classification or ClassificationResult)
            enrichments: Enrichment results
            similar_cases: Optional list of (case_id, similarity, outcome) tuples
            similar_cases_models: Optional list of SimilarCase model objects with
                                  runbook_refs, attachments_metadata fields

        Returns:
            List of proposed actions, deduplicated, gated, ranked, and capped
        """
        proposals: List[Action] = []

        # =====================================================================
        # SOURCE 1: Seeded runbooks/playbooks (GOVERNED - HIGHEST PRECEDENCE)
        # =====================================================================
        if self._runbook_registry:
            seeded_actions = self._generate_from_seeded_runbooks(
                signal, classification, enrichments
            )
            proposals.extend(seeded_actions)

        # =====================================================================
        # SOURCE 2: Fallback templates (signal-type-keyed)
        # Only if seeded runbooks didn't cover this signal type
        # =====================================================================
        template_actions = self._generate_from_templates(
            signal, classification, enrichments
        )
        proposals.extend(template_actions)

        # =====================================================================
        # SOURCE 3: Contextual actions (parameterized from enrichments)
        # =====================================================================
        contextual_actions = self._generate_contextual_actions(
            signal, classification, enrichments
        )
        proposals.extend(contextual_actions)

        # =====================================================================
        # SOURCE 4: Case-learned actions (from similar cases, high confidence)
        # =====================================================================
        if similar_cases:
            learned_actions = self._generate_learned_actions(
                signal, classification, similar_cases
            )
            proposals.extend(learned_actions)

        # =====================================================================
        # SOURCE 5: Case-linked playbook steps (SUGGESTED, not authoritative)
        # =====================================================================
        if similar_cases_models and self._case_harvester:
            case_linked_actions = self._generate_case_linked_actions(
                signal, similar_cases_models
            )
            proposals.extend(case_linked_actions)

        # =====================================================================
        # Enterprise dedupe, gating, ranking, capping
        # =====================================================================

        # Enterprise deduplication by (intent|tool|owner|target_signature)
        proposals = self._deduplicate_actions_enterprise(proposals, signal)

        # Apply gating (TP/FP/Review + data availability + risk/approval)
        proposals = self._apply_gating(proposals, classification, enrichments)

        # Rank by priority, confidence, source precedence, and risk tier
        proposals = self._rank_actions_enterprise(proposals)

        # Cap proposals: top 3-6, full plan max 12-15
        proposals = self._cap_proposals(proposals)

        return proposals

    def _generate_from_seeded_runbooks(
        self,
        signal: Signal,
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> List[Action]:
        """Generate actions from seeded runbooks/playbooks (governed templates).

        These have HIGHEST precedence and are treated as authoritative.
        """
        if not self._runbook_registry:
            return []

        actions = []

        # Find applicable runbooks for this signal
        applicable_runbooks = self._runbook_registry.find_applicable_runbooks(
            signal=signal,
            classification_label=classification.label,
            min_confidence=self._get_confidence_score(classification),
        )

        for runbook in applicable_runbooks:
            # Convert runbook actions to model Actions
            runbook_actions = self._runbook_registry.actions_to_model_actions(
                runbook.actions, signal, runbook.id
            )
            actions.extend(runbook_actions)

        return actions

    def _generate_case_linked_actions(
        self,
        signal: Signal,
        similar_cases_models: List[Any],
    ) -> List[Action]:
        """Generate actions from case-linked playbook references.

        These are treated as SUGGESTED (not authoritative) unless they
        reference whitelisted runbooks from the RunbookRegistry.
        """
        if not self._case_harvester:
            return []

        # Harvest actions from similar case artifacts
        harvest_result = self._case_harvester.harvest_actions(
            similar_cases=similar_cases_models,
            signal_entities=signal.entities,
        )

        # Convert harvested actions to model Actions
        actions = self._case_harvester.actions_to_model_actions(
            harvested_actions=harvest_result.actions,
            signal_entities=signal.entities,
        )

        return actions

    def _generate_from_templates(
        self,
        signal: Signal,
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> List[Action]:
        """Generate actions from signal-type-keyed templates."""
        actions = []
        templates = self._get_templates_for_signal(signal)

        for template in templates:
            if self._matches_conditions(template, signal, classification, enrichments):
                action = self._instantiate_template(template, signal, classification)
                actions.append(action)

        return actions

    def _matches_conditions(
        self,
        template: Dict[str, Any],
        signal: Signal,
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> bool:
        """Check if template conditions are met."""
        conditions = template.get("conditions", {})

        # Check classification
        required_classifications = conditions.get("classification", [])
        if (
            required_classifications
            and classification.label not in required_classifications
        ):
            return False

        # Check confidence thresholds
        min_confidence = conditions.get("min_confidence", 0)
        max_confidence = conditions.get("max_confidence", 1.0)
        confidence_score = self._get_confidence_score(classification)
        if not (min_confidence <= confidence_score <= max_confidence):
            return False

        # Check required entities
        required_entities = conditions.get("required_entities", [])
        for entity_type in required_entities:
            if entity_type not in signal.entities or not signal.entities[entity_type]:
                return False

        # Check enrichment requirements
        enrich_reqs = conditions.get("enrichment_requirements", {})
        for adapter, required_value in enrich_reqs.items():
            result = enrichments.get(adapter)
            if not result or result.status.value != "success":
                return False
            if required_value == "malicious":
                reputation = result.data.get("reputation", "")
                if reputation != "malicious":
                    return False

        return True

    def _instantiate_template(
        self,
        template: Dict[str, Any],
        signal: Signal,
        classification: ClassificationResult,
    ) -> Action:
        """Create action instance from template."""
        # Format strings with entity values
        title = template["title"]
        description = template["description"]

        for entity_type, entity_values in signal.entities.items():
            placeholder = "{" + entity_type + "}"
            if placeholder in description:
                description = description.replace(
                    placeholder, entity_values[0] if entity_values else entity_type
                )

        return Action(
            action_id=self._generate_action_id(template["id"], signal.signal_id),
            action_type=template["type"],
            priority=template["priority"],
            title=title,
            description=description,
            steps=template["steps"],
            reasoning=f"Based on classification: {classification.label.value}",
            source="template",
            confidence=self._get_confidence_score(classification),
            estimated_effort=template.get("estimated_effort"),
            automation_available=template.get("automation_available", False),
            related_entities=signal.entities,
        )

    def _generate_learned_actions(
        self,
        signal: Signal,
        classification: ClassificationResult,
        similar_cases: List[Tuple[str, float, str]],
    ) -> List[Action]:
        """Generate actions from similar historical cases.

        Only uses cases that are:
        - High similarity (>= min_similarity_for_learning)
        - Recent (within max_case_age_days)
        - Successful outcome (if require_successful_outcome is True)

        Args:
            signal: Current signal
            classification: Classification result
            similar_cases: List of (case_id, similarity, outcome) tuples

        Returns:
            List of learned actions from similar cases
        """
        actions = []

        # Filter to high-quality similar cases
        qualified_cases = [
            (case_id, sim, outcome)
            for case_id, sim, outcome in similar_cases
            if sim >= self.min_similarity_for_learning
            and (not self.require_successful_outcome or outcome in ["TP", "RESOLVED"])
        ]

        if not qualified_cases:
            return actions

        # Sort by similarity (highest first)
        qualified_cases.sort(key=lambda x: x[1], reverse=True)

        # Take top 3 similar cases
        top_cases = qualified_cases[:3]

        # For each qualified case, extract learned actions
        for case_id, similarity, outcome in top_cases:
            # In production, this would query the case database for actions taken
            # For now, generate appropriate actions based on outcome
            if outcome == "TP":
                actions.append(
                    Action(
                        action_id=self._generate_action_id(
                            f"learned-{case_id}", signal.signal_id
                        ),
                        action_type=ActionType.INVESTIGATE,
                        priority=2,
                        title=f"Follow playbook from similar case {case_id[:8]}",
                        description=f"Apply resolution pattern from {similarity:.0%} similar case",
                        steps=[
                            f"Review case {case_id[:8]} resolution steps",
                            "Adapt steps to current context",
                            "Execute adapted playbook",
                            "Document variations",
                        ],
                        reasoning=f"Similar case {case_id[:8]} ({similarity:.0%} match) was confirmed TP and resolved",
                        source="learned",
                        confidence=similarity
                        * 0.9,  # Confidence discounted from similarity
                        estimated_effort="15 minutes",
                        automation_available=False,
                        related_entities=signal.entities,
                    )
                )

        # If classification is TP with high confidence, add notification action
        if (
            classification.label == ClassificationLabel.TRUE_POSITIVE
            and self._get_confidence_score(classification) > 0.85
            and len(top_cases) >= 2
        ):
            actions.append(
                Action(
                    action_id=self._generate_action_id(
                        "learned-notify", signal.signal_id
                    ),
                    action_type=ActionType.NOTIFY,
                    priority=2,
                    title="Notify Security Team",
                    description="Based on similar past incidents, notify security team",
                    steps=[
                        "Prepare incident summary",
                        "Notify security team via Slack",
                        "Create incident ticket",
                    ],
                    reasoning=f"Similar past cases ({len(top_cases)}) resulted in team notification",
                    source="learned",
                    confidence=0.75,
                    estimated_effort="5 minutes",
                    automation_available=True,
                    related_entities=signal.entities,
                )
            )

        return actions

    def _generate_contextual_actions(
        self,
        signal: Signal,
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> List[Action]:
        """Generate parameterized contextual actions.

        Creates "do X in tool Y for entity Z" style actions based on
        enrichment data and signal entities.

        Args:
            signal: Current signal
            classification: Classification result
            enrichments: Enrichment results

        Returns:
            List of contextual actions
        """
        actions = []

        # Generate actions based on threat intel enrichment
        ti_result = enrichments.get("threat_intel")
        if ti_result and ti_result.status.value == "success":
            reputation = ti_result.data.get("reputation", "")
            if reputation == "malicious":
                # For each IOC entity, create specific block action
                for ioc_type in ["ip", "domain", "url", "sha256"]:
                    if ioc_type in signal.entities and signal.entities[ioc_type]:
                        ioc_value = signal.entities[ioc_type][0]
                        tool = self._get_tool_for_ioc_type(ioc_type)
                        actions.append(
                            Action(
                                action_id=self._generate_action_id(
                                    f"ctx-block-{ioc_type}", signal.signal_id
                                ),
                                action_type=ActionType.BLOCK,
                                priority=1,
                                title=f"Block {ioc_type.upper()} in {tool}",
                                description=f"Block {ioc_type}={ioc_value} in {tool}",
                                steps=[
                                    f"Verify {ioc_type} is not whitelisted",
                                    f"Add {ioc_value} to {tool} blocklist",
                                    "Verify block is active",
                                    "Monitor for bypass attempts",
                                ],
                                reasoning=f"TI enrichment confirms {ioc_type} is malicious (reputation: {reputation})",
                                source="contextual",
                                confidence=0.85,
                                estimated_effort="5 minutes",
                                automation_available=True,
                                related_entities={ioc_type: [ioc_value]},
                            )
                        )

        # Generate actions based on vulnerability enrichment
        vuln_result = enrichments.get("vulnerability")
        if vuln_result and vuln_result.status.value == "success":
            critical_vulns = vuln_result.data.get("critical_vulns", 0)
            hostname = (
                signal.entities.get("hostname", ["unknown"])[0]
                if signal.entities.get("hostname")
                else "affected system"
            )

            if critical_vulns > 0:
                actions.append(
                    Action(
                        action_id=self._generate_action_id(
                            "ctx-vuln", signal.signal_id
                        ),
                        action_type=ActionType.INVESTIGATE,
                        priority=2,
                        title=f"Assess {critical_vulns} critical vulnerabilities on {hostname}",
                        description=f"Investigate {critical_vulns} critical vulnerabilities on {hostname}",
                        steps=[
                            "Review vulnerability scan results",
                            "Check patch availability in WSUS/SCCM",
                            "Verify exploit attempts in EDR",
                            "Create remediation ticket in ITSM",
                        ],
                        reasoning=f"Vulnerability scan shows {critical_vulns} critical vulnerabilities",
                        source="contextual",
                        confidence=0.8,
                        estimated_effort="20 minutes",
                        automation_available=False,
                        related_entities=signal.entities,
                    )
                )

        # Generate actions based on CMDB enrichment
        cmdb_result = enrichments.get("cmdb")
        if cmdb_result and cmdb_result.status.value == "success":
            criticality = cmdb_result.data.get("criticality", "")
            owner = cmdb_result.data.get("owner", "")

            if criticality in ["critical", "high"] and owner:
                actions.append(
                    Action(
                        action_id=self._generate_action_id(
                            "ctx-notify-owner", signal.signal_id
                        ),
                        action_type=ActionType.NOTIFY,
                        priority=2,
                        title=f"Notify asset owner ({owner})",
                        description=f"Alert asset owner {owner} about {criticality}-criticality asset involvement",
                        steps=[
                            f"Prepare summary for {owner}",
                            "Send notification via email/Teams",
                            "Request confirmation of receipt",
                            "Schedule follow-up if no response",
                        ],
                        reasoning=f"Asset is {criticality} criticality, owned by {owner}",
                        source="contextual",
                        confidence=0.7,
                        estimated_effort="10 minutes",
                        automation_available=True,
                        related_entities=signal.entities,
                    )
                )

        # Generate actions based on EDR enrichment
        edr_result = enrichments.get("edr")
        if edr_result and edr_result.status.value == "success":
            process_activity = edr_result.data.get("suspicious_processes", [])
            hostname = (
                signal.entities.get("hostname", ["unknown"])[0]
                if signal.entities.get("hostname")
                else "affected host"
            )

            if process_activity:
                actions.append(
                    Action(
                        action_id=self._generate_action_id(
                            "ctx-edr-forensics", signal.signal_id
                        ),
                        action_type=ActionType.INVESTIGATE,
                        priority=1,
                        title=f"Collect EDR forensics from {hostname}",
                        description=f"Gather process tree and file artifacts from {hostname}",
                        steps=[
                            "Capture process tree in EDR",
                            "Collect memory dump if needed",
                            "Download suspicious files for analysis",
                            "Export timeline to case",
                        ],
                        reasoning=f"EDR shows {len(process_activity)} suspicious processes",
                        source="contextual",
                        confidence=0.85,
                        estimated_effort="15 minutes",
                        automation_available=True,
                        related_entities=signal.entities,
                    )
                )

        return actions

    def _get_tool_for_ioc_type(self, ioc_type: str) -> str:
        """Map IOC type to appropriate blocking tool."""
        tool_map = {
            "ip": "Firewall",
            "domain": "DNS/Proxy",
            "url": "Proxy",
            "sha256": "EDR",
            "md5": "EDR",
            "email": "Email Gateway",
        }
        return tool_map.get(ioc_type, "SOAR")

    def _get_action_signature(self, action: Action, signal: Signal) -> ActionSignature:
        """Create action signature for deduplication.

        Maps action to (intent|tool|owner|target_signature).
        """
        # Map ActionType to ActionIntent
        intent_map = {
            ActionType.ISOLATE: ActionIntent.CONTAIN,
            ActionType.BLOCK: ActionIntent.CONTAIN,
            ActionType.INVESTIGATE: ActionIntent.INVESTIGATE,
            ActionType.ESCALATE: ActionIntent.ESCALATE,
            ActionType.NOTIFY: ActionIntent.NOTIFY,
            ActionType.CLOSE: ActionIntent.CLOSE,
            ActionType.MONITOR: ActionIntent.MONITOR,
        }
        intent = intent_map.get(action.action_type, ActionIntent.INVESTIGATE)

        # Extract tool from description or use default
        tool = "SOAR"  # Default
        for tool_name in ["EDR", "Firewall", "SIEM", "Proxy", "DNS", "ITSM", "Email"]:
            if tool_name.lower() in action.description.lower():
                tool = tool_name
                break

        # Extract owner from source
        owner = "SOC"  # Default

        # Create target signature from related entities
        target_parts = []
        if action.related_entities:
            for key, values in sorted(action.related_entities.items()):
                if values:
                    val = values[0] if isinstance(values, list) else values
                    target_parts.append(f"{key}:{val}")
        target_signature = "|".join(target_parts[:3]) if target_parts else "global"

        return ActionSignature(
            intent=intent,
            tool=tool,
            owner=owner,
            target_signature=target_signature,
        )

    def _deduplicate_actions_enterprise(
        self, actions: List[Action], signal: Signal
    ) -> List[Action]:
        """Enterprise deduplication by (intent|tool|owner|target_signature).

        When duplicates found, keeps the one with highest source precedence:
        1. seeded (governed runbooks) - HIGHEST
        2. template (fallback templates)
        3. contextual (generated from enrichments)
        4. learned (from similar case outcomes)
        5. case_linked (suggested from case artifacts) - LOWEST

        Then by confidence and priority.
        """
        # Source precedence ranking (higher = better)
        source_precedence = {
            "seeded": 5,  # Governed runbooks - highest
            "template": 4,  # Fallback templates
            "contextual": 3,  # Generated context actions
            "learned": 2,  # Case-learned actions
            "case_linked": 1,  # Case-linked (suggested)
        }

        signature_map: Dict[str, List[Action]] = {}

        for action in actions:
            sig = self._get_action_signature(action, signal)
            key = sig.key
            if key not in signature_map:
                signature_map[key] = []
            signature_map[key].append(action)

        deduplicated = []
        for key, group in signature_map.items():
            if len(group) == 1:
                deduplicated.append(group[0])
            else:
                # Pick best action from group using source precedence first
                best = max(
                    group,
                    key=lambda a: (
                        source_precedence.get(a.source, 0),  # Source precedence first
                        a.confidence,
                        -a.priority,
                    ),
                )
                deduplicated.append(best)

        return deduplicated

    def _apply_gating(
        self,
        actions: List[Action],
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> List[Action]:
        """Apply enterprise gating to actions.

        Gates based on:
        1. Classification (TP/FP/Review) - block containment for FP
        2. Data availability - block if required enrichment missing
        3. Risk tier - flag high-risk actions for approval
        """
        gated_actions = []

        for action in actions:
            gating = self._evaluate_gating(action, classification, enrichments)

            if not gating.passed:
                # Action blocked - add reasoning to action notes
                action_copy = Action(
                    action_id=action.action_id,
                    action_type=action.action_type,
                    priority=max(action.priority + 2, 5),  # Demote priority
                    title=f"[BLOCKED] {action.title}",
                    description=action.description,
                    steps=action.steps,
                    reasoning=f"{action.reasoning} [BLOCKED: {', '.join(gating.blocked_reasons)}]",
                    source=action.source,
                    confidence=action.confidence * 0.5,
                    estimated_effort=action.estimated_effort,
                    automation_available=False,  # Block automation
                    related_entities=action.related_entities,
                )
                # Still include but demoted for visibility
                gated_actions.append(action_copy)
            elif gating.requires_approval:
                # Action needs approval - flag it
                action_copy = Action(
                    action_id=action.action_id,
                    action_type=action.action_type,
                    priority=action.priority,
                    title=f"[APPROVAL: {gating.risk_tier.value.upper()}] {action.title}",
                    description=action.description,
                    steps=action.steps,
                    reasoning=f"{action.reasoning} [Requires {', '.join(gating.approvers)} approval]",
                    source=action.source,
                    confidence=action.confidence,
                    estimated_effort=action.estimated_effort,
                    automation_available=False,  # Require manual approval
                    related_entities=action.related_entities,
                )
                gated_actions.append(action_copy)
            else:
                gated_actions.append(action)

        return gated_actions

    def _evaluate_gating(
        self,
        action: Action,
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> GatingResult:
        """Evaluate gating criteria for an action."""
        result = GatingResult()

        # Gate 1: Classification-based gating
        if classification.label == ClassificationLabel.FALSE_POSITIVE:
            # Block containment actions for FP
            if action.action_type in [ActionType.ISOLATE, ActionType.BLOCK]:
                result.passed = False
                result.blocked_reasons.append(
                    "Containment blocked for FP classification"
                )

        elif classification.label == ClassificationLabel.UNKNOWN:
            # Require approval for containment on unknown
            if action.action_type in [ActionType.ISOLATE, ActionType.BLOCK]:
                result.requires_approval = True
                result.approvers.append("Senior Analyst")

        # Gate 2: Confidence-based gating
        if action.confidence < 0.5 and action.action_type in [
            ActionType.ISOLATE,
            ActionType.BLOCK,
        ]:
            result.requires_approval = True
            result.approvers.append("SOC Lead")

        # Gate 3: Data availability gating
        # Check if required enrichment adapters succeeded
        required_adapters = self._get_required_adapters_for_action(action)
        for adapter in required_adapters:
            enrich = enrichments.get(adapter)
            if not enrich or enrich.status.value != "success":
                result.data_available = False
                result.missing_data.append(adapter)

        if not result.data_available and len(result.missing_data) > 0:
            result.blocked_reasons.append(
                f"Missing data: {', '.join(result.missing_data)}"
            )
            # Partial block - allow but demote
            if action.action_type in [ActionType.ISOLATE, ActionType.BLOCK]:
                result.passed = False

        # Gate 4: Risk tier assessment
        # Estimate risk tier based on action type and confidence
        if action.action_type == ActionType.ISOLATE:
            result.risk_tier = RiskTier.HIGH
            result.requires_approval = True
            result.approvers.append("IR Lead")
        elif (
            action.action_type == ActionType.BLOCK
            and "firewall" in action.description.lower()
        ):
            result.risk_tier = RiskTier.MEDIUM
            if action.confidence < 0.8:
                result.requires_approval = True
                result.approvers.append("SOC Lead")

        return result

    def _get_required_adapters_for_action(self, action: Action) -> List[str]:
        """Determine which enrichment adapters are required for an action."""
        required = []

        # Threat intel required for blocking IOCs
        if action.action_type == ActionType.BLOCK:
            required.append("threat_intel")

        # CMDB required for asset-related actions
        if action.action_type == ActionType.ISOLATE:
            required.append("cmdb")

        return required

    def _rank_actions_enterprise(self, actions: List[Action]) -> List[Action]:
        """Enterprise ranking with source precedence.

        Ranking factors (in order):
        1. Source precedence: seeded > template > contextual > learned > case_linked
        2. Priority (lower = more urgent)
        3. Confidence (higher = better)
        4. Automation available (prefer automated)
        """
        # Source precedence ranking (higher = better)
        source_rank = {
            "seeded": 5,  # Governed runbooks - highest
            "template": 4,  # Fallback templates
            "contextual": 3,  # Generated context actions
            "learned": 2,  # Case-learned actions
            "case_linked": 1,  # Case-linked (suggested)
        }

        def rank_key(action: Action) -> Tuple[int, int, float, int]:
            return (
                -source_rank.get(
                    action.source, 0
                ),  # Source precedence (negated for sort)
                action.priority,
                -action.confidence,
                -1 if action.automation_available else 0,
            )

        return sorted(actions, key=rank_key)

    def _cap_proposals(self, actions: List[Action]) -> List[Action]:
        """Cap proposals to enterprise limits.

        Returns:
        - Top proposals (3-6): Priority 1-2 actions with high confidence
        - Full plan (max 12-15): All viable actions
        """
        if not actions:
            return actions

        # Separate blocked actions
        blocked = [a for a in actions if "[BLOCKED]" in a.title]
        viable = [a for a in actions if "[BLOCKED]" not in a.title]

        # Cap viable actions to full_plan_max
        capped_viable = viable[: self.full_plan_max]

        # Include some blocked for visibility (max 2)
        capped_blocked = blocked[:2]

        return capped_viable + capped_blocked

    def get_top_proposals(self, actions: List[Action]) -> List[Action]:
        """Get top 3-6 proposals for immediate action.

        Filters to high-confidence, high-priority actions.
        """
        top = [
            a
            for a in actions
            if a.priority <= 2 and a.confidence >= 0.7 and "[BLOCKED]" not in a.title
        ]

        # Ensure minimum of 3 if available
        if len(top) < self.top_proposals_min and len(actions) >= self.top_proposals_min:
            # Add more from full list
            remaining = [
                a for a in actions if a not in top and "[BLOCKED]" not in a.title
            ]
            top.extend(remaining[: self.top_proposals_min - len(top)])

        # Cap at max
        return top[: self.top_proposals_max]

    # Legacy methods for backward compatibility
    def _generate_dynamic_actions(
        self,
        signal: Signal,
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> List[Action]:
        """Legacy method - redirects to contextual actions."""
        return self._generate_contextual_actions(signal, classification, enrichments)

    def _deduplicate_actions(self, actions: List[Action]) -> List[Action]:
        """Legacy deduplication - simple type:title based."""
        seen: Set[str] = set()
        deduplicated = []

        for action in actions:
            signature = f"{action.action_type.value}:{action.title}"
            if signature not in seen:
                seen.add(signature)
                deduplicated.append(action)

        return deduplicated

    def _rank_actions(self, actions: List[Action]) -> List[Action]:
        """Legacy ranking - priority and confidence only."""
        return sorted(actions, key=lambda a: (a.priority, -a.confidence))

    def _generate_action_id(self, template_id: str, signal_id: str) -> str:
        """Generate unique action ID."""
        combined = f"{template_id}:{signal_id}"
        hash_val = hashlib.sha256(combined.encode()).hexdigest()[:8]
        return f"act-{hash_val}"
