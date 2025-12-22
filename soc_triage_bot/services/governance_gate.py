"""GovernanceGate - Action gating and approval workflow.

Extracted from ActionProposalService to be a standalone CKG service.
Evaluates actions against governance policies and determines:
- Auto-execute: Safe, low-risk actions
- Requires approval: High-risk actions needing human review
- Blocked: Actions blocked by policy (e.g., containment on FP)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List

from soc_triage_bot.models import Action, ActionType
from soc_triage_bot.models.enrichment import EnrichmentResult
from soc_triage_bot.models.triage_report import ClassificationResult


class RiskTier(str, Enum):
    """Risk tier for action gating."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GatingResult:
    """Result of governance gating evaluation."""

    passed: bool = True
    requires_approval: bool = False
    data_available: bool = True
    blocked_reasons: List[str] = field(default_factory=list)
    missing_data: List[str] = field(default_factory=list)
    approvers: List[str] = field(default_factory=list)
    risk_tier: RiskTier = RiskTier.LOW


@dataclass
class GovernanceDecisionResult:
    """Result of full governance decision."""

    auto_execute: List[Action] = field(default_factory=list)
    requires_approval: List[Action] = field(default_factory=list)
    blocked: List[Action] = field(default_factory=list)
    auto_close: bool = False
    auto_close_reason: str = ""


class GovernanceGate:
    """Governance gate for action approval workflow.

    Implements enterprise governance policies:
    1. Classification-based gating (block containment on FP)
    2. Confidence thresholds (require approval for low confidence)
    3. Data availability gating (block if enrichment failed)
    4. Risk tier assessment (escalate high-risk actions)
    5. Auto-close policies (close FP cases automatically)
    """

    def __init__(
        self,
        auto_close_fp: bool = True,
        auto_execute_confidence_threshold: float = 0.8,
        high_risk_approval_required: bool = True,
    ):
        """Initialize governance gate.

        Args:
            auto_close_fp: Auto-close cases classified as FP
            auto_execute_confidence_threshold: Min confidence for auto-execute
            high_risk_approval_required: Require approval for high-risk actions
        """
        self.auto_close_fp = auto_close_fp
        self.auto_execute_threshold = auto_execute_confidence_threshold
        self.high_risk_approval_required = high_risk_approval_required

    def evaluate(
        self,
        actions: List[Action],
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> GovernanceDecisionResult:
        """Evaluate actions against governance policies.

        Args:
            actions: Proposed actions
            classification: Classification result
            enrichments: Enrichment results by adapter

        Returns:
            GovernanceDecisionResult with actions categorized
        """
        result = GovernanceDecisionResult()

        # Check auto-close policy
        if self.auto_close_fp and classification.disposition == "FALSE_POSITIVE":
            tp_likelihood = getattr(classification, "tp_likelihood", 0.0)
            if tp_likelihood <= 0.1:  # High confidence FP
                result.auto_close = True
                result.auto_close_reason = (
                    f"High confidence FP (TP likelihood: {tp_likelihood:.2f})"
                )
                return result  # No actions needed if auto-closing

        # Evaluate each action
        for action in actions:
            gating = self._evaluate_gating(action, classification, enrichments)

            if not gating.passed:
                # Blocked by policy
                action_copy = self._mark_blocked(action, gating)
                result.blocked.append(action_copy)

            elif gating.requires_approval:
                # Requires human approval
                action_copy = self._mark_approval_required(action, gating)
                result.requires_approval.append(action_copy)

            else:
                # Auto-execute allowed
                result.auto_execute.append(action)

        return result

    def _evaluate_gating(
        self,
        action: Action,
        classification: ClassificationResult,
        enrichments: Dict[str, EnrichmentResult],
    ) -> GatingResult:
        """Evaluate gating criteria for an action."""
        result = GatingResult()

        # Gate 1: Classification-based gating
        if classification.disposition == "FALSE_POSITIVE":
            # Block containment actions for FP
            if action.action_type in [ActionType.ISOLATE, ActionType.BLOCK]:
                result.passed = False
                result.blocked_reasons.append(
                    "Containment blocked for FP classification"
                )

        elif classification.disposition in ["NEEDS_REVIEW", "UNKNOWN"]:
            # Require approval for containment on unknown
            if action.action_type in [ActionType.ISOLATE, ActionType.BLOCK]:
                result.requires_approval = True
                result.approvers.append("Senior Analyst")

        # Gate 2: Confidence-based gating
        if action.confidence < self.auto_execute_threshold:
            if action.action_type in [ActionType.ISOLATE, ActionType.BLOCK]:
                result.requires_approval = True
                result.approvers.append("SOC Lead")

        # Gate 3: Data availability gating
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
        if action.action_type == ActionType.ISOLATE:
            result.risk_tier = RiskTier.HIGH
            if self.high_risk_approval_required:
                result.requires_approval = True
                result.approvers.append("IR Lead")

        elif action.action_type == ActionType.BLOCK:
            if "firewall" in action.description.lower():
                result.risk_tier = RiskTier.MEDIUM
            else:
                result.risk_tier = RiskTier.HIGH

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

    def _mark_blocked(self, action: Action, gating: GatingResult) -> Action:
        """Mark action as blocked."""
        return Action(
            action_id=action.action_id,
            action_type=action.action_type,
            priority=action.priority,
            title=f"[BLOCKED] {action.title}",
            description=action.description,
            steps=action.steps,
            reasoning=f"{action.reasoning} [Blocked: {'; '.join(gating.blocked_reasons)}]",
            source=action.source,
            confidence=action.confidence,
            estimated_effort=action.estimated_effort,
            automation_available=False,
            related_entities=action.related_entities,
        )

    def _mark_approval_required(self, action: Action, gating: GatingResult) -> Action:
        """Mark action as requiring approval."""
        return Action(
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
