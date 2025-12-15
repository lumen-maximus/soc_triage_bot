"""CaseArtifactHarvester capability for extracting runbook/playbook refs from similar cases.

Given similar cases from SOAR/historical data:
- Extract runbook/playbook references
- Optionally fetch attachments (policy-controlled)
- Summarize into structured action candidates

Enterprise merge rule: Case artifacts are treated as "suggested" not authoritative
unless they reference whitelisted runbooks from the RunbookRegistry.
"""

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..models import Action, ActionType
from ..models.triage_report import AttachmentMetadata, RunbookRef, SimilarCase


class ArtifactConfidenceLevel(str, Enum):
    """Confidence level for case-linked artifacts."""

    HIGH = "high"  # Whitelisted runbook, successful resolution
    MEDIUM = "medium"  # Non-whitelisted but successful resolution
    LOW = "low"  # FP/mixed outcomes or old cases
    SUGGESTED = "suggested"  # Just a suggestion, not authoritative


@dataclass
class HarvestedAction:
    """Action harvested from case artifacts.

    These are treated as "suggested" unless from whitelisted runbooks.
    """

    id: str
    title: str
    description: str
    intent: str
    tool: str
    owner: str
    steps: List[str] = field(default_factory=list)
    priority: int = 3  # Lower default priority than seeded templates
    source_case_id: str = ""
    source_runbook_ref: Optional[str] = None
    similarity: float = 0.0
    confidence_level: ArtifactConfidenceLevel = ArtifactConfidenceLevel.SUGGESTED
    is_whitelisted: bool = False


@dataclass
class HarvestResult:
    """Result of harvesting artifacts from similar cases."""

    actions: List[HarvestedAction] = field(default_factory=list)
    runbook_refs_found: List[RunbookRef] = field(default_factory=list)
    attachments_found: List[AttachmentMetadata] = field(default_factory=list)
    cases_analyzed: int = 0
    whitelisted_actions: int = 0
    suggested_actions: int = 0


class CaseArtifactHarvester:
    """Harvester for extracting action candidates from similar case artifacts.

    Capabilities:
    - extract_runbook_refs(similar_cases) -> List[RunbookRef]
    - harvest_actions(similar_cases, runbook_registry) -> HarvestResult
    - actions_to_model_actions(harvested, signal) -> List[Action]

    Enterprise rules:
    - High similarity (>= 0.75) + TP outcome = higher confidence
    - Whitelisted runbooks = treated as governed templates
    - Non-whitelisted = suggested only
    """

    def __init__(
        self,
        runbook_registry: Optional[Any] = None,
        soar_adapter: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize case artifact harvester.

        Args:
            runbook_registry: Optional RunbookRegistry for checking whitelisted runbooks
            soar_adapter: Optional SOAR adapter for fetching case details
            config: Configuration options
        """
        self.runbook_registry = runbook_registry
        self.soar_adapter = soar_adapter
        self.config = config or {}

        # Thresholds
        self.min_similarity_for_harvest = self.config.get("min_similarity", 0.65)
        self.high_similarity_threshold = self.config.get("high_similarity", 0.80)
        self.max_case_age_days = self.config.get("max_case_age_days", 180)
        self.max_actions_per_case = self.config.get("max_actions_per_case", 5)
        self.allow_attachment_fetch = self.config.get("allow_attachment_fetch", False)

    def extract_runbook_refs(
        self, similar_cases: List[SimilarCase]
    ) -> List[RunbookRef]:
        """Extract all runbook references from similar cases.

        Args:
            similar_cases: List of SimilarCase objects from similarity search

        Returns:
            Deduplicated list of RunbookRef objects
        """
        refs: Dict[str, RunbookRef] = {}

        for case in similar_cases:
            for ref in case.runbook_refs:
                if ref.ref_id not in refs:
                    refs[ref.ref_id] = ref

        return list(refs.values())

    def extract_attachments_metadata(
        self, similar_cases: List[SimilarCase]
    ) -> List[AttachmentMetadata]:
        """Extract attachment metadata from similar cases.

        Only includes attachments that appear to be playbooks/runbooks.

        Args:
            similar_cases: List of SimilarCase objects

        Returns:
            List of attachment metadata (content not fetched)
        """
        attachments: List[AttachmentMetadata] = []

        for case in similar_cases:
            for attach in case.attachments_metadata:
                # Only include playbook-like attachments
                if attach.is_playbook or attach.filename.endswith(
                    (".yaml", ".yml", ".md", ".json")
                ):
                    attachments.append(attach)

        return attachments

    def harvest_actions(
        self,
        similar_cases: List[SimilarCase],
        signal_entities: Optional[Dict[str, List[str]]] = None,
    ) -> HarvestResult:
        """Harvest action candidates from similar case artifacts.

        Args:
            similar_cases: List of SimilarCase objects with runbook_refs and actions_taken
            signal_entities: Optional entities for parameterization

        Returns:
            HarvestResult with harvested actions and metadata
        """
        result = HarvestResult()
        seen_action_keys: set = set()

        for case in similar_cases:
            result.cases_analyzed += 1

            # Determine confidence level based on case quality
            confidence_level = self._assess_case_confidence(case)

            # Extract actions from runbook refs
            for ref in case.runbook_refs:
                result.runbook_refs_found.append(ref)

                # Check if runbook is whitelisted
                is_whitelisted = self._is_runbook_whitelisted(ref)

                # Try to get actions from runbook
                runbook_actions = self._get_actions_from_runbook_ref(ref)

                for rb_action in runbook_actions:
                    action_key = f"{rb_action.get('intent')}|{rb_action.get('tool')}|{rb_action.get('title')}"
                    if action_key in seen_action_keys:
                        continue
                    seen_action_keys.add(action_key)

                    harvested = HarvestedAction(
                        id=self._generate_action_id(case.case_id, rb_action),
                        title=rb_action.get("title", ""),
                        description=rb_action.get("description", ""),
                        intent=rb_action.get("intent", "investigate"),
                        tool=rb_action.get("tool", "SOAR"),
                        owner=rb_action.get("owner", "SOC"),
                        steps=rb_action.get("steps", []),
                        priority=rb_action.get("priority", 3),
                        source_case_id=case.case_id,
                        source_runbook_ref=ref.ref_id,
                        similarity=self._get_case_similarity(case),
                        confidence_level=(
                            ArtifactConfidenceLevel.HIGH
                            if is_whitelisted
                            else confidence_level
                        ),
                        is_whitelisted=is_whitelisted,
                    )
                    result.actions.append(harvested)

                    if is_whitelisted:
                        result.whitelisted_actions += 1
                    else:
                        result.suggested_actions += 1

            # Extract actions from case actions_taken (if no runbook refs)
            if not case.runbook_refs and case.actions_taken:
                for action_str in case.actions_taken[: self.max_actions_per_case]:
                    action_key = f"actions_taken|{action_str}"
                    if action_key in seen_action_keys:
                        continue
                    seen_action_keys.add(action_key)

                    # Parse action string into structured action
                    harvested = self._parse_action_string(
                        action_str, case.case_id, confidence_level
                    )
                    if harvested:
                        result.actions.append(harvested)
                        result.suggested_actions += 1

            # Collect attachment metadata
            result.attachments_found.extend(case.attachments_metadata)

        return result

    def _assess_case_confidence(self, case: SimilarCase) -> ArtifactConfidenceLevel:
        """Assess confidence level for a case based on its attributes."""
        similarity = self._get_case_similarity(case)
        disposition = case.disposition.upper() if case.disposition else ""

        # High confidence: High similarity + TP/RESOLVED
        if similarity >= self.high_similarity_threshold and disposition in [
            "TP",
            "RESOLVED",
            "TRUE_POSITIVE",
        ]:
            return ArtifactConfidenceLevel.HIGH

        # Medium confidence: Decent similarity + successful outcome
        if similarity >= self.min_similarity_for_harvest and disposition in [
            "TP",
            "RESOLVED",
            "TRUE_POSITIVE",
        ]:
            return ArtifactConfidenceLevel.MEDIUM

        # Low confidence: FP or mixed outcomes
        if disposition in ["FP", "FALSE_POSITIVE"]:
            return ArtifactConfidenceLevel.LOW

        # Default to suggested
        return ArtifactConfidenceLevel.SUGGESTED

    def _get_case_similarity(self, case: SimilarCase) -> float:
        """Get similarity score from SimilarCase.

        SimilarCase might store similarity in different ways.
        """
        # Check for similarity attribute (added by similarity service)
        if hasattr(case, "similarity"):
            return getattr(case, "similarity", 0.0)
        return 0.5  # Default

    def _is_runbook_whitelisted(self, ref: RunbookRef) -> bool:
        """Check if a runbook reference is whitelisted.

        A runbook is whitelisted if:
        1. The ref explicitly marks it as whitelisted
        2. It exists in the RunbookRegistry (seeded templates)
        """
        if ref.whitelisted:
            return True

        if self.runbook_registry and hasattr(self.runbook_registry, "get_runbook"):
            runbook = self.runbook_registry.get_runbook(ref.ref_id)
            if runbook and runbook.whitelisted:
                return True

        return False

    def _get_actions_from_runbook_ref(self, ref: RunbookRef) -> List[Dict[str, Any]]:
        """Get actions from a runbook reference.

        Attempts to fetch from registry, then SOAR if available.
        """
        # Try registry first
        if self.runbook_registry and hasattr(self.runbook_registry, "get_runbook"):
            runbook = self.runbook_registry.get_runbook(ref.ref_id)
            if runbook:
                return [
                    {
                        "title": a.title,
                        "description": a.description,
                        "intent": (
                            a.intent.value if hasattr(a.intent, "value") else a.intent
                        ),
                        "tool": a.tool,
                        "owner": a.owner,
                        "steps": a.steps,
                        "priority": a.priority,
                    }
                    for a in runbook.actions
                ]

        # Try SOAR adapter if available
        if self.soar_adapter and hasattr(self.soar_adapter, "get_runbook_actions"):
            try:
                return self.soar_adapter.get_runbook_actions(ref.ref_id)
            except Exception:
                pass

        # Return empty if can't fetch
        return []

    def _parse_action_string(
        self,
        action_str: str,
        case_id: str,
        confidence_level: ArtifactConfidenceLevel,
    ) -> Optional[HarvestedAction]:
        """Parse a free-form action string into structured HarvestedAction.

        Attempts to extract intent, tool, owner from common patterns.
        """
        action_lower = action_str.lower()

        # Detect intent
        intent = "investigate"
        if any(
            w in action_lower for w in ["isolate", "contain", "block", "quarantine"]
        ):
            intent = "contain"
        elif any(w in action_lower for w in ["notify", "alert", "inform"]):
            intent = "notify"
        elif any(w in action_lower for w in ["escalate", "raise"]):
            intent = "escalate"
        elif any(w in action_lower for w in ["close", "resolve"]):
            intent = "close"
        elif any(w in action_lower for w in ["monitor", "watch"]):
            intent = "monitor"
        elif any(w in action_lower for w in ["remediate", "fix", "patch", "clean"]):
            intent = "remediate"

        # Detect tool
        tool = "SOAR"
        for t in ["EDR", "SIEM", "Firewall", "Proxy", "DNS", "Email", "IAM", "ITSM"]:
            if t.lower() in action_lower:
                tool = t
                break

        # Detect owner
        owner = "SOC"
        if "ir" in action_lower or "incident response" in action_lower:
            owner = "IR"
        elif "it " in action_lower or "operations" in action_lower:
            owner = "IT"

        return HarvestedAction(
            id=self._generate_action_id(case_id, {"title": action_str}),
            title=action_str[:100],  # Truncate if too long
            description=action_str,
            intent=intent,
            tool=tool,
            owner=owner,
            steps=[],  # No structured steps from free-form
            priority=4,  # Lower priority for unstructured
            source_case_id=case_id,
            confidence_level=confidence_level,
            is_whitelisted=False,
        )

    def _generate_action_id(self, case_id: str, action_data: Dict[str, Any]) -> str:
        """Generate unique action ID."""
        hash_input = (
            f"{case_id}:{action_data.get('title', '')}:{action_data.get('intent', '')}"
        )
        hash_val = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
        return f"harv-{hash_val}"

    def actions_to_model_actions(
        self,
        harvested_actions: List[HarvestedAction],
        signal_entities: Optional[Dict[str, List[str]]] = None,
    ) -> List[Action]:
        """Convert HarvestedActions to model Action objects.

        Enterprise rule: Mark all as "case_linked" source.
        Whitelisted actions get higher confidence.

        Args:
            harvested_actions: Actions harvested from cases
            signal_entities: Optional entities for parameterization

        Returns:
            List of Action model instances
        """
        actions = []

        # Map intent to ActionType
        intent_to_type = {
            "contain": ActionType.ISOLATE,
            "investigate": ActionType.INVESTIGATE,
            "remediate": ActionType.INVESTIGATE,
            "notify": ActionType.NOTIFY,
            "escalate": ActionType.ESCALATE,
            "close": ActionType.CLOSE,
            "monitor": ActionType.MONITOR,
        }

        for harvested in harvested_actions:
            action_type = intent_to_type.get(
                harvested.intent.lower(), ActionType.INVESTIGATE
            )

            # Determine confidence based on whitelisting and case quality
            if harvested.is_whitelisted:
                confidence = 0.85
                source = "seeded"  # Whitelisted = treat as seeded
            elif harvested.confidence_level == ArtifactConfidenceLevel.HIGH:
                confidence = 0.75
                source = "case_linked"
            elif harvested.confidence_level == ArtifactConfidenceLevel.MEDIUM:
                confidence = 0.60
                source = "case_linked"
            else:
                confidence = 0.45
                source = "case_linked"

            # Parameterize description if entities provided
            description = harvested.description
            if signal_entities:
                for entity_type, entity_values in signal_entities.items():
                    placeholder = "{" + entity_type + "}"
                    if placeholder in description and entity_values:
                        description = description.replace(placeholder, entity_values[0])

            # Mark as suggested if not whitelisted
            title = harvested.title
            if not harvested.is_whitelisted:
                title = f"[SUGGESTED] {title}"

            actions.append(
                Action(
                    action_id=harvested.id,
                    action_type=action_type,
                    priority=harvested.priority,
                    title=title,
                    description=description,
                    steps=harvested.steps,
                    reasoning=f"From similar case {harvested.source_case_id[:8]} ({harvested.similarity:.0%} match)",
                    source=source,
                    confidence=confidence,
                    estimated_effort="15 minutes",
                    automation_available=False,  # Case-linked not auto-executed
                    related_entities=signal_entities or {},
                )
            )

        return actions

    def get_harvest_summary(self, result: HarvestResult) -> Dict[str, Any]:
        """Get summary of harvest result for reporting.

        Args:
            result: HarvestResult from harvest_actions()

        Returns:
            Summary dictionary
        """
        return {
            "cases_analyzed": result.cases_analyzed,
            "total_actions": len(result.actions),
            "whitelisted_actions": result.whitelisted_actions,
            "suggested_actions": result.suggested_actions,
            "unique_runbooks": len(result.runbook_refs_found),
            "attachments_found": len(result.attachments_found),
            "action_breakdown": {
                "high_confidence": sum(
                    1
                    for a in result.actions
                    if a.confidence_level == ArtifactConfidenceLevel.HIGH
                ),
                "medium_confidence": sum(
                    1
                    for a in result.actions
                    if a.confidence_level == ArtifactConfidenceLevel.MEDIUM
                ),
                "low_confidence": sum(
                    1
                    for a in result.actions
                    if a.confidence_level == ArtifactConfidenceLevel.LOW
                ),
                "suggested": sum(
                    1
                    for a in result.actions
                    if a.confidence_level == ArtifactConfidenceLevel.SUGGESTED
                ),
            },
        }
