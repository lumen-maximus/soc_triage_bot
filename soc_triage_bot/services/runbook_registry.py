"""RunbookRegistry capability for fetching governed runbooks from SOAR.

Fetches runbooks from SOAR post-classification based on signal type and severity.
SOAR is the authoritative source for all governed runbooks.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ..models import Action, ActionType, ClassificationLabel, Signal
from ..models.triage_report import RunbookRef

if TYPE_CHECKING:
    from ..models.triage_report import ClassificationResult


class RunbookSource(str, Enum):
    """Source of runbook content."""

    SOAR_REFS = "soar_refs"  # Fetched from SOAR by ID
    WIKI = "wiki"  # Fetched from internal wiki
    CONFLUENCE = "confluence"  # Fetched from Confluence


class ActionIntent(str, Enum):
    """Canonical action intents matching action_proposal.py."""

    CONTAIN = "contain"
    INVESTIGATE = "investigate"
    REMEDIATE = "remediate"
    NOTIFY = "notify"
    ESCALATE = "escalate"
    CLOSE = "close"
    MONITOR = "monitor"


@dataclass
class RunbookAction:
    """Structured action from a runbook/playbook."""

    id: str
    intent: ActionIntent
    tool: str
    owner: str
    title: str
    description: str
    steps: List[str] = field(default_factory=list)
    priority: int = 2
    estimated_effort: str = "15 minutes"
    automation_available: bool = False
    risk_tier: str = "LOW"
    approval_required: bool = False
    approvers: List[str] = field(default_factory=list)


@dataclass
class Runbook:
    """Complete runbook/playbook with metadata and actions."""

    id: str
    version: str
    title: str
    description: str
    category: str
    signal_types: List[str]
    severity_levels: List[str]
    author: str
    approved_by: str
    approval_date: str
    review_cycle_days: int
    source: RunbookSource
    actions: List[RunbookAction]
    conditions: Dict[str, Any] = field(default_factory=dict)
    phases: Optional[List[Dict[str, Any]]] = None  # For phased playbooks
    environment_specific: bool = False
    whitelisted: bool = True  # Seeded runbooks are whitelisted by default


class RunbookRegistry:
    """Registry for SOAR-fetched runbooks/playbooks.

    Post-classification, fetches applicable runbooks from SOAR based on:
    - Signal type (phishing, malware, ransomware, insider threat, etc.)
    - Classification result (TP/FP/severity)
    - Organization-specific runbook IDs

    Note: Similar case runbooks come from CaseContextLinkingService harvest.
    This service fetches additional governed runbooks from SOAR library.
    """

    def __init__(
        self,
        soar_adapter: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize runbook registry.

        Args:
            soar_adapter: SOAR adapter for fetching runbooks (required)
            config: Configuration options (runbook_mappings, etc.)
        """
        self.config = config or {}
        self.soar_adapter = soar_adapter

        # Cache for fetched runbooks (keyed by runbook_id)
        self._runbooks_cache: Dict[str, Runbook] = {}

        # Signal type → SOAR runbook ID mappings (from config)
        self.signal_type_mappings = self.config.get(
            "signal_type_mappings",
            {
                "phishing": ["RB-PHISH-001", "PB-PHISH-RESPONSE"],
                "malware": ["RB-MALWARE-001", "PB-MALWARE-CONTAINMENT"],
                "ransomware": ["RB-RANSOM-001", "PB-RANSOMWARE-IR"],
                "insider_threat": ["RB-INSIDER-001", "PB-INSIDER-THREAT"],
                "data_exfil": ["RB-EXFIL-001", "PB-DATA-LOSS"],
                "brute_force": ["RB-BRUTE-001"],
                "vulnerability": ["RB-VULN-001", "PB-PATCH-MGMT"],
            },
        )

    async def fetch_applicable_runbooks(
        self,
        signal: Signal,
        classification: "ClassificationResult",
    ) -> List[Runbook]:
        """Fetch applicable runbooks from SOAR after classification.

        Args:
            signal: The signal being triaged
            classification: Classification result (TP/FP, severity, confidence)

        Returns:
            List of Runbook objects fetched from SOAR
        """
        if not self.soar_adapter:
            return []

        runbook_ids = self._determine_runbook_ids(signal, classification)

        runbooks = []
        for runbook_id in runbook_ids:
            # Check cache first
            if runbook_id in self._runbooks_cache:
                runbooks.append(self._runbooks_cache[runbook_id])
                continue

            # Fetch from SOAR
            try:
                if hasattr(self.soar_adapter, "get_runbook"):
                    soar_runbook = await self.soar_adapter.get_runbook(runbook_id)
                    if soar_runbook:
                        runbook = self._convert_soar_runbook(soar_runbook, runbook_id)
                        if runbook:
                            self._runbooks_cache[runbook_id] = runbook
                            runbooks.append(runbook)
            except Exception as e:
                # Log but continue - don't fail triage for missing runbook
                print(f"Warning: Failed to fetch runbook {runbook_id}: {e}")

        return runbooks

    def _determine_runbook_ids(
        self,
        signal: Signal,
        classification: "ClassificationResult",
    ) -> List[str]:
        """Determine which SOAR runbook IDs to fetch based on signal + classification.

        Args:
            signal: The signal
            classification: Classification result

        Returns:
            List of SOAR runbook IDs to fetch
        """
        runbook_ids = []

        # Skip if FP with low confidence
        if classification.label == "FP" and classification.confidence_score < 0.7:
            return []

        # Map signal type to runbook IDs
        signal_type_key = signal.signal_type.value.lower()

        # Check for specific detection keywords in title/description
        title_lower = signal.title.lower() if signal.title else ""
        desc_lower = signal.description.lower() if signal.description else ""

        # Phishing detection
        if "phish" in title_lower or "phish" in desc_lower:
            runbook_ids.extend(self.signal_type_mappings.get("phishing", []))
        # Ransomware detection
        elif "ransom" in title_lower or "ransom" in desc_lower or "encrypt" in title_lower:
            runbook_ids.extend(self.signal_type_mappings.get("ransomware", []))
        # Malware detection
        elif "malware" in title_lower or "trojan" in title_lower or "virus" in title_lower:
            runbook_ids.extend(self.signal_type_mappings.get("malware", []))
        # Brute force
        elif "brute" in title_lower or "password" in title_lower:
            runbook_ids.extend(self.signal_type_mappings.get("brute_force", []))
        # Default: try signal type mapping
        else:
            runbook_ids.extend(self.signal_type_mappings.get(signal_type_key, []))

        # For high severity TP, add incident response playbooks
        if classification.label == "TP" and classification.severity in ["high", "critical"]:
            runbook_ids.append("PB-INCIDENT-RESPONSE")

        return list(set(runbook_ids))  # Deduplicate

    def _convert_soar_runbook(self, soar_data: Dict[str, Any], runbook_id: str) -> Optional[Runbook]:
        """Convert SOAR runbook data to internal Runbook model.

        Args:
            soar_data: Raw runbook data from SOAR adapter
            runbook_id: ID of the runbook being converted

        Returns:
            Runbook instance or None if conversion fails
        """
        if not soar_data or "metadata" not in soar_data:
            return None

        meta = soar_data["metadata"]
        conditions = soar_data.get("conditions", {})
        raw_actions = soar_data.get("actions", [])

        # Parse actions
        actions = []
        for action_data in raw_actions:
            intent_str = action_data.get("intent", "INVESTIGATE")
            try:
                intent = ActionIntent(intent_str.lower())
            except ValueError:
                intent = ActionIntent.INVESTIGATE

            actions.append(
                RunbookAction(
                    id=action_data.get("id", ""),
                    intent=intent,
                    tool=action_data.get("tool", "SOAR"),
                    owner=action_data.get("owner", "SOC"),
                    title=action_data.get("title", ""),
                    description=action_data.get("description", ""),
                    steps=action_data.get("steps", []),
                    priority=action_data.get("priority", 2),
                    estimated_effort=action_data.get("estimated_effort", "15 minutes"),
                    automation_available=action_data.get("automation_available", False),
                    risk_tier=action_data.get("risk_tier", "LOW"),
                    approval_required=action_data.get("approval_required", False),
                    approvers=action_data.get("approvers", []),
                )
            )

        return Runbook(
            id=meta.get("id", ""),
            version=meta.get("version", "1.0"),
            title=meta.get("title", ""),
            description=meta.get("description", ""),
            category=meta.get("category", ""),
            signal_types=meta.get("signal_types", []),
            severity_levels=meta.get("severity_levels", []),
            author=meta.get("author", ""),
            approved_by=meta.get("approved_by", ""),
            approval_date=meta.get("approval_date", ""),
            review_cycle_days=meta.get("review_cycle_days", 90),
            source=RunbookSource.SOAR_REFS,
            actions=actions,
            conditions=conditions,
            environment_specific=meta.get("environment_specific", False),
            whitelisted=True,  # SOAR runbooks = governed = whitelisted
        )

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def list_runbooks(self) -> List[Runbook]:
        """List all cached runbooks.

        Returns:
            List of all runbooks in cache
        """
        return list(self._runbooks_cache.values())

    async def get_runbook(self, runbook_ref: str) -> Optional[Runbook]:
        """Get a specific runbook by ID or reference.

        Args:
            runbook_ref: Runbook ID or RunbookRef.ref_id

        Returns:
            Runbook if found, None otherwise
        """
        # Check local cache first
        if runbook_ref in self._runbooks_cache:
            return self._runbooks_cache[runbook_ref]

        # Try to fetch from SOAR if adapter available
        if self.soar_adapter and hasattr(self.soar_adapter, "get_runbook"):
            try:
                soar_runbook = await self.soar_adapter.get_runbook(runbook_ref)
                if soar_runbook:
                    # Convert to our Runbook format
                    runbook = self._convert_soar_runbook(soar_runbook, runbook_ref)
                    if runbook:
                        self._runbooks_cache[runbook_ref] = runbook
                        return runbook
            except Exception:
                pass

        return None

    async def get_runbook_from_ref(self, ref: RunbookRef) -> Optional[Runbook]:
        """Get runbook from a RunbookRef object.

        Args:
            ref: RunbookRef from a SimilarCase

        Returns:
            Runbook if found and accessible
        """
        return await self.get_runbook(ref.ref_id)

    def extract_actions(self, runbook: Runbook) -> List[RunbookAction]:
        """Extract all actions from a runbook.

        Args:
            runbook: Runbook to extract actions from

        Returns:
            List of RunbookAction objects
        """
        return runbook.actions.copy()

    def find_applicable_runbooks(
        self,
        signal: Signal,
        classification_label: Optional[ClassificationLabel] = None,
        min_confidence: float = 0.0,
    ) -> List[Runbook]:
        """Find runbooks applicable to a signal.

        Matches based on:
        - Signal type
        - Classification (if specified)
        - Confidence threshold

        Args:
            signal: Signal to match
            classification_label: Optional classification to filter by
            min_confidence: Minimum confidence threshold

        Returns:
            List of applicable runbooks, ordered by specificity
        """
        applicable = []

        for runbook in self._runbooks_cache.values():
            # Check signal type match
            if signal.signal_type.value not in runbook.signal_types:
                continue

            # Check classification conditions
            conditions = runbook.conditions
            if classification_label and conditions.get("classification"):
                allowed_labels = [
                    ClassificationLabel(c) if isinstance(c, str) else c
                    for c in conditions["classification"]
                ]
                # Handle string values
                allowed_values = [
                    c.value if hasattr(c, "value") else str(c) for c in allowed_labels
                ]
                if classification_label.value not in allowed_values:
                    continue

            # Check confidence threshold
            if conditions.get("min_confidence", 0) > min_confidence:
                # Runbook requires higher confidence than we have
                continue

            applicable.append(runbook)

        # Sort by specificity (more signal types = less specific)
        applicable.sort(key=lambda r: len(r.signal_types))

        return applicable

    def actions_to_model_actions(
        self,
        runbook_actions: List[RunbookAction],
        signal: Signal,
        runbook_id: str,
    ) -> List[Action]:
        """Convert RunbookActions to model Action objects.

        Args:
            runbook_actions: Actions from a runbook
            signal: Signal for parameterization
            runbook_id: Source runbook ID

        Returns:
            List of Action model instances
        """
        import hashlib

        actions = []

        for rb_action in runbook_actions:
            # Map intent to ActionType
            intent_to_type = {
                ActionIntent.CONTAIN: ActionType.ISOLATE,
                ActionIntent.INVESTIGATE: ActionType.INVESTIGATE,
                ActionIntent.REMEDIATE: ActionType.INVESTIGATE,  # Closest match
                ActionIntent.NOTIFY: ActionType.NOTIFY,
                ActionIntent.ESCALATE: ActionType.ESCALATE,
                ActionIntent.CLOSE: ActionType.CLOSE,
                ActionIntent.MONITOR: ActionType.MONITOR,
            }
            action_type = intent_to_type.get(rb_action.intent, ActionType.INVESTIGATE)

            # Parameterize description with signal entities
            description = rb_action.description
            for entity_type, entity_values in signal.entities.items():
                placeholder = "{" + entity_type + "}"
                if placeholder in description and entity_values:
                    description = description.replace(placeholder, entity_values[0])

            # Generate unique action ID
            hash_input = f"{runbook_id}:{rb_action.id}:{signal.signal_id}"
            hash_val = hashlib.sha256(hash_input.encode()).hexdigest()[:8]
            action_id = f"rb-{hash_val}"

            actions.append(
                Action(
                    action_id=action_id,
                    action_type=action_type,
                    priority=rb_action.priority,
                    title=rb_action.title,
                    description=description,
                    steps=rb_action.steps,
                    reasoning=f"From governed runbook: {runbook_id}",
                    source="seeded",  # Mark as seeded (highest precedence)
                    confidence=0.95,  # High confidence for governed templates
                    estimated_effort=rb_action.estimated_effort,
                    automation_available=rb_action.automation_available,
                    related_entities=signal.entities,
                )
            )

        return actions

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics.

        Returns:
            Dictionary with runbook counts and categories
        """
        runbooks = list(self._runbooks_cache.values())

        categories: Dict[str, int] = {}
        signal_types: set = set()
        total_actions = 0

        for rb in runbooks:
            cat = rb.category or "uncategorized"
            categories[cat] = categories.get(cat, 0) + 1
            signal_types.update(rb.signal_types)
            total_actions += len(rb.actions)

        return {
            "total_runbooks": len(runbooks),
            "total_actions": total_actions,
            "categories": categories,
            "signal_types_covered": list(signal_types),
            "sources": {
                "soar_refs": sum(
                    1 for rb in runbooks if rb.source == RunbookSource.SOAR_REFS
                ),
            },
        }
