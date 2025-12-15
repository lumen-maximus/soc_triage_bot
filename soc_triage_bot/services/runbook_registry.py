"""RunbookRegistry capability for loading governed templates.

Loads and manages runbooks/playbooks from:
1. Local YAML files (templates/runbooks/*.yaml, templates/playbooks/*.yaml)
2. SOAR references (by runbook_id, playbook_id, kb_id)

These seeded templates are GOVERNED and take precedence over case-learned actions.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

from ..models import Action, ActionType, ClassificationLabel, Signal
from ..models.triage_report import RunbookRef


class RunbookSource(str, Enum):
    """Source of runbook content."""

    SEEDED_LOCAL = "seeded_local"  # Local YAML/JSON files (governed)
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
    """Registry for seeded and SOAR-referenced runbooks.

    Capabilities:
    - list_runbooks() -> List[Runbook]
    - get_runbook(runbook_ref) -> Runbook
    - extract_actions(runbook) -> List[RunbookAction]
    - find_applicable_runbooks(signal, classification) -> List[Runbook]
    """

    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        soar_adapter: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize runbook registry.

        Args:
            templates_dir: Path to templates directory (defaults to soc_triage_bot/templates)
            soar_adapter: Optional SOAR adapter for fetching remote runbooks
            config: Configuration options
        """
        self.config = config or {}

        # Determine templates directory
        if templates_dir:
            self.templates_dir = Path(templates_dir)
        else:
            # Default to soc_triage_bot/templates relative to this file
            current_file = Path(__file__)
            self.templates_dir = current_file.parent.parent / "templates"

        self.soar_adapter = soar_adapter

        # Cache for loaded runbooks
        self._runbooks_cache: Dict[str, Runbook] = {}
        self._loaded = False

        # Auto-load on init
        self._load_all_runbooks()

    def _load_all_runbooks(self) -> None:
        """Load all runbooks from local YAML files."""
        if self._loaded:
            return

        # Load runbooks
        runbooks_dir = self.templates_dir / "runbooks"
        if runbooks_dir.exists():
            for yaml_file in runbooks_dir.glob("*.yaml"):
                try:
                    runbook = self._load_runbook_from_yaml(yaml_file)
                    if runbook:
                        self._runbooks_cache[runbook.id] = runbook
                except Exception as e:
                    print(f"Warning: Failed to load runbook {yaml_file}: {e}")

        # Load playbooks
        playbooks_dir = self.templates_dir / "playbooks"
        if playbooks_dir.exists():
            for yaml_file in playbooks_dir.glob("*.yaml"):
                try:
                    playbook = self._load_playbook_from_yaml(yaml_file)
                    if playbook:
                        self._runbooks_cache[playbook.id] = playbook
                except Exception as e:
                    print(f"Warning: Failed to load playbook {yaml_file}: {e}")

        self._loaded = True

    def _load_runbook_from_yaml(self, yaml_path: Path) -> Optional[Runbook]:
        """Load a runbook from a YAML file."""
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "metadata" not in data:
            return None

        meta = data["metadata"]
        conditions = data.get("conditions", {})
        raw_actions = data.get("actions", [])

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
            source=RunbookSource.SEEDED_LOCAL,
            actions=actions,
            conditions=conditions,
            environment_specific=meta.get("environment_specific", False),
            whitelisted=True,  # Seeded = governed = whitelisted
        )

    def _load_playbook_from_yaml(self, yaml_path: Path) -> Optional[Runbook]:
        """Load a phased playbook from a YAML file."""
        with open(yaml_path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "metadata" not in data:
            return None

        meta = data["metadata"]
        conditions = data.get("conditions", {})
        phases = data.get("phases", [])

        # Extract all actions from all phases
        all_actions = []
        for phase in phases:
            phase_actions = phase.get("actions", [])
            for action_data in phase_actions:
                intent_str = action_data.get("intent", "INVESTIGATE")
                try:
                    intent = ActionIntent(intent_str.lower())
                except ValueError:
                    intent = ActionIntent.INVESTIGATE

                all_actions.append(
                    RunbookAction(
                        id=action_data.get("id", ""),
                        intent=intent,
                        tool=action_data.get("tool", "SOAR"),
                        owner=action_data.get("owner", "SOC"),
                        title=action_data.get("title", ""),
                        description=action_data.get("description", ""),
                        steps=action_data.get("steps", []),
                        priority=action_data.get("priority", 2),
                        estimated_effort=action_data.get(
                            "estimated_effort", "15 minutes"
                        ),
                        automation_available=action_data.get(
                            "automation_available", False
                        ),
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
            source=RunbookSource.SEEDED_LOCAL,
            actions=all_actions,
            conditions=conditions,
            phases=phases,
            environment_specific=meta.get("environment_specific", False),
            whitelisted=True,
        )

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def list_runbooks(self) -> List[Runbook]:
        """List all available runbooks.

        Returns:
            List of all loaded runbooks/playbooks
        """
        return list(self._runbooks_cache.values())

    def get_runbook(self, runbook_ref: str) -> Optional[Runbook]:
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
                soar_runbook = self.soar_adapter.get_runbook(runbook_ref)
                if soar_runbook:
                    # Convert to our Runbook format
                    runbook = self._convert_soar_runbook(soar_runbook)
                    if runbook:
                        self._runbooks_cache[runbook_ref] = runbook
                        return runbook
            except Exception:
                pass

        return None

    def get_runbook_from_ref(self, ref: RunbookRef) -> Optional[Runbook]:
        """Get runbook from a RunbookRef object.

        Args:
            ref: RunbookRef from a SimilarCase

        Returns:
            Runbook if found and accessible
        """
        return self.get_runbook(ref.ref_id)

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

    def _convert_soar_runbook(self, soar_data: Dict[str, Any]) -> Optional[Runbook]:
        """Convert SOAR-fetched runbook to our format.

        Override this method for specific SOAR integrations.
        """
        # Default implementation - expects SOAR to return similar format
        if not soar_data:
            return None

        # Extract actions
        actions = []
        for action_data in soar_data.get("actions", []):
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
                )
            )

        return Runbook(
            id=soar_data.get("id", ""),
            version=soar_data.get("version", "1.0"),
            title=soar_data.get("title", ""),
            description=soar_data.get("description", ""),
            category=soar_data.get("category", ""),
            signal_types=soar_data.get("signal_types", []),
            severity_levels=soar_data.get("severity_levels", []),
            author=soar_data.get("author", ""),
            approved_by=soar_data.get("approved_by", ""),
            approval_date=soar_data.get("approval_date", ""),
            review_cycle_days=soar_data.get("review_cycle_days", 90),
            source=RunbookSource.SOAR_REFS,
            actions=actions,
            conditions=soar_data.get("conditions", {}),
            whitelisted=False,  # SOAR runbooks not whitelisted by default
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics.

        Returns:
            Dictionary with runbook counts and categories
        """
        runbooks = list(self._runbooks_cache.values())

        categories: Dict[str, int] = {}
        signal_types: Set[str] = set()
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
                "seeded_local": sum(
                    1 for rb in runbooks if rb.source == RunbookSource.SEEDED_LOCAL
                ),
                "soar_refs": sum(
                    1 for rb in runbooks if rb.source == RunbookSource.SOAR_REFS
                ),
            },
        }
