"""Action proposal service with templates, learning, and generation."""

import hashlib
from typing import Any, Dict, List, Optional

from ..models import (
    Action,
    ActionType,
    Classification,
    ClassificationLabel,
    EnrichmentResult,
    Signal,
)


class ActionProposalService:
    """Service for generating, deduplicating, and ranking action proposals."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize action proposal service.

        Args:
            config: Configuration for action templates
        """
        self.config = config or {}
        self.templates = self._load_templates()
        self.learned_actions = []  # Could be loaded from database

    def _load_templates(self) -> List[Dict[str, Any]]:
        """Load action templates."""
        return [
            {
                "id": "template-isolate-host",
                "type": ActionType.ISOLATE,
                "title": "Isolate Compromised Host",
                "description": "Isolate {hostname} from network",
                "steps": [
                    "Verify host status in EDR",
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
            },
            {
                "id": "template-investigate-user",
                "type": ActionType.INVESTIGATE,
                "title": "Investigate User Activity",
                "description": "Investigate activity for user {user}",
                "steps": [
                    "Review user's recent login history",
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
            },
            {
                "id": "template-block-ip",
                "type": ActionType.BLOCK,
                "title": "Block Malicious IP",
                "description": "Block IP address {ip} at firewall",
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
            },
            {
                "id": "template-escalate",
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
            },
            {
                "id": "template-close-fp",
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
            },
            {
                "id": "template-monitor",
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
            },
        ]

    def propose_actions(
        self,
        signal: Signal,
        classification: Classification,
        enrichments: Dict[str, EnrichmentResult],
    ) -> List[Action]:
        """Generate action proposals for a signal.

        Args:
            signal: The signal
            classification: Classification result
            enrichments: Enrichment results

        Returns:
            List of proposed actions, deduplicated and ranked
        """
        proposals = []

        # Generate from templates
        template_actions = self._generate_from_templates(
            signal, classification, enrichments
        )
        proposals.extend(template_actions)

        # Generate learned actions (mock - in production, use ML)
        learned_actions = self._generate_learned_actions(signal, classification)
        proposals.extend(learned_actions)

        # Generate dynamic actions based on context
        generated_actions = self._generate_dynamic_actions(
            signal, classification, enrichments
        )
        proposals.extend(generated_actions)

        # Deduplicate
        proposals = self._deduplicate_actions(proposals)

        # Rank by priority and confidence
        proposals = self._rank_actions(proposals)

        return proposals

    def _generate_from_templates(
        self,
        signal: Signal,
        classification: Classification,
        enrichments: Dict[str, EnrichmentResult],
    ) -> List[Action]:
        """Generate actions from templates."""
        actions = []

        for template in self.templates:
            if self._matches_conditions(template, signal, classification, enrichments):
                action = self._instantiate_template(template, signal, classification)
                actions.append(action)

        return actions

    def _matches_conditions(
        self,
        template: Dict[str, Any],
        signal: Signal,
        classification: Classification,
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
        if not (min_confidence <= classification.confidence <= max_confidence):
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
        self, template: Dict[str, Any], signal: Signal, classification: Classification
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
            confidence=classification.confidence,
            estimated_effort=template.get("estimated_effort"),
            automation_available=template.get("automation_available", False),
            related_entities=signal.entities,
        )

    def _generate_learned_actions(
        self, signal: Signal, classification: Classification
    ) -> List[Action]:
        """Generate actions based on learned patterns.

        In production, this would use ML to suggest actions based on
        similar past cases and analyst responses.
        """
        actions = []

        # Mock: Generate a learned action for high confidence TPs
        if (
            classification.label == ClassificationLabel.TRUE_POSITIVE
            and classification.confidence > 0.85
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
                    reasoning="Similar past cases resulted in team notification",
                    source="learned",
                    confidence=0.75,
                    estimated_effort="5 minutes",
                    automation_available=True,
                    related_entities=signal.entities,
                )
            )

        return actions

    def _generate_dynamic_actions(
        self,
        signal: Signal,
        classification: Classification,
        enrichments: Dict[str, EnrichmentResult],
    ) -> List[Action]:
        """Generate dynamic actions based on context.

        In production, this could use LLMs or rule-based generation.
        """
        actions = []

        # Generate custom investigation action for vulnerabilities
        vuln_result = enrichments.get("vulnerability")
        if vuln_result and vuln_result.status.value == "success":
            critical_vulns = vuln_result.data.get("critical_vulns", 0)
            if critical_vulns > 0:
                actions.append(
                    Action(
                        action_id=self._generate_action_id(
                            "gen-vuln", signal.signal_id
                        ),
                        action_type=ActionType.INVESTIGATE,
                        priority=2,
                        title="Investigate Critical Vulnerabilities",
                        description=f"Investigate {critical_vulns} critical vulnerabilities",
                        steps=[
                            "Review vulnerability details",
                            "Check patch availability",
                            "Verify exploit attempts",
                            "Plan remediation",
                        ],
                        reasoning=f"System has {critical_vulns} critical vulnerabilities",
                        source="generated",
                        confidence=0.8,
                        estimated_effort="20 minutes",
                        automation_available=False,
                        related_entities=signal.entities,
                    )
                )

        return actions

    def _deduplicate_actions(self, actions: List[Action]) -> List[Action]:
        """Remove duplicate actions."""
        seen = set()
        deduplicated = []

        for action in actions:
            # Create signature based on type and title
            signature = f"{action.action_type.value}:{action.title}"
            if signature not in seen:
                seen.add(signature)
                deduplicated.append(action)

        return deduplicated

    def _rank_actions(self, actions: List[Action]) -> List[Action]:
        """Rank actions by priority and confidence."""
        return sorted(actions, key=lambda a: (a.priority, -a.confidence))

    def _generate_action_id(self, template_id: str, signal_id: str) -> str:
        """Generate unique action ID."""
        combined = f"{template_id}:{signal_id}"
        hash_val = hashlib.sha256(combined.encode()).hexdigest()[:8]
        return f"act-{hash_val}"
