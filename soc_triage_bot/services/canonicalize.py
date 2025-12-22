"""Entity canonicalization service for CKG.

Normalizes entities to canonical IDs before graph construction.
Provides stable anchor set for the entire triage pipeline.
"""

import re
from typing import Any, Dict, Optional, Set

from ..models import Signal
from ..models.case_graph import EntityNode, EntityType, Provenance, TriageContextGraph


class CanonicalizeService:
    """Service for entity canonicalization and normalization.

    Extracts entities from signals and normalizes them to canonical IDs
    to create stable anchor points for the CKG graph.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize canonicalize service.

        Args:
            config: Configuration for entity extraction and normalization rules
        """
        self.config = config or {}

        # Regex patterns for entity extraction
        self.patterns = {
            EntityType.IP: re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            EntityType.DOMAIN: re.compile(r"\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),
            EntityType.FILE_HASH: re.compile(
                r"\b[a-fA-F0-9]{32,64}\b"  # MD5, SHA1, SHA256
            ),
            EntityType.EMAIL: re.compile(
                r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
            ),
            EntityType.URL: re.compile(
                r'https?://[^\s<>"{}|\\^`\[\]]+[^\s<>"{}|\\^`\[\].,;:!?]'
            ),
        }

    def canonicalize_entities(
        self, signal: Signal, graph: TriageContextGraph
    ) -> Dict[str, EntityNode]:
        """Extract and canonicalize entities from signal into graph nodes.

        Args:
            signal: The signal to extract entities from
            graph: The graph to add entities to

        Returns:
            Dictionary mapping canonical_id to EntityNode
        """
        entities = {}

        # Extract entities from signal
        extracted = self._extract_entities_from_signal(signal)

        # Add entities to graph with canonical IDs
        for entity_type, values in extracted.items():
            for value in values:
                canonical_id = self._make_canonical_id(entity_type, value)

                # Check if entity already exists in graph
                existing_node = graph.get_node(canonical_id)
                if existing_node and existing_node.node_type.value == "entity":
                    entity_node = existing_node
                else:
                    # Create new entity node
                    entity_node = EntityNode(
                        node_id=canonical_id,
                        entity_type=entity_type,
                        canonical_id=canonical_id,
                        entity_value=self._normalize_entity_value(entity_type, value),
                        aliases=(
                            [value]
                            if value != self._normalize_entity_value(entity_type, value)
                            else []
                        ),
                        provenance=Provenance(
                            source_system="Canonicalize",
                            confidence=0.9,
                            evidence_refs=[f"signal_id:{signal.signal_id}"],
                            query_fingerprint="entity_canonicalization",
                            ttl_seconds=86400,
                        ),
                    )
                    graph.add_node(entity_node)

                entities[canonical_id] = entity_node

        # Extract rule and detection entities
        rule_entities = self._extract_rule_entities(signal, graph)
        entities.update(rule_entities)

        # Extract host and user entities from signal metadata
        metadata_entities = self._extract_metadata_entities(signal, graph)
        entities.update(metadata_entities)

        return entities

    def _extract_entities_from_signal(
        self, signal: Signal
    ) -> Dict[EntityType, Set[str]]:
        """Extract entities from signal content using regex patterns.

        Args:
            signal: The signal to extract entities from

        Returns:
            Dictionary mapping entity type to set of extracted values
        """
        entities = {entity_type: set() for entity_type in self.patterns.keys()}

        # Combine all signal text content
        text_content = self._get_signal_text_content(signal)

        # Extract entities using patterns
        for entity_type, pattern in self.patterns.items():
            matches = pattern.findall(text_content)
            if matches:
                entities[entity_type].update(matches)

        return entities

    def _extract_rule_entities(
        self, signal: Signal, graph: TriageContextGraph
    ) -> Dict[str, EntityNode]:
        """Extract detection rule entities from signal.

        Args:
            signal: The signal to extract rules from
            graph: The graph to add entities to

        Returns:
            Dictionary mapping canonical_id to EntityNode
        """
        entities = {}

        # Extract rule ID from signal detection context
        rule_candidates = []
        if hasattr(signal, "detection_context") and signal.detection_context:
            if (
                hasattr(signal.detection_context, "rule_id")
                and signal.detection_context.rule_id
            ):
                rule_candidates.append(signal.detection_context.rule_id)
            if (
                hasattr(signal.detection_context, "rule_name")
                and signal.detection_context.rule_name
            ):
                rule_candidates.append(signal.detection_context.rule_name)

        # Try to extract from signal title/description for SIEM alerts
        if signal.signal_type.value == "siem_alert":
            if "rule:" in signal.title.lower():
                rule_part = signal.title.split("rule:")[-1].strip().split()[0]
                if rule_part:
                    rule_candidates.append(rule_part)

        for rule_value in rule_candidates:
            if rule_value:
                canonical_id = self._make_canonical_id(
                    EntityType.DETECTION_RULE, rule_value
                )

                # Check if entity already exists
                existing_node = graph.get_node(canonical_id)
                if existing_node and existing_node.node_type.value == "entity":
                    entity_node = existing_node
                else:
                    entity_node = EntityNode(
                        node_id=canonical_id,
                        entity_type=EntityType.DETECTION_RULE,
                        canonical_id=canonical_id,
                        entity_value=rule_value,
                        provenance=Provenance(
                            source_system="Canonicalize",
                            confidence=0.95,
                            evidence_refs=[f"signal_id:{signal.signal_id}"],
                            query_fingerprint="rule_extraction",
                            ttl_seconds=86400,
                        ),
                    )
                    graph.add_node(entity_node)

                entities[canonical_id] = entity_node

        return entities

    def _extract_metadata_entities(
        self, signal: Signal, graph: TriageContextGraph
    ) -> Dict[str, EntityNode]:
        """Extract host and user entities from signal entity context.

        Args:
            signal: The signal to extract metadata entities from
            graph: The graph to add entities to

        Returns:
            Dictionary mapping canonical_id to EntityNode
        """
        entities = {}

        # Host extraction from entity context
        host_candidates = []
        if hasattr(signal, "entity_context") and signal.entity_context:
            if (
                hasattr(signal.entity_context, "hostname")
                and signal.entity_context.hostname
            ):
                host_candidates.append(signal.entity_context.hostname)
            if (
                hasattr(signal.entity_context, "device_id")
                and signal.entity_context.device_id
            ):
                host_candidates.append(signal.entity_context.device_id)
            if (
                hasattr(signal.entity_context, "asset_id")
                and signal.entity_context.asset_id
            ):
                host_candidates.append(signal.entity_context.asset_id)

        for host_value in host_candidates:
            canonical_id = self._make_canonical_id(EntityType.HOST, host_value)
            existing_node = graph.get_node(canonical_id)
            if existing_node and existing_node.node_type.value == "entity":
                entity_node = existing_node
            else:
                entity_node = EntityNode(
                    node_id=canonical_id,
                    entity_type=EntityType.HOST,
                    canonical_id=canonical_id,
                    entity_value=host_value.lower(),
                    provenance=Provenance(
                        source_system="Canonicalize",
                        confidence=0.85,
                        evidence_refs=[f"signal_id:{signal.signal_id}"],
                        query_fingerprint="host_extraction",
                        ttl_seconds=86400,
                    ),
                )
                graph.add_node(entity_node)
            entities[canonical_id] = entity_node

        # User extraction from entity context
        user_candidates = []
        if hasattr(signal, "entity_context") and signal.entity_context:
            if (
                hasattr(signal.entity_context, "username")
                and signal.entity_context.username
            ):
                user_candidates.append(signal.entity_context.username)
            if (
                hasattr(signal.entity_context, "service_account")
                and signal.entity_context.service_account
            ):
                user_candidates.append(signal.entity_context.service_account)
            if hasattr(signal.entity_context, "upn") and signal.entity_context.upn:
                user_candidates.append(signal.entity_context.upn)

        for user_value in user_candidates:
            canonical_id = self._make_canonical_id(EntityType.USER, user_value)
            existing_node = graph.get_node(canonical_id)
            if existing_node and existing_node.node_type.value == "entity":
                entity_node = existing_node
            else:
                entity_node = EntityNode(
                    node_id=canonical_id,
                    entity_type=EntityType.USER,
                    canonical_id=canonical_id,
                    entity_value=user_value.lower(),
                    provenance=Provenance(
                        source_system="Canonicalize",
                        confidence=0.85,
                        evidence_refs=[f"signal_id:{signal.signal_id}"],
                        query_fingerprint="user_extraction",
                        ttl_seconds=86400,
                    ),
                )
                graph.add_node(entity_node)
            entities[canonical_id] = entity_node

        return entities

    def _get_signal_text_content(self, signal: Signal) -> str:
        """Get all text content from signal for entity extraction.

        Args:
            signal: The signal to get text from

        Returns:
            Combined text content
        """
        text_parts = []

        if signal.title:
            text_parts.append(signal.title)
        if signal.description:
            text_parts.append(signal.description)

        return " ".join(text_parts)

    def _make_canonical_id(self, entity_type: EntityType, value: str) -> str:
        """Create canonical ID for entity.

        Args:
            entity_type: Type of entity
            value: Entity value

        Returns:
            Canonical ID string
        """
        normalized_value = self._normalize_entity_value(entity_type, value)
        return f"{entity_type.value}:{normalized_value}"

    def _normalize_entity_value(self, entity_type: EntityType, value: str) -> str:
        """Normalize entity value for canonical ID generation.

        Args:
            entity_type: Type of entity
            value: Raw entity value

        Returns:
            Normalized value
        """
        value = value.strip()

        if entity_type in [EntityType.HOST, EntityType.USER]:
            return value.lower()
        elif entity_type == EntityType.DOMAIN:
            return value.lower()
        elif entity_type == EntityType.IP:
            return value  # IPs don't need case normalization
        elif entity_type == EntityType.FILE_HASH:
            return value.lower()
        elif entity_type == EntityType.EMAIL:
            return value.lower()
        elif entity_type == EntityType.URL:
            return value
        elif entity_type == EntityType.DETECTION_RULE:
            return value  # Keep original case for rule names
        else:
            return value.lower()
