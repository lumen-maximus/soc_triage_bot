"""CaseBootstrapService - Initialize CKG for triage runs.

Responsibilities:
- Create TriageContextGraph with unique case_id
- Set triage mode (REUSE_ONLY, MIN_DELTA, DEEP_DIVE)
- Configure retrieval budgets based on mode
- Add initial case and signal nodes
- Prepare graph for downstream enrichment
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional

from soc_triage_bot.models.case_graph import (
    CaseNode,
    NodeType,
    Provenance,
    RetrievalBudget,
    SignalNode,
    TriageContextGraph,
    TriageMode,
)
from soc_triage_bot.models.signal import Signal


class CaseBootstrapService:
    """Bootstrap service for CKG initialization.

    Creates the graph, assigns case_id, sets mode/budgets, and adds
    the initial case + signal nodes before enrichment pipeline starts.
    """

    def __init__(self, default_mode: TriageMode = TriageMode.MIN_DELTA):
        """Initialize bootstrap service.

        Args:
            default_mode: Default triage mode if not specified
        """
        self.default_mode = default_mode

    def bootstrap(
        self,
        signal: Signal,
        mode: Optional[TriageMode] = None,
        case_id_prefix: str = "CASE",
    ) -> TriageContextGraph:
        """Bootstrap a new case knowledge graph.

        Args:
            signal: Incoming signal to triage
            mode: Triage mode (defaults to MIN_DELTA)
            case_id_prefix: Prefix for generated case_id

        Returns:
            Initialized TriageContextGraph with case and signal nodes
        """
        triage_mode = mode or self.default_mode

        # Generate case_id from signal
        case_id = self._generate_case_id(signal, case_id_prefix)

        # Configure budgets based on mode
        budget = self._configure_budget(triage_mode)

        # Create graph
        graph = TriageContextGraph(
            case_id=case_id,
            mode=triage_mode,
            budget=budget,
        )

        # Add case node
        case_provenance = Provenance(
            source_system="triage_service",
            query_fingerprint=f"bootstrap_{case_id}",
            ttl_seconds=86400,  # 24h
            confidence=1.0,
            evidence_refs=[signal.signal_id],
        )

        case_node = CaseNode(
            node_id=f"case_{case_id}",
            node_type=NodeType.CASE,
            case_id=case_id,
            created_at=datetime.now(timezone.utc),
            provenance=case_provenance,
        )
        graph.add_node(case_node)

        # Add signal node
        signal_provenance = Provenance(
            source_system=signal.source.system,
            query_fingerprint=signal.signal_id,
            ttl_seconds=86400,
            confidence=1.0,
            evidence_refs=[signal.signal_id],
        )

        signal_node = SignalNode(
            node_id=f"signal_{signal.signal_id}",
            node_type=NodeType.SIGNAL,
            signal_id=signal.signal_id,
            signal_type=signal.signal_type.value,
            first_seen=signal.timestamp,
            provenance=signal_provenance,
        )
        graph.add_node(signal_node)

        # Link case → signal
        from soc_triage_bot.models.case_graph import EdgeType, EvidenceEdge

        edge = EvidenceEdge(
            edge_id=f"edge_{case_id}_has_signal",
            edge_type=EdgeType.HAS_SIGNAL,
            source_node_id=case_node.node_id,
            target_node_id=signal_node.node_id,
            provenance=case_provenance,
        )
        graph.add_edge(edge)

        return graph

    def _generate_case_id(self, signal: Signal, prefix: str) -> str:
        """Generate unique case_id from signal.

        Uses signal_id + timestamp + source to create deterministic ID.

        Args:
            signal: Incoming signal
            prefix: Case ID prefix

        Returns:
            Unique case_id like "CASE-2024-12-21-abc123"
        """
        # Create hash from signal metadata
        hash_input = (
            f"{signal.signal_id}_{signal.timestamp.isoformat()}_{signal.source.system}"
        )
        hash_digest = hashlib.sha256(hash_input.encode()).hexdigest()[:8]

        # Format: CASE-YYYY-MM-DD-hash
        date_str = signal.timestamp.strftime("%Y-%m-%d")
        return f"{prefix}-{date_str}-{hash_digest}"

    def _configure_budget(self, mode: TriageMode) -> RetrievalBudget:
        """Configure retrieval budget based on triage mode.

        Args:
            mode: Triage mode

        Returns:
            RetrievalBudget with appropriate limits
        """
        if mode == TriageMode.REUSE_ONLY:
            # Minimal retrieval - only use existing data
            return RetrievalBudget(
                max_case_candidates=3,
                max_deep_case_pulls=1,
                max_enrichment_adapters=0,  # No new enrichment
                max_siem_queries=0,
                max_ti_lookups=0,
                escalate_on_ambiguity=False,
            )

        elif mode == TriageMode.MIN_DELTA:
            # Balanced mode - fetch only missing data
            return RetrievalBudget(
                max_case_candidates=10,
                max_deep_case_pulls=5,
                max_enrichment_adapters=3,  # Selective enrichment
                max_siem_queries=1,
                max_ti_lookups=5,
                escalate_on_ambiguity=True,
            )

        else:  # DEEP_DIVE
            # Exhaustive mode - fetch everything
            return RetrievalBudget(
                max_case_candidates=25,
                max_deep_case_pulls=10,
                max_enrichment_adapters=5,  # Full enrichment
                max_siem_queries=2,
                max_ti_lookups=10,
                escalate_on_ambiguity=True,
            )

    def update_mode(
        self,
        graph: TriageContextGraph,
        new_mode: TriageMode,
    ) -> TriageContextGraph:
        """Update triage mode and reconfigure budget.

        Useful for adaptive triage: start with MIN_DELTA, escalate to DEEP_DIVE
        if initial analysis shows high severity.

        Args:
            graph: Existing graph
            new_mode: New triage mode

        Returns:
            Updated graph with new mode and budget
        """
        graph.mode = new_mode
        graph.budget = self._configure_budget(new_mode)
        return graph
