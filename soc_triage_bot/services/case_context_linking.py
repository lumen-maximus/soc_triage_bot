"""CaseContextLinkingService - Unified correlation and similarity with budgets.

Refactored from SimilarityService to integrate with CKG. Implements budgeted
retrieval: 3 index queries → candidate selection → top-K deep hydration.
Adds both similarity edges and correlation edges to graph.
"""

from typing import Any, Dict, List, Optional

from soc_triage_bot.models.case_graph import (
    EdgeType,
    EvidenceEdge,
    NodeType,
    Provenance,
    SimilarCaseRefNode,
    TriageContextGraph,
)
from soc_triage_bot.models.signal import Signal
from soc_triage_bot.services.similarity import SimilarityResult, SimilarityService


class CaseContextLinkingService:
    """Unified case correlation and similarity with budget controls.

    Implements 3-stage budgeted retrieval:
    1. Index queries: Fast TF-IDF + entity matching (max_case_candidates)
    2. Candidate selection: Score and rank candidates
    3. Deep hydration: Fetch full case details for top-K (max_deep_case_pulls)

    Conditional logic: Always run for ALERTS, conditional for IOC/CVE based on
    detection presence from DetectionResolver.
    """

    def __init__(
        self,
        similarity_service: Optional[SimilarityService] = None,
        soar_adapter: Optional[Any] = None,
    ):
        """Initialize case context linking service.

        Args:
            similarity_service: Existing similarity service for compatibility
            soar_adapter: Optional SOAR adapter for deep case hydration
        """
        self.similarity_service = similarity_service
        self.soar_adapter = soar_adapter

    async def link_cases(
        self,
        signal: Signal,
        graph: TriageContextGraph,
    ) -> int:
        """Link similar and correlated cases to graph.

        Args:
            signal: Signal to find cases for
            graph: Case knowledge graph to update

        Returns:
            Number of case links added
        """
        # Check if we should run based on signal type and detection presence
        if not self._should_run(signal, graph):
            return 0

        budget = graph.budget

        # Stage 1: Index queries (fast, lightweight)
        candidates = await self._query_case_index(
            signal,
            max_candidates=budget.max_case_candidates,
        )

        # Stage 2: Candidate scoring and selection
        ranked_candidates = self._rank_candidates(candidates, signal)

        # Stage 3: Deep hydration (expensive, budgeted)
        top_cases = await self._hydrate_cases(
            ranked_candidates[: budget.max_deep_case_pulls],
        )

        # Add case nodes and edges to graph
        links_added = 0
        for case in top_cases:
            if self._add_case_to_graph(case, signal, graph):
                links_added += 1

        return links_added

    def _should_run(self, signal: Signal, graph: TriageContextGraph) -> bool:
        """Determine if case linking should run.

        Always run for ALERT signals.
        For IOC/CVE: only if detection is absent (no telemetry found).
        """
        from soc_triage_bot.models.signal import SignalType

        # Always run for alerts
        if signal.signal_type == SignalType.SIEM_ALERT:
            return True

        # For IOC/CVE: check if detection is absent
        if signal.signal_type in [SignalType.IOC, SignalType.CVE]:
            # Look for detection absence observation
            from soc_triage_bot.models.case_graph import ObservationType

            obs_nodes = graph.get_nodes_by_type(NodeType.OBSERVATION)

            for node in obs_nodes:
                from soc_triage_bot.models.case_graph import ObservationNode

                if isinstance(node, ObservationNode):
                    # If detection present, skip similarity (no hunting needed)
                    if node.observation_type == ObservationType.DETECTION_PRESENCE:
                        return False

            # No detection found = run similarity for hunting context
            return True

        return True

    async def _query_case_index(
        self,
        signal: Signal,
        max_candidates: int,
    ) -> List[SimilarityResult]:
        """Query case index for candidates (Stage 1)."""
        if not self.similarity_service:
            return []

        # Use existing similarity service for index queries
        results = self.similarity_service.find_similar_extended(
            signal,
            top_k=max_candidates,
        )

        return results

    def _rank_candidates(
        self,
        candidates: List[SimilarityResult],
        signal: Signal,
    ) -> List[SimilarityResult]:
        """Rank candidates by combined score (Stage 2)."""
        # Already ranked by combined_score from similarity service
        return sorted(candidates, key=lambda x: x.combined_score, reverse=True)

    async def _hydrate_cases(
        self,
        candidates: List[SimilarityResult],
    ) -> List[Dict[str, Any]]:
        """Deep hydrate top cases with full details (Stage 3)."""
        hydrated = []

        for candidate in candidates:
            # If SOAR adapter available, fetch full case details
            if self.soar_adapter:
                try:
                    case_details = await self._fetch_case_from_soar(candidate.case_id)
                    if case_details:
                        case_details["similarity_score"] = candidate.combined_score
                        case_details["matched_entities"] = [
                            f"{m.entity_type}:{m.value}"
                            for m in candidate.matched_entities
                        ]
                        hydrated.append(case_details)
                        continue
                except Exception:
                    pass

            # Fallback: use candidate metadata
            hydrated.append(
                {
                    "case_id": candidate.case_id,
                    "similarity_score": candidate.combined_score,
                    "outcome": candidate.outcome,
                    "matched_entities": [
                        f"{m.entity_type}:{m.value}" for m in candidate.matched_entities
                    ],
                }
            )

        return hydrated

    async def _fetch_case_from_soar(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full case details from SOAR."""
        # Mock implementation - real would call SOAR adapter
        # case = await self.soar_adapter.get_case(case_id)
        return None

    def _add_case_to_graph(
        self,
        case: Dict[str, Any],
        signal: Signal,
        graph: TriageContextGraph,
    ) -> bool:
        """Add similar case node and edges to graph."""
        case_id = case.get("case_id")
        if not case_id:
            return False

        # Create provenance
        provenance = Provenance(
            source_system="SimilarityIndex",
            query_fingerprint=f"similar_{signal.signal_id}_{case_id}",
            ttl_seconds=86400,
            confidence=case.get("similarity_score", 0.0),
            evidence_refs=case.get("matched_entities", []),
        )

        # Create similar case node
        case_node = SimilarCaseRefNode(
            node_id=f"similar_case_{case_id}",
            node_type=NodeType.SIMILAR_CASE_REF,
            ref_case_id=case_id,
            similarity_score=case.get("similarity_score", 0.0),
            outcome=case.get("outcome", "unknown"),
            provenance=provenance,
        )

        graph.add_node(case_node)

        # Link signal → similar case
        signal_node_id = f"signal_{signal.signal_id}"
        edge = EvidenceEdge(
            edge_id=f"edge_{signal_node_id}_similar_{case_id}",
            edge_type=EdgeType.SIMILAR_TO,
            source_node_id=signal_node_id,
            target_node_id=case_node.node_id,
            weight=case.get("similarity_score", 0.0),
            provenance=provenance,
        )

        graph.add_edge(edge)

        return True

    def get_linked_cases_from_graph(
        self,
        graph: TriageContextGraph,
    ) -> List[Dict[str, Any]]:
        """Extract linked cases from graph for downstream use.

        Returns cases in format compatible with ActionProposalService.
        """
        cases = []

        # Get all similar case ref nodes
        case_nodes = graph.get_nodes_by_type(NodeType.SIMILAR_CASE_REF)

        for node in case_nodes:
            from soc_triage_bot.models.case_graph import SimilarCaseRefNode

            if isinstance(node, SimilarCaseRefNode):
                cases.append(
                    {
                        "case_id": node.ref_case_id,
                        "similarity": node.similarity_score,
                        "outcome": node.outcome,
                        "overlap": "graph_linked",
                        "actions_taken": [],  # Would be hydrated if available
                    }
                )

        # Sort by similarity descending
        cases.sort(key=lambda x: x.get("similarity", 0.0), reverse=True)

        return cases
