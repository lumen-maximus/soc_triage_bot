"""CaseContextLinkingService - Unified correlation and similarity with adapters + graph.

UNIFIED SERVICE that:
1. Reads GRAPH state (detection presence, entities, budgets)
2. Uses LOCAL VECTOR INDEX (TF-IDF + entity matching) to find candidates
3. Uses GRAPH DATA to filter/prioritize candidates (detection presence, asset criticality)
4. Uses SOAR ADAPTER to deep-pull only top-K candidates
5. Writes BEST RESULTS back to graph (similar case nodes, edges)
6. Extracts runbook refs and action templates from hydrated cases

Flow: Graph State → Vector Candidates → Graph Filter → SOAR Pull → Graph Write
Runs BEFORE classification. All case history queries go through this service.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from soc_triage_bot.models.case_graph import (
    EdgeType,
    EvidenceEdge,
    NodeType,
    Provenance,
    SimilarCaseRefNode,
    TriageContextGraph,
)
from soc_triage_bot.models.signal import Signal, SignalType
from soc_triage_bot.models.triage_report import (
    AttachmentMetadata,
    RunbookRef,
    SimilarCase,
)

# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class EntityMatch:
    """An entity match between current signal and historical case."""

    entity_type: str  # 'rule_id', 'indicator', 'hostname', 'username', etc.
    value: str
    source: str  # 'signal', 'case', or 'both'


@dataclass
class SimilarityResult:
    """Extended similarity result with entity matching."""

    case_id: str
    text_similarity: float  # 0-1 from TF-IDF
    entity_similarity: float  # 0-1 from entity overlap
    combined_score: float  # Weighted combination
    matched_entities: List[EntityMatch]
    outcome: Optional[str]  # 'TP', 'FP', or None


class ArtifactConfidenceLevel(str, Enum):
    """Confidence level for case-linked artifacts."""

    HIGH = "high"  # Whitelisted runbook, successful resolution
    MEDIUM = "medium"  # Non-whitelisted but successful resolution
    LOW = "low"  # FP/mixed outcomes or old cases
    SUGGESTED = "suggested"  # Just a suggestion, not authoritative


@dataclass
class HarvestedAction:
    """Action harvested from case artifacts."""

    id: str
    title: str
    description: str
    intent: str
    tool: str
    owner: str
    steps: List[str] = field(default_factory=list)
    priority: int = 3
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


@dataclass
class LinkingResult:
    """Complete result from case context linking."""

    similar_cases: List[SimilarCase]
    harvest_result: HarvestResult
    links_added_to_graph: int
    candidates_evaluated: int
    deep_hydrated: int


# =============================================================================
# UNIFIED CASE CONTEXT LINKING SERVICE
# =============================================================================


class CaseContextLinkingService:
    """Unified case correlation and similarity with adapters + graph integration.

    Flow (runs BEFORE classification):
    1. READ GRAPH: Get detection presence, entities, asset criticality, budgets
    2. VECTOR INDEX: Fast TF-IDF + entity matching to find local candidates
    3. GRAPH FILTER: Use detection presence to skip/boost candidates
    4. SOAR ADAPTER: Deep-pull only top-K candidates from SOAR
    5. GRAPH WRITE: Add similar case nodes and edges to graph
    6. HARVEST: Extract runbook refs and action templates

    This is the ONLY service that pulls case history from SOAR/SIEM.
    """

    def __init__(
        self,
        case_database: Optional[List[Dict[str, Any]]] = None,
        soar_adapter: Optional[Any] = None,
        siem_adapter: Optional[Any] = None,
        runbook_registry: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize unified case context linking service.

        Args:
            case_database: Historical case database for TF-IDF vector index
            soar_adapter: SOAR adapter for deep case hydration (live queries)
            siem_adapter: SIEM adapter for correlation queries (live queries)
            runbook_registry: Optional RunbookRegistry for whitelist checks
            config: Configuration options
        """
        self.case_database = case_database or []
        self.soar_adapter = soar_adapter
        self.siem_adapter = siem_adapter
        self.runbook_registry = runbook_registry
        self.config = config or {}

        # TF-IDF vectorizer for text similarity
        self.vectorizer = TfidfVectorizer(max_features=100)
        self.case_vectors = None

        # Entity matching weights (priority: rule > ioc > entity > text)
        self.weights = self.config.get(
            "weights",
            {
                "rule_id": 2.0,
                "indicator": 1.5,
                "entity": 1.0,
                "text": 0.5,
            },
        )
        self.min_combined_score = self.config.get("min_combined_score", 0.3)

        # Harvesting thresholds
        self.min_similarity_for_harvest = self.config.get("min_similarity", 0.65)
        self.high_similarity_threshold = self.config.get("high_similarity", 0.80)
        self.max_actions_per_case = self.config.get("max_actions_per_case", 5)

        # Build index on init
        self._build_index()

    # =========================================================================
    # PUBLIC API: Unified linking entry point
    # =========================================================================

    async def retrieve_rank_hydrate(
        self,
        signal: Signal,
        graph: Optional[TriageContextGraph] = None,
    ) -> LinkingResult:
        """Unified case linking: graph-aware retrieve, rank, hydrate, and harvest.

        Flow:
        1. READ GRAPH: Get detection presence, entities, asset criticality, budgets
        2. VECTOR INDEX: Fast TF-IDF + entity matching on local case database
        3. LIVE SOAR QUERY: Query SOAR for exact-link and entity-overlap cases
        4. GRAPH FILTER: Use detection presence to skip/boost candidates
        5. SOAR DEEP PULL: Fetch full case details for top-K only
        6. GRAPH WRITE: Add similar case nodes and edges
        7. HARVEST: Extract runbook refs and action templates

        Args:
            signal: Signal to find cases for
            graph: Case knowledge graph (provides context + receives writes)

        Returns:
            LinkingResult with similar cases, harvested artifacts, and graph links
        """
        # =====================================================================
        # STEP 1: READ GRAPH STATE (budgets, detection presence, entities)
        # =====================================================================
        if graph:
            max_candidates = graph.budget.max_case_candidates
            max_deep = graph.budget.max_deep_case_pulls
            detection_present = self._check_detection_presence(graph)
            graph_entities = self._extract_entities_from_graph(graph)
            asset_criticality = self._get_asset_criticality_from_graph(graph)
        else:
            max_candidates = 25
            max_deep = 10
            detection_present = None  # Unknown
            graph_entities = {}
            asset_criticality = "medium"

        # Check if we should run based on signal type + graph state
        if graph and not self._should_run_with_graph_context(
            signal, graph, detection_present
        ):
            return LinkingResult(
                similar_cases=[],
                harvest_result=HarvestResult(),
                links_added_to_graph=0,
                candidates_evaluated=0,
                deep_hydrated=0,
            )

        # =====================================================================
        # STEP 2: VECTOR INDEX QUERY (fast, local TF-IDF + entity matching)
        # =====================================================================
        local_candidates = self._find_similar_extended(signal, top_k=max_candidates)

        # =====================================================================
        # STEP 3: LIVE SOAR/SIEM QUERY (if adapter available)
        # =====================================================================
        live_candidates = await self._query_soar_for_related_cases(
            signal, graph_entities, max_candidates
        )

        # Merge and deduplicate candidates
        all_candidates = self._merge_candidates(local_candidates, live_candidates)

        # =====================================================================
        # STEP 4: GRAPH-AWARE FILTERING (boost/skip based on detection presence)
        # =====================================================================
        filtered_candidates = self._filter_with_graph_context(
            all_candidates, detection_present, asset_criticality
        )

        # Sort by combined score
        ranked_candidates = sorted(
            filtered_candidates, key=lambda x: x.combined_score, reverse=True
        )

        # =====================================================================
        # STEP 5: SOAR DEEP PULL (expensive - only top-K)
        # =====================================================================
        similar_cases = await self._hydrate_to_models(
            signal,
            ranked_candidates[:max_deep],
        )

        # =====================================================================
        # STEP 6: HARVEST ARTIFACTS (runbook refs, action templates)
        # =====================================================================
        harvest_result = self._harvest_artifacts(similar_cases)

        # =====================================================================
        # STEP 7: WRITE TO GRAPH (similar case nodes + edges)
        # =====================================================================
        links_added = 0
        if graph:
            for case in similar_cases:
                if self._add_case_to_graph(case, signal, graph):
                    links_added += 1

        return LinkingResult(
            similar_cases=similar_cases,
            harvest_result=harvest_result,
            links_added_to_graph=links_added,
            candidates_evaluated=len(all_candidates),
            deep_hydrated=len(similar_cases),
        )

    # =========================================================================
    # GRAPH STATE READERS
    # =========================================================================

    def _check_detection_presence(self, graph: TriageContextGraph) -> Optional[bool]:
        """Check if detection is present from graph observations."""
        from soc_triage_bot.models.case_graph import ObservationNode, ObservationType

        obs_nodes = graph.get_nodes_by_type(NodeType.OBSERVATION)

        for node in obs_nodes:
            if isinstance(node, ObservationNode):
                if node.observation_type == ObservationType.DETECTION_PRESENCE:
                    # Check if detection was found or absent
                    return True  # Detection present

        return None  # No detection observation in graph yet

    def _extract_entities_from_graph(
        self, graph: TriageContextGraph
    ) -> Dict[str, List[str]]:
        """Extract canonical entities from graph for SOAR queries."""
        from soc_triage_bot.models.case_graph import EntityNode

        entities: Dict[str, List[str]] = {}

        entity_nodes = graph.get_nodes_by_type(NodeType.ENTITY)
        for node in entity_nodes:
            if isinstance(node, EntityNode):
                entity_type = (
                    node.entity_type.value
                    if hasattr(node.entity_type, "value")
                    else str(node.entity_type)
                )
                if entity_type not in entities:
                    entities[entity_type] = []
                entities[entity_type].append(node.entity_value)

        return entities

    def _get_asset_criticality_from_graph(self, graph: TriageContextGraph) -> str:
        """Get asset criticality from CMDB observations in graph."""
        from soc_triage_bot.models.case_graph import ObservationNode, ObservationType

        obs_nodes = graph.get_nodes_by_type(NodeType.OBSERVATION)

        for node in obs_nodes:
            if isinstance(node, ObservationNode):
                if node.observation_type == ObservationType.CMDB_ASSET:
                    # Extract criticality from observation properties
                    if node.properties:
                        return node.properties.get("business_criticality", "medium")

        return "medium"

    def _should_run_with_graph_context(
        self,
        signal: Signal,
        graph: TriageContextGraph,
        detection_present: Optional[bool],
    ) -> bool:
        """Determine if case linking should run based on graph context.

        Rules:
        - ALWAYS run for ALERT/SOAR_CONTAINER (they have case context)
        - For IOC/CVE: only if detection is ABSENT (need hunting context)
        - For IOC/CVE: if detection PRESENT, skip (no need for similar cases)
        """
        # Always run for alerts and SOAR containers
        if signal.signal_type in [SignalType.SIEM_ALERT, SignalType.USER_REPORT]:
            return True

        # For IOC/CVE: skip if detection already present
        if signal.signal_type in [SignalType.IOC, SignalType.CVE]:
            if detection_present is True:
                return False  # Detection found, no need for hunting context

        return True

    # =========================================================================
    # LIVE SOAR/SIEM QUERIES
    # =========================================================================

    async def _query_soar_for_related_cases(
        self,
        signal: Signal,
        graph_entities: Dict[str, List[str]],
        max_candidates: int,
    ) -> List[SimilarityResult]:
        """Query SOAR adapter for related cases (live query)."""
        if not self.soar_adapter:
            return []

        candidates = []

        try:
            # Query 1: Exact link (correlation_id, container_id)
            if signal.metadata.get("soar_id"):
                linked = await self._query_linked_cases(signal.metadata["soar_id"])
                candidates.extend(linked)

            # Query 2: Entity overlap (host, user, IP, hash)
            entity_cases = await self._query_entity_overlap_cases(
                graph_entities, max_candidates - len(candidates)
            )
            candidates.extend(entity_cases)

            # Query 3: Rule signature (rule_id TP/FP history)
            if signal.source.rule_id:
                rule_cases = await self._query_rule_history(
                    signal.source.rule_id, max_candidates - len(candidates)
                )
                candidates.extend(rule_cases)

        except Exception:
            pass  # Graceful fallback to local index

        return candidates[:max_candidates]

    async def _query_linked_cases(self, soar_id: str) -> List[SimilarityResult]:
        """Query SOAR for explicitly linked cases."""
        # Real implementation: await self.soar_adapter.get_linked_cases(soar_id)
        return []

    async def _query_entity_overlap_cases(
        self, entities: Dict[str, List[str]], max_results: int
    ) -> List[SimilarityResult]:
        """Query SOAR for cases with entity overlap."""
        # Real implementation: await self.soar_adapter.search_by_entities(entities)
        return []

    async def _query_rule_history(
        self, rule_id: str, max_results: int
    ) -> List[SimilarityResult]:
        """Query SOAR/SIEM for rule TP/FP history."""
        # Real implementation: await self.siem_adapter.get_rule_history(rule_id)
        return []

    def _merge_candidates(
        self,
        local: List[SimilarityResult],
        live: List[SimilarityResult],
    ) -> List[SimilarityResult]:
        """Merge and deduplicate candidates from local + live sources."""
        seen_ids = set()
        merged = []

        # Prioritize live results (fresher)
        for candidate in live:
            if candidate.case_id not in seen_ids:
                seen_ids.add(candidate.case_id)
                merged.append(candidate)

        # Add local results
        for candidate in local:
            if candidate.case_id not in seen_ids:
                seen_ids.add(candidate.case_id)
                merged.append(candidate)

        return merged

    def _filter_with_graph_context(
        self,
        candidates: List[SimilarityResult],
        detection_present: Optional[bool],
        asset_criticality: str,
    ) -> List[SimilarityResult]:
        """Filter and boost candidates based on graph context."""
        filtered = []

        for candidate in candidates:
            score = candidate.combined_score

            # Boost TP outcomes if detection is present
            if detection_present and candidate.outcome == "TP":
                score *= 1.2

            # Boost FP outcomes if detection is absent (hunting context)
            if detection_present is False and candidate.outcome == "FP":
                score *= 1.1

            # Boost if asset is critical
            if asset_criticality in ["critical", "high"]:
                score *= 1.1

            # Create new result with adjusted score
            filtered.append(
                SimilarityResult(
                    case_id=candidate.case_id,
                    text_similarity=candidate.text_similarity,
                    entity_similarity=candidate.entity_similarity,
                    combined_score=min(1.0, score),  # Cap at 1.0
                    matched_entities=candidate.matched_entities,
                    outcome=candidate.outcome,
                )
            )

        return filtered

    async def link_cases(
        self,
        signal: Signal,
        graph: TriageContextGraph,
    ) -> int:
        """Backward-compatible: Link similar cases to graph.

        Args:
            signal: Signal to find cases for
            graph: Case knowledge graph to update

        Returns:
            Number of case links added
        """
        result = await self.retrieve_rank_hydrate(signal, graph)
        return result.links_added_to_graph

    def find_similar_as_models(
        self,
        signal: Signal,
        top_k: int = 5,
    ) -> List[SimilarCase]:
        """Backward-compatible: Find similar cases as SimilarCase models.

        Args:
            signal: Signal to find similar cases for
            top_k: Number of top similar cases to return

        Returns:
            List of SimilarCase Pydantic models
        """
        import asyncio

        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        if loop.is_running():
            # In running loop, use sync version
            candidates = self._find_similar_extended(signal, top_k=top_k)
            return self._candidates_to_models(candidates)

        result = loop.run_until_complete(self.retrieve_rank_hydrate(signal, graph=None))
        return result.similar_cases[:top_k]

    def find_similar_extended(
        self,
        signal: Signal,
        top_k: int = 5,
    ) -> List[SimilarityResult]:
        """Backward-compatible: Find similar cases with entity matching.

        Args:
            signal: Signal to find similar cases for
            top_k: Number of top similar cases to return

        Returns:
            List of SimilarityResult with entity matching details
        """
        return self._find_similar_extended(signal, top_k=top_k)

    # =========================================================================
    # STAGE 1: Index queries (TF-IDF + entity matching)
    # =========================================================================

    def _build_index(self):
        """Build TF-IDF index from case database."""
        if not self.case_database:
            self.case_vectors = None
            return

        case_texts = [self._case_to_text(case) for case in self.case_database]

        try:
            self.case_vectors = self.vectorizer.fit_transform(case_texts)
        except Exception:
            self.case_vectors = None

    def _find_similar_extended(
        self,
        signal: Signal,
        top_k: int = 25,
    ) -> List[SimilarityResult]:
        """Find similar cases using TF-IDF + entity matching."""
        if not self.case_database:
            return []

        signal_entities = self._extract_signal_entities(signal)
        signal_text = self._signal_to_text(signal)

        results: List[SimilarityResult] = []

        for idx, case in enumerate(self.case_database):
            # Calculate text similarity
            text_sim = 0.0
            if self.case_vectors is not None:
                try:
                    signal_vector = self.vectorizer.transform([signal_text])
                    # Handle sparse matrix row access
                    case_vector = self.case_vectors[idx]  # type: ignore[index]
                    similarity_result = cosine_similarity(signal_vector, case_vector)
                    text_sim = float(similarity_result[0, 0])
                except Exception:
                    pass

            # Calculate entity similarity
            case_entities = self._extract_case_entities(case)
            entity_sim, matched = self._calculate_entity_similarity(
                signal_entities, case_entities
            )

            # Combined score (weighted)
            text_weight = self.weights.get("text", 0.5)
            entity_weight = sum(self.weights.values()) - text_weight
            combined = (text_sim * text_weight + entity_sim * entity_weight) / (
                text_weight + entity_weight
            )

            if combined >= self.min_combined_score:
                results.append(
                    SimilarityResult(
                        case_id=case.get("case_id", f"case-{idx}"),
                        text_similarity=round(text_sim, 3),
                        entity_similarity=round(entity_sim, 3),
                        combined_score=round(combined, 3),
                        matched_entities=matched,
                        outcome=case.get("outcome"),
                    )
                )

        # Sort by combined score descending
        results.sort(key=lambda x: x.combined_score, reverse=True)
        return results[:top_k]

    # =========================================================================
    # STAGE 2: Text/Entity extraction helpers
    # =========================================================================

    def _case_to_text(self, case: Dict[str, Any]) -> str:
        """Convert case to text representation."""
        parts = [
            case.get("title", ""),
            case.get("description", ""),
            case.get("signal_type", ""),
            " ".join(case.get("tags", [])),
        ]

        entities = case.get("entities", {})
        for entity_type, entity_values in entities.items():
            if isinstance(entity_values, list):
                parts.append(f"{entity_type}:{' '.join(entity_values)}")
            else:
                parts.append(f"{entity_type}:{entity_values}")

        return " ".join(parts)

    def _signal_to_text(self, signal: Signal) -> str:
        """Convert signal to text representation."""
        parts = [
            signal.title,
            signal.description,
            signal.signal_type.value,
            " ".join(signal.tags),
        ]

        for entity_type, entity_values in signal.entities.items():
            parts.append(f"{entity_type}:{' '.join(entity_values)}")

        return " ".join(parts)

    def _extract_signal_entities(self, signal: Signal) -> Dict[str, Set[str]]:
        """Extract entities from signal for matching."""
        entities: Dict[str, Set[str]] = {
            "rule_id": set(),
            "indicator": set(),
            "hostname": set(),
            "username": set(),
            "ip": set(),
        }

        # Rule ID from detection context
        if signal.detection_context:
            if signal.detection_context.rule_id:
                entities["rule_id"].add(signal.detection_context.rule_id)
            if signal.detection_context.detection_name:
                entities["rule_id"].add(signal.detection_context.detection_name)

        # Rule ID from source (legacy)
        if signal.source.rule_id:
            entities["rule_id"].add(signal.source.rule_id)

        # Indicators from artifact context
        if signal.artifact_context:
            for attr in ["sha256", "md5", "domain", "ip", "url", "process_name"]:
                val = getattr(signal.artifact_context, attr, None)
                if val:
                    entities["indicator"].add(val)

        # Indicators from legacy field
        for ioc_type, ioc_val in signal.indicators.items():
            entities["indicator"].add(ioc_val)

        # Entities from entity context
        if signal.entity_context:
            if signal.entity_context.hostname:
                entities["hostname"].add(signal.entity_context.hostname)
            if signal.entity_context.username:
                entities["username"].add(signal.entity_context.username)
            if signal.entity_context.src_ip:
                entities["ip"].add(signal.entity_context.src_ip)

        # Entities from legacy field
        for entity_type, entity_values in signal.entities.items():
            if entity_type in entities:
                entities[entity_type].update(entity_values)

        return entities

    def _extract_case_entities(self, case: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract entities from historical case for matching."""
        entities: Dict[str, Set[str]] = {
            "rule_id": set(),
            "indicator": set(),
            "hostname": set(),
            "username": set(),
            "ip": set(),
        }

        # Rule ID
        if case.get("rule_id"):
            entities["rule_id"].add(case["rule_id"])
        if case.get("source", {}).get("rule_id"):
            entities["rule_id"].add(case["source"]["rule_id"])

        # Indicators
        for ioc_type, ioc_val in case.get("indicators", {}).items():
            if isinstance(ioc_val, list):
                entities["indicator"].update(ioc_val)
            else:
                entities["indicator"].add(ioc_val)

        # Entities
        for entity_type, entity_values in case.get("entities", {}).items():
            if entity_type in entities:
                if isinstance(entity_values, list):
                    entities[entity_type].update(entity_values)
                else:
                    entities[entity_type].add(entity_values)

        return entities

    def _calculate_entity_similarity(
        self,
        signal_entities: Dict[str, Set[str]],
        case_entities: Dict[str, Set[str]],
    ) -> Tuple[float, List[EntityMatch]]:
        """Calculate entity-based similarity with weighted scoring."""
        matches: List[EntityMatch] = []
        weighted_scores = []
        total_weight = 0

        for entity_type in ["rule_id", "indicator", "hostname", "username", "ip"]:
            signal_set = signal_entities.get(entity_type, set())
            case_set = case_entities.get(entity_type, set())

            if not signal_set and not case_set:
                continue

            # Calculate Jaccard similarity
            intersection = signal_set & case_set
            union = signal_set | case_set

            jaccard = len(intersection) / len(union) if union else 0

            # Weight by entity type priority
            weight_key = "indicator" if entity_type not in self.weights else entity_type
            if entity_type in ["hostname", "username", "ip"]:
                weight_key = "entity"
            weight = self.weights.get(weight_key, 1.0)

            weighted_scores.append(jaccard * weight)
            total_weight += weight

            # Track matched entities
            for val in intersection:
                matches.append(
                    EntityMatch(entity_type=entity_type, value=val, source="both")
                )

        if total_weight == 0:
            return 0.0, matches

        return sum(weighted_scores) / total_weight, matches

    # =========================================================================
    # STAGE 3: Deep hydration to SimilarCase models
    # =========================================================================

    async def _hydrate_to_models(
        self,
        signal: Signal,
        candidates: List[SimilarityResult],
    ) -> List[SimilarCase]:
        """Deep hydrate candidates to SimilarCase models with SOAR artifacts."""
        similar_cases: List[SimilarCase] = []

        for res in candidates:
            case_data = self._get_case_details(res.case_id) or {}

            # Build RunbookRef objects
            runbook_refs: List[RunbookRef] = []
            attachments_metadata: List[AttachmentMetadata] = []
            tasks_template_id: Optional[str] = None

            # Try to hydrate from SOAR adapter
            if self.soar_adapter:
                try:
                    soar_case = await self._fetch_case_from_soar(res.case_id)
                    if soar_case:
                        runbook_refs = self._extract_runbook_refs(soar_case)
                        attachments_metadata = self._extract_attachments(soar_case)
                        tasks_template_id = soar_case.get("tasks_template_id")
                except Exception:
                    pass

            # Fallback: check local case_data
            if not runbook_refs and "runbook_refs" in case_data:
                for ref_data in case_data.get("runbook_refs", []):
                    if isinstance(ref_data, dict):
                        runbook_refs.append(
                            RunbookRef(
                                ref_id=ref_data.get("ref_id", ""),
                                ref_type=ref_data.get("ref_type", "runbook"),
                                source=ref_data.get("source", "local"),
                                title=ref_data.get("title"),
                                whitelisted=ref_data.get("whitelisted", False),
                            )
                        )

            similar_cases.append(
                SimilarCase(
                    case_id=res.case_id,
                    similarity=res.combined_score,
                    signal_type=case_data.get("signal_type", ""),
                    title=case_data.get("title", ""),
                    outcome=res.outcome or "unknown",
                    matched_entities=[
                        f"{m.entity_type}:{m.value}" for m in res.matched_entities
                    ],
                    actions_taken=case_data.get("actions_taken", []),
                    notes=case_data.get("notes", ""),
                    runbook_refs=runbook_refs,
                    tasks_template_id=tasks_template_id,
                    attachments_metadata=attachments_metadata,
                )
            )

        return similar_cases

    def _candidates_to_models(
        self,
        candidates: List[SimilarityResult],
    ) -> List[SimilarCase]:
        """Convert candidates to SimilarCase models (sync, no SOAR hydration)."""
        similar_cases: List[SimilarCase] = []

        for res in candidates:
            case_data = self._get_case_details(res.case_id) or {}

            similar_cases.append(
                SimilarCase(
                    case_id=res.case_id,
                    similarity=res.combined_score,
                    signal_type=case_data.get("signal_type", ""),
                    title=case_data.get("title", ""),
                    outcome=res.outcome or "unknown",
                    matched_entities=[
                        f"{m.entity_type}:{m.value}" for m in res.matched_entities
                    ],
                    actions_taken=case_data.get("actions_taken", []),
                    notes=case_data.get("notes", ""),
                    runbook_refs=[],
                    attachments_metadata=[],
                )
            )

        return similar_cases

    async def _fetch_case_from_soar(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full case details from SOAR."""
        if not self.soar_adapter:
            return None
        # Real implementation would call: await self.soar_adapter.get_case(case_id)
        return None

    def _extract_runbook_refs(self, soar_case: Dict[str, Any]) -> List[RunbookRef]:
        """Extract runbook refs from SOAR case data."""
        refs = []
        for ref_data in soar_case.get("runbook_refs", []):
            refs.append(
                RunbookRef(
                    ref_id=ref_data.get("ref_id", ""),
                    ref_type=ref_data.get("ref_type", "runbook"),
                    source=ref_data.get("source", "soar"),
                    title=ref_data.get("title"),
                    url=ref_data.get("url"),
                    whitelisted=ref_data.get("whitelisted", False),
                )
            )
        return refs

    def _extract_attachments(
        self, soar_case: Dict[str, Any]
    ) -> List[AttachmentMetadata]:
        """Extract attachment metadata from SOAR case data."""
        attachments = []
        for att_data in soar_case.get("attachments_metadata", []):
            attachments.append(
                AttachmentMetadata(
                    attachment_id=att_data.get("attachment_id", ""),
                    filename=att_data.get("filename", ""),
                    content_type=att_data.get(
                        "content_type", "application/octet-stream"
                    ),
                    size_bytes=att_data.get("size_bytes"),
                    is_playbook=att_data.get("is_playbook", False),
                )
            )
        return attachments

    # =========================================================================
    # STAGE 4: Artifact harvesting
    # =========================================================================

    def _harvest_artifacts(self, similar_cases: List[SimilarCase]) -> HarvestResult:
        """Harvest actions and runbook refs from similar cases."""
        result = HarvestResult()
        seen_action_keys: set = set()

        for case in similar_cases:
            result.cases_analyzed += 1
            confidence_level = self._assess_case_confidence(case)

            # Collect runbook refs
            for ref in case.runbook_refs:
                result.runbook_refs_found.append(ref)

                is_whitelisted = self._is_runbook_whitelisted(ref)
                runbook_actions = self._get_actions_from_runbook_ref(ref)

                for rb_action in runbook_actions:
                    action_key = f"{rb_action.get('intent')}|{rb_action.get('tool')}|{rb_action.get('title')}"
                    if action_key in seen_action_keys:
                        continue
                    seen_action_keys.add(action_key)

                    harvested = HarvestedAction(
                        id=f"harvest_{case.case_id}_{len(result.actions)}",
                        title=rb_action.get("title", ""),
                        description=rb_action.get("description", ""),
                        intent=rb_action.get("intent", "investigate"),
                        tool=rb_action.get("tool", "SOAR"),
                        owner=rb_action.get("owner", "SOC"),
                        steps=rb_action.get("steps", []),
                        priority=rb_action.get("priority", 3),
                        source_case_id=case.case_id,
                        source_runbook_ref=ref.ref_id,
                        similarity=case.similarity,
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

            # Extract from actions_taken if no runbook refs
            if not case.runbook_refs and case.actions_taken:
                for action_str in case.actions_taken[: self.max_actions_per_case]:
                    action_key = f"actions_taken|{action_str}"
                    if action_key in seen_action_keys:
                        continue
                    seen_action_keys.add(action_key)

                    harvested = HarvestedAction(
                        id=f"harvest_{case.case_id}_{len(result.actions)}",
                        title=action_str[:50],
                        description=action_str,
                        intent="investigate",
                        tool="SOAR",
                        owner="SOC",
                        source_case_id=case.case_id,
                        similarity=case.similarity,
                        confidence_level=confidence_level,
                    )
                    result.actions.append(harvested)
                    result.suggested_actions += 1

            # Collect attachments
            result.attachments_found.extend(case.attachments_metadata)

        return result

    def _assess_case_confidence(self, case: SimilarCase) -> ArtifactConfidenceLevel:
        """Assess confidence level for a case."""
        similarity = case.similarity
        disposition = case.disposition.upper() if case.disposition else ""

        if similarity >= self.high_similarity_threshold and disposition in [
            "TP",
            "RESOLVED",
            "TRUE_POSITIVE",
        ]:
            return ArtifactConfidenceLevel.HIGH

        if similarity >= self.min_similarity_for_harvest and disposition in [
            "TP",
            "RESOLVED",
            "TRUE_POSITIVE",
        ]:
            return ArtifactConfidenceLevel.MEDIUM

        if disposition in ["FP", "FALSE_POSITIVE"]:
            return ArtifactConfidenceLevel.LOW

        return ArtifactConfidenceLevel.SUGGESTED

    def _is_runbook_whitelisted(self, ref: RunbookRef) -> bool:
        """Check if a runbook reference is whitelisted."""
        if ref.whitelisted:
            return True

        if self.runbook_registry and hasattr(self.runbook_registry, "get_runbook"):
            runbook = self.runbook_registry.get_runbook(ref.ref_id)
            if runbook and runbook.whitelisted:
                return True

        return False

    def _get_actions_from_runbook_ref(self, ref: RunbookRef) -> List[Dict[str, Any]]:
        """Get actions from a runbook reference."""
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
        return []

    # =========================================================================
    # STAGE 5: Graph integration
    # =========================================================================

    def _should_run(self, signal: Signal, graph: TriageContextGraph) -> bool:
        """Determine if case linking should run based on signal type."""
        # Always run for alerts and SOAR containers
        if signal.signal_type in [SignalType.SIEM_ALERT, SignalType.USER_REPORT]:
            return True

        # For IOC/CVE: check if detection is absent (no telemetry found)
        if signal.signal_type in [SignalType.IOC, SignalType.CVE]:
            from soc_triage_bot.models.case_graph import ObservationType

            obs_nodes = graph.get_nodes_by_type(NodeType.OBSERVATION)

            for node in obs_nodes:
                from soc_triage_bot.models.case_graph import ObservationNode

                if isinstance(node, ObservationNode):
                    if node.observation_type == ObservationType.DETECTION_PRESENCE:
                        return False  # Detection present, skip similarity

            return True  # No detection = run similarity for hunting context

        return True

    def _add_case_to_graph(
        self,
        case: SimilarCase,
        signal: Signal,
        graph: TriageContextGraph,
    ) -> bool:
        """Add similar case node and edges to graph."""
        case_id = case.case_id
        if not case_id:
            return False

        # Create provenance
        provenance = Provenance(
            source_system="CaseContextLinking",
            query_fingerprint=f"similar_{signal.signal_id}_{case_id}",
            ttl_seconds=86400,
            confidence=case.similarity,
            evidence_refs=case.matched_entities,
        )

        # Create similar case node
        case_node = SimilarCaseRefNode(
            node_id=f"similar_case_{case_id}",
            node_type=NodeType.SIMILAR_CASE_REF,
            ref_case_id=case_id,
            similarity_score=case.similarity,
            outcome=case.outcome or "unknown",
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
            weight=case.similarity,
            provenance=provenance,
        )

        graph.add_edge(edge)

        return True

    def get_linked_cases_from_graph(
        self,
        graph: TriageContextGraph,
    ) -> List[Dict[str, Any]]:
        """Extract linked cases from graph for downstream use."""
        cases = []

        case_nodes = graph.get_nodes_by_type(NodeType.SIMILAR_CASE_REF)

        for node in case_nodes:
            if isinstance(node, SimilarCaseRefNode):
                cases.append(
                    {
                        "case_id": node.ref_case_id,
                        "similarity": node.similarity_score,
                        "outcome": node.outcome,
                        "overlap": "graph_linked",
                        "actions_taken": [],
                    }
                )

        cases.sort(key=lambda x: x.get("similarity", 0.0), reverse=True)

        return cases

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _get_case_details(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get details of a specific case from local database."""
        for case in self.case_database:
            if case.get("case_id") == case_id:
                return case
        return None

    def add_case(self, case: Dict[str, Any]):
        """Add a new case to the database and rebuild index."""
        self.case_database.append(case)
        self._build_index()


# =============================================================================
# BACKWARD COMPATIBILITY: Aliases
# =============================================================================

# For imports that still reference SimilarityService
SimilarityService = CaseContextLinkingService
