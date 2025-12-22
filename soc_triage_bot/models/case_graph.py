"""Case Knowledge Graph (CKG) models.

The CKG is the source-of-truth state machine for the triage pipeline.
Every stage adds nodes/edges or computes scores from the graph.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

# ============================================================================
# Provenance & Evidence Tracking
# ============================================================================


class Provenance(BaseModel):
    """Provenance metadata for nodes/edges."""

    source_system: str = Field(..., description="Source system (SIEM/SOAR/TI/CMDB/EDR)")
    query_fingerprint: Optional[str] = Field(
        None, description="Hash of query params for dedup"
    )
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_seconds: Optional[int] = Field(None, description="TTL for cache invalidation")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_refs: List[str] = Field(
        default_factory=list,
        description="Raw event IDs, URLs, case artifact IDs, alert IDs",
    )


class Scope(BaseModel):
    """Scope metadata for observations."""

    time_window_start: Optional[datetime] = None
    time_window_end: Optional[datetime] = None
    environment: Optional[str] = None  # prod/staging/dev
    tenant: Optional[str] = None
    sensor_coverage: Optional[List[str]] = None  # EDR/SIEM/NDR sensors


# ============================================================================
# Node Types
# ============================================================================


class NodeType(str, Enum):
    """Node type enumeration."""

    CASE = "case"
    SIGNAL = "signal"
    ENTITY = "entity"
    OBSERVATION = "observation"
    ARTIFACT = "artifact"
    ACTION = "action"
    OUTCOME = "outcome"
    FORECAST = "forecast"
    SIMILAR_CASE_REF = "similar_case_ref"


class EntityType(str, Enum):
    """Entity type enumeration."""

    HOST = "host"
    USER = "user"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    PROCESS = "process"
    EMAIL = "email"
    CLOUD_RESOURCE = "cloud_resource"
    APPLICATION = "application"
    DETECTION_RULE = "detection_rule"
    CVE = "cve"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"


class ObservationType(str, Enum):
    """Observation type enumeration."""

    SIEM_HIT = "siem_hit"
    EDR_TELEMETRY = "edr_telemetry"
    NETWORK_TELEMETRY = "network_telemetry"
    THREAT_INTEL = "threat_intel"
    VULNERABILITY = "vulnerability"
    CMDB_ASSET = "cmdb_asset"
    IDENTITY_CONTEXT = "identity_context"
    DETECTION_PRESENCE = "detection_presence"


class TriageMode(str, Enum):
    """Triage mode for budget control."""

    REUSE_ONLY = "reuse_only"  # Use cached/SOAR data only
    MIN_DELTA = "min_delta"  # Minimal new queries
    DEEP_DIVE = "deep_dive"  # Full investigation


# ============================================================================
# Base Node
# ============================================================================


class EvidenceNode(BaseModel):
    """Base node with provenance."""

    node_id: str = Field(..., description="Unique node ID")
    node_type: NodeType
    provenance: Provenance
    properties: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# Specific Node Types
# ============================================================================


class CaseNode(EvidenceNode):
    """Case container node."""

    node_type: Literal[NodeType.CASE] = NodeType.CASE
    case_id: str
    status: str = "open"  # open/investigating/closed
    owner: Optional[str] = None
    mode: TriageMode = TriageMode.MIN_DELTA
    budgets: Dict[str, int] = Field(
        default_factory=lambda: {
            "max_case_candidates": 25,
            "max_deep_pulls": 10,
            "max_enrichment_calls": 5,
        }
    )


class SignalNode(EvidenceNode):
    """Signal triggering node."""

    node_type: Literal[NodeType.SIGNAL] = NodeType.SIGNAL
    signal_id: str
    signal_type: str  # ALERT/IOC/VULN/ANOMALY/MANUAL/SOAR_CONTAINER
    signal_subtype: Optional[str] = None  # auth/endpoint/network/email/vuln
    first_seen: datetime
    time_window: Optional[Scope] = None
    raw_ids: Dict[str, str] = Field(
        default_factory=dict, description="alert_id, container_id, correlation_id, etc."
    )


class EntityNode(EvidenceNode):
    """Canonical entity node."""

    node_type: Literal[NodeType.ENTITY] = NodeType.ENTITY
    entity_type: EntityType
    canonical_id: str = Field(..., description="Normalized identifier")
    entity_value: str = Field(..., description="hostname/IP/hash/etc.")
    aliases: List[str] = Field(
        default_factory=list, description="Alternative identifiers"
    )


class ObservationNode(EvidenceNode):
    """Observation/finding node."""

    node_type: Literal[NodeType.OBSERVATION] = NodeType.OBSERVATION
    observation_type: ObservationType
    scope: Optional[Scope] = None
    hit_count: Optional[int] = None
    sensor_coverage_gaps: List[str] = Field(default_factory=list)


class ArtifactNode(EvidenceNode):
    """SOAR artifact node."""

    node_type: Literal[NodeType.ARTIFACT] = NodeType.ARTIFACT
    artifact_type: str  # note/attachment/screenshot/ticket/runbook
    content_summary: Optional[str] = None
    attachment_id: Optional[str] = None
    url: Optional[str] = None


class ActionNode(EvidenceNode):
    """Proposed/executed action node."""

    node_type: Literal[NodeType.ACTION] = NodeType.ACTION
    action_id: str
    action_type: str  # contain/eradicate/recover/notify/tune
    priority: int
    status: str = "proposed"  # proposed/approved/executed/failed
    execution_receipt: Optional[Dict[str, Any]] = (
        None  # tool/request_id/result/timestamp
    )


class OutcomeNode(EvidenceNode):
    """Classification outcome node."""

    node_type: Literal[NodeType.OUTCOME] = NodeType.OUTCOME
    disposition: str  # TP/FP/Benign/Review
    severity: str
    confidence: str  # high/medium/low
    tp_likelihood: float
    top_drivers: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)


class ForecastNode(EvidenceNode):
    """ETS forecast node."""

    node_type: Literal[NodeType.FORECAST] = NodeType.FORECAST
    track_name: str  # rule/ioc/entity
    anomaly_score: Optional[float] = None
    baseline: Optional[float] = None
    current_vs_expected: Optional[str] = None


class SimilarCaseRefNode(EvidenceNode):
    """Reference to similar historical case."""

    node_type: Literal[NodeType.SIMILAR_CASE_REF] = NodeType.SIMILAR_CASE_REF
    ref_case_id: str
    similarity_score: float
    why_similar: List[str] = Field(default_factory=list)
    outcome: Optional[str] = None  # TP/FP from historical case


# ============================================================================
# Edge Types
# ============================================================================


class EdgeType(str, Enum):
    """Edge type enumeration."""

    HAS_SIGNAL = "has_signal"
    MENTIONS = "mentions"
    RELATED_TO = "related_to"
    HAS_OBSERVATION = "has_observation"
    HAS_ARTIFACT = "has_artifact"
    PROPOSES_ACTION = "proposes_action"
    EXECUTED_ACTION = "executed_action"
    HAS_OUTCOME = "has_outcome"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    CORRELATED_WITH = "correlated_with"
    SIMILAR_TO = "similar_to"
    HAD_ACTION = "had_action"
    JUSTIFIED_BY = "justified_by"
    DERIVED_FROM = "derived_from"
    ABOUT = "about"
    BASED_ON = "based_on"


class RelationType(str, Enum):
    """Typed entity relationships."""

    OWNED_BY = "owned_by"
    SPAWNED = "spawned"
    RESOLVED_FROM = "resolved_from"
    EXECUTED_ON = "executed_on"
    AUTHENTICATED_TO = "authenticated_to"
    COMMUNICATES_WITH = "communicates_with"
    CONTAINS = "contains"


# ============================================================================
# Base Edge
# ============================================================================


class EvidenceEdge(BaseModel):
    """Base edge with provenance."""

    edge_id: str = Field(..., description="Unique edge ID")
    edge_type: EdgeType
    source_node_id: str
    target_node_id: str
    provenance: Provenance
    properties: Dict[str, Any] = Field(default_factory=dict)
    relation_type: Optional[RelationType] = None  # For entity relationships
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    weight: float = Field(default=1.0, description="Edge weight for scoring")


# ============================================================================
# Governance Decision
# ============================================================================


class GovernanceDecision(BaseModel):
    """Governance gate decision."""

    auto_close_eligible: bool = False
    auto_action_eligible: bool = False
    requires_human: bool = True
    escalate: bool = False
    policy_rule_ids: List[str] = Field(default_factory=list)
    rationale: str = ""


# ============================================================================
# Retrieval Budgets
# ============================================================================


class RetrievalBudget(BaseModel):
    """Budget constraints for query planning."""

    max_case_candidates: int = 25
    max_deep_case_pulls: int = 10
    max_enrichment_adapters: int = 5
    max_siem_queries: int = 2
    max_ti_lookups: int = 10
    escalate_on_ambiguity: bool = True


# ============================================================================
# Main Graph
# ============================================================================


class TriageContextGraph(BaseModel):
    """Case Knowledge Graph - source of truth for triage run."""

    case_id: str = Field(..., description="Primary case identifier")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Graph structure (adjacency lists for in-memory efficiency)
    nodes: Dict[str, EvidenceNode] = Field(default_factory=dict)
    edges: List[EvidenceEdge] = Field(default_factory=list)

    # Quick lookups
    nodes_by_type: Dict[NodeType, List[str]] = Field(default_factory=dict)
    edges_by_type: Dict[EdgeType, List[str]] = Field(default_factory=dict)

    # Mode & budgets
    mode: TriageMode = TriageMode.MIN_DELTA
    budget: RetrievalBudget = Field(default_factory=RetrievalBudget)

    # Governance
    governance_decision: Optional[GovernanceDecision] = None

    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # ========================================================================
    # Graph Operations
    # ========================================================================

    def add_node(self, node: EvidenceNode) -> None:
        """Add node to graph with indexing."""
        self.nodes[node.node_id] = node

        # Update type index
        if node.node_type not in self.nodes_by_type:
            self.nodes_by_type[node.node_type] = []
        self.nodes_by_type[node.node_type].append(node.node_id)

        self.updated_at = datetime.now(timezone.utc)

    def add_edge(self, edge: EvidenceEdge) -> None:
        """Add edge to graph with indexing."""
        self.edges.append(edge)

        # Update type index
        if edge.edge_type not in self.edges_by_type:
            self.edges_by_type[edge.edge_type] = []
        self.edges_by_type[edge.edge_type].append(edge.edge_id)

        self.updated_at = datetime.now(timezone.utc)

    def get_node(self, node_id: str) -> Optional[EvidenceNode]:
        """Retrieve node by ID."""
        return self.nodes.get(node_id)

    def get_nodes_by_type(self, node_type: NodeType) -> List[EvidenceNode]:
        """Retrieve all nodes of a specific type."""
        node_ids = self.nodes_by_type.get(node_type, [])
        return [self.nodes[nid] for nid in node_ids if nid in self.nodes]

    def get_edges_by_type(self, edge_type: EdgeType) -> List[EvidenceEdge]:
        """Retrieve all edges of a specific type."""
        edge_ids = self.edges_by_type.get(edge_type, [])
        return [e for e in self.edges if e.edge_id in edge_ids]

    def get_edges_from_node(self, node_id: str) -> List[EvidenceEdge]:
        """Get all edges originating from node."""
        return [e for e in self.edges if e.source_node_id == node_id]

    def get_edges_to_node(self, node_id: str) -> List[EvidenceEdge]:
        """Get all edges pointing to node."""
        return [e for e in self.edges if e.target_node_id == node_id]

    def get_connected_nodes(
        self,
        node_id: str,
        edge_type: Optional[EdgeType] = None,
        direction: str = "outgoing",
    ) -> List[EvidenceNode]:
        """Get nodes connected via specific edge type.

        Args:
            node_id: Source node ID
            edge_type: Optional edge type filter
            direction: 'outgoing', 'incoming', or 'both'
        """
        connected = []

        if direction in ("outgoing", "both"):
            edges = self.get_edges_from_node(node_id)
            if edge_type:
                edges = [e for e in edges if e.edge_type == edge_type]
            for edge in edges:
                node = self.get_node(edge.target_node_id)
                if node:
                    connected.append(node)

        if direction in ("incoming", "both"):
            edges = self.get_edges_to_node(node_id)
            if edge_type:
                edges = [e for e in edges if e.edge_type == edge_type]
            for edge in edges:
                node = self.get_node(edge.source_node_id)
                if node:
                    connected.append(node)

        return connected

    def get_evidence_chain(self, outcome_node_id: str) -> Dict[str, Any]:
        """Get full evidence chain supporting an outcome.

        Returns supporting and contradicting observations.
        """
        supports = self.get_connected_nodes(
            outcome_node_id, edge_type=EdgeType.SUPPORTS, direction="incoming"
        )

        contradicts = self.get_connected_nodes(
            outcome_node_id, edge_type=EdgeType.CONTRADICTS, direction="incoming"
        )

        return {
            "supporting": supports,
            "contradicting": contradicts,
            "support_weight": sum(
                e.weight
                for e in self.get_edges_to_node(outcome_node_id)
                if e.edge_type == EdgeType.SUPPORTS
            ),
            "contradiction_weight": sum(
                e.weight
                for e in self.get_edges_to_node(outcome_node_id)
                if e.edge_type == EdgeType.CONTRADICTS
            ),
        }

    def compute_connectivity_score(self) -> float:
        """Compute graph connectivity as a TP indicator.

        TP cases tend to have high connectivity (entities → observations → impacts).
        FP cases tend to be disconnected or have contradictions.
        """
        if not self.nodes:
            return 0.0

        # Simple metric: edges per node
        connectivity = len(self.edges) / len(self.nodes)

        # Boost for supporting evidence, penalize contradictions
        outcome_nodes = self.get_nodes_by_type(NodeType.OUTCOME)
        if outcome_nodes:
            outcome_id = outcome_nodes[0].node_id
            chain = self.get_evidence_chain(outcome_id)
            connectivity += chain["support_weight"] * 0.1
            connectivity -= chain["contradiction_weight"] * 0.15

        return min(max(connectivity / 5.0, 0.0), 1.0)  # Normalize to 0-1

    def to_dict(self) -> Dict[str, Any]:
        """Export graph to dict for persistence."""
        return {
            "case_id": self.case_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "nodes": {nid: n.dict() for nid, n in self.nodes.items()},
            "edges": [e.dict() for e in self.edges],
            "mode": self.mode.value,
            "budget": self.budget.dict(),
            "governance_decision": (
                self.governance_decision.dict() if self.governance_decision else None
            ),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TriageContextGraph":
        """Load graph from dict."""
        # This would require more sophisticated deserialization
        # For now, basic structure
        return cls(
            case_id=data["case_id"],
            mode=TriageMode(data.get("mode", "min_delta")),
            budget=RetrievalBudget(**data.get("budget", {})),
            metadata=data.get("metadata", {}),
        )
