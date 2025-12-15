"""Similar case retrieval service.

Extended with entity-based matching for multi-track forecasting support.
Returns structured SimilarCase objects with matched entities and resolution info.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from ..models import Signal
from ..models.triage_report import SimilarCase


@dataclass
class EntityMatch:
    """An entity match between current signal and historical case."""

    entity_type: str  # 'rule_id', 'indicator', 'hostname', 'username', etc.
    value: str
    source: str  # 'signal' or 'case'


@dataclass
class SimilarityResult:
    """Extended similarity result with entity matching."""

    case_id: str
    text_similarity: float  # 0-1 from TF-IDF
    entity_similarity: float  # 0-1 from entity overlap
    combined_score: float  # Weighted combination
    matched_entities: List[EntityMatch]
    outcome: Optional[str]  # 'TP', 'FP', or None


class SimilarityService:
    """Service for finding similar past cases.

    Extended for multi-track support:
    - Entity-based matching (rule_id, indicators, hosts)
    - Weighted scoring: rule_id > indicators > entities > text
    - Returns SimilarCase objects with resolution info
    """

    def __init__(
        self,
        case_database: Optional[List[Dict[str, Any]]] = None,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize similarity service.

        Args:
            case_database: Historical case database
            config: Configuration for similarity weights
        """
        self.case_database = case_database or []
        self.vectorizer = TfidfVectorizer(max_features=100)
        self.config = config or {}

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

        self._build_index()

    def _build_index(self):
        """Build similarity index from case database."""
        if not self.case_database:
            self.case_vectors = None
            return

        case_texts = [self._case_to_text(case) for case in self.case_database]

        try:
            self.case_vectors = self.vectorizer.fit_transform(case_texts)
        except Exception:
            self.case_vectors = None

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

            # Calculate Jaccard similarity for this entity type
            intersection = signal_set & case_set
            union = signal_set | case_set

            if union:
                jaccard = len(intersection) / len(union)
            else:
                jaccard = 0

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

    def find_similar_extended(
        self,
        signal: Signal,
        top_k: int = 5,
    ) -> List[SimilarityResult]:
        """Find similar past cases with entity matching.

        Args:
            signal: Signal to find similar cases for
            top_k: Number of top similar cases to return

        Returns:
            List of SimilarityResult with entity matching details
        """
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
                    text_sim = float(
                        cosine_similarity(signal_vector, self.case_vectors[idx])[0][0]
                    )
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
                        outcome=case.get("outcome"),  # 'TP' or 'FP'
                    )
                )

        # Sort by combined score descending
        results.sort(key=lambda x: x.combined_score, reverse=True)
        return results[:top_k]

    def find_similar_as_models(
        self,
        signal: Signal,
        top_k: int = 5,
    ) -> List[SimilarCase]:
        """Find similar cases and return as SimilarCase models.

        Args:
            signal: Signal to find similar cases for
            top_k: Number of top similar cases to return

        Returns:
            List of SimilarCase Pydantic models
        """
        results = self.find_similar_extended(signal, top_k)
        similar_cases: List[SimilarCase] = []

        for res in results:
            case_data = self.get_case_details(res.case_id) or {}

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
                )
            )

        return similar_cases

    # =========================================================================
    # LEGACY METHODS (for backward compatibility)
    # =========================================================================

    def find_similar(
        self, signal: Signal, top_k: int = 5, min_similarity: float = 0.3
    ) -> List[Tuple[str, float]]:
        """Legacy find_similar returning (case_id, similarity) tuples.

        DEPRECATED: Use find_similar_extended() for new code.
        """
        if not self.case_database or self.case_vectors is None:
            return []

        try:
            signal_text = self._signal_to_text(signal)
            signal_vector = self.vectorizer.transform([signal_text])
            similarities = cosine_similarity(signal_vector, self.case_vectors)[0]

            similar_indices = np.argsort(similarities)[::-1][:top_k]

            results = []
            for idx in similar_indices:
                similarity = similarities[idx]
                if similarity >= min_similarity:
                    case_id = self.case_database[idx].get("case_id", f"case-{idx}")
                    results.append((case_id, float(similarity)))

            return results
        except Exception:
            return []

    def add_case(self, case: Dict[str, Any]):
        """Add a new case to the database."""
        self.case_database.append(case)
        self._build_index()

    def get_case_details(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get details of a specific case."""
        for case in self.case_database:
            if case.get("case_id") == case_id:
                return case
        return None
