"""Similar case retrieval service."""

from typing import List, Dict, Any, Tuple, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
from ..models import Signal


class SimilarityService:
    """Service for finding similar past cases."""
    
    def __init__(self, case_database: List[Dict[str, Any]] = None):
        """Initialize similarity service.
        
        Args:
            case_database: Historical case database
        """
        self.case_database = case_database or []
        self.vectorizer = TfidfVectorizer(max_features=100)
        self._build_index()
    
    def _build_index(self):
        """Build similarity index from case database."""
        if not self.case_database:
            self.case_vectors = None
            return
        
        # Create text representations of cases
        case_texts = []
        for case in self.case_database:
            text = self._case_to_text(case)
            case_texts.append(text)
        
        # Vectorize
        try:
            self.case_vectors = self.vectorizer.fit_transform(case_texts)
        except Exception:
            self.case_vectors = None
    
    def _case_to_text(self, case: Dict[str, Any]) -> str:
        """Convert case to text representation for similarity comparison.
        
        Args:
            case: Case dictionary
            
        Returns:
            Text representation
        """
        parts = [
            case.get("title", ""),
            case.get("description", ""),
            case.get("signal_type", ""),
            " ".join(case.get("tags", [])),
        ]
        
        # Add entity information
        entities = case.get("entities", {})
        for entity_type, entity_values in entities.items():
            parts.append(f"{entity_type}:{' '.join(entity_values)}")
        
        return " ".join(parts)
    
    def _signal_to_text(self, signal: Signal) -> str:
        """Convert signal to text representation.
        
        Args:
            signal: Signal to convert
            
        Returns:
            Text representation
        """
        parts = [
            signal.title,
            signal.description,
            signal.signal_type.value,
            " ".join(signal.tags),
        ]
        
        # Add entity information
        for entity_type, entity_values in signal.entities.items():
            parts.append(f"{entity_type}:{' '.join(entity_values)}")
        
        return " ".join(parts)
    
    def find_similar(
        self, 
        signal: Signal, 
        top_k: int = 5,
        min_similarity: float = 0.3
    ) -> List[Tuple[str, float]]:
        """Find similar past cases.
        
        Args:
            signal: Signal to find similar cases for
            top_k: Number of top similar cases to return
            min_similarity: Minimum similarity threshold
            
        Returns:
            List of (case_id, similarity_score) tuples
        """
        if not self.case_database or self.case_vectors is None:
            return []
        
        try:
            # Convert signal to text and vectorize
            signal_text = self._signal_to_text(signal)
            signal_vector = self.vectorizer.transform([signal_text])
            
            # Calculate similarities
            similarities = cosine_similarity(signal_vector, self.case_vectors)[0]
            
            # Get top-k similar cases
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
        """Add a new case to the database.
        
        Args:
            case: Case to add
        """
        self.case_database.append(case)
        self._build_index()
    
    def get_case_details(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Get details of a specific case.
        
        Args:
            case_id: ID of the case
            
        Returns:
            Case details or None if not found
        """
        for case in self.case_database:
            if case.get("case_id") == case_id:
                return case
        return None
