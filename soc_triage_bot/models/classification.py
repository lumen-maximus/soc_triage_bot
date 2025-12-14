"""Classification data models."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ClassificationLabel(str, Enum):
    """Classification labels for signals."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_POSITIVE = "benign_positive"
    UNKNOWN = "unknown"


class Classification(BaseModel):
    """Classification result for a signal."""
    
    label: ClassificationLabel
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0-1")
    
    reasoning: List[str] = Field(
        default_factory=list,
        description="Reasons for classification"
    )
    
    factors: Dict[str, float] = Field(
        default_factory=dict,
        description="Contributing factors and their weights"
    )
    
    similar_cases: List[str] = Field(
        default_factory=list,
        description="IDs of similar past cases"
    )
    
    forecast_data: Optional[Dict[str, float]] = Field(
        None,
        description="ETS forecast data"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "label": "true_positive",
                "confidence": 0.87,
                "reasoning": [
                    "IP address known malicious in threat intel",
                    "Unusual process execution pattern",
                    "Similar to 3 past confirmed incidents"
                ],
                "factors": {
                    "threat_intel_match": 0.9,
                    "anomaly_score": 0.75,
                    "historical_similarity": 0.8
                },
                "similar_cases": ["case-001", "case-042", "case-089"]
            }
        }
