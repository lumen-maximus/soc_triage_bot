"""Enrichment data models."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class EnrichmentStatus(str, Enum):
    """Status of enrichment operation."""
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    TIMEOUT = "timeout"


class EnrichmentResult(BaseModel):
    """Result from an enrichment adapter."""
    
    adapter: str = Field(..., description="Name of the adapter")
    status: EnrichmentStatus
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Enrichment data"
    )
    
    error: Optional[str] = None
    duration_ms: Optional[float] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "adapter": "threat_intel",
                "status": "success",
                "timestamp": "2025-12-14T19:00:00Z",
                "data": {
                    "reputation": "malicious",
                    "threat_score": 95,
                    "categories": ["malware", "c2"]
                },
                "duration_ms": 234.5
            }
        }
