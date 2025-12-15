"""Enrichment data models.

Extended with evidence_id for traceability in AI overlay and multi-track forecasting.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EnrichmentStatus(str, Enum):
    """Status of enrichment operation."""

    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    TIMEOUT = "timeout"


class ExtractedEntity(BaseModel):
    """An entity extracted during enrichment."""

    entity_type: str = Field(..., description="Entity type (hostname, user, ip, etc.)")
    value: str = Field(..., description="Entity value")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = Field(default="", description="Where this entity was found")


class ExtractedIndicator(BaseModel):
    """An indicator (IOC) extracted during enrichment."""

    indicator_type: str = Field(
        ..., description="Indicator type (ip, domain, hash, etc.)"
    )
    value: str = Field(..., description="Indicator value")
    reputation: Optional[str] = Field(None, description="Reputation if known")
    threat_score: Optional[float] = Field(None, ge=0.0, le=100.0)
    source: str = Field(default="", description="Source of this indicator")


class EnrichmentResult(BaseModel):
    """Result from an enrichment adapter.

    Extended with evidence_id for AI overlay traceability.
    """

    adapter: str = Field(..., description="Name of the adapter")
    status: EnrichmentStatus
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Evidence traceability
    evidence_id: str = Field(
        default="",
        description="Unique evidence ID for AI traceability (e.g., 'TI-AlienVault-001')",
    )

    # Enrichment data
    data: Dict[str, Any] = Field(default_factory=dict, description="Enrichment data")

    # Extracted entities and indicators (for multi-track forecasting)
    extracted_entities: List[ExtractedEntity] = Field(
        default_factory=list,
        description="Entities discovered during enrichment",
    )
    extracted_indicators: List[ExtractedIndicator] = Field(
        default_factory=list,
        description="Indicators/IOCs discovered during enrichment",
    )

    # Error handling
    error: Optional[str] = None
    duration_ms: Optional[float] = None

    def generate_evidence_id(self, sequence: int = 1) -> str:
        """Generate a unique evidence ID for this enrichment.

        Args:
            sequence: Sequence number for multiple results from same adapter

        Returns:
            Evidence ID string like 'ENRICH-threat_intel-001'
        """
        self.evidence_id = f"ENRICH-{self.adapter}-{sequence:03d}"
        return self.evidence_id
