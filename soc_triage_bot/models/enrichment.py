"""Enrichment data models.

Extended with evidence_id for traceability in AI overlay.
"""

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
