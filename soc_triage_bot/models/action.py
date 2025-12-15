"""Action proposal data models."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """Types of proposed actions."""

    INVESTIGATE = "investigate"
    ESCALATE = "escalate"
    BLOCK = "block"
    ISOLATE = "isolate"
    MONITOR = "monitor"
    CLOSE = "close"
    NOTIFY = "notify"


class Action(BaseModel):
    """Proposed action for a signal."""

    action_id: str = Field(..., description="Unique action identifier")
    action_type: ActionType
    priority: int = Field(
        ..., ge=1, le=5, description="Priority 1 (highest) - 5 (lowest)"
    )

    title: str
    description: str

    # Action details
    steps: List[str] = Field(
        default_factory=list, description="Steps to execute the action"
    )

    # Context
    reasoning: str = Field(..., description="Reasoning for this action")
    rationale: str = Field(
        default="", description="Rationale for recommendations (defaults to reasoning)"
    )
    source: str = Field(
        ..., description="How action was generated: template/learned/generated"
    )

    # Metadata
    confidence: float = Field(..., ge=0.0, le=1.0)
    estimated_effort: Optional[str] = None  # e.g., "5 minutes", "30 minutes"
    automation_available: bool = False

    metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional metadata (owner, auto, etc.)"
    )

    related_entities: Dict[str, List[str]] = Field(
        default_factory=dict, description="Entities this action targets"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "action_id": "act-001",
                "action_type": "isolate",
                "priority": 1,
                "title": "Isolate Compromised Host",
                "description": "Isolate workstation-01 from network",
                "steps": [
                    "Verify host status in EDR",
                    "Initiate network isolation via EDR",
                    "Notify IT security team",
                    "Document action in case management",
                ],
                "reasoning": "High confidence malware detection on critical asset",
                "rationale": "",
                "source": "template",
                "confidence": 0.92,
                "estimated_effort": "5 minutes",
                "automation_available": True,
                "metadata": {"owner": "SOC", "auto": True},
                "related_entities": {"hostname": ["workstation-01"]},
            }
        }
