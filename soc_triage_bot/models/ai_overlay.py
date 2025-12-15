"""AI Overlay data models.

This module defines placeholder models for future AI/LLM integration.
The AI overlay is applied AFTER deterministic scoring and enrichment are complete.
It provides human-readable summaries, explanations, and suggestions - but does NOT
replace the underlying deterministic scoring logic.

Usage:
    When AI support is integrated, populate these models and pass to generate_report().
    The template will conditionally render AI sections only when data is present.
"""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class TPFPLikelihood(str, Enum):
    """AI advisory on TP/FP likelihood."""

    LIKELY_TP = "likely_tp"
    UNCLEAR = "unclear"
    LIKELY_FP = "likely_fp"


class AINextCheck(BaseModel):
    """A suggested next check/query for the analyst.

    These are parameterized query templates the analyst can run,
    NOT invented facts or conclusions.
    """

    query_template_id: str = Field(
        ..., description="Query template identifier (e.g., 'Q12')"
    )
    description: str = Field(..., description="What this query checks")
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Parameters to fill in the template (e.g., host=X, timeframe=24h)",
    )
    target_system: str = Field(
        default="splunk",
        description="Target system for the query (splunk, crowdstrike, sentinel, etc.)",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "query_template_id": "Q12",
                "description": "Check for lateral movement from this host in the last 24h",
                "parameters": {"host": "workstation-01", "timeframe": "24h"},
                "target_system": "splunk",
            }
        }


class AISimilarCaseNarrative(BaseModel):
    """AI narrative comparing current case to a similar historical case.

    Note: The similarity search itself is deterministic (embeddings + retrieval).
    The AI layer explains WHY they're similar and what worked before.
    """

    case_id: str = Field(..., description="Historical case ID")
    similarity_score: float = Field(
        ..., ge=0.0, le=1.0, description="Deterministic similarity score"
    )
    shared_traits: List[str] = Field(
        default_factory=list,
        description="What traits this case shares with the historical case",
    )
    resolution_summary: str = Field(
        default="", description="How the historical case was resolved"
    )
    relevance_explanation: str = Field(
        default="", description="AI explanation of why this case is relevant"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "case_id": "case-1842",
                "similarity_score": 0.87,
                "shared_traits": [
                    "Same source IP range",
                    "PowerShell with encoded commands",
                    "After-hours execution",
                ],
                "resolution_summary": "Confirmed TP, contained via host isolation, credentials reset",
                "relevance_explanation": "This case shares the same attack pattern and IOCs, resolved as TP after credential theft was confirmed.",
            }
        }


class AIOverlay(BaseModel):
    """AI overlay layer for triage reports.

    This is applied AFTER the evidence bundle is complete. It provides:
    1. Executive summary (human-readable narrative)
    2. Explanation of the deterministic score
    3. TP/FP likelihood advisory with rationale
    4. Hypotheses and decision checklist
    5. Suggested next checks (parameterized queries)
    6. Similar cases narrative

    IMPORTANT: This layer does NOT replace deterministic scoring.
    It's an overlay that helps analysts understand and act on the evidence.
    """

    # 1. Executive Summary (2-6 bullets)
    executive_summary: List[str] = Field(
        default_factory=list,
        description="2-6 bullet summary of what happened and why it matters",
    )

    # 2. Scorecard Explanation
    scorecard_explanation: str = Field(
        default="", description="Plain English explanation of why the score is high/low"
    )

    # 3. TP/FP Likelihood Advisory
    tp_fp_likelihood: Optional[TPFPLikelihood] = Field(
        None, description="AI advisory: likely_tp, unclear, or likely_fp"
    )
    tp_fp_rationale: str = Field(
        default="", description="Rationale for the TP/FP assessment"
    )
    tp_fp_evidence_citations: List[str] = Field(
        default_factory=list, description="Evidence citations supporting the assessment"
    )

    # 4. Hypotheses & Decision Checklist
    hypotheses: List[str] = Field(
        default_factory=list,
        description="Hypotheses to consider (e.g., 'Could be legitimate admin activity')",
    )
    decision_checklist: List[str] = Field(
        default_factory=list,
        description="Questions to answer to confirm TP vs FP (e.g., 'Verify if user was on PTO')",
    )

    # 5. Suggested Next Checks
    next_checks: List[AINextCheck] = Field(
        default_factory=list,
        description="Suggested parameterized queries/playbooks to run",
    )

    # 6. Similar Cases Narrative
    similar_case_narratives: List[AISimilarCaseNarrative] = Field(
        default_factory=list,
        description="Top 3 similar cases with AI-generated comparison narratives",
    )

    # Metadata
    model_version: str = Field(
        default="", description="Version of the AI model that generated this overlay"
    )
    generation_timestamp: Optional[str] = Field(
        None, description="When this overlay was generated (ISO format)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "executive_summary": [
                    "PowerShell with encoded command detected on workstation-01 at 02:34 UTC",
                    "IP 192.168.1.100 flagged as malicious by 2 threat intel sources",
                    "User 'admin' typically inactive at this hour (anomaly score: 0.85)",
                    "Pattern matches 3 previous confirmed credential theft incidents",
                ],
                "scorecard_explanation": "High confidence TP due to: known-bad IP (0.9), anomalous timing (0.85), and similarity to past incidents (0.8). The encoded PowerShell command matches known Cobalt Strike patterns.",
                "tp_fp_likelihood": "likely_tp",
                "tp_fp_rationale": "Strong indicators of malicious activity with low false positive probability.",
                "tp_fp_evidence_citations": [
                    "Threat intel: IP listed in AlienVault OTX (last seen: 2025-12-10)",
                    "EDR: Process tree shows suspicious parent-child relationship",
                    "Historical: 87% similarity to case-1842 (confirmed TP)",
                ],
                "hypotheses": [
                    "Hypothesis A: Attacker gained initial access via phishing",
                    "Hypothesis B: Legitimate admin using PowerShell for maintenance (less likely given timing)",
                ],
                "decision_checklist": [
                    "Verify if admin was scheduled for after-hours maintenance",
                    "Check if the encoded command matches known admin scripts",
                    "Confirm whether IP 192.168.1.100 is an approved external service",
                ],
                "next_checks": [
                    {
                        "query_template_id": "Q12",
                        "description": "Check for lateral movement from workstation-01",
                        "parameters": {"host": "workstation-01", "timeframe": "24h"},
                        "target_system": "splunk",
                    },
                    {
                        "query_template_id": "Q07",
                        "description": "Search for other connections to 192.168.1.100",
                        "parameters": {"ip": "192.168.1.100", "timeframe": "7d"},
                        "target_system": "crowdstrike",
                    },
                ],
                "similar_case_narratives": [
                    {
                        "case_id": "case-1842",
                        "similarity_score": 0.87,
                        "shared_traits": [
                            "Same IP range",
                            "Encoded PowerShell",
                            "After-hours",
                        ],
                        "resolution_summary": "TP confirmed, host isolated, creds reset",
                        "relevance_explanation": "Nearly identical attack pattern; resolution took 2h with credential reset.",
                    }
                ],
                "model_version": "gpt-4-turbo-2024-04-09",
                "generation_timestamp": "2025-12-14T19:30:00Z",
            }
        }
