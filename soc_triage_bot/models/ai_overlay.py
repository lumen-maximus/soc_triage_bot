"""AI Overlay data models.

This module defines models for AI/LLM integration with the 13-section triage report.
The AI overlay is applied AFTER deterministic scoring and enrichment are complete.
It provides human-readable summaries, explanations, and suggestions - but does NOT
replace the underlying deterministic scoring logic.

SECTION MAPPING (AI overlays are interwoven into these sections):
    §1  Summary         -> executive_summary_statements
    §2  Action Plan     -> next_checks
    §5  Threat Intel    -> enrichment_interpretation, tp_fp_evidence_citations
    §7  Trend/Forecast  -> trend_interpretation, trend_concerns, track_interpretations
    §9  Triage Assess   -> scorecard_explanation, hypotheses, decision_checklist
    §10 Similar Cases   -> similar_case_narratives
    §13 Data Quality    -> data_quality_observations, confidence_caveats

    Banner              -> tp_fp_likelihood, tp_fp_rationale

GUARDRAILS:
    1. Every LLM statement must be traceable to an Evidence ID (log line, query result,
       enrichment output). Use AIStatement with evidence_ids for traceable claims.
    2. If it can't cite evidence, it must label it explicitly as Hypothesis or Assumption.
    3. LLM output is advisory - the deterministic score remains the decision anchor.
    4. LLM packages and explains calculations, it does NOT compete with them.

Usage:
    Pass AIOverlay to generate_report() alongside TriageReport.
    The template will conditionally render AI sections only when data is present.
"""

from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class StatementType(str, Enum):
    """Type of AI statement - determines how it should be treated."""

    EVIDENCE_BACKED = "evidence_backed"  # Traceable to specific evidence IDs
    HYPOTHESIS = "hypothesis"  # Possible explanation, needs verification
    ASSUMPTION = "assumption"  # Assumed true but not verified
    INFERENCE = "inference"  # Derived from multiple evidence points
    OBSERVATION = "observation"  # Direct observation from data


class AIStatement(BaseModel):
    """A single AI-generated statement with required evidence traceability.

    GUARDRAIL: Every statement must either cite evidence OR be labeled as hypothesis/assumption.
    This prevents the LLM from inventing "facts" without accountability.
    """

    text: str = Field(..., description="The statement text")
    statement_type: StatementType = Field(
        ...,
        description="Type: evidence_backed, hypothesis, assumption, inference, or observation",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs this statement is based on (required for evidence_backed type)",
    )
    confidence: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Confidence in this statement (0-1)",
    )


class TPFPLikelihood(str, Enum):
    """AI advisory on TP/FP likelihood."""

    LIKELY_TP = "likely_tp"
    UNCLEAR = "unclear"
    LIKELY_FP = "likely_fp"


class AINextCheck(BaseModel):
    """A suggested next check/query for the analyst (§2 Action Plan).

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


class AISimilarCaseNarrative(BaseModel):
    """AI narrative comparing current case to a similar historical case (§10).

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


class AITrackInterpretation(BaseModel):
    """AI interpretation for a single forecast track (§7).

    One per track (rule, ioc, entity) when forecast data is available.
    """

    track_name: str = Field(..., description="Track name: 'rule', 'ioc', or 'entity'")
    interpretation: str = Field(
        default="", description="AI interpretation of this track's forecast"
    )
    concerns: List[str] = Field(
        default_factory=list,
        description="Specific concerns for this track (e.g., 'Spike exceeds 95th percentile')",
    )
    evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting this interpretation",
    )


class AIOverlay(BaseModel):
    """AI overlay layer for the 13-section triage report.

    Each field maps to a specific section where AI insights are interwoven.
    This is applied AFTER the evidence bundle is complete.

    SECTION MAPPING:
        Banner          -> tp_fp_likelihood, tp_fp_rationale
        §1  Summary     -> executive_summary_statements
        §2  Action Plan -> next_checks
        §5  Threat Intel-> enrichment_interpretation, tp_fp_evidence_citations
        §7  Trend       -> trend_interpretation, trend_concerns, track_interpretations
        §9  Assessment  -> scorecard_explanation, hypotheses, decision_checklist
        §10 Similar     -> similar_case_narratives
        §13 Data Quality-> data_quality_observations, confidence_caveats

    GUARDRAILS (enforced by structure):
    - executive_summary_statements: Each bullet has evidence traceability
    - hypotheses: Explicitly labeled as hypotheses, not facts
    - decision_checklist: Questions to verify, not conclusions
    - All interpretations cite evidence_ids where possible

    IMPORTANT: This layer does NOT replace deterministic scoring.
    It's an overlay that PACKAGES and EXPLAINS the calculations.
    """

    # =========================================================================
    # BANNER - TP/FP Advisory
    # =========================================================================
    tp_fp_likelihood: Optional[TPFPLikelihood] = Field(
        None, description="AI advisory: likely_tp, unclear, or likely_fp"
    )
    tp_fp_rationale: str = Field(
        default="", description="Rationale for the TP/FP assessment"
    )

    # =========================================================================
    # §1 SUMMARY - Executive Summary
    # =========================================================================
    executive_summary_statements: List[AIStatement] = Field(
        default_factory=list,
        description="2-6 structured bullets with evidence traceability for §1 Summary",
    )

    # =========================================================================
    # §2 ACTION PLAN - Suggested Next Checks
    # =========================================================================
    next_checks: List[AINextCheck] = Field(
        default_factory=list,
        description="Parameterized query templates for §2 Action Plan",
    )

    # =========================================================================
    # §5 THREAT INTEL - Evidence Citations & Enrichment Interpretation
    # =========================================================================
    tp_fp_evidence_citations: List[str] = Field(
        default_factory=list,
        description="Evidence citations supporting the TP/FP assessment for §5",
    )
    enrichment_interpretation: str = Field(
        default="",
        description="AI interpretation of enrichment results for §5 Threat Intel",
    )

    # =========================================================================
    # §7 TREND & FORECAST - Interpretation
    # =========================================================================
    trend_interpretation: str = Field(
        default="",
        description="Overall AI interpretation of forecast/trend data for §7",
    )
    trend_concerns: List[str] = Field(
        default_factory=list,
        description="General trend concerns (e.g., 'Velocity increasing') for §7",
    )
    track_interpretations: List[AITrackInterpretation] = Field(
        default_factory=list,
        description="Per-track (rule/ioc/entity) AI interpretations for §7",
    )

    # =========================================================================
    # §9 TRIAGE ASSESSMENT - Scorecard, Hypotheses, Checklist
    # =========================================================================
    scorecard_explanation: str = Field(
        default="",
        description="Plain English explanation of the DETERMINISTIC score for §9",
    )
    scorecard_evidence_ids: List[str] = Field(
        default_factory=list,
        description="Evidence IDs the scorecard explanation references for §9",
    )
    hypotheses: List[str] = Field(
        default_factory=list,
        description="Hypotheses to consider for §9 (explicitly labeled as hypotheses)",
    )
    decision_checklist: List[str] = Field(
        default_factory=list,
        description="Questions to answer to confirm TP vs FP for §9",
    )

    # =========================================================================
    # §10 SIMILAR CASES - Narratives
    # =========================================================================
    similar_case_narratives: List[AISimilarCaseNarrative] = Field(
        default_factory=list,
        description="Top 3 similar cases with AI-generated comparison narratives for §10",
    )

    # =========================================================================
    # §13 DATA QUALITY - Observations & Caveats
    # =========================================================================
    data_quality_observations: List[str] = Field(
        default_factory=list,
        description="AI observations about data gaps or quality issues for §13",
    )
    confidence_caveats: List[str] = Field(
        default_factory=list,
        description="Caveats that may affect confidence for §13",
    )

    # =========================================================================
    # METADATA
    # =========================================================================
    model_version: str = Field(
        default="", description="Version of the AI model that generated this overlay"
    )
    generation_timestamp: Optional[str] = Field(
        None, description="When this overlay was generated (ISO format)"
    )
