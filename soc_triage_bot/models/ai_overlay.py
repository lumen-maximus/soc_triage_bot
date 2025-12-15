"""AI Overlay data models.

This module defines models for AI/LLM integration with the 13-section triage report.
The AI overlay is applied AFTER deterministic scoring and enrichment are complete.
It provides human-readable summaries, explanations, and suggestions - but does NOT
replace the underlying deterministic scoring logic.

SECTION MAPPING (AI overlays are interwoven into these sections):
    Banner              -> tp_fp_likelihood, tp_fp_rationale, model_version
    §1  Summary         -> executive_summary_statements
    §2  Action Plan     -> next_checks, action_rationale, action_prioritization_reasoning,
                           additional_action_suggestions, action_dependencies, action_risks
    §3  Context         -> context_interpretation, entity_extraction_confidence, indicator_context
    §4  Correlation     -> scope_interpretation, correlation_insights
    §5  Threat Intel    -> enrichment_interpretation, tp_fp_evidence_citations
    §6  Exposure        -> exposure_interpretation, exploit_likelihood_assessment
    §7  Trend/Forecast  -> trend_interpretation, trend_concerns, track_interpretations
    §8  Timeline        -> timeline_narrative, attack_chain_hypothesis
    §9  Triage Assess   -> scorecard_explanation, hypotheses, decision_checklist
    §10 Similar Cases   -> similar_case_narratives
    §11 Closure         -> closure_guidance, tp_verification_steps, fp_verification_steps,
                           similar_case_closure_patterns
    §12 Stakeholder     -> business_impact_summary, risk_communication
    §13 Data Quality    -> data_quality_observations, confidence_caveats

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
        default=None,
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
        §2  Action Plan -> next_checks, action_rationale, action_prioritization_reasoning,
                           additional_action_suggestions, action_dependencies, action_risks
        §3  Context     -> context_interpretation, entity_extraction_confidence, indicator_context
        §4  Correlation -> scope_interpretation, correlation_insights
        §5  Threat Intel-> enrichment_interpretation, tp_fp_evidence_citations
        §6  Exposure    -> exposure_interpretation, exploit_likelihood_assessment
        §7  Trend       -> trend_interpretation, trend_concerns, track_interpretations
        §8  Timeline    -> timeline_narrative, attack_chain_hypothesis
        §9  Assessment  -> scorecard_explanation, hypotheses, decision_checklist
        §10 Similar     -> similar_case_narratives
        §11 Closure     -> closure_guidance, tp_verification_steps, fp_verification_steps,
                           similar_case_closure_patterns
        §12 Stakeholder -> business_impact_summary, risk_communication
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
    # §2 ACTION PLAN - AI-Enhanced Action Recommendations
    # =========================================================================
    next_checks: List[AINextCheck] = Field(
        default_factory=list,
        description="Parameterized query templates for investigation (SIEM/EDR queries)",
    )
    action_rationale: str = Field(
        default="",
        description="AI explanation of WHY the deterministic actions were proposed - connects evidence to recommendations",
    )
    action_prioritization_reasoning: str = Field(
        default="",
        description="AI reasoning for the priority ordering of actions (why action A before B)",
    )
    additional_action_suggestions: List[str] = Field(
        default_factory=list,
        description="AI-suggested actions beyond deterministic proposals (creative/contextual suggestions)",
    )
    action_dependencies: List[str] = Field(
        default_factory=list,
        description="Dependencies between actions (e.g., 'Collect forensics before reimaging')",
    )
    action_risks: List[str] = Field(
        default_factory=list,
        description="Potential risks or side effects of proposed actions",
    )

    # =========================================================================
    # §3 NORMALIZED SIGNAL CONTEXT - Entity Extraction & Interpretation
    # =========================================================================
    context_interpretation: str = Field(
        default="",
        description="AI interpretation of the extracted entities, indicators, and CVEs for §3",
    )
    entity_extraction_confidence: str = Field(
        default="",
        description="AI assessment of confidence in entity extraction (e.g., 'HIGH: All entities clearly identified from structured fields')",
    )
    indicator_context: List[str] = Field(
        default_factory=list,
        description="AI context for each indicator (e.g., 'Domain suspicious-domain.com is a known C2 server')",
    )

    # =========================================================================
    # §4 CORRELATION & SCOPE - Spread/Impact Interpretation
    # =========================================================================
    scope_interpretation: str = Field(
        default="",
        description="AI interpretation of the scope and spread assessment for §4",
    )
    correlation_insights: List[str] = Field(
        default_factory=list,
        description="AI insights connecting sightings and correlations for §4",
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
    # §6 EXPOSURE & VULNERABILITY - Risk Assessment
    # =========================================================================
    exposure_interpretation: str = Field(
        default="",
        description="AI interpretation of exposure and vulnerability context for §6",
    )
    exploit_likelihood_assessment: str = Field(
        default="",
        description="AI assessment of exploitation likelihood based on context for §6",
    )

    # =========================================================================
    # §7 TREND & FORECAST - Interpretation
    # Cross-track synthesis belongs in trend_interpretation.
    # Per-track details belong in track_interpretations.
    # =========================================================================
    trend_interpretation: str = Field(
        default="",
        description=(
            "Cross-track synthesis: What do the tracks TOGETHER mean? "
            "Focus on patterns across tracks, not individual track details. "
            "E.g., 'Triple-track spike strongly correlates with active attack' or "
            "'Rule high + Entity normal suggests noisy rule, not targeted attack'. "
            "Keep brief (1-2 sentences). For §7."
        ),
    )
    trend_concerns: List[str] = Field(
        default_factory=list,
        description=(
            "Cross-track concerns only (e.g., 'Multi-track spike pattern is rare', "
            "'IOC new to environment - limited baseline'). For §7."
        ),
    )
    track_interpretations: List[AITrackInterpretation] = Field(
        default_factory=list,
        description="Per-track (rule/ioc/entity) AI interpretations for §7. One per active track.",
    )

    # =========================================================================
    # §8 EVIDENCE TIMELINE - Attack Chain Narrative
    # =========================================================================
    timeline_narrative: str = Field(
        default="",
        description="AI narrative connecting timeline events into a coherent story for §8",
    )
    attack_chain_hypothesis: str = Field(
        default="",
        description="AI hypothesis about the attack chain/progression for §8 (labeled as hypothesis)",
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
    # §11 CLOSURE CRITERIA - Context-Specific Guidance
    # =========================================================================
    closure_guidance: str = Field(
        default="",
        description="AI-generated context-specific closure guidance based on signal details for §11",
    )
    tp_verification_steps: List[str] = Field(
        default_factory=list,
        description="Specific steps to verify TRUE POSITIVE based on this signal's context for §11",
    )
    fp_verification_steps: List[str] = Field(
        default_factory=list,
        description="Specific steps to verify FALSE POSITIVE based on this signal's context for §11",
    )
    similar_case_closure_patterns: List[str] = Field(
        default_factory=list,
        description="Closure patterns observed in similar cases for §11",
    )

    # =========================================================================
    # §12 STAKEHOLDER SNAPSHOT - Business Impact
    # =========================================================================
    business_impact_summary: str = Field(
        default="",
        description="AI-generated plain-language business impact summary for executives in §12",
    )
    risk_communication: str = Field(
        default="",
        description="AI risk explanation in non-technical language for stakeholders in §12",
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
