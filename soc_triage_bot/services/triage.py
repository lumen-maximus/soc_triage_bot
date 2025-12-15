"""Main triage orchestration service.

Extended to orchestrate multi-track ETS forecasting and assemble TriageReport.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..models import Action, AIOverlay, Classification, EnrichmentResult, Signal
from ..models.triage_report import (
    AssetContext,
    ClassificationResult,
    EnrichmentBundle,
    EntityFocus,
    ForecastBundle,
    HostContext,
    NormalizedSignal,
    Recommendation,
    ReportMeta,
    SignalContext,
    TriageReport,
    UserContext,
)
from .action_proposal import ActionProposalService
from .classification import ClassificationService
from .enrichment import EnrichmentService
from .forecasting import ForecastingService, MultiTrackHistoricalData
from .report import ReportService
from .similarity import SimilarityService


class TriageResult:
    """Complete triage result with both legacy and new formats."""

    def __init__(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        classification: Classification,
        actions: List[Action],
        report: str,
        forecast_data: Optional[Dict[str, Any]] = None,
        similar_cases: Optional[List[tuple]] = None,
        duration_ms: Optional[float] = None,
        # New structured output
        triage_report: Optional[TriageReport] = None,
        classification_result: Optional[ClassificationResult] = None,
        forecast_bundle: Optional[ForecastBundle] = None,
    ):
        self.signal = signal
        self.enrichments = enrichments
        self.classification = classification
        self.actions = actions
        self.report = report
        self.forecast_data = forecast_data
        self.similar_cases = similar_cases
        self.duration_ms = duration_ms
        self.timestamp = datetime.now(timezone.utc)

        # New structured output
        self.triage_report = triage_report
        self.classification_result = classification_result
        self.forecast_bundle = forecast_bundle


class TriageService:
    """Main service orchestrating the complete triage workflow.

    Extended for multi-track forecasting:
    - Accepts MultiTrackHistoricalData for forecast_multi_track()
    - Assembles complete TriageReport model
    - Returns both legacy and new structured output
    """

    def __init__(
        self,
        enrichment_service: EnrichmentService,
        forecasting_service: Optional[ForecastingService] = None,
        similarity_service: Optional[SimilarityService] = None,
        classification_service: Optional[ClassificationService] = None,
        action_proposal_service: Optional[ActionProposalService] = None,
        report_service: Optional[ReportService] = None,
    ):
        """Initialize triage service."""
        self.enrichment_service = enrichment_service
        self.forecasting_service = forecasting_service or ForecastingService()
        self.similarity_service = similarity_service or SimilarityService()
        self.classification_service = classification_service or ClassificationService()
        self.action_proposal_service = (
            action_proposal_service or ActionProposalService()
        )
        self.report_service = report_service or ReportService()

    async def triage_extended(
        self,
        signal: Signal,
        historical_data: Optional[MultiTrackHistoricalData] = None,
        ai_overlay: Optional[AIOverlay] = None,
        forecast_enabled: bool = True,
    ) -> TriageResult:
        """Execute extended triage workflow with multi-track forecasting.

        Args:
            signal: Signal to triage
            historical_data: Structured multi-track historical data
            ai_overlay: Optional AI overlay for LLM-generated insights
            forecast_enabled: Whether to run ETS forecasting (default True)

        Returns:
            Complete triage result with TriageReport
        """
        start_time = datetime.now(timezone.utc)

        # Step 1: Concurrent enrichments (with evidence IDs)
        enrichments = await self.enrichment_service.enrich_signal(signal)

        # Generate evidence IDs for enrichments
        for idx, (adapter_name, result) in enumerate(enrichments.items()):
            result.generate_evidence_id(idx + 1)

        # Step 2: Multi-track ETS forecasting (if enabled)
        forecast_bundle = ForecastBundle(enabled=False)
        if forecast_enabled and historical_data:
            forecast_bundle = self.forecasting_service.forecast_multi_track(
                signal, historical_data
            )

        # Step 3: Similar case retrieval (entity-based)
        # NOTE: SimilarCase models include runbook_refs, attachments_metadata
        # from SOAR. This is the SINGLE source - no re-fetching later.
        similar_cases_models = self.similarity_service.find_similar_as_models(signal)
        similar_cases_tuples = [
            (c.case_id, c.similarity, c.outcome) for c in similar_cases_models
        ]

        # Step 4: Extended classification
        classification_result = self.classification_service.classify_extended(
            signal=signal,
            enrichments=enrichments,
            similar_cases=similar_cases_tuples,
            forecast=forecast_bundle,
        )

        # Step 5: Action proposals -> Recommendations
        # Pass similar_cases_models for case-learned and case-linked actions
        actions = self.action_proposal_service.propose_actions(
            signal=signal,
            classification=self._classification_result_to_legacy(classification_result),
            enrichments=enrichments,
            similar_cases=similar_cases_tuples,
            similar_cases_models=similar_cases_models,
        )
        recommendations = self._actions_to_recommendations(actions)

        # Step 6: Assemble TriageReport
        triage_report = self._assemble_triage_report(
            signal=signal,
            enrichments=enrichments,
            classification=classification_result,
            forecast=forecast_bundle,
            similar_cases=similar_cases_models,
            recommendations=recommendations,
            start_time=start_time,
        )

        # Step 7: Generate report using new template
        report = self.report_service.generate_report(triage_report, ai_overlay)

        # Calculate duration
        duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return TriageResult(
            signal=signal,
            enrichments=enrichments,
            classification=self._classification_result_to_legacy(classification_result),
            actions=actions,
            report=report,
            forecast_data=(
                {"enabled": forecast_bundle.enabled} if forecast_bundle else None
            ),
            similar_cases=[(c.case_id, c.similarity) for c in similar_cases_models],
            duration_ms=duration_ms,
            # New structured output
            triage_report=triage_report,
            classification_result=classification_result,
            forecast_bundle=forecast_bundle,
        )

    def _assemble_triage_report(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        classification: ClassificationResult,
        forecast: ForecastBundle,
        similar_cases: List,
        recommendations: List[Recommendation],
        start_time: datetime,
    ) -> TriageReport:
        """Assemble complete TriageReport from components."""

        # Build NormalizedSignal
        normalized_signal = NormalizedSignal(
            id=signal.signal_id,
            type=signal.signal_type.value.upper(),
            source=signal.source.system,
            name=signal.title,
            category=signal.description[:50] if signal.description else "",
            timestamp_utc=(
                signal.timestamp.isoformat() + "Z" if signal.timestamp else ""
            ),
            raw=signal.raw_data if signal.raw_data else {},
        )

        # Build SignalContext
        entity_focus = None
        track_c_entity = signal.get_track_c_entity()
        if track_c_entity:
            entity_focus = EntityFocus(
                primary=f"{track_c_entity[0]}:{track_c_entity[1]}"
            )

        signal_context = SignalContext(
            signal_subtype=signal.signal_type.value,
            entity_focus=entity_focus,
            username=signal.entity_context.username if signal.entity_context else None,
            hostname=signal.entity_context.hostname if signal.entity_context else None,
            src_ip=signal.entity_context.src_ip if signal.entity_context else None,
            dst_ip=signal.entity_context.dst_ip if signal.entity_context else None,
            alert_rule=(
                signal.detection_context.rule_name
                if signal.detection_context
                else signal.source.rule_name
            ),
            alert_vendor=signal.source.system,
            indicators=signal.get_track_b_keys(),
            cves=(
                [signal.vuln_context.cve]
                if signal.vuln_context and signal.vuln_context.cve
                else []
            ),
        )

        # Build EnrichmentBundle from enrichment results
        enrichment_bundle = self._build_enrichment_bundle(enrichments, signal_context)

        # Build ReportMeta
        report_meta = ReportMeta(
            generated_utc=datetime.now(timezone.utc).isoformat() + "Z",
            triage_owner="Automated",
            tool_version="2.0.0",
        )

        return TriageReport(
            signal=normalized_signal,
            meta=report_meta,
            ctx=signal_context,
            classification=classification,
            forecast=forecast,
            enrich=enrichment_bundle,
            similar_cases=similar_cases,
            recommendations=recommendations,
            exec=None,  # Executive summary is optional
        )

    def _build_enrichment_bundle(
        self,
        enrichments: Dict[str, EnrichmentResult],
        ctx: SignalContext,
    ) -> EnrichmentBundle:
        """Build EnrichmentBundle from raw enrichment results."""
        bundle = EnrichmentBundle()

        # Extract CMDB data for asset context
        cmdb = enrichments.get("cmdb")
        if cmdb and cmdb.status.value == "success":
            host_assets = cmdb.data.get("host_assets", {})
            if ctx.hostname and ctx.hostname in host_assets:
                asset = host_assets[ctx.hostname]
                bundle.asset_context = AssetContext(
                    host=HostContext(
                        hostname=ctx.hostname,
                        os=asset.get("os", ""),
                        criticality=asset.get("business_criticality", "medium"),
                        business_unit=asset.get("business_unit", ""),
                        owner=asset.get("owner", ""),
                        segment=asset.get("network_segment", ""),
                    ),
                    user=(
                        UserContext(
                            username=ctx.username or "",
                            role=asset.get("user_role", ""),
                            department=asset.get("department", ""),
                            risk_score=asset.get("user_risk_score"),
                        )
                        if ctx.username
                        else None
                    ),
                )

        # Extract TI summary
        ti = enrichments.get("threat_intel")
        if ti and ti.status.value == "success":
            bundle.ti_summary = ti.data.get("summary", "")
            matches = ti.data.get("matches_found", 0)
            reputation = ti.data.get("reputation", "unknown")
            bundle.correlation_summary = (
                f"TI: {matches} matches, reputation={reputation}"
            )

        return bundle

    def _actions_to_recommendations(
        self, actions: List[Action]
    ) -> List[Recommendation]:
        """Convert legacy Actions to Recommendations."""
        return [
            Recommendation(
                priority=a.priority,
                description=a.description,
                owner_team=a.metadata.get("owner", "SOC") if a.metadata else "SOC",
                auto_executable=a.metadata.get("auto", False) if a.metadata else False,
                status="Open",
                rationale=a.rationale if a.rationale else a.reasoning,
            )
            for a in actions
        ]

    def _classification_result_to_legacy(
        self, cr: ClassificationResult
    ) -> Classification:
        """Convert ClassificationResult to legacy Classification."""
        from ..models import ClassificationLabel

        # Map disposition to label
        if "True Positive" in cr.disposition:
            label = ClassificationLabel.TRUE_POSITIVE
        elif "False Positive" in cr.disposition:
            label = ClassificationLabel.FALSE_POSITIVE
        else:
            label = ClassificationLabel.UNKNOWN

        return Classification(
            label=label,
            confidence=cr.tp_likelihood,
            reasoning=cr.reasons_tp + cr.reasons_fp,
            factors={},
            similar_cases=[],
            forecast_data=None,
        )
