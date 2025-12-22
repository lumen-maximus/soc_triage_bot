"""Main triage orchestration service.

Orchestrates multi-track ETS forecasting and assembles TriageReport.
Integrates Case Knowledge Graph (CKG) for evidence tracking and governance.
"""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ..models import Action, AIOverlay, EnrichmentResult, Signal
from ..models.case_graph import TriageContextGraph, TriageMode
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
from .case_bootstrap import CaseBootstrapService
from .case_context_linking import CaseContextLinkingService
from .classification import ClassificationService
from .detection_resolver import DetectionResolver
from .enrichment import EnrichmentService
from .fetch_planner import FetchPlanner
from .forecasting import ForecastingService, MultiTrackHistoricalData
from .governance_gate import GovernanceGate
from .report import ReportService

if TYPE_CHECKING:
    from .ai import AIService


class TriageResult:
    """Complete triage result with ClassificationResult.

    ClassificationResult has `.label` and `.confidence_score` computed properties
    for use with ActionProposalService and RunbookRegistry.
    """

    def __init__(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        classification: ClassificationResult,
        actions: List[Action],
        report: str,
        forecast_data: Optional[Dict[str, Any]] = None,
        similar_cases: Optional[List[tuple]] = None,
        duration_ms: Optional[float] = None,
        # Structured output (same as classification, kept for API clarity)
        triage_report: Optional[TriageReport] = None,
        forecast_bundle: Optional[ForecastBundle] = None,
        # CKG graph
        graph: Optional[TriageContextGraph] = None,
    ):
        self.signal = signal
        self.enrichments = enrichments
        self.classification = (
            classification  # ClassificationResult with .label property
        )
        self.actions = actions
        self.report = report
        self.forecast_data = forecast_data
        self.similar_cases = similar_cases
        self.duration_ms = duration_ms
        self.timestamp = datetime.now(timezone.utc)

        # Structured output references
        self.triage_report = triage_report
        self.classification_result = classification  # Alias for clarity
        self.forecast_bundle = forecast_bundle

        # CKG graph for evidence tracking
        self.graph = graph


class TriageService:
    """Main service orchestrating the complete triage workflow.

    Multi-track forecasting support:
    - Accepts MultiTrackHistoricalData for forecast_multi_track()
    - Assembles complete TriageReport model
    - Returns structured TriageResult with full report
    - Optionally uses AIService for AI overlay generation

    Case Knowledge Graph (CKG) integration:
    - Uses CaseBootstrapService to initialize graph
    - Uses FetchPlanner for delta-only enrichments
    - Uses DetectionResolver to validate IOC/CVE detections
    - Uses GovernanceGate to filter/approve actions
    - Uses CaseContextLinking to link similar cases in graph
    """

    def __init__(
        self,
        enrichment_service: EnrichmentService,
        forecasting_service: Optional[ForecastingService] = None,
        classification_service: Optional[ClassificationService] = None,
        action_proposal_service: Optional[ActionProposalService] = None,
        report_service: Optional[ReportService] = None,
        ai_service: Optional["AIService"] = None,
        historical_data_service: Optional[Any] = None,
        # CKG services
        case_bootstrap_service: Optional[CaseBootstrapService] = None,
        fetch_planner: Optional[FetchPlanner] = None,
        detection_resolver: Optional[DetectionResolver] = None,
        governance_gate: Optional[GovernanceGate] = None,
        case_context_linking: Optional[CaseContextLinkingService] = None,
        enable_ckg: bool = True,
    ):
        """Initialize triage service.

        Args:
            enrichment_service: Service for signal enrichment
            forecasting_service: Service for ETS forecasting (optional)
            classification_service: Service for classification (optional)
            action_proposal_service: Service for action proposals (optional)
            report_service: Service for report generation (optional)
            ai_service: Service for AI overlay generation (optional)
            historical_data_service: Service for historical data fetching (optional)
            case_bootstrap_service: CKG bootstrap service (optional)
            fetch_planner: CKG fetch planner for delta-only enrichment (optional)
            detection_resolver: CKG detection resolver (optional)
            governance_gate: CKG governance gate for action filtering (optional)
            case_context_linking: CKG case linking service (optional)
            enable_ckg: Enable CKG integration (default True)
        """
        self.enrichment_service = enrichment_service
        self.forecasting_service = forecasting_service or ForecastingService()
        self.classification_service = classification_service or ClassificationService()
        self.action_proposal_service = (
            action_proposal_service or ActionProposalService()
        )
        self.report_service = report_service or ReportService()
        self.ai_service = ai_service  # None = no AI overlay
        self.historical_data_service = historical_data_service  # None = no auto-fetch

        # CKG services
        self.enable_ckg = enable_ckg
        self.case_bootstrap_service = case_bootstrap_service or CaseBootstrapService()
        self.fetch_planner = fetch_planner or FetchPlanner()
        self.detection_resolver = detection_resolver or DetectionResolver()
        self.governance_gate = governance_gate or GovernanceGate()
        self.case_context_linking = case_context_linking or CaseContextLinkingService()

    async def triage_extended(
        self,
        signal: Signal,
        historical_data: Optional[MultiTrackHistoricalData] = None,
        ai_overlay: Optional[AIOverlay] = None,
        forecast_enabled: bool = True,
        triage_mode: TriageMode = TriageMode.MIN_DELTA,
    ) -> TriageResult:
        """Execute extended triage workflow with multi-track forecasting and CKG.

        Args:
            signal: Signal to triage
            historical_data: Structured multi-track historical data
            ai_overlay: Optional AI overlay for LLM-generated insights
            forecast_enabled: Whether to run ETS forecasting (default True)
            triage_mode: CKG triage mode (default MIN_DELTA)

        Returns:
            Complete triage result with TriageReport and CKG graph
        """
        start_time = datetime.now(timezone.utc)

        # =====================================================================
        # CKG PHASE 1: Bootstrap graph
        # =====================================================================
        graph = None
        if self.enable_ckg:
            graph = self.case_bootstrap_service.bootstrap(signal, mode=triage_mode)

        # =====================================================================
        # CKG PHASE 2: Fetch Planning (determine what to enrich)
        # =====================================================================
        # Note: FetchPlanner.plan() could be used to filter adapters in future
        # For now, we run all enrichments

        # Step 1: Concurrent enrichments (with evidence IDs + CKG graph writing)
        if self.enable_ckg and graph:
            enrichments = await self.enrichment_service.enrich_signal_ckg(signal, graph)
        else:
            enrichments = await self.enrichment_service.enrich_signal(signal)

        # Generate evidence IDs for enrichments
        for idx, (adapter_name, result) in enumerate(enrichments.items()):
            result.generate_evidence_id(idx + 1)

        # =====================================================================
        # CKG PHASE 3: Detection Resolution (validate IOC/CVE presence)
        # =====================================================================
        if self.enable_ckg and graph:
            await self.detection_resolver.resolve(signal, graph)

        # Auto-fetch historical data if needed
        if (
            forecast_enabled
            and historical_data is None
            and self.historical_data_service
        ):
            try:
                historical_data = await self.historical_data_service.fetch_for_signal(
                    signal
                )
            except Exception:
                pass  # Graceful - forecasting will be skipped

        # Step 2: Multi-track ETS forecasting (if enabled + CKG graph writing)
        forecast_bundle = ForecastBundle(enabled=False)
        if forecast_enabled and historical_data:
            if self.enable_ckg and graph:
                forecast_bundle = self.forecasting_service.forecast_multi_track_ckg(
                    signal, historical_data, graph
                )
            else:
                forecast_bundle = self.forecasting_service.forecast_multi_track(
                    signal, historical_data
                )

        # Step 3: Similar case retrieval (entity-based)
        # NOTE: SimilarCase models include runbook_refs, attachments_metadata
        # from SOAR. This is the SINGLE source - no re-fetching later.
        similar_cases_models = self.case_context_linking.find_similar_as_models(signal)

        # Augment with SOAR-linked cases if available
        similar_cases_models = self._augment_similar_cases_with_soar(
            signal, similar_cases_models
        )

        # =====================================================================
        # CKG PHASE 4: Case Context Linking (add similar cases to graph)
        # =====================================================================
        if self.enable_ckg and graph and similar_cases_models:
            # link_cases takes (signal, graph) and returns num links added
            await self.case_context_linking.link_cases(signal, graph)

        similar_cases_tuples = [
            (c.case_id, c.similarity, c.outcome) for c in similar_cases_models
        ]

        # Step 4: Extended classification (with CKG graph writing)
        if self.enable_ckg and graph:
            classification_result = self.classification_service.classify_extended_ckg(
                signal=signal,
                enrichments=enrichments,
                similar_cases=similar_cases_tuples,
                forecast=forecast_bundle,
                graph=graph,
            )
        else:
            classification_result = self.classification_service.classify_extended(
                signal=signal,
                enrichments=enrichments,
                similar_cases=similar_cases_tuples,
                forecast=forecast_bundle,
            )

        # Apply SOAR classification hints if available
        classification_result = self._apply_soar_classification_hints(
            signal, classification_result
        )

        # Step 5: Action proposals -> Recommendations (with CKG graph writing)
        if self.enable_ckg and graph:
            actions = self.action_proposal_service.propose_actions_ckg(
                signal=signal,
                classification=classification_result,
                enrichments=enrichments,
                similar_cases=similar_cases_tuples,
                similar_cases_models=similar_cases_models,
                graph=graph,
            )
        else:
            actions = self.action_proposal_service.propose_actions(
                signal=signal,
                classification=classification_result,
                enrichments=enrichments,
                similar_cases=similar_cases_tuples,
                similar_cases_models=similar_cases_models,
            )

        # =====================================================================
        # CKG PHASE 5: Governance Gate (filter/approve actions)
        # =====================================================================
        if self.enable_ckg:
            # evaluate() returns GovernanceDecisionResult
            governance_result = self.governance_gate.evaluate(
                actions, classification_result, enrichments
            )
            # Use auto-execute and requires-approval actions, filter out blocked
            actions = (
                governance_result.auto_execute + governance_result.requires_approval
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

        # Step 6.5: Generate AI overlay if service available and not provided
        if ai_overlay is None and self.ai_service is not None:
            ai_overlay = await self.ai_service.generate_overlay(triage_report, signal)

        # Step 7: Generate report using new template
        report = self.report_service.generate_report(triage_report, ai_overlay)

        # Calculate duration
        duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return TriageResult(
            signal=signal,
            enrichments=enrichments,
            classification=classification_result,
            actions=actions,
            report=report,
            forecast_data=(
                {"enabled": forecast_bundle.enabled} if forecast_bundle else None
            ),
            similar_cases=[(c.case_id, c.similarity) for c in similar_cases_models],
            duration_ms=duration_ms,
            triage_report=triage_report,
            forecast_bundle=forecast_bundle,
            graph=graph,
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
        """Convert Actions to Recommendations for TriageReport."""
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

    def _augment_similar_cases_with_soar(
        self, signal: Signal, similar_cases_models: List
    ) -> List:
        """Augment similar cases with SOAR-linked related cases.

        Merges SOAR-explicitly linked cases (100% similarity) with
        TF-IDF discovered cases, avoiding duplicates.

        Args:
            signal: Signal with potential SOAR metadata
            similar_cases_models: List of SimilarCase models from TF-IDF

        Returns:
            Merged list of similar cases, sorted by similarity
        """
        from ..models.triage_report import SimilarCase

        all_cases = []

        # Extract SOAR pre-linked cases if available
        if signal.metadata.get("soar_related_cases"):
            soar_case_ids = signal.metadata["soar_related_cases"]
            for case_id in soar_case_ids:
                # Create similar case with 100% similarity (explicitly linked)
                similar_case = SimilarCase(
                    case_id=case_id,
                    similarity=1.0,  # SOAR explicitly linked = 100%
                    outcome="unknown",  # Would be fetched in production
                    overlap="soar_linked",
                    actions_taken=[],
                )
                all_cases.append(similar_case)

        # Add TF-IDF cases (avoiding duplicates)
        soar_ids = {c.case_id for c in all_cases}
        for case in similar_cases_models:
            if case.case_id not in soar_ids:
                all_cases.append(case)

        # Sort by similarity (descending)
        all_cases.sort(key=lambda c: c.similarity, reverse=True)

        return all_cases[:10]  # Return top 10

    def _apply_soar_classification_hints(
        self, signal: Signal, classification: ClassificationResult
    ) -> ClassificationResult:
        """Apply SOAR analyst assessment as classification hint.

        Uses SOAR status to adjust TP likelihood with 15% weight.

        Args:
            signal: Signal with potential SOAR metadata
            classification: Base classification result

        Returns:
            Classification with SOAR hints applied
        """
        soar_status = signal.metadata.get("soar_status", "").lower()

        if not soar_status:
            return classification

        # Adjust based on SOAR analyst assessment
        if any(kw in soar_status for kw in ["confirmed", "malicious", "true_positive"]):
            classification.tp_likelihood = min(1.0, classification.tp_likelihood + 0.15)
            if classification.reasons_tp is None:
                classification.reasons_tp = []
            classification.reasons_tp.append(f"SOAR analyst marked as {soar_status}")
        elif any(kw in soar_status for kw in ["benign", "false_positive", "dismissed"]):
            classification.tp_likelihood = max(0.0, classification.tp_likelihood - 0.15)
            if classification.reasons_fp is None:
                classification.reasons_fp = []
            classification.reasons_fp.append(f"SOAR analyst marked as {soar_status}")

        return classification
