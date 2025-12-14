"""Main triage orchestration service."""

from typing import Dict, Any, List, Optional
from datetime import datetime
from ..models import Signal, EnrichmentResult, Classification, Action
from .enrichment import EnrichmentService
from .forecasting import ForecastingService
from .similarity import SimilarityService
from .classification import ClassificationService
from .action_proposal import ActionProposalService
from .report import ReportService


class TriageResult:
    """Complete triage result."""
    
    def __init__(
        self,
        signal: Signal,
        enrichments: Dict[str, EnrichmentResult],
        classification: Classification,
        actions: List[Action],
        report: str,
        forecast_data: Optional[Dict[str, Any]] = None,
        similar_cases: Optional[List[tuple]] = None,
        duration_ms: Optional[float] = None
    ):
        self.signal = signal
        self.enrichments = enrichments
        self.classification = classification
        self.actions = actions
        self.report = report
        self.forecast_data = forecast_data
        self.similar_cases = similar_cases
        self.duration_ms = duration_ms
        self.timestamp = datetime.utcnow()


class TriageService:
    """Main service orchestrating the complete triage workflow."""
    
    def __init__(
        self,
        enrichment_service: EnrichmentService,
        forecasting_service: ForecastingService = None,
        similarity_service: SimilarityService = None,
        classification_service: ClassificationService = None,
        action_proposal_service: ActionProposalService = None,
        report_service: ReportService = None
    ):
        """Initialize triage service.
        
        Args:
            enrichment_service: Service for enrichments
            forecasting_service: Optional forecasting service
            similarity_service: Optional similarity service
            classification_service: Optional classification service
            action_proposal_service: Optional action proposal service
            report_service: Optional report service
        """
        self.enrichment_service = enrichment_service
        self.forecasting_service = forecasting_service or ForecastingService()
        self.similarity_service = similarity_service or SimilarityService()
        self.classification_service = classification_service or ClassificationService()
        self.action_proposal_service = action_proposal_service or ActionProposalService()
        self.report_service = report_service or ReportService()
    
    async def triage(
        self,
        signal: Signal,
        historical_data: List[Dict[str, Any]] = None
    ) -> TriageResult:
        """Execute complete triage workflow.
        
        Args:
            signal: Signal to triage
            historical_data: Optional historical data for forecasting
            
        Returns:
            Complete triage result
        """
        start_time = datetime.utcnow()
        
        # Step 1: Concurrent enrichments
        enrichments = await self.enrichment_service.enrich_signal(signal)
        
        # Step 2: ETS forecasting with rolling backtest
        forecast_data = None
        if historical_data:
            forecast_data = self.forecasting_service.forecast(
                historical_data,
                signal.signal_type.value
            )
        
        # Step 3: Similar case retrieval
        similar_cases = self.similarity_service.find_similar(signal)
        
        # Step 4: Classification
        classification = self.classification_service.classify(
            signal=signal,
            enrichments=enrichments,
            similar_cases=similar_cases,
            forecast_data=forecast_data
        )
        
        # Step 5: Action proposals
        actions = self.action_proposal_service.propose_actions(
            signal=signal,
            classification=classification,
            enrichments=enrichments
        )
        
        # Step 6: Generate report
        report = self.report_service.generate_report(
            signal=signal,
            enrichments=enrichments,
            classification=classification,
            actions=actions,
            forecast_data=forecast_data,
            similar_cases=similar_cases
        )
        
        # Calculate duration
        duration_ms = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        return TriageResult(
            signal=signal,
            enrichments=enrichments,
            classification=classification,
            actions=actions,
            report=report,
            forecast_data=forecast_data,
            similar_cases=similar_cases,
            duration_ms=duration_ms
        )
