"""FastAPI REST API for SOC Triage Bot."""

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid

from .models import Signal, SignalType, SignalSource
from .services import TriageService, EnrichmentService, ForecastingService, SimilarityService
from .services.forecasting import MultiTrackHistoricalData, TrackTimeSeries
from .adapters import SIEMAdapter, EDRAdapter, ThreatIntelAdapter, VulnerabilityAdapter, CMDBAdapter

# Initialize services
adapters = [
    SIEMAdapter(),
    EDRAdapter(),
    ThreatIntelAdapter(),
    VulnerabilityAdapter(),
    CMDBAdapter()
]

enrichment_service = EnrichmentService(adapters)
forecasting_service = ForecastingService()
similarity_service = SimilarityService()

triage_service = TriageService(
    enrichment_service=enrichment_service,
    forecasting_service=forecasting_service,
    similarity_service=similarity_service
)

# Store for triage results (in production, use database)
triage_results: Dict[str, Any] = {}

# Initialize FastAPI app
app = FastAPI(
    title="SOC Triage Bot API",
    description="Async, SIEM-agnostic SOC triage agent service",
    version="0.1.0"
)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "SOC Triage Bot",
        "version": "0.1.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    adapter_health = await enrichment_service.health_check()
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "adapters": adapter_health
    }


@app.post("/triage", response_model=Dict[str, Any])
async def triage_signal(
    signal: Signal,
    historical_data: Optional[MultiTrackHistoricalData] = None,
    legacy_historical_data: Optional[List[Dict[str, Any]]] = None
):
    """
    Triage a security signal.
    
    This endpoint:
    1. Normalizes the input signal
    2. Runs concurrent enrichments
    3. Performs multi-track ETS forecasting if historical data provided
    4. Finds similar cases
    5. Classifies as TP/FP
    6. Generates action proposals
    7. Renders a report
    
    Args:
        signal: Normalized security signal
        historical_data: Optional multi-track historical time series data
        legacy_historical_data: Optional legacy format (list of dicts with timestamp/count)
            - Deprecated: Use historical_data instead
        
    Returns:
        Triage result with classification, actions, and structured report
    """
    try:
        # Support both new and legacy historical data formats
        multi_track_data = historical_data
        if multi_track_data is None and legacy_historical_data is not None:
            # Convert legacy list format to MultiTrackHistoricalData
            values = [d.get("count", 0) for d in legacy_historical_data]
            from datetime import datetime as dt
            timestamps_raw = [d.get("timestamp") for d in legacy_historical_data]
            timestamps = []
            for ts in timestamps_raw:
                if isinstance(ts, dt):
                    timestamps.append(ts)
                elif isinstance(ts, str):
                    try:
                        timestamps.append(dt.fromisoformat(ts.replace("Z", "+00:00")))
                    except ValueError:
                        timestamps.append(datetime.utcnow())
                else:
                    timestamps.append(datetime.utcnow())
            
            track_a = TrackTimeSeries(
                track_name="rule",
                entity_key="rule_id",
                entity_value=signal.source.rule_id or "unknown",
                metric_name="alert_count",
                timestamps=timestamps,
                values=values,
                bucket_minutes=15,
            )
            multi_track_data = MultiTrackHistoricalData(track_a=track_a)
        
        # Execute extended triage with multi-track support
        result = await triage_service.triage_extended(signal, multi_track_data)
        
        # Store result
        triage_id = str(uuid.uuid4())
        triage_results[triage_id] = result
        
        # Build response with both legacy and new fields
        response = {
            "triage_id": triage_id,
            "signal_id": signal.signal_id,
            "classification": {
                "label": result.classification.label.value,
                "confidence": result.classification.confidence,
                "reasoning": result.classification.reasoning,
                "factors": result.classification.factors
            },
            "actions": [
                {
                    "action_id": action.action_id,
                    "type": action.action_type.value,
                    "priority": action.priority,
                    "title": action.title,
                    "description": action.description,
                    "confidence": action.confidence,
                    "source": action.source
                }
                for action in result.actions
            ],
            "enrichments": {
                name: {
                    "status": enrich.status.value,
                    "duration_ms": enrich.duration_ms
                }
                for name, enrich in result.enrichments.items()
            },
            "similar_cases": result.similar_cases,
            "forecast_data": result.forecast_data,
            "duration_ms": result.duration_ms,
            "timestamp": result.timestamp.isoformat()
        }
        
        # Add new structured output if available
        if result.classification_result:
            response["classification_result"] = {
                "disposition": result.classification_result.disposition,
                "tp_likelihood": result.classification_result.tp_likelihood,
                "severity": result.classification_result.severity,
                "confidence": result.classification_result.confidence,
                "reasons_tp": result.classification_result.reasons_tp,
                "reasons_fp": result.classification_result.reasons_fp,
            }
        
        if result.forecast_bundle:
            response["forecast_bundle"] = {
                "enabled": result.forecast_bundle.enabled,
                "bucket_minutes": result.forecast_bundle.bucket_minutes,
            }
        
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/triage/{triage_id}")
async def get_triage_result(triage_id: str):
    """Get a triage result by ID."""
    if triage_id not in triage_results:
        raise HTTPException(status_code=404, detail="Triage result not found")
    
    result = triage_results[triage_id]
    
    return {
        "triage_id": triage_id,
        "signal_id": result.signal.signal_id,
        "classification": {
            "label": result.classification.label.value,
            "confidence": result.classification.confidence,
            "reasoning": result.classification.reasoning
        },
        "actions_count": len(result.actions),
        "timestamp": result.timestamp.isoformat()
    }


@app.get("/triage/{triage_id}/report", response_class=PlainTextResponse)
async def get_triage_report(triage_id: str):
    """Get the Markdown report for a triage result."""
    if triage_id not in triage_results:
        raise HTTPException(status_code=404, detail="Triage result not found")
    
    result = triage_results[triage_id]
    return result.report


@app.get("/triage/{triage_id}/actions")
async def get_triage_actions(triage_id: str):
    """Get the proposed actions for a triage result."""
    if triage_id not in triage_results:
        raise HTTPException(status_code=404, detail="Triage result not found")
    
    result = triage_results[triage_id]
    
    return {
        "triage_id": triage_id,
        "signal_id": result.signal.signal_id,
        "actions": [
            {
                "action_id": action.action_id,
                "type": action.action_type.value,
                "priority": action.priority,
                "title": action.title,
                "description": action.description,
                "steps": action.steps,
                "reasoning": action.reasoning,
                "source": action.source,
                "confidence": action.confidence,
                "estimated_effort": action.estimated_effort,
                "automation_available": action.automation_available
            }
            for action in result.actions
        ]
    }


@app.post("/signals/normalize")
async def normalize_signal(raw_signal: Dict[str, Any]) -> Signal:
    """
    Normalize a raw signal to the common schema.
    
    This endpoint accepts various signal formats and normalizes them.
    """
    # Detect signal type and normalize
    signal_type = raw_signal.get("type", "siem_alert")
    
    try:
        signal_type_enum = SignalType(signal_type)
    except ValueError:
        signal_type_enum = SignalType.SIEM_ALERT
    
    # Create normalized signal
    signal = Signal(
        signal_id=raw_signal.get("id", str(uuid.uuid4())),
        signal_type=signal_type_enum,
        timestamp=datetime.fromisoformat(raw_signal.get("timestamp", datetime.utcnow().isoformat())),
        source=SignalSource(
            system=raw_signal.get("system", "unknown"),
            rule_id=raw_signal.get("rule_id"),
            rule_name=raw_signal.get("rule_name")
        ),
        title=raw_signal.get("title", "Untitled Signal"),
        description=raw_signal.get("description", ""),
        severity=raw_signal.get("severity", "medium"),
        entities=raw_signal.get("entities", {}),
        raw_data=raw_signal,
        tags=raw_signal.get("tags", []),
        metadata=raw_signal.get("metadata", {})
    )
    
    return signal


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
