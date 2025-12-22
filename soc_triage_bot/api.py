"""FastAPI REST API for SOC Triage Bot."""

import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

from .container import ServiceContainer
from .models import Signal, SignalSource, SignalType
from .services.forecasting import MultiTrackHistoricalData

# Store for triage results (in production, use database)
triage_results: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan with container startup/shutdown."""
    # Initialize service container
    container = ServiceContainer(enable_ckg=True, demo_mode=False)

    # Startup: initialize adapters and connections
    await container.startup()

    # Store container in app state
    app.state.container = container

    yield

    # Shutdown: cleanup resources
    await container.shutdown()


# Initialize FastAPI app with lifespan
app = FastAPI(
    title="SOC Triage Bot API",
    description="Async, SIEM-agnostic SOC triage agent service",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/")
async def root():
    """Root endpoint."""
    return {"service": "SOC Triage Bot", "version": "0.1.0", "status": "operational"}


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    health_status = await container.health_check()

    return {
        "status": health_status.get("overall", "unknown"),
        "timestamp": datetime.utcnow().isoformat(),
        "details": health_status,
    }


@app.post("/triage", response_model=Dict[str, Any])
async def triage_signal(
    signal: Signal, historical_data: Optional[MultiTrackHistoricalData] = None
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

    Returns:
        Triage result with classification, actions, and structured report
    """
    try:
        # Execute extended triage with multi-track support
        result = await container.triage_service.triage_extended(signal, historical_data)

        # Store result
        triage_id = str(uuid.uuid4())
        triage_results[triage_id] = result

        # Build response
        response = {
            "triage_id": triage_id,
            "signal_id": signal.signal_id,
            "classification": {
                "label": result.classification.label.value,
                "confidence": result.classification.confidence,
                "reasoning": result.classification.reasoning,
                "factors": result.classification.factors,
            },
            "actions": [
                {
                    "action_id": action.action_id,
                    "type": action.action_type.value,
                    "priority": action.priority,
                    "title": action.title,
                    "description": action.description,
                    "confidence": action.confidence,
                    "source": action.source,
                }
                for action in result.actions
            ],
            "enrichments": {
                name: {"status": enrich.status.value, "duration_ms": enrich.duration_ms}
                for name, enrich in result.enrichments.items()
            },
            "similar_cases": result.similar_cases,
            "forecast_data": result.forecast_data,
            "duration_ms": result.duration_ms,
            "timestamp": result.timestamp.isoformat(),
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
            "reasoning": result.classification.reasoning,
        },
        "actions_count": len(result.actions),
        "timestamp": result.timestamp.isoformat(),
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
                "automation_available": action.automation_available,
            }
            for action in result.actions
        ],
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
        timestamp=datetime.fromisoformat(
            raw_signal.get("timestamp", datetime.utcnow().isoformat())
        ),
        source=SignalSource(
            system=raw_signal.get("system", "unknown"),
            rule_id=raw_signal.get("rule_id"),
            rule_name=raw_signal.get("rule_name"),
        ),
        title=raw_signal.get("title", "Untitled Signal"),
        description=raw_signal.get("description", ""),
        severity=raw_signal.get("severity", "medium"),
        entities=raw_signal.get("entities", {}),
        raw_data=raw_signal,
        tags=raw_signal.get("tags", []),
        metadata=raw_signal.get("metadata", {}),
    )

    return signal


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
