"""Command-line interface for SOC Triage Bot."""

import click
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import Signal, SignalType, SignalSource
from .services import TriageService, EnrichmentService
from .adapters import SIEMAdapter, EDRAdapter, ThreatIntelAdapter, VulnerabilityAdapter, CMDBAdapter


def setup_triage_service():
    """Initialize the triage service."""
    adapters = [
        SIEMAdapter(),
        EDRAdapter(),
        ThreatIntelAdapter(),
        VulnerabilityAdapter(),
        CMDBAdapter()
    ]
    
    enrichment_service = EnrichmentService(adapters)
    return TriageService(enrichment_service=enrichment_service)


@click.group()
@click.version_option(version="0.1.0")
def main():
    """SOC Triage Bot - Async, SIEM-agnostic SOC triage agent service."""
    pass


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, reload: bool):
    """Start the REST API server."""
    import uvicorn
    
    click.echo(f"Starting SOC Triage Bot API on {host}:{port}")
    uvicorn.run(
        "soc_triage_bot.api:app",
        host=host,
        port=port,
        reload=reload
    )


@main.command()
@click.argument("signal_file", type=click.Path(exists=True))
@click.option("--historical-data", type=click.Path(exists=True), help="Historical data JSON file")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
@click.option("--format", "-f", type=click.Choice(["markdown", "json"]), default="markdown", help="Output format")
def triage(signal_file: str, historical_data: Optional[str], output: Optional[str], format: str):
    """Triage a security signal from a JSON file."""
    # Load signal
    with open(signal_file) as f:
        signal_data = json.load(f)
    
    # Parse signal
    signal = parse_signal_from_json(signal_data)
    
    # Load historical data if provided
    hist_data = None
    if historical_data:
        with open(historical_data) as f:
            hist_data = json.load(f)
    
    # Execute triage
    click.echo(f"Triaging signal: {signal.signal_id}")
    result = asyncio.run(execute_triage(signal, hist_data))
    
    # Output results
    if format == "json":
        output_data = format_result_as_json(result)
        output_text = json.dumps(output_data, indent=2, default=str)
    else:
        output_text = result.report
    
    if output:
        with open(output, "w") as f:
            f.write(output_text)
        click.echo(f"Report written to: {output}")
    else:
        click.echo("\n" + output_text)


@main.command()
@click.option("--type", "signal_type", type=click.Choice(["siem_alert", "ioc", "cve", "hunt", "user_report"]), 
              default="siem_alert", help="Signal type")
@click.option("--title", prompt=True, help="Signal title")
@click.option("--description", prompt=True, help="Signal description")
@click.option("--severity", type=click.Choice(["low", "medium", "high", "critical"]), 
              default="medium", help="Severity level")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
def create(signal_type: str, title: str, description: str, severity: str, output: Optional[str]):
    """Create and triage a new signal interactively."""
    # Create signal
    signal = Signal(
        signal_id=f"sig-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        signal_type=SignalType(signal_type),
        timestamp=datetime.utcnow(),
        source=SignalSource(system="cli", rule_name="manual"),
        title=title,
        description=description,
        severity=severity,
        entities={},
        tags=[],
        raw_data={}
    )
    
    click.echo(f"Created signal: {signal.signal_id}")
    
    # Execute triage
    result = asyncio.run(execute_triage(signal, None))
    
    # Output report
    if output:
        with open(output, "w") as f:
            f.write(result.report)
        click.echo(f"Report written to: {output}")
    else:
        click.echo("\n" + result.report)


@main.command()
def health():
    """Check health of all adapters."""
    adapters = [
        SIEMAdapter(),
        EDRAdapter(),
        ThreatIntelAdapter(),
        VulnerabilityAdapter(),
        CMDBAdapter()
    ]
    
    enrichment_service = EnrichmentService(adapters)
    
    click.echo("Checking adapter health...")
    health_status = asyncio.run(enrichment_service.health_check())
    
    for adapter_name, is_healthy in health_status.items():
        status = "✓ healthy" if is_healthy else "✗ unhealthy"
        click.echo(f"  {adapter_name}: {status}")


@main.command()
@click.argument("signal_file", type=click.Path(exists=True))
def validate(signal_file: str):
    """Validate a signal JSON file."""
    try:
        with open(signal_file) as f:
            signal_data = json.load(f)
        
        signal = parse_signal_from_json(signal_data)
        click.echo(f"✓ Signal is valid: {signal.signal_id}")
        click.echo(f"  Type: {signal.signal_type.value}")
        click.echo(f"  Severity: {signal.severity}")
        click.echo(f"  Entities: {len(signal.entities)} types")
    except Exception as e:
        click.echo(f"✗ Signal validation failed: {e}", err=True)
        raise click.Abort()


async def execute_triage(signal: Signal, historical_data):
    """Execute triage asynchronously."""
    triage_service = setup_triage_service()
    result = await triage_service.triage(signal, historical_data)
    return result


def parse_signal_from_json(data: dict) -> Signal:
    """Parse a signal from JSON data."""
    signal_type = SignalType(data.get("signal_type", "siem_alert"))
    
    # Parse timestamp
    timestamp_str = data.get("timestamp")
    if timestamp_str:
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    else:
        timestamp = datetime.utcnow()
    
    # Parse source
    source_data = data.get("source", {})
    source = SignalSource(
        system=source_data.get("system", "unknown"),
        instance=source_data.get("instance"),
        rule_id=source_data.get("rule_id"),
        rule_name=source_data.get("rule_name")
    )
    
    return Signal(
        signal_id=data.get("signal_id", f"sig-{int(datetime.utcnow().timestamp())}"),
        signal_type=signal_type,
        timestamp=timestamp,
        source=source,
        title=data.get("title", "Untitled"),
        description=data.get("description", ""),
        severity=data.get("severity", "medium"),
        entities=data.get("entities", {}),
        raw_data=data.get("raw_data", {}),
        tags=data.get("tags", []),
        metadata=data.get("metadata", {})
    )


def format_result_as_json(result):
    """Format triage result as JSON."""
    return {
        "signal_id": result.signal.signal_id,
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
                "source": action.source,
                "confidence": action.confidence
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
        "duration_ms": result.duration_ms,
        "timestamp": result.timestamp.isoformat()
    }


if __name__ == "__main__":
    main()
