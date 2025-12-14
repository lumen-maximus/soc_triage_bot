# SOC Triage Bot

An async, SIEM-agnostic SOC triage agent service that automates security alert analysis and response recommendations.

## Features

- **Signal Ingestion & Normalization**: Accepts various signal types (SIEM alerts, IOCs, CVEs, hunt findings, user reports) and normalizes them to a common schema
- **Concurrent Enrichments**: Runs enrichments in parallel using adapters for:
  - SIEM (historical context, alert frequency)
  - EDR (endpoint data, process trees)
  - Threat Intelligence (reputation, campaigns)
  - Vulnerability databases (CVE details, patch status)
  - CMDB (asset criticality, ownership)
- **ETS Forecasting**: Multi-horizon Exponential Smoothing forecasting with rolling backtest and anomaly detection
- **Similar Case Retrieval**: TF-IDF based similarity search to find related historical cases
- **Deterministic Classification**: Rule-based TP/FP classification using enrichment data and historical patterns
- **Action Proposals**: Generate, deduplicate, and rank action recommendations from:
  - Pre-defined templates
  - Case-learned patterns
  - Dynamic context-based generation
- **Jinja Markdown Reports**: Professional, readable triage reports
- **Dual Interfaces**: Both CLI and REST API available

## Installation

```bash
# Clone the repository
git clone https://github.com/Maxthecoder1/soc_triage_bot.git
cd soc_triage_bot

# Install dependencies
pip install -e .

# For development (includes test dependencies)
pip install -e ".[dev]"
```

## Quick Start

### CLI Usage

```bash
# Start the REST API server
soc-triage serve --host 0.0.0.0 --port 8000

# Triage a signal from a JSON file
soc-triage triage examples/siem_alert.json -o report.md

# Triage with historical data for forecasting
soc-triage triage examples/siem_alert.json \
  --historical-data examples/historical_data.json \
  -o report.md

# Create and triage a signal interactively
soc-triage create --type siem_alert

# Validate a signal file
soc-triage validate examples/siem_alert.json

# Check adapter health
soc-triage health
```

### REST API Usage

Start the server:

```bash
soc-triage serve
```

Or with uvicorn directly:

```bash
uvicorn soc_triage_bot.api:app --host 0.0.0.0 --port 8000
```

Example API calls:

```bash
# Health check
curl http://localhost:8000/health

# Triage a signal
curl -X POST http://localhost:8000/triage \
  -H "Content-Type: application/json" \
  -d @examples/siem_alert.json

# Get triage result
curl http://localhost:8000/triage/{triage_id}

# Get Markdown report
curl http://localhost:8000/triage/{triage_id}/report

# Get action proposals
curl http://localhost:8000/triage/{triage_id}/actions

# Normalize a raw signal
curl -X POST http://localhost:8000/signals/normalize \
  -H "Content-Type: application/json" \
  -d '{"type":"siem_alert","title":"Test","description":"Test alert","severity":"high"}'
```

## Signal Format

Signals follow a normalized schema:

```json
{
  "signal_id": "sig-20251214-001",
  "signal_type": "siem_alert",
  "timestamp": "2025-12-14T19:00:00Z",
  "source": {
    "system": "splunk",
    "rule_id": "rule-001",
    "rule_name": "Suspicious PowerShell"
  },
  "title": "Suspicious PowerShell Execution",
  "description": "PowerShell with encoded command detected",
  "severity": "high",
  "entities": {
    "hostname": ["workstation-01"],
    "user": ["admin"],
    "ip": ["192.0.2.15"]
  },
  "tags": ["malware", "powershell"],
  "raw_data": {},
  "metadata": {}
}
```

### Signal Types

- `siem_alert`: Alerts from SIEM systems
- `ioc`: Indicator of Compromise matches
- `cve`: Vulnerability reports
- `hunt`: Threat hunting findings
- `user_report`: User-submitted security concerns

## Architecture

### Components

1. **Models**: Pydantic models for signals, enrichments, classifications, and actions
2. **Adapters**: Pluggable adapters for external systems (SIEM, EDR, TI, Vuln, CMDB)
3. **Services**:
   - `EnrichmentService`: Orchestrates concurrent enrichments
   - `ForecastingService`: ETS forecasting with rolling backtest
   - `SimilarityService`: Similar case retrieval using TF-IDF
   - `ClassificationService`: Deterministic TP/FP classification
   - `ActionProposalService`: Template, learned, and generated action proposals
   - `ReportService`: Jinja2-based report generation
   - `TriageService`: Main orchestrator for the complete workflow

### Workflow

1. **Ingest**: Accept signal in various formats
2. **Normalize**: Convert to common schema
3. **Enrich**: Run concurrent enrichments via adapters
4. **Forecast**: Analyze time series patterns (if historical data provided)
5. **Retrieve**: Find similar historical cases
6. **Classify**: Determine TP/FP/Unknown with confidence score
7. **Propose**: Generate ranked action recommendations
8. **Report**: Render comprehensive Markdown report

## Configuration

The system is designed to be SIEM-agnostic with pluggable adapters. To integrate with your environment:

1. **Implement Custom Adapters**: Extend `BaseAdapter` for your specific systems
2. **Configure Endpoints**: Set API endpoints and credentials in adapter configs
3. **Tune Classification**: Adjust confidence thresholds in `ClassificationService`
4. **Add Templates**: Extend action templates in `ActionProposalService`

Example custom adapter:

```python
from soc_triage_bot.adapters import BaseAdapter
from soc_triage_bot.models import Signal, EnrichmentResult, EnrichmentStatus

class MySIEMAdapter(BaseAdapter):
    async def enrich(self, signal: Signal) -> EnrichmentResult:
        # Query your SIEM
        data = await query_my_siem(signal)
        
        return EnrichmentResult(
            adapter=self.name,
            status=EnrichmentStatus.SUCCESS,
            data=data
        )
```

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=soc_triage_bot --cov-report=html
```

### Project Structure

```
soc_triage_bot/
├── soc_triage_bot/
│   ├── __init__.py
│   ├── models/          # Pydantic data models
│   │   ├── signal.py
│   │   ├── enrichment.py
│   │   ├── classification.py
│   │   └── action.py
│   ├── adapters/        # Enrichment adapters
│   │   ├── base.py
│   │   ├── siem.py
│   │   ├── edr.py
│   │   ├── threat_intel.py
│   │   ├── vulnerability.py
│   │   └── cmdb.py
│   ├── services/        # Core services
│   │   ├── enrichment.py
│   │   ├── forecasting.py
│   │   ├── similarity.py
│   │   ├── classification.py
│   │   ├── action_proposal.py
│   │   ├── report.py
│   │   └── triage.py
│   ├── api.py          # FastAPI REST API
│   └── cli.py          # Click CLI
├── tests/              # Test suite
├── examples/           # Example signals
└── pyproject.toml     # Project configuration
```

## API Documentation

When the server is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Extending the System

### Adding New Signal Types

1. Add to `SignalType` enum in `models/signal.py`
2. Update normalization logic in `api.py` or `cli.py`
3. Add example in `examples/`

### Adding New Adapters

1. Create new adapter in `adapters/`
2. Extend `BaseAdapter`
3. Implement `enrich()` method
4. Register in `api.py` and `cli.py`

### Adding Action Templates

Edit `ActionProposalService._load_templates()` in `services/action_proposal.py`

## License

MIT License - see LICENSE file for details

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For issues, questions, or contributions, please open an issue on GitHub.
