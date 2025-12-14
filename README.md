# SOC Triage Agent (Async, SIEM-Agnostic)

An enterprise-grade, **SIEM/SOAR-agnostic** triage service that ingests multiple signal types (SIEM alert, IOC, CVE, hunt finding, user report), runs **concurrent enrichments**, performs **ETS multi-horizon forecasting with rolling backtests**, retrieves **similar cases**, produces **TP/FP/Needs Review** classification, and outputs a **non-redundant SOC triage report** (Jinja → Markdown) with ranked action proposals.

## What it does
- **Normalize** any input signal into a common schema (entities, IOCs, CVEs, artifacts)
- **Enrich async** via adapters (SIEM/EDR/TI/Vuln/CMDB) with timeouts + graceful degradation
- **Forecast** (ETS) for rule/IOC/entity tracks (H1/H6/H24) + backtest + calibrated thresholds
- **Find similar cases** with explainable scoring (overlap reasons + time decay)
- **Recommend actions** from templates + case-learned + generated (deduped, ranked, capped)
- **Render report**: Markdown packet for SOC + light stakeholder summary

## Repo layout
```
.
├─ src/triage_agent/
│  ├─ api/                 # FastAPI service endpoints
│  ├─ cli/                 # CLI entrypoints
│  ├─ core/                # pipeline orchestration + state machine
│  ├─ models/              # normalized schema + report model
│  ├─ connectors/          # adapter interfaces + vendor implementations
│  ├─ forecast/            # ETS + rolling backtest + calibration
│  ├─ similar_cases/       # retrieval + scoring
│  ├─ actions/             # templates + merge/dedupe/rank
│  └─ report/              # Jinja templates + renderer
├─ templates/
│  ├─ report.md.j2
│  └─ runbooks/*.yaml
└─ examples/
   ├─ alert.json
   ├─ ioc.json
   └─ cve.json
```

## Quickstart
### Requirements
- Python 3.11+ (async-first)
- Optional: Redis (cache), Postgres (case store)

### Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Run CLI
```bash
triage run --signal-file examples/alert.json --forecast on --output report.md --demo
triage run --ioc "domain=evil.example" --forecast on --output report.md
triage run --cve "CVE-2024-12345" --forecast on --output report.md
```

### Run API
```bash
uvicorn triage_agent.api.main:app --host 0.0.0.0 --port 8080
```

Example request:
```bash
curl -s http://localhost:8080/triage/run \
  -H "Content-Type: application/json" \
  -d @examples/alert.json
```

## Configuration
All integrations are adapter-driven. Configure via env vars (or a config file).
```bash
# Core
TRIAGE_ENV=dev
TRIAGE_CACHE_ENABLED=true
TRIAGE_CASESTORE_ENABLED=true

# Optional adapters (examples)
SPLUNK_BASE_URL=...
SPLUNK_TOKEN=...

CS_CLIENT_ID=...
CS_CLIENT_SECRET=...

TI_PROVIDER=...
VULN_PROVIDER=...
CMDB_PROVIDER=...
```

## Adapters (SIEM/SOAR agnostic)
Implement these interfaces to support any stack:
- `SIEMClient`: search, pivot, time-series (zero-filled buckets)
- `SOARClient` (optional): case read/search, attachments
- `EDRClient`: detections + device context (+ gated response actions)
- `TIClient`: IOC reputation/context
- `VulnClient`: CVE exposure/applicability
- `CMDBClient`: asset owner/criticality/segment

## Safety & governance (enterprise defaults)
- Read-only by default; containment actions require explicit enablement + approvals
- All steps are logged to an audit trail (queries, pivots, recommendations)
- Forecasting is reliability-gated (backtest metrics determine confidence)

## Development
```bash
pytest
ruff check .
mypy .
```

## Roadmap
- Pluggable policy engine for approvals/permissions
- Scheduled ETS calibration jobs + cached thresholds
- Optional LLM “planner/narrator” with strict schema guardrails
