# Enterprise Spec: Async SOC Triage Agent

## 1) Purpose

Build an **async triage agent** that accepts **multiple signal types** (SIEM alerts, threat intel/IOCs, CVE/vuln signals, hunt findings, user reports), enriches them with environment context, determines **TP/FP/Needs Review**, and produces a **non-redundant SOC-grade triage packet** (Markdown via Jinja) with **ranked action proposals** at the top.

It must also support **ETS multi-horizon forecasting** with **rolling backtests** and **calibrated thresholds**, and use **SOAR similar-case retrieval** to inform recommendations.

---

## 2) Goals and non-goals

### Goals

- **Multi-source ingestion**: start from Alert _or_ IOC _or_ CVE _or_ Hunt _or_ User report.
- **Deterministic triage outcome**: TP/FP/Review + confidence + severity + incident type.
- **Enterprise-grade recommendations**:

  - Actions come from **templates + case-learned + contextual generation**
  - Strict dedupe + ranking so “proposals” aren’t noisy.

- **Explainable**: every decision and recommendation cites specific evidence and data gaps.
- **Async**: enrichments run concurrently and degrade gracefully.
- **Forecasting**: ETS (H1/H6/H24) + **rolling backtests** + reliability gates.

### Non-goals

- Full incident response automation (containment execution) by default. (Agent can recommend and optionally mark actions as auto-executable, but execution is a separate control plane.)

---

## 3) Supported signal types

### `SIEM_ALERT`

- Input: alert payload (rule name/id, entities, timestamps, fields)
- Agent focus: validate alert logic, correlate telemetry, enrich entities, propose response.

### `TI_INDICATOR` (IOC-led)

- Input: indicator(s) + optional TI context
- Agent focus: “Do we see it locally?”, sightings scope, reputation, blocking guidance.

### `VULNERABILITY_ALERT` (CVE-led)

- Input: CVE(s) and/or scanner finding(s)
- Agent focus: exposure/applicability, internet-facing risk, exploit telemetry, patch priority.

### `HUNT_FINDING`

- Input: hunt id/query + matching artifacts/entities
- Agent focus: validate hunt signal, expand scope, convert to incident type if warranted.

### `USER_REPORTED`

- Input: user report + minimal details
- Agent focus: collect evidence, correlate with telemetry, confirm/deny.

---

## 4) High-level architecture

### Components

- **TriageOrchestrator (async)**: coordinates pipeline steps, concurrency, timeouts.
- **Connectors (async)**:

  - `SIEMClient`: search, timeseries, entity pivoting
  - `SOARClient`: search cases, read case features/notes/actions
  - `TIClient`: reputation/contexts for IOC values
  - `VulnClient`: asset exposure, CVE applicability, KEV flags (if available)
  - `AssetCMDBClient`: owner/criticality/segment/service mapping
  - `EDRClient` (optional): host evidence metadata (not full raw if restricted)

- **EvidenceNormalizer**: extracts consistent entities/artifacts from any signal type.
- **Classifier**: computes TP likelihood, severity, incident type, MITRE tags.
- **Forecaster**: ETS fit + rolling backtest + calibrated thresholds (H1/H6/H24).
- **SimilarCaseRetriever**: candidate generation + explainable scoring + time decay.
- **ActionEngine**: templates + case-learned + generated actions → merge/dedupe/rank.
- **ReportRenderer**: Jinja → Markdown report.
- **CLI Runner**: one command runs pipeline and outputs report + step-by-step narration.

---

## 5) Data model (normalized “report object”)

### Canonical `NormalizedContext`

- `signal`: `{id, type, source, name, category, timestamp_utc, raw}`
- `entities`: `{username?, hostname?, src_ip?, dst_ip?, cloud_resource?, app?}`
- `indicators`: dict `{indicator_type -> value}` (supports all)
- `cves`: list of CVE IDs
- `alert_identity`: `{rule_id?, rule_name?, vendor?}`
- `artifacts`: `{file_hash?, cmdline_hash?, process_name?, parent_process?, url?, domain?}`
- `entity_focus`: `{primary, secondary[]}` (chosen by signal type/subtype mapping)

### `Enrichment`

- `local_sightings[]`: where/when/how often IOC or condition observed
- `related_events[]`: correlated timeline events
- `threat_intel{value->record}`: reputation, confidence, sources, notes
- `asset_context`: host/user/service criticality, owners, segment
- `host_vulns[]`: vulnerabilities for host (if host exists)
- `env_exposure`: vuln exposure summary (if CVE-led)
- `scope`: impacted hosts/users/segments + spread assessment
- `notes`: data gaps, assumptions

### `Classification`

- `disposition`: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW
- `tp_likelihood` (0..1), `confidence` (low/med/high), `severity` (low..critical)
- `incident_type` + `mitre`: `{tactics[], techniques[]}`
- `reasons_tp[]`, `reasons_fp[]`, `triage_judgment`

### `Forecast`

- `enabled`, `bucket_minutes`
- `tracks`: `rule`, `ioc`, `entity` (each optional)
- each track: horizons H1/H6/H24 totals + interpretation + confidence + backtest metrics + thresholds

### `Recommendations`

- list of `RecommendedAction` with `intent/priority/owner/tool/source/dedupe_key`

---

## 6) Pipeline (end-to-end)

### Step 0 — Ingest

Input can be any of:

- `--signal-file alert.json`
- `--ioc "domain=evil.com"`
- `--cve CVE-2024-12345`
- `--hunt-id HUNT-007`
- `--user-report report.txt`

### Step 1 — Normalize (must succeed)

- Extract entities, indicators, CVEs, artifacts.
- Determine `signal_subtype` (auth/endpoint/network/email/vuln/etc.)
- Select `entity_focus.primary` using mapping rules.

### Step 2 — Enrich (async fan-out)

Run concurrently with timeouts:

- SIEM correlation (events around timestamp, pivots on entities/IOCs)
- Local IOC sightings (multi-telemetry if IOC-led)
- TI lookups for IOCs
- Asset context lookups (CMDB/asset inventory)
- Vulnerability exposure (if CVEs present)
- Optional: EDR metadata lookups

### Step 3 — Forecast (optional, gated)

If forecasting enabled and you can retrieve bucketed series:

- Build series for up to 3 tracks:

  1. Rule metric (alert counts)
  2. IOC sightings metric
  3. Entity behavior metric (dynamic)

- Fit ETS per track and horizon totals.
- Perform rolling-origin backtest per horizon (H1/H6/H24).
- Calibrate spike thresholds from backtest residual quantiles.
- Assign reliability gate (Low/Med/High) so forecast doesn’t over-drive decisions.

### Step 4 — Similar cases (SOAR)

- Candidate generation (OR query across rule/IOC/CVE/entities/MITRE/artifact hashes)
- Score with weighted overlaps + time decay
- Return top N with “overlap reasons” + actions_taken summary

### Step 5 — Classify (TP/FP/Review)

Compute TP likelihood using a **rule-based scoring model** (auditable) plus optional ML later.
Inputs:

- TI reputation + confidence
- Local sightings + correlated event density
- Entity criticality/exposure
- CVE KEV/exploit telemetry (if available)
- Similar-case outcomes (weighted)
- ETS spike (only if reliable)

Output:

- disposition + severity + confidence + reasons_tp/fp + incident type + MITRE tags

### Step 6 — Recommend actions (enterprise-grade)

Actions generated from **both**:

1. **Templates** (runbooks/playbooks) keyed by signal type/subtype/incident type
2. **Case-learned** actions (only from high-similarity, recent, successful cases)
3. **Generated** contextual actions (parameterized “do X in tool Y for entity Z”)

Then:

- dedupe by `(intent|tool|owner|target_signature)`
- apply gating (TP/FP/Review + data availability + risk/approval)
- rank and cap:

  - Proposals at top: 3–6
  - Full action plan: max 12–15

### Step 7 — Render report

- Render the **Jinja Markdown template** (the one you already have)
- Populate non-redundant sections:

  - Entities only in “Normalized Context”
  - Evidence only in “Correlation/Timeline”
  - Decision only in “Decision Banner”
  - Actions only in “Action Plan”

### Step 8 — Output

- Write `report.md` (and optional JSON)
- Print a concise SOC-style narration to stdout in demo mode

---

## 7) Entity selection rules (by signal type)

### If `SIEM_ALERT`

Pick primary entity based on alert family:

- Auth → `username` (secondary `src_ip`)
- Endpoint execution → `hostname` (secondary `username`)
- Network beaconing → `src_ip/hostname` (secondary `domain`)
- Email → `sender/recipient` (secondary `domain`)

### If `TI_INDICATOR`

Primary entity = indicator itself; secondary = impacted hosts/users from sightings.

### If `VULNERABILITY_ALERT`

Primary entity = asset/service group (internet-facing/segment); secondary = affected hosts.

### If `HUNT_FINDING`

Primary entity = hunt key (host/user/process/cloud resource).

### If `USER_REPORTED`

Primary entity = user+host; secondary = app/service involved.

---

## 8) ETS forecasting spec (enterprise-grade)

### Tracks and metrics

- Rule track: `count(alert firings per bucket)`
- IOC track: `count(ioc sightings per bucket)`
- Entity track: `count(entity behavior per bucket)` (auth failures per user, suspicious process launches per host, etc.)

### Horizons

- H1 = next 1 hour (sum of next N buckets)
- H6 = next 6 hours
- H24 = next 24 hours

### Backtesting

Rolling-origin evaluation:

- Train window: 28–56 days (if daily seasonality)
- Step: 1 bucket
- Score per horizon on **horizon totals**:

  - sMAPE, MASE, RMSE
  - Coverage95 if bands are produced

### Calibration

- Compute residual quantiles per horizon:

  - Spike threshold = forecast_total + Q99(residual)

- Reliability gate:

  - Low if insufficient history/splits or MASE too high
  - Only allow ETS to “boost scope/monitoring” if reliability >= Medium

---

## 9) Similar-case retrieval spec

### Candidate generation (high recall)

OR across:

- rule_id/rule_name
- exact IOC matches
- CVE overlap
- hostname/username/ip overlaps
- MITRE techniques/tactics
- artifact hash overlaps

### Scoring (explainable)

Weighted overlaps + time decay; return “overlap reasons” like:

- “Exact IOC match domain=…”
- “Same analytic id …”
- “CVE overlap …”
- “Same host …”

---

## 10) Recommendations spec (templates + cases + generated)

### Action taxonomy (intents)

`validate, scope, contain, collect, notify, tune, patch, monitor, document, eradicate, recover`

### Gating

- Containment actions require TP likelihood high or explicit approval flag.
- No host? no isolate-host actions. No IOC? no block actions. No CVE? no patch actions.

### Dedupe key

`intent|tool|owner|target_signature`

### Ranking

Disposition-aware ordering:

- TP-leaning: contain/notify → scope → collect → monitor → document
- Ambiguous: validate → collect → scope → monitor → notify
- FP-leaning: validate → tune → document → monitor

---

## 11) CLI requirements (single-command demo)

### Command

`triage run [--signal-file alert.json | --ioc ... | --cve ... | --hunt-id ... | --user-report ...] [--forecast on|off] [--output report.md] [--demo]`

### Behavior

- One command runs full pipeline.
- `--demo` prints SOC-style step narration:

  - “Pulled correlated events…”
  - “IOC reputation: suspicious…”
  - “Backtest reliability: Medium (MASE H6=1.1)…”
  - “Recommended actions ranked…”

---

## 12) Async + reliability requirements

### Concurrency

- Enrichment fan-out uses `asyncio.gather()` with per-task timeouts.
- Failures must not break report; they populate **Data Quality & Gaps**.

### Timeouts and budgets

- Each connector call has a timeout and retry policy.
- Overall pipeline has a max wall-clock budget (configurable).

### Caching

- Cache TI lookups and time series pulls to reduce SIEM load.
- Backtests should run on a schedule (daily) when possible; triage run can reuse stored backtest metrics.

---

## 13) Security, privacy, and audit

- Redact secrets/PII in `Raw Signal Payload` appendix (configurable redaction policy).
- Full audit log includes:

  - queries executed (hashed or template-id)
  - connector response counts
  - classification inputs and final reasons

- No automatic containment without explicit enablement and approvals.

---

## 14) Testing and acceptance criteria

### MVP acceptance

- Supports at least: SIEM_ALERT + IOC + CVE
- Produces report with:

  - Decision Banner
  - Non-redundant context/evidence/actions sections
  - Similar cases table (even if stubbed)
  - Action proposals (templates + generated)

- Async fan-out with graceful degradation.

### Enterprise acceptance

- Rolling backtest per horizon (H1/H6/H24) with stored metrics
- Similar-case scoring explainability
- Recommendation dedupe/ranking is stable and capped
- Demo command works end-to-end in VS Code

---

## 15) Config (example)

- `bucket_minutes=15`
- `lookback_days=56`
- `similar_cases_lookback=180`
- `min_similarity_score=35`
- `case_action_similarity_threshold=60`
- `half_life_days=60`
- `forecast_horizons=[1,6,24]`
- `max_proposals=6`
- `max_actions=15`

---

If you want the next artifact, tell me whether you want this spec turned into:

1. a **single `README.md`** + folder layout + interface stubs, or
2. a **Python package skeleton** (async pipeline, connectors, report renderer, CLI) that your Copilot agent can execute step-by-step.

# Enterprise Spec: Async SOC Triage Agent

## 1) Purpose

Build an **async triage agent** that accepts **multiple signal types** (SIEM alerts, threat intel/IOCs, CVE/vuln signals, hunt findings, user reports), enriches them with environment context, determines **TP/FP/Needs Review**, and produces a **non-redundant SOC-grade triage packet** (Markdown via Jinja) with **ranked action proposals** at the top.

It must also support **ETS multi-horizon forecasting** with **rolling backtests** and **calibrated thresholds**, and use **SOAR similar-case retrieval** to inform recommendations.

---

## 2) Goals and non-goals

### Goals

- **Multi-source ingestion**: start from Alert _or_ IOC _or_ CVE _or_ Hunt _or_ User report.
- **Deterministic triage outcome**: TP/FP/Review + confidence + severity + incident type.
- **Enterprise-grade recommendations**:

  - Actions come from **templates + case-learned + contextual generation**
  - Strict dedupe + ranking so “proposals” aren’t noisy.

- **Explainable**: every decision and recommendation cites specific evidence and data gaps.
- **Async**: enrichments run concurrently and degrade gracefully.
- **Forecasting**: ETS (H1/H6/H24) + **rolling backtests** + reliability gates.

### Non-goals

- Full incident response automation (containment execution) by default. (Agent can recommend and optionally mark actions as auto-executable, but execution is a separate control plane.)

---

## 3) Supported signal types

### `SIEM_ALERT`

- Input: alert payload (rule name/id, entities, timestamps, fields)
- Agent focus: validate alert logic, correlate telemetry, enrich entities, propose response.

### `TI_INDICATOR` (IOC-led)

- Input: indicator(s) + optional TI context
- Agent focus: “Do we see it locally?”, sightings scope, reputation, blocking guidance.

### `VULNERABILITY_ALERT` (CVE-led)

- Input: CVE(s) and/or scanner finding(s)
- Agent focus: exposure/applicability, internet-facing risk, exploit telemetry, patch priority.

### `HUNT_FINDING`

- Input: hunt id/query + matching artifacts/entities
- Agent focus: validate hunt signal, expand scope, convert to incident type if warranted.

### `USER_REPORTED`

- Input: user report + minimal details
- Agent focus: collect evidence, correlate with telemetry, confirm/deny.

---

## 4) High-level architecture

### Components

- **TriageOrchestrator (async)**: coordinates pipeline steps, concurrency, timeouts.
- **Connectors (async)**:

  - `SIEMClient`: search, timeseries, entity pivoting
  - `SOARClient`: search cases, read case features/notes/actions
  - `TIClient`: reputation/contexts for IOC values
  - `VulnClient`: asset exposure, CVE applicability, KEV flags (if available)
  - `AssetCMDBClient`: owner/criticality/segment/service mapping
  - `EDRClient` (optional): host evidence metadata (not full raw if restricted)

- **EvidenceNormalizer**: extracts consistent entities/artifacts from any signal type.
- **Classifier**: computes TP likelihood, severity, incident type, MITRE tags.
- **Forecaster**: ETS fit + rolling backtest + calibrated thresholds (H1/H6/H24).
- **SimilarCaseRetriever**: candidate generation + explainable scoring + time decay.
- **ActionEngine**: templates + case-learned + generated actions → merge/dedupe/rank.
- **ReportRenderer**: Jinja → Markdown report.
- **CLI Runner**: one command runs pipeline and outputs report + step-by-step narration.

---

## 5) Data model (normalized “report object”)

### Canonical `NormalizedContext`

- `signal`: `{id, type, source, name, category, timestamp_utc, raw}`
- `entities`: `{username?, hostname?, src_ip?, dst_ip?, cloud_resource?, app?}`
- `indicators`: dict `{indicator_type -> value}` (supports all)
- `cves`: list of CVE IDs
- `alert_identity`: `{rule_id?, rule_name?, vendor?}`
- `artifacts`: `{file_hash?, cmdline_hash?, process_name?, parent_process?, url?, domain?}`
- `entity_focus`: `{primary, secondary[]}` (chosen by signal type/subtype mapping)

### `Enrichment`

- `local_sightings[]`: where/when/how often IOC or condition observed
- `related_events[]`: correlated timeline events
- `threat_intel{value->record}`: reputation, confidence, sources, notes
- `asset_context`: host/user/service criticality, owners, segment
- `host_vulns[]`: vulnerabilities for host (if host exists)
- `env_exposure`: vuln exposure summary (if CVE-led)
- `scope`: impacted hosts/users/segments + spread assessment
- `notes`: data gaps, assumptions

### `Classification`

- `disposition`: TRUE_POSITIVE | FALSE_POSITIVE | NEEDS_REVIEW
- `tp_likelihood` (0..1), `confidence` (low/med/high), `severity` (low..critical)
- `incident_type` + `mitre`: `{tactics[], techniques[]}`
- `reasons_tp[]`, `reasons_fp[]`, `triage_judgment`

### `Forecast`

- `enabled`, `bucket_minutes`
- `tracks`: `rule`, `ioc`, `entity` (each optional)
- each track: horizons H1/H6/H24 totals + interpretation + confidence + backtest metrics + thresholds

### `Recommendations`

- list of `RecommendedAction` with `intent/priority/owner/tool/source/dedupe_key`

---

## 6) Pipeline (end-to-end)

### Step 0 — Ingest

Input can be any of:

- `--signal-file alert.json`
- `--ioc "domain=evil.com"`
- `--cve CVE-2024-12345`
- `--hunt-id HUNT-007`
- `--user-report report.txt`

### Step 1 — Normalize (must succeed)

- Extract entities, indicators, CVEs, artifacts.
- Determine `signal_subtype` (auth/endpoint/network/email/vuln/etc.)
- Select `entity_focus.primary` using mapping rules.

### Step 2 — Enrich (async fan-out)

Run concurrently with timeouts:

- SIEM correlation (events around timestamp, pivots on entities/IOCs)
- Local IOC sightings (multi-telemetry if IOC-led)
- TI lookups for IOCs
- Asset context lookups (CMDB/asset inventory)
- Vulnerability exposure (if CVEs present)
- Optional: EDR metadata lookups

### Step 3 — Forecast (optional, gated)

If forecasting enabled and you can retrieve bucketed series:

- Build series for up to 3 tracks:

  1. Rule metric (alert counts)
  2. IOC sightings metric
  3. Entity behavior metric (dynamic)

- Fit ETS per track and horizon totals.
- Perform rolling-origin backtest per horizon (H1/H6/H24).
- Calibrate spike thresholds from backtest residual quantiles.
- Assign reliability gate (Low/Med/High) so forecast doesn’t over-drive decisions.

### Step 4 — Similar cases (SOAR)

- Candidate generation (OR query across rule/IOC/CVE/entities/MITRE/artifact hashes)
- Score with weighted overlaps + time decay
- Return top N with “overlap reasons” + actions_taken summary

### Step 5 — Classify (TP/FP/Review)

Compute TP likelihood using a **rule-based scoring model** (auditable) plus optional ML later.
Inputs:

- TI reputation + confidence
- Local sightings + correlated event density
- Entity criticality/exposure
- CVE KEV/exploit telemetry (if available)
- Similar-case outcomes (weighted)
- ETS spike (only if reliable)

Output:

- disposition + severity + confidence + reasons_tp/fp + incident type + MITRE tags

### Step 6 — Recommend actions (enterprise-grade)

Actions generated from **both**:

1. **Templates** (runbooks/playbooks) keyed by signal type/subtype/incident type
2. **Case-learned** actions (only from high-similarity, recent, successful cases)
3. **Generated** contextual actions (parameterized “do X in tool Y for entity Z”)

Then:

- dedupe by `(intent|tool|owner|target_signature)`
- apply gating (TP/FP/Review + data availability + risk/approval)
- rank and cap:

  - Proposals at top: 3–6
  - Full action plan: max 12–15

### Step 7 — Render report

- Render the **Jinja Markdown template** (the one you already have)
- Populate non-redundant sections:

  - Entities only in “Normalized Context”
  - Evidence only in “Correlation/Timeline”
  - Decision only in “Decision Banner”
  - Actions only in “Action Plan”

### Step 8 — Output

- Write `report.md` (and optional JSON)
- Print a concise SOC-style narration to stdout in demo mode

---

## 7) Entity selection rules (by signal type)

### If `SIEM_ALERT`

Pick primary entity based on alert family:

- Auth → `username` (secondary `src_ip`)
- Endpoint execution → `hostname` (secondary `username`)
- Network beaconing → `src_ip/hostname` (secondary `domain`)
- Email → `sender/recipient` (secondary `domain`)

### If `TI_INDICATOR`

Primary entity = indicator itself; secondary = impacted hosts/users from sightings.

### If `VULNERABILITY_ALERT`

Primary entity = asset/service group (internet-facing/segment); secondary = affected hosts.

### If `HUNT_FINDING`

Primary entity = hunt key (host/user/process/cloud resource).

### If `USER_REPORTED`

Primary entity = user+host; secondary = app/service involved.

---

## 8) ETS forecasting spec (enterprise-grade)

### Tracks and metrics

- Rule track: `count(alert firings per bucket)`
- IOC track: `count(ioc sightings per bucket)`
- Entity track: `count(entity behavior per bucket)` (auth failures per user, suspicious process launches per host, etc.)

### Horizons

- H1 = next 1 hour (sum of next N buckets)
- H6 = next 6 hours
- H24 = next 24 hours

### Backtesting

Rolling-origin evaluation:

- Train window: 28–56 days (if daily seasonality)
- Step: 1 bucket
- Score per horizon on **horizon totals**:

  - sMAPE, MASE, RMSE
  - Coverage95 if bands are produced

### Calibration

- Compute residual quantiles per horizon:

  - Spike threshold = forecast_total + Q99(residual)

- Reliability gate:

  - Low if insufficient history/splits or MASE too high
  - Only allow ETS to “boost scope/monitoring” if reliability >= Medium

---

## 9) Similar-case retrieval spec

### Candidate generation (high recall)

OR across:

- rule_id/rule_name
- exact IOC matches
- CVE overlap
- hostname/username/ip overlaps
- MITRE techniques/tactics
- artifact hash overlaps

### Scoring (explainable)

Weighted overlaps + time decay; return “overlap reasons” like:

- “Exact IOC match domain=…”
- “Same analytic id …”
- “CVE overlap …”
- “Same host …”

---

## 10) Recommendations spec (templates + cases + generated)

### Action taxonomy (intents)

`validate, scope, contain, collect, notify, tune, patch, monitor, document, eradicate, recover`

### Gating

- Containment actions require TP likelihood high or explicit approval flag.
- No host? no isolate-host actions. No IOC? no block actions. No CVE? no patch actions.

### Dedupe key

`intent|tool|owner|target_signature`

### Ranking

Disposition-aware ordering:

- TP-leaning: contain/notify → scope → collect → monitor → document
- Ambiguous: validate → collect → scope → monitor → notify
- FP-leaning: validate → tune → document → monitor

---

## 11) CLI requirements (single-command demo)

### Command

`triage run [--signal-file alert.json | --ioc ... | --cve ... | --hunt-id ... | --user-report ...] [--forecast on|off] [--output report.md] [--demo]`

### Behavior

- One command runs full pipeline.
- `--demo` prints SOC-style step narration:

  - “Pulled correlated events…”
  - “IOC reputation: suspicious…”
  - “Backtest reliability: Medium (MASE H6=1.1)…”
  - “Recommended actions ranked…”

---

## 12) Async + reliability requirements

### Concurrency

- Enrichment fan-out uses `asyncio.gather()` with per-task timeouts.
- Failures must not break report; they populate **Data Quality & Gaps**.

### Timeouts and budgets

- Each connector call has a timeout and retry policy.
- Overall pipeline has a max wall-clock budget (configurable).

### Caching

- Cache TI lookups and time series pulls to reduce SIEM load.
- Backtests should run on a schedule (daily) when possible; triage run can reuse stored backtest metrics.

---

## 13) Security, privacy, and audit

- Redact secrets/PII in `Raw Signal Payload` appendix (configurable redaction policy).
- Full audit log includes:

  - queries executed (hashed or template-id)
  - connector response counts
  - classification inputs and final reasons

- No automatic containment without explicit enablement and approvals.

---

## 14) Testing and acceptance criteria

### MVP acceptance

- Supports at least: SIEM_ALERT + IOC + CVE
- Produces report with:

  - Decision Banner
  - Non-redundant context/evidence/actions sections
  - Similar cases table (even if stubbed)
  - Action proposals (templates + generated)

- Async fan-out with graceful degradation.

### Enterprise acceptance

- Rolling backtest per horizon (H1/H6/H24) with stored metrics
- Similar-case scoring explainability
- Recommendation dedupe/ranking is stable and capped
- Demo command works end-to-end in VS Code

---

## 15) Config (example)

- `bucket_minutes=15`
- `lookback_days=56`
- `similar_cases_lookback=180`
- `min_similarity_score=35`
- `case_action_similarity_threshold=60`
- `half_life_days=60`
- `forecast_horizons=[1,6,24]`
- `max_proposals=6`
- `max_actions=15`

---

If you want the next artifact, tell me whether you want this spec turned into:

1. a **single `README.md`** + folder layout + interface stubs, or
2. a **Python package skeleton** (async pipeline, connectors, report renderer, CLI) that your Copilot agent can execute step-by-step.

Below is a clean, enterprise-grade **action system** you can drop into the triage agent: **taxonomy (intent), gating rules, dedupe keys, ranking**, and **how templates + case-derived + contextual actions merge** into the “Proposals” at the top of the report.

---

## 1) Action taxonomy (enterprise “intent” categories)

Every recommended action must have an **intent**. This is what prevents redundancy and enables deterministic ranking.

**Core intents (SOC triage)**

- `validate` — confirm/deny the signal with specific evidence
- `scope` — find blast radius (hosts/users/segments)
- `contain` — stop spread / isolate / block
- `eradicate` — remove persistence / kill processes / remediate
- `recover` — restore normal ops, re-enable accounts, etc.
- `tune` — suppress false positives / update detection logic
- `patch` — remediate CVE exposure
- `notify` — comms/hand-off to IR/IT/NetOps/Owner
- `collect` — acquire artifacts (triage package, logs, memory, pcap)
- `monitor` — watchlist / heightened monitoring / additional detections
- `document` — case notes, evidence links, final narrative

**Rule**: Top-of-report “proposals” should mostly be `validate/scope/contain/notify` depending on TP/FP leaning.

---

## 2) Action model fields (what each action must include)

Minimum fields to make actions enterprise-grade and auditable:

- `intent` (one of above)
- `priority` (P1/P2/P3)
- `owner_team` (SOC / IR / IT / NetOps / IAM / AppSec / Vulnerability Mgmt)
- `tool` (SIEM / EDR / SOAR / Firewall / IAM / Scanner)
- `description` (one sentence, imperative, parameterized)
- `rationale` (1 line only; don’t repeat evidence)
- `gating` metadata (why it’s applicable)
- `source` (`template`, `case_learned`, `generated`)
- `dedupe_key` (computed)

---

## 3) Gating rules (when actions are allowed to appear)

This is where enterprise-grade discipline comes from.

### A) Disposition gating

- If **TP Likelihood ≥ 0.75**:

  - allow `contain`, `notify(IR)`, `collect`, `scope`

- If **0.35 ≤ TP Likelihood < 0.75**:

  - allow `validate`, `scope`, `collect`, limited `contain` only if low-risk (e.g., block indicator at proxy if policy allows)

- If **TP Likelihood < 0.35**:

  - prefer `validate`, `tune`, `document`; restrict `contain` to **reversible** steps or “request approval”

### B) Signal-type gating

- `SIEM_ALERT`:

  - always allow `validate`, `scope`, `collect`

- `TI_INDICATOR`:

  - always allow `scope` + `monitor`; allow `contain` only if TI reputation is suspicious/malicious or local sightings exist

- `VULNERABILITY_ALERT / CVE-led`:

  - always allow `patch`, `scope(exposure)`, `monitor(exploit telemetry)`

- `USER_REPORTED`:

  - always allow `collect` + `validate`; contain only after corroboration

### C) Data-availability gating

If you don’t have:

- `hostname` → don’t propose “isolate host”
- `username` → don’t propose “disable user”
- `indicator` → don’t propose “block IOC”
- `CVE` or vuln exposure data → don’t propose “patch CVE X”

### D) Risk gating for containment

Containment proposals must be labeled:

- **low-risk reversible** (safe at triage)
- **requires approval** (IR / system owner)

---

## 4) Dedupe strategy (non-redundant output)

### A) Canonical dedupe key

Dedupe should not be “exact string match.” Use normalized intent + target + tool + owner.

**dedupe_key =**

```
(intent) + "|" + (tool) + "|" + (owner_team) + "|" + (normalized_target_signature)
```

Where `normalized_target_signature` is computed from the action’s target:

- host actions → `host:<hostname>`
- user actions → `user:<username>`
- IOC actions → `ioc:<type>=<value>`
- CVE actions → `cve:<CVE-ID>`
- rule actions → `rule:<rule_id or normalized_rule_name>`

### B) Merge preference order

If duplicates exist:

1. keep **generated** (most specific) over template (generic)
2. keep template over case-learned (unless case-learned is more specific AND recent AND successful)
3. keep the one with:

   - higher priority
   - higher confidence gating
   - more explicit tool instructions

---

## 5) Ranking rules (enterprise ordering)

You want the top “proposals” to read like what a strong Tier-2 would do.

### A) Priority ordering by disposition

**If TP-leaning (≥0.75)**

1. `contain` (reversible) OR `notify(IR)` if containment requires approval
2. `scope`
3. `collect`
4. `monitor`
5. `document`

**If ambiguous**

1. `validate`
2. `collect`
3. `scope`
4. `monitor`
5. `notify` (conditional)

**If FP-leaning (<0.35)**

1. `validate` (prove benign)
2. `tune`
3. `document`
4. `monitor` (optional)

### B) ETS trend boost (optional but controlled)

If ETS shows **spike** AND backtest reliability is acceptable:

- boost `scope` and `monitor` actions earlier
- do **not** auto-boost `contain` unless corroborated by TI/local sightings

Reliability gate example:

- only treat ETS as decision-support if `backtest.MASE(H6 or H24) <= 1.2` OR `coverage95 within 0.85–0.98`

---

## 6) Templates vs case-learned vs generated (how to use each)

### Templates (runbook backbone)

Templates define:

- minimum triage steps per signal subtype
- compliance steps (ticketing, evidence, escalation thresholds)

Templates MUST be parameterized:

- “Run SIEM saved search `IOC_SCOPE_DNS_PROXY` for `{ioc}`”
- “Collect EDR triage package from `{host}` (process tree + netconns)”

### Case-learned actions (local best practice)

Case-derived actions are eligible only if:

- similarity score ≥ threshold (e.g., 60)
- case disposition matches current path (TP actions from TP cases, tune actions from FP cases)
- time-decayed weight is good (recent cases)

Case actions should be rewritten into normalized intents and targets, not pasted raw.

### Generated actions (fill in the gaps)

Generated actions are:

- context-specific queries to answer the unknowns
- routing actions based on owners/criticality
- CVE exposure validation actions based on asset posture

Generated is what makes it feel “agentic” and not generic.

---

## 7) Code stubs (drop-in core functions)

### Action dataclass + normalization + dedupe key

```python
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class RecommendedAction:
    intent: str                 # validate/scope/contain/patch/tune/...
    priority: int               # 1..n
    owner_team: str
    tool: str
    description: str
    rationale: str = ""
    source: str = "template"    # template | case_learned | generated
    requires_approval: bool = False
    target: Optional[Dict[str, str]] = None  # {"type":"host","value":"WS-123"} etc.

    def dedupe_key(self) -> str:
        t = (self.target or {})
        target_sig = f"{t.get('type','na')}:{(t.get('value','na') or '').lower()}"
        return f"{self.intent}|{self.tool}|{self.owner_team}|{target_sig}"
```

### Template action selection (parameterized, gated)

```python
def template_actions(ctx, classification) -> list[RecommendedAction]:
    st = ctx["signal_type"]
    subtype = ctx.get("signal_subtype") or ""
    actions: list[RecommendedAction] = []

    # Always: baseline validation
    actions.append(RecommendedAction(
        intent="validate", priority=2, owner_team="SOC", tool="SIEM",
        description="Validate the signal by confirming the triggering condition and reviewing supporting events.",
        rationale="Baseline triage step.",
        source="template",
        target={"type":"rule","value": ctx.get("alert_rule") or ctx.get("signal_name") or "na"}
    ))

    if st == "SIEM_ALERT":
        if ctx.get("hostname"):
            actions.append(RecommendedAction(
                intent="collect", priority=3, owner_team="SOC", tool="EDR",
                description=f"Collect endpoint triage artifacts from host {ctx['hostname']} (process tree, netconns, recent binaries).",
                rationale="Supports rapid confirmation and scoping.",
                source="template",
                target={"type":"host","value": ctx["hostname"]}
            ))
        actions.append(RecommendedAction(
            intent="scope", priority=4, owner_team="SOC", tool="SIEM",
            description="Scope for additional matches across environment (same rule + related artifacts) in last 24h/7d.",
            rationale="Determine spread and persistence.",
            source="template",
            target={"type":"rule","value": ctx.get("alert_rule") or "na"}
        ))

    if st == "TI_INDICATOR" and ctx.get("indicators"):
        (t, v) = next(iter(ctx["indicators"].items()))
        actions.append(RecommendedAction(
            intent="scope", priority=3, owner_team="SOC", tool="SIEM",
            description=f"Run environment-wide searches for IOC {t}={v} across DNS/Proxy/Firewall/EDR telemetry.",
            rationale="Establish local presence and impacted assets.",
            source="template",
            target={"type":"ioc","value": f"{t}={v}"}
        ))

    if (ctx.get("cves") or []) or st == "VULNERABILITY_ALERT":
        cves = ctx.get("cves") or []
        cve_txt = ", ".join(cves[:3]) + ("..." if len(cves) > 3 else "")
        actions.append(RecommendedAction(
            intent="patch", priority=3, owner_team="VulnMgmt", tool="Scanner",
            description=f"Validate CVE applicability and prioritize remediation for: {cve_txt}.",
            rationale="Reduce exposure and prevent exploitation.",
            source="template",
            target={"type":"cve","value": cve_txt or "na"}
        ))

    return actions
```

### Case-learned action extraction (eligible + rewritten)

```python
def case_learned_actions(similar_cases, classification) -> list[RecommendedAction]:
    actions: list[RecommendedAction] = []
    tp = classification["tp_likelihood"]

    # Gate: choose case actions aligned with current disposition path
    want_tp_actions = tp >= 0.6

    for sc in similar_cases:
        disp = (sc.get("disposition") or "").upper()
        if want_tp_actions and "FALSE" in disp:
            continue
        if (not want_tp_actions) and "TRUE" in disp:
            # still allow tuning actions if present, but not containment
            pass

        for a in sc.get("actions_taken") or []:
            intent = infer_intent_from_action(a)
            if not want_tp_actions and intent in ("contain", "eradicate", "recover"):
                continue

            actions.append(RecommendedAction(
                intent=intent,
                priority=8, owner_team=infer_owner(intent),
                tool=infer_tool(intent),
                description=a.strip(),
                rationale="Observed in similar historical cases (local precedent).",
                source="case_learned",
                target=None
            ))

    return actions
```

### Generated actions (context-driven, specific)

```python
def generated_actions(ctx, enrich, classification, forecast) -> list[RecommendedAction]:
    actions: list[RecommendedAction] = []

    # Containment gating
    tp = classification["tp_likelihood"]
    ti_has_mal = enrich.get("ti_summary", "").lower().find("malicious") >= 0
    local_total = sum(int(x.get("count",0) or 0) for x in (enrich.get("local_sightings") or []))

    if tp >= 0.75 and ctx.get("hostname"):
        actions.append(RecommendedAction(
            intent="contain", priority=1, owner_team="SOC/IR", tool="EDR",
            description=f"Isolate host {ctx['hostname']} (requires approval if production-critical).",
            rationale="High TP likelihood; reduce risk of spread.",
            source="generated",
            requires_approval=True,
            target={"type":"host","value": ctx["hostname"]}
        ))

    # IOC block (only if malicious or seen locally)
    if ctx.get("indicators"):
        (t, v) = next(iter(ctx["indicators"].items()))
        if ti_has_mal or local_total > 0:
            actions.append(RecommendedAction(
                intent="contain", priority=2, owner_team="NetOps", tool="Firewall/Proxy",
                description=f"Block IOC {t}={v} at appropriate control points (proxy/DNS/firewall) per policy.",
                rationale="Reduce continued contact with known-bad infrastructure.",
                source="generated",
                requires_approval=False,
                target={"type":"ioc","value": f"{t}={v}"}
            ))

    # ETS spike -> boost scoping/monitoring if reliable
    if forecast.get("reliable_spike"):
        actions.append(RecommendedAction(
            intent="scope", priority=4, owner_team="SOC", tool="SIEM",
            description="Run expanded scoping queries due to elevated trend (campaign suspicion).",
            rationale="ETS indicates elevated activity above baseline with reliable backtest.",
            source="generated",
            target={"type":"metric","value":"trend_spike"}
        ))
        actions.append(RecommendedAction(
            intent="monitor", priority=6, owner_team="SOC", tool="SIEM/SOAR",
            description="Add temporary watchlist/monitoring for related artifacts for next 24h.",
            rationale="Early warning for spread/persistence.",
            source="generated",
            target={"type":"metric","value":"trend_spike"}
        ))

    return actions
```

### Merge + dedupe + rank (the core)

```python
def merge_dedupe_rank(*, template, generated, case_learned, classification) -> list[RecommendedAction]:
    # Source preference: generated > template > case_learned
    source_rank = {"generated": 3, "template": 2, "case_learned": 1}

    all_actions = generated + template + case_learned

    # Normalize priorities by intent/disposition if needed (optional)
    # ... (keep simple for demo)

    # Dedupe
    best_by_key: dict[str, RecommendedAction] = {}
    for a in all_actions:
        k = a.dedupe_key()
        if k not in best_by_key:
            best_by_key[k] = a
        else:
            cur = best_by_key[k]
            # keep higher source rank, then lower priority number (higher urgency), then longer specificity
            if source_rank.get(a.source, 0) > source_rank.get(cur.source, 0):
                best_by_key[k] = a
            elif a.priority < cur.priority:
                best_by_key[k] = a
            elif len(a.description) > len(cur.description) + 20:
                best_by_key[k] = a

    deduped = list(best_by_key.values())

    # Rank: by priority, then intent ordering based on disposition
    tp = classification["tp_likelihood"]
    if tp >= 0.75:
        intent_order = {"contain": 0, "notify": 1, "scope": 2, "collect": 3, "monitor": 4, "document": 5, "tune": 6, "patch": 3, "validate": 2}
    elif tp <= 0.35:
        intent_order = {"validate": 0, "tune": 1, "document": 2, "monitor": 3, "scope": 4, "collect": 4, "contain": 9, "notify": 5, "patch": 2}
    else:
        intent_order = {"validate": 0, "collect": 1, "scope": 2, "monitor": 3, "notify": 4, "contain": 6, "tune": 5, "patch": 2, "document": 6}

    deduped.sort(key=lambda a: (a.priority, intent_order.get(a.intent, 50), a.owner_team, a.tool))
    return deduped
```

### Intent/owner/tool inference (case-learned normalization)

```python
def infer_intent_from_action(text: str) -> str:
    t = text.lower()
    if any(x in t for x in ["isolate", "contain", "block", "disable account", "quarantine"]):
        return "contain"
    if any(x in t for x in ["scope", "search", "hunt", "look for", "query"]):
        return "scope"
    if any(x in t for x in ["collect", "acquire", "triage package", "pcap", "memory"]):
        return "collect"
    if any(x in t for x in ["patch", "remediate", "upgrade", "apply update"]):
        return "patch"
    if any(x in t for x in ["tune", "suppress", "whitelist", "update rule"]):
        return "tune"
    if any(x in t for x in ["notify", "escalate", "engage", "handoff"]):
        return "notify"
    if any(x in t for x in ["validate", "confirm", "verify"]):
        return "validate"
    return "document"

def infer_owner(intent: str) -> str:
    return {
        "contain": "SOC/IR",
        "scope": "SOC",
        "collect": "SOC",
        "patch": "VulnMgmt",
        "tune": "Detection Engineering",
        "notify": "SOC",
        "monitor": "SOC",
        "validate": "SOC",
        "document": "SOC",
    }.get(intent, "SOC")

def infer_tool(intent: str) -> str:
    return {
        "contain": "EDR/Firewall",
        "scope": "SIEM",
        "collect": "EDR",
        "patch": "Scanner",
        "tune": "SIEM",
        "notify": "SOAR",
        "monitor": "SIEM/SOAR",
        "validate": "SIEM",
        "document": "SOAR",
    }.get(intent, "SIEM")
```

---

## 8) What to put at the top of the report (“Proposals”)

In the report template, “Immediate Next Steps / Proposals” should be:

- the top **3–6 actions** after merge/dedupe/rank
- with **owner + tool** baked into the sentence or adjacent columns

Example top proposals output (what the agent writes):

- “P1 (SOC/IR, EDR): Isolate host WS-123 (approval required if production-critical).”
- “P1 (SOC, SIEM): Validate detection triggers and review correlated events for the last 24h.”
- “P2 (SOC, SIEM): Scope for IOC domain=evil.example across DNS/Proxy/EDR; enumerate impacted hosts/users.”

That reads like a SOC analyst and meets enterprise expectations.

---

If you want, next I can output a single `recommend_actions_async()` function (async) that:

- calls templates + case-extraction + generation
- runs merge/dedupe/rank
- returns `(proposals, full_action_plan)` so your report can show tight proposals up top and a richer plan below.

Both — and if you want this to be enterprise-grade, it **has to be both**, but with strict rules so you don’t end up with a noisy, repetitive “kitchen sink” action list.

## Where recommended actions come from

### 1) Templates (runbooks / playbooks) — the backbone

These are the **default, repeatable steps** that should fire **based on signal type + subtype + incident type**.

- Pros: consistent, auditable, aligned to policy
- Cons: can be generic if not parameterized (host/user/IOC/CVE-specific)

**Enterprise rule:** templates must be **parameterized** (fill in IOC/host/user/CVE) and have **gating conditions** (only show if applicable).

---

### 2) Similar-case learned actions — the “what worked here before”

Pull from similar cases, but **not blindly**. Use them as “local best practice”:

- Pros: reflects your environment, your tooling, your past outcomes, your stakeholders’ preferences
- Cons: can copy bad habits, or irrelevant actions if similarity is weak

**Enterprise rule:** case-derived actions must be:

- **eligible** (case similarity score above threshold)
- **successful** (prefer cases closed TP for containment actions; closed FP for tuning actions)
- **recent** (time decay)
- **deduped** against templates

---

### 3) Contextual generation — fills the gaps

This is where you add actions that are _neither_ pure runbook steps _nor_ lifted from cases, like:

- “Pull EDR triage package from HOST=X”
- “Query SIEM for IOC=Y across DNS+Proxy+EDR”
- “Check exposure for CVE=Z across internet-facing assets”
- “Open/change-ticket to patch group / firewall team”

**Enterprise rule:** generated actions must be **bounded** and **mapped to owners** and **tooling** (SOC vs IR vs IT vs NetOps).

---

## What should show at the top of the report

The “proposals” at the top should be **3–6 items max**, and they must be:

1. **Decision-linked** (TP/FP/Review changes what you propose)
2. **Ordered** by priority + time-to-value
3. **Owner-tagged**
4. **Executable** (“do X in system Y”), not vague

Example structure:

- **P1**: Contain / protect (if high TP)
- **P1**: Validate with specific evidence
- **P2**: Scope expansion query
- **P2**: Notify/route to owner team
- **P3**: Hardening/tuning follow-ups (only if relevant)

---

## The enterprise-grade merge algorithm (how you combine both)

### Step A — Start with templates (playbook core)

Select template actions based on:

- signal.type (SIEM_ALERT / IOC / CVE / HUNT / USER)
- signal_subtype (auth / endpoint exec / DNS / email / vuln)
- incident_type + MITRE (optional)
- severity threshold

### Step B — Inject context actions (make them specific)

Examples:

- Replace `{HOST}` `{USER}` `{IOC}` `{CVE}` placeholders
- Add the exact SIEM query name / saved search reference
- Add which data sources to check (DNS/proxy/EDR/firewall)

### Step C — Pull “learned actions” from similar cases

- Only from cases with similarity score ≥ X (ex: 60)
- Prefer cases with **same disposition** path:

  - If current is TP-leaning → actions from TP cases
  - If FP-leaning → actions from FP cases (tuning/whitelisting/logic fixes)

### Step D — Dedupe + rank + cap

Dedupe by:

- normalized action text
- action “intent” (containment / scoping / evidence / tuning / comms)
- same owner + same tool

Rank by:

- priority class (P1/P2/P3)
- confidence gate (don’t recommend containment as P1 if confidence is Low)
- recency + success rate of case-derived actions

Cap:

- Top section: **max 6**
- Full action plan: **max 12–15**

---

## How this maps to your code (clean mental model)

You want `recommend()` to return actions from three sources:

- `template_actions = get_template_actions(ctx, classification)`
- `context_actions = generate_context_actions(ctx, enrich, classification)`
- `case_actions = extract_case_actions(similar_cases, ctx, classification)`

Then:

- `merged = merge_and_rank(template_actions, context_actions, case_actions)`
- `top_proposals = merged[:6]`

---

## Minimal async stub showing the “both” design

```python
async def recommend(self, ctx, enrich, classification, similar_cases, forecast):
    template_actions = self._template_actions(ctx, classification)
    context_actions  = self._context_actions(ctx, enrich, classification)
    case_actions     = self._case_actions(similar_cases, ctx, classification)

    merged = self._merge_dedupe_rank(
        template_actions=template_actions,
        context_actions=context_actions,
        case_actions=case_actions,
        classification=classification,
        forecast=forecast,
    )

    # keep proposals tight; rest goes into Action Plan table
    return merged[:12]


def _template_actions(self, ctx, classification):
    # Runbook-backed steps (parameterized, gated)
    # returns list[RecommendedAction]
    ...

def _context_actions(self, ctx, enrich, classification):
    # Adds specific “do X in tool Y for entity Z” actions.
    ...

def _case_actions(self, similar_cases, ctx, classification):
    # Extract actions from cases above similarity threshold
    # apply disposition gating + recency bias
    ...

def _merge_dedupe_rank(self, template_actions, context_actions, case_actions, classification, forecast):
    # dedupe by (intent, owner, normalized_text) and rank by priority logic
    ...
```

---

## Pushback you should adopt for stakeholders

If they want “enterprise-grade,” don’t let the agent “just copy actions from prior cases.” That turns into:

- institutionalizing mistakes
- re-running irrelevant containment
- inconsistent outcomes

The correct story is:

- **Templates** ensure compliance and consistency
- **Similar cases** adapt to your environment
- **Context generation** makes it immediately actionable

If you want, I’ll output the concrete action taxonomy + dedupe keys (intent categories + normalization rules), so your top “proposals” are consistently sharp and non-redundant.

````jinja
{# ============================================================================
SOC TRIAGE REPORT (Enterprise Template)
- Purpose: Triage packet for SOC analysts + minimal stakeholder clarity.
- Goals: (1) classify TP/FP/Needs Review, (2) summarize supporting evidence,
         (3) recommend actions, (4) include calibrated ETS multi-horizon trend context.
- Non-redundancy rule: each section answers a distinct question; avoid repeating facts.
- This template assumes a normalized triage object `r` (report model) passed in.
============================================================================ #}

{# ---------------------------------------------------------------------------
Expected `r` shape (high-level)
r.meta:   { generated_utc, triage_owner, tool_version, env, report_id }
r.signal: { id, type, source, name, category, timestamp_utc, raw }
r.ctx:    { username, hostname, src_ip, dst_ip, indicators:dict, cves:list,
            alert_rule, alert_vendor, signal_subtype, entity_focus: {primary, secondary:list} }
r.enrich: { correlation_summary, related_events:list, local_sightings:list,
            threat_intel:dict[value->ti_record],
            asset_context:{host,user,cloud,app}, host_vulns:list, env_exposure:dict,
            scope:{impacted_hosts, impacted_users, impacted_segments, spread_assessment},
            notes:{data_gaps:list, assumptions:list} }
r.forecast: {
   enabled: bool,
   bucket_minutes:int,
   seasonality: {mode, season_length_buckets},
   tracks: {
     rule:   ForecastTrack,
     ioc:    ForecastTrack,
     entity: ForecastTrack
   }
}
ForecastTrack: {
  metric_key, metric_name, series_window, history_points,
  horizons: { H1:{...}, H6:{...}, H24:{...} },
  interpretation, confidence,
  backtest: { status, window_days, splits, step_buckets,
              metrics: { H1:{smape,mase,rmse,coverage95}, H6:{...}, H24:{...} },
              thresholds: { H1:{spike_q, drop_q}, H6:{...}, H24:{...} },
              notes:list
  },
  latest: { current_bucket_count, current_vs_expected, ingestion_lag_buckets }
}
r.classification: {
  disposition, tp_likelihood, severity, confidence,
  incident_type, mitre:{tactics:list, techniques:list},
  reasons_tp:list, reasons_fp:list, triage_judgment
}
r.similar_cases: list[ {case_id, created_at_utc, disposition, overlap, actions_taken:list, notes_summary} ]
r.recommendations: list[ {priority, description, owner_team, auto_executable, status, rationale} ]

Optional:
r.exec: { business_process, potential_impact, external_impact, compliance_notes }
---------------------------------------------------------------------------- #}

{# ============================================================================
HEADER
============================================================================ #}
# SOC Triage Report – {{ r.signal.id }}

**Signal Type:** {{ r.signal.type }}
**Signal Source:** {{ r.signal.source }}
**Signal Name:** {{ r.signal.name }}
**Category:** {{ r.signal.category }}
**Signal Time (UTC):** {{ r.signal.timestamp_utc }}
**Generated (UTC):** {{ r.meta.generated_utc }}
**Triage Owner:** {{ r.meta.triage_owner }}
**Tool Version:** {{ r.meta.tool_version }}

{# ============================================================================
DECISION BANNER (single source of truth)
============================================================================ #}
---

## Decision Banner

{# The banner must be the only place where "the answer" is stated. #}
> **Triage Decision:** **{{ r.classification.disposition }}**
> **Severity (if TP):** **{{ r.classification.severity }}**
> **TP Likelihood:** **{{ (r.classification.tp_likelihood * 100) | round(0) }}%**
> **Confidence:** {{ r.classification.confidence }}

**Top Rationale (one-line):**
- {{ (r.classification.reasons_tp[0] if r.classification.reasons_tp else (r.classification.reasons_fp[0] if r.classification.reasons_fp else "N/A")) }}

{# Immediate next steps should not restate the decision; they should be action-oriented. #}
**Immediate Next Steps (P1/P2)**
1. {{ r.recommendations[0].description if r.recommendations and r.recommendations|length > 0 else "N/A" }}
2. {{ r.recommendations[1].description if r.recommendations and r.recommendations|length > 1 else "N/A" }}

{# ============================================================================
1) SUMMARY (answers: what is it + why it matters in plain language)
============================================================================ #}
---

## 1. Summary (SOC + Stakeholders)

{# Keep this short; avoid duplicating indicator lists or tables. #}
> {{ r.signal.name }} ({{ r.signal.type }}) triaged as **{{ r.classification.severity }}** with **{{ (r.classification.tp_likelihood * 100) | round(0) }}%** TP likelihood; spread={{ r.enrich.scope.spread_assessment }}.

- **What we started with:** {{ r.signal.type }} from {{ r.signal.source }}.
- **What correlation showed:** {{ r.enrich.correlation_summary if r.enrich.correlation_summary else "No additional correlation available." }}
- **Why it matters if true:** Potential compromise / malicious activity; impact depends on asset criticality and scope.
- **Current stance:** {{ r.classification.disposition }}.

{# ============================================================================
2) ACTION PLAN (answers: what to do next)
============================================================================ #}
---

## 2. Action Plan (SOC Runbook-Oriented)

{# Avoid duplicating rationale here; keep it operational. #}
| # | Action | Priority | Owner/Team | Auto-Executable | Status |
|---|--------|----------|------------|-----------------|--------|
{%- if r.recommendations and r.recommendations|length > 0 -%}
{%- for a in r.recommendations -%}
| {{ loop.index }} | {{ a.description }} | P{{ a.priority }} | {{ a.owner_team }} | {{ "Yes" if a.auto_executable else "No" }} | {{ a.status if a.status else "Open" }} |
{%- endfor -%}
{%- else -%}
| 1 | N/A | P- | SOC | No | Open |
{%- endif -%}

{# Optional: brief branching guidance (don’t restate evidence). #}
**Branch Guidance**
- **If TRUE POSITIVE:** contain + scope + escalate per runbook for {{ r.classification.incident_type }}.
- **If FALSE POSITIVE:** document justification and propose tuning/suppression with evidence.

{# ============================================================================
3) NORMALIZATION (answers: what entities/IOCs/CVEs we extracted)
============================================================================ #}
---

## 3. Normalized Signal Context

{# This section is the canonical place for entities/indicators/cves. Don’t repeat elsewhere. #}

### 3.1 Signal Subtype / Focus
- **Signal subtype (if derived):** {{ r.ctx.signal_subtype if r.ctx.signal_subtype else "N/A" }}
- **Primary entity focus:** {{ r.ctx.entity_focus.primary if r.ctx.entity_focus and r.ctx.entity_focus.primary else "N/A" }}
- **Secondary entity focus:**
  {%- if r.ctx.entity_focus and r.ctx.entity_focus.secondary and r.ctx.entity_focus.secondary|length > 0 -%}
  {{ r.ctx.entity_focus.secondary | join(", ") }}
  {%- else -%}
  N/A
  {%- endif -%}

{# Signal-type handling notes: show only what’s relevant; do not fabricate values. #}
### 3.2 Entities (if available)
- **User:** {{ r.ctx.username if r.ctx.username else "N/A" }}
- **Host:** {{ r.ctx.hostname if r.ctx.hostname else "N/A" }}
- **Src IP:** {{ r.ctx.src_ip if r.ctx.src_ip else "N/A" }}
- **Dst IP:** {{ r.ctx.dst_ip if r.ctx.dst_ip else "N/A" }}
- **Alert rule/vendor (if SIEM alert-led):**
  {%- if r.signal.type == "SIEM_ALERT" -%}
  {{ (r.ctx.alert_rule if r.ctx.alert_rule else "N/A") ~ " / " ~ (r.ctx.alert_vendor if r.ctx.alert_vendor else "N/A") }}
  {%- else -%}
  N/A
  {%- endif -%}

### 3.3 Indicators (All Types Supported)
{# Indicators are arbitrary key/value. #}
{%- if r.ctx.indicators and r.ctx.indicators|length > 0 -%}
| Indicator Type | Value |
|---|---|
{%- for k, v in r.ctx.indicators.items() -%}
| {{ k }} | {{ v }} |
{%- endfor -%}
{%- else -%}
- **Indicators:** none
{%- endif -%}

### 3.4 CVEs (If Provided/Derived)
{%- if r.ctx.cves and r.ctx.cves|length > 0 -%}
- **CVEs:** {{ r.ctx.cves | join(", ") }}
{%- else -%}
- **CVEs:** none
{%- endif -%}

{# ============================================================================
4) CORRELATION (answers: do we see it here? where? scope?)
============================================================================ #}
---

## 4. Correlation & Scope

### 4.1 Local Sightings (Indicator / Signal Correlation)
{# For IOC-led signals, this is the key “is it in our environment?” evidence. #}
| Match Type | Where Seen | Count | Time Window | Notes |
|-----------|-----------:|------:|------------|------|
{%- if r.enrich.local_sightings and r.enrich.local_sightings|length > 0 -%}
{%- for s in r.enrich.local_sightings -%}
| {{ s.match_type if s.match_type else "N/A" }} | {{ s.where_seen if s.where_seen else "N/A" }} | {{ s.count if s.count is not none else 0 }} | {{ s.time_window if s.time_window else "N/A" }} | {{ s.notes if s.notes else "" }} |
{%- endfor -%}
{%- else -%}
| N/A | N/A | 0 | N/A | No local sightings recorded. |
{%- endif -%}

### 4.2 Scope Summary
- **Impacted hosts:** {{ (r.enrich.scope.impacted_hosts|length) if r.enrich.scope and r.enrich.scope.impacted_hosts else 0 }}
- **Impacted users:** {{ (r.enrich.scope.impacted_users|length) if r.enrich.scope and r.enrich.scope.impacted_users else 0 }}
- **Impacted segments/tenants:**
  {%- if r.enrich.scope and r.enrich.scope.impacted_segments and r.enrich.scope.impacted_segments|length > 0 -%}
  {{ r.enrich.scope.impacted_segments | join(", ") }}
  {%- else -%}
  N/A
  {%- endif -%}
- **Spread assessment:** {{ r.enrich.scope.spread_assessment if r.enrich.scope and r.enrich.scope.spread_assessment else "N/A" }}

{# ============================================================================
5) THREAT INTEL (answers: what does intel say about indicators?)
============================================================================ #}
---

## 5. Threat Intelligence Enrichment

{# Show only as table + one-line rollup to avoid redundancy. #}
| Indicator | Type | Reputation | Confidence | Source(s) | Notes |
|----------|------|------------|------------|----------|------|
{%- if r.enrich.threat_intel and r.enrich.threat_intel|length > 0 -%}
{%- for indicator, ti in r.enrich.threat_intel.items() -%}
| {{ indicator }} | {{ ti.type if ti.type else "N/A" }} | {{ ti.reputation if ti.reputation else "unknown" }} | {{ ti.confidence if ti.confidence else "low" }} | {{ ti.source if ti.source else "N/A" }} | {{ ti.notes if ti.notes else "" }} |
{%- endfor -%}
{%- else -%}
| N/A | N/A | unknown | low | N/A | No TI enrichment available. |
{%- endif -%}

{# Optional: a TI roll-up string precomputed in the pipeline to avoid repeated logic in templates. #}
> **TI Summary:** {{ r.enrich.ti_summary if r.enrich.ti_summary else "N/A" }}

{# ============================================================================
6) EXPOSURE & VULNERABILITY CONTEXT (answers: are we exposed? is it exploitable?)
============================================================================ #}
---

## 6. Exposure & Vulnerability Context

{# This section is always present. The data shown depends on signal type / availability. #}

### 6.1 Asset Context (If Available)
{%- set host_ctx = (r.enrich.asset_context.host if r.enrich.asset_context and r.enrich.asset_context.host else {}) -%}
{%- set user_ctx = (r.enrich.asset_context.user if r.enrich.asset_context and r.enrich.asset_context.user else {}) -%}

- **Host criticality:** {{ host_ctx.criticality if host_ctx.criticality else "N/A" }}
- **Business unit / owner:** {{ (host_ctx.business_unit if host_ctx.business_unit else "N/A") ~ " / " ~ (host_ctx.owner if host_ctx.owner else "N/A") }}
- **Network segment:** {{ host_ctx.segment if host_ctx.segment else "N/A" }}
- **User role/department:** {{ (user_ctx.role if user_ctx.role else "N/A") ~ " / " ~ (user_ctx.department if user_ctx.department else "N/A") }}

### 6.2 Host-Level Vulnerabilities (If Host Scope Exists)
| Host/Asset | CVE/Finding | Severity | Exploited in Wild? | Notes |
|-----------|-------------|----------|--------------------|------|
{%- if r.ctx.hostname and r.enrich.host_vulns and r.enrich.host_vulns|length > 0 -%}
{%- for v in r.enrich.host_vulns -%}
| {{ v.asset if v.asset else r.ctx.hostname }} | {{ v.cve if v.cve else "N/A" }} | {{ v.severity if v.severity else "N/A" }} | {{ "Yes" if v.exploited_in_the_wild else "No" }} | {{ v.notes if v.notes else "" }} |
{%- endfor -%}
{%- elif r.ctx.hostname -%}
| {{ r.ctx.hostname }} | N/A | N/A | No | No host vuln findings available. |
{%- else -%}
| N/A | N/A | N/A | N/A | No host scope available for host-level exposure. |
{%- endif -%}

### 6.3 Environment Exposure (If CVE-Led or Host Unknown)
{# For CVE-led signals, this is critical. For others, it's still informative when CVEs present. #}
{%- set env = (r.enrich.env_exposure if r.enrich.env_exposure else {}) -%}
- **Vulnerable assets count:** {{ env.vulnerable_assets_count if env.vulnerable_assets_count is not none else "N/A" }}
- **Highest severity exposure:** {{ env.highest_exposure_severity if env.highest_exposure_severity else "N/A" }}
- **Known exploited exposure present?:**
  {%- if env.known_exploited_exposure is boolean -%}
  {{ "Yes" if env.known_exploited_exposure else "No" }}
  {%- else -%}
  N/A
  {%- endif -%}
- **Exposure summary:** {{ env.summary if env.summary else "N/A" }}
{%- if env.sample_assets and env.sample_assets|length > 0 -%}
- **Sample affected assets:** {{ env.sample_assets | join(", ") }}
{%- endif -%}

{# ============================================================================
7) ETS TREND & FORECAST (answers: is this rising? what’s expected next?)
============================================================================ #}
---

## 7. Trend & Forecast (ETS, Multi-Horizon)

{# This section must explicitly state reliability (backtest) and not overstate results. #}
{%- if r.forecast and r.forecast.enabled -%}
- **Bucket size:** {{ r.forecast.bucket_minutes }} minutes
- **Seasonality mode:** {{ r.forecast.seasonality.mode if r.forecast.seasonality and r.forecast.seasonality.mode else "auto/none" }}
- **Season length (buckets):** {{ r.forecast.seasonality.season_length_buckets if r.forecast.seasonality and r.forecast.seasonality.season_length_buckets else "N/A" }}

{# -------- RULE TRACK -------- #}
### 7.1 Rule / Detection Track
{%- set t = r.forecast.tracks.rule -%}
{%- if t and t.metric_key -%}
- **Metric:** {{ t.metric_name }}
- **History window:** {{ t.series_window }} (points={{ t.history_points }})
- **Current vs Expected:** {{ t.latest.current_vs_expected if t.latest else "N/A" }}
- **Forecast totals:** H1={{ t.horizons.H1.total if t.horizons and t.horizons.H1 else "N/A" }}, H6={{ t.horizons.H6.total if t.horizons and t.horizons.H6 else "N/A" }}, H24={{ t.horizons.H24.total if t.horizons and t.horizons.H24 else "N/A" }}
- **Interpretation:** {{ t.interpretation }}
- **Confidence:** {{ t.confidence }}

#### 7.1.a Backtest (Rule Track)
{%- if t.backtest and t.backtest.status == "ok" -%}
- **Backtest window:** {{ t.backtest.window_days }}d, splits={{ t.backtest.splits }}, step={{ t.backtest.step_buckets }} bucket(s)
- **H1 metrics:** sMAPE={{ t.backtest.metrics.H1.smape }}, MASE={{ t.backtest.metrics.H1.mase }}, RMSE={{ t.backtest.metrics.H1.rmse }}, Coverage95={{ t.backtest.metrics.H1.coverage95 }}
- **H6 metrics:** sMAPE={{ t.backtest.metrics.H6.smape }}, MASE={{ t.backtest.metrics.H6.mase }}, RMSE={{ t.backtest.metrics.H6.rmse }}, Coverage95={{ t.backtest.metrics.H6.coverage95 }}
- **H24 metrics:** sMAPE={{ t.backtest.metrics.H24.smape }}, MASE={{ t.backtest.metrics.H24.mase }}, RMSE={{ t.backtest.metrics.H24.rmse }}, Coverage95={{ t.backtest.metrics.H24.coverage95 }}
- **Spike threshold (quantile):** H1={{ t.backtest.thresholds.H1.spike_q }}, H6={{ t.backtest.thresholds.H6.spike_q }}, H24={{ t.backtest.thresholds.H24.spike_q }}
{%- if t.backtest.notes and t.backtest.notes|length > 0 -%}
- **Backtest notes:** {{ t.backtest.notes | join(" | ") }}
{%- endif -%}
{%- else -%}
- **Backtest status:** {{ t.backtest.status if t.backtest else "N/A" }}
- **Notes:** Backtest not available or insufficient history; treat this track as informational only.
{%- endif -%}
{%- else -%}
- **Rule track:** Not applicable (no alert rule / metric available).
{%- endif -%}

{# -------- IOC TRACK -------- #}
### 7.2 Indicator / IOC Track
{%- set t = r.forecast.tracks.ioc -%}
{%- if t and t.metric_key -%}
- **Metric:** {{ t.metric_name }}
- **History window:** {{ t.series_window }} (points={{ t.history_points }})
- **Current vs Expected:** {{ t.latest.current_vs_expected if t.latest else "N/A" }}
- **Forecast totals:** H1={{ t.horizons.H1.total if t.horizons and t.horizons.H1 else "N/A" }}, H6={{ t.horizons.H6.total if t.horizons and t.horizons.H6 else "N/A" }}, H24={{ t.horizons.H24.total if t.horizons and t.horizons.H24 else "N/A" }}
- **Interpretation:** {{ t.interpretation }}
- **Confidence:** {{ t.confidence }}

#### 7.2.a Backtest (IOC Track)
{%- if t.backtest and t.backtest.status == "ok" -%}
- **Backtest window:** {{ t.backtest.window_days }}d, splits={{ t.backtest.splits }}, step={{ t.backtest.step_buckets }} bucket(s)
- **H1 metrics:** sMAPE={{ t.backtest.metrics.H1.smape }}, MASE={{ t.backtest.metrics.H1.mase }}, RMSE={{ t.backtest.metrics.H1.rmse }}, Coverage95={{ t.backtest.metrics.H1.coverage95 }}
- **H6 metrics:** sMAPE={{ t.backtest.metrics.H6.smape }}, MASE={{ t.backtest.metrics.H6.mase }}, RMSE={{ t.backtest.metrics.H6.rmse }}, Coverage95={{ t.backtest.metrics.H6.coverage95 }}
- **H24 metrics:** sMAPE={{ t.backtest.metrics.H24.smape }}, MASE={{ t.backtest.metrics.H24.mase }}, RMSE={{ t.backtest.metrics.H24.rmse }}, Coverage95={{ t.backtest.metrics.H24.coverage95 }}
- **Spike threshold (quantile):** H1={{ t.backtest.thresholds.H1.spike_q }}, H6={{ t.backtest.thresholds.H6.spike_q }}, H24={{ t.backtest.thresholds.H24.spike_q }}
{%- else -%}
- **Backtest status:** {{ t.backtest.status if t.backtest else "N/A" }}
- **Notes:** Backtest not available or insufficient history; treat this track as informational only.
{%- endif -%}
{%- else -%}
- **IOC track:** Not applicable (no indicator / metric available).
{%- endif -%}

{# -------- ENTITY TRACK -------- #}
### 7.3 Entity Behavior Track (Dynamic by Signal Type)
{# The pipeline should set r.ctx.entity_focus + select an entity metric accordingly. #}
{%- set t = r.forecast.tracks.entity -%}
{%- if t and t.metric_key -%}
- **Metric:** {{ t.metric_name }}
- **Entity focus:** {{ r.ctx.entity_focus.primary if r.ctx.entity_focus and r.ctx.entity_focus.primary else "N/A" }}
- **History window:** {{ t.series_window }} (points={{ t.history_points }})
- **Current vs Expected:** {{ t.latest.current_vs_expected if t.latest else "N/A" }}
- **Forecast totals:** H1={{ t.horizons.H1.total if t.horizons and t.horizons.H1 else "N/A" }}, H6={{ t.horizons.H6.total if t.horizons and t.horizons.H6 else "N/A" }}, H24={{ t.horizons.H24.total if t.horizons and t.horizons.H24 else "N/A" }}
- **Interpretation:** {{ t.interpretation }}
- **Confidence:** {{ t.confidence }}

#### 7.3.a Backtest (Entity Track)
{%- if t.backtest and t.backtest.status == "ok" -%}
- **Backtest window:** {{ t.backtest.window_days }}d, splits={{ t.backtest.splits }}, step={{ t.backtest.step_buckets }} bucket(s)
- **H1 metrics:** sMAPE={{ t.backtest.metrics.H1.smape }}, MASE={{ t.backtest.metrics.H1.mase }}, RMSE={{ t.backtest.metrics.H1.rmse }}, Coverage95={{ t.backtest.metrics.H1.coverage95 }}
- **H6 metrics:** sMAPE={{ t.backtest.metrics.H6.smape }}, MASE={{ t.backtest.metrics.H6.mase }}, RMSE={{ t.backtest.metrics.H6.rmse }}, Coverage95={{ t.backtest.metrics.H6.coverage95 }}
- **H24 metrics:** sMAPE={{ t.backtest.metrics.H24.smape }}, MASE={{ t.backtest.metrics.H24.mase }}, RMSE={{ t.backtest.metrics.H24.rmse }}, Coverage95={{ t.backtest.metrics.H24.coverage95 }}
- **Spike threshold (quantile):** H1={{ t.backtest.thresholds.H1.spike_q }}, H6={{ t.backtest.thresholds.H6.spike_q }}, H24={{ t.backtest.thresholds.H24.spike_q }}
{%- else -%}
- **Backtest status:** {{ t.backtest.status if t.backtest else "N/A" }}
- **Notes:** Backtest not available or insufficient history; treat this track as informational only.
{%- endif -%}
{%- else -%}
- **Entity track:** Not applicable (no suitable entity metric selected for this signal type).
{%- endif -%}

{%- else -%}
- **Forecasting:** disabled or not supported for this report.
{%- endif -%}

{# ============================================================================
8) EVIDENCE TIMELINE (answers: what happened and when)
============================================================================ #}
---

## 8. Evidence Timeline (Correlated Events)

| Time (UTC) | Source/System | Event Summary | Relevance |
|------------|--------------|--------------|-----------|
{%- if r.enrich.related_events and r.enrich.related_events|length > 0 -%}
{%- for ev in r.enrich.related_events -%}
| {{ ev.timestamp_utc if ev.timestamp_utc else "N/A" }} | {{ ev.source if ev.source else "N/A" }} | {{ ev.summary if ev.summary else "N/A" }} | {{ ev.relevance if ev.relevance else "N/A" }} |
{%- endfor -%}
{%- else -%}
| N/A | N/A | No correlated events available. | N/A |
{%- endif -%}

> **Timeline interpretation:** {{ r.enrich.timeline_interpretation if r.enrich.timeline_interpretation else ("Timeline contains correlated activity; review events above." if r.enrich.related_events and r.enrich.related_events|length > 0 else "No correlated timeline events available.") }}

{# ============================================================================
9) TRIAGE ASSESSMENT (answers: why we decided this)
============================================================================ #}
---

## 9. Triage Assessment

{# No duplication of indicators; just reasoning. #}
- **Disposition:** {{ r.classification.disposition }}
- **TP Likelihood:** {{ (r.classification.tp_likelihood * 100) | round(0) }}%
- **Severity:** {{ r.classification.severity }}
- **Confidence:** {{ r.classification.confidence }}

### 9.1 Drivers Toward TRUE POSITIVE
{%- if r.classification.reasons_tp and r.classification.reasons_tp|length > 0 -%}
{%- for x in r.classification.reasons_tp -%}
- {{ x }}
{%- endfor -%}
{%- else -%}
- No strong TP drivers identified.
{%- endif -%}

### 9.2 Drivers Toward FALSE POSITIVE / Benign
{%- if r.classification.reasons_fp and r.classification.reasons_fp|length > 0 -%}
{%- for x in r.classification.reasons_fp -%}
- {{ x }}
{%- endfor -%}
{%- else -%}
- No strong FP drivers identified.
{%- endif -%}

### 9.3 Incident Typing (MITRE ATT&CK)
- **Proposed incident type:** {{ r.classification.incident_type }}
- **MITRE tactics:** {{ r.classification.mitre.tactics | join(", ") if r.classification.mitre and r.classification.mitre.tactics else "N/A" }}
- **MITRE techniques:** {{ r.classification.mitre.techniques | join(", ") if r.classification.mitre and r.classification.mitre.techniques else "N/A" }}

> **Triage judgment:** {{ r.classification.triage_judgment }}

{# ============================================================================
10) SIMILAR CASES (answers: have we seen this before? what worked?)
============================================================================ #}
---

## 10. Similar Cases (SOAR)

| Case ID | Opened (UTC) | Disposition | Overlap | Key Actions Taken |
|--------|--------------|------------|---------|------------------|
{%- if r.similar_cases and r.similar_cases|length > 0 -%}
{%- for sc in r.similar_cases -%}
| {{ sc.case_id }} | {{ sc.created_at_utc }} | {{ sc.disposition }} | {{ sc.overlap }} | {{ (sc.actions_taken | join("; ")) if sc.actions_taken and sc.actions_taken|length > 0 else "N/A" }} |
{%- endfor -%}
{%- else -%}
| N/A | N/A | N/A | N/A | N/A |
{%- endif -%}

{%- if not r.similar_cases or r.similar_cases|length == 0 -%}
- *No relevant prior cases found in the configured lookback window.*
{%- endif -%}

{# ============================================================================
11) CLOSURE CRITERIA (answers: what would change the decision)
============================================================================ #}
---

## 11. Closure Criteria

**Mark as TRUE POSITIVE if**
- Confirmed malicious activity in correlated telemetry tied to the signal/indicator/CVE.
- Host/user shows compromise indicators **OR** confirmed exploit attempt aligned to CVE telemetry.

**Mark as FALSE POSITIVE / benign if**
- Activity fully explained by authorized change/maintenance (corroborated).
- Detection/IOC/CVE is verified non-applicable or benign in this environment (documented).

**Runbook reference:** {{ r.classification.runbook_ref if r.classification.runbook_ref else "RB-GEN-001 Generic Signal Triage" }}

{# ============================================================================
12) STAKEHOLDER SNAPSHOT (answers: exec-level “so what?” without deep details)
============================================================================ #}
---

## 12. Stakeholder Snapshot (Minimal)

{%- set exec = (r.exec if r.exec else {}) -%}
- **Affected business process:** {{ exec.business_process if exec.business_process else (host_ctx.business_process if host_ctx.business_process else "N/A") }}
- **Potential impact:** {{ exec.potential_impact if exec.potential_impact else "Potential compromise / malicious activity; impact depends on criticality and scope." }}
- **External/customer impact:** {{ exec.external_impact if exec.external_impact else "N/A" }}
- **Compliance notes:** {{ exec.compliance_notes if exec.compliance_notes else (host_ctx.compliance if host_ctx.compliance else "N/A") }}

{# ============================================================================
13) DATA QUALITY / GAPS (answers: what’s missing so we don’t overclaim)
============================================================================ #}
---

## 13. Data Quality & Gaps

{%- if r.enrich.notes and r.enrich.notes.data_gaps and r.enrich.notes.data_gaps|length > 0 -%}
**Data gaps**
{%- for g in r.enrich.notes.data_gaps -%}
- {{ g }}
{%- endfor -%}
{%- else -%}
- No major data gaps recorded.
{%- endif -%}

{%- if r.enrich.notes and r.enrich.notes.assumptions and r.enrich.notes.assumptions|length > 0 -%}
**Assumptions**
{%- for a in r.enrich.notes.assumptions -%}
- {{ a }}
{%- endfor -%}
{%- endif -%}

{# ============================================================================
APPENDIX (raw payload for auditability)
============================================================================ #}
---

## Appendix A. Raw Signal Payload (Audit)

```json
{{ r.signal.raw | tojson(indent=2) }}
````

{# Optional: include only if your pipeline safely redacts sensitive fields. #}
{#

## Appendix B. Internal Correlated Event Samples (Redacted)

```text
{{ r.enrich.related_events_sample }}
```

#}

```

```

You’re thinking about this the right way: **multi-horizon ETS only becomes “enterprise-grade” when you (1) backtest each horizon explicitly, (2) calibrate thresholds from that backtest, and (3) choose the _right entity metric_ per signal type** so the forecast is forecasting something meaningful.

## Enterprise-grade multi-horizon backtesting (H1 / H6 / H24)

### 1) What you must pull from the SIEM

For each “forecastable metric,” pull a **zero-filled, bucketed time series**:

- Bucket: `bucket_minutes` (e.g., 15m)
- History: enough for seasonality + stable scoring

  - daily seasonality: **28–56 days** minimum (15m buckets → 2,688–5,376 points)
  - weekly seasonality: **8–12 weeks** is better if you want day-of-week effects

You will do this for _each_ metric you forecast:

- **Rule series**: count of alert firings for the detection rule / analytic
- **Indicator series**: count of IOC sightings (same indicator) across telemetry
- **Entity series**: count of an entity behavior (depends on signal type; mapping below)

### 2) Rolling-origin backtest (explicit per horizon)

You don’t “backtest ETS once.” You backtest it **per horizon** and **per metric**, using rolling-origin evaluation.

**Core idea**

- Choose a training window `W` (e.g., 28 days)
- Choose a step size `S` (e.g., 1 bucket)
- For each split:

  - fit ETS on train window
  - forecast next `H` buckets (H1, H6, H24)
  - compare forecasted **horizon total** vs actual **horizon total**
  - record errors
  - slide forward by `S`, repeat

**Why horizon totals (not per-step)**
SOC use is “what happens in next hour / 6 hours / day.” So score:

- `sum_forecast[1..H]` vs `sum_actual[1..H]`

### 3) Metrics you should compute (counts-friendly)

For each horizon H:

- **sMAPE** (robust when counts vary): good default
- **MASE** (scale-free): excellent for comparing series with different volumes
- **Pinball loss** (if you generate quantiles/bands): evaluates your uncertainty bands
- **Coverage** (band calibration): % of times actual ∈ [lo, hi] should be close to nominal (e.g., ~95%)

Also track:

- **Intermittency rate** = % of zeros
- **Overdispersion** ≈ variance/mean (helps decide Poisson-ish vs bursty)

### 4) Model selection policy (enterprise-grade)

You should not assume one ETS flavor works everywhere. Pick per metric using backtest:

- Try: **Holt (trend)** and **Holt-Winters (daily seasonality)**, optionally **weekly** if data supports.
- Choose best by weighted score:

  - primary: **MASE(H24)** + **MASE(H6)** + **MASE(H1)** (weighted toward your operational horizon)
  - secondary: calibration (coverage near target)

**Cold-start rule**
If backtest splits < N (e.g., < 200 splits) or history < 14 days:

- mark ETS confidence **Low**
- don’t use ETS as a decision driver, only as “context”

### 5) Threshold calibration from backtest (turn forecast into “spike”)

This is what makes it enterprise-grade.

For each horizon and metric:

- compute residual distribution: `err = actual_total - forecast_total`
- define alerting threshold from quantiles:

  - spike if `actual_total > forecast_total + Q99(err)` (or 3-sigma equivalent)
  - drop if `actual_total < forecast_total - Q01(err)` (optional)

Then in the triage report, “Spike” is not a vibe—it’s statistically grounded.

### 6) Drift and incident-awareness

Production reality: incidents create structural breaks.
Add:

- **drift monitor**: rolling MASE / coverage; if degrading, down-rank ETS confidence
- **blackout / incident labeling**: if you have incident periods, either:

  - exclude from baseline training, or
  - keep but tag as “incident-inflated baseline” (so you don’t normalize badness)

### 7) Practical enterprise constraints (don’t skip)

- **Zero-fill correctness**: SIEM queries must output empty buckets as 0
- **Late-arriving data**: backtest should ignore most recent “incomplete ingestion” window (e.g., last 1–2 buckets)
- **Rate limiting**: cache series and reuse across triage runs; backtest runs scheduled (daily), not per alert

---

## Which entity metric to forecast (depends on signal type)

You don’t always forecast “the host.” You forecast the **entity most likely to represent the _unit of spread or impact_** for that signal.

Here’s a practical mapping you can implement immediately:

### 1) If signal type = **SIEM_ALERT**

**Primary entity** (pick what the detection is _about_):

- Auth alerts → `username`, `source_ip`, `tenant/account`
- Endpoint execution alerts → `hostname`, `process_name`, `parent_process`, `user`
- Network alerts → `src_ip`, `dst_ip`, `hostname`, `subnet/segment`
- Email alerts → `sender`, `recipient`, `message_id`, `domain`

**Entity metric examples to forecast**

- Auth: `failed_logins_per_user`, `distinct_src_ips_per_user`, `impossible_travel_events`
- Endpoint: `suspicious_process_count_per_host`, `powershell_encoded_count_per_host`
- Network: `blocked_connections_per_src_ip`, `dns_queries_to_new_domains_per_host`

### 2) If signal type = **TI_INDICATOR (IOC-led)**

**Primary entity**

- Always the **indicator itself** (ip/domain/hash/url/etc.)
  **Secondary entities**
- impacted hosts/users observed in SIEM matches

**Entity metric to forecast**

- `ioc_sightings_total` (already)
- optional: `distinct_hosts_hitting_ioc`, `distinct_users_exposed`

### 3) If signal type = **VULNERABILITY_ALERT (CVE-led)**

**Primary entity**

- `asset` (host/service/app), `exposure_surface` (internet-facing yes/no), `business service`
  **Secondary entities**
- `vuln_cluster` (all assets sharing CVE), `segment`

**Entity metric to forecast**

- If you have exploit telemetry: `exploitation_signals_for_cve` (WAF hits, IDS sig hits, EDR exploit blocks)
- If not: forecast is less useful; instead use ETS on **scan findings rate** or **new vulnerable assets/day**

### 4) If signal type = **HUNT_FINDING**

**Primary entity**

- whatever the hunt is keyed on: `hostname`, `user`, `process`, `cloud workload`, `namespace`
  **Entity metric to forecast**
- hunt’s “match rate” per entity (e.g., `suspicious_dns_matches_per_host`)

### 5) If signal type = **USER_REPORTED**

**Primary entity**

- `hostname` + `username` (if known); also `application` if complaint is app-specific
  **Entity metric to forecast**
- usually not ETS-first; use ETS as supporting context:

  - `endpoint_alert_volume_for_host`
  - `edr_detections_for_host`
  - `auth_anomalies_for_user`

---

## Recommendation for your triage agent design

Implement **three forecast tracks**, but populate the third dynamically:

1. **Rule forecast** (only when you have a detection rule / analytic name)
2. **Indicator forecast** (only when you have an indicator)
3. **Entity forecast (dynamic)** chosen by the mapping above

And make “Spike” depend on:

- calibrated thresholds from rolling backtest
- backtest confidence gates (don’t over-trust noisy series)

If you want, I can paste just the **async function stubs** you’d add next:

- `async fetch_series(metric_key, lookback_days, bucket_minutes) -> List[int]` with zero-fill + ingestion lag handling
- `backtest_multi_horizon_ets(series, horizons, window, step) -> BacktestSummary`
- `calibrate_thresholds(backtest_summary) -> Thresholds`
- plus how those summaries show up in the report as a non-redundant “ETS Reliability” line.

Below is a **single-flag** design that covers:

1. **One flag for _any_ IOC/indicator type** (ip, domain, url, hash, email, ja3, mutex, registry, etc.)
2. **One flag for _any_ signal type** (IOC-led, SIEM alert-led, CVE-led, hunt finding, user report, etc.)

You’ll use **exactly one flag**: `--signal "<spec>"`

---

## Single flag formats

### A) IOC-led (any indicator type)

```bash
python triage_agent.py --signal "ioc:<type>=<value>"
```

Examples (all are valid):

```bash
python triage_agent.py --signal "ioc:ip=203.0.113.50"
python triage_agent.py --signal "ioc:domain=evil.example"
python triage_agent.py --signal "ioc:url=https://evil.example/a"
python triage_agent.py --signal "ioc:hash=44d88612fea8a8f36de82e1278abb02f"
python triage_agent.py --signal "ioc:email=phish@evil.example"
python triage_agent.py --signal "ioc:ja3=72a589da586844d7f0818ce684948eea"
python triage_agent.py --signal "ioc:mutex=Global\\BadMutex"
python triage_agent.py --signal "ioc:registry=HKCU\\Software\\BadKey"
python triage_agent.py --signal "ioc:process=powershell.exe -enc AAA..."
```

> You’re not limited to a fixed list. **`<type>` is arbitrary** — your pipeline treats it as an indicator type and tries to correlate it in SIEM and enrich it if you implement the TI method for that type.

---

### B) SIEM alert-led (single flag)

**Alert by ID**:

```bash
python triage_agent.py --signal "alert_id:A-1001"
```

**Alert by JSON** (inline):

```bash
python triage_agent.py --signal 'alert_json:{"id":"A-1001","source":"Splunk","name":"Suspicious PowerShell","category":"Malware","hostname":"WS-123","username":"jdoe"}'
```

**Alert from file**:

```bash
python triage_agent.py --signal "alert_file:./sample_alert.json"
```

---

### C) CVE-led triage (single flag)

```bash
python triage_agent.py --signal "cve:CVE-2024-1234"
python triage_agent.py --signal "cve:CVE-2024-1234,CVE-2024-9999"
```

---

### D) Hunt finding / user report (single flag, JSON payload)

```bash
python triage_agent.py --signal 'hunt_json:{"name":"Suspicious DNS pattern","hostname":"WS-9","domain":"weird.example"}'
python triage_agent.py --signal 'user_json:{"reporter":"helpdesk","hostname":"LAP-2","summary":"popups and cpu spike"}'
```

---

## Code: drop-in parsing + builder (single `--signal`)

Paste this into your file and wire it in `main()`.

```python
import json
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, List, Optional

def _split_once(s: str, sep: str) -> Tuple[str, str]:
    if sep not in s:
        raise ValueError(f"Expected '{sep}' in '{s}'")
    a, b = s.split(sep, 1)
    return a.strip(), b.strip()

def _parse_indicator_kv(expr: str) -> Tuple[str, str]:
    # supports type=value (value can include '=' if you escape earlier; here we split once)
    t, v = _split_once(expr, "=")
    if not t or not v:
        raise ValueError(f"Bad indicator format '{expr}' (expected type=value)")
    return t, v

def build_signal_from_signal_flag(flag: str, *, siem) -> "Signal":
    """
    Single flag entrypoint:
      --signal "ioc:ip=1.2.3.4"
      --signal "alert_id:A-1001"
      --signal "alert_json:{...}"
      --signal "alert_file:./x.json"
      --signal "cve:CVE-2024-1234,CVE-2024-9999"
      --signal "hunt_json:{...}"
      --signal "user_json:{...}"
    """
    ts = datetime.now(timezone.utc)

    kind, payload = _split_once(flag, ":")

    # ---------------- IOC-led ----------------
    if kind == "ioc":
        ind_type, value = _parse_indicator_kv(payload)
        raw = {"indicator_type": ind_type, "value": value}
        return Signal(
            id=f"CASE-IOC-{ind_type}-{value}",
            type="TI_INDICATOR",
            source="ThreatIntel",
            name=f"IOC: {ind_type}={value}",
            category="TI-IOC",
            timestamp=ts,
            raw=raw,
        )

    # ---------------- Alert-led ----------------
    if kind == "alert_id":
        # requires SIEM lookup method
        raw = siem.get_alert_by_id(payload)  # implement in SIEMClient
        return Signal(
            id=raw.get("id") or payload,
            type="SIEM_ALERT",
            source=raw.get("source") or "SIEM",
            name=raw.get("name") or "Alert",
            category=raw.get("category") or "Uncategorized",
            timestamp=ts,
            raw=raw,
        )

    if kind == "alert_json":
        raw = json.loads(payload)
        return Signal(
            id=raw.get("id") or "CASE-ALERT",
            type="SIEM_ALERT",
            source=raw.get("source") or "SIEM",
            name=raw.get("name") or "Alert",
            category=raw.get("category") or "Uncategorized",
            timestamp=ts,
            raw=raw,
        )

    if kind == "alert_file":
        with open(payload, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return Signal(
            id=raw.get("id") or "CASE-ALERT",
            type="SIEM_ALERT",
            source=raw.get("source") or "SIEM",
            name=raw.get("name") or "Alert",
            category=raw.get("category") or "Uncategorized",
            timestamp=ts,
            raw=raw,
        )

    # ---------------- CVE-led ----------------
    if kind == "cve":
        # allow comma-separated
        cves = [x.strip() for x in payload.split(",") if x.strip()]
        raw = {"cves": cves}
        return Signal(
            id=f"CASE-CVE-{cves[0]}" if cves else "CASE-CVE",
            type="HUNT_FINDING",
            source="VulnIntel",
            name="CVE Exposure Signal",
            category="Vulnerability",
            timestamp=ts,
            raw=raw,
        )

    # ---------------- Hunt / User reported ----------------
    if kind == "hunt_json":
        raw = json.loads(payload)
        return Signal(
            id=raw.get("id") or "CASE-HUNT",
            type="HUNT_FINDING",
            source=raw.get("source") or "Hunt",
            name=raw.get("name") or "Hunt Finding",
            category=raw.get("category") or "Hunt",
            timestamp=ts,
            raw=raw,
        )

    if kind == "user_json":
        raw = json.loads(payload)
        return Signal(
            id=raw.get("id") or "CASE-USER",
            type="USER_REPORTED",
            source=raw.get("source") or "UserReport",
            name=raw.get("name") or "User Report",
            category=raw.get("category") or "User Report",
            timestamp=ts,
            raw=raw,
        )

    raise ValueError(f"Unsupported --signal kind '{kind}'.")
```

---

## Argparse: literally one flag

Replace your “starting signal” args with this:

```python
p.add_argument("--signal", required=True,
              help='Single flag: '
                   '"ioc:type=value" | "alert_id:ID" | "alert_json:{...}" | "alert_file:path" | '
                   '"cve:CVE-...,CVE-..." | "hunt_json:{...}" | "user_json:{...}"')
```

Then in `main()`:

```python
signal = build_signal_from_signal_flag(args.signal, siem=siem)
report = agent.triage(signal)
print(report.markdown)
```

---

## SIEM lookup method needed for alert_id

Add this to your `SIEMClient` (even as a demo stub):

```python
class SIEMClient:
    def get_alert_by_id(self, alert_id: str) -> Dict[str, Any]:
        return {
            "id": alert_id,
            "source": "Splunk",
            "name": "Suspicious PowerShell",
            "category": "Malware",
            "hostname": "WS-123",
            "username": "jdoe",
            "src_ip": "10.1.2.3",
        }
```

---

If you want this to feel _extra slick_ in your demo, I’d also add aliases so you can do **either**:

- `--signal "ioc:ip=..."` (explicit type)
- `--signal "ip=..."` (auto-assume IOC)

…but the spec above already satisfies: **single flag for all indicator types + single flag for all signal types**.

````python
"""
triage_agent_async.py

Async SOC triage agent supporting MULTIPLE signal types:
- SIEM_ALERT           (alert-led)
- TI_INDICATOR         (IOC-led)
- VULNERABILITY_ALERT  (CVE-led)
- HUNT_FINDING         (internal hunt-led)
- USER_REPORTED        (human report-led)
- OTHER

Key properties:
- Fully async pipeline (async/await)
- External integrations are async stubs (replace with real connectors)
- ETS forecasting included (Holt / Holt-Winters additive), executed via asyncio.to_thread()
  so it doesn't block the event loop.
- Produces a single SOC-ready markdown report (consistent sections).

Note: This file intentionally omits CLI (per your request).
"""

from __future__ import annotations

import asyncio
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from collections import Counter


# =========================================================
# Core Models
# =========================================================

SignalType = str  # keep simple for demo; could be Literal[...] or Enum


@dataclass
class Signal:
    """
    Raw incoming signal. "raw" may contain:
      - SIEM alert payload
      - IOC record (indicator_type/value)
      - CVE list
      - hunt/user report details
    """
    id: str
    type: SignalType                 # SIEM_ALERT / TI_INDICATOR / VULNERABILITY_ALERT / HUNT_FINDING / USER_REPORTED / OTHER
    source: str                      # Splunk / Sentinel / EDR / MISP / Scanner / etc.
    name: str                        # rule name / title
    category: str                    # Malware / TI-IOC / Vulnerability / etc.
    timestamp: datetime
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedContext:
    """
    Unified triage context regardless of starting signal type.
    Downstream steps ONLY use this context + enrichment.
    """
    signal: Signal

    # Entities (may be None depending on signal)
    username: Optional[str] = None
    hostname: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    # Indicators extracted from signal (arbitrary indicator types allowed)
    indicators: Dict[str, str] = field(default_factory=dict)   # {"ip": "...", "domain": "...", "hash": "...", "ja3": "...", ...}

    # CVEs extracted (if any)
    cves: List[str] = field(default_factory=list)

    # Normalized "alert identity" (if alert-led)
    alert_rule: Optional[str] = None
    alert_vendor: Optional[str] = None


@dataclass
class EnrichmentContext:
    """
    All correlation, TI, asset, vuln, and scope data needed for classification + report.
    """

    # Correlated events & sightings
    related_events: List[Dict[str, Any]] = field(default_factory=list)      # raw-ish events
    local_sightings: List[Dict[str, Any]] = field(default_factory=list)     # rolled-up per indicator
    correlation_summary: str = ""

    # Threat intel per indicator value
    threat_intel: Dict[str, Dict[str, Any]] = field(default_factory=dict)   # indicator_value -> TI record

    # Asset context (host/user)
    asset_context: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # {"host": {...}, "user": {...}}

    # Vulnerabilities (host-level) and environment exposure (CVE-led / unknown host)
    host_vulns: List[Dict[str, Any]] = field(default_factory=list)
    env_exposure: Dict[str, Any] = field(default_factory=dict)

    # Scope inference
    impacted_hosts: List[str] = field(default_factory=list)
    impacted_users: List[str] = field(default_factory=list)
    impacted_segments: List[str] = field(default_factory=list)
    spread_assessment: str = "isolated"


@dataclass
class ForecastBlock:
    metric_name: str
    current_vs_expected: str
    h1: str
    h6: str
    h24: str
    interpretation: str
    confidence: str


@dataclass
class TrendForecast:
    rule: ForecastBlock
    ioc: ForecastBlock
    entity: ForecastBlock


@dataclass
class ClassificationResult:
    disposition: str                 # Probable TRUE POSITIVE / Likely FALSE POSITIVE / Requires Analyst Review
    tp_likelihood: float             # 0..1
    severity: str                    # LOW / MEDIUM / HIGH / CRITICAL
    confidence: str                  # Low / Medium / High
    incident_type: str
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    reasons_tp: List[str] = field(default_factory=list)
    reasons_fp: List[str] = field(default_factory=list)
    triage_judgment: str = ""


@dataclass
class SimilarCase:
    case_id: str
    created_at: datetime
    disposition: str
    overlap: str
    actions_taken: List[str] = field(default_factory=list)
    notes_summary: str = ""


@dataclass
class RecommendedAction:
    description: str
    priority: int
    owner_team: str = "SOC"
    auto_executable: bool = False
    rationale: str = ""


@dataclass
class TriageReport:
    markdown: str
    ctx: NormalizedContext
    enrichment: EnrichmentContext
    forecast: TrendForecast
    classification: ClassificationResult
    similar_cases: List[SimilarCase]
    recommendations: List[RecommendedAction]


# =========================================================
# Async Integration Stubs (replace with real connectors)
# =========================================================

class AsyncSIEMClient:
    async def get_alert_by_id(self, alert_id: str) -> Dict[str, Any]:
        return {}

    async def get_related_events(self, *, ctx: NormalizedContext, lookback: timedelta) -> List[Dict[str, Any]]:
        return []

    async def search_by_indicator(self, *, ind_type: str, value: str, lookback: timedelta) -> List[Dict[str, Any]]:
        return []

    async def get_rule_count_series(self, *, rule_name: str, bucket_minutes: int, lookback: timedelta) -> List[int]:
        return []

    async def get_ioc_count_series(self, *, ind_type: str, value: str, bucket_minutes: int, lookback: timedelta) -> List[int]:
        return []

    async def get_entity_count_series(self, *, metric: str, entity: str, bucket_minutes: int, lookback: timedelta) -> List[int]:
        return []


class AsyncSOARClient:
    async def search_similar_cases(self, *, query: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []

    async def get_case_notes(self, case_id: str) -> str:
        return ""


class AsyncThreatIntelClient:
    """
    For indicator-type specific enrichment, implement what you want.
    The triage agent will call enrich_indicator(type, value) for ANY indicator type.
    """
    async def enrich_indicator(self, ind_type: str, value: str) -> Dict[str, Any]:
        return {
            "type": ind_type,
            "reputation": "unknown",     # malicious / suspicious / benign / unknown
            "confidence": "low",         # low / medium / high
            "source": "n/a",
            "notes": "",
        }


class AsyncAssetClient:
    async def get_asset_context(self, hostname: str) -> Dict[str, Any]:
        return {
            "criticality": "UNKNOWN",
            "business_unit": "N/A",
            "owner": "N/A",
            "segment": "N/A",
            "security_posture": "N/A",
            "business_process": "N/A",
            "compliance": "N/A",
        }

    async def get_user_context(self, username: str) -> Dict[str, Any]:
        return {"role": "N/A", "department": "N/A"}


class AsyncVulnClient:
    async def get_vulnerabilities_for_host(self, hostname: str) -> List[Dict[str, Any]]:
        """
        Each finding may include:
          {"asset":..., "cve":..., "severity":..., "cvss":..., "exploited_in_the_wild": bool, "notes":...}
        """
        return []

    async def get_environment_exposure_for_cves(self, cves: List[str]) -> Dict[str, Any]:
        """
        Example shape:
          {
            "vulnerable_assets_count": 123,
            "highest_exposure_severity": "CRITICAL",
            "known_exploited_exposure": True,
            "summary": "...",
            "sample_assets": ["host1","host2"]
          }
        """
        return {
            "vulnerable_assets_count": 0,
            "highest_exposure_severity": "N/A",
            "known_exploited_exposure": False,
            "summary": "No environment exposure data available.",
            "sample_assets": [],
        }


# =========================================================
# ETS Forecasting (sync core; run via asyncio.to_thread)
# =========================================================

class ETSForecaster:
    """
    Lightweight ETS (Holt / Holt-Winters additive) with small grid search.
    No external deps. Intended for SOC trend baselines (counts/rates).
    """

    def __init__(self, season_length: Optional[int] = None):
        self.season_length = season_length

    def fit_and_forecast(self, series: List[int], horizons: List[int]) -> Dict[int, Tuple[float, float, float]]:
        series = [max(0, int(x)) for x in series]
        if len(series) < 12:
            return {h: (float("nan"), float("nan"), float("nan")) for h in horizons}

        if self.season_length and len(series) >= 2 * self.season_length:
            model = self._fit_hw_additive(series, self.season_length)
        else:
            model = self._fit_holt_linear(series)

        forecasts = model["forecast_func"](max(horizons))
        resid = model["residuals"]
        resid_std = self._std(resid) if resid else 0.0

        out: Dict[int, Tuple[float, float, float]] = {}
        for h in horizons:
            window = forecasts[:h]
            mean_per_step = sum(window) / max(1, len(window))
            band = 1.96 * resid_std * math.sqrt(max(1, h))
            lo = max(0.0, mean_per_step - band)
            hi = max(0.0, mean_per_step + band)
            out[h] = (mean_per_step, lo, hi)
        return out

    def _fit_holt_linear(self, y: List[int]) -> Dict[str, Any]:
        best = {"sse": float("inf")}
        l0 = float(y[0])
        b0 = float(y[1] - y[0]) if len(y) > 1 else 0.0

        grid = [0.1, 0.2, 0.3, 0.5, 0.7, 0.9]
        for alpha in grid:
            for beta in grid:
                l, b = l0, b0
                residuals: List[float] = []
                sse = 0.0
                for t in range(1, len(y)):
                    yhat = l + b
                    e = y[t] - yhat
                    residuals.append(e)
                    sse += e * e
                    l_new = alpha * y[t] + (1 - alpha) * (l + b)
                    b_new = beta * (l_new - l) + (1 - beta) * b
                    l, b = l_new, b_new
                if sse < best["sse"]:
                    best = {"sse": sse, "alpha": alpha, "beta": beta, "l": l, "b": b, "residuals": residuals}

        def forecast_func(h: int) -> List[float]:
            return [max(0.0, best["l"] + (i + 1) * best["b"]) for i in range(h)]

        return {"forecast_func": forecast_func, "residuals": best["residuals"], "params": best}

    def _fit_hw_additive(self, y: List[int], m: int) -> Dict[str, Any]:
        best = {"sse": float("inf")}
        l0 = sum(y[:m]) / m
        b0 = (sum(y[m:2*m]) / m - sum(y[:m]) / m) / m
        s0 = [y[i] - l0 for i in range(m)]

        grid_a = [0.1, 0.2, 0.3, 0.5, 0.7]
        grid_b = [0.1, 0.2, 0.3, 0.5]
        grid_g = [0.1, 0.2, 0.3, 0.5, 0.7]

        for alpha in grid_a:
            for beta in grid_b:
                for gamma in grid_g:
                    l, b = float(l0), float(b0)
                    s = list(map(float, s0))
                    residuals: List[float] = []
                    sse = 0.0

                    for t in range(m, len(y)):
                        season = s[t % m]
                        yhat = l + b + season
                        e = y[t] - yhat
                        residuals.append(e)
                        sse += e * e

                        l_new = alpha * (y[t] - season) + (1 - alpha) * (l + b)
                        b_new = beta * (l_new - l) + (1 - beta) * b
                        s_new = gamma * (y[t] - l_new) + (1 - gamma) * season

                        l, b = l_new, b_new
                        s[t % m] = s_new

                    if sse < best["sse"]:
                        best = {
                            "sse": sse, "alpha": alpha, "beta": beta, "gamma": gamma,
                            "l": l, "b": b, "s": s, "m": m, "residuals": residuals
                        }

        def forecast_func(h: int) -> List[float]:
            out = []
            for i in range(1, h + 1):
                season = best["s"][(len(y) + i - 1) % best["m"]]
                out.append(max(0.0, best["l"] + i * best["b"] + season))
            return out

        return {"forecast_func": forecast_func, "residuals": best["residuals"], "params": best}

    @staticmethod
    def _std(xs: List[float]) -> float:
        if not xs:
            return 0.0
        mu = sum(xs) / len(xs)
        var = sum((x - mu) ** 2 for x in xs) / max(1, len(xs) - 1)
        return math.sqrt(var)


# =========================================================
# Playbook Templates (SOC phrasing)
# =========================================================

PLAYBOOK_TEMPLATES: Dict[str, List[str]] = {
    "DEFAULT": [
        "Validate the signal using correlated telemetry and detection logic/IOC definition.",
        "Confirm scope (hosts/users/segments) and whether activity is ongoing or expanding.",
        "If malicious indicators are confirmed, contain and escalate per runbook.",
    ],
    "IOC:malicious": [
        "Run environment-wide SIEM search for the indicator (DNS/proxy/firewall/EDR) and identify impacted assets.",
        "Block the indicator where policy permits; document scope and exceptions.",
        "If internal communication is confirmed, collect endpoint/network triage evidence and assess for follow-on behavior.",
    ],
    "ALERT:powershell": [
        "Validate PowerShell command line + parent chain; rule out known admin automation.",
        "Collect endpoint triage package (process tree, network connections, script block logs if available).",
        "Scope for similar execution across endpoints; if widespread, treat as campaign.",
    ],
    "CVE": [
        "Validate CVE applicability (version/path/mitigations) and confirm exposure (internet-facing, lateral exposure).",
        "Prioritize remediation by criticality; hunt for exploitation evidence aligned to the CVE.",
        "If exploitation evidence exists, escalate to IR and contain affected assets.",
    ],
}


# =========================================================
# Async Triage Agent
# =========================================================

class TriageAgentAsync:
    def __init__(
        self,
        *,
        siem: AsyncSIEMClient,
        soar: AsyncSOARClient,
        ti: AsyncThreatIntelClient,
        asset: AsyncAssetClient,
        vuln: AsyncVulnClient,
        bucket_minutes: int = 15,
        trend_lookback_days: int = 14,
        season_length: Optional[int] = None,
        max_concurrency: int = 10,
    ):
        self.siem = siem
        self.soar = soar
        self.ti = ti
        self.asset = asset
        self.vuln = vuln

        self.bucket_minutes = bucket_minutes
        self.trend_lookback_days = trend_lookback_days
        self.ets = ETSForecaster(season_length=season_length)

        self._sem = asyncio.Semaphore(max_concurrency)

    async def triage(self, signal: Signal) -> TriageReport:
        ctx = await self.normalize(signal)
        enrichment = await self.enrich(ctx)
        forecast = await self.forecast_trends(ctx, enrichment)
        classification = await self.classify(ctx, enrichment, forecast)
        similar_cases = await self.find_similar_cases(ctx)
        recommendations = await self.recommend(ctx, enrichment, classification, similar_cases, forecast)
        md = await self.build_report(ctx, enrichment, forecast, classification, similar_cases, recommendations)

        return TriageReport(
            markdown=md,
            ctx=ctx,
            enrichment=enrichment,
            forecast=forecast,
            classification=classification,
            similar_cases=similar_cases,
            recommendations=recommendations,
        )

    # -------------------------
    # Step 0: Normalize (async-friendly; may call SIEM for alert hydration)
    # -------------------------
    async def normalize(self, signal: Signal) -> NormalizedContext:
        raw = dict(signal.raw or {})
        ctx = NormalizedContext(signal=signal)

        # If alert-led but raw is minimal, optionally hydrate by alert id
        if signal.type == "SIEM_ALERT" and raw.get("alert_id") and len(raw.keys()) <= 2:
            hydrated = await self.siem.get_alert_by_id(str(raw["alert_id"]))
            raw.update(hydrated)
            ctx.signal.raw = raw

        # Generic entity extraction (works for all signal types)
        ctx.username = raw.get("username") or raw.get("user")
        ctx.hostname = raw.get("hostname") or raw.get("host")
        ctx.src_ip = raw.get("src_ip") or raw.get("source_ip") or raw.get("src")
        ctx.dst_ip = raw.get("dst_ip") or raw.get("destination_ip") or raw.get("dst")

        # Indicator extraction: allow arbitrary indicator keys
        # Common keys:
        for k in ("ip", "domain", "url", "hash", "email", "ja3", "sha256", "md5", "mutex", "registry"):
            if raw.get(k):
                ctx.indicators[k] = str(raw[k])

        # IOC-led signal standard shape: {"indicator_type": "...", "value": "..."}
        if signal.type == "TI_INDICATOR":
            it = raw.get("indicator_type")
            val = raw.get("value")
            if it and val:
                ctx.indicators[str(it)] = str(val)

        # CVE extraction supports string or list
        cves: List[str] = []
        for key in ("cve", "cves", "CVE"):
            if raw.get(key):
                v = raw[key]
                if isinstance(v, str):
                    cves.append(v.strip())
                elif isinstance(v, list):
                    cves.extend([str(x).strip() for x in v])
        ctx.cves = sorted(set([c for c in cves if c]))

        # Alert identity fields
        if signal.type == "SIEM_ALERT":
            ctx.alert_rule = raw.get("rule") or raw.get("rule_name") or signal.name
            ctx.alert_vendor = raw.get("vendor") or raw.get("product") or signal.source

        return ctx

    # -------------------------
    # Step 1: Enrich / Correlate (parallelized)
    # -------------------------
    async def enrich(self, ctx: NormalizedContext) -> EnrichmentContext:
        e = EnrichmentContext()

        lookback_events = timedelta(hours=24)
        lookback_ioc = timedelta(days=30)

        # Parallel fetches: related events + asset context + vulns + env exposure + TI enrich + IOC sightings
        tasks = []

        tasks.append(asyncio.create_task(self._safe_call(self.siem.get_related_events, ctx=ctx, lookback=lookback_events)))

        if ctx.hostname:
            tasks.append(asyncio.create_task(self._safe_call(self.asset.get_asset_context, hostname=ctx.hostname)))
            tasks.append(asyncio.create_task(self._safe_call(self.vuln.get_vulnerabilities_for_host, hostname=ctx.hostname)))
        else:
            # placeholders
            tasks.append(asyncio.create_task(asyncio.sleep(0, result={})))
            tasks.append(asyncio.create_task(asyncio.sleep(0, result=[])))

        if ctx.username:
            tasks.append(asyncio.create_task(self._safe_call(self.asset.get_user_context, username=ctx.username)))
        else:
            tasks.append(asyncio.create_task(asyncio.sleep(0, result={})))

        if ctx.cves:
            tasks.append(asyncio.create_task(self._safe_call(self.vuln.get_environment_exposure_for_cves, cves=ctx.cves)))
        else:
            tasks.append(asyncio.create_task(asyncio.sleep(0, result={
                "vulnerable_assets_count": 0,
                "highest_exposure_severity": "N/A",
                "known_exploited_exposure": False,
                "summary": "No CVEs provided by signal; environment exposure not computed.",
                "sample_assets": [],
            })))

        # TI enrichment for ALL indicators (any type) — bounded concurrency
        ti_task = asyncio.create_task(self._enrich_all_indicators(ctx))
        tasks.append(ti_task)

        # Local IOC sightings for indicators — bounded concurrency
        sightings_task = asyncio.create_task(self._search_all_indicators(ctx, lookback_ioc))
        tasks.append(sightings_task)

        results = await asyncio.gather(*tasks)

        # Unpack results by order
        idx = 0
        e.related_events = results[idx] or []; idx += 1
        host_ctx = results[idx] or {}; idx += 1
        e.host_vulns = results[idx] or []; idx += 1
        user_ctx = results[idx] or {}; idx += 1
        e.env_exposure = results[idx] or {}; idx += 1
        e.threat_intel = results[idx] or {}; idx += 1
        e.local_sightings = results[idx] or []; idx += 1

        e.asset_context["host"] = host_ctx
        e.asset_context["user"] = user_ctx

        # Build scope from sightings matches (best effort if SIEM returns host/user fields)
        impacted_hosts: List[str] = []
        impacted_users: List[str] = []
        impacted_segments: List[str] = []

        for s in e.local_sightings:
            for m in (s.get("_matches") or [])[:500]:
                h = m.get("hostname") or m.get("host")
                u = m.get("username") or m.get("user")
                seg = m.get("segment")
                if h:
                    impacted_hosts.append(str(h))
                if u:
                    impacted_users.append(str(u))
                if seg:
                    impacted_segments.append(str(seg))

        e.impacted_hosts = sorted(set(impacted_hosts))
        e.impacted_users = sorted(set(impacted_users))
        e.impacted_segments = sorted(set(impacted_segments))

        # Spread assessment
        host_cnt = len(e.impacted_hosts) if e.impacted_hosts else (1 if ctx.hostname else 0)
        if host_cnt >= 20:
            e.spread_assessment = "broad"
        elif host_cnt >= 3:
            e.spread_assessment = "limited"
        else:
            e.spread_assessment = "isolated"

        # Correlation summary (SOC-friendly)
        local_total = sum(int(x.get("count", 0) or 0) for x in e.local_sightings)
        e.correlation_summary = (
            f"Local indicator matches (30d)={local_total}; impacted_hosts={len(e.impacted_hosts)}, "
            f"impacted_users={len(e.impacted_users)}, spread={e.spread_assessment}."
        )

        return e

    async def _enrich_all_indicators(self, ctx: NormalizedContext) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}

        async def enrich_one(ind_type: str, value: str) -> None:
            async with self._sem:
                rec = await self._safe_call(self.ti.enrich_indicator, ind_type=ind_type, value=value)
                if rec is None:
                    rec = {"type": ind_type, "reputation": "unknown", "confidence": "low", "source": "n/a", "notes": ""}
                out[value] = rec

        await asyncio.gather(*(enrich_one(t, v) for t, v in ctx.indicators.items()))
        # Also enrich src/dst ip even if not present as indicator (optional)
        for ip in [ctx.src_ip, ctx.dst_ip]:
            if ip and ip not in out:
                await enrich_one("ip", ip)
        return out

    async def _search_all_indicators(self, ctx: NormalizedContext, lookback: timedelta) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []

        async def search_one(ind_type: str, value: str) -> None:
            async with self._sem:
                matches = await self._safe_call(self.siem.search_by_indicator, ind_type=ind_type, value=value, lookback=lookback)
                matches = matches or []
                out.append({
                    "match_type": "alert_or_event",
                    "where_seen": ctx.signal.source,
                    "count": len(matches),
                    "time_window": f"{int(lookback.total_seconds() // 86400)}d",
                    "notes": f"SIEM search matches for {ind_type}={value}",
                    "indicator_type": ind_type,
                    "indicator_value": value,
                    "_matches": matches,  # kept internal for scope extraction; not printed verbatim in report
                })

        await asyncio.gather(*(search_one(t, v) for t, v in ctx.indicators.items()))
        return out

    async def _safe_call(self, fn, **kwargs):
        try:
            return await fn(**kwargs)
        except Exception:
            return None

    # -------------------------
    # Step 2: Forecast (ETS) – executed off-thread to keep async
    # -------------------------
    async def forecast_trends(self, ctx: NormalizedContext, e: EnrichmentContext) -> TrendForecast:
        b = self.bucket_minutes
        lookback = timedelta(days=self.trend_lookback_days)

        # horizons in buckets for multi-horizon (H1/H6/H24)
        h1 = max(1, int(60 / b))
        h6 = max(1, int(360 / b))
        h24 = max(1, int(1440 / b))
        horizons = [h1, h6, h24]

        # Gather time series in parallel (these are async SIEM calls)
        rule_task = None
        if ctx.alert_rule:
            rule_task = asyncio.create_task(self.siem.get_rule_count_series(rule_name=ctx.alert_rule, bucket_minutes=b, lookback=lookback))
        else:
            rule_task = asyncio.create_task(asyncio.sleep(0, result=[]))

        ioc_task = None
        if ctx.indicators:
            ind_type, value = next(iter(ctx.indicators.items()))
            ioc_task = asyncio.create_task(self.siem.get_ioc_count_series(ind_type=ind_type, value=value, bucket_minutes=b, lookback=lookback))
        else:
            ioc_task = asyncio.create_task(asyncio.sleep(0, result=[]))

        # Optional entity metric (stubbed empty unless you wire it)
        entity_task = asyncio.create_task(asyncio.sleep(0, result=[]))

        rule_series, ioc_series, entity_series = await asyncio.gather(rule_task, ioc_task, entity_task)

        # ETS fit/forecast is CPU-ish; run off-thread
        rule_block = await self._ets_block_async(
            metric_name=f"alerts/{b}m for rule '{ctx.alert_rule}'" if ctx.alert_rule else f"alerts/{b}m (rule)",
            series=rule_series or [],
            horizons=horizons,
            hint="detection volume",
        )
        ioc_block = await self._ets_block_async(
            metric_name=f"IOC matches/{b}m for first extracted indicator" if ctx.indicators else f"IOC matches/{b}m",
            series=ioc_series or [],
            horizons=horizons,
            hint="IOC sightings",
        )
        entity_block = await self._ets_block_async(
            metric_name=f"entity metric/{b}m (optional)",
            series=entity_series or [],
            horizons=horizons,
            hint="entity behavior",
        )

        return TrendForecast(rule=rule_block, ioc=ioc_block, entity=entity_block)

    async def _ets_block_async(self, *, metric_name: str, series: List[int], horizons: List[int], hint: str) -> ForecastBlock:
        if not series or len(series) < 12:
            return ForecastBlock(
                metric_name=metric_name,
                current_vs_expected="N/A (insufficient history)",
                h1="N/A",
                h6="N/A",
                h24="N/A",
                interpretation=f"No reliable {hint} forecast due to limited history.",
                confidence="Low",
            )

        # Run ETS off-thread
        forecasts = await asyncio.to_thread(self.ets.fit_and_forecast, series, horizons)

        current = series[-1]
        expected = sum(series[:-1]) / max(1, len(series[:-1]))
        pct = "N/A" if expected <= 0 else f"{((current - expected) / expected) * 100:+.0f}%"
        current_vs_expected = f"{current} vs {expected:.1f} expected ({pct})"

        def fmt_total(h: int) -> str:
            mean_step, lo_step, hi_step = forecasts[h]
            if math.isnan(mean_step):
                return "N/A"
            mean_total = mean_step * h
            lo_total = lo_step * h
            hi_total = hi_step * h
            return f"{mean_total:.1f} (≈{lo_total:.1f}–{hi_total:.1f})"

        # Interpretation: compare current to upper band of H1 per-step
        mean_step, lo_step, hi_step = forecasts[horizons[0]]
        interpretation = "Within expected range."
        if not math.isnan(hi_step) and current > hi_step:
            interpretation = "Spike above ETS baseline; likely elevated activity/campaign."
        elif expected > 0 and current > expected * 2:
            interpretation = "Spike above baseline; likely elevated activity/campaign."
        elif expected > 0 and current < expected * 0.5:
            interpretation = "Below baseline; activity appears lower than typical."

        # Confidence heuristic: more history + lower volatility => higher
        vol = self._std([float(x) for x in series[:-1]])
        confidence = "Medium"
        if len(series) < 48 or vol > max(3.0, expected):
            confidence = "Low"

        return ForecastBlock(
            metric_name=metric_name,
            current_vs_expected=current_vs_expected,
            h1=fmt_total(horizons[0]),
            h6=fmt_total(horizons[1]),
            h24=fmt_total(horizons[2]),
            interpretation=interpretation,
            confidence=confidence,
        )

    @staticmethod
    def _std(xs: List[float]) -> float:
        if not xs:
            return 0.0
        mu = sum(xs) / len(xs)
        var = sum((x - mu) ** 2 for x in xs) / max(1, len(xs) - 1)
        return math.sqrt(var)

    # -------------------------
    # Step 3: Classify (multi-dimensional; all signal types)
    # -------------------------
    async def classify(self, ctx: NormalizedContext, e: EnrichmentContext, f: TrendForecast) -> ClassificationResult:
        score = 0.25
        reasons_tp: List[str] = []
        reasons_fp: List[str] = []

        # 1) TI
        ti_mal = 0
        ti_susp = 0
        for rec in e.threat_intel.values():
            rep = (rec.get("reputation") or "").lower()
            if rep == "malicious":
                ti_mal += 1
            elif rep == "suspicious":
                ti_susp += 1

        if ti_mal:
            score += min(0.45, 0.25 + 0.10 * (ti_mal - 1))
            reasons_tp.append(f"Threat intel flags {ti_mal} indicator(s) as malicious.")
        elif ti_susp:
            score += min(0.25, 0.15 + 0.05 * (ti_susp - 1))
            reasons_tp.append(f"Threat intel flags {ti_susp} indicator(s) as suspicious.")
        else:
            reasons_fp.append("Threat intel provides no strong malicious context (unknown/benign).")

        # 2) Local sightings
        local_total = sum(int(s.get("count", 0) or 0) for s in e.local_sightings)
        if local_total >= 10:
            score += 0.25
            reasons_tp.append(f"Indicators observed locally at meaningful volume (matches={local_total} over 30d).")
        elif local_total >= 1:
            score += 0.12
            reasons_tp.append(f"Indicators observed locally (matches={local_total} over 30d).")
        else:
            if ctx.signal.type == "TI_INDICATOR":
                reasons_fp.append("IOC not observed locally (no SIEM matches).")
            else:
                reasons_fp.append("Limited local corroboration beyond the primary signal.")

        # 3) CVE / Vulnerability posture
        host_high = [v for v in e.host_vulns if (v.get("severity") or "").upper() in ("HIGH", "CRITICAL")]
        host_expl = [v for v in e.host_vulns if v.get("exploited_in_the_wild") is True]
        if ctx.hostname:
            if host_high or host_expl:
                score += 0.12
                reasons_tp.append(f"Host has high-risk vuln posture (HIGH/CRIT={len(host_high)}, exploited={len(host_expl)}).")
            else:
                reasons_fp.append("No high-risk host vulnerabilities found (based on available data).")

        if ctx.cves:
            env_cnt = int(e.env_exposure.get("vulnerable_assets_count", 0) or 0)
            env_expl = bool(e.env_exposure.get("known_exploited_exposure", False))
            if env_expl:
                score += 0.10
                reasons_tp.append("CVE set includes known-exploited exposure risk in environment.")
            if env_cnt >= 50:
                score += 0.10
                reasons_tp.append(f"Environment exposure appears broad (vulnerable assets≈{env_cnt}).")
            elif env_cnt >= 1:
                score += 0.05
                reasons_tp.append(f"Environment exposure exists (vulnerable assets≈{env_cnt}).")
            elif env_cnt == 0:
                reasons_fp.append("No environment exposure found for provided CVEs (based on available data).")

        # 4) Asset/user criticality
        host_ctx = e.asset_context.get("host", {}) or {}
        crit = (host_ctx.get("criticality") or "").upper()
        if crit == "HIGH":
            score += 0.12
            reasons_tp.append("Target host is HIGH criticality.")
        elif crit == "MEDIUM":
            score += 0.06
            reasons_tp.append("Target host is MEDIUM criticality.")
        else:
            reasons_fp.append("Host criticality unknown/low (based on available context).")

        user_ctx = e.asset_context.get("user", {}) or {}
        role = (user_ctx.get("role") or "")
        if role and any(x in role.lower() for x in ["admin", "engineer", "finance", "domain", "security"]):
            score += 0.08
            reasons_tp.append(f"User role appears sensitive/elevated: {role}.")
        elif ctx.username:
            reasons_fp.append("User role does not appear elevated (based on available context).")

        # 5) Trend persistence (ETS)
        if "Spike" in f.rule.interpretation:
            score += 0.08
            reasons_tp.append("ETS indicates detection volume spike above baseline (possible campaign/surge).")
        if "Spike" in f.ioc.interpretation:
            score += 0.08
            reasons_tp.append("ETS indicates IOC sightings spike above baseline (possible active spread).")
        if f.rule.confidence == "Low" and f.ioc.confidence == "Low":
            reasons_fp.append("ETS forecast confidence is low; treat trend signals cautiously.")

        # Clamp
        score = max(0.0, min(1.0, score))

        # Disposition
        if score >= 0.80:
            disposition = "Probable TRUE POSITIVE"
        elif score <= 0.20:
            disposition = "Likely FALSE POSITIVE"
        else:
            disposition = "Requires Analyst Review"

        # Severity
        if score >= 0.85:
            severity = "CRITICAL"
        elif score >= 0.65:
            severity = "HIGH"
        elif score >= 0.40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Confidence
        confidence = "Medium"
        if score >= 0.75 and (ti_mal or local_total >= 10 or bool(host_expl)):
            confidence = "High"
        elif score <= 0.35 and local_total == 0 and ti_mal == 0 and not host_expl:
            confidence = "Low"

        incident_type, tactics, techniques = self._infer_incident_type(ctx)
        triage_judgment = (
            f"{disposition}. Score={int(score*100)}%, Severity={severity}. "
            f"Key drivers: {('; '.join(reasons_tp[:2]) or 'none')}."
        )

        return ClassificationResult(
            disposition=disposition,
            tp_likelihood=score,
            severity=severity,
            confidence=confidence,
            incident_type=incident_type,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            reasons_tp=reasons_tp[:6],
            reasons_fp=reasons_fp[:6],
            triage_judgment=triage_judgment,
        )

    def _infer_incident_type(self, ctx: NormalizedContext) -> Tuple[str, List[str], List[str]]:
        name = (ctx.signal.name or "").lower()
        cat = (ctx.signal.category or "").lower()

        if ctx.cves or ctx.signal.type == "VULNERABILITY_ALERT":
            return ("Vulnerability / Exposure Signal", ["Initial Access"], ["T1190"])
        if "powershell" in name:
            return ("Suspicious PowerShell Execution", ["Execution"], ["T1059.001"])
        if ctx.signal.type == "TI_INDICATOR":
            return ("IOC-led Threat Signal", ["Discovery"], [])
        if "phish" in cat or "phish" in name:
            return ("Phishing", ["Initial Access"], ["T1566"])
        return ("Unclassified Security Signal", [], [])

    # -------------------------
    # Step 4: Similar cases (async)
    # -------------------------
    async def find_similar_cases(self, ctx: NormalizedContext) -> List[SimilarCase]:
        query: Dict[str, Any] = {
            "lookback_days": 90,
            "signal_type": ctx.signal.type,
            "signal_name": ctx.signal.name,
        }
        if ctx.hostname:
            query["hostname"] = ctx.hostname
        if ctx.username:
            query["username"] = ctx.username
        if ctx.indicators:
            t, v = next(iter(ctx.indicators.items()))
            query["indicator_type"] = t
            query["indicator_value"] = v
        if ctx.cves:
            query["cves"] = ctx.cves

        raw_cases = await self._safe_call(self.soar.search_similar_cases, query=query) or []
        out: List[SimilarCase] = []

        async def hydrate_case(rc: Dict[str, Any]) -> Optional[SimilarCase]:
            cid = rc.get("id") or rc.get("case_id") or "UNKNOWN"
            notes = await self._safe_call(self.soar.get_case_notes, case_id=cid) or ""
            return SimilarCase(
                case_id=cid,
                created_at=rc.get("created_at") or datetime.now(timezone.utc),
                disposition=rc.get("disposition") or "UNKNOWN",
                overlap=rc.get("overlap") or self._build_overlap(ctx),
                actions_taken=rc.get("actions_taken") or [],
                notes_summary=str(notes)[:400],
            )

        hydrated = await asyncio.gather(*(hydrate_case(rc) for rc in raw_cases[:10]))
        for h in hydrated:
            if h:
                out.append(h)
        return out

    def _build_overlap(self, ctx: NormalizedContext) -> str:
        parts = []
        if ctx.signal.name:
            parts.append(f"signal={ctx.signal.name}")
        if ctx.hostname:
            parts.append(f"host={ctx.hostname}")
        if ctx.username:
            parts.append(f"user={ctx.username}")
        if ctx.indicators:
            k, v = next(iter(ctx.indicators.items()))
            parts.append(f"{k}={v}")
        if ctx.cves:
            parts.append(f"cves={','.join(ctx.cves[:2])}{'...' if len(ctx.cves)>2 else ''}")
        return ", ".join(parts) if parts else "N/A"

    # -------------------------
    # Step 5: Recommendations (async-friendly; mostly logic)
    # -------------------------
    async def recommend(
        self,
        ctx: NormalizedContext,
        e: EnrichmentContext,
        c: ClassificationResult,
        similar_cases: List[SimilarCase],
        f: TrendForecast,
    ) -> List[RecommendedAction]:
        recs: List[RecommendedAction] = []

        # pick playbook
        playbook_key = "DEFAULT"

        # CVE-led
        if ctx.cves or ctx.signal.type == "VULNERABILITY_ALERT":
            playbook_key = "CVE"

        # PowerShell alert-led
        if ctx.signal.type == "SIEM_ALERT" and "powershell" in (ctx.signal.name or "").lower():
            playbook_key = "ALERT:powershell"

        # IOC-led malicious indicator
        if ctx.signal.type == "TI_INDICATOR" and e.threat_intel:
            reps = [ (rec.get("reputation") or "").lower() for rec in e.threat_intel.values() ]
            if "malicious" in reps:
                playbook_key = "IOC:malicious"

        # route action first
        if c.tp_likelihood >= 0.70:
            recs.append(RecommendedAction(
                description="Escalate to Tier 2 / Incident Response for confirmation and containment authorization.",
                priority=1,
                owner_team="SOC/IR",
                rationale="High TP likelihood / severity warrants rapid senior review."
            ))
        elif c.tp_likelihood <= 0.30:
            recs.append(RecommendedAction(
                description="Perform quick validation; if benign, document and consider tuning/suppression.",
                priority=1,
                owner_team="SOC",
                rationale="Low TP likelihood; prioritize efficiency while preserving audit trail."
            ))
        else:
            recs.append(RecommendedAction(
                description="Proceed with standard analyst validation and scope check.",
                priority=1,
                owner_team="SOC",
                rationale="Moderate TP likelihood; needs human judgment."
            ))

        # playbook steps
        steps = PLAYBOOK_TEMPLATES.get(playbook_key, PLAYBOOK_TEMPLATES["DEFAULT"])
        for i, step in enumerate(steps):
            recs.append(RecommendedAction(
                description=step,
                priority=2 + i,
                owner_team="SOC",
                rationale=f"Playbook step ({playbook_key})."
            ))

        # add “learned actions” from similar cases (avoid duplicates)
        hist = Counter()
        for sc in similar_cases:
            hist.update(sc.actions_taken or [])
        for action, count in hist.most_common(3):
            if any(r.description == action for r in recs):
                continue
            recs.append(RecommendedAction(
                description=action,
                priority=10,
                owner_team="SOC",
                rationale=f"Observed in {count} similar historical cases."
            ))

        # trend-aware step
        if "Spike" in f.rule.interpretation or "Spike" in f.ioc.interpretation:
            recs.append(RecommendedAction(
                description="Assess whether activity is campaign-wide; run proactive scoping queries across the environment.",
                priority=6,
                owner_team="SOC",
                rationale="ETS indicates elevated activity may persist."
            ))

        recs.sort(key=lambda r: r.priority)
        return recs[:12]

    # -------------------------
    # Step 6: Report (async; pure rendering)
    # -------------------------
    async def build_report(
        self,
        ctx: NormalizedContext,
        e: EnrichmentContext,
        f: TrendForecast,
        c: ClassificationResult,
        similar_cases: List[SimilarCase],
        recs: List[RecommendedAction],
    ) -> str:
        now_utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        tp_pct = int(c.tp_likelihood * 100)

        def na(v: Optional[str]) -> str:
            return v if v else "N/A"

        def yn(v: bool) -> str:
            return "Yes" if v else "No"

        # Immediate next steps
        imm1 = recs[0].description if len(recs) > 0 else "N/A"
        imm2 = recs[1].description if len(recs) > 1 else "N/A"

        rationale_one = c.reasons_tp[0] if c.reasons_tp else (c.reasons_fp[0] if c.reasons_fp else "N/A")

        # Action table rows (top 3)
        action_rows = []
        for i, r in enumerate(recs[:3], start=1):
            action_rows.append(f"| {i} | {r.description} | P{r.priority} | {r.owner_team} | {yn(r.auto_executable)} | Open |")
        while len(action_rows) < 3:
            i = len(action_rows) + 1
            action_rows.append(f"| {i} | N/A | P- | SOC | No | Open |")

        # Sightings rows (top 2)
        sight_rows = []
        for s in (e.local_sightings or [])[:2]:
            sight_rows.append(
                f"| {s.get('match_type','N/A')} | {s.get('where_seen','N/A')} | {s.get('count',0)} | {s.get('time_window','N/A')} | {s.get('notes','N/A')} |"
            )
        while len(sight_rows) < 2:
            sight_rows.append("| N/A | N/A | 0 | N/A | No local sightings recorded. |")

        # TI rows (top 2)
        ti_rows = []
        for ind, rec in list(e.threat_intel.items())[:2]:
            ti_rows.append(
                f"| {ind} | {rec.get('type','N/A')} | {rec.get('reputation','unknown')} | {rec.get('confidence','low')} | {rec.get('source','N/A')} | {rec.get('notes','')} |"
            )
        while len(ti_rows) < 2:
            ti_rows.append("| N/A | N/A | unknown | low | N/A | No TI enrichment available. |")

        # Vuln rows (host-level)
        vuln_rows = []
        if ctx.hostname:
            for v in (e.host_vulns or [])[:2]:
                vuln_rows.append(
                    f"| {v.get('asset', ctx.hostname)} | {v.get('cve','N/A')} | {v.get('severity','N/A')} | {yn(bool(v.get('exploited_in_the_wild')))} | {v.get('notes','')} |"
                )
            while len(vuln_rows) < 2:
                vuln_rows.append(f"| {ctx.hostname} | N/A | N/A | No | No host vuln findings available. |")
            env_exposure_lines = [
                "### 6.2 Environment Exposure Summary (If No Specific Host)",
                "- **Vulnerable assets count:** N/A",
                "- **Highest severity exposure:** N/A",
                "- **Known exploited exposure present?:** N/A",
                "- **Exposure summary:** N/A",
            ]
        else:
            vuln_rows = [
                "| N/A | N/A | N/A | N/A | No host scope available for asset-level exposure. |",
                "| N/A | N/A | N/A | N/A | No host scope available for asset-level exposure. |",
            ]
            env_cnt = e.env_exposure.get("vulnerable_assets_count", "N/A")
            env_high = e.env_exposure.get("highest_exposure_severity", "N/A")
            env_expl = e.env_exposure.get("known_exploited_exposure", None)
            env_expl_s = yn(bool(env_expl)) if isinstance(env_expl, bool) else "N/A"
            env_sum = e.env_exposure.get("summary", "N/A")
            env_exposure_lines = [
                "### 6.2 Environment Exposure Summary (If No Specific Host)",
                f"- **Vulnerable assets count:** {env_cnt}",
                f"- **Highest severity exposure:** {env_high}",
                f"- **Known exploited exposure present?:** {env_expl_s}",
                f"- **Exposure summary:** {env_sum}",
            ]

        # Timeline rows (top 3)
        tl_rows = []
        for ev in (e.related_events or [])[:3]:
            tl_rows.append(
                f"| {ev.get('timestamp','N/A')} | {ev.get('source','N/A')} | {ev.get('summary','N/A')} | {ev.get('relevance','N/A')} |"
            )
        while len(tl_rows) < 3:
            tl_rows.append("| N/A | N/A | No correlated event available. | N/A |")

        timeline_interp = "No correlated timeline events available." if not e.related_events else \
            "Timeline contains correlated activity; review above rows for escalation triggers."

        # Similar cases rows
        case_rows = []
        none_line = ""
        if similar_cases:
            for sc in similar_cases[:2]:
                case_rows.append(
                    f"| {sc.case_id} | {sc.created_at.replace(microsecond=0).isoformat()} | {sc.disposition} | {sc.overlap} | {', '.join(sc.actions_taken[:4]) or 'N/A'} |"
                )
            while len(case_rows) < 2:
                case_rows.append("| N/A | N/A | N/A | N/A | N/A |")
        else:
            case_rows = ["| N/A | N/A | N/A | N/A | N/A |", "| N/A | N/A | N/A | N/A | N/A |"]
            none_line = "- *No relevant prior cases found in the last 90 days.*"

        # Stakeholder snapshot minimal fields
        host_ctx = e.asset_context.get("host", {}) or {}
        business_process = host_ctx.get("business_process") or "N/A"
        compliance_notes = host_ctx.get("compliance") or "N/A"

        indicators_summary = ", ".join(f"{k}={v}" for k, v in ctx.indicators.items()) if ctx.indicators else "none"
        cves_summary = ", ".join(ctx.cves) if ctx.cves else "none"

        md = f"""# SOC Triage Report – {ctx.signal.id}

**Signal Type:** {ctx.signal.type}
**Signal Source:** {ctx.signal.source}
**Signal Name:** {ctx.signal.name}
**Category:** {ctx.signal.category}
**Generated (UTC):** {now_utc}
**Triage Owner:** TriageAgentAsync

---

## Decision Banner

> **Triage Decision:** **{c.disposition}**
> *(Probable TRUE POSITIVE / Likely FALSE POSITIVE / Requires Analyst Review)*

- **Severity (if TP):** **{c.severity}**
- **TP Likelihood:** **{tp_pct}%**
- **Confidence:** {c.confidence}
- **Top Rationale:** {rationale_one}

**Immediate Next Steps**
1. {imm1}
2. {imm2}

---

## 1. Summary (SOC + Stakeholders)

> {ctx.signal.name} ({ctx.signal.type}) triaged as {c.severity} with {tp_pct}% TP likelihood; spread={e.spread_assessment}.

- **What we started with:** {ctx.signal.type} from {ctx.signal.source}: {ctx.signal.name}
- **What we found after correlation:** {e.correlation_summary or "No additional correlation available."}
- **Why it matters if true:** Potential compromise / malicious activity; impact depends on criticality and scope.
- **Current stance:** Under triage; actions proposed below.

---

## 2. Action Plan (Always Present)

| # | Action | Priority | Owner/Team | Auto-Executable | Status |
|---|--------|----------|------------|-----------------|--------|
{chr(10).join(action_rows)}

**If TRUE POSITIVE path:** Execute P1/P2 actions, confirm scope, and escalate per runbook.
**If FALSE POSITIVE path:** Document rationale, tune detection/IOC logic, and close with evidence.

---

## 3. Signal Normalization (Always Present)

- **Normalized entities (if known):**
  - User: {na(ctx.username)}
  - Host: {na(ctx.hostname)}
  - Src IP: {na(ctx.src_ip)}
  - Dst IP: {na(ctx.dst_ip)}
- **Indicators extracted:** {indicators_summary}
- **CVEs extracted:** {cves_summary}

---

## 4. Correlation Results (Always Present)

### 4.1 Local Sightings (Alerts/Events)

| Match Type | Where Seen | Count | Time Window | Notes |
|-----------|-----------|------:|------------|-------|
{chr(10).join(sight_rows)}

### 4.2 Scope Summary

- **Impacted hosts:** {len(e.impacted_hosts) if e.impacted_hosts else 0}
- **Impacted users:** {len(e.impacted_users) if e.impacted_users else 0}
- **Impacted segments/tenants:** {", ".join(e.impacted_segments) if e.impacted_segments else "N/A"}
- **Spread assessment:** {e.spread_assessment}

---

## 5. Threat Intelligence (Always Present)

| Indicator | Type | Reputation | Confidence | Source(s) | Notes |
|----------|------|-----------|------------|----------|-------|
{chr(10).join(ti_rows)}

> **TI Summary:** {self._summarize_ti(e.threat_intel)}

---

## 6. Exposure & Vulnerability Context (Always Present)

### 6.1 Asset-Level Exposure (If Host Scope Exists)

| Host/Asset | CVE/Finding | Severity | Exploited in Wild? | Notes |
|-----------|-------------|----------|--------------------|------|
{chr(10).join(vuln_rows)}

{chr(10).join(env_exposure_lines)}

---

## 7. Trend & Forecast (ETS, Always Present)

### 7.1 Detection Volume Trend (Rule/Use-Case Level)
- **Metric:** {f.rule.metric_name}
- **Current vs Expected:** {f.rule.current_vs_expected}
- **Forecast (H1/H6/H24):** {f.rule.h1} / {f.rule.h6} / {f.rule.h24}
- **Interpretation:** {f.rule.interpretation}
- **Uncertainty/Confidence:** {f.rule.confidence}

### 7.2 IOC Sightings Trend (Indicator Level)
- **Metric:** {f.ioc.metric_name}
- **Current vs Expected:** {f.ioc.current_vs_expected}
- **Forecast (H1/H6/H24):** {f.ioc.h1} / {f.ioc.h6} / {f.ioc.h24}
- **Interpretation:** {f.ioc.interpretation}
- **Uncertainty/Confidence:** {f.ioc.confidence}

### 7.3 Entity Behavior Trend (Optional Metric Slot)
- **Metric:** {f.entity.metric_name}
- **Current vs Expected:** {f.entity.current_vs_expected}
- **Forecast (H1/H6/H24):** {f.entity.h1} / {f.entity.h6} / {f.entity.h24}
- **Interpretation:** {f.entity.interpretation}
- **Uncertainty/Confidence:** {f.entity.confidence}

---

## 8. Evidence Timeline (Always Present)

| Time (UTC) | Source/System | Event Summary | Relevance |
|------------|--------------|--------------|-----------|
{chr(10).join(tl_rows)}

> **Timeline Interpretation:** {timeline_interp}

---

## 9. Triage Assessment (Always Present)

- **TP Likelihood:** **{tp_pct}%**
- **Severity:** **{c.severity}**
- **Confidence:** {c.confidence}

**Drivers Toward TRUE POSITIVE**
{self._bullets(c.reasons_tp, fallback="No strong TP drivers identified.")}

**Drivers Toward FALSE POSITIVE / Benign**
{self._bullets(c.reasons_fp, fallback="No strong FP drivers identified.")}

**Proposed Incident Type:** {c.incident_type}
**MITRE ATT&CK:** Tactics {", ".join(c.mitre_tactics) or "N/A"}; Techniques {", ".join(c.mitre_techniques) or "N/A"}

> **Triage Judgment:** {c.triage_judgment}

---

## 10. Similar Cases (Always Present)

| Case ID | Opened (UTC) | Disposition | Overlap | Key Actions Taken |
|--------|--------------|------------|---------|------------------|
{chr(10).join(case_rows)}
{none_line}

---

## 11. Closure Criteria (Always Present)

**Mark as TRUE POSITIVE if**
- Confirmed malicious activity in correlated telemetry tied to the signal/indicator/CVE.
- Host/user shows compromise indicators OR confirmed exploit attempt aligned to the CVE.

**Mark as FALSE POSITIVE / benign if**
- Activity fully explained by authorized change/maintenance with corroborating evidence.
- Indicator/detection/CVE is verified non-applicable or benign in our environment (documented).

**Runbook Reference:** {self._runbook_reference(c.incident_type)}

---

## 12. Stakeholder Snapshot (Always Present but Minimal)

- **Affected business process:** {business_process}
- **Potential impact:** Potential compromise / malicious activity; impact depends on criticality and scope.
- **Customer/external impact:** N/A
- **Compliance notes:** {compliance_notes}

---

## Appendix (Always Present)

### A. Raw Signal Payload
```json
{json.dumps(ctx.signal.raw or {}, indent=2)}
````

"""
return md

```
# Helpers for report
def _summarize_ti(self, ti: Dict[str, Dict[str, Any]]) -> str:
    if not ti:
        return "No TI enrichment available."
    reps = Counter((v.get("reputation") or "unknown").lower() for v in ti.values())
    return "TI reputations: " + ", ".join(f"{k}={v}" for k, v in reps.items())

def _bullets(self, items: List[str], *, fallback: str) -> str:
    if not items:
        return f"- {fallback}"
    return "\n".join(f"- {x}" for x in items)

def _runbook_reference(self, incident_type: str) -> str:
    if "Vulnerability" in incident_type:
        return "RB-VULN-001 Vulnerability Exposure & Exploitation Triage"
    if "PowerShell" in incident_type:
        return "RB-PS-001 Suspicious PowerShell on Endpoint"
    if "IOC-led" in incident_type:
        return "RB-IOC-001 Malicious IOC Triage and Blocking"
    return "RB-GEN-001 Generic Signal Triage"
```

```

```

Gmail Maxavier Jean-Philippe <maxjeanphilippe@gmail.com>
Soc notes
Maxavier Jean-Philippe <maxjeanphilippe@gmail.com> Sun, Dec 14, 2025 at 6:22 PM
To: Max Jeanphilippe <maxjeanphilippe@gmail.com>
Soc agent

Yes — but they’re optional “AI sidecars” inside the deterministic flow, not replacements for the deterministic logic. In Level 1, the safe pattern is: AI can suggest / rank / cluster / extract, while the pipeline still produces the authoritative facts and score.

Here are the main deterministic stages where you can add “AI flavor” without turning it into an action-taking agent:

1. Pre-normalization: extraction + cleanup

AI flavor: help turn messy vendor payloads into clean fields.

    •	Log/message field extraction when formats are inconsistent

    •	Entity extraction from free-text (usernames, hosts, URLs, hashes)

    •	Dedup / near-duplicate detection (“these 30 alerts are the same incident”)

Guardrail: AI outputs are treated like “proposed parse,” then validated (schema checks, regex sanity, required fields).

2. Normalization mapping (vendor-agnostic)

AI flavor: assist mapping vendor-specific fields to your canonical schema.

    •	“This looks like src_ip, this looks like process.parent…”

    •	Useful when onboarding new sources fast

Guardrail: the final mapping is still config-driven; AI can generate a draft mapping that humans approve.

3. Correlation grouping (before scoring)

AI flavor: cluster alerts into “cases” better than rigid keys sometimes can.

    •	Semantic clustering using embeddings over (normalized fields + short narratives)

    •	Helps when “same incident” doesn’t share a perfect join key

Guardrail: clustering affects grouping, not truth. Analysts can split/merge.

4. Enrichment prioritization (not enrichment itself)

AI flavor: decide which enrichments are worth running first and what to highlight.

    •	“Given this pattern, pull IAM + VPN + recent logins”

    •	“This looks like process injection; prioritize EDR process tree”

Guardrail: enrichments are still deterministic API calls; AI only orders or recommends.

5. Scoring support (advisory features, not the score engine)

AI flavor: produce extra signals/features that feed your deterministic scorecard.

    •	“Benign admin tool vs suspicious dual-use” (label with confidence)

    •	“Likely automated scanner vs targeted activity”

    •	“Narrative risk cues” extracted from context (again: as features, not decisions)

Guardrail: deterministic score remains primary; AI features are weighted lightly and can be disabled.

6. Packet generation (the big, obvious one)

You already have this:

    •	Summary + rationale + checklist + suggested queries + similar cases

    •	Evidence-cited narrative

⸻

A simple rule to keep Level 1 sane

If the output can change containment/remediation or declare truth on its own → that’s Level 2/3.

If it improves parsing, grouping, prioritization, summarizing, and suggesting → that’s fair game for Level 1.

If you tell me your current deterministic stages (even just: ingest → normalize → enrich → correlate → score → packet), I’ll map the exact “AI enhancement hooks” into each stage as labeled submodules you can put on a slide.

Yep — Level 1 is exactly “LLM flavor on top of a deterministic triage pipeline,” and you’re also right that an LLM usually won’t beat pure calculations/rules for the parts that are already calculable. So the trick is: don’t use the LLM where math/rules win. Use it where humans currently spend time stitching context into a decision and a write-up.

Level 1: what stays deterministic vs where the LLM goes

Keep 100% deterministic (your 99.9%)

    •	Ingest / normalize / schema mapping

    •	Enrichment pulls (CMDB, IAM, vuln, TI, EDR telemetry, geo, etc.)

    •	Correlation & scoring (rules, thresholds, suppression, allowlists)

    •	Timeline assembly (ordered events + joins)

    •	“Evidence bundle” (raw logs/queries/results, hashes, host/user, process tree, etc.)

This is your “truth layer.”

Add LLM only as an overlay (the “AI label” layer)

You add it after the evidence bundle is complete.

    1.	Executive summary (2–6 bullets)

    •	Turns the evidence into a human-readable “what happened / why it matters.”

    •	Saves analyst time. Doesn’t replace scoring.

    2.	Rationale / explanation of the deterministic score

    •	LLM reads the scorecard + evidence and explains why it’s high/low in plain English.

    •	Useful for handoffs, managers, audits.

    3.	Hypotheses + decision checklist

    •	“To confirm TP vs FP, verify X/Y/Z.”

    •	These are questions to answer, not invented facts.

    4.	Suggested next steps (query/playbook suggestions)

    •	LLM proposes which pre-approved query templates to run next (Splunk SPL, CrowdStrike searches, etc.)

    •	But it should output them as suggestions, or as parameterized templates your deterministic system can render.

    5.	“Similar cases” narrative

    •	Similarity search itself should be deterministic (embeddings + retrieval).

    •	LLM compares: “This looks like Case 1842 because {shared traits}… last time we resolved by {actions}.”

That’s enough to honestly call it “AI-enabled” without pretending it’s doing the hard math.

The key guardrail: LLM can’t add new “truth”

To keep it sane:

    •	Every LLM statement must be traceable to an Evidence ID (log line, query result, enrichment output).

    •	If it can’t cite evidence, it must label it explicitly as Hypothesis or Assumption.

    •	LLM output is advisory, and the deterministic score remains the decision anchor.

This is how you avoid “LLM being dumber than calculations” — it’s not competing with calculations, it’s packaging them.

Where it goes in your packet (so you can literally add an “AI Enhancement” section)

Here’s a packet layout that works well:

A) Deterministic core (what you already do)

    •	Alert metadata (source, rule, time, severity)

    •	Entities (user/host/IP/process/file)

    •	Enrichments (asset criticality, identity risk, vuln context, TI hits)

    •	Timeline

    •	Correlation summary

    •	Deterministic triage score + reasons (scorecard)

B) AI Enhancement (Level 1)

    •	AI Executive Summary (bullet narrative)

    •	AI Explanation of Scorecard (plain English mapping to reasons)

    •	AI TP/FP Likelihood (advisory)

    •	e.g., “Likely FP / Unclear / Likely TP” + rationale + evidence citations

    •	AI Next Checks (no actions)

    •	“Run Query Template Q12 with host=X, timeframe=24h”

    •	AI Similar Cases (top 3 + why they match + what worked)

That’s clean, defensible, and vendor-agnostic.

“But it’s template-based already… what’s the gain?”

Even if your packet is templated, LLM value is usually in:

    •	Compressing 50 lines of context into 5 bullets

    •	Explaining “why this is probably noise” in a way a human trusts

    •	Turning a messy alert + enrichments into a coherent story for handoff/escalation

    •	Suggesting the next 2–3 checks so analysts don’t stall

So the performance gain is mostly time-to-triage and handoff quality, not “smarter math.”

Minimal implementation that still counts as “AI-enabled”

If you want the smallest credible add:

    •	AI Executive Summary

    •	AI Next Checks

    •	Similar Cases

That’s it. Low risk, easy to demo, clearly helpful, doesn’t change your deterministic engine.

If you want, I can write a concrete JSON schema for the packet with an ai_enhancementobject (and the evidence-citation format), so your engineers can implement it without debate.

You’re not wrong. A lot of stakeholders say “agent” when what they actually want is “AI help” and a demoable workflow win.

Here’s the clean way to frame it so you don’t get vendor-locked and you still satisfy the AI narrative.

1. Define “agent” by capability level (so you can say “yes” without overcommitting)

Use a simple maturity ladder:

    •	Level 0 — Deterministic pipeline: normalize → enrich → correlate → score → packet.

    •	Level 1 — LLM-assisted triage (copilot): same pipeline + LLM writes the packet + “similar cases” + suggested next checks. No actions.

    •	Level 2 — Tool-using agent (supervised): LLM can request a small set of allowlisted queries/enrichments; system executes them deterministically; analyst approves.

    •	Level 3 — Autonomous agent: executes containment/remediation. (This is where risk + governance explode.)

What you’re describing is Level 1. If a stakeholder insists on the word “agent,” you can call it an “agentic triage assistant” but be explicit: it is non-actuating (read-only + advisory). That’s a legit “agent” in marketing terms, without the dangerous part.

2. How to stay SIEM/SOAR-agnostic (Splunk, Splunk SOAR, CrowdStrike, etc.)

Don’t build inside Splunk or CrowdStrike. Build a Triage Service that sits next to them.

Core idea: vendor adapters are thin; your logic is vendor-neutral

    •	Inputs: alerts via webhook / syslog / API polling / message bus (Kafka/SQS/etc.)

    •	Normalize: map everything to a canonical schema (OCSF-style or your own “minimal common schema”)

    •	Enrich/Correlate: internal services (CMDB, IAM, vuln, TI, EDR telemetry via adapters)

    •	Outputs: a packet object (JSON) + a human packet (markdown/PDF) + a score

Integration back into tools (without lock-in)

You return results through generic surfaces:

    •	Attach packet to the case/alert (most platforms support adding comments/artifacts/attachments)

    •	Create a ticket (ServiceNow/Jira) if that’s the system of record

    •	Send to a case queue (your own lightweight case UI if needed)

Adapters are just I/O:

    •	Splunk ES notable event in → packet comment/artifact out

    •	Splunk SOAR container in → updated container notes/tasks out

    •	CrowdStrike alert in → add incident note / create case / push to ticketing out

If you ever swap vendors, you only rewrite the adapter, not the brain.

3. Why “agent” is unnecessary until later (and what is useful now)

You nailed it: if it’s “mostly pipeline” and “not taking actions,” then the only “agent” behavior you need is:

    •	Narrative + reasoning: turn evidence into an analyst-ready summary

    •	Similarity: find prior cases and resolutions

    •	Suggestions: “run these queries / validate these facts / check these 3 hypotheses”

That’s a copilot, not a tool-using agent.

The moment you allow it to act (contain host, disable user, block hash), you need:

    •	approval workflows,

    •	strict RBAC,

    •	tool allowlists,

    •	parameter validation,

    •	full audit logging,

    •	and safety controls against prompt injection / bad context.

So the sensible pitch is: Phase 1 delivers time savings safely; Phase 2 adds supervised tool use; Phase 3 is optional and gated.

4. A stakeholder-proof sentence you can use

“We’re delivering an AI-enabled triage assistant that automatically generates a standardized investigation packet and recommended next steps across any SIEM/SOAR. It’s vendor-agnostic because it runs as an external triage service with thin adapters. No autonomous actions in phase 1—only evidence-backed summaries and suggestions.”

5. Practical architecture choice (minimal regret)

   • Do headless auto-packet generation by default (every alert gets one).

   • Add an optional chat only as a drill-down UI (“why did you say this is likely FP?”, “show similar incidents”), not as the primary workflow.

That way you satisfy the “agent” crowd without forcing analysts to chat just to do their job.

If you want, I can sketch a concrete “packet schema” (fields + evidence links + scoring + suggested queries) that you can plug into Splunk SOAR containers and CrowdStrike cases with the same output.

Maxavier — you’re thinking about this the right way: a SOC triage “packet generator” is already a mostly deterministic pipeline. AI only earns its keep in the spots where (a) humans burn time, (b) rules don’t generalize well across vendors/signals, or (c) the “last mile” is writing/deciding under uncertainty.

Where AI actually moves the needle (and where it doesn’t)

Keep these deterministic (high confidence, low ROI for GenAI)

    •	Ingest / parse / normalize (schemas, field mapping, timestamps, IDs)

    •	Known enrichments (CMDB/asset criticality, IAM context, vuln context, TI lookups)

    •	Hard correlation rules (same host/user/hash, known campaign logic, suppression lists)

    •	Evidence capture (what happened, where, when, raw artifacts)

If you let an LLM “invent” structure or evidence, you’ll hate your life during audits and incident reviews.

Add AI here (highest ROI)

    1.	“Find similar cases” (semantic retrieval / embeddings)

    •	This is a perfect AI use: cluster noisy alerts, link to prior incidents, and surface “what solved this last time.”

    •	Helps vendor-agnostic triage because similarity can be based on normalized attributes + narrative artifacts.

    2.	Packet drafting (LLM summarization with citations to evidence)

    •	Turn the deterministic evidence bundle into a clean “story”: what triggered, key artifacts, likely hypothesis, and recommended next checks.

    •	Important: the LLM should only summarize retrieved evidence (and link every claim to a source field/log/query result).

    3.	TP/FP probability score as an advisory signal (not the decider)

    •	Use a classifier (could be ML, could be LLM-as-judge with guardrails) that outputs: likelihood + reasons + top features.

    •	Then combine with your deterministic scorecard. AI influences priority; it doesn’t “declare truth.”

    4.	Next-best-action recommendations (playbook selection)

    •	AI proposes which playbook + which queries to run next, but execution stays controlled/deterministic (SOAR steps, RBAC, approvals).

Expected gains (realistic, not hype)

    •	The biggest measurable improvement is usually analyst time per alert and MTTR, because the system pre-assembles context and writes the narrative.

    •	There’s published evidence in live SOC operations showing GenAI tooling adoption associated with a ~30% reduction in MTTR in a Microsoft Security Copilot analysis (difference-in-differences) — your mileage will vary, but it’s a credible order-of-magnitude target if you instrument properly.

Is a “chatbot with sessions” redundant if packets are auto-generated?

Not redundant — but it shouldn’t be the primary interface.

The clean pattern is:

    •	Push mode (default): every signal → auto-triage → packet attached to the alert/case (and optionally an auto-suppression/escalation decision when confidence is high).

    •	Pull mode (when needed): analyst clicks “Ask follow-ups” to:

    •	drill into why it scored TP/FP,

    •	request one more enrichment,

    •	run a safe query (“show last 24h DNS for host X”),

    •	compare with similar cases.

So the “agent” can be headless most of the time, and interactive only when an analyst wants to pivot. Same backend, two front-ends.

“Agentic” concerns (server-based + security)

If stakeholders want “agentic,” be careful: tool-using agents create real risk (prompt injection, confused deputy, over-permissioned actions). UK NCSC explicitly warns prompt injection is structurally different from SQL injection and should be treated like an inherently confusable deputy problem. OWASP also ranks Prompt Injection as a top LLM risk.

That doesn’t mean “don’t do it.” It means:

    •	Treat LLM output as untrusted.

    •	Put deterministic gates in front of actions (RBAC, allowlisted tools, parameter validation, human approval for destructive steps).

    •	Maintain a full audit log of tool calls, prompts, retrieved evidence, and final packet.

    •	Follow an AI risk framework (NIST AI RMF is a solid baseline for governance).

Vendor-agnostic diagnostic: do this first

To truly be “signal agnostic,” normalize into a common schema (OCSF is designed for vendor-agnostic security event representation).

Once everything is in a canonical shape, both deterministic rules and AI similarity search work way better.

If you need to satisfy the “Magenta minimum” without overbuilding

If “Magenta” is basically “we need an AI platform/on-prem model pipeline,” you can meet the requirement with an augmentation layer:

    •	ingest → normalize (OCSF) → deterministic enrich/correlate → AI packet writer + similar-case retrieval → output packet + score

…and keep “agentic actions” as a later phase.

That gives stakeholders visible AI value without making your core detection/triage correctness depend on a model.

⸻
