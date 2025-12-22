# Service & Adapter Audit Report

**Date**: 2024-12-22
**Purpose**: Identify redundancies between services/adapters and ensure proper dependency injection

---

## 🔍 Key Findings

### ❌ **CRITICAL ISSUE: Repeated Adapter Instantiation**

**Problem**: Adapters are instantiated **3+ times** across the codebase:

1. In CLI (`cli.py` line ~200)
2. In API (`api.py` line ~30)
3. In TriageService constructor (implicitly via default parameters)
4. Every test file

**Impact**:

- Connection pools created multiple times
- Configuration inconsistency
- Memory waste
- No centralized health monitoring

### ❌ **Service Instantiation Anti-Pattern**

**Problem**: Services instantiate their own dependencies with `or` pattern:

```python
self.forecasting_service = forecasting_service or ForecastingService()
self.classification_service = classification_service or ClassificationService()
```

**Issues**:

- Tight coupling
- Difficult to test
- Configuration not shared
- Duplicate instances created

### ⚠️ **Service-to-Adapter Relationships**

| Service                       | Adapters Used                              | Relationship Status                      |
| ----------------------------- | ------------------------------------------ | ---------------------------------------- |
| **EnrichmentService**         | All 5 adapters (SIEM, EDR, TI, Vuln, CMDB) | ✅ Correct - parallel enrichment         |
| **SourceHydrator**            | SIEM, SOAR adapters                        | ✅ Correct - fetch missing payload       |
| **HistoricalDataService**     | Capable adapters only                      | ✅ Correct - filtered subset             |
| **CaseContextLinkingService** | SOAR adapter                               | ✅ Correct - case similarity             |
| **ClassificationService**     | None directly                              | ✅ Correct - consumes enrichment results |
| **ActionProposalService**     | None directly                              | ✅ Correct - uses RunbookRegistry        |
| **RunbookRegistry**           | SOAR adapter                               | ✅ Correct - fetch runbooks              |

**No Service-Adapter Redundancy Found** ✅

---

## ✅ Services Without Redundancy Issues

### CKG Services (Stateless/Config-only)

- **CaseBootstrapService**: No external deps
- **CanonicalizeService**: Config only
- **FetchPlanner**: Stateless logic
- **GovernanceGate**: Config only

### Processing Services

- **ForecastingService**: Stateless ETS calculations
- **ReportService**: Template rendering only
- **SignalRouter**: Stateless parsing logic

---

## 🎯 Recommended Solution: **Service Container Pattern**

### Benefits

1. **Single source of truth** for all adapters/services
2. **Shared configuration** across CLI/API/tests
3. **Easy testing** with mock injection
4. **Lifecycle management** (startup/shutdown)
5. **Health monitoring** centralized

### Implementation Plan

```python
# New file: soc_triage_bot/container.py

class ServiceContainer:
    """Centralized dependency injection container."""

    def __init__(self, config: Optional[Settings] = None):
        self.config = config or get_settings()

        # Adapters (singleton instances)
        self._adapters = None
        self._siem_adapter = None
        self._edr_adapter = None
        self._ti_adapter = None
        self._vuln_adapter = None
        self._cmdb_adapter = None
        self._soar_adapter = None

        # Services (singleton instances)
        self._enrichment_service = None
        self._classification_service = None
        self._forecasting_service = None
        self._action_proposal_service = None
        # ... etc

        self._triage_service = None

    @property
    def adapters(self) -> List[BaseAdapter]:
        """Get all enrichment adapters."""
        if self._adapters is None:
            self._adapters = [
                self.siem_adapter,
                self.edr_adapter,
                self.ti_adapter,
                self.vuln_adapter,
                self.cmdb_adapter,
            ]
        return self._adapters

    @property
    def siem_adapter(self) -> SIEMAdapter:
        if self._siem_adapter is None:
            self._siem_adapter = SIEMAdapter(config=self.config.siem)
        return self._siem_adapter

    # ... similar for other adapters

    @property
    def enrichment_service(self) -> EnrichmentService:
        if self._enrichment_service is None:
            self._enrichment_service = EnrichmentService(self.adapters)
        return self._enrichment_service

    @property
    def triage_service(self) -> TriageService:
        if self._triage_service is None:
            self._triage_service = TriageService(
                enrichment_service=self.enrichment_service,
                classification_service=self.classification_service,
                forecasting_service=self.forecasting_service,
                action_proposal_service=self.action_proposal_service,
                # ... all other services
            )
        return self._triage_service

    async def startup(self):
        """Initialize connections."""
        for adapter in self.adapters:
            if hasattr(adapter, 'connect'):
                await adapter.connect()

    async def shutdown(self):
        """Close connections."""
        for adapter in self.adapters:
            if hasattr(adapter, 'close'):
                await adapter.close()
```

### Usage in CLI

```python
# Instead of instantiating everything manually:
container = ServiceContainer()
await container.startup()

result = await container.triage_service.triage_extended(signal)

await container.shutdown()
```

### Usage in API

```python
# At startup
container = ServiceContainer()

@app.on_event("startup")
async def startup():
    await container.startup()

@app.on_event("shutdown")
async def shutdown():
    await container.shutdown()

@app.post("/triage")
async def triage_signal(signal: Signal):
    result = await container.triage_service.triage_extended(signal)
    return result
```

### Usage in Tests

```python
# Easy mocking
container = ServiceContainer()
container._siem_adapter = MockSIEMAdapter()
container._edr_adapter = MockEDRAdapter()

triage_service = container.triage_service  # Uses mocks
```

---

## 📋 Action Items

### High Priority

1. ✅ **Create `container.py`** with ServiceContainer class
2. ✅ **Update CLI** to use container
3. ✅ **Update API** to use container
4. ✅ **Update TriageService** to remove `or` pattern defaults
5. ✅ **Add container to tests**

### Medium Priority

6. Add health check aggregation to container
7. Add metrics collection hooks
8. Add configuration validation at startup
9. Document container usage patterns

### Low Priority

10. Add hot-reload support for config changes
11. Add adapter pool sizing configuration
12. Add request-scoped containers for multi-tenant

---

## 🔄 Migration Path

### Phase 1: Create Container (Non-Breaking)

- Add `container.py` alongside existing code
- CLI/API can opt-in to use it
- Existing instantiation still works

### Phase 2: Update Entry Points

- CLI uses container
- API uses container
- Tests use container

### Phase 3: Remove Defaults (Breaking)

- Remove `or Service()` patterns from TriageService
- Force explicit injection
- Update documentation

---

## 📊 Current Service Dependency Graph

```
CLI/API
  └─> TriageService
       ├─> EnrichmentService
       │    └─> [SIEM, EDR, TI, Vuln, CMDB] Adapters
       ├─> ClassificationService
       ├─> ForecastingService
       ├─> ActionProposalService
       │    ├─> RunbookRegistry
       │    │    └─> SOAR Adapter
       │    └─> CaseArtifactHarvester
       │         └─> SOAR Adapter
       ├─> ReportService
       ├─> AIService (optional)
       ├─> HistoricalDataService (optional)
       │    └─> [Capable Adapters]
       ├─> CaseBootstrapService
       ├─> CanonicalizeService
       ├─> SourceHydrator
       │    └─> [SIEM, SOAR] Adapters
       ├─> FetchPlanner
       ├─> GovernanceGate
       └─> CaseContextLinkingService
            └─> SOAR Adapter
```

**Issue**: Adapters instantiated at **3 different points** in this tree!

---

## ✅ Conclusion

**No service-to-service redundancy exists.** Each service has a clear, distinct purpose.

**Critical issue**: Adapter instantiation is **repeated** across entry points, causing:

- Wasted resources
- Configuration drift
- Testing difficulties

**Solution**: Implement **ServiceContainer** for centralized dependency injection.

**Estimated effort**: 4-6 hours for full implementation + testing
