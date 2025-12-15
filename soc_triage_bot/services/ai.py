"""AI Service for generating AI overlays on triage reports.

Provides LLM-powered insights for each section of the triage report.
Supports multiple providers (OpenAI, Anthropic, Ollama) via adapter pattern.
Falls back to mock data when AI is disabled.
"""

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from ..adapters.ai_provider import (
    AIProviderConfig,
    AIResponse,
    BaseAIProvider,
    MockProvider,
    get_provider,
)
from ..config.settings import AISettings, get_settings
from ..models import Signal
from ..models.ai_overlay import (
    AINextCheck,
    AIOverlay,
    AISimilarCaseNarrative,
    AIStatement,
    AITrackInterpretation,
    StatementType,
    TPFPLikelihood,
)
from ..models.triage_report import TriageReport

logger = logging.getLogger(__name__)


@dataclass
class PromptConfig:
    """Configuration for a single prompt template."""

    description: str
    template: str
    max_tokens: int = 250


class PromptsLoader:
    """Loads and caches prompt templates from YAML."""

    _instance: Optional["PromptsLoader"] = None
    _prompts: Optional[Dict[str, PromptConfig]] = None
    _version: str = "unknown"
    _system_prompt: str = ""

    def __new__(cls) -> "PromptsLoader":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def load(
        self, prompts_path: Optional[Path] = None, force_reload: bool = False
    ) -> Dict[str, PromptConfig]:
        """Load prompts from YAML file.

        Args:
            prompts_path: Path to prompts YAML file
            force_reload: Force reload even if cached

        Returns:
            Dictionary of prompt name to PromptConfig
        """
        if self._prompts is not None and not force_reload:
            return self._prompts

        if prompts_path is None:
            prompts_path = (
                Path(__file__).parent.parent
                / "config"
                / "prompts"
                / "overlay_prompts.yaml"
            )

        if not prompts_path.exists():
            logger.warning(f"Prompts file not found: {prompts_path}, using defaults")
            self._prompts = {}
            self._version = "default"
            self._system_prompt = "You are a security analyst AI assistant."
            return self._prompts

        with open(prompts_path) as f:
            data = yaml.safe_load(f)

        self._version = data.get("version", "unknown")
        self._system_prompt = data.get(
            "system_prompt", "You are a security analyst AI assistant."
        )

        prompts_data = data.get("prompts", {})
        self._prompts = {}

        for name, config in prompts_data.items():
            self._prompts[name] = PromptConfig(
                description=config.get("description", ""),
                template=config.get("template", ""),
                max_tokens=config.get("max_tokens", 250),
            )

        logger.info(f"Loaded {len(self._prompts)} prompts, version {self._version}")
        return self._prompts

    @property
    def version(self) -> str:
        """Get prompts version."""
        if self._prompts is None:
            self.load()
        return self._version

    @property
    def system_prompt(self) -> str:
        """Get system prompt."""
        if self._prompts is None:
            self.load()
        return self._system_prompt


class AIService:
    """Service for generating AI overlays on triage reports.

    When enabled, uses configured LLM provider to generate insights.
    When disabled, returns mock/placeholder data.
    """

    def __init__(
        self,
        provider: Optional[BaseAIProvider] = None,
        settings: Optional[AISettings] = None,
        prompts_path: Optional[Path] = None,
    ):
        """Initialize AI service.

        Args:
            provider: AI provider instance (optional, created from settings)
            settings: AI settings (optional, loaded from environment)
            prompts_path: Path to prompts YAML (optional, uses default)
        """
        self.settings = settings or get_settings().ai
        self.prompts_loader = PromptsLoader()
        self.prompts = self.prompts_loader.load(prompts_path)

        # Initialize provider
        if provider is not None:
            self.provider = provider
        elif self.settings.enabled:
            config = AIProviderConfig(
                provider_name=self.settings.provider,
                model=self.settings.model,
                api_key_env=self.settings.api_key_env,
                endpoint=self.settings.endpoint,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
                timeout_seconds=self.settings.timeout_seconds,
            )
            self.provider = get_provider(config)
        else:
            self.provider = MockProvider()

        # Cache stub (placeholder for future SQLite/Redis implementation)
        self._cache_enabled = self.settings.cache_enabled
        self._cache: Dict[str, AIResponse] = {}  # In-memory cache for POC

    @property
    def enabled(self) -> bool:
        """Check if AI generation is enabled."""
        return self.settings.enabled

    @classmethod
    def from_settings(cls, settings=None) -> "AIService":
        """Create AIService from settings.

        Args:
            settings: AISettings or AppSettings (uses environment if not provided)

        Returns:
            Configured AIService instance
        """
        from ..config.settings import AISettings, AppSettings

        if settings is None:
            ai_settings = get_settings().ai
        elif isinstance(settings, AppSettings):
            ai_settings = settings.ai
        elif isinstance(settings, AISettings):
            ai_settings = settings
        else:
            ai_settings = get_settings().ai

        return cls(settings=ai_settings)

    async def generate_overlay(
        self,
        triage_report: TriageReport,
        signal: Optional[Signal] = None,
    ) -> AIOverlay:
        """Generate AI overlay for a triage report.

        Args:
            triage_report: The assembled triage report
            signal: Optional original signal for additional context

        Returns:
            AIOverlay with generated insights for each section
        """
        if not self.settings.enabled:
            logger.debug("AI service disabled, returning mock overlay")
            return self.create_mock_overlay(triage_report, signal)

        # Build context for prompt templates
        context = self._build_prompt_context(triage_report, signal)

        # Generate each section
        try:
            overlay = await self._generate_all_sections(context)
            return overlay
        except Exception as e:
            logger.error(f"AI generation failed: {e}, falling back to mock")
            return self.create_mock_overlay(triage_report, signal)

    async def _generate_all_sections(self, context: Dict[str, Any]) -> AIOverlay:
        """Generate all overlay sections using LLM.

        Args:
            context: Template context dictionary

        Returns:
            Populated AIOverlay
        """
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

        # Banner
        tp_fp_rationale = await self._generate_section("banner_risk_statement", context)

        # Section 1 - Summary (executive_summary_statements)
        summary_text = await self._generate_section("section_1_summary", context)

        # Section 2 - Actions (next_checks) - parsed separately
        # Actions would require structured parsing; for now generate description
        actions_desc = await self._generate_section("section_2_actions", context)

        # Section 3 - Context
        context_interp = await self._generate_section("section_3_context", context)
        entity_confidence = await self._generate_section(
            "section_3_behavioral", context
        )

        # Section 4 - Correlation
        scope_interp = await self._generate_section("section_4_correlation", context)
        correlation_insight = await self._generate_section("section_4_pattern", context)

        # Section 5 - Threat Intel
        enrichment_interp = await self._generate_section(
            "section_5_ti_analysis", context
        )
        evidence_citation = await self._generate_section(
            "section_5_attribution", context
        )

        # Section 6 - Exposure
        exposure_interp = await self._generate_section("section_6_exposure", context)
        exploit_likelihood = await self._generate_section(
            "section_6_blast_radius", context
        )

        # Section 7 - Trend
        trend_interp = await self._generate_section("section_7_trend", context)
        trend_concerns_text = await self._generate_section("section_7_anomaly", context)

        # Section 8 - Timeline
        timeline = await self._generate_section("section_8_timeline", context)
        attack_hypothesis = await self._generate_section("section_8_gaps", context)

        # Section 9 - Assessment
        scorecard_explanation = await self._generate_section(
            "section_9_assessment", context
        )
        hypotheses_text = await self._generate_section("section_9_tp_reasons", context)
        checklist_text = await self._generate_section("section_9_fp_reasons", context)

        # Section 10 - Similar Cases - would require structured parsing
        # Section 11 - Closure
        closure_guidance = await self._generate_section("section_11_criteria", context)
        tp_steps = await self._generate_section("section_11_evidence", context)
        fp_steps = await self._generate_section("section_11_next_check", context)

        # Section 12 - Stakeholder
        business_impact = await self._generate_section(
            "section_12_stakeholder", context
        )
        risk_comms = await self._generate_section("section_12_comms", context)

        # Section 13 - Data Quality
        quality_observations = await self._generate_section(
            "section_13_quality", context
        )
        caveats = await self._generate_section("section_13_gaps", context)

        return AIOverlay(
            # Banner
            tp_fp_likelihood=TPFPLikelihood.UNCLEAR,  # Default, would be parsed from LLM
            tp_fp_rationale=tp_fp_rationale,
            # Section 1 - Executive Summary
            executive_summary_statements=[
                AIStatement(
                    text=summary_text,
                    statement_type=StatementType.OBSERVATION,
                    evidence_ids=[],
                )
            ],
            # Section 2 - Next Checks
            next_checks=[
                AINextCheck(
                    query_template_id="QT-GEN-001",
                    description=actions_desc or "Follow recommended actions",
                    target_system="SIEM",
                    parameters={},
                )
            ],
            # Section 3 - Context Interpretation
            context_interpretation=context_interp,
            entity_extraction_confidence=entity_confidence,
            indicator_context=[],
            # Section 4 - Scope/Correlation
            scope_interpretation=scope_interp,
            correlation_insights=[correlation_insight] if correlation_insight else [],
            # Section 5 - Threat Intel
            enrichment_interpretation=enrichment_interp,
            tp_fp_evidence_citations=[evidence_citation] if evidence_citation else [],
            # Section 6 - Exposure
            exposure_interpretation=exposure_interp,
            exploit_likelihood_assessment=exploit_likelihood,
            # Section 7 - Trend
            trend_interpretation=trend_interp,
            trend_concerns=[trend_concerns_text] if trend_concerns_text else [],
            track_interpretations=[],
            # Section 8 - Timeline
            timeline_narrative=timeline,
            attack_chain_hypothesis=attack_hypothesis,
            # Section 9 - Assessment
            scorecard_explanation=scorecard_explanation,
            scorecard_evidence_ids=[],
            hypotheses=[hypotheses_text] if hypotheses_text else [],
            decision_checklist=[checklist_text] if checklist_text else [],
            # Section 10 - Similar Cases
            similar_case_narratives=[],
            # Section 11 - Closure
            closure_guidance=closure_guidance,
            tp_verification_steps=[tp_steps] if tp_steps else [],
            fp_verification_steps=[fp_steps] if fp_steps else [],
            similar_case_closure_patterns=[],
            # Section 12 - Stakeholder
            business_impact_summary=business_impact,
            risk_communication=risk_comms,
            # Section 13 - Data Quality
            data_quality_observations=(
                [quality_observations] if quality_observations else []
            ),
            confidence_caveats=[caveats] if caveats else [],
            # Metadata
            model_version=f"{self.settings.provider}/{self.settings.model}",
            generation_timestamp=now.isoformat(),
        )

    async def _generate_section(self, prompt_name: str, context: Dict[str, Any]) -> str:
        """Generate a single section using the LLM.

        Args:
            prompt_name: Name of the prompt template
            context: Template context dictionary

        Returns:
            Generated text or fallback message
        """
        prompt_config = self.prompts.get(prompt_name)
        if prompt_config is None:
            logger.warning(f"Prompt not found: {prompt_name}")
            return f"[AI: No prompt template for {prompt_name}]"

        # Format the prompt with context
        try:
            prompt = prompt_config.template.format(**context)
        except KeyError as e:
            logger.warning(f"Missing context key for {prompt_name}: {e}")
            prompt = prompt_config.template

        # Check cache
        cache_key = self._get_cache_key(prompt_name, context)
        if self._cache_enabled and cache_key in self._cache:
            logger.debug(f"Cache hit for {prompt_name}")
            return self._cache[cache_key].content

        # Generate
        try:
            response = await self.provider.generate(
                prompt=prompt,
                system_prompt=self.prompts_loader.system_prompt,
            )

            # Cache result
            if self._cache_enabled:
                self._cache[cache_key] = response

            return response.content
        except Exception as e:
            logger.error(f"Generation failed for {prompt_name}: {e}")
            return f"[AI: Generation failed - {str(e)[:50]}]"

    def _build_prompt_context(
        self, triage_report: TriageReport, signal: Optional[Signal] = None
    ) -> Dict[str, Any]:
        """Build context dictionary for prompt templates.

        Args:
            triage_report: The triage report
            signal: Optional original signal

        Returns:
            Context dictionary with all template variables
        """
        # Extract key data from triage report
        context: Dict[str, Any] = {
            "signal_id": triage_report.signal.id if triage_report.signal else "unknown",
            "signal_type": (
                triage_report.signal.type if triage_report.signal else "unknown"
            ),
            "signal_name": (
                triage_report.signal.name if triage_report.signal else "Unknown Signal"
            ),
            "signal_source": (
                triage_report.signal.source if triage_report.signal else "unknown"
            ),
            "signal_timestamp": (
                triage_report.signal.timestamp_utc
                if triage_report.signal
                else "unknown"
            ),
        }

        # Classification
        if triage_report.classification:
            context["classification_disposition"] = (
                triage_report.classification.disposition
            )
            context["classification_confidence"] = (
                triage_report.classification.tp_likelihood
            )
        else:
            context["classification_disposition"] = "Unknown"
            context["classification_confidence"] = 0.5

        # Context/entities
        if triage_report.ctx:
            ctx_dict = {
                "hostname": triage_report.ctx.hostname,
                "username": triage_report.ctx.username,
                "src_ip": triage_report.ctx.src_ip,
                "dst_ip": triage_report.ctx.dst_ip,
                "alert_rule": triage_report.ctx.alert_rule,
            }
            context["entities_json"] = json.dumps(
                {k: v for k, v in ctx_dict.items() if v}, indent=2
            )
            context["context_json"] = json.dumps(ctx_dict, indent=2)
        else:
            context["entities_json"] = "{}"
            context["context_json"] = "{}"

        # Enrichments summary
        if triage_report.enrich:
            enrich_parts = []
            if triage_report.enrich.ti_summary:
                enrich_parts.append(f"TI: {triage_report.enrich.ti_summary}")
            if triage_report.enrich.asset_context:
                enrich_parts.append("Asset context available")
            if triage_report.enrich.correlation_summary:
                enrich_parts.append(triage_report.enrich.correlation_summary)
            context["enrichments_summary"] = "; ".join(enrich_parts) or "No enrichments"
        else:
            context["enrichments_summary"] = "No enrichments available"

        # Similar cases summary
        if triage_report.similar_cases:
            cases_summary = []
            for case in triage_report.similar_cases[:3]:
                cases_summary.append(
                    f"{case.case_id[:8]} ({case.similarity:.0%} match, {case.outcome})"
                )
            context["similar_cases_summary"] = ", ".join(cases_summary)
        else:
            context["similar_cases_summary"] = "No similar cases found"

        # Forecast summary
        if triage_report.forecast and triage_report.forecast.enabled:
            forecast_parts = []
            if triage_report.forecast.tracks.rule:
                forecast_parts.append(
                    f"Rule track: {triage_report.forecast.tracks.rule.metric_name or 'Rule frequency'}"
                )
            if triage_report.forecast.tracks.ioc:
                forecast_parts.append(
                    f"IOC track: {triage_report.forecast.tracks.ioc.metric_name or 'IOC sightings'}"
                )
            if triage_report.forecast.tracks.entity:
                forecast_parts.append(
                    f"Entity track: {triage_report.forecast.tracks.entity.metric_name or 'Entity behavior'}"
                )
            context["forecast_summary"] = (
                "; ".join(forecast_parts) or "Forecast data available"
            )
        else:
            context["forecast_summary"] = "Forecasting not enabled"

        return context

    def _get_cache_key(self, prompt_name: str, context: Dict[str, Any]) -> str:
        """Generate cache key for a prompt + context combination.

        Args:
            prompt_name: Name of the prompt
            context: Context dictionary

        Returns:
            Cache key string
        """
        # Use relevant context fields for cache key
        key_parts = [
            prompt_name,
            context.get("signal_id", ""),
            context.get("classification_disposition", ""),
            str(context.get("classification_confidence", "")),
            self.prompts_loader.version,
        ]
        content = "|".join(key_parts)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def create_mock_overlay(
        self,
        triage_report: Optional[TriageReport] = None,
        signal: Optional[Signal] = None,
    ) -> AIOverlay:
        """Create a fully populated AI overlay for testing/demo.

        This provides realistic, detailed mock content suitable for demos
        and testing. All 13 sections are populated with coherent,
        interconnected content that tells a complete attack story.

        Args:
            triage_report: Optional triage report for context
            signal: Optional signal for context

        Returns:
            AIOverlay with comprehensive demo content
        """
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)

        return AIOverlay(
            model_version="GPT-4o (2024-12-14)",
            generation_timestamp=now.isoformat() + "Z",
            tp_fp_likelihood=TPFPLikelihood.LIKELY_TP,
            tp_fp_rationale=(
                "Multi-source TI correlation (3/3 indicators malicious), Cobalt Strike signature match, "
                "and timeline consistency with known attack chain strongly support TRUE POSITIVE disposition. "
                "Developer context is the only FP driver, but does not explain C2 communication or Mimikatz activity."
            ),
            executive_summary_statements=[
                AIStatement(
                    text="Active Cobalt Strike compromise detected on engineering workstation with confirmed credential theft.",
                    statement_type=StatementType.EVIDENCE_BACKED,
                    evidence_ids=["E-001", "E-003", "E-004"],
                ),
                AIStatement(
                    text="Attack chain shows 6-hour progression from initial C2 contact to lateral movement.",
                    statement_type=StatementType.EVIDENCE_BACKED,
                    evidence_ids=["E-002", "E-005"],
                ),
                AIStatement(
                    text="Initial access was likely via phishing email, consistent with similar case CASE-2024-0892.",
                    statement_type=StatementType.HYPOTHESIS,
                    evidence_ids=["E-006"],
                ),
                AIStatement(
                    text="Scope may extend beyond 3 identified hosts - additional lateral movement possible.",
                    statement_type=StatementType.ASSUMPTION,
                    evidence_ids=[],
                ),
            ],
            next_checks=[
                AINextCheck(
                    query_template_id="QT-DNS-001",
                    description="Find all hosts communicating with suspicious-domain.com",
                    target_system="Splunk",
                    parameters={
                        "domain": "suspicious-domain.com",
                        "timeframe": "-24h",
                        "source": "dns",
                    },
                ),
                AINextCheck(
                    query_template_id="QT-EDR-002",
                    description="Find all hosts with Cobalt Strike hash",
                    target_system="CrowdStrike",
                    parameters={
                        "hash": "abc123def456789012345678901234567890abcdef",
                        "timeframe": "-7d",
                    },
                ),
                AINextCheck(
                    query_template_id="QT-AD-003",
                    description="Review jsmith account activity for anomalous logins",
                    target_system="Active Directory",
                    parameters={
                        "username": "jsmith",
                        "timeframe": "-72h",
                        "event_types": "4624,4625,4648",
                    },
                ),
            ],
            # §3 Context Interpretation
            context_interpretation=(
                "Signal contains high-quality structured data from Splunk SIEM alert. "
                "Primary entity (WORKSTATION-042) is clearly identified with associated user (jsmith). "
                "All three indicator types (IP, domain, hash) are present and correlated. "
                "CVEs extracted from vulnerability context are directly relevant to the attack chain."
            ),
            entity_extraction_confidence="HIGH: All primary entities clearly identified from structured SIEM fields",
            indicator_context=[
                "IP 10.0.0.5 is external C2 infrastructure",
                "Domain suspicious-domain.com is freshly registered (5 days ago)",
                "Hash matches known Cobalt Strike loader variant",
            ],
            # §4 Scope/Correlation
            scope_interpretation=(
                "Current evidence suggests limited scope (3 hosts), but lateral movement timeline indicates "
                "attacker had 6 hours of access. SMB connections to additional hosts not yet fully investigated."
            ),
            correlation_insights=[
                "C2 domain first seen in environment 6 hours ago - suggests fresh campaign",
                "Beacon pattern matches known Cobalt Strike malleable C2 profile",
                "Credential dump followed by RDP to DC suggests privilege escalation attempt",
            ],
            # §5 Threat Intel
            tp_fp_evidence_citations=[
                "[E-001] IP 10.0.0.5 malicious in VirusTotal (48/92), AbuseIPDB (100% confidence), OTX (APT29 campaign)",
                "[E-002] Domain suspicious-domain.com registered 5 days ago via NameCheap, WHOIS privacy enabled",
                "[E-003] File hash matches Cobalt Strike loader (Hybrid Analysis, 42/72 detections)",
                "[E-004] Process injection pattern matches T1055 (MITRE ATT&CK)",
                "[E-005] lsass.exe memory access matches Mimikatz credential dumping (T1003.001)",
            ],
            enrichment_interpretation=(
                "All three indicators (IP, domain, hash) confirmed malicious across multiple TI sources. "
                "This is not a new/unknown threat - infrastructure is linked to known APT29 campaigns."
            ),
            # §6 Exposure
            exposure_interpretation=(
                "WORKSTATION-042 has CVE-2024-1234 (AMSI bypass) which may have allowed the encoded PowerShell "
                "to execute without detection. This vulnerability affects 127 other workstations in the environment."
            ),
            exploit_likelihood_assessment=(
                "HIGH: CVE-2024-1234 is actively exploited in the wild and present on affected host. "
                "Likely contributed to attack success."
            ),
            # §7 Trend/Forecast
            trend_interpretation=(
                "Triple-track spike (Rule + IOC + Entity all elevated) is rare and historically "
                "correlates with 95% TP rate. This pattern indicates coordinated attack activity, "
                "not noise or isolated anomaly."
            ),
            trend_concerns=[
                "Triple-track spike pattern is rare and historically correlates with 95% TP rate",
                "IOC is new to environment - no baseline, so spike thresholds may be conservative",
            ],
            track_interpretations=[
                AITrackInterpretation(
                    track_name="rule",
                    interpretation="5.2x spike above baseline indicates rule is triggering on active attack, not noise",
                    concerns=["May need to hunt for similar alerts in last 6 hours"],
                    evidence_ids=["E-001"],
                ),
                AITrackInterpretation(
                    track_name="ioc",
                    interpretation="IOC sightings accelerating - 8 in last hour vs 0 yesterday",
                    concerns=["New campaign targeting organization?"],
                    evidence_ids=["E-002"],
                ),
                AITrackInterpretation(
                    track_name="entity",
                    interpretation="Host behavior highly anomalous - 4.1x above typical developer activity",
                    concerns=["Other developer workstations may be targeted"],
                    evidence_ids=["E-003"],
                ),
            ],
            # §8 Timeline
            timeline_narrative=(
                "Attack timeline reconstructed from correlated events shows clear kill chain progression:\n\n"
                "1. **T-6h15m**: Initial C2 contact via DNS to suspicious-domain.com\n"
                "2. **T-5h45m**: Beacon check-in via HTTPS POST (4.2KB payload)\n"
                "3. **T-4h30m**: Encoded PowerShell spawned from explorer.exe (detection event)\n"
                "4. **T-3h15m**: Credential harvesting via Mimikatz (lsass access)\n"
                "5. **T-2h45m**: Lateral movement attempt to DC via RDP\n"
                "6. **T-1h30m**: Confirmed lateral movement to WORKSTATION-089 via SMB"
            ),
            attack_chain_hypothesis=(
                "Based on timeline and TTP analysis, this appears to be a standard APT compromise pattern:\n\n"
                "**Initial Access**: Likely phishing email (similar to CASE-2024-0892)\n"
                "**Execution**: Encoded PowerShell (T1059.001) exploiting AMSI bypass\n"
                "**Persistence**: Cobalt Strike beacon (checking in every 30 min)\n"
                "**Credential Access**: Mimikatz (T1003.001) for domain credential theft\n"
                "**Lateral Movement**: RDP/SMB to additional hosts\n\n"
                "**Current Stage**: Active lateral movement - attacker likely has domain admin or is attempting to obtain."
            ),
            # §9 Assessment
            scorecard_explanation=(
                "TP likelihood of 87% is driven by:\n"
                "- TI match score: +35% (3/3 indicators malicious, high confidence)\n"
                "- Attack pattern match: +25% (Cobalt Strike signature confirmed)\n"
                "- ETS anomaly: +15% (triple-track spike, 95th percentile)\n"
                "- Similar case match: +12% (92% similarity to confirmed TP)\n\n"
                "FP discount: -13% for developer context and elevated privileges baseline."
            ),
            scorecard_evidence_ids=[
                "E-001",
                "E-002",
                "E-003",
                "E-004",
                "E-005",
                "E-006",
            ],
            hypotheses=[
                "Initial access was via phishing email with malicious attachment (consistent with similar case)",
                "Attacker may have domain admin credentials - RDP to DC is concerning",
                "Additional hosts beyond the 3 identified may be compromised",
                "Data exfiltration may have occurred but not yet detected",
            ],
            decision_checklist=[
                "Confirm jsmith did not intentionally run the encoded PowerShell (interview user)",
                "Verify WORKSTATION-089 and SERVER-DC01 are not already compromised",
                "Check for data exfiltration indicators in proxy/DLP logs",
                "Confirm no unauthorized access to source code repositories",
                "Validate that C2 domain is not a legitimate CDN or research infrastructure",
            ],
            # §10 Similar Cases
            similar_case_narratives=[
                AISimilarCaseNarrative(
                    case_id="CASE-2024-0892",
                    similarity_score=0.92,
                    shared_traits=[
                        "Same C2 domain (suspicious-domain.com)",
                        "Identical attack chain (phishing -> Cobalt Strike -> Mimikatz -> lateral)",
                        "Same MITRE techniques (T1059.001, T1055, T1003.001)",
                        "Similar host type (developer workstation)",
                    ],
                    resolution_summary=(
                        "Confirmed TRUE POSITIVE. Contained via EDR isolation, credentials reset, IOCs blocked. "
                        "Full remediation took 72 hours. Root cause was phishing email from spoofed HR sender."
                    ),
                    relevance_explanation=(
                        "This is likely the same campaign or actor. The identical C2 infrastructure and TTP overlap "
                        "suggest reuse of attack toolkit. Runbook RB-MAL-003 from this case should be followed."
                    ),
                ),
                AISimilarCaseNarrative(
                    case_id="CASE-2024-0756",
                    similarity_score=0.78,
                    shared_traits=[
                        "Cobalt Strike beacon activity",
                        "Lateral movement pattern",
                        "Credential access TTPs",
                    ],
                    resolution_summary=(
                        "TRUE POSITIVE confirmed. Different domain but same actor TTP. Contained within 24 hours."
                    ),
                    relevance_explanation=(
                        "Same threat actor tactics but different infrastructure. Confirms this TTP pattern is "
                        "consistently malicious in our environment."
                    ),
                ),
            ],
            # §11 Closure
            closure_guidance=(
                "Case can be closed as TRUE POSITIVE when:\n"
                "1. Root cause (initial access vector) is identified and documented\n"
                "2. All affected hosts are contained and remediated\n"
                "3. Compromised credentials are reset across the domain\n"
                "4. IOCs are blocked at perimeter and endpoint\n"
                "5. No evidence of ongoing C2 communication for 72+ hours"
            ),
            tp_verification_steps=[
                "Confirm forensic artifacts match known Cobalt Strike behavior",
                "Verify all TI matches are high-confidence (not sinkholed/research infrastructure)",
                "Document lateral movement scope with EDR timeline",
                "Confirm credential theft via lsass access patterns",
            ],
            fp_verification_steps=[
                "Interview jsmith to confirm no authorized red team/pentest activity",
                "Check if PowerShell script is a known developer tool",
                "Verify C2 domain is not legitimate CDN or cloud infrastructure",
                "Confirm no scheduled security testing on affected hosts",
            ],
            similar_case_closure_patterns=[
                "CASE-2024-0892: Closed as TP after 72h - credential rotation, EDR isolation, IOC blocking",
                "CASE-2024-0756: Closed as TP after 24h - faster response due to existing playbook",
            ],
            # §12 Stakeholder
            business_impact_summary=(
                "**CRITICAL BUSINESS RISK**\n\n"
                "A developer workstation with access to source code and internal systems has been compromised. "
                "Credential theft has occurred, and lateral movement to a domain controller was attempted.\n\n"
                "**Immediate Risks:**\n"
                "- Intellectual property theft (source code)\n"
                "- Supply chain compromise if CI/CD access is obtained\n"
                "- Domain-wide compromise if DC credentials were harvested\n\n"
                "**Recommended Executive Action:**\n"
                "Authorize immediate containment and IR engagement. Consider notifying legal/privacy teams "
                "given SOC2/GDPR implications."
            ),
            risk_communication=(
                "For non-technical stakeholders: An attacker has gained access to an employee's computer and "
                "stolen login credentials. They are now trying to access other computers and systems in our network. "
                "We are taking immediate action to stop them and assess what information they may have accessed."
            ),
            # §13 Data Quality
            data_quality_observations=[
                "Email gateway logs unavailable - cannot confirm phishing as initial access vector",
                "Cloud SaaS (M365, Okta) logs not integrated - user cloud activity is a blind spot",
                "SERVER-DC01 EDR telemetry is delayed by 15 minutes - lateral movement scope may be incomplete",
            ],
            confidence_caveats=[
                "Initial access vector is hypothesized (phishing) but not confirmed",
                "Full lateral movement scope pending EDR sync completion",
                "No data exfiltration evidence yet, but investigation ongoing",
            ],
        )

    # Cache stub methods for future SQLite implementation
    def _get_cached(self, cache_key: str) -> Optional[AIResponse]:
        """Get cached response (stub for future implementation).

        Args:
            cache_key: Cache key

        Returns:
            Cached AIResponse or None
        """
        # POC: In-memory cache only
        return self._cache.get(cache_key)

    def _set_cached(self, cache_key: str, response: AIResponse) -> None:
        """Set cached response (stub for future implementation).

        Args:
            cache_key: Cache key
            response: Response to cache
        """
        # POC: In-memory cache only
        self._cache[cache_key] = response

    async def health_check(self) -> Dict[str, Any]:
        """Check AI service health.

        Returns:
            Health status dictionary
        """
        provider_healthy = await self.provider.health_check()

        return {
            "enabled": self.settings.enabled,
            "provider": self.settings.provider,
            "model": self.settings.model,
            "provider_healthy": provider_healthy,
            "prompts_version": self.prompts_loader.version,
            "prompts_loaded": len(self.prompts),
            "cache_enabled": self._cache_enabled,
            "cache_size": len(self._cache),
        }
