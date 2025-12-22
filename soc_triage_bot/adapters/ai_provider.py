"""AI Provider adapters for LLM integration.

Provides abstraction layer for different AI/LLM providers:
- OpenAI (GPT-4, GPT-4o)
- Anthropic (Claude)
- Ollama (local models)
- Mock (for testing/POC)

Uses asyncio.to_thread for sync provider SDKs.
"""

import asyncio
import hashlib
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class AIProviderConfig:
    """Configuration for an AI provider."""

    provider_name: str
    model: str
    api_key_env: str = ""  # Environment variable name for API key
    endpoint: Optional[str] = None  # Custom endpoint (for Ollama, Azure, etc.)
    temperature: float = 0.7
    max_tokens: int = 2048
    timeout_seconds: int = 30


@dataclass
class AIResponse:
    """Response from an AI provider."""

    content: str
    model: str
    provider: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    cached: bool = False
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseAIProvider(ABC):
    """Abstract base class for AI providers.

    All providers must implement the async generate() method.
    For sync SDKs, use asyncio.to_thread() wrapper.
    """

    def __init__(self, config: AIProviderConfig):
        """Initialize provider with configuration."""
        self.config = config
        self.name = config.provider_name

    @abstractmethod
    async def generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> AIResponse:
        """Generate a response from the AI model.

        Args:
            prompt: The user prompt to send to the model
            system_prompt: Optional system prompt for context

        Returns:
            AIResponse with generated content and metadata
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the provider is available and configured correctly."""
        ...
        pass

    def _get_api_key(self) -> Optional[str]:
        """Get API key from environment variable."""
        if self.config.api_key_env:
            return os.environ.get(self.config.api_key_env)
        return None

    def _generate_cache_key(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> str:
        """Generate a cache key for the prompt."""
        content = f"{self.config.model}:{system_prompt or ''}:{prompt}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class MockProvider(BaseAIProvider):
    """Mock provider for testing and POC.

    Returns predefined responses without making API calls.
    """

    def __init__(self, config: Optional[AIProviderConfig] = None):
        """Initialize mock provider."""
        if config is None:
            config = AIProviderConfig(
                provider_name="mock",
                model="mock-v1",
            )
        super().__init__(config)
        self._mock_responses: Dict[str, str] = {}

    def set_mock_response(self, prompt_contains: str, response: str) -> None:
        """Set a mock response for prompts containing specific text."""
        self._mock_responses[prompt_contains] = response

    async def generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> AIResponse:
        """Return mock response."""
        start_time = datetime.now(timezone.utc)

        # Check for matching mock response
        for key, response in self._mock_responses.items():
            if key in prompt:
                content = response
                break
        else:
            # Default mock response based on prompt content
            content = self._generate_default_mock(prompt)

        latency_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return AIResponse(
            content=content,
            model=self.config.model,
            provider=self.name,
            prompt_tokens=len(prompt.split()),
            completion_tokens=len(content.split()),
            total_tokens=len(prompt.split()) + len(content.split()),
            latency_ms=latency_ms,
            cached=False,
            metadata={"mock": True},
        )

    def _generate_default_mock(self, prompt: str) -> str:
        """Generate default mock response based on prompt keywords."""
        prompt_lower = prompt.lower()

        if "summary" in prompt_lower or "executive" in prompt_lower:
            return "This security event requires immediate attention based on threat intelligence correlation and behavioral analysis."
        elif "action" in prompt_lower or "recommendation" in prompt_lower:
            return "Recommend isolating affected systems, collecting forensic artifacts, and notifying incident response team."
        elif "context" in prompt_lower:
            return "The signal context indicates potential lateral movement activity consistent with known APT techniques."
        elif "threat" in prompt_lower or "intel" in prompt_lower:
            return "Threat intelligence indicates this IOC is associated with financially motivated threat actors."
        elif "risk" in prompt_lower or "exposure" in prompt_lower:
            return "Exposure analysis shows moderate risk with potential for data exfiltration if not contained."
        elif "trend" in prompt_lower or "forecast" in prompt_lower:
            return "Historical trend analysis shows this is an anomalous spike compared to baseline."
        elif "timeline" in prompt_lower:
            return "Attack timeline suggests initial access occurred within the past 24 hours."
        elif "assessment" in prompt_lower or "classification" in prompt_lower:
            return "Classification assessment indicates high likelihood of true positive based on multiple corroborating factors."
        elif "similar" in prompt_lower or "case" in prompt_lower:
            return "Similar historical cases were resolved through network isolation and credential rotation."
        elif "closure" in prompt_lower:
            return "Case can be closed once containment is verified and forensic collection is complete."
        elif "stakeholder" in prompt_lower:
            return "Recommend briefing CISO and legal team given potential regulatory implications."
        elif "quality" in prompt_lower or "data" in prompt_lower:
            return "Data quality is sufficient for analysis with minor gaps in endpoint telemetry."
        else:
            return "AI analysis indicates this event warrants further investigation."

    async def health_check(self) -> bool:
        """Mock provider is always healthy."""
        return True


class OpenAIProvider(BaseAIProvider):
    """OpenAI provider for GPT models.

    Uses asyncio.to_thread for the sync openai SDK.
    """

    def __init__(self, config: AIProviderConfig):
        """Initialize OpenAI provider."""
        super().__init__(config)
        self._client = None

    def _get_client(self):
        """Lazy load OpenAI client."""
        if self._client is None:
            try:
                from openai import OpenAI

                api_key = self._get_api_key()
                if not api_key:
                    raise ValueError(
                        f"OpenAI API key not found in env var: {self.config.api_key_env}"
                    )
                self._client = OpenAI(
                    api_key=api_key,
                    timeout=self.config.timeout_seconds,
                )
            except ImportError:
                raise ImportError(
                    "openai package not installed. Run: pip install openai"
                )
        return self._client

    def _sync_generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Sync generation call - wrapped by asyncio.to_thread."""
        client = self._get_client()

        messages: List[Dict[str, Any]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.config.model,
            messages=messages,  # type: ignore
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )

        return {
            "content": response.choices[0].message.content or "",
            "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
            "completion_tokens": (
                response.usage.completion_tokens if response.usage else 0
            ),
            "total_tokens": response.usage.total_tokens if response.usage else 0,
            "model": response.model,
        }

    async def generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> AIResponse:
        """Generate response using OpenAI API."""
        start_time = datetime.now(timezone.utc)

        result = await asyncio.to_thread(self._sync_generate, prompt, system_prompt)

        latency_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return AIResponse(
            content=result["content"],
            model=result["model"],
            provider=self.name,
            prompt_tokens=result["prompt_tokens"],
            completion_tokens=result["completion_tokens"],
            total_tokens=result["total_tokens"],
            latency_ms=latency_ms,
        )

    async def health_check(self) -> bool:
        """Check if OpenAI is accessible."""
        try:
            api_key = self._get_api_key()
            if not api_key:
                return False
            # Simple models list call to verify connectivity
            client = self._get_client()
            await asyncio.to_thread(lambda: list(client.models.list())[:1])
            return True
        except Exception:
            return False


class AnthropicProvider(BaseAIProvider):
    """Anthropic provider for Claude models.

    Uses asyncio.to_thread for the sync anthropic SDK.
    """

    def __init__(self, config: AIProviderConfig):
        """Initialize Anthropic provider."""
        super().__init__(config)
        self._client = None

    def _get_client(self):
        """Lazy load Anthropic client."""
        if self._client is None:
            try:
                from anthropic import Anthropic

                api_key = self._get_api_key()
                if not api_key:
                    raise ValueError(
                        f"Anthropic API key not found in env var: {self.config.api_key_env}"
                    )
                self._client = Anthropic(
                    api_key=api_key,
                    timeout=self.config.timeout_seconds,
                )
            except ImportError:
                raise ImportError(
                    "anthropic package not installed. Run: pip install anthropic"
                )
        return self._client

    def _sync_generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """Sync generation call - wrapped by asyncio.to_thread."""
        client = self._get_client()

        message = client.messages.create(
            model=self.config.model,
            max_tokens=self.config.max_tokens,
            system=system_prompt or "You are a security analyst AI assistant.",
            messages=[{"role": "user", "content": prompt}],
        )

        content = ""
        for block in message.content:
            # Type narrowing: only TextBlock has text attribute
            if block.type == "text":
                content += block.text

        return {
            "content": content,
            "prompt_tokens": message.usage.input_tokens,
            "completion_tokens": message.usage.output_tokens,
            "total_tokens": message.usage.input_tokens + message.usage.output_tokens,
            "model": message.model,
        }

    async def generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> AIResponse:
        """Generate response using Anthropic API."""
        start_time = datetime.now(timezone.utc)

        result = await asyncio.to_thread(self._sync_generate, prompt, system_prompt)

        latency_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return AIResponse(
            content=result["content"],
            model=result["model"],
            provider=self.name,
            prompt_tokens=result["prompt_tokens"],
            completion_tokens=result["completion_tokens"],
            total_tokens=result["total_tokens"],
            latency_ms=latency_ms,
        )

    async def health_check(self) -> bool:
        """Check if Anthropic is accessible."""
        try:
            api_key = self._get_api_key()
            return api_key is not None and len(api_key) > 0
        except Exception:
            return False


class OllamaProvider(BaseAIProvider):
    """Ollama provider for local LLM models.

    Uses HTTP requests to local Ollama server.
    """

    def __init__(self, config: AIProviderConfig):
        """Initialize Ollama provider."""
        super().__init__(config)
        self.endpoint = config.endpoint or "http://localhost:11434"

    async def generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> AIResponse:
        """Generate response using Ollama API."""
        import aiohttp

        start_time = datetime.now(timezone.utc)

        url = f"{self.endpoint}/api/generate"
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            },
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as response:
                response.raise_for_status()
                data = await response.json()

        latency_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

        return AIResponse(
            content=data.get("response", ""),
            model=self.config.model,
            provider=self.name,
            prompt_tokens=data.get("prompt_eval_count", 0),
            completion_tokens=data.get("eval_count", 0),
            total_tokens=data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
            latency_ms=latency_ms,
            metadata={
                "total_duration": data.get("total_duration"),
                "load_duration": data.get("load_duration"),
            },
        )

    async def health_check(self) -> bool:
        """Check if Ollama server is accessible."""
        import aiohttp

        try:
            url = f"{self.endpoint}/api/tags"
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    return response.status == 200
        except Exception:
            return False


def get_provider(config: AIProviderConfig) -> BaseAIProvider:
    """Factory function to get the appropriate provider.

    Args:
        config: Provider configuration

    Returns:
        Configured AI provider instance

    Raises:
        ValueError: If provider is not supported
    """
    provider_map = {
        "mock": MockProvider,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
    }

    provider_class = provider_map.get(config.provider_name.lower())
    if provider_class is None:
        raise ValueError(
            f"Unsupported provider: {config.provider_name}. "
            f"Supported: {list(provider_map.keys())}"
        )

    return provider_class(config)
