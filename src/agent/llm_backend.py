"""
LLM backend abstraction for the finance agent.

Supports:
- "openai" → gpt-4o-mini (default)
- "anthropic" → claude-haiku
- "mock" → deterministic responses for testing

Selection via MODEL_PROVIDER env var. Falls back to mock mode
if the selected provider's API key isn't configured.
"""

import json
import os
import logging
from abc import ABC, abstractmethod

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)


class LLMBackend(ABC):
    """Abstract base for LLM backends."""

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Send a prompt and return the text response."""
        ...


class OpenAIBackend(LLMBackend):
    """OpenAI GPT backend."""

    def __init__(self) -> None:
        from openai import OpenAI
        self._client = OpenAI()
        self._model = os.getenv("MODEL_NAME", "gpt-4o-mini")

    def complete(self, prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=1024,
        )
        return response.choices[0].message.content or ""


class AnthropicBackend(LLMBackend):
    """Anthropic Claude backend."""

    def __init__(self) -> None:
        import anthropic
        self._client = anthropic.Anthropic()
        self._model = os.getenv("MODEL_NAME", "claude-haiku-4-5-20251001")

    def complete(self, prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text if response.content else ""


class MockBackend(LLMBackend):
    """
    Mock backend for testing and demo mode.

    Returns deterministic placeholder responses that match
    the expected JSON schemas from prompts.py.
    """

    def complete(self, prompt: str) -> str:
        prompt_lower = prompt.lower()

        # Categorization request
        if "categorize" in prompt_lower and "merchant" in prompt_lower:
            return json.dumps({
                "merchant": "Unknown",
                "amount": 0.0,
                "category": "Other",
                "is_subscription": False,
                "confidence": 0.5,
            })

        # Anomaly detection
        if "anomalies" in prompt_lower and "analyze" in prompt_lower:
            return json.dumps({
                "anomalies": [],
                "summary": "No anomalies detected (mock mode)",
            })

        # Weekly summary
        if "weekly" in prompt_lower and "summary" in prompt_lower:
            return json.dumps({
                "period": "last 7 days",
                "total_spent": 0.0,
                "by_category": {},
                "top_merchants": [],
                "subscriptions_detected": [],
                "anomalies_detected": 0,
                "insights": ["Running in mock mode — connect an LLM for real insights"],
                "security_flags": 0,
            })

        return json.dumps({"response": "mock mode", "input_length": len(prompt)})


def get_llm_backend() -> LLMBackend:
    """
    Get the configured LLM backend.

    Selection order:
    1. MODEL_PROVIDER env var ("openai", "anthropic", "mock")
    2. Auto-detect based on available API keys
    3. Fall back to mock mode
    """
    provider = os.getenv("MODEL_PROVIDER", "").lower()

    if provider == "openai":
        if os.getenv("OPENAI_API_KEY"):
            try:
                return OpenAIBackend()
            except Exception as e:
                logger.warning("OpenAI backend init failed: %s — falling back to mock", e)
        else:
            logger.info("OPENAI_API_KEY not set — using mock backend")

    elif provider == "anthropic":
        if os.getenv("ANTHROPIC_API_KEY"):
            try:
                return AnthropicBackend()
            except Exception as e:
                logger.warning("Anthropic backend init failed: %s — falling back to mock", e)
        else:
            logger.info("ANTHROPIC_API_KEY not set — using mock backend")

    elif provider == "mock":
        return MockBackend()

    # Auto-detect
    if os.getenv("OPENAI_API_KEY"):
        try:
            return OpenAIBackend()
        except Exception:
            pass

    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            return AnthropicBackend()
        except Exception:
            pass

    logger.info("No LLM API key configured — using mock backend")
    return MockBackend()
