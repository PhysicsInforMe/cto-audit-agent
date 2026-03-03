"""
LLM Router — Routing con fallback tra provider disponibili.

Prova Ollama first. Graceful degradation: restituisce None se nessun provider disponibile.
"""

from __future__ import annotations

from cto_audit.llm.local import OllamaProvider
from cto_audit.llm.provider import LLMConfig, LLMProvider, LLMResponse


class LLMRouter:
    """
    Router LLM con fallback tra provider.

    Prova i provider in ordine e usa il primo disponibile.
    Se nessun provider e disponibile, generate() restituisce None.
    """

    def __init__(
        self,
        providers: list[LLMProvider] | None = None,
    ) -> None:
        if providers is not None:
            self._providers = providers
        else:
            # Default: solo Ollama
            self._providers = [OllamaProvider()]

    def generate(self, prompt: str, config: LLMConfig | None = None) -> LLMResponse | None:
        """
        Genera una risposta dal primo provider disponibile.

        Returns:
            LLMResponse o None se nessun provider disponibile
        """
        for provider in self._providers:
            if provider.is_available():
                try:
                    return provider.generate(prompt, config)
                except (ConnectionError, RuntimeError):
                    continue
        return None

    def is_available(self) -> bool:
        """Controlla se almeno un provider e disponibile."""
        return any(p.is_available() for p in self._providers)

    @property
    def available_providers(self) -> list[str]:
        """Lista dei provider attualmente disponibili."""
        return [p.provider_name for p in self._providers if p.is_available()]
