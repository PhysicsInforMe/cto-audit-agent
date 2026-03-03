"""
LLM Provider Protocol — Interfaccia comune per tutti i provider LLM.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class TaskComplexity(str, Enum):
    """Complessita del task LLM — determina modello e temperatura."""
    LOW = "low"        # classificazione → modelli piccoli, temp=0.0
    MEDIUM = "medium"  # summarization → modelli medi, temp=0.1
    HIGH = "high"      # generazione report → modelli grandi, temp=0.2


class LLMConfig(BaseModel):
    """Configurazione per una richiesta LLM."""
    task_complexity: TaskComplexity = TaskComplexity.MEDIUM
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=2048, ge=1)
    system_prompt: str | None = None


class LLMResponse(BaseModel):
    """Risposta da un provider LLM."""
    text: str
    model_used: str
    tokens_used: int = 0
    provider: str  # "ollama", "claude", "gemini"


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol per provider LLM."""

    def generate(self, prompt: str, config: LLMConfig | None = None) -> LLMResponse:
        """Genera una risposta dal LLM."""
        ...

    def is_available(self) -> bool:
        """Controlla se il provider e disponibile."""
        ...

    @property
    def provider_name(self) -> str:
        """Nome del provider."""
        ...
