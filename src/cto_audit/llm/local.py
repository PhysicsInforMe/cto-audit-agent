"""
OllamaProvider — Provider LLM locale via Ollama HTTP API.

Comunica via httpx con /api/generate.
Model mapping per TaskComplexity (configurabile).
"""

from __future__ import annotations

import httpx

from cto_audit.llm.provider import LLMConfig, LLMResponse, TaskComplexity


# Default model mapping per complessita task
DEFAULT_MODEL_MAP: dict[TaskComplexity, str] = {
    TaskComplexity.LOW: "phi3:mini",
    TaskComplexity.MEDIUM: "mistral:7b",
    TaskComplexity.HIGH: "llama3.1:8b",
}

# Temperatura default per complessita
DEFAULT_TEMP_MAP: dict[TaskComplexity, float] = {
    TaskComplexity.LOW: 0.0,
    TaskComplexity.MEDIUM: 0.1,
    TaskComplexity.HIGH: 0.2,
}


class OllamaProvider:
    """
    Provider LLM locale via Ollama.

    Richiede Ollama in esecuzione su localhost:11434.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model_map: dict[TaskComplexity, str] | None = None,
        timeout: float = 120.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model_map = model_map or dict(DEFAULT_MODEL_MAP)
        self._timeout = timeout

    def generate(self, prompt: str, config: LLMConfig | None = None) -> LLMResponse:
        """
        Genera una risposta via Ollama /api/generate.

        Args:
            prompt: Il prompt da inviare
            config: Configurazione LLM (opzionale)

        Returns:
            LLMResponse con testo generato

        Raises:
            ConnectionError: se Ollama non e raggiungibile
            RuntimeError: per errori HTTP
        """
        config = config or LLMConfig()
        model = self._model_map.get(config.task_complexity, self._model_map[TaskComplexity.MEDIUM])
        temperature = config.temperature if config.temperature != 0.1 else DEFAULT_TEMP_MAP.get(
            config.task_complexity, 0.1
        )

        payload: dict = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": config.max_tokens,
            },
        }

        if config.system_prompt:
            payload["system"] = config.system_prompt

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(
                    f"{self._base_url}/api/generate",
                    json=payload,
                )
        except httpx.ConnectError as e:
            raise ConnectionError(
                f"Impossibile connettersi a Ollama su {self._base_url}: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise ConnectionError(
                f"Timeout connessione a Ollama su {self._base_url}: {e}"
            ) from e

        if response.status_code != 200:
            raise RuntimeError(
                f"Errore HTTP {response.status_code} da Ollama: {response.text}"
            )

        data = response.json()
        text = data.get("response", "")
        tokens = data.get("eval_count", 0)

        return LLMResponse(
            text=text,
            model_used=model,
            tokens_used=tokens,
            provider="ollama",
        )

    def is_available(self) -> bool:
        """Controlla se Ollama e raggiungibile."""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self._base_url}/api/tags")
                return response.status_code == 200
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    @property
    def provider_name(self) -> str:
        return "ollama"
