"""
Test per LLM Provider, OllamaProvider e LLMRouter.

Tutti i test usano mock httpx — nessuna dipendenza da Ollama reale.
"""

import pytest
from unittest.mock import patch, MagicMock

import httpx

from cto_audit.llm.provider import (
    LLMConfig,
    LLMResponse,
    LLMProvider,
    TaskComplexity,
)
from cto_audit.llm.local import OllamaProvider, DEFAULT_MODEL_MAP
from cto_audit.llm.router import LLMRouter


# --- Test LLMConfig ---

class TestLLMConfig:
    def test_default_config(self):
        config = LLMConfig()
        assert config.task_complexity == TaskComplexity.MEDIUM
        assert config.temperature == 0.1
        assert config.max_tokens == 2048
        assert config.system_prompt is None

    def test_custom_config(self):
        config = LLMConfig(
            task_complexity=TaskComplexity.HIGH,
            temperature=0.3,
            max_tokens=4096,
            system_prompt="You are a CTO.",
        )
        assert config.task_complexity == TaskComplexity.HIGH
        assert config.temperature == 0.3

    def test_temperature_bounds(self):
        with pytest.raises(Exception):
            LLMConfig(temperature=-0.1)
        with pytest.raises(Exception):
            LLMConfig(temperature=2.1)

    def test_max_tokens_positive(self):
        with pytest.raises(Exception):
            LLMConfig(max_tokens=0)


class TestLLMResponse:
    def test_valid_response(self):
        resp = LLMResponse(
            text="Hello world",
            model_used="mistral:7b",
            tokens_used=42,
            provider="ollama",
        )
        assert resp.text == "Hello world"
        assert resp.provider == "ollama"


# --- Test OllamaProvider ---

class TestOllamaProvider:
    def test_provider_name(self):
        provider = OllamaProvider()
        assert provider.provider_name == "ollama"

    def test_model_selection_by_complexity(self):
        """Verifica che il modello corretto sia selezionato per complessita."""
        provider = OllamaProvider()

        for complexity, expected_model in DEFAULT_MODEL_MAP.items():
            config = LLMConfig(task_complexity=complexity)

            with patch("cto_audit.llm.local.httpx.Client") as mock_client_cls:
                mock_client = MagicMock()
                mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
                mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "response": "test",
                    "eval_count": 10,
                }
                mock_client.post.return_value = mock_response

                provider.generate("test prompt", config)

                call_args = mock_client.post.call_args
                payload = call_args.kwargs.get("json") or call_args[1].get("json")
                assert payload["model"] == expected_model

    def test_generate_success(self):
        provider = OllamaProvider()

        with patch("cto_audit.llm.local.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "response": "Generated text here",
                "eval_count": 25,
            }
            mock_client.post.return_value = mock_response

            result = provider.generate("Tell me about Python")

            assert isinstance(result, LLMResponse)
            assert result.text == "Generated text here"
            assert result.tokens_used == 25
            assert result.provider == "ollama"

    def test_generate_with_system_prompt(self):
        provider = OllamaProvider()
        config = LLMConfig(system_prompt="You are an expert.")

        with patch("cto_audit.llm.local.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"response": "ok", "eval_count": 5}
            mock_client.post.return_value = mock_response

            provider.generate("test", config)

            call_args = mock_client.post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")
            assert payload["system"] == "You are an expert."

    def test_generate_connection_error(self):
        provider = OllamaProvider()

        with patch("cto_audit.llm.local.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")

            with pytest.raises(ConnectionError, match="Impossibile connettersi"):
                provider.generate("test")

    def test_generate_http_error(self):
        provider = OllamaProvider()

        with patch("cto_audit.llm.local.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            mock_response = MagicMock()
            mock_response.status_code = 500
            mock_response.text = "Internal Server Error"
            mock_client.post.return_value = mock_response

            with pytest.raises(RuntimeError, match="Errore HTTP 500"):
                provider.generate("test")

    def test_is_available_true(self):
        provider = OllamaProvider()

        with patch("cto_audit.llm.local.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.get.return_value = mock_response

            assert provider.is_available() is True

    def test_is_available_false(self):
        provider = OllamaProvider()

        with patch("cto_audit.llm.local.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = httpx.ConnectError("refused")

            assert provider.is_available() is False

    def test_custom_model_map(self):
        custom_map = {
            TaskComplexity.LOW: "custom:small",
            TaskComplexity.MEDIUM: "custom:medium",
            TaskComplexity.HIGH: "custom:large",
        }
        provider = OllamaProvider(model_map=custom_map)

        with patch("cto_audit.llm.local.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"response": "ok", "eval_count": 1}
            mock_client.post.return_value = mock_response

            config = LLMConfig(task_complexity=TaskComplexity.HIGH)
            provider.generate("test", config)

            call_args = mock_client.post.call_args
            payload = call_args.kwargs.get("json") or call_args[1].get("json")
            assert payload["model"] == "custom:large"


# --- Test LLMRouter ---

class _MockProvider:
    """Mock provider per test del router."""

    def __init__(self, name: str, available: bool = True, response_text: str = "mock"):
        self._name = name
        self._available = available
        self._response_text = response_text
        self._raise_on_generate = False

    def generate(self, prompt: str, config: LLMConfig | None = None) -> LLMResponse:
        if self._raise_on_generate:
            raise ConnectionError("Provider failed")
        return LLMResponse(
            text=self._response_text,
            model_used="mock-model",
            tokens_used=10,
            provider=self._name,
        )

    def is_available(self) -> bool:
        return self._available

    @property
    def provider_name(self) -> str:
        return self._name


class TestLLMRouter:
    def test_single_provider_available(self):
        provider = _MockProvider("test", available=True, response_text="hello")
        router = LLMRouter(providers=[provider])

        result = router.generate("test prompt")
        assert result is not None
        assert result.text == "hello"
        assert result.provider == "test"

    def test_no_provider_available(self):
        provider = _MockProvider("test", available=False)
        router = LLMRouter(providers=[provider])

        result = router.generate("test prompt")
        assert result is None

    def test_fallback_to_second_provider(self):
        p1 = _MockProvider("primary", available=False)
        p2 = _MockProvider("fallback", available=True, response_text="from fallback")
        router = LLMRouter(providers=[p1, p2])

        result = router.generate("test")
        assert result is not None
        assert result.provider == "fallback"
        assert result.text == "from fallback"

    def test_fallback_on_error(self):
        p1 = _MockProvider("primary", available=True)
        p1._raise_on_generate = True
        p2 = _MockProvider("fallback", available=True, response_text="fallback ok")
        router = LLMRouter(providers=[p1, p2])

        result = router.generate("test")
        assert result is not None
        assert result.provider == "fallback"

    def test_is_available(self):
        p1 = _MockProvider("a", available=False)
        p2 = _MockProvider("b", available=True)
        router = LLMRouter(providers=[p1, p2])

        assert router.is_available() is True

    def test_not_available(self):
        p1 = _MockProvider("a", available=False)
        router = LLMRouter(providers=[p1])

        assert router.is_available() is False

    def test_available_providers_list(self):
        p1 = _MockProvider("ollama", available=True)
        p2 = _MockProvider("claude", available=False)
        router = LLMRouter(providers=[p1, p2])

        available = router.available_providers
        assert available == ["ollama"]

    def test_empty_providers(self):
        router = LLMRouter(providers=[])
        assert router.generate("test") is None
        assert not router.is_available()

    def test_protocol_compliance(self):
        """OllamaProvider implementa LLMProvider protocol."""
        provider = OllamaProvider()
        assert isinstance(provider, LLMProvider)
