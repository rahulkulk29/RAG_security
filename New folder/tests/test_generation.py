"""
Unit tests for Gemini generation client: configuration, error handling,
sanitization, exception context stripping, and google-genai SDK compatibility.
"""
import logging
import pytest
from unittest.mock import MagicMock

from app.core.config import settings
from app.generation.client import GeminiClient
from app.generation.exceptions import (
    GenerationError,
    GeminiConfigurationError,
    GeminiAPIError,
    EmptyResponseError,
)


class FakeGeminiResponse:
    """Mock Gemini response object exposing text property."""
    def __init__(self, text: str):
        self._text = text

    @property
    def text(self) -> str:
        if isinstance(self._text, Exception):
            raise self._text
        return self._text


class FakeGenAIModels:
    """Mock Models service mirroring the google-genai client.models interface."""
    def __init__(self, response_text: str = "Default generated text"):
        self.response_text = response_text
        self.last_model = None
        self.last_contents = None
        self.last_config = None
        self.call_count = 0

    def generate_content(self, model: str, contents: str, config=None):
        self.call_count += 1
        self.last_model = model
        self.last_contents = contents
        self.last_config = config
        return FakeGeminiResponse(self.response_text)


class FakeGenAIClient:
    """Mock genai.Client instance for unit testing google-genai SDK calls."""
    def __init__(self, response_text: str = "Default generated text"):
        self.models = FakeGenAIModels(response_text=response_text)


class FakeLegacyGeminiModel:
    """Mock model provider with direct generate_content method for backward compatibility."""
    def __init__(self, response_text: str = "Default legacy text"):
        self.response_text = response_text
        self.last_prompt = None
        self.last_config = None
        self.call_count = 0

    def generate_content(self, *args, **kwargs):
        self.call_count += 1
        if "contents" in kwargs:
            self.last_prompt = kwargs["contents"]
        elif args:
            self.last_prompt = args[0]
        self.last_config = kwargs.get("config")
        return FakeGeminiResponse(self.response_text)


# =============================================================================
# 1. SUCCESSFUL GENERATION & SDK INTERFACE
# =============================================================================

def test_successful_generation_new_sdk_interface():
    """Verify that generation through the google-genai client.models interface returns clean text."""
    expected_text = "ApexPay settlement occurs daily at 00:00 UTC."
    fake_client = FakeGenAIClient(response_text=expected_text)
    client = GeminiClient(
        model_id="gemini-2.0-flash",
        client_instance=fake_client,
    )

    result = client.generate("Summarize merchant settlement procedures.")

    assert result == expected_text
    assert fake_client.models.call_count == 1
    assert fake_client.models.last_model == "gemini-2.0-flash"
    assert fake_client.models.last_contents == "Summarize merchant settlement procedures."


def test_client_instantiation_with_fake_provider():
    """Verify client can be instantiated directly with an injected fake provider without network calls."""
    from app.generation.prompts import DEFAULT_SYSTEM_INSTRUCTION

    fake_client = FakeGenAIClient(response_text="Fake response")
    client = GeminiClient(
        api_key="fake-test-key",
        model_id="gemini-test-custom",
        temperature=0.2,
        timeout=15.0,
        client_instance=fake_client,
    )

    assert client.model_id == "gemini-test-custom"
    assert client.timeout == 15.0
    assert client.temperature == 0.2
    assert client.system_instruction == DEFAULT_SYSTEM_INSTRUCTION

    res = client.generate("Test prompt")
    assert res == "Fake response"
    assert fake_client.models.last_config.temperature == 0.2
    assert fake_client.models.last_config.system_instruction == DEFAULT_SYSTEM_INSTRUCTION
    assert fake_client.models.last_config.http_options.timeout == 15000  # 15s in ms


def test_backward_compatibility_with_model_instance():
    """Verify that injecting model_instance directly continues to work cleanly."""
    legacy_model = FakeLegacyGeminiModel(response_text="Legacy response")
    client = GeminiClient(model_instance=legacy_model)

    result = client.generate("Test prompt")
    assert result == "Legacy response"
    assert legacy_model.call_count == 1
    assert legacy_model.last_prompt == "Test prompt"


# =============================================================================
# 2. TEMPERATURE AND TIMEOUT FORWARDING
# =============================================================================

def test_temperature_forwarding():
    """Verify temperature setting is forwarded into GenerateContentConfig."""
    fake_client = FakeGenAIClient()
    client = GeminiClient(
        temperature=0.7,
        client_instance=fake_client,
    )
    client.generate("Test temperature")
    assert fake_client.models.last_config.temperature == 0.7


def test_timeout_forwarding_and_per_request_override():
    """Verify timeout is converted to milliseconds in HttpOptions, with per-call override support."""
    fake_client = FakeGenAIClient()
    client = GeminiClient(
        timeout=45.0,
        client_instance=fake_client,
    )

    # 1. Default instance timeout (45.0s -> 45000ms)
    client.generate("Test instance timeout")
    assert fake_client.models.last_config.http_options.timeout == 45000

    # 2. Per-request override (12.5s -> 12500ms)
    client.generate("Test override timeout", timeout=12.5)
    assert fake_client.models.last_config.http_options.timeout == 12500


# =============================================================================
# 3. EXCEPTION CONTEXT STRIPPING & PROVIDER ERROR HANDLING
# =============================================================================

def test_provider_api_exception_translated_safely_and_no_retained_context():
    """
    CRITICAL SECURITY & SAFETY TEST:
    Verify that provider/network failures are translated to GeminiAPIError,
    and neither __cause__ nor __context__ retains the original sensitive provider exception.
    """
    secret_leak = "GoogleAPIError 503: quota leak with secret CANARY_KEY_12345 and sensitive token"
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError(secret_leak)

    client = GeminiClient(client_instance=mock_client)

    with pytest.raises(GeminiAPIError) as exc_info:
        client.generate("Generate summary")

    err = exc_info.value
    msg = str(err)
    assert "Gemini generation request failed" in msg
    assert "CANARY_KEY_12345" not in msg
    assert "503" not in msg

    # Task B assertion: Ensure original provider exceptions are strictly not retained
    assert err.__cause__ is None
    assert err.__context__ is None
    assert err.error_type == "RuntimeError"

    # Verify original exception object is nowhere in the error's attributes
    for val in vars(err).values():
        assert "CANARY_KEY_12345" not in str(val)
        assert not isinstance(val, Exception)


def test_empty_or_blocked_response_has_no_retained_context():
    """
    Verify that safety-blocked or unparseable responses raise EmptyResponseError,
    and neither __cause__ nor __context__ retains the original exception.
    """
    mock_client = MagicMock()
    safety_error = ValueError(
        "Invalid operation: The response.text accessor blocked by finish_reason=SAFETY CANARY_TOKEN_999"
    )
    mock_client.models.generate_content.return_value = FakeGeminiResponse(safety_error)

    client = GeminiClient(client_instance=mock_client)

    with pytest.raises(EmptyResponseError) as exc_info:
        client.generate("Test query")

    err = exc_info.value
    assert "empty or unparseable response" in str(err)
    assert "CANARY_TOKEN_999" not in str(err)

    # Task B assertion: Ensure original extraction exception is not retained
    assert err.__cause__ is None
    assert err.__context__ is None
    assert err.error_type == "ValueError"


def test_empty_model_response_handled_safely():
    """Verify that None, empty string, or whitespace model responses raise EmptyResponseError."""
    mock_client = MagicMock()

    # 1. Provider returns None
    mock_client.models.generate_content.return_value = None
    client = GeminiClient(client_instance=mock_client)
    with pytest.raises(EmptyResponseError, match="empty or unparseable response") as exc_info:
        client.generate("Test query")
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None

    # 2. Provider returns response with empty text
    mock_client.models.generate_content.return_value = FakeGeminiResponse("")
    with pytest.raises(EmptyResponseError, match="empty or unparseable response") as exc_info:
        client.generate("Test query")
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None

    # 3. Provider returns response with whitespace-only text
    mock_client.models.generate_content.return_value = FakeGeminiResponse("   \n\t  ")
    with pytest.raises(EmptyResponseError, match="empty or unparseable response") as exc_info:
        client.generate("Test query")
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None


def test_malformed_response_unrecognized_format():
    """Verify that unrecognized response object raises EmptyResponseError with no retained context."""
    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = 12345
    client = GeminiClient(client_instance=mock_client)

    with pytest.raises(EmptyResponseError, match="empty or unparseable response") as exc_info:
        client.generate("Test query")
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None


# =============================================================================
# 4. SECURITY & SANITIZATION (ZERO LEAKAGE IN LOGS OR MESSAGES)
# =============================================================================

def test_secrets_and_prompts_never_appear_in_logs_or_errors(caplog):
    """
    CRITICAL SECURITY TEST:
    Verify that API keys, sensitive prompts, canary tokens, and provider error strings
    never appear in logs, public exception messages, __cause__, or __context__.
    """
    secret_key = "SECRET_API_KEY_super_confidential_999"
    canary_prompt = "Attacker prompt with CANARY_TA_ADMIN_KEY_8888 and FLAG{gemini_leak}"
    raw_error_message = f"Internal crash at 0xDEADBEEF using {secret_key} with token FLAG{{gemini_leak}}"

    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = RuntimeError(raw_error_message)

    client = GeminiClient(
        api_key=secret_key,
        model_id="gemini-test-model",
        client_instance=mock_client,
    )

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(GeminiAPIError) as exc_info:
            client.generate(canary_prompt)

    # 1. Exception message does not contain secrets or prompts
    err_text = str(exc_info.value)
    assert secret_key not in err_text
    assert "CANARY_TA_ADMIN_KEY_8888" not in err_text
    assert "FLAG{gemini_leak}" not in err_text
    assert "0xDEADBEEF" not in err_text

    # 2. Exception context and cause are strictly None
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None

    # 3. Logs do not contain full prompts, secret keys, or raw provider exception messages
    logs = caplog.text
    assert secret_key not in logs
    assert "CANARY_TA_ADMIN_KEY_8888" not in logs
    assert "FLAG{gemini_leak}" not in logs
    assert "0xDEADBEEF" not in logs
    assert raw_error_message not in logs

    # 4. Log records sanitized operation and exception class name only
    assert "Gemini generation failed (RuntimeError)" in logs


# =============================================================================
# 5. CONFIGURATION & PROMPT VALIDATION
# =============================================================================

def test_missing_api_key_handled_safely(monkeypatch):
    """Verify that initializing GeminiClient without an API key raises GeminiConfigurationError."""
    monkeypatch.setattr(settings, "gemini_api_key", None)

    # 1. Omitted and settings is None
    with pytest.raises(GeminiConfigurationError) as exc_info:
        GeminiClient(api_key=None, model_id="gemini-2.0-flash")
    assert "Gemini API key is not configured" in str(exc_info.value)

    # 2. Empty string
    with pytest.raises(GeminiConfigurationError) as exc_info:
        GeminiClient(api_key="", model_id="gemini-2.0-flash")
    assert "Gemini API key is not configured" in str(exc_info.value)

    # 3. Whitespace string
    with pytest.raises(GeminiConfigurationError) as exc_info:
        GeminiClient(api_key="   ", model_id="gemini-2.0-flash")
    assert "Gemini API key is not configured" in str(exc_info.value)


def test_missing_model_id_handled_safely(monkeypatch):
    """Verify that initializing GeminiClient without a model ID raises GeminiConfigurationError."""
    monkeypatch.setattr(settings, "gemini_model_id", None)

    # 1. Omitted and settings is None
    with pytest.raises(GeminiConfigurationError) as exc_info:
        GeminiClient(api_key="valid-test-key", model_id=None)
    assert "Gemini model ID is not configured" in str(exc_info.value)

    # 2. Empty string
    with pytest.raises(GeminiConfigurationError) as exc_info:
        GeminiClient(api_key="valid-test-key", model_id="")
    assert "Gemini model ID is not configured" in str(exc_info.value)

    # 3. Whitespace string
    with pytest.raises(GeminiConfigurationError) as exc_info:
        GeminiClient(api_key="valid-test-key", model_id="   ")
    assert "Gemini model ID is not configured" in str(exc_info.value)


def test_prompt_validation():
    """Verify that empty, non-string, or whitespace-only prompts are rejected with ValueError."""
    fake_client = FakeGenAIClient()
    client = GeminiClient(client_instance=fake_client)

    # Empty string
    with pytest.raises(ValueError, match="Prompt must be a non-empty string"):
        client.generate("")

    # Whitespace only
    with pytest.raises(ValueError, match="Prompt must be a non-empty string"):
        client.generate("   \n\t  ")

    # Non-string types
    for bad_prompt in [None, 12345, [], {}]:
        with pytest.raises(ValueError, match="Prompt must be a non-empty string"):
            client.generate(bad_prompt)  # type: ignore


def test_exception_inheritance():
    """Verify that all client exception types inherit from GenerationError."""
    assert issubclass(GeminiConfigurationError, GenerationError)
    assert issubclass(GeminiAPIError, GenerationError)
    assert issubclass(EmptyResponseError, GenerationError)
