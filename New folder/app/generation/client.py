"""
Gemini Generation Client for secure LLM invocation using the Google GenAI SDK.
"""
import logging
from typing import Optional, Any, Union
from google import genai
from google.genai import types

from app.core.config import settings
from app.generation.exceptions import (
    GenerationError,
    GeminiConfigurationError,
    GeminiAPIError,
    EmptyResponseError,
)
from app.generation.prompts import PromptBundle, DEFAULT_SYSTEM_INSTRUCTION

logger = logging.getLogger("rag_security.generation.client")


class GeminiClient:
    """
    Client for generating text with Google Gemini models via google-genai SDK.

    Security controls:
    1. Configuration validation: Fails closed when API key or model ID is missing or empty.
    2. Zero secret leakage: Never echoes API keys, prompts, or sensitive error tokens in logs/exceptions.
    3. Safe error translation: Provider exceptions are translated to sanitized GeminiAPIError with no retained context.
    4. Malformed/empty response defense: Responses without text content fail closed with EmptyResponseError.
    5. Exception isolation: Ensures public exceptions do not retain sensitive provider objects in __cause__ or __context__.
    6. System instruction ownership: The client strictly owns the trusted system instruction (DEFAULT_SYSTEM_INSTRUCTION).
       No constructor argument, raw prompt string, or PromptBundle is permitted to override it.
    7. Dependency injection: Supports custom client or model instances/fake providers for isolated testing.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_id: Optional[str] = None,
        temperature: Optional[float] = None,
        timeout: Optional[float] = None,
        model_instance: Optional[Any] = None,
        client_instance: Optional[Any] = None,
    ):
        """
        Initializes the Gemini client.

        Args:
            api_key: Optional Gemini API key override (defaults to settings.gemini_api_key).
            model_id: Optional model identifier override (defaults to settings.gemini_model_id).
            temperature: Sampling temperature (defaults to settings.gemini_temperature or 0.0).
            timeout: Request timeout in seconds (defaults to settings.gemini_request_timeout or 30.0).
            model_instance: Injected provider/model instance for testing without network calls.
            client_instance: Injected genai.Client instance for testing without network calls.
        """
        self.temperature = (
            temperature
            if temperature is not None
            else getattr(settings, "gemini_temperature", 0.0)
        )
        self.timeout = (
            timeout
            if timeout is not None
            else getattr(settings, "gemini_request_timeout", 30.0)
        )
        # Client strictly owns the application trusted system instruction
        self.system_instruction = DEFAULT_SYSTEM_INSTRUCTION

        # Resolve configuration values
        self._api_key = (
            api_key
            if api_key is not None
            else getattr(settings, "gemini_api_key", None)
        )
        self.model_id = (
            model_id
            if model_id is not None
            else getattr(settings, "gemini_model_id", None)
        )

        # Injected provider instance (supports both client_instance and model_instance)
        injected = client_instance if client_instance is not None else model_instance
        self._client = injected

        if self._client is None:
            if not self._api_key or not isinstance(self._api_key, str) or not self._api_key.strip():
                raise GeminiConfigurationError("Gemini API key is not configured")
            if not self.model_id or not isinstance(self.model_id, str) or not self.model_id.strip():
                raise GeminiConfigurationError("Gemini model ID is not configured")

            self._client = genai.Client(api_key=self._api_key)
        else:
            if not self.model_id:
                self.model_id = "mock-gemini-model"

    def _build_generation_config(
        self,
        effective_timeout: Optional[float] = None,
    ) -> types.GenerateContentConfig:
        """
        Builds the GenerateContentConfig with temperature, trusted system instruction, and http_options.
        """
        http_options: Optional[types.HttpOptions] = None
        if effective_timeout is not None and effective_timeout > 0:
            # google-genai types.HttpOptions expects timeout in milliseconds
            timeout_ms = int(effective_timeout * 1000)
            http_options = types.HttpOptions(timeout=timeout_ms)

        config_kwargs: dict[str, Any] = {
            "temperature": self.temperature,
            "system_instruction": self.system_instruction,
        }
        if http_options is not None:
            config_kwargs["http_options"] = http_options

        return types.GenerateContentConfig(**config_kwargs)

    def generate(
        self,
        prompt: Union[str, PromptBundle],
        timeout: Optional[float] = None,
    ) -> str:
        """
        Submits prompt to configured Gemini model and returns generated text.

        The generation client strictly owns the trusted system instruction. If a PromptBundle is provided,
        its user_prompt is treated strictly as untrusted input. The client never accepts system instruction
        overrides from generate() callers.

        Args:
            prompt: Text prompt string or explicit PromptBundle instance.
            timeout: Optional per-request timeout override in seconds.

        Returns:
            Non-empty generated text response string.

        Raises:
            ValueError: If prompt is empty or not a valid string or PromptBundle instance.
            GeminiConfigurationError: If client model is not configured.
            GeminiAPIError: If provider API or network call fails.
            EmptyResponseError: If model returns an empty or unparseable response.
        """
        # 1. Validate prompt input with explicit type checks
        if isinstance(prompt, str):
            if not prompt.strip():
                raise ValueError("Prompt must be a non-empty string")
            prompt_str = prompt
        elif isinstance(prompt, PromptBundle):
            # PromptBundle.user_prompt is treated strictly as untrusted input.
            if not prompt.user_prompt or not prompt.user_prompt.strip():
                raise ValueError("Prompt must be a non-empty string")
            prompt_str = prompt.user_prompt
        else:
            raise ValueError("Prompt must be a non-empty string or PromptBundle")

        if self._client is None:
            raise GeminiConfigurationError("Gemini client is not configured")

        effective_timeout = timeout if timeout is not None else self.timeout
        config = self._build_generation_config(
            effective_timeout=effective_timeout,
        )

        # 2. Invoke model generation safely
        logger.debug(
            "Submitting generation request to model '%s' (prompt_length=%d)",
            self.model_id,
            len(prompt_str),
        )

        response = None
        provider_failed = False
        provider_error_type: Optional[str] = None

        try:
            if hasattr(self._client, "models") and hasattr(self._client.models, "generate_content"):
                response = self._client.models.generate_content(
                    model=self.model_id,
                    contents=prompt_str,
                    config=config,
                )
            elif hasattr(self._client, "generate_content"):
                # Support injected mock models with generate_content
                try:
                    response = self._client.generate_content(
                        model=self.model_id,
                        contents=prompt_str,
                        config=config,
                    )
                except TypeError:
                    try:
                        response = self._client.generate_content(prompt_str, config=config)
                    except TypeError:
                        response = self._client.generate_content(prompt_str)
            else:
                provider_failed = True
                provider_error_type = "InvalidProviderInterface"
        except Exception as exc:
            provider_failed = True
            provider_error_type = type(exc).__name__

        # Handle provider failure strictly OUTSIDE the except block to ensure
        # the original exception is never attached to __context__ or __cause__.
        if provider_failed:
            logger.error("Gemini generation failed (%s)", provider_error_type)
            api_err = GeminiAPIError("Gemini generation request failed")
            api_err.__cause__ = None
            api_err.__context__ = None
            api_err.error_type = provider_error_type
            raise api_err

        # 3. Parse and validate response content
        if response is None:
            logger.warning("Gemini returned None response")
            empty_err = EmptyResponseError("Gemini returned an empty or unparseable response")
            empty_err.__cause__ = None
            empty_err.__context__ = None
            raise empty_err

        text_content: Optional[str] = None
        extraction_failed = False
        extraction_error_type: Optional[str] = None

        try:
            # In google-genai, GenerateContentResponse exposes a .text property
            text_candidate = getattr(response, "text", None)
            if text_candidate is not None:
                text_content = text_candidate
        except Exception as err:
            extraction_failed = True
            extraction_error_type = type(err).__name__

        # Handle extraction failure strictly OUTSIDE the except block
        if extraction_failed:
            logger.warning(
                "Failed to extract text from Gemini response (%s)",
                extraction_error_type,
            )
            empty_err = EmptyResponseError("Gemini returned an empty or unparseable response")
            empty_err.__cause__ = None
            empty_err.__context__ = None
            empty_err.error_type = extraction_error_type
            raise empty_err

        if text_content is None:
            if isinstance(response, str):
                text_content = response
            elif isinstance(response, dict) and "text" in response:
                text_content = response["text"]
            else:
                logger.warning(
                    "Gemini returned unrecognized response format (%s)",
                    type(response).__name__,
                )
                empty_err = EmptyResponseError("Gemini returned an empty or unparseable response")
                empty_err.__cause__ = None
                empty_err.__context__ = None
                raise empty_err

        if not isinstance(text_content, str) or not text_content.strip():
            logger.warning("Gemini response contained empty or whitespace-only text")
            empty_err = EmptyResponseError("Gemini returned an empty or unparseable response")
            empty_err.__cause__ = None
            empty_err.__context__ = None
            raise empty_err

        logger.debug(
            "Generation completed successfully for model '%s' (response_length=%d)",
            self.model_id,
            len(text_content),
        )
        return text_content
