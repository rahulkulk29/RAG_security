"""
Exception hierarchy for LLM generation operations.
"""

class GenerationError(Exception):
    """Base exception for all generation operations."""
    pass


class GeminiConfigurationError(GenerationError):
    """Raised when required Gemini configuration (API key, model ID) is missing or invalid."""
    pass


class GeminiAPIError(GenerationError):
    """Raised when the Gemini API provider encounters an error or network failure."""
    pass


class EmptyResponseError(GenerationError):
    """Raised when the Gemini model returns an empty, blocked, or unparseable response."""
    pass


class PromptConstructionError(GenerationError, ValueError):
    """Raised when prompt construction or query input validation fails."""
    pass


class ContextLengthExceededError(PromptConstructionError):
    """Raised when the serialized retrieval context exceeds the maximum allowed length."""
    pass


class OutputValidationError(GenerationError):
    """Raised when the generated output is invalid, empty, or exceeds configured limits."""
    pass


class SensitiveOutputDetectedError(GenerationError):
    """Raised when the generated output contains a protected synthetic canary token."""
    pass


class SecretRegistryError(GenerationError):
    """Raised when the canary/secret registry cannot be loaded, parsed, or validated."""
    pass
