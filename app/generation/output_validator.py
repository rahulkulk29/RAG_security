"""
Output validation and synthetic secret leakage protection for generated answers.

Security design:
1. Output validation: Rejects non-string, empty, whitespace-only, and over-limit generated
   answers. Does not silently truncate; fails closed on invalid output.
2. Canary registry: Loads synthetic canary token values from the trusted server-side registry
   (data/secrets/canaries.json). Never accepts canary values from API requests.
3. Leakage detection: Performs case-sensitive exact substring matching of each registered
   canary token against the generated answer text. If any token appears anywhere in the
   answer, the entire answer is rejected — never partially returned.
4. Fail-closed: If the registry file is missing, unreadable, or malformed, generation
   fails closed with SecretRegistryError.
5. Sanitized logging: Never logs canary token values, generated answer content, or
   registry file paths in error messages or exception text.

Known limitations:
- Exact substring matching only. Does not detect encoded, obfuscated, paraphrased,
  transliterated, base64-wrapped, or semantically equivalent representations of secrets.
- Case-sensitive matching. This matches the existing canary format (all-caps structured
  tokens and FLAG{...} patterns). Case-insensitive matching would increase false positives
  for short tokens without meaningful security benefit against encoding attacks.
- This is a synthetic secret leakage defense for the security testbed, not a complete
  data loss prevention (DLP) product.
"""
import json
import logging
from pathlib import Path
from typing import Optional, FrozenSet

from app.core.config import settings
from app.generation.exceptions import (
    OutputValidationError,
    SensitiveOutputDetectedError,
    SecretRegistryError,
)

logger = logging.getLogger("rag_security.generation.output_validator")


class CanaryRegistry:
    """
    Immutable registry of synthetic canary token values loaded from the
    trusted server-side secrets file.

    The registry is loaded once at initialization and stored as a frozen set
    of token strings. It never exposes token values in logs, exceptions,
    or API responses.
    """

    def __init__(
        self,
        registry_path: Optional[Path] = None,
        allow_empty: bool = False,
    ):
        """
        Loads canary tokens from the registry file.

        Args:
            registry_path: Path to canaries.json. Defaults to settings.canaries_path.
            allow_empty: Explicit test-only flag to allow zero registered tokens.
                Defaults to False. Strictly permitted only when settings.environment == "test".
                Always rejected in production, staging, and development environments.

        Raises:
            SecretRegistryError: If the file is missing, unreadable, malformed,
                or empty (when allow_empty is False or in production).
        """
        path = registry_path if registry_path is not None else settings.canaries_path

        try:
            raw_text = Path(path).read_text(encoding="utf-8")
        except (FileNotFoundError, PermissionError, OSError):
            logger.error("Secret registry unavailable: cannot read registry file")
            raise SecretRegistryError("Secret registry is unavailable")

        try:
            data = json.loads(raw_text)
        except (json.JSONDecodeError, ValueError):
            logger.error("Secret registry unavailable: malformed JSON")
            raise SecretRegistryError("Secret registry is unavailable")

        if not isinstance(data, list):
            logger.error("Secret registry unavailable: expected a JSON array")
            raise SecretRegistryError("Secret registry is unavailable")

        tokens: set[str] = set()
        for idx, entry in enumerate(data):
            if not isinstance(entry, dict):
                logger.error("Secret registry unavailable: entry at index %d is not a dict", idx)
                raise SecretRegistryError("Secret registry is unavailable")

            token = entry.get("token")
            if not isinstance(token, str) or not token.strip():
                logger.error("Secret registry unavailable: missing or invalid token at index %d", idx)
                raise SecretRegistryError("Secret registry is unavailable")

            tokens.add(token)

        # Enforce non-empty registry: empty registries are rejected by default.
        # Non-empty canary registries are mandatory in production, staging, and development.
        # allow_empty=True is permitted strictly when settings.environment == "test" for isolated unit tests.
        if not tokens:
            current_env = getattr(settings, "environment", "development").lower()
            if current_env != "test" or not allow_empty:
                logger.error("Secret registry unavailable: registry contains no valid canary tokens")
                raise SecretRegistryError("Secret registry is unavailable")

        self._tokens: FrozenSet[str] = frozenset(tokens)
        logger.debug("Canary registry loaded successfully (token_count=%d)", len(self._tokens))

    @property
    def token_count(self) -> int:
        """Returns the number of registered canary tokens."""
        return len(self._tokens)

    def contains_canary(self, text: str) -> bool:
        """
        Checks whether the text contains any registered canary token value.

        Uses case-sensitive exact substring matching. See module docstring
        for detection limitations.

        Args:
            text: The generated answer text to scan.

        Returns:
            True if any canary token appears as a substring in the text.
        """
        for token in self._tokens:
            if token in text:
                return True
        return False


class OutputValidator:
    """
    Validates generated answers and scans for synthetic secret leakage.

    Validation rules:
    1. Output must be a string.
    2. Output must not be empty or whitespace-only.
    3. Output must not exceed max_answer_length characters.
    4. Output must not contain any registered canary token value.

    When validation passes, the answer is returned with leading/trailing
    whitespace stripped. No other semantic transformation is applied.
    """

    def __init__(
        self,
        canary_registry: Optional[CanaryRegistry] = None,
        max_answer_length: Optional[int] = None,
    ):
        """
        Args:
            canary_registry: Injected CanaryRegistry for testing. Defaults to loading
                from settings.canaries_path.
            max_answer_length: Maximum allowed answer length. Defaults to settings.max_answer_length.

        Raises:
            SecretRegistryError: If the canary registry cannot be loaded.
        """
        self.registry = canary_registry if canary_registry is not None else CanaryRegistry()

        raw_max = (
            max_answer_length
            if max_answer_length is not None
            else getattr(settings, "max_answer_length", 50000)
        )
        if isinstance(raw_max, bool) or not isinstance(raw_max, int) or raw_max <= 0:
            raise ValueError("max_answer_length must be a positive integer")
        self.max_answer_length = raw_max

    def validate(self, answer: object) -> str:
        """
        Validates a generated answer for type, content, length, and secret leakage.

        Args:
            answer: The raw generated answer from the Gemini client.

        Returns:
            The validated and whitespace-stripped answer string.

        Raises:
            OutputValidationError: If the answer is invalid (non-string, empty, over-limit).
            SensitiveOutputDetectedError: If the answer contains a registered canary token.
        """
        # 1. Type check
        if not isinstance(answer, str):
            logger.warning("Output validation failed: non-string output type (%s)", type(answer).__name__)
            raise OutputValidationError("Generated output is invalid")

        # 2. Empty/whitespace check
        clean = answer.strip()
        if not clean:
            logger.warning("Output validation failed: empty or whitespace-only output")
            raise OutputValidationError("Generated output is empty")

        # 3. Length check (on stripped output)
        if len(clean) > self.max_answer_length:
            logger.warning(
                "Output validation failed: output length (%d) exceeds maximum (%d)",
                len(clean),
                self.max_answer_length,
            )
            raise OutputValidationError("Generated output exceeds maximum allowed length")

        # 4. Canary leakage check
        if self.registry.contains_canary(clean):
            logger.warning("Output validation failed: protected content detected in generated output")
            raise SensitiveOutputDetectedError("Generated output contains protected content")

        return clean

