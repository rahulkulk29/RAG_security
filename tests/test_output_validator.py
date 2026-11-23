"""
Unit tests for OutputValidator and CanaryRegistry (Milestone 5.4).
Tests string validation, boundary length checks, whitespace normalization,
canary secret detection, registry error handling, and zero leakage in logs/exceptions.
"""
import json
import logging
import pytest
from pathlib import Path

from app.generation.output_validator import OutputValidator, CanaryRegistry
from app.generation.exceptions import (
    OutputValidationError,
    SensitiveOutputDetectedError,
    SecretRegistryError,
)

SYNTHETIC_TEST_CANARY = "CANARY_TEST_SYNTHETIC_TOKEN_99999"
SYNTHETIC_TEST_FLAG = "FLAG{TEST_SYNTHETIC_SECRET_12345}"


@pytest.fixture
def temp_canary_file(tmp_path: Path) -> Path:
    """Creates a temporary valid canaries.json file with synthetic test secrets."""
    canaries = [
        {
            "canary_id": "CANARY-TEST-01",
            "token": SYNTHETIC_TEST_CANARY,
            "tenant_id": "tenant_a",
            "doc_id": "doc_test_01",
            "access_level": "admin",
            "description": "Synthetic test canary 1",
            "canary_type": "standard_secret",
        },
        {
            "canary_id": "CANARY-TEST-02",
            "token": SYNTHETIC_TEST_FLAG,
            "tenant_id": "tenant_b",
            "doc_id": "doc_test_02",
            "access_level": "admin",
            "description": "Synthetic test canary 2",
            "canary_type": "standard_secret",
        },
    ]
    file_path = tmp_path / "test_canaries.json"
    file_path.write_text(json.dumps(canaries), encoding="utf-8")
    return file_path


@pytest.fixture
def custom_registry(temp_canary_file: Path) -> CanaryRegistry:
    return CanaryRegistry(registry_path=temp_canary_file)


@pytest.fixture
def validator(custom_registry: CanaryRegistry) -> OutputValidator:
    return OutputValidator(canary_registry=custom_registry, max_answer_length=1000)


# =========================================================================
# Output Validation Unit Tests
# =========================================================================

def test_valid_normal_answer_passes(validator):
    answer = "The system operates under multi-tenant isolation principles."
    result = validator.validate(answer)
    assert result == answer


def test_safe_normalization_strips_outer_whitespace_preserving_internal(validator):
    raw_answer = "  \n\tThe quarterly revenue is $5M.\nBreakdown:\n- Product: $3M\n- Services: $2M  \n"
    expected = "The quarterly revenue is $5M.\nBreakdown:\n- Product: $3M\n- Services: $2M"
    result = validator.validate(raw_answer)
    assert result == expected


@pytest.mark.parametrize("invalid_empty", ["", "   ", "\t\n  \r\n"])
def test_empty_or_whitespace_answer_rejected(validator, invalid_empty):
    with pytest.raises(OutputValidationError, match="output is empty"):
        validator.validate(invalid_empty)


@pytest.mark.parametrize("non_string", [None, 12345, True, False, ["an answer"], {"text": "hello"}])
def test_non_string_output_rejected(validator, non_string):
    with pytest.raises(OutputValidationError, match="output is invalid"):
        validator.validate(non_string)


def test_output_exceeding_max_length_rejected(validator):
    over_limit = "A" * 1001
    with pytest.raises(OutputValidationError, match="exceeds maximum allowed length"):
        validator.validate(over_limit)


def test_boundary_length_output_accepted(validator):
    # Exactly at limit (1000 chars)
    boundary = "A" * 1000
    result = validator.validate(boundary)
    assert len(result) == 1000
    assert result == boundary


def test_validator_constructor_invalid_max_length(custom_registry):
    with pytest.raises(ValueError, match="positive integer"):
        OutputValidator(canary_registry=custom_registry, max_answer_length=0)

    with pytest.raises(ValueError, match="positive integer"):
        OutputValidator(canary_registry=custom_registry, max_answer_length=-10)

    with pytest.raises(ValueError, match="positive integer"):
        OutputValidator(canary_registry=custom_registry, max_answer_length="1000")  # type: ignore


# =========================================================================
# Synthetic Secret Detection Tests
# =========================================================================

def test_exact_canary_value_detected(validator):
    with pytest.raises(SensitiveOutputDetectedError, match="contains protected content"):
        validator.validate(SYNTHETIC_TEST_CANARY)


def test_ordinary_answer_without_canary_passes(validator):
    answer = "All transactions are secured with TLS 1.3 and encrypted at rest."
    assert validator.validate(answer) == answer


def test_canary_in_middle_of_sentence_detected(validator):
    answer = f"The administrator credentials were found to be {SYNTHETIC_TEST_CANARY} in the audit log."
    with pytest.raises(SensitiveOutputDetectedError, match="contains protected content"):
        validator.validate(answer)


def test_flag_format_canary_detected(validator):
    answer = f"Key leaked: {SYNTHETIC_TEST_FLAG}"
    with pytest.raises(SensitiveOutputDetectedError, match="contains protected content"):
        validator.validate(answer)


def test_canary_with_valid_text_rejected_in_full(validator):
    answer = f"Here is the report overview:\nEverything looks normal.\nSecret: {SYNTHETIC_TEST_CANARY}\nEnd."
    with pytest.raises(SensitiveOutputDetectedError):
        validator.validate(answer)


def test_canary_never_appears_in_exception_message(validator):
    answer = f"Leaked {SYNTHETIC_TEST_CANARY}"
    try:
        validator.validate(answer)
        pytest.fail("Expected SensitiveOutputDetectedError")
    except SensitiveOutputDetectedError as exc:
        assert SYNTHETIC_TEST_CANARY not in str(exc)
        assert SYNTHETIC_TEST_FLAG not in str(exc)


def test_canary_never_appears_in_captured_logs(validator, caplog):
    answer = f"Sensitive data: {SYNTHETIC_TEST_CANARY}"
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(SensitiveOutputDetectedError):
            validator.validate(answer)

    assert SYNTHETIC_TEST_CANARY not in caplog.text
    assert SYNTHETIC_TEST_FLAG not in caplog.text


def test_case_sensitive_matching_policy(validator):
    # Canary is uppercase; lowercase variant should NOT match under documented policy
    lowercase_variant = SYNTHETIC_TEST_CANARY.lower()
    result = validator.validate(f"Token is {lowercase_variant}")
    assert lowercase_variant in result


# =========================================================================
# Canary Registry Failure and Edge Cases Tests
# =========================================================================

def test_missing_registry_file_fails_closed(tmp_path: Path):
    missing_path = tmp_path / "non_existent_canaries.json"
    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=missing_path)


def test_malformed_json_registry_fails_closed(tmp_path: Path):
    bad_json = tmp_path / "bad_canaries.json"
    bad_json.write_text("{ this is not valid json }", encoding="utf-8")
    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=bad_json)


def test_non_list_registry_fails_closed(tmp_path: Path):
    dict_json = tmp_path / "dict_canaries.json"
    dict_json.write_text(json.dumps({"token": "some_token"}), encoding="utf-8")
    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=dict_json)


def test_entry_missing_token_fails_closed(tmp_path: Path):
    invalid_entry = tmp_path / "invalid_entry_canaries.json"
    invalid_entry.write_text(json.dumps([{"canary_id": "C1"}]), encoding="utf-8")
    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=invalid_entry)


def test_entry_non_dict_fails_closed(tmp_path: Path):
    invalid_entry = tmp_path / "string_entry_canaries.json"
    invalid_entry.write_text(json.dumps(["CANARY_TOKEN_STRING"]), encoding="utf-8")
    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=invalid_entry)


def test_empty_registry_rejected_by_default(tmp_path: Path):
    """Empty canary registry file is rejected by default to prevent silent bypass."""
    empty_json = tmp_path / "empty_canaries.json"
    empty_json.write_text("[]", encoding="utf-8")
    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=empty_json)


def test_empty_registry_rejected_in_production(tmp_path: Path, monkeypatch):
    """Even with allow_empty=True, an empty registry must fail closed in production."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "environment", "production")
    empty_json = tmp_path / "empty_canaries.json"
    empty_json.write_text("[]", encoding="utf-8")

    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=empty_json, allow_empty=True)


def test_empty_registry_rejected_in_development_with_override(tmp_path: Path, monkeypatch):
    """Empty registry is rejected in development even when allow_empty=True is passed."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "environment", "development")
    empty_json = tmp_path / "empty_canaries.json"
    empty_json.write_text("[]", encoding="utf-8")

    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=empty_json, allow_empty=True)


def test_empty_registry_rejected_in_staging_with_override(tmp_path: Path, monkeypatch):
    """Empty registry is rejected in staging even when allow_empty=True is passed."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "environment", "staging")
    empty_json = tmp_path / "empty_canaries.json"
    empty_json.write_text("[]", encoding="utf-8")

    with pytest.raises(SecretRegistryError, match="unavailable"):
        CanaryRegistry(registry_path=empty_json, allow_empty=True)


def test_explicit_test_only_empty_registry_accepted(tmp_path: Path, monkeypatch):
    """Explicitly configured test-only option allows empty registries strictly in test environment."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "environment", "test")
    empty_json = tmp_path / "empty_canaries.json"
    empty_json.write_text("[]", encoding="utf-8")

    reg = CanaryRegistry(registry_path=empty_json, allow_empty=True)
    assert reg.token_count == 0
    assert reg.contains_canary("Any normal text") is False


def test_registry_initialization_errors_never_reveal_paths_or_tokens(tmp_path: Path):
    """Registry load failures must use static sanitized messages and never leak file paths."""
    secret_path = tmp_path / "secret_corp_financial_canaries.json"
    secret_path.write_text("{ malformed json }", encoding="utf-8")

    with pytest.raises(SecretRegistryError) as exc_info:
        CanaryRegistry(registry_path=secret_path)

    err_str = str(exc_info.value)
    assert "secret_corp_financial_canaries" not in err_str
    assert str(tmp_path) not in err_str
    assert err_str == "Secret registry is unavailable"


def test_production_default_registry_loads_real_canaries():
    """Verify default CanaryRegistry successfully loads the real project canaries.json."""
    reg = CanaryRegistry()
    assert reg.token_count > 0
    # Must contain the known real canaries without leaking them
    assert reg.contains_canary("Some totally normal response text without secrets") is False
    assert reg.contains_canary("CANARY_TENANT_A_MEMBER_APITOKEN_55210") is True

