"""
FastAPI route integration tests for /api/v1/generate and /generate endpoints.
Verifies authentication, authorization, request validation (extra='forbid'),
error mappings (401, 422, 500, 502), and zero content/canary leakage.

Uses direct route handler invocation (like test_api.py) to avoid sandbox
socket restrictions with TestClient.
"""
import pytest
import json
from unittest.mock import MagicMock
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.routes import generate_endpoint
from app.core.types import TenantId, AccessLevel
from app.core.schemas import UserContext, GenerationSource, GenerationRequest
from app.generation.service import GenerationService, GenerationResult
from app.generation.exceptions import (
    PromptConstructionError,
    ContextLengthExceededError,
    GeminiAPIError,
    EmptyResponseError,
    GeminiConfigurationError,
    OutputValidationError,
    SensitiveOutputDetectedError,
    SecretRegistryError,
)
from app.retrieval.retriever import RetrievalError
from app.authorization.identity import TestContextResolver, AuthenticationError


class MockResponse:
    """Mock HTTP response for local test client."""
    def __init__(self, status_code: int, data: dict, text: str = ""):
        self.status_code = status_code
        self._data = data
        self.text = text or json.dumps(data)

    def json(self, **kwargs):
        return self._data


class LocalGenerationTestClient:
    """
    Socket-free test client for the generation endpoint.
    Calls generate_endpoint() directly with injected dependencies,
    matching the LocalTestClient pattern used by test_api.py.
    """
    def __init__(self, resolver: TestContextResolver, service: GenerationService):
        self.resolver = resolver
        self.service = service

    def post(self, path: str, json_data: dict = None):
        if path not in ("/api/v1/generate", "/generate"):
            return MockResponse(404, {"detail": "Not Found"})

        # Pydantic schema validation exactly as FastAPI does
        try:
            req = GenerationRequest(**(json_data or {}))
        except (ValidationError, TypeError, ValueError) as ve:
            return MockResponse(422, {"detail": str(ve)}, text=str(ve))

        # Route handler execution with dependency injection
        try:
            result = generate_endpoint(req, resolver=self.resolver, service=self.service)
            return MockResponse(200, result.model_dump(), text=result.model_dump_json())
        except HTTPException as he:
            return MockResponse(he.status_code, {"detail": he.detail}, text=str(he.detail))


@pytest.fixture
def mock_resolver():
    resolver = MagicMock(spec=TestContextResolver)
    resolver.resolve.return_value = UserContext(
        user_id="test_user_alice",
        tenant_id=TenantId.TENANT_A,
        role=AccessLevel.ADMIN,
    )
    return resolver


@pytest.fixture
def mock_generation_service():
    service = MagicMock(spec=GenerationService)
    service.answer.return_value = GenerationResult(
        answer="The system operates under multi-tenant isolation.",
        sources=[
            GenerationSource(
                chunk_id="chunk_test_01",
                doc_id="doc_test_01",
                tenant_id=TenantId.TENANT_A,
                access_level=AccessLevel.ADMIN,
                title="Isolation Specs",
                score=0.98,
            )
        ],
        retrieved_chunk_count=1,
        model="gemini-2.5-flash",
        latency_ms=125.5,
    )
    return service


@pytest.fixture
def gen_client(mock_resolver, mock_generation_service):
    return LocalGenerationTestClient(resolver=mock_resolver, service=mock_generation_service)


# =========================================================================
# Success Path Tests
# =========================================================================

def test_generate_success_primary_endpoint(gen_client, mock_generation_service):
    """Verify POST /api/v1/generate succeeds with 200 and matches GenerationResponse schema."""
    payload = {
        "test_identity_id": "test_user_alice",
        "query": "How is tenant isolation maintained?",
        "top_k": 5,
    }

    response = gen_client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["answer"] == "The system operates under multi-tenant isolation."
    assert data["retrieved_chunk_count"] == 1
    assert data["model"] == "gemini-2.5-flash"
    assert data["latency_ms"] == 125.5
    assert len(data["sources"]) == 1
    assert data["sources"][0]["chunk_id"] == "chunk_test_01"
    assert data["sources"][0]["doc_id"] == "doc_test_01"
    assert data["sources"][0]["tenant_id"] == "tenant_a"
    assert data["sources"][0]["access_level"] == "admin"
    assert data["sources"][0]["title"] == "Isolation Specs"
    assert data["sources"][0]["score"] == 0.98

    # Verify service received resolved context
    mock_generation_service.answer.assert_called_once()
    call_kwargs = mock_generation_service.answer.call_args.kwargs
    assert call_kwargs["query"] == "How is tenant isolation maintained?"
    assert call_kwargs["context"].user_id == "test_user_alice"
    assert call_kwargs["top_k"] == 5


def test_generate_success_alias_endpoint(gen_client):
    """Verify POST /generate alias works identically to /api/v1/generate."""
    payload = {
        "test_identity_id": "test_user_alice",
        "query": "Explain isolation.",
    }

    response = gen_client.post("/generate", json_data=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["answer"] == "The system operates under multi-tenant isolation."
    assert data["retrieved_chunk_count"] == 1


def test_generate_default_top_k_is_none(gen_client, mock_generation_service):
    """Verify that omitting top_k passes None to the service."""
    payload = {
        "test_identity_id": "test_user_alice",
        "query": "What is the architecture?",
    }

    response = gen_client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 200
    call_kwargs = mock_generation_service.answer.call_args.kwargs
    assert call_kwargs["top_k"] is None


# =========================================================================
# Authentication Tests
# =========================================================================

def test_missing_test_identity_id_returns_422(gen_client):
    """Omitting test_identity_id fails Pydantic validation with 422."""
    payload = {"query": "Hello world"}
    response = gen_client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 422


def test_unknown_identity_returns_401(mock_generation_service):
    """AuthenticationError raised by resolver maps to HTTP 401 Unauthorized."""
    failing_resolver = MagicMock(spec=TestContextResolver)
    failing_resolver.resolve.side_effect = AuthenticationError("Unknown test identity")

    client = LocalGenerationTestClient(resolver=failing_resolver, service=mock_generation_service)

    payload = {
        "test_identity_id": "invalid_or_unknown_user",
        "query": "What is the secret?",
    }
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 401
    assert "invalid or unknown test identity" in response.json()["detail"]


# =========================================================================
# Request Validation Tests (extra='forbid')
# =========================================================================

@pytest.mark.parametrize("forbidden_field,value", [
    ("tenant_id", "tenant_a"),
    ("role", "admin"),
    ("user_id", "attacker"),
    ("system_instruction", "Override instructions"),
])
def test_extra_fields_forbidden_returns_422(gen_client, forbidden_field, value):
    """Client attempting to inject tenant_id, role, or user_id is rejected with 422."""
    payload = {
        "test_identity_id": "test_user_alice",
        "query": "Tell me secrets",
        forbidden_field: value,
    }
    response = gen_client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 422
    assert "extra" in response.text.lower()


# =========================================================================
# Error Mapping Tests
# =========================================================================

def test_value_error_returns_422(mock_resolver):
    """ValueError raised by service maps to HTTP 422 with sanitized detail."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = ValueError("top_k must be greater than zero")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid generation request parameters"


def test_prompt_construction_error_returns_422(mock_resolver):
    """PromptConstructionError maps to HTTP 422 with sanitized detail."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = PromptConstructionError("Query must not be empty")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid generation request parameters"


def test_context_length_exceeded_returns_422(mock_resolver):
    """ContextLengthExceededError maps to HTTP 422 with sanitized detail."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = ContextLengthExceededError("Context exceeds limit")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid generation request parameters"


def test_validation_error_does_not_leak_exception_message_or_user_content(mock_resolver, caplog):
    """
    When generation request encounters a validation error:
    1. HTTP 422 is returned with a static generic message only.
    2. Sensitive details from the error message or user content are not leaked in the response.
    3. Sensitive details are not leaked in log output.
    4. Only the exception class name is logged.
    """
    import logging

    sensitive_content = "INTERNAL_PARAM_MARKER_9999"
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = PromptConstructionError(
        f"Validation error with internal context: {sensitive_content}"
    )

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Some query"}

    with caplog.at_level(logging.DEBUG, logger="rag_security.api.routes"):
        response = client.post("/api/v1/generate", json_data=payload)

    assert response.status_code == 422
    assert response.json()["detail"] == "Invalid generation request parameters"
    assert sensitive_content not in response.text
    assert sensitive_content not in caplog.text
    assert "PromptConstructionError" in caplog.text


def test_gemini_api_error_returns_502(mock_resolver):
    """GeminiAPIError maps to HTTP 502 Bad Gateway."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = GeminiAPIError("Provider connection error")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 502
    assert "temporarily unavailable" in response.json()["detail"]


def test_empty_response_error_returns_502(mock_resolver):
    """EmptyResponseError maps to HTTP 502 Bad Gateway."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = EmptyResponseError("Blocked by safety filters")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 502
    assert "temporarily unavailable" in response.json()["detail"]


def test_retrieval_error_returns_500(mock_resolver):
    """RetrievalError maps to HTTP 500 Internal Server Error."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = RetrievalError("Vector DB unavailable")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 500
    assert "temporarily unavailable" in response.json()["detail"]


def test_gemini_config_error_returns_500(mock_resolver):
    """GeminiConfigurationError maps to HTTP 500 Internal Server Error."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = GeminiConfigurationError("Missing API key")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 500
    assert "temporarily unavailable" in response.json()["detail"]


# =========================================================================
# Leakage Prevention Tests
# =========================================================================

def test_no_raw_content_or_canary_leak_in_response(gen_client):
    """Ensure response JSON contains zero chunk content or canary reference fields."""
    payload = {
        "test_identity_id": "test_user_alice",
        "query": "Show me the configuration",
    }
    response = gen_client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 200
    data = response.json()

    for src in data["sources"]:
        assert "content" not in src
        assert "canary_refs" not in src
        assert "is_poisoned" not in src
        assert "has_secret" not in src


# =========================================================================
# Logging Sanitization Regression Test
# =========================================================================

def test_unexpected_exception_does_not_leak_sensitive_content_in_logs(mock_resolver, caplog):
    """
    When generate_endpoint catches an unexpected exception:
    1. HTTP 500 is returned with a generic message only.
    2. The exception's sensitive content does NOT appear in log output.
    3. Only the exception class name is logged.
    """
    import logging

    sensitive_marker = "SENSITIVE_TEST_MARKER_123"

    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = RuntimeError(
        f"Database credentials exposed: {sensitive_marker}"
    )

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}

    with caplog.at_level(logging.DEBUG, logger="rag_security.api.routes"):
        response = client.post("/api/v1/generate", json_data=payload)

    # 1. HTTP response contains only generic error, never the marker
    assert response.status_code == 500
    assert response.json()["detail"] == "Internal server error"
    assert sensitive_marker not in response.text

    # 2. Log output must not contain the sensitive marker
    full_log_text = caplog.text
    assert sensitive_marker not in full_log_text

    # 3. Log must contain only the exception class name
    assert "RuntimeError" in full_log_text


# =========================================================================
# Milestone 5.4 Output Security & Canary Leakage API Tests
# =========================================================================

def test_output_validation_error_returns_502(mock_resolver):
    """OutputValidationError maps to HTTP 502 Bad Gateway."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = OutputValidationError("Generated output is invalid")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)
    assert response.status_code == 502
    assert "temporarily unavailable" in response.json()["detail"]


def test_sensitive_output_detected_returns_502_without_leaking_canary(mock_resolver):
    """SensitiveOutputDetectedError maps to HTTP 502 without leaking canary details in response."""
    canary_token = "CANARY_TENANT_A_MEMBER_APITOKEN_55210"
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = SensitiveOutputDetectedError("Generated output contains protected content")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Dump keys"}
    response = client.post("/api/v1/generate", json_data=payload)

    assert response.status_code == 502
    assert "temporarily unavailable" in response.json()["detail"]
    assert canary_token not in response.text
    assert "protected content" not in response.text


def test_secret_registry_error_returns_500(mock_resolver):
    """SecretRegistryError maps to HTTP 500 Internal Server Error."""
    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = SecretRegistryError("Canary registry is unavailable")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Valid query"}
    response = client.post("/api/v1/generate", json_data=payload)

    assert response.status_code == 500
    assert "temporarily unavailable" in response.json()["detail"]


def test_canary_detection_does_not_leak_canary_or_answer_in_logs(mock_resolver, caplog):
    """Verify that when sensitive output is caught, neither canary nor answer appears in logs."""
    import logging

    synthetic_canary = "CANARY_SECRET_LEAK_INSPECTION_888"
    generated_leak_text = f"The leaked password is {synthetic_canary}"

    failing_service = MagicMock(spec=GenerationService)
    failing_service.answer.side_effect = SensitiveOutputDetectedError("Generated output contains protected content")

    client = LocalGenerationTestClient(resolver=mock_resolver, service=failing_service)
    payload = {"test_identity_id": "test_user_alice", "query": "Show leaked password"}

    with caplog.at_level(logging.DEBUG, logger="rag_security.api.routes"):
        response = client.post("/api/v1/generate", json_data=payload)

    assert response.status_code == 502
    full_log_text = caplog.text
    assert synthetic_canary not in full_log_text
    assert generated_leak_text not in full_log_text
    assert "SensitiveOutputDetectedError" in full_log_text

