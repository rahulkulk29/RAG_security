"""
Unit tests for GenerationService (Milestone 5.3).
Tests dependency injection, query validation, authorization filtering,
prompt construction integration, Gemini client invocation, safe source formatting,
exception propagation, and the mandatory security regression test.
"""
import pytest
from unittest.mock import MagicMock
from typing import List, Optional

from app.core.types import TenantId, AccessLevel
from app.core.schemas import UserContext, DocumentChunk, CandidateChunk, GenerationSource
from app.generation.service import GenerationService, GenerationResult
from app.generation.prompts import PromptBuilder, PromptBundle
from app.generation.client import GeminiClient
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
from app.retrieval.retriever import SecureRetriever, RetrievalError
from app.authorization.guard import AuthorizationGuard
from app.generation.output_validator import OutputValidator, CanaryRegistry


def _create_candidate(
    chunk_id: str,
    doc_id: str,
    tenant_id: TenantId,
    access_level: AccessLevel,
    title: str = "Test Title",
    content: str = "Test content.",
    score: float = 0.95,
) -> CandidateChunk:
    chunk = DocumentChunk(
        chunk_id=chunk_id,
        doc_id=doc_id,
        tenant_id=tenant_id,
        access_level=access_level,
        title=title,
        content=content,
        chunk_index=0,
        category="security",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    return CandidateChunk(
        chunk=chunk,
        score=score,
        distance=0.05,
    )


class FakeRetriever:
    """Fake retriever that returns pre-configured candidates without network."""
    def __init__(self, candidates: Optional[List[CandidateChunk]] = None):
        self.candidates = candidates if candidates is not None else []
        self.last_query = None
        self.last_context = None
        self.last_top_k = None

    def retrieve(self, query: str, context: UserContext, top_k: Optional[int] = None) -> List[CandidateChunk]:
        self.last_query = query
        self.last_context = context
        self.last_top_k = top_k
        return self.candidates


class FakeGeminiClient:
    """Fake Gemini client returning canned responses without API calls."""
    def __init__(self, response_text: str = "This is a safe generated answer."):
        self.response_text = response_text
        self.model_id = "gemini-2.5-flash"
        self.last_prompt = None

    def generate(self, prompt, timeout=None) -> str:
        self.last_prompt = prompt
        return self.response_text


@pytest.fixture
def user_context_tenant_a():
    return UserContext(user_id="alice", tenant_id=TenantId.TENANT_A, role=AccessLevel.ADMIN)


@pytest.fixture
def user_context_tenant_b():
    return UserContext(user_id="bob", tenant_id=TenantId.TENANT_B, role=AccessLevel.MEMBER)


# =========================================================================
# Initialization Tests
# =========================================================================

def test_service_initialization_with_custom_dependencies(user_context_tenant_a):
    """Verify GenerationService correctly accepts custom injected components."""
    fake_retriever = FakeRetriever()
    fake_guard = AuthorizationGuard()
    fake_builder = PromptBuilder()
    fake_client = FakeGeminiClient()

    service = GenerationService(
        retriever=fake_retriever,
        guard=fake_guard,
        prompt_builder=fake_builder,
        gemini_client=fake_client,
    )
    assert service.retriever is fake_retriever
    assert service.guard is fake_guard
    assert service.prompt_builder is fake_builder
    assert service.gemini_client is fake_client


# =========================================================================
# Successful Generation Tests
# =========================================================================

def test_successful_generation_end_to_end(user_context_tenant_a):
    """Test successful end-to-end generation with mocked components."""
    candidate = _create_candidate(
        chunk_id="chk_01",
        doc_id="doc_01",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.ADMIN,
        title="Payment Security Rules",
        content="Payment tokens expire after 15 minutes.",
    )
    fake_retriever = FakeRetriever(candidates=[candidate])
    fake_client = FakeGeminiClient(response_text="Payment tokens expire in 15 minutes.")

    service = GenerationService(
        retriever=fake_retriever,
        gemini_client=fake_client,
    )

    result = service.answer(
        query="What is the token expiration?",
        context=user_context_tenant_a,
        top_k=5,
    )

    assert isinstance(result, GenerationResult)
    assert result.answer == "Payment tokens expire in 15 minutes."
    assert result.model == "gemini-2.5-flash"
    assert result.retrieved_chunk_count == 1
    assert len(result.sources) == 1
    assert result.sources[0].chunk_id == "chk_01"
    assert result.sources[0].doc_id == "doc_01"
    assert result.sources[0].tenant_id == TenantId.TENANT_A
    assert result.sources[0].access_level == AccessLevel.ADMIN
    assert result.sources[0].title == "Payment Security Rules"
    assert result.sources[0].score == 0.95
    assert result.latency_ms >= 0.0


def test_empty_retrieval_generation(user_context_tenant_a):
    """Test that empty retrieval proceeds through PromptBuilder's empty-context mechanism."""
    fake_retriever = FakeRetriever(candidates=[])
    fake_client = FakeGeminiClient(response_text="No documents were available to answer your query.")

    service = GenerationService(
        retriever=fake_retriever,
        gemini_client=fake_client,
    )

    result = service.answer(
        query="Where is the secret key?",
        context=user_context_tenant_a,
    )

    assert result.answer == "No documents were available to answer your query."
    assert result.retrieved_chunk_count == 0
    assert result.sources == []
    # Verify prompt builder sent empty context marker
    assert isinstance(fake_client.last_prompt, PromptBundle)
    assert "No reference documents provided or available" in fake_client.last_prompt.user_prompt


def test_sources_contain_no_raw_content(user_context_tenant_a):
    """Verify that GenerationSource models contain metadata only, never raw chunk content."""
    candidate = _create_candidate(
        chunk_id="chk_sensitive_01",
        doc_id="doc_sensitive_01",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.ADMIN,
        title="Confidential Key",
        content="SECRET_RAW_CONTENT_CANARY_VALUE_12345",
    )
    fake_retriever = FakeRetriever(candidates=[candidate])
    fake_client = FakeGeminiClient()

    service = GenerationService(
        retriever=fake_retriever,
        gemini_client=fake_client,
    )

    result = service.answer(
        query="What is the key?",
        context=user_context_tenant_a,
    )

    for source in result.sources:
        source_dict = source.model_dump()
        assert "content" not in source_dict
        assert "SECRET_RAW_CONTENT_CANARY_VALUE_12345" not in str(source_dict)


# =========================================================================
# Query Validation Tests
# =========================================================================

@pytest.mark.parametrize("invalid_query", ["", "   ", "\t\n  "])
def test_empty_or_whitespace_query_raises_error(user_context_tenant_a, invalid_query):
    """Empty/whitespace queries are rejected with PromptConstructionError."""
    fake_client = FakeGeminiClient()
    service = GenerationService(
        retriever=FakeRetriever(),
        gemini_client=fake_client,
    )
    with pytest.raises(PromptConstructionError):
        service.answer(query=invalid_query, context=user_context_tenant_a)


# =========================================================================
# top_k Validation Tests
# =========================================================================

@pytest.mark.parametrize("invalid_top_k", [0, -1, -50])
def test_non_positive_top_k_raises_value_error(user_context_tenant_a, invalid_top_k):
    fake_client = FakeGeminiClient()
    service = GenerationService(
        retriever=FakeRetriever(),
        gemini_client=fake_client,
    )
    with pytest.raises(ValueError, match="greater than zero"):
        service.answer(query="valid query", context=user_context_tenant_a, top_k=invalid_top_k)


def test_exceeding_max_top_k_raises_value_error(user_context_tenant_a):
    fake_client = FakeGeminiClient()
    service = GenerationService(
        retriever=FakeRetriever(),
        gemini_client=fake_client,
    )
    with pytest.raises(ValueError, match="exceeds maximum allowed limit"):
        service.answer(query="valid query", context=user_context_tenant_a, top_k=500)


# =========================================================================
# Exception Propagation Tests
# =========================================================================

def test_prompt_builder_context_length_exceeded_propagates(user_context_tenant_a):
    mock_builder = MagicMock()
    mock_builder.build.side_effect = ContextLengthExceededError("Context too long")

    candidate = _create_candidate("c1", "d1", TenantId.TENANT_A, AccessLevel.PUBLIC)
    fake_retriever = FakeRetriever([candidate])

    service = GenerationService(
        retriever=fake_retriever,
        prompt_builder=mock_builder,
        gemini_client=FakeGeminiClient(),
    )

    with pytest.raises(ContextLengthExceededError, match="Context too long"):
        service.answer(query="test query", context=user_context_tenant_a)


def test_prompt_construction_error_propagates(user_context_tenant_a):
    mock_builder = MagicMock()
    mock_builder.build.side_effect = PromptConstructionError("Construction failed")

    service = GenerationService(
        retriever=FakeRetriever([]),
        prompt_builder=mock_builder,
        gemini_client=FakeGeminiClient(),
    )

    with pytest.raises(PromptConstructionError, match="Construction failed"):
        service.answer(query="test query", context=user_context_tenant_a)


def test_gemini_api_error_propagates(user_context_tenant_a):
    mock_client = MagicMock()
    mock_client.generate.side_effect = GeminiAPIError("Model quota exceeded")
    mock_client.model_id = "mock-model"

    service = GenerationService(
        retriever=FakeRetriever([]),
        gemini_client=mock_client,
    )

    with pytest.raises(GeminiAPIError, match="Model quota exceeded"):
        service.answer(query="test query", context=user_context_tenant_a)


def test_empty_response_error_propagates(user_context_tenant_a):
    mock_client = MagicMock()
    mock_client.generate.side_effect = EmptyResponseError("Blocked by safety filters")
    mock_client.model_id = "mock-model"

    service = GenerationService(
        retriever=FakeRetriever([]),
        gemini_client=mock_client,
    )

    with pytest.raises(EmptyResponseError, match="Blocked by safety filters"):
        service.answer(query="test query", context=user_context_tenant_a)


def test_retrieval_error_propagates(user_context_tenant_a):
    mock_retriever = MagicMock()
    mock_retriever.retrieve.side_effect = RetrievalError("Chroma index corrupted")

    service = GenerationService(
        retriever=mock_retriever,
        gemini_client=FakeGeminiClient(),
    )

    with pytest.raises(RetrievalError, match="Chroma index corrupted"):
        service.answer(query="test query", context=user_context_tenant_a)


# =========================================================================
# MANDATORY CRITICAL SECURITY REGRESSION TEST
# =========================================================================

def test_mandatory_security_regression_authorization_filter_isolation():
    """
    CRITICAL SECURITY REGRESSION TEST:
    Verify that if retrieval produces candidates from multiple tenants or exceeding privilege:
    1. AuthorizationGuard filters out all unauthorized chunks.
    2. PromptBuilder receives ONLY authorized chunks.
    3. The prompt sent to GeminiClient contains ONLY authorized chunks and NO unauthorized content.
    4. The returned GenerationResult.sources contains ONLY authorized chunks.
    """
    context_member_a = UserContext(
        user_id="alice_member",
        tenant_id=TenantId.TENANT_A,
        role=AccessLevel.MEMBER,
    )

    authorized_chunk = _create_candidate(
        chunk_id="auth_chunk_ta_01",
        doc_id="doc_ta_01",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.MEMBER,
        title="Authorized Tenant A Document",
        content="AUTHORIZED_CONTENT_ALPHA",
    )
    unauthorized_other_tenant = _create_candidate(
        chunk_id="unauth_chunk_tb_01",
        doc_id="doc_tb_01",
        tenant_id=TenantId.TENANT_B,  # Tenant B chunk should be blocked for Tenant A user!
        access_level=AccessLevel.PUBLIC,
        title="Unauthorized Tenant B Document",
        content="UNAUTHORIZED_TENANT_B_CONTENT_BETA",
    )
    unauthorized_higher_clearance = _create_candidate(
        chunk_id="unauth_chunk_ta_admin",
        doc_id="doc_ta_admin",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.ADMIN,  # ADMIN exceeds MEMBER clearance!
        title="Admin Document",
        content="UNAUTHORIZED_ADMIN_CONTENT_GAMMA",
    )

    # Retriever returns mixed candidates (simulating bypass or bad retriever mock)
    mixed_candidates = [authorized_chunk, unauthorized_other_tenant, unauthorized_higher_clearance]
    fake_retriever = FakeRetriever(candidates=mixed_candidates)
    fake_client = FakeGeminiClient(response_text="Processed safe context.")

    service = GenerationService(
        retriever=fake_retriever,
        guard=AuthorizationGuard(),
        prompt_builder=PromptBuilder(),
        gemini_client=fake_client,
    )

    result = service.answer(
        query="List all configuration details",
        context=context_member_a,
    )

    # 1. Output sources verification
    assert result.retrieved_chunk_count == 1
    assert len(result.sources) == 1
    assert result.sources[0].chunk_id == "auth_chunk_ta_01"
    assert result.sources[0].tenant_id == TenantId.TENANT_A
    assert result.sources[0].access_level == AccessLevel.MEMBER

    # 2. Gemini prompt inspection
    assert isinstance(fake_client.last_prompt, PromptBundle)
    sent_prompt = fake_client.last_prompt.user_prompt

    # Authorized content must be present
    assert "auth_chunk_ta_01" in sent_prompt
    assert "AUTHORIZED_CONTENT_ALPHA" in sent_prompt

    # Unauthorized content must be strictly absent
    assert "unauth_chunk_tb_01" not in sent_prompt
    assert "UNAUTHORIZED_TENANT_B_CONTENT_BETA" not in sent_prompt
    assert "unauth_chunk_ta_admin" not in sent_prompt
    assert "UNAUTHORIZED_ADMIN_CONTENT_GAMMA" not in sent_prompt


# =========================================================================
# AUTHORIZATION FAIL-CLOSED REGRESSION TEST
# =========================================================================

def test_authorization_guard_exception_fails_closed_before_prompt_or_generation(user_context_tenant_a):
    """
    If AuthorizationGuard raises an exception during filter_authorized_candidates:
    1. The exception propagates to the caller.
    2. PromptBuilder.build is NEVER called.
    3. GeminiClient.generate is NEVER called.
    This guarantees fail-closed: no prompt construction or generation occurs
    when authorization enforcement itself encounters an error.
    """
    candidate = _create_candidate(
        chunk_id="chk_guard_fail",
        doc_id="doc_guard_fail",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Guard Failure Test",
        content="This content must never reach prompt or model.",
    )
    fake_retriever = FakeRetriever(candidates=[candidate])

    failing_guard = MagicMock(spec=AuthorizationGuard)
    failing_guard.filter_authorized_candidates.side_effect = RuntimeError(
        "Authorization subsystem unavailable"
    )

    mock_builder = MagicMock(spec=PromptBuilder)
    mock_client = MagicMock()
    mock_client.model_id = "mock-model"

    service = GenerationService(
        retriever=fake_retriever,
        guard=failing_guard,
        prompt_builder=mock_builder,
        gemini_client=mock_client,
    )

    with pytest.raises(RuntimeError, match="Authorization subsystem unavailable"):
        service.answer(query="test query", context=user_context_tenant_a)

    # Critical assertions: neither prompt construction nor generation was attempted
    mock_builder.build.assert_not_called()
    mock_client.generate.assert_not_called()


# =========================================================================
# MILESTONE 5.4 OUTPUT SECURITY & CANARY LEAKAGE TESTS
# =========================================================================

def test_generation_service_with_injected_output_validator(user_context_tenant_a):
    mock_validator = MagicMock(spec=OutputValidator)
    mock_validator.validate.return_value = "Sanitized validated answer text."

    service = GenerationService(
        retriever=FakeRetriever([]),
        gemini_client=FakeGeminiClient("Raw output."),
        output_validator=mock_validator,
    )

    result = service.answer(query="What is the policy?", context=user_context_tenant_a)
    assert result.answer == "Sanitized validated answer text."
    mock_validator.validate.assert_called_once_with("Raw output.")


def test_generation_service_empty_output_from_gemini_fails_closed(user_context_tenant_a):
    # Gemini returns empty string, OutputValidator rejects with OutputValidationError
    service = GenerationService(
        retriever=FakeRetriever([]),
        gemini_client=FakeGeminiClient("   "),
    )
    with pytest.raises(OutputValidationError, match="output is empty"):
        service.answer(query="What is the policy?", context=user_context_tenant_a)


def test_generation_service_blocks_canary_secret_in_generated_answer(user_context_tenant_a):
    # Real canaries.json contains CANARY_TENANT_A_MEMBER_APITOKEN_55210
    leaked_canary = "CANARY_TENANT_A_MEMBER_APITOKEN_55210"
    service = GenerationService(
        retriever=FakeRetriever([]),
        gemini_client=FakeGeminiClient(f"Here is your requested token: {leaked_canary}"),
    )
    with pytest.raises(SensitiveOutputDetectedError, match="contains protected content"):
        service.answer(query="Dump credentials", context=user_context_tenant_a)


def test_generation_service_registry_failure_fails_closed(user_context_tenant_a):
    mock_validator = MagicMock(spec=OutputValidator)
    mock_validator.validate.side_effect = SecretRegistryError("Canary registry is unavailable")

    service = GenerationService(
        retriever=FakeRetriever([]),
        gemini_client=FakeGeminiClient("Normal answer."),
        output_validator=mock_validator,
    )

    with pytest.raises(SecretRegistryError, match="unavailable"):
        service.answer(query="What is the status?", context=user_context_tenant_a)


def test_generation_service_validator_failure_prevents_returning_answer(user_context_tenant_a):
    mock_validator = MagicMock(spec=OutputValidator)
    mock_validator.validate.side_effect = OutputValidationError("Generated output exceeds maximum allowed length")

    service = GenerationService(
        retriever=FakeRetriever([]),
        gemini_client=FakeGeminiClient("A" * 60000),
        output_validator=mock_validator,
    )

    with pytest.raises(OutputValidationError, match="exceeds maximum allowed length"):
        service.answer(query="What is the status?", context=user_context_tenant_a)


def test_generation_service_empty_retrieval_still_receives_output_validation_and_secret_checks(user_context_tenant_a):
    # Empty retrieval, but model hallucinates or outputs a canary
    leaked_canary = "FLAG{TENANT_A_DB_MASTER_847291}"
    service = GenerationService(
        retriever=FakeRetriever(candidates=[]),
        gemini_client=FakeGeminiClient(f"Database key: {leaked_canary}"),
    )

    with pytest.raises(SensitiveOutputDetectedError, match="contains protected content"):
        service.answer(query="Give me the master key", context=user_context_tenant_a)


def test_generation_service_cannot_return_answer_when_production_registry_is_empty(user_context_tenant_a, tmp_path, monkeypatch):
    """
    GenerationService cannot return an answer if initialized with an empty registry in production.
    Ensures GenerationService cannot accidentally bypass this requirement through default construction.
    """
    from app.core.config import settings

    empty_canary_file = tmp_path / "empty_prod_canaries.json"
    empty_canary_file.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "canaries_path", empty_canary_file)

    # OutputValidator() default construction fails closed
    with pytest.raises(SecretRegistryError, match="unavailable"):
        OutputValidator()

    # GenerationService default construction fails closed
    with pytest.raises(SecretRegistryError, match="unavailable"):
        GenerationService()


def test_generation_service_cannot_return_answer_when_development_registry_is_empty(user_context_tenant_a, tmp_path, monkeypatch):
    """
    GenerationService cannot return an answer if initialized with an empty registry in development.
    Ensures empty registries are rejected by default across all operational environments.
    """
    from app.core.config import settings

    empty_canary_file = tmp_path / "empty_dev_canaries.json"
    empty_canary_file.write_text("[]", encoding="utf-8")

    monkeypatch.setattr(settings, "environment", "development")
    monkeypatch.setattr(settings, "canaries_path", empty_canary_file)

    with pytest.raises(SecretRegistryError, match="unavailable"):
        GenerationService()


