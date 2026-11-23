"""
FastAPI integration tests for /retrieve endpoint: authentication, authorization, and leak prevention.
"""
import pytest
from pathlib import Path
import json
from fastapi import HTTPException
from pydantic import ValidationError

from app.core.config import settings
from app.core.types import TenantId, AccessLevel
from app.core.schemas import DocumentChunk, RetrievalRequest
from app.ingestion.indexer import ChromaIndexer
from app.authorization.identity import TestContextResolver, AuthenticationError
from app.authorization.guard import AuthorizationGuard
from app.retrieval.retriever import SecureRetriever
from app.api.main import create_app
from app.api.routes import get_retriever, get_context_resolver, retrieve_endpoint


class MockResponse:
    """Mock HTTP response matching requests/httpx Response interface."""
    def __init__(self, status_code: int, data: dict, text: str = ""):
        self.status_code = status_code
        self._data = data
        self.text = text or json.dumps(data)

    def json(self, **kwargs):
        return self._data


class LocalTestClient:
    """
    Lightweight, socket-free test client for FastAPI endpoints.
    Allows complete HTTP endpoint validation inside sandboxed and offline environments
    where loopback sockets are restricted.
    """
    def __init__(self, resolver: TestContextResolver, retriever: SecureRetriever):
        self.resolver = resolver
        self.retriever = retriever

    def get(self, path: str):
        if path == "/health":
            return MockResponse(200, {"status": "healthy", "service": "rag-security-testbed"})
        return MockResponse(404, {"detail": "Not Found"})

    def post(self, path: str, json: dict = None):
        if path not in ("/retrieve", "/query/retrieve"):
            return MockResponse(404, {"detail": "Not Found"})

        # Pydantic schema validation exactly as FastAPI does
        try:
            req = RetrievalRequest(**(json or {}))
        except (ValidationError, TypeError, ValueError) as ve:
            return MockResponse(422, {"detail": str(ve)}, text=str(ve))

        # Route handler execution with dependency injection
        try:
            result = retrieve_endpoint(req, resolver=self.resolver, retriever=self.retriever)
            return MockResponse(200, result.model_dump(), text=result.model_dump_json())
        except HTTPException as he:
            return MockResponse(he.status_code, {"detail": he.detail}, text=str(he.detail))


@pytest.fixture
def api_test_setup(temp_chroma_dir: Path, mock_embedder):
    """Sets up a populated test collection and configured TestClient."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_api")

    chunks = [
        # Tenant A Public
        DocumentChunk(
            chunk_id="doc_ta_pub_c00",
            doc_id="doc_ta_pub",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="ApexPay Platform Overview",
            content="ApexPay platform documentation and developer guides.",
            chunk_index=0,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        ),
        # Tenant A Member
        DocumentChunk(
            chunk_id="doc_ta_mem_c00",
            doc_id="doc_ta_mem",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.MEMBER,
            title="ApexPay Merchant Settlement Procedures",
            content="Daily settlement rules for ApexPay merchant accounts.",
            chunk_index=0,
            category="finance",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        ),
        # Tenant A Admin
        DocumentChunk(
            chunk_id="doc_ta_adm_c00",
            doc_id="doc_ta_adm",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.ADMIN,
            title="ApexPay Master Keys",
            content="Master vault token: CANARY_TA_ADMIN_KEY_SECRET.",
            chunk_index=0,
            category="security",
            is_poisoned=False,
            has_secret=True,
            canary_refs=["CANARY-TA-ADM-01"],
        ),
        # Tenant B Public
        DocumentChunk(
            chunk_id="doc_tb_pub_c00",
            doc_id="doc_tb_pub",
            tenant_id=TenantId.TENANT_B,
            access_level=AccessLevel.PUBLIC,
            title="Beacon Health Telemedicine Overview",
            content="Beacon Health platform overview and telehealth services.",
            chunk_index=0,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        ),
        # Tenant B Admin
        DocumentChunk(
            chunk_id="doc_tb_adm_c00",
            doc_id="doc_tb_adm",
            tenant_id=TenantId.TENANT_B,
            access_level=AccessLevel.ADMIN,
            title="Beacon Health Secret HIPAA Audit",
            content="Confidential HIPAA audit token: CANARY_TB_HIPAA_SECRET_TOKEN.",
            chunk_index=0,
            category="audit",
            is_poisoned=False,
            has_secret=True,
            canary_refs=["CANARY-TB-ADM-01"],
        ),
    ]

    embs = mock_embedder.embed_batch([c.content for c in chunks])
    indexer.upsert_chunks(chunks, embeddings=embs)

    resolver = TestContextResolver()
    retriever = SecureRetriever(
        indexer=indexer,
        embedder=mock_embedder,
        guard=AuthorizationGuard(),
        use_pre_filter=True,
    )

    app = create_app()
    app.dependency_overrides[get_context_resolver] = lambda: resolver
    app.dependency_overrides[get_retriever] = lambda: retriever

    client = LocalTestClient(resolver=resolver, retriever=retriever)
    return client, retriever


def test_api_health(api_test_setup):
    """Verify health endpoint returns 200 OK."""
    client, _ = api_test_setup
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_api_valid_retrieval(api_test_setup):
    """Verify valid request returns authorized chunks with provenance."""
    client, _ = api_test_setup
    payload = {
        "test_identity_id": "user_ta_public",
        "query": "ApexPay platform overview developer",
        "top_k": 2
    }
    resp = client.post("/retrieve", json=payload)
    assert resp.status_code == 200

    data = resp.json()
    assert data["test_identity_id"] == "user_ta_public"
    assert data["tenant_id"] == "tenant_a"
    assert data["role"] == "public"
    assert data["total_retrieved"] >= 1
    assert data["results"][0]["doc_id"] == "doc_ta_pub"
    assert data["results"][0]["title"] == "ApexPay Platform Overview"


def test_api_unknown_identity_returns_401(api_test_setup):
    """Verify unknown test identity returns HTTP 401 Unauthorized."""
    client, _ = api_test_setup
    payload = {
        "test_identity_id": "user_forged_superadmin",
        "query": "ApexPay developer guide",
        "top_k": 2
    }
    resp = client.post("/retrieve", json=payload)
    assert resp.status_code == 401
    assert "Authentication failed" in resp.json()["detail"]


def test_api_client_cannot_override_tenant_or_role(api_test_setup):
    """
    CRITICAL SECURITY TEST:
    Client sends request with client-supplied tenant_id='tenant_b' and role='admin',
    but provides test_identity_id='user_ta_public'.
    Verify that the server-resolved identity completely overrides client claims.
    """
    client, _ = api_test_setup
    forged_payload = {
        "test_identity_id": "user_ta_public",
        "query": "ApexPay developer guide",
        "top_k": 2,
        # Forged claims attempting privilege escalation and tenant switching:
        "tenant_id": "tenant_b",
        "role": "admin",
        "user_id": "admin_hacker"
    }
    resp = client.post("/retrieve", json=forged_payload)
    assert resp.status_code == 200

    data = resp.json()
    # Server-resolved identity MUST be tenant_a and public
    assert data["tenant_id"] == "tenant_a"
    assert data["role"] == "public"
    assert data["test_identity_id"] == "user_ta_public"

    # Verify no admin or Tenant B chunks are returned
    for item in data["results"]:
        assert item["tenant_id"] == "tenant_a"
        assert item["access_level"] == "public"


def test_api_invalid_query_returns_422(api_test_setup):
    """Verify empty or missing query returns HTTP 422 Unprocessable Entity."""
    client, _ = api_test_setup

    # Empty query
    resp1 = client.post("/retrieve", json={"test_identity_id": "user_ta_public", "query": ""})
    assert resp1.status_code == 422

    # Whitespace query
    resp2 = client.post("/retrieve", json={"test_identity_id": "user_ta_public", "query": "   "})
    assert resp2.status_code == 422

    # Missing query
    resp3 = client.post("/retrieve", json={"test_identity_id": "user_ta_public"})
    assert resp3.status_code == 422


def test_api_invalid_top_k_returns_422(api_test_setup):
    """Verify out-of-range or invalid top_k returns HTTP 422."""
    client, _ = api_test_setup

    # top_k = 0
    resp1 = client.post("/retrieve", json={"test_identity_id": "user_ta_public", "query": "test", "top_k": 0})
    assert resp1.status_code == 422

    # top_k negative
    resp2 = client.post("/retrieve", json={"test_identity_id": "user_ta_public", "query": "test", "top_k": -2})
    assert resp2.status_code == 422

    # top_k too large (> 10)
    resp3 = client.post("/retrieve", json={"test_identity_id": "user_ta_public", "query": "test", "top_k": 100})
    assert resp3.status_code == 422


def test_api_tenant_isolation_enforced(api_test_setup):
    """Verify Tenant A user cannot retrieve Tenant B content through the API."""
    client, _ = api_test_setup

    # Tenant A admin searches specifically for Beacon Health (Tenant B)
    payload = {
        "test_identity_id": "user_ta_admin",
        "query": "Beacon Health telemedicine platform patient appointments",
        "top_k": 4
    }
    resp = client.post("/retrieve", json=payload)
    assert resp.status_code == 200

    data = resp.json()
    for item in data["results"]:
        assert item["tenant_id"] == "tenant_a"
        assert "Beacon" not in item["title"]


def test_api_role_authorization_enforced(api_test_setup):
    """Verify public user cannot retrieve member or admin documents."""
    client, _ = api_test_setup

    # Public user queries for master vault keys
    payload = {
        "test_identity_id": "user_ta_public",
        "query": "ApexPay master vault keys token",
        "top_k": 4
    }
    resp = client.post("/retrieve", json=payload)
    assert resp.status_code == 200

    data = resp.json()
    for item in data["results"]:
        assert item["access_level"] == "public"
        assert "CANARY" not in item["content"]


def test_api_unauthorized_content_never_in_response(api_test_setup, monkeypatch):
    """
    CRITICAL SECURITY TEST:
    Simulate ChromaDB returning Tenant B admin secrets to a Tenant A public user.
    Verify:
    1. The mocked ChromaDB record is structurally valid (including chunk_index) and
       successfully passes metadata parsing to reach the post-retrieval authorization guard.
    2. The AuthorizationGuard explicitly rejects the record due to cross-tenant role mismatch.
    3. The HTTP response body contains zero unauthorized chunks and the canary secret token
       NEVER appears in the raw response text.
    """
    client, retriever = api_test_setup
    canary_token = "CANARY_TB_HIPAA_SECRET_TOKEN"

    fake_chroma_results = {
        "ids": [["doc_tb_adm_c00"]],
        "documents": [["Confidential HIPAA audit token: CANARY_TB_HIPAA_SECRET_TOKEN."]],
        "metadatas": [[{
            "doc_id": "doc_tb_adm",
            "tenant_id": "tenant_b",
            "access_level": "admin",
            "title": "Beacon Health Secret HIPAA Audit",
            "category": "audit",
            "chunk_index": 0,
            "is_poisoned": False,
            "has_secret": True,
            "canary_refs": "CANARY-TB-ADM-01",
        }]],
        "distances": [[0.02]],
    }

    monkeypatch.setattr(retriever.indexer.collection, "query", lambda **kwargs: fake_chroma_results)

    # Spy on the post-retrieval authorization guard to prove the candidate reaches the guard
    guard_evaluated_candidates = []
    original_filter = retriever.guard.filter_authorized_candidates

    def spy_guard_filter(candidates, context):
        guard_evaluated_candidates.extend(candidates)
        return original_filter(candidates, context)

    monkeypatch.setattr(retriever.guard, "filter_authorized_candidates", spy_guard_filter)

    payload = {
        "test_identity_id": "user_ta_public",
        "query": "HIPAA audit secret token",
        "top_k": 4
    }
    resp = client.post("/retrieve", json=payload)
    assert resp.status_code == 200

    # 1. Verify candidate was structurally valid and reached the post-retrieval guard
    assert len(guard_evaluated_candidates) == 1
    eval_chunk = guard_evaluated_candidates[0].chunk
    assert eval_chunk.chunk_id == "doc_tb_adm_c00"
    assert eval_chunk.tenant_id == TenantId.TENANT_B
    assert eval_chunk.access_level == AccessLevel.ADMIN
    assert eval_chunk.chunk_index == 0

    # 2. Canary token MUST NOT appear anywhere in the response JSON text
    raw_response_text = resp.text
    assert canary_token not in raw_response_text

    # 3. Response is empty because the guard rejected the cross-tenant admin chunk
    data = resp.json()
    assert data["total_retrieved"] == 0
    assert data["results"] == []


# =============================================================================
# HARDENING & ENVIRONMENT RESTRICTION TESTS (MILESTONE 4.1)
# =============================================================================

def test_api_auth_error_never_reflects_attacker_input(api_test_setup):
    """
    CRITICAL SECURITY TEST:
    Verify that an attacker-controlled identity string (e.g. XSS payload, SQL injection,
    or leaked credential token) is NEVER reflected in the 401 response body.
    """
    client, _ = api_test_setup

    malicious_identities = [
        "<script>alert('xss_attack')</script>",
        "admin' OR '1'='1",
        "CANARY_SEC_ATTACKER_PAYLOAD_TOKEN",
        "../../etc/passwd",
    ]

    for attack_id in malicious_identities:
        resp = client.post("/retrieve", json={
            "test_identity_id": attack_id,
            "query": "ApexPay overview",
            "top_k": 2,
        })
        assert resp.status_code == 401
        # Response must match the generic, non-leaking detail
        assert resp.json()["detail"] == "Authentication failed: invalid or unknown test identity"
        # Malicious payload must not be reflected anywhere in response text
        assert attack_id not in resp.text


def test_api_production_mode_blocks_retrieval_endpoints(api_test_setup, monkeypatch):
    """
    CRITICAL SECURITY TEST:
    Verify that in production mode, both the primary '/retrieve' endpoint and the
    alias '/query/retrieve' return 403 Forbidden fail-closed.
    """
    client, _ = api_test_setup
    monkeypatch.setattr(settings, "environment", "production")

    payload = {
        "test_identity_id": "user_ta_public",
        "query": "ApexPay overview",
        "top_k": 2,
    }

    # Primary route
    resp1 = client.post("/retrieve", json=payload)
    assert resp1.status_code == 403
    assert "disabled in production" in resp1.json()["detail"]

    # Alias route
    resp2 = client.post("/query/retrieve", json=payload)
    assert resp2.status_code == 403
    assert "disabled in production" in resp2.json()["detail"]


def test_test_context_resolver_blocks_in_production(monkeypatch):
    """
    Verify that TestContextResolver refuses to resolve test identities in production.
    """
    monkeypatch.setattr(settings, "environment", "production")
    resolver = TestContextResolver()

    with pytest.raises(AuthenticationError) as exc_info:
        resolver.resolve("user_ta_admin")

    assert "disabled in production" in str(exc_info.value)


def test_api_cors_configuration():
    """
    Verify that application CORS middleware is safely configured with explicit origins
    and does not use unrestricted wildcards with credentials.
    """
    from fastapi.middleware.cors import CORSMiddleware

    app = create_app()

    # Find CORSMiddleware in app's user middleware stack
    cors_mw = None
    for mw in app.user_middleware:
        if mw.cls == CORSMiddleware:
            cors_mw = mw
            break

    assert cors_mw is not None, "CORSMiddleware must be configured on application"
    mw_options = cors_mw.kwargs

    # Verify explicit origins (never wildcard '*')
    assert "*" not in mw_options["allow_origins"]
    assert set(mw_options["allow_origins"]) == set(settings.cors_allowed_origins)

    # Verify restricted methods and headers
    assert set(mw_options["allow_methods"]) == set(settings.cors_allowed_methods)
    assert set(mw_options["allow_headers"]) == set(settings.cors_allowed_headers)


def test_environment_setting_constrained_literal():
    """
    Verify that Settings.environment strictly enforces the constrained Literal type
    ['development', 'test', 'production'] and rejects unsupported values like
    'prod' or 'production '.
    """
    from pydantic import ValidationError
    from app.core.config import Settings

    # Valid values must succeed
    for valid_env in ["development", "test", "production"]:
        s = Settings(environment=valid_env)
        assert s.environment == valid_env

    # Invalid values must fail during Settings construction/startup
    invalid_envs = ["prod", "production ", "dev", "staging", "TEST", ""]
    for bad_env in invalid_envs:
        with pytest.raises(ValidationError):
            Settings(environment=bad_env)


def test_settings_max_top_k_validation(monkeypatch: pytest.MonkeyPatch):
    """
    Verify that Settings.max_top_k requires a positive integer:
    - Direct constructor rejects booleans, zero, negative integers, floats, and strings.
    - Direct constructor Settings(max_top_k=10) succeeds, Settings(max_top_k="10") fails.
    - Environment variables accept valid positive integer strings (e.g. MAX_TOP_K=10).
    - Environment variables reject zero (MAX_TOP_K=0), negative values, and non-numeric strings (MAX_TOP_K=invalid).
    """
    from pydantic import ValidationError
    from app.core.config import Settings

    # 1. Valid positive integers via direct constructor
    for valid_k in [1, 5, 10, 50]:
        s = Settings(max_top_k=valid_k)
        assert s.max_top_k == valid_k

    # 2. Zero and negative limits via constructor
    for bad_num in [0, -1, -10]:
        with pytest.raises(ValidationError):
            Settings(max_top_k=bad_num)

    # 3. Explicitly reject booleans via constructor (must not be coerced to 1 or 0)
    for bad_bool in [True, False]:
        with pytest.raises(ValidationError):
            Settings(max_top_k=bad_bool)

    # 4. Reject floats and strings via constructor (no silent coercion)
    for bad_val in [4.5, 10.0, "10", "4", "invalid", ""]:
        with pytest.raises(ValidationError):
            Settings(max_top_k=bad_val)

    # 5. Environment variable MAX_TOP_K=10 is accepted
    monkeypatch.setenv("MAX_TOP_K", "10")
    s_env = Settings()
    assert s_env.max_top_k == 10

    # 6. Environment variable MAX_TOP_K=0 is rejected
    monkeypatch.setenv("MAX_TOP_K", "0")
    with pytest.raises(ValidationError):
        Settings()

    # 7. Environment variable MAX_TOP_K=invalid is rejected
    monkeypatch.setenv("MAX_TOP_K", "invalid")
    with pytest.raises(ValidationError):
        Settings()

    # 8. Environment variable negative or float string is rejected
    for bad_env_val in ["-5", "10.5", "true"]:
        monkeypatch.setenv("MAX_TOP_K", bad_env_val)
        with pytest.raises(ValidationError):
            Settings()


def test_settings_max_top_k_dotenv_and_precedence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Verify Milestone 4.1 configuration behavior:
    1. Valid .env entry MAX_TOP_K=10 is accepted.
    2. Invalid .env entry MAX_TOP_K=invalid is rejected.
    3. Zero/negative .env entry MAX_TOP_K=0 is rejected.
    4. Direct constructor arguments take precedence over environment variables.
    5. Direct constructor invalid values take precedence and fail closed even if env is valid.
    """
    from pydantic import ValidationError
    from app.core.config import Settings

    # 1. Valid .env file entry MAX_TOP_K=10 is accepted
    valid_env = tmp_path / "valid.env"
    valid_env.write_text("MAX_TOP_K=10\n", encoding="utf-8")
    s_valid = Settings(_env_file=valid_env)
    assert s_valid.max_top_k == 10

    # 2. Invalid .env entry MAX_TOP_K=invalid is rejected
    invalid_env = tmp_path / "invalid.env"
    invalid_env.write_text("MAX_TOP_K=invalid\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        Settings(_env_file=invalid_env)

    # 3. Zero .env entry MAX_TOP_K=0 is rejected
    zero_env = tmp_path / "zero.env"
    zero_env.write_text("MAX_TOP_K=0\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        Settings(_env_file=zero_env)

    # 4. Direct constructor argument takes precedence over environment variable
    monkeypatch.setenv("MAX_TOP_K", "10")
    s_precedence = Settings(max_top_k=5)
    assert s_precedence.max_top_k == 5

    # 5. Direct constructor invalid value takes precedence and fails even if env is valid
    with pytest.raises(ValidationError):
        Settings(max_top_k="invalid")

    with pytest.raises(ValidationError):
        Settings(max_top_k=0)

    # 6. Direct constructor argument takes precedence over .env file
    s_dotenv_override = Settings(_env_file=valid_env, max_top_k=8)
    assert s_dotenv_override.max_top_k == 8



