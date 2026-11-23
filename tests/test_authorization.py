"""
Comprehensive test suite for identity resolution, RBAC filter evaluation, and authorization gate.
"""
import pytest
import logging
from typing import Dict, Any
from pydantic import ValidationError

from app.core.types import TenantId, AccessLevel
from app.core.schemas import UserContext, DocumentChunk, CandidateChunk
from app.authorization.identity import (
    TestContextResolver,
    AuthenticationError,
    TEST_IDENTITY_REGISTRY,
)
from app.authorization.evaluator import build_where_filter
from app.authorization.guard import AuthorizationGuard


# =============================================================================
# 1. IDENTITY RESOLUTION TESTS
# =============================================================================

def test_valid_test_identity_resolution():
    """Verify that all 9 predefined test identities resolve to correct immutable UserContexts."""
    resolver = TestContextResolver()

    expected_matrix = {
        "user_ta_public": (TenantId.TENANT_A, AccessLevel.PUBLIC),
        "user_ta_member": (TenantId.TENANT_A, AccessLevel.MEMBER),
        "user_ta_admin": (TenantId.TENANT_A, AccessLevel.ADMIN),
        "user_tb_public": (TenantId.TENANT_B, AccessLevel.PUBLIC),
        "user_tb_member": (TenantId.TENANT_B, AccessLevel.MEMBER),
        "user_tb_admin": (TenantId.TENANT_B, AccessLevel.ADMIN),
        "user_tc_public": (TenantId.TENANT_C, AccessLevel.PUBLIC),
        "user_tc_member": (TenantId.TENANT_C, AccessLevel.MEMBER),
        "user_tc_admin": (TenantId.TENANT_C, AccessLevel.ADMIN),
    }

    for identity_id, (expected_tenant, expected_role) in expected_matrix.items():
        ctx = resolver.resolve(identity_id)
        assert isinstance(ctx, UserContext)
        assert ctx.user_id == identity_id
        assert ctx.tenant_id == expected_tenant
        assert ctx.role == expected_role


def test_unknown_identity_raises_authentication_error():
    """Verify that unknown, empty, or malformed identity IDs raise AuthenticationError."""
    resolver = TestContextResolver()

    invalid_identities = [
        "user_unknown_hacker",
        "user_ta_superadmin",
        "admin",
        "root",
        "",
        "   ",
        None,
        12345,
    ]

    for bad_id in invalid_identities:
        with pytest.raises(AuthenticationError):
            resolver.resolve(bad_id)  # type: ignore


def test_client_cannot_override_identity_context():
    """Verify that UserContext is frozen and cannot be modified after resolution."""
    resolver = TestContextResolver()
    ctx = resolver.resolve("user_ta_public")

    with pytest.raises(ValidationError):
        ctx.role = AccessLevel.ADMIN  # type: ignore

    with pytest.raises(ValidationError):
        ctx.tenant_id = TenantId.TENANT_B  # type: ignore


# =============================================================================
# 2. PRE-RETRIEVAL WHERE FILTER EVALUATOR TESTS
# =============================================================================

def test_build_where_filter_tenant_and_role_matrix():
    """Verify deterministic ChromaDB filter generation across all roles."""
    ctx_pub = UserContext(user_id="u1", tenant_id=TenantId.TENANT_A, role=AccessLevel.PUBLIC)
    filter_pub = build_where_filter(ctx_pub)
    assert filter_pub == {
        "$and": [
            {"tenant_id": {"$eq": "tenant_a"}},
            {"access_level": {"$eq": "public"}},
        ]
    }

    ctx_mem = UserContext(user_id="u2", tenant_id=TenantId.TENANT_B, role=AccessLevel.MEMBER)
    filter_mem = build_where_filter(ctx_mem)
    assert filter_mem == {
        "$and": [
            {"tenant_id": {"$eq": "tenant_b"}},
            {"access_level": {"$in": ["public", "member"]}},
        ]
    }

    ctx_adm = UserContext(user_id="u3", tenant_id=TenantId.TENANT_C, role=AccessLevel.ADMIN)
    filter_adm = build_where_filter(ctx_adm)
    assert filter_adm == {
        "$and": [
            {"tenant_id": {"$eq": "tenant_c"}},
            {"access_level": {"$in": ["public", "member", "admin"]}},
        ]
    }


# =============================================================================
# 3. ROLE AUTHORIZATION TESTS
# =============================================================================

@pytest.fixture
def chunk_factory():
    """Helper creating test chunks for specified tenant and access level."""
    def _create(tenant: TenantId, level: AccessLevel, chunk_id: str = "chunk_01", content: str = "Test content"):
        return DocumentChunk(
            chunk_id=chunk_id,
            doc_id=f"doc_{chunk_id}",
            tenant_id=tenant,
            access_level=level,
            title="Test Doc Title",
            content=content,
            chunk_index=0,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        )
    return _create


@pytest.fixture
def candidate_factory(chunk_factory):
    """Helper creating CandidateChunk objects wrapping DocumentChunk."""
    def _create(tenant: TenantId, level: AccessLevel, chunk_id: str = "cand_01", distance: float = 0.1, content: str = "Test content"):
        chunk = chunk_factory(tenant, level, chunk_id=chunk_id, content=content)
        return CandidateChunk(
            chunk=chunk,
            distance=distance,
            score=max(0.0, 1.0 - distance),
        )
    return _create


def test_role_authorization_public_user(chunk_factory):
    """Public user can only access public documents within their tenant."""
    ctx = UserContext(user_id="user_ta_public", tenant_id=TenantId.TENANT_A, role=AccessLevel.PUBLIC)

    chunk_public = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    chunk_member = chunk_factory(TenantId.TENANT_A, AccessLevel.MEMBER)
    chunk_admin = chunk_factory(TenantId.TENANT_A, AccessLevel.ADMIN)

    assert AuthorizationGuard.is_chunk_authorized(chunk_public, ctx) is True
    assert AuthorizationGuard.is_chunk_authorized(chunk_member, ctx) is False
    assert AuthorizationGuard.is_chunk_authorized(chunk_admin, ctx) is False


def test_role_authorization_member_user(chunk_factory):
    """Member user can access public and member documents, but not admin documents."""
    ctx = UserContext(user_id="user_ta_member", tenant_id=TenantId.TENANT_A, role=AccessLevel.MEMBER)

    chunk_public = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    chunk_member = chunk_factory(TenantId.TENANT_A, AccessLevel.MEMBER)
    chunk_admin = chunk_factory(TenantId.TENANT_A, AccessLevel.ADMIN)

    assert AuthorizationGuard.is_chunk_authorized(chunk_public, ctx) is True
    assert AuthorizationGuard.is_chunk_authorized(chunk_member, ctx) is True
    assert AuthorizationGuard.is_chunk_authorized(chunk_admin, ctx) is False


def test_role_authorization_admin_user(chunk_factory):
    """Admin user can access public, member, and admin documents of their tenant."""
    ctx = UserContext(user_id="user_ta_admin", tenant_id=TenantId.TENANT_A, role=AccessLevel.ADMIN)

    chunk_public = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    chunk_member = chunk_factory(TenantId.TENANT_A, AccessLevel.MEMBER)
    chunk_admin = chunk_factory(TenantId.TENANT_A, AccessLevel.ADMIN)

    assert AuthorizationGuard.is_chunk_authorized(chunk_public, ctx) is True
    assert AuthorizationGuard.is_chunk_authorized(chunk_member, ctx) is True
    assert AuthorizationGuard.is_chunk_authorized(chunk_admin, ctx) is True


# =============================================================================
# 4. TENANT ISOLATION TESTS
# =============================================================================

def test_tenant_isolation_cross_tenant_rejected(chunk_factory):
    """Cross-tenant documents are rejected even if access level is public or caller is admin."""
    guard = AuthorizationGuard()

    ctx_ta_admin = UserContext(user_id="user_ta_admin", tenant_id=TenantId.TENANT_A, role=AccessLevel.ADMIN)

    # Tenant B documents (public, member, admin)
    tb_pub = chunk_factory(TenantId.TENANT_B, AccessLevel.PUBLIC, "tb_pub")
    tb_mem = chunk_factory(TenantId.TENANT_B, AccessLevel.MEMBER, "tb_mem")
    tb_adm = chunk_factory(TenantId.TENANT_B, AccessLevel.ADMIN, "tb_adm")

    # All must be rejected for Tenant A admin
    assert guard.is_chunk_authorized(tb_pub, ctx_ta_admin) is False
    assert guard.is_chunk_authorized(tb_mem, ctx_ta_admin) is False
    assert guard.is_chunk_authorized(tb_adm, ctx_ta_admin) is False

    # In a list filtering scenario, all are removed
    filtered = guard.filter_authorized_chunks([tb_pub, tb_mem, tb_adm], ctx_ta_admin)
    assert len(filtered) == 0


def test_tenant_isolation_pairwise_matrix(chunk_factory):
    """Pairwise check across all tenants verifying cross-tenant access is strictly 0%."""
    guard = AuthorizationGuard()
    all_tenants = [TenantId.TENANT_A, TenantId.TENANT_B, TenantId.TENANT_C]

    for caller_t in all_tenants:
        ctx = UserContext(user_id=f"user_{caller_t.value}_admin", tenant_id=caller_t, role=AccessLevel.ADMIN)
        for doc_t in all_tenants:
            chunk = chunk_factory(doc_t, AccessLevel.PUBLIC)
            authorized = guard.is_chunk_authorized(chunk, ctx)
            if caller_t == doc_t:
                assert authorized is True, f"Own-tenant document unexpectedly rejected for {caller_t}"
            else:
                assert authorized is False, f"Cross-tenant document unexpectedly authorized for caller {caller_t} -> doc {doc_t}"


# =============================================================================
# 5. FAIL-CLOSED AND INTEGRITY TESTS
# =============================================================================

def test_fail_closed_missing_or_corrupt_metadata(chunk_factory):
    """Verify that chunks with missing, None, or invalid metadata fail closed."""
    guard = AuthorizationGuard()
    ctx = UserContext(user_id="user_ta_admin", tenant_id=TenantId.TENANT_A, role=AccessLevel.ADMIN)

    # 1. Non-chunk object
    assert guard.is_chunk_authorized("not_a_chunk", ctx) is False
    assert guard.is_chunk_authorized(None, ctx) is False

    # 2. Corrupt tenant
    bad_tenant_chunk = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    bad_tenant_chunk.__dict__["tenant_id"] = "invalid_tenant_string"
    assert guard.is_chunk_authorized(bad_tenant_chunk, ctx) is False

    # 3. Corrupt access level
    bad_level_chunk = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    bad_level_chunk.__dict__["access_level"] = "superadmin_invalid"
    assert guard.is_chunk_authorized(bad_level_chunk, ctx) is False

    # 4. None tenant or access level
    none_tenant_chunk = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    none_tenant_chunk.__dict__["tenant_id"] = None
    assert guard.is_chunk_authorized(none_tenant_chunk, ctx) is False

    none_level_chunk = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    none_level_chunk.__dict__["access_level"] = None
    assert guard.is_chunk_authorized(none_level_chunk, ctx) is False

    # 5. Blank chunk_id or doc_id
    blank_id_chunk = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    blank_id_chunk.chunk_id = "   "
    assert guard.is_chunk_authorized(blank_id_chunk, ctx) is False

    blank_doc_chunk = chunk_factory(TenantId.TENANT_A, AccessLevel.PUBLIC)
    blank_doc_chunk.doc_id = ""
    assert guard.is_chunk_authorized(blank_doc_chunk, ctx) is False


def test_authorization_rejection_never_exposes_document_content(caplog, chunk_factory):
    """Verify that rejection audit logs log only provenance IDs and NEVER chunk text or secrets."""
    guard = AuthorizationGuard()
    ctx = UserContext(user_id="user_ta_public", tenant_id=TenantId.TENANT_A, role=AccessLevel.PUBLIC)

    secret_canary = "CANARY_SECRET_CONFIDENTIAL_TOKEN_XYZ_9876"
    sensitive_content = "Super secret unreleased earnings revenue $450M."

    unauthorized_chunk = chunk_factory(
        TenantId.TENANT_A,
        AccessLevel.ADMIN,
        chunk_id="chunk_secret_01",
        content=f"{sensitive_content} with token {secret_canary}"
    )

    with caplog.at_level(logging.WARNING):
        authorized = guard.filter_authorized_chunks([unauthorized_chunk], ctx)

    assert len(authorized) == 0

    # Inspect all captured log records
    full_log_text = " ".join(record.message for record in caplog.records)
    assert "chunk_secret_01" in full_log_text
    assert secret_canary not in full_log_text
    assert sensitive_content not in full_log_text
    assert "$450M" not in full_log_text


# =============================================================================
# 6. FOCUSED CANDIDATECHUNK FILTERING TESTS (MILESTONE 4.1)
# =============================================================================

def test_filter_authorized_candidates_same_tenant_public(candidate_factory):
    """
    Verify that a same-tenant public candidate is authorized for a public caller
    when evaluated through filter_authorized_candidates().
    """
    guard = AuthorizationGuard()
    ctx = UserContext(user_id="user_ta_public", tenant_id=TenantId.TENANT_A, role=AccessLevel.PUBLIC)

    cand = candidate_factory(TenantId.TENANT_A, AccessLevel.PUBLIC, chunk_id="c_pub_01")
    survived = guard.filter_authorized_candidates([cand], ctx)

    assert len(survived) == 1
    assert survived[0].chunk.chunk_id == "c_pub_01"
    assert survived[0].chunk.tenant_id == TenantId.TENANT_A
    assert survived[0].chunk.access_level == AccessLevel.PUBLIC


def test_filter_authorized_candidates_same_tenant_unauthorized_admin(candidate_factory):
    """
    Verify that a same-tenant admin candidate is rejected for a public caller
    when evaluated through filter_authorized_candidates().
    """
    guard = AuthorizationGuard()
    ctx = UserContext(user_id="user_ta_public", tenant_id=TenantId.TENANT_A, role=AccessLevel.PUBLIC)

    cand_admin = candidate_factory(TenantId.TENANT_A, AccessLevel.ADMIN, chunk_id="c_adm_01")
    survived = guard.filter_authorized_candidates([cand_admin], ctx)

    assert len(survived) == 0


def test_filter_authorized_candidates_cross_tenant(candidate_factory):
    """
    Verify that a cross-tenant candidate (Tenant B) is rejected for a Tenant A caller,
    even when the caller has admin privileges.
    """
    guard = AuthorizationGuard()
    ctx_admin = UserContext(user_id="user_ta_admin", tenant_id=TenantId.TENANT_A, role=AccessLevel.ADMIN)

    cand_tb = candidate_factory(TenantId.TENANT_B, AccessLevel.PUBLIC, chunk_id="c_tb_pub_01")
    survived = guard.filter_authorized_candidates([cand_tb], ctx_admin)

    assert len(survived) == 0


def test_filter_authorized_candidates_mixed_list(candidate_factory):
    """
    Verify that in a mixed list containing same-tenant authorized, same-tenant unauthorized,
    and cross-tenant candidates, ONLY authorized candidates survive.
    """
    guard = AuthorizationGuard()
    ctx_member = UserContext(user_id="user_ta_member", tenant_id=TenantId.TENANT_A, role=AccessLevel.MEMBER)

    c1 = candidate_factory(TenantId.TENANT_A, AccessLevel.PUBLIC, chunk_id="ta_pub_01", distance=0.10)
    c2 = candidate_factory(TenantId.TENANT_A, AccessLevel.MEMBER, chunk_id="ta_mem_01", distance=0.15)
    c3 = candidate_factory(TenantId.TENANT_A, AccessLevel.ADMIN, chunk_id="ta_adm_01", distance=0.05)   # unauthorized tier
    c4 = candidate_factory(TenantId.TENANT_B, AccessLevel.PUBLIC, chunk_id="tb_pub_01", distance=0.08)  # unauthorized cross-tenant
    c5 = candidate_factory(TenantId.TENANT_C, AccessLevel.MEMBER, chunk_id="tc_mem_01", distance=0.12)  # unauthorized cross-tenant

    survived = guard.filter_authorized_candidates([c1, c2, c3, c4, c5], ctx_member)

    # Only Tenant A public and member chunks must survive
    assert len(survived) == 2
    assert [c.chunk.chunk_id for c in survived] == ["ta_pub_01", "ta_mem_01"]
    assert survived[0].distance == 0.10
    assert survived[1].distance == 0.15


def test_cross_tenant_rejection_logging_never_exposes_secret_or_content(caplog, candidate_factory):
    """
    CRITICAL AUDIT & LEAK PREVENTION TEST:
    Verify that when a valid Tenant B document is rejected for a Tenant A caller:
    1. The document is rejected by filter_authorized_candidates().
    2. The rejection audit logs record provenance IDs (chunk_id, tenant, role).
    3. The rejection audit logs NEVER contain document content or synthetic secret tokens.
    """
    guard = AuthorizationGuard()
    ctx_ta = UserContext(user_id="user_ta_member", tenant_id=TenantId.TENANT_A, role=AccessLevel.MEMBER)

    secret_canary = "CANARY_TB_DIAGNOSTIC_CONFIDENTIAL_KEY_7777"
    secret_content = f"Confidential patient oncology treatment plan with key: {secret_canary}."

    tb_cand = candidate_factory(
        TenantId.TENANT_B,
        AccessLevel.PUBLIC,
        chunk_id="chunk_tb_patient_01",
        content=secret_content,
    )

    with caplog.at_level(logging.WARNING):
        authorized = guard.filter_authorized_candidates([tb_cand], ctx_ta)

    # 1. Candidate must be completely rejected
    assert len(authorized) == 0

    # 2. Inspect log text
    log_text = " ".join(record.message for record in caplog.records)

    # Non-sensitive provenance must be recorded for auditability
    assert "chunk_tb_patient_01" in log_text
    assert "tenant_b" in log_text
    assert "user_ta_member" in log_text

    # Sensitive document content and canary secret token MUST NOT appear anywhere in logs
    assert secret_canary not in log_text
    assert "patient oncology treatment" not in log_text
    assert secret_content not in log_text


