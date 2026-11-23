"""
Application-level authorization gate and post-retrieval verification audit.

HIGHEST PRIORITY SECURITY BOUNDARY:
This module enforces zero-trust authorization at the application layer.
Every candidate chunk retrieved from ChromaDB must independently pass
authorization validation before it is returned to callers or admitted into
LLM context.

ChromaDB 'where' filters are only an optimization; this guard is the definitive
security barrier against cross-tenant leakage and privilege escalation.
"""
import logging
from typing import List, Any

from app.core.types import TenantId, AccessLevel
from app.core.schemas import UserContext, DocumentChunk, CandidateChunk

logger = logging.getLogger("rag_security.authorization.guard")


class AuthorizationGuard:
    """
    Independent application-level authorization service.
    
    Validates tenant isolation and role-based privilege tiers with strict
    fail-closed semantics.
    """

    @staticmethod
    def is_chunk_authorized(chunk: Any, context: UserContext) -> bool:
        """
        Determines whether a chunk is authorized for the given UserContext.
        
        Rules:
        1. TENANT ISOLATION:
           - The chunk's tenant_id must strictly match context.tenant_id.
           - Cross-tenant documents are ALWAYS rejected, regardless of role.
        2. ROLE HIERARCHY:
           - PUBLIC: can access PUBLIC documents only.
           - MEMBER: can access PUBLIC and MEMBER documents.
           - ADMIN:  can access PUBLIC, MEMBER, and ADMIN documents.
        3. FAIL-CLOSED INTEGRITY:
           - Reject chunks with missing, None, or invalid tenant/access_level metadata.
           - Reject chunks with empty or non-string IDs.
        """
        if not isinstance(chunk, DocumentChunk):
            return False

        # Validate ID integrity
        if not isinstance(chunk.chunk_id, str) or not chunk.chunk_id.strip():
            return False
        if not isinstance(chunk.doc_id, str) or not chunk.doc_id.strip():
            return False

        # Validate and enforce Tenant isolation
        if not isinstance(chunk.tenant_id, TenantId):
            return False
        if chunk.tenant_id != context.tenant_id:
            return False

        # Validate AccessLevel
        if not isinstance(chunk.access_level, AccessLevel):
            return False

        # Enforce role hierarchy
        if context.role == AccessLevel.PUBLIC:
            return chunk.access_level == AccessLevel.PUBLIC
        elif context.role == AccessLevel.MEMBER:
            return chunk.access_level in (AccessLevel.PUBLIC, AccessLevel.MEMBER)
        elif context.role == AccessLevel.ADMIN:
            return chunk.access_level in (
                AccessLevel.PUBLIC,
                AccessLevel.MEMBER,
                AccessLevel.ADMIN,
            )

        return False

    def filter_authorized_candidates(
        self,
        candidates: List[CandidateChunk],
        context: UserContext
    ) -> List[CandidateChunk]:
        """
        Filters a list of CandidateChunk items, returning only authorized candidates.
        
        Logs an audit warning for any rejected candidate without exposing chunk content.
        """
        authorized: List[CandidateChunk] = []

        for candidate in candidates:
            if not isinstance(candidate, CandidateChunk):
                logger.warning(
                    "Rejected candidate of invalid type '%s' for caller '%s'",
                    type(candidate).__name__,
                    context.user_id,
                )
                continue

            chunk = candidate.chunk
            if self.is_chunk_authorized(chunk, context):
                authorized.append(candidate)
            else:
                # Log audit record with IDs and tiers only - NEVER document content or secrets
                c_id = getattr(chunk, "chunk_id", "<unknown>")
                c_tenant = getattr(getattr(chunk, "tenant_id", None), "value", "<invalid>")
                c_level = getattr(getattr(chunk, "access_level", None), "value", "<invalid>")
                logger.warning(
                    "AUTHORIZATION_REJECTED: chunk='%s' [tenant=%s, level=%s] "
                    "denied to caller='%s' [tenant=%s, role=%s]",
                    c_id,
                    c_tenant,
                    c_level,
                    context.user_id,
                    context.tenant_id.value,
                    context.role.value,
                )

        return authorized

    def filter_authorized_chunks(
        self,
        chunks: List[DocumentChunk],
        context: UserContext
    ) -> List[DocumentChunk]:
        """Convenience method for filtering raw DocumentChunk lists."""
        authorized: List[DocumentChunk] = []
        for chunk in chunks:
            if self.is_chunk_authorized(chunk, context):
                authorized.append(chunk)
            else:
                c_id = getattr(chunk, "chunk_id", "<unknown>")
                c_tenant = getattr(getattr(chunk, "tenant_id", None), "value", "<invalid>")
                c_level = getattr(getattr(chunk, "access_level", None), "value", "<invalid>")
                logger.warning(
                    "AUTHORIZATION_REJECTED: chunk='%s' [tenant=%s, level=%s] "
                    "denied to caller='%s' [tenant=%s, role=%s]",
                    c_id,
                    c_tenant,
                    c_level,
                    context.user_id,
                    context.tenant_id.value,
                    context.role.value,
                )
        return authorized

