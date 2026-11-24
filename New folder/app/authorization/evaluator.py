"""
ChromaDB pre-retrieval query filter builder based on caller UserContext.

SECURITY NOTE:
ChromaDB where filters are an efficiency and performance optimization to reduce
candidate scan overhead. They MUST NOT be treated as a security boundary.
Vector databases can suffer from query parser anomalies, filter syntax bugs,
or operator bypasses. The application-level authorization gate (AuthorizationGuard)
must independently validate every candidate chunk returned from storage.
"""
from typing import Dict, Any

from app.core.types import AccessLevel
from app.core.schemas import UserContext


def build_where_filter(context: UserContext) -> Dict[str, Any]:
    """
    Constructs a deterministic ChromaDB metadata 'where' filter for the caller's context.
    
    Rules:
    - Tenant isolation: strictly matches context.tenant_id.
    - Role hierarchy:
      - PUBLIC: can access 'public'
      - MEMBER: can access 'public', 'member'
      - ADMIN:  can access 'public', 'member', 'admin'
    """
    tenant_clause = {"tenant_id": {"$eq": context.tenant_id.value}}

    if context.role == AccessLevel.PUBLIC:
        level_clause = {"access_level": {"$eq": AccessLevel.PUBLIC.value}}
    elif context.role == AccessLevel.MEMBER:
        level_clause = {
            "access_level": {
                "$in": [AccessLevel.PUBLIC.value, AccessLevel.MEMBER.value]
            }
        }
    elif context.role == AccessLevel.ADMIN:
        level_clause = {
            "access_level": {
                "$in": [
                    AccessLevel.PUBLIC.value,
                    AccessLevel.MEMBER.value,
                    AccessLevel.ADMIN.value,
                ]
            }
        }
    else:
        # Fail-closed for any unknown role
        level_clause = {"access_level": {"$eq": "__UNAUTHORIZED_ROLE__"}}

    return {
        "$and": [
            tenant_clause,
            level_clause,
        ]
    }

