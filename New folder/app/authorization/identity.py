"""
Trusted Identity Simulation for RAG Security Testbed.

IMPORTANT ARCHITECTURAL & SECURITY NOTICE:
The project does not implement production authentication (such as OAuth2, OIDC,
SAML, or Keycloak). Instead, it implements a controlled test identity simulation
designed specifically for security benchmarking and evaluation:
- The evaluation runner and API clients supply a predefined test_identity_id.
- A trusted server-side component, TestContextResolver, inspects an immutable
  registry of authorized test identities and produces a validated UserContext
  (user_id, tenant_id, role).
- Arbitrary client request-body fields or HTTP headers (such as a client sending
  tenant_id: "tenant_b" or role: "admin") are NEVER treated as proof of identity.
- If a request supplies an unknown or invalid test_identity_id, the resolver
  immediately fails closed (raising AuthenticationError, mapped to HTTP 401).

In production, identity must be established via cryptographically signed tokens
(e.g., JWTs) issued by an identity provider and verified using public keys.
"""
from typing import Dict, Optional

from app.core.config import settings
from app.core.types import TenantId, AccessLevel
from app.core.schemas import UserContext


class AuthenticationError(Exception):
    """Raised when identity resolution fails or an invalid test identity is provided."""
    pass


# Static, immutable registry of predefined test identities for the benchmark
TEST_IDENTITY_REGISTRY: Dict[str, UserContext] = {
    # Tenant A identities
    "user_ta_public": UserContext(
        user_id="user_ta_public",
        tenant_id=TenantId.TENANT_A,
        role=AccessLevel.PUBLIC
    ),
    "user_ta_member": UserContext(
        user_id="user_ta_member",
        tenant_id=TenantId.TENANT_A,
        role=AccessLevel.MEMBER
    ),
    "user_ta_admin": UserContext(
        user_id="user_ta_admin",
        tenant_id=TenantId.TENANT_A,
        role=AccessLevel.ADMIN
    ),

    # Tenant B identities
    "user_tb_public": UserContext(
        user_id="user_tb_public",
        tenant_id=TenantId.TENANT_B,
        role=AccessLevel.PUBLIC
    ),
    "user_tb_member": UserContext(
        user_id="user_tb_member",
        tenant_id=TenantId.TENANT_B,
        role=AccessLevel.MEMBER
    ),
    "user_tb_admin": UserContext(
        user_id="user_tb_admin",
        tenant_id=TenantId.TENANT_B,
        role=AccessLevel.ADMIN
    ),

    # Tenant C identities
    "user_tc_public": UserContext(
        user_id="user_tc_public",
        tenant_id=TenantId.TENANT_C,
        role=AccessLevel.PUBLIC
    ),
    "user_tc_member": UserContext(
        user_id="user_tc_member",
        tenant_id=TenantId.TENANT_C,
        role=AccessLevel.MEMBER
    ),
    "user_tc_admin": UserContext(
        user_id="user_tc_admin",
        tenant_id=TenantId.TENANT_C,
        role=AccessLevel.ADMIN
    ),
}


class TestContextResolver:
    """
    Server-side resolver mapping predefined test identity keys to validated UserContexts.
    
    Guarantees fail-closed semantics: any missing, unrecognized, or malformed
    identity key raises AuthenticationError. Client-supplied tenant or role
    claims are completely ignored.
    """
    __test__ = False  # Prevent pytest from mistaking this helper class as a test suite

    def __init__(self, registry: Optional[Dict[str, UserContext]] = None):
        self._registry: Dict[str, UserContext] = (
            registry if registry is not None else TEST_IDENTITY_REGISTRY
        )

    def resolve(self, test_identity_id: str) -> UserContext:
        """
        Resolves a test identity ID to an authenticated, immutable UserContext.
        
        Args:
            test_identity_id: Predefined identity key (e.g. 'user_ta_member').
            
        Returns:
            Validated UserContext containing user_id, tenant_id, and role.
            
        Raises:
            AuthenticationError: If the identity ID is unknown, non-string, or empty,
                                 or if invoked in a production environment.
        """
        if getattr(settings, "environment", "development").lower() == "production":
            raise AuthenticationError(
                "Test identity resolution is strictly disabled in production environment"
            )

        if not isinstance(test_identity_id, str):
            raise AuthenticationError(
                f"Invalid test identity format: expected string, got {type(test_identity_id).__name__}"
            )

        identity_key = test_identity_id.strip()
        if not identity_key:
            raise AuthenticationError("Test identity ID cannot be empty or whitespace-only")

        context = self._registry.get(identity_key)
        if context is None:
            raise AuthenticationError(
                f"Unknown test identity '{identity_key}'. Predefined test identities are required."
            )

        return context
