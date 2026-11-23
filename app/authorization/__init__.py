"""Authorization module: identity resolution, query filter building, and authorization guard."""
from app.authorization.identity import (
    AuthenticationError,
    TEST_IDENTITY_REGISTRY,
    TestContextResolver,
)
from app.authorization.evaluator import build_where_filter
from app.authorization.guard import AuthorizationGuard

__all__ = [
    "AuthenticationError",
    "TEST_IDENTITY_REGISTRY",
    "TestContextResolver",
    "build_where_filter",
    "AuthorizationGuard",
]

