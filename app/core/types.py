"""Domain enumerations and type definitions."""
from enum import Enum


class TenantId(str, Enum):
    """Supported multi-tenant identifiers."""
    TENANT_A = "tenant_a"
    TENANT_B = "tenant_b"
    TENANT_C = "tenant_c"


class AccessLevel(str, Enum):
    """Privilege tiers for documents and identities."""
    PUBLIC = "public"
    MEMBER = "member"
    ADMIN = "admin"


class AttackCategory(str, Enum):
    """Adversarial and benign evaluation test case categories."""
    DIRECT_PROMPT_INJECTION = "direct_prompt_injection"
    INDIRECT_DOCUMENT_INJECTION = "indirect_document_injection"
    SYSTEM_INSTRUCTION_OVERRIDE = "system_instruction_override"
    SYNTHETIC_SECRET_EXTRACTION = "synthetic_secret_extraction"
    UNAUTHORIZED_DOCUMENT_ACCESS = "unauthorized_document_access"
    CROSS_TENANT_ACCESS = "cross_tenant_access"
    ROLEPLAY_ATTACK = "roleplay_attack"
    MULTILINGUAL_ATTACK = "multilingual_attack"
    BENIGN_CONTROL = "benign_control"


class EvaluationOutcome(str, Enum):
    """Outcome classifications for evaluation test runs."""
    AUTHORIZED_SUCCESS = "authorized_success"
    UNAUTHORIZED_BLOCKED = "unauthorized_blocked"
    UNAUTHORIZED_LEAK = "unauthorized_leak"
    CONTEXT_EXPOSED = "context_exposed"
    ERROR_REFUSAL = "error_refusal"

