"""Pydantic schemas and data transfer objects."""
from typing import List, Optional
from pydantic import BaseModel, Field, ConfigDict
from app.core.types import TenantId, AccessLevel


class UserContext(BaseModel):
    """Authenticated caller context resolved server-side."""
    model_config = ConfigDict(frozen=True)

    user_id: str = Field(..., description="Unique caller identifier")
    tenant_id: TenantId = Field(..., description="Tenant organization the caller belongs to")
    role: AccessLevel = Field(..., description="Caller role determining access level")


class DocumentMetadata(BaseModel):
    """Metadata attributes of a knowledge base document."""
    doc_id: str = Field(..., description="Unique document ID (e.g. doc_ta_public_01)")
    tenant_id: TenantId = Field(..., description="Owning tenant organization")
    access_level: AccessLevel = Field(..., description="Required access tier to view this document")
    title: str = Field(..., description="Descriptive title of document")
    category: str = Field(..., description="Domain category, e.g. product, finance, engineering")
    has_secret: bool = Field(default=False, description="Whether document houses a synthetic canary")
    canary_token: Optional[str] = Field(default=None, description="The canary token string if present in source frontmatter")
    is_poisoned: bool = Field(default=False, description="Whether document contains prompt injection payload")
    canary_refs: List[str] = Field(default_factory=list, description="Safe canary identifiers, e.g. CANARY-TA-MEM-01")


class DocumentChunk(BaseModel):
    """A distinct text chunk extracted from a document with full metadata inheritance."""
    chunk_id: str = Field(..., description="Unique chunk ID (e.g. doc_ta_public_01_c01)")
    doc_id: str = Field(..., description="Parent document identifier")
    tenant_id: TenantId = Field(..., description="Inherited tenant ID")
    access_level: AccessLevel = Field(..., description="Inherited access level")
    title: str = Field(..., description="Inherited document title")
    content: str = Field(..., description="Text content of the chunk")
    chunk_index: int = Field(..., description="Zero-indexed chunk sequence position")
    category: str = Field(..., description="Inherited document category")
    is_poisoned: bool = Field(default=False, description="Inherited poison flag")
    has_secret: bool = Field(default=False, description="Inherited secret flag")
    canary_refs: List[str] = Field(default_factory=list, description="Inherited safe canary references")


class CorpusManifestEntry(BaseModel):
    """Manifest record representing a valid document in the corpus."""
    doc_id: str
    relative_path: str
    tenant_id: TenantId
    access_level: AccessLevel
    title: str
    category: str
    is_poisoned: bool
    has_secret: bool
    canary_refs: List[str] = Field(default_factory=list)


class QueryRequest(BaseModel):
    """Incoming user or benchmark query request."""
    query: str = Field(..., min_length=1, max_length=2000, description="User or attacker prompt")
    test_identity_id: str = Field(
        ...,
        description="Key resolving to a predefined test identity via TestContextResolver"
    )
    top_k: int = Field(default=4, ge=1, le=10, description="Number of context chunks to retrieve")


class RetrievedSource(BaseModel):
    """Source provenance of a chunk returned in retrieval."""
    chunk_id: str
    doc_id: str
    tenant_id: TenantId
    access_level: AccessLevel
    score: float


class QueryResponse(BaseModel):
    """Unified response model for vulnerable and defended RAG pipelines."""
    response: str = Field(..., description="Generated text response from the pipeline")
    sources: List[RetrievedSource] = Field(default_factory=list, description="Retrieved chunks used in context")
    blocked: bool = Field(default=False, description="Whether a defensive guardrail intervened")
    block_reason: Optional[str] = Field(default=None, description="Reason for defense intervention")
    latency_ms: float = Field(..., description="End-to-end execution latency in milliseconds")


class CandidateChunk(BaseModel):
    """Retrieved candidate chunk with relevance scoring and provenance."""
    chunk: DocumentChunk
    distance: Optional[float] = Field(default=None, description="Cosine distance from ChromaDB (0 = identical)")
    score: Optional[float] = Field(default=None, description="Similarity score (1 - distance)")


class RetrievedChunk(BaseModel):
    """An authorized retrieved chunk formatted for context assembly or client response."""
    chunk_id: str
    doc_id: str
    tenant_id: TenantId
    access_level: AccessLevel
    title: str
    content: str
    score: Optional[float] = None
    distance: Optional[float] = None


class RetrievalRequest(BaseModel):
    """Request model for secure retrieval endpoint."""
    model_config = ConfigDict(extra="ignore")

    test_identity_id: str = Field(..., description="Key resolving to a predefined test identity")
    query: str = Field(..., min_length=1, max_length=2000, description="Search query string")
    top_k: int = Field(default=4, ge=1, le=10, description="Number of context chunks to retrieve")


class RetrievalResponse(BaseModel):
    """Response model for secure retrieval endpoint."""
    test_identity_id: str
    tenant_id: TenantId
    role: AccessLevel
    query: str
    results: List[RetrievedChunk]
    total_retrieved: int


class GenerationRequest(BaseModel):
    """
    Client request model for secure generation endpoint.
    Strictly forbids extraneous caller fields (tenant_id, role, system_instruction, etc.).
    """
    model_config = ConfigDict(extra="forbid")

    test_identity_id: str = Field(..., description="Key resolving to a predefined test identity")
    query: str = Field(..., min_length=1, max_length=2000, description="User question")
    top_k: Optional[int] = Field(default=None, ge=1, le=10, description="Optional retrieval chunk limit override")


class GenerationSource(BaseModel):
    """Source provenance reference for an authorized chunk admitted into LLM context."""
    chunk_id: str
    doc_id: str
    tenant_id: TenantId
    access_level: AccessLevel
    title: str
    score: Optional[float] = None


class GenerationResponse(BaseModel):
    """Response model for secure generation endpoint."""
    answer: str = Field(..., description="Generated answer text")
    sources: List[GenerationSource] = Field(default_factory=list, description="Authorized source references")
    retrieved_chunk_count: int = Field(..., description="Number of authorized chunks included in generation context")
    model: str = Field(..., description="Identifier of the model used for generation")
    latency_ms: float = Field(..., description="End-to-end execution latency in milliseconds")


