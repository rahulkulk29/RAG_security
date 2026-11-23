"""
FastAPI route definitions for secure multi-tenant semantic retrieval.
"""
import logging
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, status

from app.core.config import settings
from app.core.schemas import (
    RetrievalRequest,
    RetrievalResponse,
    RetrievedChunk,
    UserContext,
    GenerationRequest,
    GenerationResponse,
    GenerationSource,
)
from app.authorization.identity import TestContextResolver, AuthenticationError
from app.retrieval.retriever import SecureRetriever, RetrievalError
from app.generation.service import GenerationService
from app.generation.exceptions import (
    PromptConstructionError,
    ContextLengthExceededError,
    GeminiConfigurationError,
    GeminiAPIError,
    EmptyResponseError,
    OutputValidationError,
    SensitiveOutputDetectedError,
    SecretRegistryError,
)

logger = logging.getLogger("rag_security.api.routes")

router = APIRouter(tags=["Retrieval", "Generation"])

# Lazy singleton instances for dependency injection
_resolver: Optional[TestContextResolver] = None
_retriever: Optional[SecureRetriever] = None
_generation_service: Optional[GenerationService] = None


def get_context_resolver() -> TestContextResolver:
    global _resolver
    if _resolver is None:
        _resolver = TestContextResolver()
    return _resolver


def get_retriever() -> SecureRetriever:
    global _retriever
    if _retriever is None:
        _retriever = SecureRetriever()
    return _retriever


def get_generation_service() -> GenerationService:
    global _generation_service
    if _generation_service is None:
        _generation_service = GenerationService()
    return _generation_service


@router.post(
    "/retrieve",
    response_model=RetrievalResponse,
    status_code=status.HTTP_200_OK,
    summary="Secure multi-tenant document retrieval",
    description="Resolves caller identity and returns authorized candidate chunks with relevance scoring."
)
@router.post(
    "/query/retrieve",
    response_model=RetrievalResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False
)
def retrieve_endpoint(
    request: RetrievalRequest,
    resolver: TestContextResolver = Depends(get_context_resolver),
    retriever: SecureRetriever = Depends(get_retriever),
) -> RetrievalResponse:
    """
    Retrieves authorized knowledge base chunks for an authenticated test identity.
    
    Security controls:
    1. Environment Protection: Rejects execution in production environment (403 Forbidden).
    2. Identity Resolution: Resolves request.test_identity_id server-side.
       Ignores any client-supplied tenant_id, role, or user_id fields.
    3. Safe Authentication: Returns generic 401 response and never logs untrusted input.
    4. Vector Search: Queries ChromaDB using query embedding.
    5. Authorization Gate: Enforces tenant isolation and role privilege tiers.
    6. Fail-closed: Never returns unauthorized chunks or sensitive internal errors.
    """
    # 1. Environment restriction: Raw retrieval endpoint is strictly disabled in production
    if getattr(settings, "environment", "development").lower() == "production":
        logger.warning("Attempted to access development retrieval endpoint in production mode")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Development retrieval endpoint is disabled in production",
        )

    # 2. Resolve trusted identity (fails closed with generic 401 without echoing client input)
    try:
        context = resolver.resolve(request.test_identity_id)
    except AuthenticationError:
        logger.warning("Authentication failed: invalid or unrecognized test identity attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: invalid or unknown test identity",
        )

    # 3. Execute semantic retrieval and authorization
    try:
        candidates = retriever.retrieve(
            query=request.query,
            context=context,
            top_k=request.top_k
        )
    except ValueError as val_err:
        logger.warning("Invalid retrieval parameters: exception_class=%s", type(val_err).__name__)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid retrieval request parameters",
        )
    except RetrievalError as ret_err:
        logger.error("Internal retrieval failure: exception_class=%s", type(ret_err).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Retrieval service temporarily unavailable"
        )
    except Exception as exc:
        logger.error("Unexpected error in retrieve endpoint: exception_class=%s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

    # 3. Format authorized output chunks
    results: List[RetrievedChunk] = [
        RetrievedChunk(
            chunk_id=c.chunk.chunk_id,
            doc_id=c.chunk.doc_id,
            tenant_id=c.chunk.tenant_id,
            access_level=c.chunk.access_level,
            title=c.chunk.title,
            content=c.chunk.content,
            score=c.score,
            distance=c.distance
        )
        for c in candidates
    ]

    return RetrievalResponse(
        test_identity_id=context.user_id,
        tenant_id=context.tenant_id,
        role=context.role,
        query=request.query,
        results=results,
        total_retrieved=len(results)
    )


@router.post(
    "/api/v1/generate",
    response_model=GenerationResponse,
    status_code=status.HTTP_200_OK,
    summary="Secure multi-tenant RAG generation",
    description="Resolves caller identity, retrieves and authorizes candidate documents, constructs delimited prompt, and invokes Gemini model securely.",
)
@router.post(
    "/generate",
    response_model=GenerationResponse,
    status_code=status.HTTP_200_OK,
    include_in_schema=False,
    summary="Secure RAG generation alias",
)
def generate_endpoint(
    request: GenerationRequest,
    resolver: TestContextResolver = Depends(get_context_resolver),
    service: GenerationService = Depends(get_generation_service),
) -> GenerationResponse:
    """
    Executes end-to-end secure RAG generation.

    Security & Pipeline Steps:
    1. Identity Resolution: Resolves test_identity_id server-side.
       Client-supplied tenant_id, role, or user_id are strictly forbidden and rejected.
    2. Authentication Check: Invalid or unknown test identity yields HTTP 401 Unauthorized.
    3. Retrieval & Defense-in-depth: Authorized context retrieved and filtered.
    4. Prompt Construction: Structural XML-style delimiters, JSON-serialized query, zero prompt injection bypass.
    5. Generation: Gemini model invoked with trusted system instructions.
    6. Safe Metadata Response: Only source metadata returned; zero raw content or canary tokens.
    """
    # 1. Resolve server-side test identity
    try:
        context = resolver.resolve(request.test_identity_id)
    except AuthenticationError:
        logger.warning("Authentication failed in generate endpoint: invalid or unrecognized test identity")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: invalid or unknown test identity",
        )

    # 2. Execute generation pipeline
    try:
        result = service.answer(
            query=request.query,
            context=context,
            top_k=request.top_k,
        )
    except (ValueError, PromptConstructionError, ContextLengthExceededError) as val_err:
        logger.warning("Generation request validation error: exception_class=%s", type(val_err).__name__)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid generation request parameters",
        )
    except (GeminiAPIError, EmptyResponseError, OutputValidationError, SensitiveOutputDetectedError) as gemini_err:
        logger.error("Generation output error: exception_class=%s", type(gemini_err).__name__)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Generation provider temporarily unavailable",
        )
    except (RetrievalError, GeminiConfigurationError, SecretRegistryError) as dep_err:
        logger.error("Generation internal dependency failure: exception_class=%s", type(dep_err).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Generation service temporarily unavailable",
        )
    except Exception as exc:
        logger.error("Unexpected error in generate endpoint: exception_class=%s", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )

    # 3. Return safe generation response
    return GenerationResponse(
        answer=result.answer,
        sources=result.sources,
        retrieved_chunk_count=result.retrieved_chunk_count,
        model=result.model,
        latency_ms=result.latency_ms,
    )

