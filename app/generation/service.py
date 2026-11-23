"""
Secure Generation Service orchestrating retrieval, authorization,
prompt construction, and Gemini generation.
"""
import logging
import time
from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict

from app.core.config import settings
from app.core.schemas import UserContext, GenerationSource, CandidateChunk
from app.retrieval.retriever import SecureRetriever
from app.authorization.guard import AuthorizationGuard
from app.generation.prompts import PromptBuilder
from app.generation.client import GeminiClient
from app.generation.output_validator import OutputValidator
from app.generation.exceptions import PromptConstructionError

logger = logging.getLogger("rag_security.generation.service")


class GenerationResult(BaseModel):
    """Internal result produced by GenerationService."""
    model_config = ConfigDict(frozen=True)

    answer: str = Field(..., description="Generated answer text")
    sources: List[GenerationSource] = Field(default_factory=list, description="Authorized source references")
    retrieved_chunk_count: int = Field(..., description="Number of authorized chunks included in context")
    model: str = Field(..., description="Model identifier used for generation")
    latency_ms: float = Field(..., description="End-to-end execution latency in milliseconds")


class GenerationService:
    """
    Orchestration service for secure RAG generation.

    Execution Flow:
    1. Validates query and receives trusted UserContext.
    2. Retrieves candidate chunks using SecureRetriever.
    3. Evaluates candidates through AuthorizationGuard (defense-in-depth).
    4. Serializes authorized candidates and question into PromptBundle using PromptBuilder.
    5. Calls GeminiClient.generate() with PromptBundle.
    6. Validates generated output (type, length, format).
    7. Scans validated output for synthetic secret leakage.
    8. Constructs GenerationResult with answer, authorized source metadata, and execution latency.
    """

    def __init__(
        self,
        retriever: Optional[SecureRetriever] = None,
        guard: Optional[AuthorizationGuard] = None,
        prompt_builder: Optional[PromptBuilder] = None,
        gemini_client: Optional[GeminiClient] = None,
        output_validator: Optional[OutputValidator] = None,
    ):
        self.retriever = retriever if retriever is not None else SecureRetriever()
        self.guard = guard if guard is not None else AuthorizationGuard()
        self.prompt_builder = prompt_builder if prompt_builder is not None else PromptBuilder()
        self.gemini_client = gemini_client if gemini_client is not None else GeminiClient()
        self.output_validator = output_validator if output_validator is not None else OutputValidator()

    def answer(
        self,
        query: str,
        context: UserContext,
        top_k: Optional[int] = None,
    ) -> GenerationResult:
        """
        Generates an authorized answer for the provided query and UserContext.

        Args:
            query: User question string.
            context: Trusted caller UserContext resolved server-side.
            top_k: Optional retrieval candidate limit override.

        Returns:
            GenerationResult containing answer text, authorized source provenance, and latency.

        Raises:
            ValueError: If query or top_k parameter validation fails.
            PromptConstructionError: If query format or prompt construction fails.
            ContextLengthExceededError: If serialized context exceeds limits.
            RetrievalError: If internal vector retrieval fails.
            GenerationError: If Gemini provider or configuration fails.
        """
        start_time = time.perf_counter()

        # 1. Validate query string
        if not isinstance(query, str):
            logger.warning("Generation request rejected: non-string query type (%s)", type(query).__name__)
            raise PromptConstructionError("Query must be a string")

        clean_query = query.strip()
        if not clean_query:
            logger.warning("Generation request rejected: empty or whitespace-only query")
            raise PromptConstructionError("Query must not be empty or whitespace-only")

        # 2. Validate and determine top_k
        effective_top_k = top_k if top_k is not None else getattr(settings, "default_top_k", 4)
        if isinstance(effective_top_k, bool) or not isinstance(effective_top_k, int):
            raise ValueError(f"top_k must be an integer, got {type(effective_top_k).__name__}")
        if effective_top_k <= 0:
            raise ValueError(f"top_k must be greater than zero, got {effective_top_k}")
        max_k = getattr(settings, "max_top_k", 10)
        if effective_top_k > max_k:
            raise ValueError(f"top_k ({effective_top_k}) exceeds maximum allowed limit of {max_k}")

        logger.debug(
            "Executing generation service for caller '%s' (tenant='%s', role='%s', query_length=%d, top_k=%d)",
            context.user_id,
            context.tenant_id.value,
            context.role.value,
            len(clean_query),
            effective_top_k,
        )

        # 3. Retrieve candidates via SecureRetriever (handles embeddings and vector search)
        candidates = self.retriever.retrieve(
            query=clean_query,
            context=context,
            top_k=effective_top_k,
        )

        # 4. Enforce AuthorizationGuard as definitive security barrier (defense-in-depth)
        authorized_candidates = self.guard.filter_authorized_candidates(
            candidates,
            context,
        )

        # 5. Build PromptBundle (untrusted context + safely escaped JSON query)
        prompt_bundle = self.prompt_builder.build(
            query=clean_query,
            chunks=authorized_candidates,
        )

        # 6. Generate answer via GeminiClient
        answer_text = self.gemini_client.generate(prompt_bundle)

        # 7. Validate generated output and scan for synthetic secret leakage
        validated_answer = self.output_validator.validate(answer_text)

        # 8. Extract safe source provenance metadata (never include raw document content or canary values)
        sources: List[GenerationSource] = []
        for candidate in authorized_candidates:
            chunk = candidate.chunk
            sources.append(
                GenerationSource(
                    chunk_id=chunk.chunk_id,
                    doc_id=chunk.doc_id,
                    tenant_id=chunk.tenant_id,
                    access_level=chunk.access_level,
                    title=chunk.title,
                    score=candidate.score,
                )
            )

        latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
        model_name = getattr(self.gemini_client, "model_id", "unknown-model")

        logger.debug(
            "Generation service completed for caller '%s' (sources_count=%d, latency_ms=%.2f)",
            context.user_id,
            len(sources),
            latency_ms,
        )

        return GenerationResult(
            answer=validated_answer,
            sources=sources,
            retrieved_chunk_count=len(sources),
            model=model_name,
            latency_ms=latency_ms,
        )

