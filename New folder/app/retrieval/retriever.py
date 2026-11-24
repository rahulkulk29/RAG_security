"""
Secure semantic retrieval service with pre-retrieval optimization and post-retrieval authorization.
"""
import logging
import math
import re
from typing import List, Optional, Dict, Any, Tuple

from app.core.config import settings
from app.core.types import TenantId, AccessLevel
from app.core.schemas import UserContext, DocumentChunk, CandidateChunk
from app.ingestion.embeddings import EmbeddingGenerator
from app.ingestion.indexer import ChromaIndexer
from app.authorization.evaluator import build_where_filter
from app.authorization.guard import AuthorizationGuard

logger = logging.getLogger("rag_security.retrieval.retriever")

# Regex to detect raw canary secret leaks in metadata
CANARY_LEAK_PATTERN = re.compile(r"(CANARY_[A-Z0-9_]+|FLAG\{[^\}]+\})")
# Safe canary reference format (e.g. CANARY-TA-ADM-01)
CANARY_REF_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class RetrievalError(Exception):
    """Raised when retrieval operations fail internally without leaking system details."""
    pass


def _parse_and_validate_canary_refs(raw_refs: Any) -> Optional[List[str]]:
    """
    Validates the serialized canary_refs string from ChromaDB metadata.
    
    Requirements:
    - Must be a string.
    - If empty string, returns an empty list.
    - If non-empty, splits by comma and validates each reference ID.
    - Rejects empty identifiers (e.g. 'CANARY-1,', ',CANARY-1').
    - Rejects raw canary secret tokens or invalid format tokens.
    """
    if not isinstance(raw_refs, str):
        return None
    if not raw_refs:
        return []

    tokens = raw_refs.split(",")
    validated_refs: List[str] = []
    for token in tokens:
        if not token or token != token.strip():
            return None
        if not CANARY_REF_PATTERN.match(token):
            return None
        if CANARY_LEAK_PATTERN.search(token):
            return None
        validated_refs.append(token)

    return validated_refs


def _validate_raw_chroma_results(
    raw_results: Any,
) -> Optional[Tuple[List[Any], List[Any], List[Any], List[Any]]]:
    """
    Validates complete raw ChromaDB query result structure before candidate parsing.
    
    Ensures that ids, documents, metadatas, and distances are all present, are valid
    nested lists, and have identical element counts. Returns (ids, docs, metas, dists)
    if valid, or None if malformed or misaligned.
    """
    if not isinstance(raw_results, dict):
        logger.warning("ChromaDB query returned non-dict result: %s", type(raw_results).__name__)
        return None

    required_keys = ("ids", "documents", "metadatas", "distances")
    for key in required_keys:
        val = raw_results.get(key)
        if not isinstance(val, list):
            logger.warning("ChromaDB result missing or non-list key '%s': %s", key, type(val).__name__)
            return None
        if len(val) != 1 or not isinstance(val[0], list):
            logger.warning(
                "ChromaDB result key '%s' must contain exactly one result group, found %d",
                key,
                len(val) if isinstance(val, list) else 0,
            )
            return None

    ids = raw_results["ids"][0]
    docs = raw_results["documents"][0]
    metas = raw_results["metadatas"][0]
    dists = raw_results["distances"][0]

    n = len(ids)
    if not (len(docs) == n and len(metas) == n and len(dists) == n):
        logger.warning(
            "ChromaDB result array lengths misaligned: ids=%d, docs=%d, metas=%d, dists=%d",
            len(ids),
            len(docs),
            len(metas),
            len(dists),
        )
        return None

    return ids, docs, metas, dists


def _parse_and_validate_candidate(
    chunk_id: Any,
    doc_text: Any,
    meta: Any,
    dist: Any,
) -> Optional[CandidateChunk]:
    """
    Performs fail-closed validation of raw candidate data from ChromaDB.
    
    Rejects malformed, missing, or typed-mismatched fields and returns None
    without constructing invalid placeholder objects or mutating __dict__.

    Note on score semantics: `1 - distance` clamped to [0.0, 1.0] provides
    a heuristic similarity ranking score based on cosine distance, not a calibrated probability.
    """
    # 1. Validate chunk_id
    if not isinstance(chunk_id, str) or not chunk_id.strip():
        logger.warning("Candidate rejected: invalid or empty chunk_id")
        return None

    # 2. Validate document content (strict non-empty string)
    if not isinstance(doc_text, str) or not doc_text.strip():
        logger.warning("Candidate rejected: invalid or empty document content")
        return None

    # 3. Validate metadata dictionary
    if not isinstance(meta, dict):
        logger.warning("Candidate rejected: metadata is not a dictionary")
        return None

    # 4. Validate doc_id
    doc_id = meta.get("doc_id")
    if not isinstance(doc_id, str) or not doc_id.strip():
        logger.warning("Candidate rejected: invalid or empty doc_id")
        return None

    # 5. Validate tenant_id against TenantId enum
    raw_tenant = meta.get("tenant_id")
    if not isinstance(raw_tenant, str):
        logger.warning("Candidate rejected: non-string tenant_id")
        return None
    try:
        tenant_id = TenantId(raw_tenant)
    except (ValueError, TypeError):
        logger.warning("Candidate rejected: invalid tenant_id")
        return None

    # 6. Validate access_level against AccessLevel enum
    raw_level = meta.get("access_level")
    if not isinstance(raw_level, str):
        logger.warning("Candidate rejected: non-string access_level")
        return None
    try:
        access_level = AccessLevel(raw_level)
    except (ValueError, TypeError):
        logger.warning("Candidate rejected: invalid access_level")
        return None

    # 7. Validate title and category
    title = meta.get("title")
    if not isinstance(title, str) or not title.strip():
        logger.warning("Candidate rejected: invalid or empty title")
        return None

    category = meta.get("category")
    if not isinstance(category, str) or not category.strip():
        logger.warning("Candidate rejected: invalid or empty category")
        return None

    # 8. Validate chunk_index (must be a valid non-negative int; reject bools)
    chunk_index = meta.get("chunk_index")
    if isinstance(chunk_index, bool) or not isinstance(chunk_index, int) or chunk_index < 0:
        logger.warning("Candidate rejected: invalid chunk_index")
        return None

    # 9. Validate boolean flags (must be actual booleans)
    is_poisoned = meta.get("is_poisoned")
    if not isinstance(is_poisoned, bool):
        logger.warning("Candidate rejected: is_poisoned is not a boolean")
        return None

    has_secret = meta.get("has_secret")
    if not isinstance(has_secret, bool):
        logger.warning("Candidate rejected: has_secret is not a boolean")
        return None

    # 10. Validate canary_refs (key must exist in metadata)
    if "canary_refs" not in meta:
        logger.warning("Candidate rejected: missing 'canary_refs' metadata key")
        return None

    canary_refs = _parse_and_validate_canary_refs(meta["canary_refs"])
    if canary_refs is None:
        logger.warning("Candidate rejected: malformed canary_refs")
        return None

    # 11. Validate distance and calculate score
    if isinstance(dist, bool) or not isinstance(dist, (float, int)):
        logger.warning("Candidate rejected: invalid distance type")
        return None

    try:
        dist_float = float(dist)
    except (OverflowError, ValueError):
        logger.warning("Candidate rejected: distance overflow or conversion error")
        return None

    if math.isnan(dist_float) or math.isinf(dist_float) or dist_float < 0.0:
        logger.warning("Candidate rejected: distance out of bounds (NaN, Inf, or negative)")
        return None

    # Score semantics: `1 - distance` clamped to [0.0, 1.0] is a heuristic similarity score
    # derived from cosine distance, not a calibrated probability.
    score = max(0.0, min(1.0, 1.0 - dist_float))

    # 12. Reconstitute DocumentChunk domain object
    try:
        doc_chunk = DocumentChunk(
            chunk_id=chunk_id,
            doc_id=doc_id,
            tenant_id=tenant_id,
            access_level=access_level,
            title=title,
            content=doc_text,
            chunk_index=chunk_index,
            category=category,
            is_poisoned=is_poisoned,
            has_secret=has_secret,
            canary_refs=canary_refs,
        )
        return CandidateChunk(
            chunk=doc_chunk,
            distance=dist_float,
            score=score,
        )
    except Exception as exc:
        logger.warning("Candidate rejected: failed to construct DocumentChunk (%s)", type(exc).__name__)
        return None


def _validate_max_top_k(val: Any) -> int:
    """
    Validates max_top_k configuration / constructor parameter.

    Requirements:
    - Must be an integer greater than zero.
    - Explicitly reject booleans.
    - Reject floats, strings, zero, and negative values.
    - Do not silently coerce invalid values.
    """
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(
            f"max_top_k must be a positive integer, got invalid type {type(val).__name__}"
        )
    if val <= 0:
        raise ValueError(f"max_top_k must be greater than zero, got {val}")
    return val


class SecureRetriever:
    """
    Coordinates semantic vector retrieval and application-level authorization.
    
    Architecture:
    1. Validates query text and top_k bounds.
    2. Generates query vector embedding.
    3. Queries ChromaDB (with optional pre-retrieval metadata filter).
    4. Reconstitutes CandidateChunk objects preserving similarity scoring.
    5. Applies AuthorizationGuard to guarantee zero cross-tenant or unauthorized
       access, even if the database filter fails or is bypassed.
    """

    def __init__(
        self,
        indexer: Optional[ChromaIndexer] = None,
        embedder: Optional[EmbeddingGenerator] = None,
        guard: Optional[AuthorizationGuard] = None,
        use_pre_filter: bool = True,
        max_query_length: Optional[int] = None,
        max_top_k: Optional[int] = None,
    ):
        self.indexer = indexer or ChromaIndexer()
        self.embedder = embedder or EmbeddingGenerator.get_instance()
        self.guard = guard or AuthorizationGuard()
        self.use_pre_filter = use_pre_filter
        self.max_query_length = (
            max_query_length
            if max_query_length is not None
            else getattr(settings, "max_query_length", 2000)
        )
        raw_max_top_k = (
            max_top_k
            if max_top_k is not None
            else getattr(settings, "max_top_k", 10)
        )
        self.max_top_k = _validate_max_top_k(raw_max_top_k)

    def retrieve(
        self,
        query: str,
        context: UserContext,
        top_k: int = 4,
        use_pre_filter: Optional[bool] = None,
    ) -> List[CandidateChunk]:
        """
        Executes secure semantic search for the given query and caller context.
        
        Args:
            query: User or attacker search prompt.
            context: Server-resolved caller UserContext.
            top_k: Number of candidate chunks to request from storage.
            use_pre_filter: Whether to apply ChromaDB where filter optimization.
                            Defaults to instance configuration.
                            
        Returns:
            List of authorized CandidateChunk instances.
            
        Raises:
            ValueError: If query or top_k fail validation.
            RetrievalError: If vector search or embedding generation fails internally.
        """
        # 1. Validate query
        if not isinstance(query, str):
            raise ValueError(f"Query must be a string, got {type(query).__name__}")
        query_clean = query.strip()
        if not query_clean:
            raise ValueError("Query cannot be empty or whitespace-only")
        if len(query) > self.max_query_length:
            raise ValueError(
                f"Query length ({len(query)}) exceeds maximum allowed limit of {self.max_query_length} characters"
            )

        # 2. Validate top_k
        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise ValueError(
                f"top_k must be a positive integer, got invalid type {type(top_k).__name__}"
            )
        if top_k <= 0:
            raise ValueError(f"top_k must be greater than zero, got {top_k}")
        if top_k > self.max_top_k:
            raise ValueError(
                f"top_k ({top_k}) exceeds maximum allowed limit of {self.max_top_k}"
            )

        # 3. Generate query embedding
        try:
            query_embedding = self.embedder.embed_text(query_clean)
        except ValueError as val_err:
            # Query validation errors in embedder
            raise
        except Exception as emb_err:
            logger.error("Embedding generation failed during retrieval: %s", type(emb_err).__name__)
            raise RetrievalError("Failed to generate query embedding vector") from None

        # 4. Construct ChromaDB pre-retrieval where filter (if enabled)
        should_pre_filter = (
            use_pre_filter if use_pre_filter is not None else self.use_pre_filter
        )
        where_filter: Optional[Dict[str, Any]] = None
        if should_pre_filter:
            where_filter = build_where_filter(context)

        # 5. Execute vector search in ChromaDB
        try:
            query_params: Dict[str, Any] = {
                "query_embeddings": [query_embedding],
                "n_results": top_k,
                "include": ["documents", "metadatas", "distances"],
            }
            if where_filter:
                query_params["where"] = where_filter

            raw_results = self.indexer.collection.query(**query_params)
        except Exception as db_err:
            logger.error("ChromaDB query execution failed: %s", type(db_err).__name__)
            raise RetrievalError("Vector database search query failed") from None

        # 6. Parse and validate candidate chunks
        validated = _validate_raw_chroma_results(raw_results)
        if validated is None:
            return []

        ids, docs, metas, distances = validated
        candidates: List[CandidateChunk] = []

        for idx, chunk_id in enumerate(ids):
            candidate = _parse_and_validate_candidate(
                chunk_id=chunk_id,
                doc_text=docs[idx],
                meta=metas[idx],
                dist=distances[idx],
            )
            if candidate is not None:
                candidates.append(candidate)

        # 7. Post-retrieval authorization gate (the definitive security barrier)
        try:
            authorized_candidates = self.guard.filter_authorized_candidates(
                candidates, context
            )
        except Exception as guard_err:
            logger.error("Authorization guard evaluation failed: %s", type(guard_err).__name__)
            raise RetrievalError("Authorization filter evaluation failed") from None

        return authorized_candidates

