"""ChromaDB persistent vector indexing with idempotency, chunk synchronization, and canary sanitization."""
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict
import re
import chromadb
from chromadb.config import Settings as ChromaSettings

from app.core.config import settings
from app.core.types import TenantId, AccessLevel
from app.core.schemas import DocumentChunk
from app.ingestion.embeddings import EmbeddingGenerator


# Regex to detect raw canary tokens or flags accidentally placed into metadata
CANARY_LEAK_PATTERN = re.compile(r"(CANARY_[A-Z0-9_]+|FLAG\{[^\}]+\})")


def _validate_batch_size(batch_size: Any) -> int:
    """Validate that batch_size is a strictly positive integer, explicitly rejecting booleans."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int):
        raise ValueError(
            f"batch_size must be a positive integer, got invalid type {type(batch_size).__name__}"
        )
    if batch_size <= 0:
        raise ValueError(f"batch_size must be a positive integer, got {batch_size}")
    return batch_size


class ChromaIndexer:
    """
    Manages persistent ChromaDB vector storage, chunk indexing, and stale chunk pruning.
    
    Architectural & Transactional Note:
    ChromaDB is an embedded document store that does not provide cross-call atomic
    transactions or rollback across separate API calls (e.g. delete followed by upsert).
    The pipeline guarantees that known application-level input validation, embedding
    generation, cross-document collision checks, and preparation occur BEFORE any
    deletion is performed. However, it does not guarantee rollback if the process crashes,
    storage fails, or power is lost between operations.
    """

    def __init__(
        self,
        persist_dir: Optional[Path] = None,
        collection_name: Optional[str] = None,
    ):
        self.persist_dir = persist_dir or settings.chroma_db_dir
        self.collection_name = collection_name or settings.chroma_collection_name
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self.client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=ChromaSettings(anonymized_telemetry=False)
        )
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )

    def _sanitize_and_validate_metadata(self, chunk: DocumentChunk) -> Dict[str, Any]:
        """
        Prepares metadata dictionary for ChromaDB storage.
        
        Strictly forbids storing raw canary tokens or secrets in metadata.
        Serializes complex fields (like canary_refs) into primitive scalar values.
        Redacts secret values if a violation is detected to prevent log leakage.
        """
        canary_refs_str = ",".join(chunk.canary_refs)

        meta: Dict[str, Any] = {
            "doc_id": chunk.doc_id,
            "tenant_id": chunk.tenant_id.value,
            "access_level": chunk.access_level.value,
            "title": str(chunk.title),
            "chunk_index": int(chunk.chunk_index),
            "category": str(chunk.category),
            "is_poisoned": bool(chunk.is_poisoned),
            "has_secret": bool(chunk.has_secret),
            "canary_refs": canary_refs_str,
        }

        # Security assertion: ensure metadata never contains raw canary tokens
        for key, val in meta.items():
            if isinstance(val, str) and CANARY_LEAK_PATTERN.search(val):
                raise ValueError(
                    f"CRITICAL SECURITY VIOLATION: Raw canary token detected in metadata key '{key}'. "
                    f"Raw secret values are redacted to prevent log leakage."
                )

        return meta

    def _validate_batch_inputs(
        self,
        chunks: List[DocumentChunk],
        embeddings: Optional[List[List[float]]] = None,
        target_doc_id: Optional[str] = None
    ) -> tuple[List[str], List[str], List[List[float]], List[Dict[str, Any]]]:
        """
        Validates and prepares all replacement chunk data prior to any database mutation.
        
        Validation sequence:
        1. Validate batch structure and chunk objects.
        2. Validate foreign doc_id if target_doc_id is specified.
        3. Reject duplicate chunk IDs within the batch.
        4. Sanitize and validate all ChromaDB metadata (canary redaction).
        5. Generate embeddings if caller did not supply them.
        6. Validate embedding count matches chunk count.
        7. Validate each vector (384-dim, numeric scalars, bool rejected, finite values).
        8. Cross-document chunk ID collision check against ChromaDB.
        9. Return prepared (ids, documents, valid_embeddings, metadatas).
        """
        # 1. Structure and chunk objects
        for c in chunks:
            if not isinstance(c, DocumentChunk):
                raise ValueError(f"Expected DocumentChunk object, got {type(c).__name__}")

        # 2. Foreign doc_id check
        if target_doc_id is not None:
            for c in chunks:
                if c.doc_id != target_doc_id:
                    raise ValueError(
                        f"Document ID mismatch during synchronization: chunk '{c.chunk_id}' has doc_id '{c.doc_id}', "
                        f"expected '{target_doc_id}'"
                    )

        # 3. Duplicate chunk IDs check
        seen_ids = set()
        for c in chunks:
            if c.chunk_id in seen_ids:
                raise ValueError(f"Duplicate chunk ID detected in batch: '{c.chunk_id}'")
            seen_ids.add(c.chunk_id)

        # 4. Metadata sanitization and canary token detection
        metadatas = [self._sanitize_and_validate_metadata(c) for c in chunks]

        # 5. Embedding generation if not supplied
        if embeddings is None:
            embedder = EmbeddingGenerator.get_instance()
            texts = [c.content for c in chunks]
            embeddings = embedder.embed_batch(texts)

        # 6. Embedding count validation
        if len(chunks) != len(embeddings):
            raise ValueError(
                f"Chunk count ({len(chunks)}) does not match embeddings count ({len(embeddings)})"
            )

        # 7. Strict vector validation
        for vec in embeddings:
            EmbeddingGenerator.validate_vector(vec)

        # 8. Cross-document chunk ID collision check against ChromaDB (fail-closed ownership validation)
        incoming_ids = [c.chunk_id for c in chunks]
        existing_records = self.collection.get(ids=incoming_ids)
        if existing_records and existing_records.get("ids"):
            existing_ids = existing_records["ids"]
            existing_metas = existing_records.get("metadatas")
            id_to_doc = {c.chunk_id: c.doc_id for c in chunks}
            for idx, ex_id in enumerate(existing_ids):
                ex_meta = existing_metas[idx] if existing_metas and idx < len(existing_metas) else None
                if not isinstance(ex_meta, dict):
                    raise ValueError(
                        f"Existing chunk has missing or invalid ownership metadata; refusing overwrite for chunk '{ex_id}'."
                    )
                ex_doc_id = ex_meta.get("doc_id")
                if not isinstance(ex_doc_id, str) or not ex_doc_id.strip():
                    raise ValueError(
                        f"Existing chunk has missing or invalid ownership metadata; refusing overwrite for chunk '{ex_id}'."
                    )
                incoming_doc = id_to_doc.get(ex_id)
                if ex_doc_id != incoming_doc:
                    raise ValueError(
                        f"Cross-document chunk ID collision: chunk ID '{ex_id}' already exists in ChromaDB "
                        f"belonging to document '{ex_doc_id}', cannot be overwritten by document '{incoming_doc}'"
                    )

        ids = [c.chunk_id for c in chunks]
        documents = [c.content for c in chunks]

        return ids, documents, embeddings, metadatas

    def upsert_chunks(
        self,
        chunks: List[DocumentChunk],
        embeddings: Optional[List[List[float]]] = None,
        batch_size: int = 64,
        sync_stale: bool = False
    ) -> int:
        """
        Inserts or updates chunks in the ChromaDB collection.
        
        If sync_stale=True, obsolete chunks from previously indexed versions
        of the documents in this batch are pruned ONLY AFTER all replacement chunks,
        metadata, and embeddings are completely validated.
        """
        valid_batch_size = _validate_batch_size(batch_size)

        if not chunks:
            return 0

        # Step 1: Pre-validate all replacement data, metadata, and embeddings upfront
        ids, documents, valid_embeddings, metadatas = self._validate_batch_inputs(
            chunks, embeddings
        )

        # Step 2: Prune stale chunks only after successful validation
        if sync_stale:
            doc_groups = defaultdict(list)
            for c in chunks:
                doc_groups[c.doc_id].append(c)

            for doc_id, doc_chunks in doc_groups.items():
                existing = self.collection.get(where={"doc_id": {"$eq": doc_id}})
                existing_ids = set(existing["ids"]) if existing and existing.get("ids") else set()
                new_ids = set(c.chunk_id for c in doc_chunks)
                stale_ids = existing_ids - new_ids
                if stale_ids:
                    self.collection.delete(ids=list(stale_ids))

        # Step 3: Upsert pre-validated chunks in batches
        total_chunks = len(chunks)
        for i in range(0, total_chunks, valid_batch_size):
            end_idx = min(i + valid_batch_size, total_chunks)
            self.collection.upsert(
                ids=ids[i:end_idx],
                embeddings=valid_embeddings[i:end_idx],
                documents=documents[i:end_idx],
                metadatas=metadatas[i:end_idx]
            )

        return total_chunks

    def sync_document_chunks(
        self,
        doc_id: str,
        new_chunks: List[DocumentChunk],
        embeddings: Optional[List[List[float]]] = None,
        batch_size: int = 64
    ) -> int:
        """
        Synchronizes chunks for a specific document ID:
        - Validates that target doc_id is valid.
        - Validates that all chunks belong to the target doc_id.
        - Pre-validates all metadata, chunk IDs, and embeddings BEFORE pruning.
        - Removes obsolete chunks when the document changes and produces fewer chunks.
        - Deletes all chunks if the document produces zero chunks.
        - Leaves chunks of other documents untouched.
        - Directly upserts prepared data without redundant re-validation.
        """
        if not isinstance(doc_id, str) or not doc_id.strip():
            raise ValueError(f"doc_id must be a non-empty string, got {doc_id!r}")

        valid_batch_size = _validate_batch_size(batch_size)

        # Step 1: If replacement chunks exist, pre-validate them BEFORE any deletion
        ids: List[str] = []
        documents: List[str] = []
        valid_embeddings: List[List[float]] = []
        metadatas: List[Dict[str, Any]] = []

        if new_chunks:
            ids, documents, valid_embeddings, metadatas = self._validate_batch_inputs(
                new_chunks, embeddings, target_doc_id=doc_id
            )

        # Step 2: Determine stale chunks for this specific document
        existing = self.collection.get(where={"doc_id": {"$eq": doc_id}})
        existing_ids = set(existing["ids"]) if existing and existing.get("ids") else set()

        new_ids = set(c.chunk_id for c in new_chunks)
        stale_ids = existing_ids - new_ids

        # Step 3: Prune stale IDs (safe because new chunks are already validated)
        if stale_ids:
            self.collection.delete(ids=list(stale_ids))

        # Step 4: Upsert pre-validated chunks directly (no redundant second validation)
        if new_chunks:
            total_chunks = len(ids)
            for i in range(0, total_chunks, valid_batch_size):
                end_idx = min(i + valid_batch_size, total_chunks)
                self.collection.upsert(
                    ids=ids[i:end_idx],
                    embeddings=valid_embeddings[i:end_idx],
                    documents=documents[i:end_idx],
                    metadatas=metadatas[i:end_idx]
                )

        return len(new_chunks)

    def delete_document_chunks(self, doc_id: str) -> int:
        """Removes all chunks associated with a specific document ID."""
        if not isinstance(doc_id, str) or not doc_id.strip():
            raise ValueError(f"doc_id must be a non-empty string, got {doc_id!r}")

        existing = self.collection.get(where={"doc_id": {"$eq": doc_id}})
        if existing and existing.get("ids"):
            self.collection.delete(ids=existing["ids"])
            return len(existing["ids"])
        return 0

    def query(
        self,
        query_embedding: List[float],
        top_k: int = 4,
        where_filter: Optional[Dict[str, Any]] = None
    ) -> List[DocumentChunk]:
        """
        Executes vector similarity search with optional metadata filtering.
        
        Returns reconstituted DocumentChunk objects with title preserved.
        """
        query_params: Dict[str, Any] = {
            "query_embeddings": [query_embedding],
            "n_results": top_k,
            "include": ["documents", "metadatas", "distances"]
        }
        if where_filter:
            query_params["where"] = where_filter

        results = self.collection.query(**query_params)

        retrieved_chunks: List[DocumentChunk] = []
        if not results or not results["ids"] or not results["ids"][0]:
            return retrieved_chunks

        ids = results["ids"][0]
        docs = results["documents"][0] if results.get("documents") else []
        metas = results["metadatas"][0] if results.get("metadatas") else []

        for idx, chunk_id in enumerate(ids):
            meta = metas[idx] if idx < len(metas) else {}
            content = docs[idx] if idx < len(docs) else ""

            canary_refs_raw = meta.get("canary_refs", "")
            canary_refs = [ref for ref in canary_refs_raw.split(",") if ref] if canary_refs_raw else []

            chunk = DocumentChunk(
                chunk_id=chunk_id,
                doc_id=meta.get("doc_id", ""),
                tenant_id=TenantId(meta.get("tenant_id", "tenant_a")),
                access_level=AccessLevel(meta.get("access_level", "public")),
                title=meta.get("title", ""),
                content=content,
                chunk_index=int(meta.get("chunk_index", 0)),
                category=meta.get("category", ""),
                is_poisoned=bool(meta.get("is_poisoned", False)),
                has_secret=bool(meta.get("has_secret", False)),
                canary_refs=canary_refs,
            )
            retrieved_chunks.append(chunk)

        return retrieved_chunks

    def count(self) -> int:
        """Returns the total number of chunks currently stored in the collection."""
        return self.collection.count()

    def reset(self) -> None:
        """Deletes and recreates the collection."""
        self.client.delete_collection(self.collection_name)
        self.collection = self.client.create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
