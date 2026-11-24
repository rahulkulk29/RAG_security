"""Tests for ChromaIndexer: storage, querying, metadata filters, idempotency, canary security, title preservation, and stale chunk pruning."""
import pytest
from pathlib import Path

from app.core.types import TenantId, AccessLevel
from app.core.schemas import DocumentChunk
from app.ingestion.indexer import ChromaIndexer


def test_indexer_upsert_and_count(temp_chroma_dir: Path, mock_embedder):
    """Verify upserting chunks persists data and reflects in collection count."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_1")

    chunk = DocumentChunk(
        chunk_id="doc_ta_public_01_c00",
        doc_id="doc_ta_public_01",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="ApexPay Platform Overview",
        content="ApexPay developer documentation content.",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    embs = mock_embedder.embed_batch([chunk.content])
    count = indexer.upsert_chunks([chunk], embeddings=embs)

    assert count == 1
    assert indexer.count() == 1


def test_title_propagation_and_persistence(temp_chroma_dir: Path, mock_embedder):
    """Verify document title is stored in ChromaDB and faithfully restored upon retrieval."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_title")

    chunk = DocumentChunk(
        chunk_id="doc_title_test_c00",
        doc_id="doc_title_test",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="ApexPay Platform Architecture Guide",
        content="Architecture specification content.",
        chunk_index=0,
        category="architecture",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    embs = mock_embedder.embed_batch([chunk.content])
    indexer.upsert_chunks([chunk], embeddings=embs)

    # 1. Verify direct collection metadata
    raw_items = indexer.collection.get(ids=[chunk.chunk_id])
    assert raw_items["metadatas"][0]["title"] == "ApexPay Platform Architecture Guide"

    # 2. Verify restored DocumentChunk via query()
    q_vec = mock_embedder.embed_text("architecture")
    results = indexer.query(query_embedding=q_vec, top_k=1)
    assert len(results) == 1
    assert results[0].title == "ApexPay Platform Architecture Guide"


def test_idempotency_no_duplicates(temp_chroma_dir: Path, mock_embedder):
    """Verify running upsert multiple times produces zero duplicate records."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_idempotent")

    chunks = [
        DocumentChunk(
            chunk_id=f"doc_ta_public_01_c{i:02d}",
            doc_id="doc_ta_public_01",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="ApexPay Platform Overview",
            content=f"Paragraph {i} content text.",
            chunk_index=i,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        )
        for i in range(3)
    ]

    embs = mock_embedder.embed_batch([c.content for c in chunks])

    # First run
    indexer.upsert_chunks(chunks, embeddings=embs)
    assert indexer.count() == 3

    # Second run with exact same chunks
    indexer.upsert_chunks(chunks, embeddings=embs)
    assert indexer.count() == 3, "Idempotency violated: duplicate chunks created"


def test_stale_chunk_removal(temp_chroma_dir: Path, mock_embedder):
    """Verify obsolete chunks are pruned when a document is re-indexed with fewer chunks."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_stale")

    # Document A initially has 3 chunks
    doc_a_chunks_v1 = [
        DocumentChunk(
            chunk_id=f"doc_a_c{i:02d}",
            doc_id="doc_a",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="Doc A",
            content=f"Doc A content paragraph {i}",
            chunk_index=i,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        )
        for i in range(3)
    ]

    # Document B has 1 chunk
    doc_b_chunk = DocumentChunk(
        chunk_id="doc_b_c00",
        doc_id="doc_b",
        tenant_id=TenantId.TENANT_B,
        access_level=AccessLevel.PUBLIC,
        title="Doc B",
        content="Doc B content",
        chunk_index=0,
        category="security",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    all_chunks = doc_a_chunks_v1 + [doc_b_chunk]
    embs = mock_embedder.embed_batch([c.content for c in all_chunks])
    indexer.upsert_chunks(all_chunks, embeddings=embs)
    assert indexer.count() == 4

    # Document A changes and now only generates 2 chunks (c00, c01). c02 is now obsolete.
    doc_a_chunks_v2 = doc_a_chunks_v1[:2]
    doc_a_embs_v2 = mock_embedder.embed_batch([c.content for c in doc_a_chunks_v2])

    indexer.sync_document_chunks("doc_a", doc_a_chunks_v2, embeddings=doc_a_embs_v2)

    # Total count should now be 3 (2 for doc_a + 1 for doc_b)
    assert indexer.count() == 3

    # doc_a_c02 should be completely gone
    res = indexer.collection.get(ids=["doc_a_c02"])
    assert len(res["ids"]) == 0

    # Unrelated document B must remain completely intact
    doc_b_res = indexer.collection.get(ids=["doc_b_c00"])
    assert len(doc_b_res["ids"]) == 1


def test_document_zero_chunks_removal(temp_chroma_dir: Path, mock_embedder):
    """Verify synchronizing a document with zero chunks removes all its previous chunks without touching others."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_zero")

    chunk_a = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Doc A content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    chunk_b = DocumentChunk(
        chunk_id="doc_b_c00",
        doc_id="doc_b",
        tenant_id=TenantId.TENANT_B,
        access_level=AccessLevel.PUBLIC,
        title="Doc B",
        content="Doc B content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    embs = mock_embedder.embed_batch([chunk_a.content, chunk_b.content])
    indexer.upsert_chunks([chunk_a, chunk_b], embeddings=embs)
    assert indexer.count() == 2

    # Sync doc_a with 0 chunks (e.g. emptied or deleted document)
    indexer.sync_document_chunks("doc_a", [])

    assert indexer.count() == 1
    # doc_a is deleted
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 0
    # doc_b is untouched
    assert len(indexer.collection.get(ids=["doc_b_c00"])["ids"]) == 1


def test_query_retrieval_and_filtering(temp_chroma_dir: Path, mock_embedder):
    """Verify vector search returns matching chunk and respects metadata where_filter."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_query")

    chunk_ta = DocumentChunk(
        chunk_id="doc_ta_c00",
        doc_id="doc_ta",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Fintech Payments",
        content="Payment processing APIs for fintech.",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    chunk_tb = DocumentChunk(
        chunk_id="doc_tb_c00",
        doc_id="doc_tb",
        tenant_id=TenantId.TENANT_B,
        access_level=AccessLevel.PUBLIC,
        title="Healthcare Patient Security",
        content="Cloud healthcare patient database security.",
        chunk_index=0,
        category="medical",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    embs = mock_embedder.embed_batch([chunk_ta.content, chunk_tb.content])
    indexer.upsert_chunks([chunk_ta, chunk_tb], embeddings=embs)

    # Query with tenant_a filter
    q_vec = mock_embedder.embed_text("fintech payments")
    results = indexer.query(
        query_embedding=q_vec,
        top_k=2,
        where_filter={"tenant_id": {"$eq": "tenant_a"}}
    )

    assert len(results) == 1
    assert results[0].chunk_id == "doc_ta_c00"
    assert results[0].tenant_id == TenantId.TENANT_A
    assert results[0].title == "Fintech Payments"


def test_security_sanitization_blocks_raw_canary_leak(temp_chroma_dir: Path):
    """Verify indexer refuses to store raw canary token and redacts secret from exception message."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_sec")

    raw_secret_value = "CANARY_TENANT_A_ADMIN_PAYROLL_98412"

    # Attempt to slip a raw canary token into category
    leaky_chunk = DocumentChunk(
        chunk_id="leaky_chunk_c00",
        doc_id="doc_leaky",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.ADMIN,
        title="Confidential Payroll",
        content="Some confidential text",
        chunk_index=0,
        category=raw_secret_value,
        is_poisoned=False,
        has_secret=True,
        canary_refs=["CANARY-TA-ADM-01"],
    )

    with pytest.raises(ValueError) as exc_info:
        indexer._sanitize_and_validate_metadata(leaky_chunk)

    err_msg = str(exc_info.value)
    # Check that error is raised
    assert "CRITICAL SECURITY VIOLATION: Raw canary token detected" in err_msg
    # CRUCIAL: Raw secret string must NOT be printed in the exception message
    assert raw_secret_value not in err_msg
    assert "redacted" in err_msg


def test_metadata_contains_safe_refs_only(temp_chroma_dir: Path, mock_embedder):
    """Verify stored metadata contains safe canary_refs and no raw token strings."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_safe_refs")

    chunk = DocumentChunk(
        chunk_id="doc_ta_admin_01_c00",
        doc_id="doc_ta_admin_01",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.ADMIN,
        title="Executive Compensation",
        content="Executive compensation record.",
        chunk_index=0,
        category="finance",
        is_poisoned=False,
        has_secret=True,
        canary_refs=["CANARY-TA-ADM-01"],
    )

    embs = mock_embedder.embed_batch([chunk.content])
    indexer.upsert_chunks([chunk], embeddings=embs)

    raw_items = indexer.collection.get()
    meta = raw_items["metadatas"][0]

    assert meta["canary_refs"] == "CANARY-TA-ADM-01"
    assert "CANARY_TENANT_" not in str(meta)
    assert "FLAG{" not in str(meta)


def test_reset_clears_collection(temp_chroma_dir: Path, mock_embedder):
    """Verify reset drops all records and recreates empty collection."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_reset")

    chunk = DocumentChunk(
        chunk_id="chunk_01",
        doc_id="doc_01",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Test Document",
        content="Content to be deleted.",
        chunk_index=0,
        category="test",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    embs = mock_embedder.embed_batch([chunk.content])
    indexer.upsert_chunks([chunk], embeddings=embs)
    assert indexer.count() == 1

    indexer.reset()
    assert indexer.count() == 0


def test_sync_rejects_foreign_document_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify that sync_document_chunks strictly rejects chunks with mismatched doc_id."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_mismatch")

    foreign_chunk = DocumentChunk(
        chunk_id="doc_foreign_c00",
        doc_id="doc_foreign",
        tenant_id=TenantId.TENANT_B,
        access_level=AccessLevel.PUBLIC,
        title="Foreign Document",
        content="Foreign content",
        chunk_index=0,
        category="security",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    with pytest.raises(ValueError, match="Document ID mismatch during synchronization"):
        indexer.sync_document_chunks("doc_target", [foreign_chunk])


def test_invalid_embedding_count_preserves_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify that an embedding count mismatch does not prune existing chunks before failing."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_emb_err")

    original_chunks = [
        DocumentChunk(
            chunk_id="doc_a_c00",
            doc_id="doc_a",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="Doc A",
            content="Original paragraph 0",
            chunk_index=0,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        ),
        DocumentChunk(
            chunk_id="doc_a_c01",
            doc_id="doc_a",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="Doc A",
            content="Original paragraph 1",
            chunk_index=1,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        ),
    ]
    embs = mock_embedder.embed_batch([c.content for c in original_chunks])
    indexer.upsert_chunks(original_chunks, embeddings=embs)
    assert indexer.count() == 2

    # Attempt to sync with 1 replacement chunk but 2 embedding vectors (count mismatch)
    replacement = [original_chunks[0]]
    bad_embs = [embs[0], embs[1]]

    with pytest.raises(ValueError, match="does not match embeddings count"):
        indexer.sync_document_chunks("doc_a", replacement, embeddings=bad_embs)

    # CRITICAL: Existing chunks must NOT have been pruned
    assert indexer.count() == 2
    res = indexer.collection.get(ids=["doc_a_c00", "doc_a_c01"])
    assert len(res["ids"]) == 2


def test_invalid_canary_metadata_preserves_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify that metadata validation failure does not prune existing chunks before failing."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_canary_err")

    original_chunks = [
        DocumentChunk(
            chunk_id="doc_a_c00",
            doc_id="doc_a",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="Doc A",
            content="Original paragraph 0",
            chunk_index=0,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        )
    ]
    embs = mock_embedder.embed_batch([c.content for c in original_chunks])
    indexer.upsert_chunks(original_chunks, embeddings=embs)
    assert indexer.count() == 1

    # Attempt to sync with a replacement chunk that has an unauthorized raw canary in metadata
    bad_replacement = [
        DocumentChunk(
            chunk_id="doc_a_c00",
            doc_id="doc_a",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="Doc A",
            content="Valid document body text",
            chunk_index=0,
            category="CANARY_TENANT_A_LEAK_IN_CATEGORY",
            is_poisoned=False,
            has_secret=True,
            canary_refs=[],
        )
    ]

    with pytest.raises(ValueError, match="CRITICAL SECURITY VIOLATION"):
        indexer.sync_document_chunks("doc_a", bad_replacement)

    # CRITICAL: Existing chunk must still be preserved
    assert indexer.count() == 1
    res = indexer.collection.get(ids=["doc_a_c00"])
    assert len(res["ids"]) == 1


def test_duplicate_chunk_ids_rejected(temp_chroma_dir: Path, mock_embedder):
    """Verify that batches with duplicate chunk IDs are rejected without modifying existing data."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_dup")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    # Attempt to sync with duplicate chunk IDs
    dup_chunks = [
        DocumentChunk(
            chunk_id="doc_a_c01",
            doc_id="doc_a",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="Doc A",
            content="Replacement 1",
            chunk_index=1,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        ),
        DocumentChunk(
            chunk_id="doc_a_c01",  # duplicate ID
            doc_id="doc_a",
            tenant_id=TenantId.TENANT_A,
            access_level=AccessLevel.PUBLIC,
            title="Doc A",
            content="Replacement 2",
            chunk_index=2,
            category="product",
            is_poisoned=False,
            has_secret=False,
            canary_refs=[],
        ),
    ]

    with pytest.raises(ValueError, match="Duplicate chunk ID detected"):
        indexer.sync_document_chunks("doc_a", dup_chunks)

    # Existing chunk must remain untouched
    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_wrong_dimension_embeddings_preserve_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify that an embedding with incorrect dimension does not prune existing chunks before failing."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_wrong_dim")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    # Attempt to sync with wrong dimension embedding (e.g. 200 instead of 384)
    bad_embs = [[0.1] * 200]
    with pytest.raises(ValueError, match="Embedding dimension mismatch"):
        indexer.sync_document_chunks("doc_a", [original_chunk], embeddings=bad_embs)

    # Existing chunk must still be preserved
    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_nan_or_infinity_embeddings_preserve_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify that embeddings containing NaN or infinity do not prune existing chunks before failing."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_nan_inf")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    # Attempt to sync with NaN in vector
    nan_vec = [0.1] * 383 + [float("nan")]
    with pytest.raises(ValueError, match="Non-finite embedding component detected"):
        indexer.sync_document_chunks("doc_a", [original_chunk], embeddings=[nan_vec])

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1

    # Attempt to sync with +Inf in vector
    inf_vec = [0.1] * 383 + [float("inf")]
    with pytest.raises(ValueError, match="Non-finite embedding component detected"):
        indexer.sync_document_chunks("doc_a", [original_chunk], embeddings=[inf_vec])

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_non_numeric_embeddings_preserve_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify that embeddings containing non-numeric scalar values do not prune existing chunks."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_non_num")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    # Attempt to sync with string in vector
    bad_str_vec = [0.1] * 383 + ["non_numeric_string"]  # type: ignore
    with pytest.raises(ValueError, match="Non-numeric embedding component detected"):
        indexer.sync_document_chunks("doc_a", [original_chunk], embeddings=[bad_str_vec])

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1

    # Attempt to sync with boolean in vector
    bad_bool_vec = [0.1] * 383 + [True]  # type: ignore
    with pytest.raises(ValueError, match="Non-numeric embedding component detected"):
        indexer.sync_document_chunks("doc_a", [original_chunk], embeddings=[bad_bool_vec])

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_invalid_batch_size_preserves_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify that batch_size=0 rejects immediately and preserves existing chunks."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_bs_zero")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    replacement_chunk = DocumentChunk(
        chunk_id="doc_a_c01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Replacement content",
        chunk_index=1,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.upsert_chunks([replacement_chunk], batch_size=0, sync_stale=True)

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1

    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.sync_document_chunks("doc_a", [replacement_chunk], batch_size=0)

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_negative_batch_size_preserves_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify that negative batch_size rejects immediately and preserves existing chunks."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_bs_neg")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    replacement_chunk = DocumentChunk(
        chunk_id="doc_a_c01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Replacement content",
        chunk_index=1,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.upsert_chunks([replacement_chunk], batch_size=-1, sync_stale=True)

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_boolean_batch_size_rejected(temp_chroma_dir: Path, mock_embedder):
    """Verify that boolean values for batch_size (True/False) are rejected."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_bs_bool")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    replacement_chunk = DocumentChunk(
        chunk_id="doc_a_c01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Replacement content",
        chunk_index=1,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.upsert_chunks([replacement_chunk], batch_size=True, sync_stale=True)  # type: ignore

    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.sync_document_chunks("doc_a", [replacement_chunk], batch_size=True)  # type: ignore

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_float_batch_size_rejected(temp_chroma_dir: Path, mock_embedder):
    """Verify that float values for batch_size are rejected."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_bs_float")

    chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.upsert_chunks([chunk], batch_size=1.5)  # type: ignore

    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.sync_document_chunks("doc_a", [chunk], batch_size=2.0)  # type: ignore


def test_sync_stale_invalid_embedding_preserves_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify upsert_chunks(sync_stale=True) preserves existing chunks on invalid embeddings."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_sync_invalid_emb")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    replacement_chunk = DocumentChunk(
        chunk_id="doc_a_c01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Replacement content",
        chunk_index=1,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    # Wrong dimension
    with pytest.raises(ValueError, match="Embedding dimension mismatch"):
        indexer.upsert_chunks([replacement_chunk], embeddings=[[0.1] * 128], sync_stale=True)

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1

    # Non-finite vector
    nan_vec = [0.1] * 383 + [float("nan")]
    with pytest.raises(ValueError, match="Non-finite embedding component detected"):
        indexer.upsert_chunks([replacement_chunk], embeddings=[nan_vec], sync_stale=True)

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_sync_stale_invalid_metadata_preserves_existing_chunks(temp_chroma_dir: Path, mock_embedder):
    """Verify upsert_chunks(sync_stale=True) preserves existing chunks when canary metadata check fails."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_sync_invalid_meta")

    original_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([original_chunk])
    assert indexer.count() == 1

    bad_meta_chunk = DocumentChunk(
        chunk_id="doc_a_c01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Leaked CANARY_SEC_4a7b1c3d5e9f in title",
        content="Replacement content",
        chunk_index=1,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    with pytest.raises(ValueError, match="CRITICAL SECURITY VIOLATION: Raw canary token detected"):
        indexer.upsert_chunks([bad_meta_chunk], sync_stale=True)

    assert indexer.count() == 1
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 1


def test_sync_rejects_chunk_id_owned_by_another_document(temp_chroma_dir: Path, mock_embedder):
    """Verify that attempting to synchronize a chunk whose ID belongs to another doc is rejected."""
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_collision")

    # Document B has chunk "doc_b_c00"
    chunk_b = DocumentChunk(
        chunk_id="doc_b_c00",
        doc_id="doc_b",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.ADMIN,
        title="Doc B Title",
        content="Doc B sensitive data",
        chunk_index=0,
        category="internal",
        is_poisoned=False,
        has_secret=True,
        canary_refs=[],
    )
    indexer.upsert_chunks([chunk_b])
    assert indexer.count() == 1

    # Document A attempts to sync a chunk with chunk_id "doc_b_c00"
    colliding_chunk = DocumentChunk(
        chunk_id="doc_b_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A Title",
        content="Doc A attempting to overwrite Doc B",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    # Test via sync_document_chunks
    with pytest.raises(ValueError, match="Cross-document chunk ID collision"):
        indexer.sync_document_chunks("doc_a", [colliding_chunk])

    # doc_b chunk must remain intact and owned by doc_b
    assert indexer.count() == 1
    existing_b = indexer.collection.get(ids=["doc_b_c00"])
    assert existing_b["metadatas"][0]["doc_id"] == "doc_b"
    assert existing_b["metadatas"][0]["title"] == "Doc B Title"

    # Test via upsert_chunks(sync_stale=True)
    with pytest.raises(ValueError, match="Cross-document chunk ID collision"):
        indexer.upsert_chunks([colliding_chunk], sync_stale=True)

    assert indexer.count() == 1
    existing_b = indexer.collection.get(ids=["doc_b_c00"])
    assert existing_b["metadatas"][0]["doc_id"] == "doc_b"


def test_collection_delete_never_called_on_invalid_input(temp_chroma_dir: Path, mock_embedder, monkeypatch):
    """
    Spy on collection.delete() to prove that no deletion is attempted when inputs are invalid.
    Also verifies that delete() is called only during valid sync with genuine stale chunks.
    """
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_delete_spy")

    # Initial chunk for doc_a
    orig_chunk = DocumentChunk(
        chunk_id="doc_a_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Original Doc A",
        content="Original content",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([orig_chunk])

    # Initial chunk for doc_b
    chunk_b = DocumentChunk(
        chunk_id="doc_b_c00",
        doc_id="doc_b",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.ADMIN,
        title="Original Doc B",
        content="Doc B content",
        chunk_index=0,
        category="admin",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    indexer.upsert_chunks([chunk_b])
    assert indexer.count() == 2

    # Track calls to collection.delete
    delete_calls = []
    real_delete = indexer.collection.delete

    def spy_delete(*args, **kwargs):
        delete_calls.append({"args": args, "kwargs": kwargs})
        return real_delete(*args, **kwargs)

    monkeypatch.setattr(indexer.collection, "delete", spy_delete)

    # 1. Invalid batch size
    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.sync_document_chunks("doc_a", [orig_chunk], batch_size=0)
    assert len(delete_calls) == 0

    with pytest.raises(ValueError, match="batch_size must be a positive integer"):
        indexer.upsert_chunks([orig_chunk], batch_size=True, sync_stale=True)  # type: ignore
    assert len(delete_calls) == 0

    # 2. Invalid vector (wrong dimension)
    bad_dim_chunk = DocumentChunk(
        chunk_id="doc_a_c01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A New",
        content="New content",
        chunk_index=1,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    with pytest.raises(ValueError, match="Embedding dimension mismatch"):
        indexer.sync_document_chunks("doc_a", [bad_dim_chunk], embeddings=[[0.5] * 100])
    assert len(delete_calls) == 0

    # 3. Invalid vector (non-finite)
    nan_vector = [0.1] * 383 + [float("nan")]
    with pytest.raises(ValueError, match="Non-finite embedding component detected"):
        indexer.upsert_chunks([bad_dim_chunk], embeddings=[nan_vector], sync_stale=True)
    assert len(delete_calls) == 0

    # 4. Invalid metadata (canary token leak)
    leaked_chunk = DocumentChunk(
        chunk_id="doc_a_c01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Title with CANARY_SEC_4a7b1c3d5e9f",
        content="New content",
        chunk_index=1,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    with pytest.raises(ValueError, match="CRITICAL SECURITY VIOLATION: Raw canary token detected"):
        indexer.sync_document_chunks("doc_a", [leaked_chunk])
    assert len(delete_calls) == 0

    with pytest.raises(ValueError, match="CRITICAL SECURITY VIOLATION: Raw canary token detected"):
        indexer.upsert_chunks([leaked_chunk], sync_stale=True)
    assert len(delete_calls) == 0

    # 5. Cross-document chunk ID collision
    collision_chunk = DocumentChunk(
        chunk_id="doc_b_c00",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A Collision",
        content="Trying to hijack doc_b chunk",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    with pytest.raises(ValueError, match="Cross-document chunk ID collision"):
        indexer.sync_document_chunks("doc_a", [collision_chunk])
    assert len(delete_calls) == 0

    with pytest.raises(ValueError, match="Cross-document chunk ID collision"):
        indexer.upsert_chunks([collision_chunk], sync_stale=True)
    assert len(delete_calls) == 0

    # 6. Valid sync with a genuine replacement chunk (replaces doc_a_c00 with doc_a_c01)
    valid_replacement = DocumentChunk(
        chunk_id="doc_a_c01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A Valid Replacement",
        content="Valid replacement content",
        chunk_index=1,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )
    valid_embs = mock_embedder.embed_batch([valid_replacement.content])
    indexer.sync_document_chunks("doc_a", [valid_replacement], embeddings=valid_embs)

    # Now delete MUST have been called exactly once for the stale chunk "doc_a_c00"
    assert len(delete_calls) == 1
    assert delete_calls[0]["kwargs"]["ids"] == ["doc_a_c00"]

    # Verify database state: doc_a has doc_a_c01, doc_a_c00 is gone, doc_b_c00 is untouched
    assert indexer.count() == 2
    assert len(indexer.collection.get(ids=["doc_a_c00"])["ids"]) == 0
    assert len(indexer.collection.get(ids=["doc_a_c01"])["ids"]) == 1
    assert len(indexer.collection.get(ids=["doc_b_c00"])["ids"]) == 1


def test_sync_rejects_existing_chunk_with_missing_doc_id_metadata(temp_chroma_dir: Path, mock_embedder, monkeypatch):
    """
    Verify fail-closed ownership behavior when an existing ChromaDB record has metadata
    missing the required 'doc_id' attribute.
    """
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_missing_doc_id")

    # Directly insert an unowned/legacy record without doc_id in metadata
    indexer.collection.add(
        ids=["orphan_chunk_01"],
        documents=["Legacy content without doc_id metadata"],
        embeddings=[[0.1] * 384],
        metadatas=[{"category": "untracked", "title": "Untracked Guide"}]
    )
    assert indexer.count() == 1

    delete_calls = []
    real_delete = indexer.collection.delete

    def spy_delete(*args, **kwargs):
        delete_calls.append({"args": args, "kwargs": kwargs})
        return real_delete(*args, **kwargs)

    monkeypatch.setattr(indexer.collection, "delete", spy_delete)

    incoming_chunk = DocumentChunk(
        chunk_id="orphan_chunk_01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A Overwrite Attempt",
        content="Attempting to overwrite orphan chunk",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    # 1. Test via sync_document_chunks
    with pytest.raises(ValueError, match="Existing chunk has missing or invalid ownership metadata; refusing overwrite"):
        indexer.sync_document_chunks("doc_a", [incoming_chunk])

    assert indexer.count() == 1
    existing_rec = indexer.collection.get(ids=["orphan_chunk_01"])
    assert existing_rec["documents"][0] == "Legacy content without doc_id metadata"
    assert existing_rec["metadatas"][0] == {"category": "untracked", "title": "Untracked Guide"}
    assert len(delete_calls) == 0

    # 2. Test via upsert_chunks(sync_stale=True)
    with pytest.raises(ValueError, match="Existing chunk has missing or invalid ownership metadata; refusing overwrite"):
        indexer.upsert_chunks([incoming_chunk], sync_stale=True)

    assert indexer.count() == 1
    existing_rec = indexer.collection.get(ids=["orphan_chunk_01"])
    assert existing_rec["documents"][0] == "Legacy content without doc_id metadata"
    assert existing_rec["metadatas"][0] == {"category": "untracked", "title": "Untracked Guide"}
    assert len(delete_calls) == 0


def test_sync_rejects_existing_chunk_with_none_or_empty_doc_id_metadata(temp_chroma_dir: Path, mock_embedder, monkeypatch):
    """
    Verify fail-closed ownership behavior when an existing ChromaDB record has None metadata
    or an empty string doc_id.
    
    ChromaDB environment note:
    ChromaDB allows collection.add() with metadatas=None (which stores None) and empty string
    attribute values, but rejects empty dictionaries ([{}]) with 'Expected metadata to be a non-empty dict'.
    Both supported malformed representations (None metadata and blank string doc_id) are verified.
    """
    indexer = ChromaIndexer(persist_dir=temp_chroma_dir, collection_name="test_col_none_meta")

    # Insert a record with metadatas=None
    indexer.collection.add(
        ids=["none_meta_chunk_01"],
        documents=["Raw content with None metadata"],
        embeddings=[[0.1] * 384],
        metadatas=None
    )
    # Insert a record with whitespace doc_id
    indexer.collection.add(
        ids=["empty_doc_id_chunk_01"],
        documents=["Raw content with empty doc_id"],
        embeddings=[[0.1] * 384],
        metadatas=[{"doc_id": "   ", "category": "test"}]
    )
    assert indexer.count() == 2

    delete_calls = []
    real_delete = indexer.collection.delete

    def spy_delete(*args, **kwargs):
        delete_calls.append({"args": args, "kwargs": kwargs})
        return real_delete(*args, **kwargs)

    monkeypatch.setattr(indexer.collection, "delete", spy_delete)

    chunk_targeting_none = DocumentChunk(
        chunk_id="none_meta_chunk_01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A Overwrite None",
        content="Attempting overwrite on None metadata",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    chunk_targeting_empty = DocumentChunk(
        chunk_id="empty_doc_id_chunk_01",
        doc_id="doc_a",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="Doc A Overwrite Empty",
        content="Attempting overwrite on empty doc_id",
        chunk_index=0,
        category="product",
        is_poisoned=False,
        has_secret=False,
        canary_refs=[],
    )

    # 1. Targeting None metadata via sync_document_chunks
    with pytest.raises(ValueError, match="Existing chunk has missing or invalid ownership metadata; refusing overwrite"):
        indexer.sync_document_chunks("doc_a", [chunk_targeting_none])

    assert indexer.count() == 2
    rec_none = indexer.collection.get(ids=["none_meta_chunk_01"])
    assert rec_none["documents"][0] == "Raw content with None metadata"
    assert rec_none["metadatas"][0] is None
    assert len(delete_calls) == 0

    # 2. Targeting empty doc_id via upsert_chunks(sync_stale=True)
    with pytest.raises(ValueError, match="Existing chunk has missing or invalid ownership metadata; refusing overwrite"):
        indexer.upsert_chunks([chunk_targeting_empty], sync_stale=True)

    assert indexer.count() == 2
    rec_empty = indexer.collection.get(ids=["empty_doc_id_chunk_01"])
    assert rec_empty["documents"][0] == "Raw content with empty doc_id"
    assert rec_empty["metadatas"][0]["doc_id"] == "   "
    assert len(delete_calls) == 0



