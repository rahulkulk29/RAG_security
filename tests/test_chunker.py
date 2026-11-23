"""Tests for TextChunker: partitioning, deterministic IDs, and metadata propagation."""
import pytest

from app.core.types import TenantId, AccessLevel
from app.core.schemas import DocumentMetadata, DocumentChunk
from app.ingestion.chunker import TextChunker


def test_chunk_single_document(sample_metadata: DocumentMetadata, sample_doc_body: str):
    """Verify that a document within chunk size produces exactly one chunk with full metadata."""
    chunker = TextChunker(chunk_size_chars=2000, chunk_overlap_chars=300)
    chunks = chunker.chunk_document(sample_metadata, sample_doc_body)

    assert len(chunks) == 1
    chunk = chunks[0]
    assert chunk.chunk_id == f"{sample_metadata.doc_id}_c00"
    assert chunk.doc_id == sample_metadata.doc_id
    assert chunk.tenant_id == sample_metadata.tenant_id
    assert chunk.access_level == sample_metadata.access_level
    assert chunk.title == sample_metadata.title
    assert chunk.chunk_index == 0
    assert chunk.category == sample_metadata.category
    assert chunk.is_poisoned == sample_metadata.is_poisoned
    assert chunk.has_secret == sample_metadata.has_secret
    assert chunk.canary_refs == sample_metadata.canary_refs
    assert len(chunk.content) > 0


def test_multi_chunk_splitting(sample_metadata: DocumentMetadata, sample_doc_body: str):
    """Verify splitting behavior, sequential ID generation, and metadata inheritance across multiple chunks."""
    # Use smaller chunk window to force multi-chunk splitting
    chunker = TextChunker(chunk_size_chars=150, chunk_overlap_chars=30)
    chunks = chunker.chunk_document(sample_metadata, sample_doc_body)

    assert len(chunks) > 1

    for idx, chunk in enumerate(chunks):
        assert chunk.chunk_id == f"{sample_metadata.doc_id}_c{idx:02d}"
        assert chunk.chunk_index == idx
        assert chunk.doc_id == sample_metadata.doc_id
        assert chunk.tenant_id == sample_metadata.tenant_id
        assert chunk.access_level == sample_metadata.access_level
        assert chunk.title == sample_metadata.title
        assert len(chunk.content) > 0
        assert len(chunk.content) <= 150 + 50  # Boundary margin check


def test_avoid_empty_chunks(sample_metadata: DocumentMetadata):
    """Verify empty or whitespace-only documents do not produce empty chunks."""
    chunker = TextChunker()
    assert chunker.chunk_document(sample_metadata, "") == []
    assert chunker.chunk_document(sample_metadata, "   \n\n\t   ") == []


def test_invalid_chunk_parameters():
    """Verify validation of chunk configuration parameters."""
    with pytest.raises(ValueError, match="strictly less than chunk_size"):
        TextChunker(chunk_size_chars=200, chunk_overlap_chars=200)

    with pytest.raises(ValueError, match="strictly less than chunk_size"):
        TextChunker(chunk_size_chars=200, chunk_overlap_chars=250)

    with pytest.raises(ValueError, match="chunk_size must be positive"):
        TextChunker(chunk_size_chars=0, chunk_overlap_chars=0)

    with pytest.raises(ValueError, match="chunk_overlap must be non-negative"):
        TextChunker(chunk_size_chars=200, chunk_overlap_chars=-10)


def test_chunk_all_preserves_every_document(sample_metadata: DocumentMetadata):
    """Verify that chunk_all produces chunks covering every input document without loss."""
    docs = [
        (sample_metadata, "Document one body content."),
        (
            DocumentMetadata(
                doc_id="doc_ta_public_02",
                tenant_id=TenantId.TENANT_A,
                access_level=AccessLevel.PUBLIC,
                title="Doc 2",
                category="pricing",
                has_secret=False,
                is_poisoned=False,
                canary_refs=[],
            ),
            "Document two body content."
        ),
    ]

    chunker = TextChunker()
    chunks = chunker.chunk_all(docs)

    assert len(chunks) == 2
    assert chunks[0].chunk_id == "doc_ta_public_01_c00"
    assert chunks[1].chunk_id == "doc_ta_public_02_c00"

