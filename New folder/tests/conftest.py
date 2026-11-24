"""Pytest fixtures and test environment setup."""
import pytest
from pathlib import Path
from typing import List
import hashlib
import numpy as np

from app.core.types import TenantId, AccessLevel
from app.core.schemas import DocumentMetadata, DocumentChunk
from app.ingestion.embeddings import EmbeddingGenerator


class MockEmbeddingGenerator:
    """Fast deterministic 384-dimensional mock embedding generator for unit tests."""
    EXPECTED_DIMENSION: int = 384

    def embed_text(self, text: str) -> List[float]:
        if not text or not text.strip():
            raise ValueError("Cannot embed empty text")
        # Generate stable, cross-process deterministic vector based on SHA-256 digest
        seed = int.from_bytes(hashlib.sha256(text.encode("utf-8")).digest()[:4], "big")
        rng = np.random.RandomState(seed)
        vec = rng.randn(self.EXPECTED_DIMENSION).astype(float)
        norm = np.linalg.norm(vec)
        return (vec / norm).tolist()

    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        return [self.embed_text(t) for t in texts]


@pytest.fixture
def mock_embedder():
    """Provides a fast mock embedder returning 384-dim unit vectors."""
    return MockEmbeddingGenerator()


@pytest.fixture
def sample_metadata():
    """Provides standard valid document metadata."""
    return DocumentMetadata(
        doc_id="doc_ta_public_01",
        tenant_id=TenantId.TENANT_A,
        access_level=AccessLevel.PUBLIC,
        title="ApexPay Platform Overview & Developer Guide",
        category="product",
        has_secret=False,
        is_poisoned=False,
        canary_refs=[],
    )


@pytest.fixture
def sample_doc_body():
    """Provides realistic sample document text."""
    return (
        "# ApexPay Platform Overview & Developer Guide\n\n"
        "ApexPay is a cloud-native payments infrastructure platform built by FinTech Corp. "
        "It enables modern digital merchants to accept payments across 45 countries with "
        "sub-second transaction routing, dynamic currency conversion, and automated merchant settlements.\n\n"
        "Merchants integrate with ApexPay using our official SDKs (Python, Node.js, Go) or direct REST endpoints. "
        "All requests must be made over TLS 1.3 with a valid public publishable key formatted as pk_live_apex_."
    )


@pytest.fixture
def temp_chroma_dir(tmp_path: Path):
    """Provides an isolated temporary directory for ChromaDB tests."""
    chroma_dir = tmp_path / "test_chromadb"
    chroma_dir.mkdir(parents=True, exist_ok=True)
    return chroma_dir

