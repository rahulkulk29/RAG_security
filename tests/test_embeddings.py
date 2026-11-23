"""Tests for EmbeddingGenerator: dimension validation, batch processing, finite values, and setup error handling."""
import pytest
import math
import numpy as np

from app.ingestion.embeddings import EmbeddingGenerator


def test_embedding_dimension_and_type():
    """Verify generated embedding has exactly 384 dimensions and float values."""
    generator = EmbeddingGenerator.get_instance()
    text = "Enterprise RAG security and access control evaluation."
    vector = generator.embed_text(text)

    assert len(vector) == EmbeddingGenerator.EXPECTED_DIMENSION
    assert isinstance(vector, list)
    assert all(isinstance(v, float) for v in vector)


def test_embedding_values_finite():
    """Verify that all embedding vector components are strictly finite numbers."""
    generator = EmbeddingGenerator.get_instance()
    vector = generator.embed_text("Test sentence for numerical stability checks.")

    for val in vector:
        assert not math.isnan(val), "Vector contains NaN value"
        assert not math.isinf(val), "Vector contains infinite value"


def test_batch_embedding():
    """Verify batch embedding generation matches input size and per-item dimension."""
    generator = EmbeddingGenerator.get_instance()
    texts = [
        "First test sentence for batching.",
        "Second test sentence with different semantic content.",
        "Third document chunk content."
    ]
    vectors = generator.embed_batch(texts)

    assert len(vectors) == 3
    for vec in vectors:
        assert len(vec) == EmbeddingGenerator.EXPECTED_DIMENSION


def test_reject_empty_text():
    """Verify that empty or whitespace-only inputs are rejected."""
    generator = EmbeddingGenerator.get_instance()

    with pytest.raises(ValueError, match="Cannot embed empty"):
        generator.embed_text("")

    with pytest.raises(ValueError, match="Cannot embed empty"):
        generator.embed_text("   \n\t  ")

    with pytest.raises(ValueError, match="Cannot embed empty"):
        generator.embed_batch(["Valid text", ""])


def test_singleton_pattern():
    """Verify that get_instance returns the cached singleton."""
    inst1 = EmbeddingGenerator.get_instance()
    inst2 = EmbeddingGenerator.get_instance()
    assert inst1 is inst2


def test_uncached_model_error():
    """Verify clear, actionable error is raised when a model is not found in local cache."""
    # Ensure temporary instance tries an uncached bogus model
    with pytest.raises(RuntimeError) as exc_info:
        EmbeddingGenerator(model_name="non_existent/model-that-does-not-exist-xyz", allow_download=False)

    msg = str(exc_info.value)
    assert "not found in local cache" in msg
    assert "scripts/setup_model.py" in msg


def test_vector_validation_failure():
    """Verify that _validate_vector catches non-compliant vectors."""
    generator = EmbeddingGenerator.get_instance()

    # Wrong dimension
    with pytest.raises(ValueError, match="Embedding dimension mismatch"):
        generator._validate_vector([0.1] * 128)

    # NaN value
    bad_vec_nan = [0.1] * 383 + [float("nan")]
    with pytest.raises(ValueError, match="Non-finite embedding component detected"):
        generator._validate_vector(bad_vec_nan)

    # Inf value
    bad_vec_inf = [0.1] * 383 + [float("inf")]
    with pytest.raises(ValueError, match="Non-finite embedding component detected"):
        generator._validate_vector(bad_vec_inf)


def test_embedding_validation_errors_do_not_expose_text():
    """Verify that vector validation errors never expose sensitive text, secrets, or raw floats."""
    sensitive_secret = "CANARY_CONFIDENTIAL_PAYROLL_SECRET_XYZ"

    # 1. Non-finite vector
    with pytest.raises(ValueError) as exc_nan:
        EmbeddingGenerator.validate_vector([0.1] * 383 + [float("nan")])
    msg_nan = str(exc_nan.value)
    assert sensitive_secret not in msg_nan
    assert "Non-finite embedding component detected" in msg_nan

    # 2. Non-numeric vector (string)
    with pytest.raises(ValueError) as exc_str:
        EmbeddingGenerator.validate_vector([0.1] * 383 + [sensitive_secret])
    msg_str = str(exc_str.value)
    # The actual secret string value must NOT be printed in the exception
    assert sensitive_secret not in msg_str
    assert "Non-numeric embedding component detected: str" in msg_str

    # 3. Boolean vector
    with pytest.raises(ValueError) as exc_bool:
        EmbeddingGenerator.validate_vector([0.1] * 383 + [True])
    msg_bool = str(exc_bool.value)
    assert "Non-numeric embedding component detected: bool" in msg_bool

    # 4. Unsupported vector container type
    with pytest.raises(ValueError) as exc_type:
        EmbeddingGenerator.validate_vector("not_a_vector_list")
    assert "Unsupported vector type" in str(exc_type.value)


def test_oversized_integer_vector_component_rejected():
    """Verify that an extremely large integer component is rejected safely without leaking OverflowError or values."""
    oversized_int = 10**1000
    bad_vec = [0.1] * 383 + [oversized_int]

    with pytest.raises(ValueError) as exc_info:
        EmbeddingGenerator.validate_vector(bad_vec)

    msg = str(exc_info.value)
    assert "Non-finite embedding component detected" in msg
    # Crucially ensure raw value is NOT leaked into the error message
    assert str(oversized_int) not in msg
