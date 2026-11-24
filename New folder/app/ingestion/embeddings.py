"""Local embedding generation using sentence-transformers/all-MiniLM-L6-v2."""
from typing import List, Optional, Dict, Any
import math
import numpy as np
from sentence_transformers import SentenceTransformer
from app.core.config import settings


class EmbeddingGenerator:
    """
    Generates local vector embeddings using sentence-transformers.
    
    In normal runtime, models are loaded strictly from local cache (local_files_only=True)
    to ensure predictable, offline-capable execution without unexpected network latency.
    
    A fresh developer environment should run:
        python scripts/setup_model.py
    or call EmbeddingGenerator.download_model() once with network access enabled.
    """

    _instance: Optional["EmbeddingGenerator"] = None
    _models: Dict[str, SentenceTransformer] = {}

    EXPECTED_DIMENSION: int = 384

    def __init__(self, model_name: Optional[str] = None, allow_download: bool = False):
        self.model_name = model_name or settings.embedding_model_name
        self.allow_download = allow_download
        self._load_model()

    def _load_model(self) -> None:
        """Load the SentenceTransformer model from cache, or download if explicitly permitted."""
        if self.model_name not in EmbeddingGenerator._models:
            if not self.allow_download:
                try:
                    loaded_model = SentenceTransformer(
                        self.model_name,
                        local_files_only=True
                    )
                    EmbeddingGenerator._models[self.model_name] = loaded_model
                except Exception as exc:
                    raise RuntimeError(
                        f"Embedding model '{self.model_name}' is not found in local cache. "
                        f"Fresh developer environments must run 'python scripts/setup_model.py' "
                        f"or initialize with allow_download=True to download weights before running offline. "
                        f"Underlying error: {exc}"
                    ) from exc
            else:
                loaded_model = SentenceTransformer(
                    self.model_name,
                    local_files_only=False
                )
                EmbeddingGenerator._models[self.model_name] = loaded_model

        self.model = EmbeddingGenerator._models[self.model_name]

    @classmethod
    def download_model(cls, model_name: Optional[str] = None) -> "SentenceTransformer":
        """
        Explicit setup method to download and cache model weights in a fresh environment.
        Requires active network access.
        """
        target_model = model_name or settings.embedding_model_name
        loaded_model = SentenceTransformer(target_model, local_files_only=False)
        cls._models[target_model] = loaded_model
        return loaded_model

    @classmethod
    def get_instance(
        cls,
        model_name: Optional[str] = None,
        allow_download: bool = False
    ) -> "EmbeddingGenerator":
        """Singleton accessor to prevent redundant model loading across pipeline calls."""
        if cls._instance is None or (model_name and cls._instance.model_name != model_name):
            cls._instance = cls(model_name, allow_download=allow_download)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Resets the singleton and model cache for clean test isolation."""
        cls._instance = None
        cls._models.clear()

    @classmethod
    def validate_vector(cls, vector: Any) -> None:
        """
        Verify vector dimension, numeric scalar types, and finite constraints.
        
        Security Note:
        Exception messages identify strictly the technical validation category
        and never include raw document content, chunk text, canary strings,
        or raw vector scalar values.
        """
        if not isinstance(vector, (list, np.ndarray)):
            raise ValueError(
                f"Unsupported vector type: expected list or array, got {type(vector).__name__}"
            )

        if len(vector) != cls.EXPECTED_DIMENSION:
            raise ValueError(
                f"Embedding dimension mismatch: expected {cls.EXPECTED_DIMENSION}, got {len(vector)}"
            )

        for val in vector:
            if isinstance(val, bool) or not isinstance(val, (float, int, np.floating, np.integer)):
                raise ValueError(
                    f"Non-numeric embedding component detected: {type(val).__name__}"
                )
            try:
                fval = float(val)
                if math.isnan(fval) or math.isinf(fval):
                    raise ValueError(
                        "Non-finite embedding component detected (NaN or Inf)"
                    )
            except (OverflowError, ValueError) as err:
                if isinstance(err, ValueError) and "Non-finite" in str(err):
                    raise
                raise ValueError(
                    "Non-finite embedding component detected (overflow or unconvertible numeric value)"
                ) from None

    def _validate_vector(self, vector: List[float]) -> None:
        """Instance delegation to validate_vector."""
        self.validate_vector(vector)

    def embed_text(self, text: str) -> List[float]:
        """Generate embedding vector for a single string."""
        if not text or not text.strip():
            raise ValueError("Cannot embed empty or whitespace-only text")

        vector = self.model.encode(text, convert_to_numpy=True).tolist()
        self._validate_vector(vector)
        return vector

    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """Batch-generate embeddings for a collection of strings."""
        if not texts:
            return []

        for idx, text in enumerate(texts):
            if not text or not text.strip():
                raise ValueError(f"Cannot embed empty or whitespace-only text at index {idx}")

        raw_vectors = self.model.encode(
            texts,
            batch_size=batch_size,
            show_progress_bar=False,
            convert_to_numpy=True
        ).tolist()

        for vec in raw_vectors:
            self._validate_vector(vec)

        return raw_vectors
