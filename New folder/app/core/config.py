"""Application configuration and environment settings."""
from pathlib import Path
from typing import Optional, Literal, Any
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for RAG security testbed."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Base paths
    project_root: Path = Path(__file__).resolve().parent.parent.parent
    data_dir: Path = project_root / "data"
    corpus_dir: Path = data_dir / "corpus"
    manifest_path: Path = data_dir / "corpus_manifest.json"
    canaries_path: Path = data_dir / "secrets" / "canaries.json"
    chroma_db_dir: Path = data_dir / "chromadb"

    # Ingestion & ChromaDB
    chroma_collection_name: str = "rag_knowledge_base"
    embedding_model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    
    # Chunking configuration
    # By default, approximately 500 words/tokens with ~75 tokens overlap.
    # When using character-based token approximation (1 token ≈ 4 characters):
    # 500 tokens ≈ 2000 chars, 75 tokens ≈ 300 chars.
    chunk_size_chars: int = 2000
    chunk_overlap_chars: int = 300

    # Environment & API Security
    environment: Literal["development", "test", "production"] = "development"
    cors_allowed_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8000",
    ]
    cors_allowed_methods: list[str] = ["GET", "POST", "OPTIONS"]
    cors_allowed_headers: list[str] = ["Content-Type", "Authorization"]

    # Retrieval & context configuration
    max_query_length: int = 2000
    default_top_k: int = 4
    max_top_k: int = 10
    max_context_chars: int = 50000

    # Output validation
    max_answer_length: int = 50000

    @classmethod
    def _settings_build_values(
        cls,
        sources: tuple[Any, ...],
        init_kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        values = super()._settings_build_values(sources, init_kwargs)
        # Environment variables and .env configuration supply string values.
        # Coerce valid numeric integer strings for max_top_k, max_context_chars, and max_query_length
        # only when not explicitly passed via direct Python constructor arguments (init_kwargs).
        for key in ("max_top_k", "max_context_chars", "max_query_length", "max_answer_length"):
            if key not in init_kwargs and key in values:
                val = values[key]
                if isinstance(val, str):
                    try:
                        values[key] = int(val)
                    except ValueError:
                        # Retain raw value so field_validator raises ValidationError
                        pass
        return values

    @field_validator("max_query_length", mode="before")
    @classmethod
    def validate_max_query_length(cls, v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(
                f"max_query_length must be a positive integer, got {type(v).__name__}"
            )
        if v <= 0:
            raise ValueError(f"max_query_length must be greater than zero, got {v}")
        return v

    @field_validator("max_top_k", mode="before")
    @classmethod
    def validate_max_top_k(cls, v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(
                f"max_top_k must be a positive integer, got {type(v).__name__}"
            )
        if v <= 0:
            raise ValueError(f"max_top_k must be greater than zero, got {v}")
        return v

    @field_validator("max_context_chars", mode="before")
    @classmethod
    def validate_max_context_chars(cls, v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(
                f"max_context_chars must be a positive integer, got {type(v).__name__}"
            )
        if v <= 0:
            raise ValueError(f"max_context_chars must be greater than zero, got {v}")
        return v

    @field_validator("max_answer_length", mode="before")
    @classmethod
    def validate_max_answer_length(cls, v: Any) -> int:
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(
                f"max_answer_length must be a positive integer, got {type(v).__name__}"
            )
        if v <= 0:
            raise ValueError(f"max_answer_length must be greater than zero, got {v}")
        return v

    # Gemini & Generation configuration
    # Unset by default; model will be configured and verified during Milestone 5
    gemini_model_id: Optional[str] = None
    gemini_api_key: Optional[str] = None
    gemini_request_timeout: float = 30.0
    gemini_temperature: float = 0.0


settings = Settings()

