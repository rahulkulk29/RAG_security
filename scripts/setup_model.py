"""One-time developer setup script: downloads and verifies the SentenceTransformer model."""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.ingestion.embeddings import EmbeddingGenerator


def main():
    print(f"Downloading and caching embedding model: '{settings.embedding_model_name}'...")
    try:
        model = EmbeddingGenerator.download_model(settings.embedding_model_name)
        test_emb = model.encode("Security benchmark verification query")
        print(f"Model successfully downloaded and verified. Dimension: {len(test_emb)}")
    except Exception as e:
        print(f"ERROR: Failed to download embedding model: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

