"""Database seeding script: ingests, chunks, embeds, and indexes synthetic corpus into ChromaDB."""
import argparse
import sys
import time
from pathlib import Path
from collections import Counter

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.config import settings
from app.ingestion.loader import DocumentLoader
from app.ingestion.chunker import TextChunker
from app.ingestion.embeddings import EmbeddingGenerator
from app.ingestion.indexer import ChromaIndexer


def seed_database(reset: bool = False, verbose: bool = True) -> int:
    """
    Executes end-to-end ingestion pipeline:
    1. Loads all 24 documents and cross-validates against manifest.
    2. Chunks documents with metadata inheritance.
    3. Generates 384-dimensional embeddings via Sentence Transformers.
    4. Idempotently indexes chunks into ChromaDB.
    """
    start_time = time.time()
    print("=" * 65)
    print("  RAG Security Testbed: Document Ingestion & Database Seeding")
    print("=" * 65)

    # 1. Initialize components
    print("\n[1/4] Initializing Ingestion Components...")
    loader = DocumentLoader()
    chunker = TextChunker()
    embedder = EmbeddingGenerator.get_instance()
    indexer = ChromaIndexer()

    if reset:
        print("  (!) Reset flag specified: Clearing existing ChromaDB collection...")
        indexer.reset()

    # 2. Load documents
    print("\n[2/4] Loading and Validating Knowledge Base Documents...")
    documents = loader.load_all_documents()
    print(f"  --> Successfully loaded {len(documents)} validated documents from corpus.")

    tenant_doc_counts = Counter(doc[0].tenant_id.value for doc in documents)
    level_doc_counts = Counter(doc[0].access_level.value for doc in documents)
    print(f"      Tenants: {dict(tenant_doc_counts)}")
    print(f"      Access Levels: {dict(level_doc_counts)}")

    # 3. Chunk documents
    print("\n[3/4] Chunking Document Bodies...")
    chunks = chunker.chunk_all(documents)
    print(f"  --> Generated {len(chunks)} total chunks across {len(documents)} documents.")
    if verbose:
        for c in chunks[:4]:
            print(f"      Chunk '{c.chunk_id}': {len(c.content)} chars | tenant={c.tenant_id.value} | level={c.access_level.value}")
        if len(chunks) > 4:
            print(f"      ... and {len(chunks) - 4} more chunks.")

    # 4. Generate embeddings and index
    print("\n[4/4] Generating Embeddings and Indexing into ChromaDB...")
    texts = [c.content for c in chunks]
    emb_start = time.time()
    embeddings = embedder.embed_batch(texts)
    emb_time = time.time() - emb_start
    print(f"  --> Generated {len(embeddings)} embeddings ({EmbeddingGenerator.EXPECTED_DIMENSION}-dim) in {emb_time:.2f}s.")

    index_start = time.time()
    upserted_count = indexer.upsert_chunks(chunks, embeddings, sync_stale=True)
    index_time = time.time() - index_start
    final_count = indexer.count()
    print(f"  --> Upserted {upserted_count} chunks in {index_time:.2f}s.")
    print(f"  --> Total ChromaDB Collection Count: {final_count} chunks.")

    elapsed = time.time() - start_time
    print("\n" + "=" * 65)
    print(f"  Seeding Complete in {elapsed:.2f}s | Collection: '{indexer.collection_name}'")
    print("=" * 65 + "\n")
    return final_count


def main():
    parser = argparse.ArgumentParser(description="Seed ChromaDB with synthetic corpus.")
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset existing collection before seeding"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress detailed chunk logging"
    )
    args = parser.parse_args()

    try:
        seed_database(reset=args.reset, verbose=not args.quiet)
    except Exception as e:
        print(f"\n[FATAL ERROR] Ingestion failed: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

