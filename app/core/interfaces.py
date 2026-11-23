"""Interface definitions and typing protocols across system boundaries."""
from typing import Protocol, List, Dict, Any, Optional, Tuple
from app.core.schemas import (
    UserContext,
    DocumentMetadata,
    DocumentChunk,
    QueryRequest,
    QueryResponse,
)


class BaseDocumentLoader(Protocol):
    """Protocol for reading and parsing knowledge base documents."""
    def load_documents(self) -> List[Tuple[DocumentMetadata, str]]:
        """Load and validate all documents, returning metadata and body text."""
        ...


class BaseChunker(Protocol):
    """Protocol for partitioning document bodies into chunk sequences."""
    def chunk_document(
        self,
        metadata: DocumentMetadata,
        content: str
    ) -> List[DocumentChunk]:
        """Split document text into chunks preserving metadata."""
        ...


class BaseEmbeddingGenerator(Protocol):
    """Protocol for computing vector embeddings."""
    def embed_text(self, text: str) -> List[float]:
        """Generate embedding vector for a single string."""
        ...

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embedding vectors for a batch of strings."""
        ...


class BaseVectorStore(Protocol):
    """Protocol for vector database indexing and search."""
    def upsert_chunks(
        self,
        chunks: List[DocumentChunk],
        embeddings: List[List[float]]
    ) -> int:
        """Idempotently insert or update chunks with their embeddings."""
        ...

    def query(
        self,
        query_embedding: List[float],
        top_k: int = 4,
        where_filter: Optional[Dict[str, Any]] = None
    ) -> List[DocumentChunk]:
        """Execute vector similarity search with optional metadata filter."""
        ...

    def count(self) -> int:
        """Return total number of stored chunks."""
        ...


class TestContextResolver(Protocol):
    """Protocol for server-side test identity resolution."""
    def resolve(self, test_identity_id: str) -> UserContext:
        """Resolve a test identity key to an authenticated UserContext, or raise AuthenticationError."""
        ...


class BaseRetriever(Protocol):
    """Protocol for executing similarity search with optional authorization filters."""
    def retrieve(
        self,
        query: str,
        top_k: int = 4,
        where_filter: Optional[Dict[str, Any]] = None
    ) -> List[DocumentChunk]:
        """Execute similarity search with optional metadata filtering."""
        ...


class BaseAuthorizer(Protocol):
    """Protocol for RBAC pre-retrieval filtering and post-retrieval verification."""
    def build_retrieval_filter(self, context: UserContext) -> Dict[str, Any]:
        """Construct deterministic ChromaDB where filter based on caller context."""
        ...

    def verify_chunk_access(self, chunk: DocumentChunk, context: UserContext) -> bool:
        """Post-retrieval verification check for a single chunk before context generation."""
        ...


class BaseGenerator(Protocol):
    """Protocol for formatting prompts and invoking generation."""
    def generate(
        self,
        query: str,
        context_chunks: List[DocumentChunk],
        hardened: bool = False
    ) -> str:
        """Format prompt and invoke LLM using configured model ID."""
        ...


class BaseRAGPipeline(Protocol):
    """Protocol for end-to-end RAG pipeline execution."""
    def run(self, request: QueryRequest) -> QueryResponse:
        """Execute full RAG pipeline from query to response."""
        ...

