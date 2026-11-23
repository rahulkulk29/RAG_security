"""Document chunking engine with deterministic chunk IDs and metadata inheritance."""
from typing import List, Optional
import re

from app.core.config import settings
from app.core.schemas import DocumentMetadata, DocumentChunk


class TextChunker:
    """Partitions document body text into overlapping chunks while preserving metadata."""

    def __init__(
        self,
        chunk_size_chars: Optional[int] = None,
        chunk_overlap_chars: Optional[int] = None,
    ):
        """
        Initialize chunker.
        
        Chunk size defaults:
        - chunk_size_chars: 2000 (approx. 500 tokens at ~4 chars/token)
        - chunk_overlap_chars: 300 (approx. 75 tokens at ~4 chars/token)
        """
        self.chunk_size = chunk_size_chars if chunk_size_chars is not None else settings.chunk_size_chars
        self.chunk_overlap = chunk_overlap_chars if chunk_overlap_chars is not None else settings.chunk_overlap_chars

        if self.chunk_size <= 0:
            raise ValueError(f"chunk_size must be positive, got {self.chunk_size}")
        if self.chunk_overlap < 0:
            raise ValueError(f"chunk_overlap must be non-negative, got {self.chunk_overlap}")
        if self.chunk_overlap >= self.chunk_size:
            raise ValueError(
                f"chunk_overlap ({self.chunk_overlap}) must be strictly less than chunk_size ({self.chunk_size})"
            )

    def _split_text(self, text: str) -> List[str]:
        """Split text into chunks using logical break boundaries."""
        cleaned_text = text.strip()
        if not cleaned_text:
            return []

        if len(cleaned_text) <= self.chunk_size:
            return [cleaned_text]

        chunks: List[str] = []
        start = 0
        text_len = len(cleaned_text)

        while start < text_len:
            end = start + self.chunk_size

            if end >= text_len:
                chunk = cleaned_text[start:].strip()
                if chunk:
                    chunks.append(chunk)
                break

            # Find a natural breakpoint near the end of the window
            break_point = -1
            # Search candidate boundaries in descending priority
            for sep in ["\n\n", "\n", ". ", "? ", "! ", " "]:
                pos = cleaned_text.rfind(sep, start + self.chunk_overlap, end)
                if pos != -1:
                    break_point = pos + len(sep)
                    break

            # If no boundary found, hard slice at end
            if break_point == -1 or break_point <= start:
                break_point = end

            chunk = cleaned_text[start:break_point].strip()
            if chunk:
                chunks.append(chunk)

            # Advance start with overlap
            new_start = break_point - self.chunk_overlap
            if new_start <= start:
                new_start = break_point
            start = new_start

        return chunks

    def chunk_document(
        self,
        metadata: DocumentMetadata,
        content: str
    ) -> List[DocumentChunk]:
        """
        Partitions the document body into DocumentChunk objects.
        
        Assigns deterministic IDs: '{doc_id}_c{chunk_index:02d}'.
        Inherits all metadata from parent document.
        """
        raw_chunks = self._split_text(content)
        if not raw_chunks:
            return []

        document_chunks: List[DocumentChunk] = []
        for idx, chunk_text in enumerate(raw_chunks):
            chunk_id = f"{metadata.doc_id}_c{idx:02d}"
            document_chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    doc_id=metadata.doc_id,
                    tenant_id=metadata.tenant_id,
                    access_level=metadata.access_level,
                    title=metadata.title,
                    content=chunk_text,
                    chunk_index=idx,
                    category=metadata.category,
                    is_poisoned=metadata.is_poisoned,
                    has_secret=metadata.has_secret,
                    canary_refs=list(metadata.canary_refs),
                )
            )

        return document_chunks

    def chunk_all(
        self,
        documents: List[tuple[DocumentMetadata, str]]
    ) -> List[DocumentChunk]:
        """Process a list of (metadata, content) tuples into a flat list of DocumentChunks."""
        all_chunks: List[DocumentChunk] = []
        for meta, body in documents:
            doc_chunks = self.chunk_document(meta, body)
            all_chunks.extend(doc_chunks)
        return all_chunks
