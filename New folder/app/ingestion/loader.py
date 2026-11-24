"""Document loading, YAML frontmatter parsing, and manifest cross-validation."""
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
import json
import yaml

from app.core.config import settings
from app.core.types import TenantId, AccessLevel
from app.core.schemas import DocumentMetadata, CorpusManifestEntry


class DocumentLoader:
    """Loads and validates markdown documents against the corpus manifest."""

    def __init__(
        self,
        corpus_dir: Optional[Path] = None,
        manifest_path: Optional[Path] = None,
    ):
        self.corpus_dir = corpus_dir or settings.corpus_dir
        self.manifest_path = manifest_path or settings.manifest_path
        self._manifest_map: Dict[str, CorpusManifestEntry] = {}

    def load_manifest(self) -> Dict[str, CorpusManifestEntry]:
        """Load and parse the corpus manifest."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Corpus manifest not found at {self.manifest_path}")

        with open(self.manifest_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        manifest_map: Dict[str, CorpusManifestEntry] = {}
        for item in data:
            entry = CorpusManifestEntry(**item)
            if entry.doc_id in manifest_map:
                raise ValueError(f"Duplicate document ID in manifest: {entry.doc_id}")
            manifest_map[entry.doc_id] = entry

        self._manifest_map = manifest_map
        return manifest_map

    def parse_markdown_file(self, file_path: Path) -> Tuple[DocumentMetadata, str]:
        """Parse a markdown file into DocumentMetadata and document body text."""
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        content = file_path.read_text(encoding="utf-8")
        if not content.startswith("---"):
            raise ValueError(f"Malformed document {file_path}: Missing leading frontmatter delimiter ('---')")

        parts = content.split("---", 2)
        if len(parts) < 3:
            raise ValueError(f"Malformed document {file_path}: Frontmatter not properly closed with '---'")

        frontmatter_str = parts[1]
        body_str = parts[2].strip()

        try:
            fm_data = yaml.safe_load(frontmatter_str)
        except Exception as e:
            raise ValueError(f"YAML parsing error in {file_path}: {e}") from e

        if not isinstance(fm_data, dict):
            raise ValueError(f"Invalid frontmatter structure in {file_path}: Expected mapping")

        # Required fields in frontmatter
        required_fields = ["doc_id", "tenant_id", "access_level", "title", "category"]
        for field in required_fields:
            if field not in fm_data:
                raise ValueError(f"Missing required field '{field}' in {file_path}")

        doc_id = fm_data["doc_id"]

        # Cross-validate against manifest
        if not self._manifest_map:
            self.load_manifest()

        if doc_id not in self._manifest_map:
            raise ValueError(
                f"Document ID '{doc_id}' in {file_path} is not registered in corpus manifest"
            )

        manifest_entry = self._manifest_map[doc_id]

        # Verify metadata consistency
        if fm_data["tenant_id"] != manifest_entry.tenant_id.value:
            raise ValueError(
                f"Tenant ID mismatch for '{doc_id}': frontmatter '{fm_data['tenant_id']}' != manifest '{manifest_entry.tenant_id.value}'"
            )

        if fm_data["access_level"] != manifest_entry.access_level.value:
            raise ValueError(
                f"Access level mismatch for '{doc_id}': frontmatter '{fm_data['access_level']}' != manifest '{manifest_entry.access_level.value}'"
            )

        if fm_data["title"] != manifest_entry.title:
            raise ValueError(
                f"Title mismatch for '{doc_id}': frontmatter '{fm_data['title']}' != manifest '{manifest_entry.title}'"
            )

        if fm_data["category"] != manifest_entry.category:
            raise ValueError(
                f"Category mismatch for '{doc_id}': frontmatter '{fm_data['category']}' != manifest '{manifest_entry.category}'"
            )

        if fm_data.get("is_poisoned", False) != manifest_entry.is_poisoned:
            raise ValueError(
                f"is_poisoned mismatch for '{doc_id}': frontmatter '{fm_data.get('is_poisoned')}' != manifest '{manifest_entry.is_poisoned}'"
            )

        if fm_data.get("has_secret", False) != manifest_entry.has_secret:
            raise ValueError(
                f"has_secret mismatch for '{doc_id}': frontmatter '{fm_data.get('has_secret')}' != manifest '{manifest_entry.has_secret}'"
            )

        # Validate relative path if located within project data directory
        try:
            data_dir_resolved = settings.data_dir.resolve()
            file_resolved = file_path.resolve()
            actual_rel = file_resolved.relative_to(data_dir_resolved).as_posix()
            expected_rel = manifest_entry.relative_path.replace("\\", "/")
            if actual_rel != expected_rel:
                raise ValueError(
                    f"Relative path mismatch for '{doc_id}': actual '{actual_rel}' != manifest '{expected_rel}'"
                )
        except ValueError as rel_err:
            err_lower = str(rel_err).lower()
            if "not in the subpath" in err_lower or "not relative" in err_lower or "does not start with" in err_lower:
                # External or temporary directory in testing: ensure filename matches
                expected_filename = Path(manifest_entry.relative_path).name
                if file_path.name != expected_filename:
                    raise ValueError(
                        f"Filename mismatch for '{doc_id}': actual '{file_path.name}' != manifest expected '{expected_filename}'"
                    )
            else:
                raise

        metadata = DocumentMetadata(
            doc_id=doc_id,
            tenant_id=TenantId(fm_data["tenant_id"]),
            access_level=AccessLevel(fm_data["access_level"]),
            title=str(fm_data["title"]),
            category=str(fm_data["category"]),
            has_secret=bool(fm_data.get("has_secret", False)),
            canary_token=fm_data.get("canary_token"),
            is_poisoned=bool(fm_data.get("is_poisoned", False)),
            canary_refs=list(manifest_entry.canary_refs),
        )

        return metadata, body_str

    def load_all_documents(self) -> List[Tuple[DocumentMetadata, str]]:
        """Load all markdown documents from the corpus directory."""
        self.load_manifest()

        if not self.corpus_dir.exists():
            raise FileNotFoundError(f"Corpus directory not found at {self.corpus_dir}")

        md_files = list(self.corpus_dir.glob("**/*.md"))
        if not md_files:
            raise ValueError(f"No markdown documents found in {self.corpus_dir}")

        documents: List[Tuple[DocumentMetadata, str]] = []
        seen_doc_ids = set()

        for file_path in md_files:
            meta, body = self.parse_markdown_file(file_path)
            if meta.doc_id in seen_doc_ids:
                raise ValueError(f"Duplicate document ID discovered across corpus files: {meta.doc_id}")
            seen_doc_ids.add(meta.doc_id)
            documents.append((meta, body))

        # Check that all manifest documents were found and loaded
        manifest_doc_ids = set(self._manifest_map.keys())
        missing_docs = manifest_doc_ids - seen_doc_ids
        if missing_docs:
            raise ValueError(f"Missing corpus documents declared in manifest: {missing_docs}")

        extra_docs = seen_doc_ids - manifest_doc_ids
        if extra_docs:
            raise ValueError(f"Corpus contains unmanifested documents: {extra_docs}")

        # Sort deterministically by doc_id
        documents.sort(key=lambda item: item[0].doc_id)
        return documents
