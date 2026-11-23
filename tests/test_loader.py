"""Tests for DocumentLoader: parsing, frontmatter extraction, and manifest validation."""
import pytest
from pathlib import Path
from collections import Counter

from app.core.config import settings
from app.core.types import TenantId, AccessLevel
from app.ingestion.loader import DocumentLoader


def test_load_all_24_documents():
    """Verify that all 24 documents from the corpus are successfully loaded."""
    loader = DocumentLoader()
    documents = loader.load_all_documents()

    assert len(documents) == 24
    # Verify deterministic sorting by doc_id
    doc_ids = [doc[0].doc_id for doc in documents]
    assert doc_ids == sorted(doc_ids)


def test_tenant_and_access_level_distribution():
    """Verify exact tenant and access level counts matching approved architecture."""
    loader = DocumentLoader()
    documents = loader.load_all_documents()

    tenant_counts = Counter(doc[0].tenant_id.value for doc in documents)
    assert tenant_counts["tenant_a"] == 8
    assert tenant_counts["tenant_b"] == 8
    assert tenant_counts["tenant_c"] == 8

    # Verify distribution per tenant
    for tenant in ["tenant_a", "tenant_b", "tenant_c"]:
        tenant_docs = [doc[0] for doc in documents if doc[0].tenant_id.value == tenant]
        level_counts = Counter(doc.access_level.value for doc in tenant_docs)
        assert level_counts["public"] == 3
        assert level_counts["member"] == 3
        assert level_counts["admin"] == 2


def test_manifest_consistency():
    """Verify metadata parity between frontmatter and manifest."""
    loader = DocumentLoader()
    manifest_map = loader.load_manifest()
    documents = loader.load_all_documents()

    assert len(manifest_map) == 24
    for meta, body in documents:
        assert meta.doc_id in manifest_map
        manifest_entry = manifest_map[meta.doc_id]
        assert meta.tenant_id == manifest_entry.tenant_id
        assert meta.access_level == manifest_entry.access_level
        assert meta.title == manifest_entry.title
        assert meta.category == manifest_entry.category
        assert meta.is_poisoned == manifest_entry.is_poisoned
        assert meta.has_secret == manifest_entry.has_secret
        assert meta.canary_refs == manifest_entry.canary_refs
        assert len(body) > 0


def test_canary_refs_population():
    """Verify canary_refs are correctly attached to documents with secrets."""
    loader = DocumentLoader()
    documents = loader.load_all_documents()

    secret_docs = [doc[0] for doc in documents if doc[0].has_secret]
    assert len(secret_docs) > 0
    for doc in secret_docs:
        assert len(doc.canary_refs) > 0

    non_secret_docs = [doc[0] for doc in documents if not doc[0].has_secret]
    for doc in non_secret_docs:
        assert len(doc.canary_refs) == 0


def test_reject_missing_frontmatter(tmp_path: Path):
    """Verify rejection of files without frontmatter delimiter."""
    bad_file = tmp_path / "bad_doc.md"
    bad_file.write_text("# Just Markdown without frontmatter", encoding="utf-8")

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="Missing leading frontmatter delimiter"):
        loader.parse_markdown_file(bad_file)


def test_reject_unclosed_frontmatter(tmp_path: Path):
    """Verify rejection of unclosed frontmatter."""
    bad_file = tmp_path / "unclosed.md"
    bad_file.write_text("---\ndoc_id: doc_ta_public_01\n# No closing dashes", encoding="utf-8")

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="Frontmatter not properly closed"):
        loader.parse_markdown_file(bad_file)


def test_reject_missing_required_field(tmp_path: Path):
    """Verify rejection when frontmatter misses required fields."""
    bad_file = tmp_path / "missing_fields.md"
    bad_file.write_text(
        "---\n"
        "doc_id: doc_ta_public_01\n"
        "# missing tenant_id, access_level, title, category\n"
        "---\n"
        "Body content",
        encoding="utf-8"
    )

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="Missing required field"):
        loader.parse_markdown_file(bad_file)


def test_reject_unmanifested_document(tmp_path: Path):
    """Verify rejection of document ID not listed in manifest."""
    unmanifested_file = tmp_path / "ghost_doc.md"
    unmanifested_file.write_text(
        "---\n"
        "doc_id: doc_unmanifested_999\n"
        "tenant_id: tenant_a\n"
        "access_level: public\n"
        "title: Ghost Title\n"
        "category: test\n"
        "---\n"
        "Body content",
        encoding="utf-8"
    )

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="not registered in corpus manifest"):
        loader.parse_markdown_file(unmanifested_file)


def test_reject_access_level_mismatch(tmp_path: Path):
    """Verify rejection when frontmatter access_level conflicts with manifest."""
    conflicting_file = tmp_path / "doc_ta_public_01.md"
    # doc_ta_public_01 in manifest has access_level: public, here we spoof admin
    conflicting_file.write_text(
        "---\n"
        "doc_id: doc_ta_public_01\n"
        "tenant_id: tenant_a\n"
        "access_level: admin\n"
        "title: ApexPay Platform Overview & Developer Guide\n"
        "category: product\n"
        "---\n"
        "Body content",
        encoding="utf-8"
    )

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="Access level mismatch"):
        loader.parse_markdown_file(conflicting_file)


def test_reject_title_mismatch(tmp_path: Path):
    """Verify rejection when frontmatter title conflicts with manifest."""
    conflicting_file = tmp_path / "doc_ta_public_01.md"
    conflicting_file.write_text(
        "---\n"
        "doc_id: doc_ta_public_01\n"
        "tenant_id: tenant_a\n"
        "access_level: public\n"
        "title: Spoofed Untrusted Title\n"
        "category: product\n"
        "---\n"
        "Body content",
        encoding="utf-8"
    )

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="Title mismatch"):
        loader.parse_markdown_file(conflicting_file)


def test_reject_category_mismatch(tmp_path: Path):
    """Verify rejection when frontmatter category conflicts with manifest."""
    conflicting_file = tmp_path / "doc_ta_public_01.md"
    conflicting_file.write_text(
        "---\n"
        "doc_id: doc_ta_public_01\n"
        "tenant_id: tenant_a\n"
        "access_level: public\n"
        "title: ApexPay Platform Overview & Developer Guide\n"
        "category: unverified_category\n"
        "---\n"
        "Body content",
        encoding="utf-8"
    )

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="Category mismatch"):
        loader.parse_markdown_file(conflicting_file)


def test_reject_relative_path_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Verify rejection when file placed in data_dir does not match manifest relative_path."""
    # Place doc_ta_public_01 inside data/corpus/tenant_b instead of tenant_a
    mock_data_dir = tmp_path / "data"
    wrong_location = mock_data_dir / "corpus" / "tenant_b" / "doc_ta_public_01.md"
    wrong_location.parent.mkdir(parents=True, exist_ok=True)
    wrong_location.write_text(
        "---\n"
        "doc_id: doc_ta_public_01\n"
        "tenant_id: tenant_a\n"
        "access_level: public\n"
        "title: ApexPay Platform Overview & Developer Guide\n"
        "category: product\n"
        "---\n"
        "Body content",
        encoding="utf-8"
    )

    import app.ingestion.loader as loader_module
    monkeypatch.setattr(loader_module.settings, "data_dir", mock_data_dir)

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="Relative path mismatch"):
        loader.parse_markdown_file(wrong_location)


def test_reject_filename_mismatch(tmp_path: Path):
    """Verify rejection when filename outside data_dir does not match manifest doc_id."""
    mismatched_filename = tmp_path / "wrong_name.md"
    mismatched_filename.write_text(
        "---\n"
        "doc_id: doc_ta_public_01\n"
        "tenant_id: tenant_a\n"
        "access_level: public\n"
        "title: ApexPay Platform Overview & Developer Guide\n"
        "category: product\n"
        "---\n"
        "Body content",
        encoding="utf-8"
    )

    loader = DocumentLoader()
    with pytest.raises(ValueError, match="Filename mismatch"):
        loader.parse_markdown_file(mismatched_filename)
