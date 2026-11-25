"""
Release archive packaging and strict hygiene verification utilities.
"""
import os
import zipfile
from pathlib import Path
from typing import Dict, List

FORBIDDEN_DIR_NAMES = ("__pycache__", ".pytest_cache", ".git", "secrets", "chroma_db", "chromadb")
FORBIDDEN_SUFFIXES = (".pyc", ".pyo", ".log")


def is_forbidden_archive_entry(entry_path: str) -> bool:
    """Return True if an archive entry violates release hygiene rules."""
    normalized = entry_path.replace("\\", "/")
    parts = [p for p in Path(normalized).parts if p not in ("", ".")]
    name = Path(normalized).name

    for forbidden_dir in FORBIDDEN_DIR_NAMES:
        if forbidden_dir in parts:
            return True

    if any(name.endswith(sfx) for sfx in FORBIDDEN_SUFFIXES):
        return True

    if name.startswith(".env") or name == "canaries.json" or name == "chroma.sqlite3":
        return True

    if "chroma_db" in normalized.lower() or "chromadb" in normalized.lower():
        return True

    if "secrets/" in normalized.lower():
        return True

    return False


def verify_archive_clean(zip_path: Path) -> List[str]:
    """
    Inspect every entry in a ZIP archive and raise AssertionError if empty
    or if any forbidden entry is present. Returns the verified entry list.
    """
    with zipfile.ZipFile(zip_path, "r") as zf:
        entries = zf.namelist()
        assert len(entries) > 0, f"Archive {zip_path} is empty"
        forbidden_hits = [
            e for e in entries if is_forbidden_archive_entry(e) or e.endswith("/")
        ]
        assert not forbidden_hits, (
            f"Archive {zip_path} contains forbidden entries: {forbidden_hits}"
        )
        return entries


def build_clean_archive(src_dir: Path, zip_path: Path) -> List[str]:
    """Build a clean ZIP archive from src_dir and verify every entry."""
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(src_dir):
            dirs[:] = [d for d in dirs if d not in FORBIDDEN_DIR_NAMES]
            for fname in sorted(files):
                full_path = Path(root) / fname
                rel_path = full_path.as_posix()
                if not is_forbidden_archive_entry(rel_path):
                    zf.write(full_path, rel_path)

    return verify_archive_clean(zip_path)


def package_release_archives(
    archive_map: Dict[str, str] | None = None,
) -> Dict[str, Dict[str, int]]:
    """Build and verify all release archives, returning size and entry count metadata."""
    targets = archive_map or {
        "app.zip": "app",
        "tests.zip": "tests",
        "evaluation.zip": "evaluation",
        "data.zip": "data",
    }
    results: Dict[str, Dict[str, int]] = {}
    for zip_name, src_dir in targets.items():
        zp = Path(zip_name)
        entries = build_clean_archive(Path(src_dir), zp)
        results[zip_name] = {
            "size_bytes": zp.stat().st_size,
            "entry_count": len(entries),
        }
    return results

