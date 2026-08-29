"""Safely load small UTF-8 repository files for deterministic analysis."""

from __future__ import annotations

from pathlib import Path


MAX_SCANNABLE_FILE_SIZE_BYTES = 1_000_000


def read_repository_text_file(
    repository_root: Path,
    relative_path: str,
    size_bytes: int,
) -> str | None:
    """Return safe UTF-8 text, or ``None`` when a file should not be scanned."""

    if size_bytes > MAX_SCANNABLE_FILE_SIZE_BYTES:
        return None

    root = repository_root.resolve(strict=True)
    file_path = root / relative_path

    if file_path.is_symlink():
        return None

    try:
        resolved_file = file_path.resolve(strict=True)
    except OSError:
        return None

    if not resolved_file.is_relative_to(root) or not resolved_file.is_file():
        return None

    try:
        content = resolved_file.read_bytes()
    except OSError:
        return None

    if b"\x00" in content:
        return None

    try:
        return content.decode("utf-8")
    except UnicodeDecodeError:
        return None

