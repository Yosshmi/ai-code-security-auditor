"""Build a deterministic inventory of files in a local repository."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


DEFAULT_IGNORED_DIRECTORIES = frozenset(
    {".git", ".venv", "__pycache__", "node_modules"}
)


class InventoryError(RuntimeError):
    """Raised when the repository inventory cannot be completed."""


@dataclass(frozen=True)
class FileRecord:
    """Facts collected about one repository file."""

    relative_path: str
    extension: str
    size_bytes: int


@dataclass(frozen=True)
class RepositoryInventory:
    """Files and skipped paths discovered during repository traversal."""

    files: tuple[FileRecord, ...]
    skipped_directories: tuple[str, ...]
    skipped_symbolic_links: tuple[str, ...]

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def total_size_bytes(self) -> int:
        return sum(file.size_bytes for file in self.files)

    @property
    def extension_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for file in self.files:
            counts[file.extension] = counts.get(file.extension, 0) + 1
        return counts


def collect_repository_inventory(
    repository_path: Path,
    ignored_directories: frozenset[str] = DEFAULT_IGNORED_DIRECTORIES,
) -> RepositoryInventory:
    """Recursively collect file metadata without following symbolic links."""

    root = repository_path.resolve(strict=True)
    files: list[FileRecord] = []
    skipped_directories: list[str] = []
    skipped_symbolic_links: list[str] = []

    def relative_name(path: Path) -> str:
        return path.relative_to(root).as_posix()

    def walk(directory: Path) -> None:
        try:
            entries = sorted(directory.iterdir(), key=lambda entry: entry.name.lower())
        except OSError as error:
            raise InventoryError(f"cannot read directory: {relative_name(directory)}") from error

        for entry in entries:
            try:
                if entry.is_symlink():
                    skipped_symbolic_links.append(relative_name(entry))
                elif entry.is_dir():
                    if entry.name in ignored_directories:
                        skipped_directories.append(relative_name(entry))
                    else:
                        walk(entry)
                elif entry.is_file():
                    extension = entry.suffix.lower() or "[no extension]"
                    files.append(
                        FileRecord(
                            relative_path=relative_name(entry),
                            extension=extension,
                            size_bytes=entry.stat().st_size,
                        )
                    )
            except OSError as error:
                raise InventoryError(
                    f"cannot inspect repository entry: {relative_name(entry)}"
                ) from error

    walk(root)
    return RepositoryInventory(
        files=tuple(files),
        skipped_directories=tuple(skipped_directories),
        skipped_symbolic_links=tuple(skipped_symbolic_links),
    )

