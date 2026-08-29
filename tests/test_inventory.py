from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security_auditor.inventory import collect_repository_inventory


class CollectRepositoryInventoryTests(unittest.TestCase):
    def test_collects_nested_files_extensions_and_sizes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_bytes(b"a" * 100)
            (root / "app.py").write_bytes(b"b" * 200)
            (root / "src").mkdir()
            (root / "src" / "helper.PY").write_bytes(b"c" * 50)

            inventory = collect_repository_inventory(root)

        self.assertEqual(inventory.total_files, 3)
        self.assertEqual(inventory.total_size_bytes, 350)
        self.assertEqual(inventory.extension_counts, {".md": 1, ".py": 2})
        self.assertEqual(
            [file.relative_path for file in inventory.files],
            ["app.py", "README.md", "src/helper.PY"],
        )

    def test_skips_ignored_directories_but_scans_dot_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            (root / ".git" / "config").write_bytes(b"ignored")
            (root / ".github").mkdir()
            (root / ".github" / "workflow.yml").write_bytes(b"included")

            inventory = collect_repository_inventory(root)

        self.assertEqual(inventory.total_files, 1)
        self.assertEqual(inventory.files[0].relative_path, ".github/workflow.yml")
        self.assertEqual(inventory.skipped_directories, (".git",))

    def test_records_files_without_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "LICENSE").write_bytes(b"license")

            inventory = collect_repository_inventory(root)

        self.assertEqual(inventory.extension_counts, {"[no extension]": 1})

    def test_skips_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            link = root / "outside-link.txt"
            link.write_bytes(b"private")

            with mock.patch.object(
                Path,
                "is_symlink",
                autospec=True,
                side_effect=lambda path: path.name == "outside-link.txt",
            ):
                inventory = collect_repository_inventory(root)

        self.assertEqual(inventory.total_files, 0)
        self.assertEqual(inventory.skipped_symbolic_links, ("outside-link.txt",))


if __name__ == "__main__":
    unittest.main()
