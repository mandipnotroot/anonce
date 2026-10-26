# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise documentation parsing without network requests."""

from pathlib import Path
import tempfile
import unittest

from docs_check import check_local, headings, lint, references
from policy import ROOT


class DocumentationTests(unittest.TestCase):
    def test_fenced_examples_are_not_document_headings(self):
        text = "# Title\n\nAudience: contributors.\n\n```sh\n# comment\n```\n"
        self.assertEqual(lint(Path("docs/example.md"), text), [])

    def test_audience_and_fence_errors(self):
        self.assertIn("missing audience", lint(Path("docs/example.md"), "# Title\n"))
        self.assertIn("unclosed code fence", lint(Path("example.md"), "# Title\n```\n"))

    def test_links_include_definitions_and_skip_code(self):
        text = "[text](guide.md)\n[ref]: other.md\n```\n[x](ignored.md)\n```\n"
        self.assertEqual(references(text), ["guide.md", "other.md"])

    def test_duplicate_heading_anchors(self):
        self.assertEqual(headings("# Title\n## Review\n## Review\n"), {"title", "review", "review-1"})

    def test_missing_targets_anchors_and_path_escape_fail(self):
        scratch = ROOT / ".cache" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            (root / "guide.md").write_text("# Guide\n")
            self.assertIsNone(check_local(Path("index.md"), "guide.md#guide", root))
            self.assertIsNotNone(check_local(Path("index.md"), "guide.md#missing", root))
            self.assertIsNotNone(check_local(Path("index.md"), "missing.md", root))
            self.assertIsNotNone(check_local(Path("index.md"), "../outside.md", root))


if __name__ == "__main__":
    unittest.main()
