# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise pinned artifacts, bounded downloads, and safe member extraction."""

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import install_mdbook
from policy import ROOT


class MdbookInstallationTests(unittest.TestCase):
    def test_platform_names(self):
        for system, machine, expected in [
            ("Linux", "x86_64", "linux-x86_64"),
            ("Linux", "AMD64", "linux-x86_64"),
            ("Darwin", "arm64", "darwin-aarch64"),
            ("Linux", "aarch64", "linux-aarch64"),
        ]:
            with self.subTest(system=system, machine=machine):
                self.assertEqual(install_mdbook.platform_key(system, machine), expected)

    def test_download_and_cache_both_require_matching_checksums(self):
        scratch = ROOT / ".cache/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        data = b"synthetic artifact"
        entry = {"url": "https://example.invalid/tool", "sha256": hashlib.sha256(data).hexdigest()}
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            cache = Path(directory)
            response = io.BytesIO(data)
            response.url = entry["url"]
            with patch.object(install_mdbook, "urlopen", return_value=response) as fetch:
                self.assertEqual(install_mdbook.download(entry, cache), data)
                self.assertEqual(install_mdbook.download(entry, cache), data)
                fetch.assert_called_once()
            (cache / entry["sha256"]).write_bytes(b"modified artifact")
            with self.assertRaises(ValueError):
                install_mdbook.download(entry, cache)
            for data, redirected in [(b"oversize artifact", False), (b"small", True)]:
                response = io.BytesIO(data)
                response.url = "http://example.invalid/tool" if redirected else entry["url"]
                (cache / entry["sha256"]).unlink()
                with patch.object(install_mdbook, "urlopen", return_value=response), \
                        patch.object(install_mdbook, "MAX_DOWNLOAD", 8), self.assertRaises(ValueError):
                    install_mdbook.download(entry, cache)
                (cache / entry["sha256"]).write_bytes(b"reset")

    def test_archive_member_rejects_links_and_missing_members(self):
        for kind, valid in [(tarfile.REGTYPE, True), (tarfile.SYMTYPE, False), (tarfile.LNKTYPE, False)]:
            with self.subTest(kind=kind):
                data = io.BytesIO()
                with tarfile.open(fileobj=data, mode="w:gz") as archive:
                    member = tarfile.TarInfo("mdbook")
                    member.type = kind
                    member.linkname = "outside"
                    member.size = 4 if valid else 0
                    archive.addfile(member, io.BytesIO(b"tool") if valid else None)
                if valid:
                    self.assertEqual(install_mdbook.archive_member(data.getvalue(), "mdbook"), b"tool")
                    with self.assertRaises(KeyError):
                        install_mdbook.archive_member(data.getvalue(), "missing")
                    with patch.object(install_mdbook, "MAX_DOWNLOAD", 1), self.assertRaises(ValueError):
                        install_mdbook.archive_member(data.getvalue(), "mdbook")
                else:
                    with self.assertRaises(ValueError):
                        install_mdbook.archive_member(data.getvalue(), "mdbook")

    def test_notices_are_copied_verbatim_and_missing_cache_fails_offline(self):
        scratch = ROOT / ".cache/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        data = b"original upstream license\n"
        digest = hashlib.sha256(data).hexdigest()
        config = {"notices": {"sample": {"url": "https://example.invalid/license", "sha256": digest}}}
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory)
            cache = root / ".cache/mdbook/downloads"
            cache.mkdir(parents=True)
            output = root / "site"
            with patch.object(install_mdbook, "ROOT", root), \
                    patch.object(install_mdbook, "manifest", return_value=config), \
                    patch.object(install_mdbook, "urlopen") as fetch:
                with self.assertRaises(ValueError):
                    install_mdbook.copy_notices(output)
                (cache / digest).write_bytes(data)
                install_mdbook.copy_notices(output)
                self.assertEqual((output / "assets/upstream-licenses/sample.txt").read_bytes(), data)
                fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
