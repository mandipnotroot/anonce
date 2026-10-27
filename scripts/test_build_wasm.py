# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for WASM artifact and upstream-material admission gates."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from build_wasm import checked_material, check_wasm


class WASMBuildChecks(unittest.TestCase):
    def test_material_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notice"
            data = b"synthetic notice"
            path.write_bytes(data)
            self.assertEqual(checked_material(path, hashlib.sha256(data).hexdigest()), data)
            for digest in ("0" * 64, "", hashlib.sha256(data + b"!").hexdigest()):
                with self.subTest(digest=digest), self.assertRaises(ValueError):
                    checked_material(path, digest)

    def test_artifact_size_and_header(self):
        header = b"\0asm\x01\0\0\0"
        check_wasm(header + b"\0", 9)
        for data, maximum in ((b"", 9), (header, 9), (header + b"\0\0", 9), (b"x" * 9, 9), (b"\0asm\x02\0\0\0!", 9)):
            with self.subTest(data=data, maximum=maximum), self.assertRaises(ValueError):
                check_wasm(data, maximum)


if __name__ == "__main__":
    unittest.main()
