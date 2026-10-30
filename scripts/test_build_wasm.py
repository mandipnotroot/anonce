# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for WASM artifact and upstream-material admission gates."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import call, patch

from build_wasm import checked_material, check_wasm, member_notices


class WASMBuildChecks(unittest.TestCase):
    def test_ci_node_runtime(self):
        root = Path(__file__).resolve().parents[1]
        config = tomllib.loads((root / "scripts/wasm.toml").read_text())
        for filename, job, command in (
            ("checks.yml", "runtime", "make wasm-test"),
            ("pages.yml", "build", "make docs-setup check docs-build"),
        ):
            with self.subTest(workflow=filename):
                workflow = (root / ".github/workflows" / filename).read_text()
                section = re.search(rf"(?ms)^  {job}:\n(.*?)(?=^  [\w-]+:|\Z)", workflow)
                self.assertIsNotNone(section)
                steps = section[1].split(f"run: {command}", 1)
                self.assertEqual(len(steps), 2, "WASM check command must exist")
                setup = re.search(
                    r"actions/setup-node@[0-9a-f]{40}[^\n]*\n        with:\n          node-version: '([^']+)'",
                    steps[0],
                )
                self.assertIsNotNone(setup, "install pinned Node before WASM checks")
                self.assertEqual(f"v{setup[1]}", config["node_version"])

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

    def test_member_notices(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {}
            for name in ("LICENSE", "PATENTS"):
                data = f"synthetic {name}".encode()
                (root / name).write_bytes(data)
                config[f"{name.lower()}_sha256"] = hashlib.sha256(data).hexdigest()
            info = json.dumps({"Dir": directory}).encode()
            with patch("build_wasm.subprocess.check_output", return_value=info):
                materials = member_notices("go", {}, config)
            self.assertEqual(set(materials), {"LICENSE.x-crypto", "PATENTS.x-crypto", "LICENSE.x-sys", "PATENTS.x-sys"})
            for name in materials:
                self.assertEqual(materials[name], (root / name.split(".")[0]).read_bytes())
            for info in ({}, {"Dir": directory, "Replace": {"Dir": directory}}):
                with self.subTest(info=info), patch("build_wasm.subprocess.check_output", return_value=json.dumps(info).encode()), patch("build_wasm.subprocess.run"), self.assertRaises(ValueError):
                    member_notices("go", {}, config)
            (root / "LICENSE").write_bytes(b"changed")
            with patch("build_wasm.subprocess.check_output", return_value=json.dumps({"Dir": directory}).encode()), self.assertRaises(ValueError):
                member_notices("go", {}, config)

    def test_member_notices_cold_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = {}
            for name in ("LICENSE", "PATENTS"):
                data = f"synthetic {name}".encode()
                (root / name).write_bytes(data)
                config[f"{name.lower()}_sha256"] = hashlib.sha256(data).hexdigest()
            cached = json.dumps({"Dir": directory}).encode()
            uncached = json.dumps({"Version": "v0.0.0"}).encode()
            env = {"GOTOOLCHAIN": "synthetic"}
            with patch("build_wasm.subprocess.check_output", side_effect=[uncached, cached, uncached, cached]), patch("build_wasm.subprocess.run") as download:
                materials = member_notices("go", env, config)
            self.assertEqual(set(materials), {"LICENSE.x-crypto", "PATENTS.x-crypto", "LICENSE.x-sys", "PATENTS.x-sys"})
            self.assertEqual(download.call_args_list, [
                call(["go", "mod", "download", module], cwd=Path(__file__).resolve().parents[1], env=env, check=True)
                for module in ("golang.org/x/crypto", "golang.org/x/sys")
            ])

    def test_member_notice_download_failures(self):
        for info, error in (
            ({"Replace": {"Dir": "synthetic"}}, ValueError),
            ({}, subprocess.CalledProcessError),
        ):
            with self.subTest(info=info), patch("build_wasm.subprocess.check_output", return_value=json.dumps(info).encode()), patch("build_wasm.subprocess.run", side_effect=subprocess.CalledProcessError(1, "go")) as download:
                with self.assertRaises(error):
                    member_notices("go", {}, {})
                if info.get("Replace"):
                    download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
