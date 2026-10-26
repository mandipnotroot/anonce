# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise inspection of real disposable Git objects and references."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import policy


class HistoryTests(unittest.TestCase):
    def setUp(self):
        scratch = policy.ROOT / ".cache" / "history-tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copyfile(policy.ROOT / policy.CONFIG, self.root / policy.CONFIG)
        self.environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "HOME": str(self.root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
        self.run_git("init", "-q", "--initial-branch=main")
        self.run_git("config", "user.name", "Example Maintainer")
        self.run_git("config", "user.email", "contributor@example.invalid")
        self.root_patch = patch.object(policy, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.sample = policy.Inspector().config["rules"][0]["samples"][0]

    def run_git(self, *args):
        return subprocess.run(
            ["git", "-c", "commit.gpgsign=false", *args], cwd=self.root,
            env=self.environment, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout

    def commit(self, text="Public material.\n"):
        (self.root / "record.txt").write_text(text)
        self.run_git("add", "record.txt")
        self.run_git("commit", "-qm", "docs: describe public material")

    def test_deleted_historical_content_is_still_detected(self):
        self.commit(self.sample)
        self.run_git("rm", "record.txt")
        self.run_git("commit", "-qm", "docs: remove obsolete material")
        inspector = policy.Inspector()
        inspector.history(["--all"])
        self.assertTrue(any("content" in error for error in inspector.failures))

    def test_reference_names_are_inspected(self):
        self.commit()
        self.run_git("branch", self.sample)
        inspector = policy.Inspector()
        inspector.history(["--all"])
        self.assertTrue(any("reference" in error for error in inspector.failures))

    def test_nested_tag_annotations_are_inspected(self):
        self.commit()
        self.run_git("tag", "-a", "inner", "-m", self.sample)
        self.run_git("tag", "-a", "outer", "inner", "-m", "Release details")
        self.run_git("tag", "-d", "inner")
        inspector = policy.Inspector()
        inspector.history(["--all"])
        self.assertTrue(any("tag object" in error for error in inspector.failures))

    def test_dependency_exception_is_limited_to_identity(self):
        config = policy.Inspector().config["dependency_identity"]
        self.run_git("config", "user.name", config["name"])
        self.run_git("config", "user.email", config["email"])
        self.commit()
        ordinary = policy.Inspector()
        ordinary.history(["--all"])
        self.assertTrue(ordinary.failures)
        permitted = policy.Inspector()
        permitted.history(["--all"], allow_dependency=True)
        self.assertEqual(permitted.failures, [])

    def test_missing_metadata_inspector_fails_closed(self):
        inspector = policy.Inspector()
        with patch.object(policy.shutil, "which", return_value=None):
            inspector.blob("diagram.png", "fixture", b"\x89PNG\r\n\x1a\n")
        self.assertTrue(any("required" in error for error in inspector.failures))


if __name__ == "__main__":
    unittest.main()
