# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Check workflow triggers and policy metadata-inspector prerequisites."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WorkflowTriggerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = (ROOT / ".github/workflows/checks.yml").read_text()
        match = re.search(
            r"^  pull_request:\n    types: \[([^\]\n]+)\]$",
            cls.workflow,
            re.MULTILINE,
        )
        if match is None:
            raise AssertionError("checks must declare explicit PR event types")
        cls.pr_events = {event.strip() for event in match[1].split(",")}

    def test_metadata_edits_do_not_trigger_checks(self):
        for event in ("edited", "labeled", "unlabeled"):
            with self.subTest(event=event):
                self.assertNotIn(event, self.pr_events)

    def test_source_and_lifecycle_events_trigger_checks(self):
        for event in ("opened", "synchronize", "reopened", "ready_for_review"):
            with self.subTest(event=event):
                self.assertIn(event, self.pr_events)

    def test_main_pushes_and_manual_runs_remain_enabled(self):
        self.assertRegex(self.workflow, r"(?m)^  push:\n    branches: \[main\]$")
        self.assertRegex(self.workflow, r"(?m)^  workflow_dispatch:$")


class MetadataWorkflowTests(unittest.TestCase):
    def test_metadata_inspector_precedes_policy_checks(self):
        root = Path(__file__).resolve().parents[1]
        for filename, job, command in (
            ("checks.yml", "policy", "python3 scripts/policy.py --index"),
            ("pages.yml", "build", "make docs-setup check docs-build"),
            ("nightly.yml", "repository", "make docs-setup check docs-build docs-external"),
        ):
            with self.subTest(workflow=filename):
                workflow = (root / ".github/workflows" / filename).read_text()
                section = re.search(rf"(?ms)^  {job}:\n(.*?)(?=^  [\w-]+:|\Z)", workflow)
                self.assertIsNotNone(section)
                steps = section[1].split(f"run: {command}", 1)
                self.assertEqual(len(steps), 2, "policy check command must exist")
                self.assertRegex(
                    steps[0],
                    r"sudo apt-get update\n\s+sudo apt-get install --yes --no-install-recommends "
                    r"libimage-exiftool-perl\n\s+exiftool -ver\n",
                    "install and verify ExifTool before inspecting tracked assets",
                )


if __name__ == "__main__":
    unittest.main()
