# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Keep source checks independent of pull-request metadata edits."""

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


if __name__ == "__main__":
    unittest.main()
