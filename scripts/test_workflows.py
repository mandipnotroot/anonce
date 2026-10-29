# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Check that every policy-running workflow installs its metadata inspector."""

from pathlib import Path
import re
import unittest


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
