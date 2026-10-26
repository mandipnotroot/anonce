# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the policy configuration and commit grammar."""

import unittest

from commit_lint import validate
from policy import Inspector


class PolicyTests(unittest.TestCase):
    def test_every_configured_example_is_detected(self):
        inspector = Inspector()
        for item in inspector.config["rules"]:
            for index, sample in enumerate(item["samples"]):
                with self.subTest(rule=item["id"], example=index):
                    before = len(inspector.failures)
                    inspector.text("fixture", sample)
                    self.assertGreater(len(inspector.failures), before)

    def test_neutral_contributor_language_is_permitted(self):
        inspector = Inspector()
        inspector.text("fixture", "Contributors and automated tooling must credit people. Now / Next / Later.")
        self.assertEqual(inspector.failures, [])

    def test_ordinary_reproducibility_headers_are_narrowly_permitted(self):
        inspector = Inspector()
        for header in inspector.config["ordinary_headers"]:
            inspector.text("fixture", header["sample"])
        self.assertEqual(inspector.failures, [])

    def test_permitted_header_does_not_hide_other_lines(self):
        inspector = Inspector()
        sample = inspector.config["rules"][0]["samples"][0]
        header = inspector.config["ordinary_headers"][0]["sample"]
        inspector.text("fixture", header + "\n" + sample)
        self.assertTrue(inspector.failures)

    def test_scopes_and_breaking_markers(self):
        self.assertIsNone(validate("feat(ca)!: add certificate profile\n\nBREAKING CHANGE: replace profile"))
        self.assertIsNone(validate("docs: clarify enrollment"))
        self.assertIsNotNone(validate("docs(unknown): clarify enrollment"))
        self.assertIsNotNone(validate("Docs: Clarify enrollment."))

    def test_commit_descriptions_reject_surrounding_whitespace(self):
        for message in (
            "docs(repo):  clarify checks",
            "docs(repo): \tclarify checks",
            "docs(repo): clarify checks ",
            "docs(repo): clarify checks\t",
            "docs(repo):  ",
        ):
            with self.subTest(message=message):
                self.assertIsNotNone(validate(message))
        self.assertIsNone(validate("docs(repo): clarify checks"))


if __name__ == "__main__":
    unittest.main()
