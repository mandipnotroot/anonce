# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Ensure changelog comparisons inspect the correct content."""

import unittest

from check_pr import unreleased


class ChangelogTests(unittest.TestCase):
    def test_release_section_is_not_part_of_unreleased(self):
        text = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n- Useful change.\n\n## [0.1.0] - 2026-10-26\n\n### Fixed\n\n- Old change.\n"
        self.assertEqual(unreleased(text), "### Added\n\n- Useful change.")

    def test_comparison_links_do_not_count_as_an_entry_change(self):
        text = "## [Unreleased]\n\n### Added\n\n- Useful change.\n\n[Unreleased]: https://example.invalid\n"
        self.assertEqual(unreleased(text), "### Added\n\n- Useful change.")

    def test_missing_heading_fails(self):
        with self.assertRaises(ValueError):
            unreleased("# Changelog\n")


if __name__ == "__main__":
    unittest.main()
