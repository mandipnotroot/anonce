# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression checks for product markup admission without network access."""

import unittest

from browser_markup import BrowserMarkup, check_css, ROOT


class BrowserMarkupTests(unittest.TestCase):
    def test_css_admission(self):
        css = (ROOT / "web/browser/screen.css").read_text()
        check_css(css)
        for addition in (
            '@import "remote.css";',
            'a { background: url("https://example.invalid"); }',
            'a { background: u/**/rl("/local"); }',
            r'a { background: u\72l("/local"); }',
            'a { width: expression(1); }',
            'a { behavior: test; }',
            '@font-face {}',
            '{',
            '}',
        ):
            with self.subTest(addition=addition), self.assertRaises(ValueError):
                check_css(css + addition)
        with self.assertRaises(ValueError):
            check_css(css.replace(":focus-visible", ":hover"))

    def test_product_pages(self):
        for name in ("identity", "anonymous"):
            with self.subTest(page=name):
                BrowserMarkup().validate((ROOT / f"web/browser/{name}.html").read_text())

    def test_rejected_markup(self):
        markup = (ROOT / "web/browser/identity.html").read_text()
        cases = {
            "script origin": markup.replace("/assets/identity.mjs", "https://example.invalid/script.mjs"),
            "inline script": markup.replace("</script>", "alert(1)</script>"),
            "inline handler": markup.replace("<body ", '<body onclick="alert(1)" '),
            "inline style": markup.replace("<body ", '<body style="display:none" '),
            "native action": markup.replace('<form id="member"', '<form action="/api/browser/backup" id="member"'),
            "named secret": markup.replace('id="passphrase"', 'id="passphrase" name="passphrase"'),
            "missing label": markup.replace('for="passphrase"', 'for="missing"'),
            "duplicate ID": markup.replace('id="confirmation"', 'id="passphrase"'),
            "duplicate attribute": markup.replace('id="confirmation"', 'id="confirmation" id="extra"'),
            "missing fragment": markup.replace('href="#main"', 'href="#missing"'),
            "missing source": markup.replace('href="/source"', 'href="#main"'),
            "tracking URL": markup.replace('href="/source"', 'href="//example.invalid"'),
            "active metadata": markup.replace('<meta charset="utf-8">', '<meta http-equiv="refresh" content="0">'),
            "unbalanced": markup.replace("</main>", ""),
            "doctype": markup.replace("<!doctype html>", ""),
        }
        for name, value in cases.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                BrowserMarkup().validate(value)


if __name__ == "__main__":
    unittest.main()
