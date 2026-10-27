# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for the inert-shell checks; no external requests are made."""

import base64
import hashlib
import unittest

from web_check import ShellParser, check_css, check_integrity


CSS = ":focus-visible {} .skip-link:focus {} @media (prefers-color-scheme: dark) {} @media print {}"
DIGEST = hashlib.sha256(CSS.encode()).digest()
PATH = f"/assets/shell.{DIGEST.hex()}.css"
INTEGRITY = "sha256-" + base64.b64encode(DIGEST).decode()
HTML = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Mock</title>
<link rel="stylesheet" href="{PATH}" integrity="{INTEGRITY}" crossorigin="anonymous"></head>
<body><a href="#main">Skip to content</a><main id="main"><h1>Development only</h1>
<h2 id="status">Status</h2><section aria-labelledby="status"><p>Unavailable</p></section>
<button type="button" disabled>Unavailable</button></main><footer><a href="/source">Source</a></footer></body></html>'''


class ShellChecks(unittest.TestCase):
    def test_valid_shell(self):
        self.assertEqual(ShellParser().validate(HTML), (PATH, INTEGRITY))
        check_css(CSS)
        check_integrity(PATH, INTEGRITY, CSS.encode())

    def test_reject_markup(self):
        cases = {
            "script": HTML.replace("<p>Unavailable</p>", "<script>alert(1)</script>"),
            "style element": HTML.replace("<p>Unavailable</p>", "<style>body{}</style>"),
            "inline style": HTML.replace("<p>", '<p style="color:red">'),
            "handler": HTML.replace("<p>", '<p onclick="alert(1)">'),
            "remote URL": HTML.replace('href="/source"', 'href="https://example.invalid"'),
            "network path": HTML.replace('href="/source"', 'href="//example.invalid"'),
            "additional network path": HTML.replace("</footer>", '<a href="//example.invalid">Remote</a></footer>'),
            "encoded URL": HTML.replace('href="/source"', 'href="/&#47;example.invalid"'),
            "additional encoded URL": HTML.replace("</footer>", '<a href="/&#47;example.invalid">Remote</a></footer>'),
            "query": HTML.replace('href="/source"', 'href="/source?secret=value"'),
            "form": HTML.replace("<p>Unavailable</p>", "<form></form>"),
            "input": HTML.replace("<p>Unavailable</p>", "<input>"),
            "image": HTML.replace("<p>Unavailable</p>", '<img src="/track">'),
            "enabled control": HTML.replace(" disabled", ""),
            "missing source": HTML.replace('href="/source"', 'href="/about"'),
            "broken fragment": HTML.replace('href="#main"', 'href="#missing"'),
            "broken label": HTML.replace('aria-labelledby="status"', 'aria-labelledby="missing"'),
            "missing label value": HTML.replace('aria-labelledby="status"', 'aria-labelledby'),
            "empty label": HTML.replace('aria-labelledby="status"', 'aria-labelledby=""'),
            "missing href value": HTML.replace('href="/source"', 'href'),
            "heading order": HTML.replace("<h2 id=", "<h3 id=").replace("</h2>", "</h3>"),
            "duplicate ID": HTML.replace("<p>", '<p id="status">'),
            "duplicate attribute": HTML.replace('id="main"', 'id="main" id="other"'),
            "missing main": HTML.replace('<main id="main">', '<div id="main">').replace("</main>", "</div>"),
            "missing warning": HTML.replace("Development only", "Ready"),
            "missing language": HTML.replace('lang="en"', 'lang=""'),
            "unbalanced": HTML.replace("</main>", ""),
            "no doctype": HTML.replace("<!doctype html>", ""),
            "meta refresh": HTML.replace('<meta charset="utf-8">', '<meta http-equiv="refresh" content="0;url=/other">'),
            "external asset": HTML.replace(PATH, "https://example.invalid/shell.css"),
        }
        for name, html in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                ShellParser().validate(html)

    def test_reject_css(self):
        for addition in (
            '@import "remote.css";',
            'a { background: url("https://example.invalid"); }',
            'a { background: URL ("/local"); }',
            'a { background: u/**/rl("/local"); }',
            r'a { background: u\72l("/local"); }',
            "a { width: expression(1); }",
            "a { behavior: test; }",
            "@font-face {}",
            "{",
            "}",
        ):
            with self.subTest(addition=addition), self.assertRaises(ValueError):
                check_css(CSS + addition)

    def test_reject_integrity_mismatch(self):
        for path, integrity, content in (
            (PATH, INTEGRITY, b"changed"),
            ("/assets/shell.css", INTEGRITY, CSS.encode()),
            (PATH, "sha256-invalid", CSS.encode()),
        ):
            with self.subTest(path=path, integrity=integrity), self.assertRaises(ValueError):
                check_integrity(path, integrity, content)


if __name__ == "__main__":
    unittest.main()
