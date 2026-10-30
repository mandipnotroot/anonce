#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Check first-party browser markup, accessible references and local asset loading."""

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


class BrowserMarkup(HTMLParser):
    """Validate the bounded embedded pages, not arbitrary user HTML."""

    void = {"meta", "link", "input", "br", "hr"}
    allowed = set("html head meta title link script body a header nav main h1 h2 h3 p section div footer form label input button fieldset legend ul li output textarea select option span strong br hr".split())

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.ids = set()
        self.references = []
        self.labels = set()
        self.controls = []
        self.counts = Counter()
        self.source = False
        self.skip = False
        self.doctype = False
        self.heading = 0

    def handle_decl(self, declaration):
        require(declaration.lower() == "doctype html" and not self.doctype, "invalid doctype")
        self.doctype = True

    def handle_starttag(self, tag, attributes):
        require(tag in self.allowed, f"unexpected element: {tag}")
        attrs = dict(attributes)
        require(len(attrs) == len(attributes), "duplicate attribute")
        for name, value in attributes:
            require(not name.startswith("on") and name not in {"style", "srcdoc", "action", "formaction"}, "inline execution or native form action")
            if name == "id":
                require(value and value not in self.ids, "empty or duplicate ID")
                self.ids.add(value)
            if name in {"aria-labelledby", "aria-describedby"}:
                require(value, "empty accessible reference")
                self.references.extend(value.split())
            if name in {"src", "href"}:
                require(value and re.fullmatch(r"/assets/[a-z-]+\.(?:mjs|css)|/source|#[a-z][a-z-]*", value), "unexpected resource or navigation URL")
                if value.startswith("#"):
                    self.references.append(value[1:])
        self.counts[tag] += 1
        if tag == "html":
            require(attrs.get("lang") == "en", "missing document language")
        if tag == "script":
            require(attrs.get("type") == "module" and re.fullmatch(r"/assets/[a-z-]+\.mjs", attrs.get("src", "")), "nonlocal or inline executable script")
        if tag == "meta":
            require("http-equiv" not in attrs, "active metadata")
        if tag == "link":
            require(attrs.get("rel") == "stylesheet" and re.fullmatch(r"/assets/[a-z-]+\.css", attrs.get("href", "")), "unexpected stylesheet")
        if tag == "label":
            require(attrs.get("for"), "label without control reference")
            self.labels.add(attrs["for"])
            self.references.append(attrs["for"])
        if tag in {"input", "textarea", "select"}:
            require(attrs.get("id") and "name" not in attrs, "unlabelled or natively submittable control")
            self.controls.append(attrs["id"])
        if tag == "a":
            self.source |= attrs.get("href") == "/source"
            self.skip |= attrs.get("href") == "#main"
        if re.fullmatch(r"h[1-3]", tag):
            level = int(tag[1])
            require(level <= self.heading + 1, "heading level skipped")
            self.heading = level
        if tag not in self.void:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        require(self.stack and self.stack[-1] == tag, "unbalanced markup")
        self.stack.pop()

    def handle_data(self, data):
        require(not self.stack or self.stack[-1] != "script" or not data.strip(), "inline script body")

    def validate(self, markup):
        self.feed(markup)
        self.close()
        require(self.doctype and not self.stack, "incomplete document")
        for tag in ("html", "head", "title", "body", "main", "h1", "footer", "script", "link"):
            require(self.counts[tag] == 1, f"expected one {tag}")
        require(self.source and self.skip, "missing source or skip link")
        require(all(ref in self.ids for ref in self.references), "missing fragment or accessible reference")
        require(all(control in self.labels for control in self.controls), "control without explicit label")


def check_css(css):
    clean = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    require(not re.search(r"\\|@import|url\s*\(|expression\s*\(|javascript:|behavior\s*:", clean, re.IGNORECASE), "loading or executable CSS")
    require(all(rule.lower() == "media" for rule in re.findall(r"@([\w-]+)", clean)), "unexpected CSS at-rule")
    depth = 0
    for character in clean:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        require(depth >= 0, "unbalanced CSS")
    require(depth == 0 and ":focus-visible" in clean, "incomplete CSS or missing visible focus")


def main():
    try:
        for name in ("identity", "anonymous"):
            BrowserMarkup().validate((ROOT / f"web/browser/{name}.html").read_text())
        check_css((ROOT / "web/browser/screen.css").read_text())
    except (OSError, ValueError) as error:
        print(f"browser markup check failed: {error}", file=sys.stderr)
        return 1
    print("browser markup checks: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
