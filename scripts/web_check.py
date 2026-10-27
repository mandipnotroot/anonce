#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Check the rendered local shell, its static markup, CSS, headers, and asset hashes."""

import base64
from collections import Counter
from contextlib import contextmanager
import hashlib
from html.parser import HTMLParser
from http.client import HTTPConnection
from pathlib import Path
import re
import socket
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://source.example.invalid/anonce/archive/test-revision.tar.gz"
CSP = "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
MAX_RESPONSE = 128 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


class ShellParser(HTMLParser):
    """Deliberately small allowlist for the inert shell, not a general HTML validator."""

    allowed = set("html head meta title link body a header nav aside strong main h1 h2 h3 p section div article footer dl dt dd span button".split())
    void = {"meta", "link"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.counts = Counter()
        self.ids = set()
        self.references = []
        self.styles = []
        self.links = []
        self.last_heading = 0
        self.doctypes = 0
        self.text = []

    def handle_decl(self, decl):
        require(decl.lower() == "doctype html", "unexpected declaration")
        self.doctypes += 1

    def handle_starttag(self, tag, attributes):
        require(tag in self.allowed, f"unexpected element: {tag}")
        attrs = dict(attributes)
        require(len(attrs) == len(attributes), "duplicate attribute")
        for name, value in attributes:
            require(not name.startswith("on") and name not in {"style", "src", "srcdoc", "action", "formaction"}, "executable or loading attribute")
            require(name in {"lang", "charset", "name", "content", "rel", "href", "integrity", "crossorigin", "class", "aria-label", "aria-current", "aria-labelledby", "aria-describedby", "id", "tabindex", "type", "disabled"}, f"unexpected attribute: {name}")
            if name == "id":
                require(value and value not in self.ids, "empty or duplicate ID")
                self.ids.add(value)
            if name in {"aria-labelledby", "aria-describedby"}:
                require(value, "empty accessible-description reference")
                self.references.extend(value.split())
        self.counts[tag] += 1
        if tag == "html":
            require(attrs.get("lang") == "en", "missing document language")
        if tag == "meta":
            require(set(attrs) in ({"charset"}, {"name", "content"}), "unexpected metadata")
            require(attrs.get("charset") == "utf-8" or attrs.get("name") in {"viewport", "color-scheme"}, "unexpected metadata value")
        if tag in {"a", "link"}:
            href = attrs.get("href", "")
            require(href and re.fullmatch(r"/(?!/)[a-zA-Z0-9/._-]*|#[a-zA-Z][a-zA-Z0-9_-]*", href), "non-local or noncanonical link")
            if href.startswith("#"):
                self.references.append(href[1:])
            if tag == "a":
                self.links.append(href)
            else:
                require(attrs.get("rel") == "stylesheet" and attrs.get("crossorigin") == "anonymous", "unexpected asset relation")
                require(re.fullmatch(r"/assets/shell\.[a-f0-9]{64}\.css", href), "stylesheet URL is not content-addressed")
                self.styles.append((href, attrs.get("integrity")))
        if tag == "button":
            require("disabled" in attrs and attrs.get("type") == "button", "interactive control in read-only shell")
        if re.fullmatch(r"h[1-3]", tag):
            level = int(tag[1])
            require(level <= self.last_heading + 1, "heading skipped a level")
            self.last_heading = level
        if tag not in self.void:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        require(tag in self.void, "self-closing non-void element")
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        require(self.stack and self.stack[-1] == tag, "unbalanced HTML elements")
        self.stack.pop()

    def handle_data(self, data):
        self.text.append(data)

    def validate(self, html):
        self.feed(html)
        self.close()
        require(not self.stack and self.doctypes == 1, "incomplete HTML document")
        for tag in ("html", "head", "title", "body", "main", "h1", "footer"):
            require(self.counts[tag] == 1, f"expected one {tag}")
        require(len(self.styles) == 1, "expected exactly one stylesheet")
        require(all(ref in self.ids for ref in self.references), "missing fragment or accessible-description target")
        require("#main" in self.links and "/source" in self.links, "missing skip or corresponding-source link")
        require("Development only" in " ".join(self.text), "missing development warning")
        return self.styles[0]


def check_css(css):
    # This shell intentionally needs no imports, URLs, escapes, or executable CSS.
    # Reject those rather than trying to normalize alternate loading syntax.
    clean = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    require(not re.search(r"\\|@import|url\s*\(|expression\s*\(|javascript:|behavior\s*:", clean, re.IGNORECASE), "loading or executable CSS")
    require(all(rule.lower() == "media" for rule in re.findall(r"@([\w-]+)", clean)), "unexpected CSS at-rule")
    depth = 0
    for character in clean:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        require(depth >= 0, "unbalanced CSS braces")
    require(depth == 0 and "{" in clean, "incomplete stylesheet")
    for selector in (":focus-visible", ".skip-link:focus", "prefers-color-scheme: dark", "@media print"):
        require(selector in clean, f"missing shell CSS rule: {selector}")


def check_integrity(path, integrity, content):
    digest = hashlib.sha256(content).digest()
    require(path == f"/assets/shell.{digest.hex()}.css", "stylesheet path digest mismatch")
    require(integrity == "sha256-" + base64.b64encode(digest).decode("ascii"), "stylesheet SRI mismatch")


def request(port, path, method="GET"):
    # Direct loopback connection: no proxy settings, DNS, cookies, or redirects.
    connection = HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        content = response.read(MAX_RESPONSE + 1)
        require(len(content) <= MAX_RESPONSE, "response exceeded shell size bound")
        return response.status, dict(response.getheaders()), content
    finally:
        connection.close()


@contextmanager
def server(styleguide):
    # Port reservation cannot be transferred to the process. A bind race fails the
    # check rather than falling back to a different address or accepting secrets.
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    args = [str(ROOT / "bin/server"), "-listen", f"127.0.0.1:{port}", "-source-url", SOURCE]
    if styleguide:
        args.append("-dev-styleguide")
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while True:
            require(process.poll() is None, "local shell exited before liveness")
            try:
                status, _, body = request(port, "/healthz")
                require(status == 200 and body == b"ok", "invalid liveness response")
                break
            except OSError:
                require(time.monotonic() < deadline, "local shell startup timed out")
                time.sleep(0.05)
        yield port
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            _, errors = process.communicate(timeout=7)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise ValueError("local shell failed bounded shutdown") from None
        require(process.returncode == 0 and not errors, "local shell exited unsuccessfully or emitted diagnostics")


def check_delivery(port, path, content_type):
    status, headers, content = request(port, path)
    require(status == 200, f"{path}: expected successful GET")
    expected = {
        "Content-Type": content_type,
        "Content-Security-Policy": CSP,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }
    require(all(headers.get(key) == value for key, value in expected.items()), f"{path}: incorrect security or content headers")
    require("Set-Cookie" not in headers and "Access-Control-Allow-Origin" not in headers, "unexpected cookie or CORS access")
    head_status, head_headers, head_body = request(port, path, "HEAD")
    require(head_status == status and not head_body, "incorrect HEAD behavior")
    require(all(head_headers.get(key) == value for key, value in expected.items()), "HEAD headers do not match GET")
    write_status, write_headers, _ = request(port, path, "POST")
    require(write_status == 405 and write_headers.get("Allow") == "GET, HEAD", "shell accepted a write")
    return content


def main():
    for styleguide in (False, True):
        with server(styleguide) as port:
            paths = ["/", "/about"] + (["/dev/styleguide"] if styleguide else [])
            for path in paths:
                html = check_delivery(port, path, "text/html; charset=utf-8").decode("utf-8")
                parser = ShellParser()
                asset, integrity = parser.validate(html)
                require(("/dev/styleguide" in parser.links) == styleguide, "style-guide navigation escaped development gate")
                for link in parser.links:
                    if not link.startswith("#") and link != "/source":
                        link_status, _, _ = request(port, link)
                        require(link_status == 200, "broken local page link")
                css = check_delivery(port, asset, "text/css; charset=utf-8")
                check_integrity(asset, integrity, css)
                check_css(css.decode("utf-8"))
                require(css == (ROOT / "web/assets/shell.css").read_bytes(), "binary assets differ from the working source; rebuild")
            if not styleguide:
                require(request(port, "/dev/styleguide")[0] == 404, "style guide enabled by default")
            require(request(port, "/readyz")[0] == 503, "shell claims protocol readiness")
            require(request(port, "/api/v1/submissions", "POST")[0] == 501, "shell enabled submissions")
            status, headers, body = request(port, "/source")
            require(status == 302 and headers.get("Location") == SOURCE and not body, "incorrect corresponding-source redirect")
    print("web checks: passed (rendered inert markup, local CSS/SRI, development gate, headers, methods, process shutdown)")
    print("Browser rendering, accessibility, screenshots, and protocol security remain untested by this check.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError) as error:
        print(f"web checks: {error}", file=sys.stderr)
        sys.exit(1)
