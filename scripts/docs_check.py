#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate Markdown structure, local references, and external citation status."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import sys
import tomllib
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import Request, urlopen

from policy import ROOT, git


def prose(text):
    output = []
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            if fence is None:
                fence = marker.group(1)[0]
            elif marker.group(1)[0] == fence:
                fence = None
            output.append("")
        else:
            output.append(line if fence is None else "")
    return "\n".join(output), fence


def headings(text):
    clean, _ = prose(text)
    seen = {}
    anchors = set()
    for title in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", clean, re.MULTILINE):
        title = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", title)
        slug = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
    anchors.update(re.findall(r'<a\s+(?:id|name)=["\']([^"\']+)', text))
    return anchors


def references(text):
    clean, _ = prose(text)
    inline = re.findall(r"\]\(([^\s)]+)(?:\s+\"[^\"]*\")?\)", clean)
    definitions = re.findall(r"^\s*\[[^]]+\]:\s*(\S+)", clean, re.MULTILINE)
    return [value.strip("<>") for value in inline + definitions]


def lint(path, text):
    errors = []
    clean, fence = prose(text)
    if fence:
        errors.append("unclosed code fence")
    if len(re.findall(r"^#\s+", clean, re.MULTILINE)) != 1:
        errors.append("expected exactly one top-level heading")
    if path.parts[0] == "docs" and not re.search(r"^Audience:\s+\S", clean, re.MULTILINE):
        errors.append("missing audience")
    if not text.endswith("\n"):
        errors.append("missing final newline")
    previous = 0
    for match in re.finditer(r"^(#{1,6})\s+", clean, re.MULTILINE):
        level = len(match.group(1))
        if previous and level > previous + 1:
            errors.append("heading level skips a parent")
        previous = level
    for number, line in enumerate(text.splitlines(), 1):
        if line.rstrip() != line:
            errors.append(f"line {number}: trailing whitespace")
        if "\t" in line:
            errors.append(f"line {number}: tab in Markdown")
    return errors


def check_local(source, reference, root=ROOT):
    parsed = urlsplit(reference)
    if parsed.scheme or reference.startswith("//"):
        return None
    target = ((root / source).parent / unquote(parsed.path)).resolve() if parsed.path else root / source
    try:
        target.relative_to(root)
    except ValueError:
        return "local link escapes repository"
    if not target.exists():
        return f"missing target: {reference}"
    if parsed.fragment and target.suffix.lower() == ".md":
        if unquote(parsed.fragment) not in headings(target.read_text()):
            return f"missing anchor: {reference}"
    return None


def check_external(url, expected):
    try:
        request = Request(url, headers={"User-Agent": "anonce-reference-check/0.1", "Accept": "*/*"})
        with urlopen(request, timeout=30) as response:
            status = response.status
    except HTTPError as error:
        status = error.code
    except (URLError, TimeoutError, OSError) as error:
        return f"{url}: connection failed ({type(error).__name__})"
    wanted = expected.get(url, 200)
    if status != wanted:
        return f"{url}: HTTP {status}, expected {wanted}"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lint", action="store_true")
    parser.add_argument("--links", action="store_true")
    parser.add_argument("--external", action="store_true")
    args = parser.parse_args()
    paths = [Path(value.decode()) for value in git("ls-files", "-z").stdout.split(b"\x00") if value and value.endswith(b".md")]
    failures = []
    external = set()
    count = 0
    for path in paths:
        if path.as_posix().startswith(("third_party/", "web/vendor/")):
            continue
        text = (ROOT / path).read_text()
        if args.lint:
            failures.extend(f"{path}: {error}" for error in lint(path, text))
        for reference in references(text):
            parsed = urlsplit(reference)
            if parsed.scheme in ("http", "https"):
                external.add(reference.split("#", 1)[0])
            elif args.links:
                count += 1
                error = check_local(path, reference)
                if error:
                    failures.append(f"{path}: {error}")
    if args.external:
        config = tomllib.loads((ROOT / "scripts/links.toml").read_text())
        expected = config["expected_status"]
        with ThreadPoolExecutor(max_workers=6) as pool:
            failures.extend(error for error in pool.map(lambda url: check_external(url, expected), sorted(external)) if error)
    for error in failures:
        print(error, file=sys.stderr)
    if failures:
        return 1
    print(f"documentation checks: passed ({len(paths)} Markdown files, {count} local references, {len(external)} external URLs indexed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
