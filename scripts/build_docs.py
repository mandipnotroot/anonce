#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Assemble canonical tracked documents into a disposable site input tree."""

import argparse
import hashlib
from html import escape
from html.parser import HTMLParser
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tomllib
from urllib.parse import unquote, urlsplit

from install_mdbook import copy_notices, manifest
from policy import ROOT, git


class ScriptAttributes(HTMLParser):
    def handle_starttag(self, tag, attributes):
        self.attributes = dict(attributes)


def externalize_scripts(output, site_url=""):
    """Keep theme code unchanged but serve executable scripts as local assets."""
    pattern = re.compile(r"(<script\b[^>]*>)(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
    assets = output / "assets" / "site-scripts"
    for page in output.rglob("*.html"):
        def replace(match):
            tag, code = match.groups()
            parser = ScriptAttributes()
            parser.feed(tag)
            attributes = parser.attributes
            script_type = (attributes.get("type") or "").lower()
            if "src" in attributes or script_type not in ("", "module", "text/javascript", "application/javascript"):
                return match.group(0)
            digest = hashlib.sha256(code.encode()).hexdigest()
            asset = assets / f"{digest}.js"
            assets.mkdir(parents=True, exist_ok=True)
            asset.write_text(code)
            relative = os.path.relpath(asset, page.parent)
            if page == output / "404.html":
                relative = urlsplit(site_url).path.rstrip("/") + "/" + asset.relative_to(output).as_posix()
            relative = escape(relative, quote=True)
            return f'{tag[:-1]} src="{relative}"></script>'

        page.write_text(pattern.sub(replace, page.read_text()))


def normalize_chapter_links(output):
    """Normalize README output names and 404 self-links under its base URL."""
    pattern = re.compile(r"(<a\b[^>]*\bhref=[\"'])([^\"']+)([\"'])", re.IGNORECASE)
    for page in output.rglob("*.html"):
        def replace(match):
            reference = match.group(2)
            if page.name == "404.html" and reference.startswith("#"):
                return match.group(1) + "404.html" + reference + match.group(3)
            parsed = urlsplit(reference)
            if parsed.scheme or parsed.netloc or Path(parsed.path).name != "README.html":
                return match.group(0)
            path = parsed.path[:-len("README.html")] + "index.html"
            return match.group(1) + reference.replace(parsed.path, path, 1) + match.group(3)
        page.write_text(pattern.sub(replace, page.read_text()))


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []
        self.resources = []
        self.base = None

    def handle_starttag(self, tag, attributes):
        values = dict(attributes)
        for key in ("id", "name" if tag == "a" else "id"):
            if values.get(key):
                self.ids.add(values[key])
        if any(key.startswith("on") for key in values):
            raise ValueError("documentation contains an inline event handler")
        if tag == "base":
            self.base = values.get("href")
        if tag == "a" and values.get("href"):
            self.links.append(values["href"])
        if tag in ("script", "img", "iframe", "source") and values.get("src"):
            self.resources.append(values["src"])
        if tag == "link" and values.get("href") and set((values.get("rel") or "").split()) & {"stylesheet", "icon", "preload"}:
            self.resources.append(values["href"])
        if tag == "script" and "src" not in values and (values.get("type") or "").lower() not in ("application/json", "application/ld+json"):
            raise ValueError("documentation contains an inline executable script")


def validate_site(output, site_url):
    """Check rendered links/anchors and prohibit remotely loaded page resources."""
    output = output.resolve()
    pages = {}
    for path in output.rglob("*.html"):
        page = Page()
        page.feed(path.read_text())
        pages[path] = page
    base_path = urlsplit(site_url).path.rstrip("/")
    for path, page in pages.items():
        for reference, resource in [(value, False) for value in page.links] + [(value, True) for value in page.resources]:
            parsed = urlsplit(reference)
            if parsed.scheme == "javascript":
                raise ValueError("documentation contains a script URL")
            if parsed.scheme or parsed.netloc:
                if resource:
                    raise ValueError("documentation loads a non-local resource")
                continue
            relative = unquote(parsed.path)
            if relative.startswith("/"):
                if base_path and relative.startswith(base_path + "/"):
                    relative = relative[len(base_path):]
                target = output / relative.lstrip("/")
            elif page.base:
                if page.base != site_url:
                    raise ValueError("unexpected documentation base URL")
                target = output / relative
            else:
                target = path.parent / relative if relative else path
            target = target.resolve()
            if not target.is_relative_to(output):
                raise ValueError("rendered documentation link escapes the site")
            if target.is_dir():
                target /= "index.html"
            if not target.is_file():
                raise ValueError(f"missing rendered link from {path.relative_to(output)}: {reference}")
            if not resource and parsed.fragment and target in pages and unquote(parsed.fragment) not in pages[target].ids:
                raise ValueError(f"missing rendered anchor from {path.relative_to(output)}: {reference}")
    for path in output.rglob("*.css"):
        if re.search(r"(?:url\(\s*['\"]?|@import\s*['\"])(?:https?:|//)", path.read_text(), re.IGNORECASE):
            raise ValueError("documentation CSS loads a remote resource")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--command", default=".cache/mdbook/bin/mdbook")
    args = parser.parse_args()
    command = shlex.split(args.command)
    version = subprocess.run([*command, "--version"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
    if version != f"mdbook v{manifest()['version']}":
        raise ValueError("documentation requires the pinned mdBook version; run make docs-setup")
    configuration = (ROOT / "book.toml").read_text()
    config = tomllib.loads(configuration)
    if (config["book"]["src"], config["build"]["build-dir"], config["output"]["html"]["theme"]) != ("source", "site", "theme"):
        raise ValueError("book paths must stay inside the disposable build tree")
    scratch = ROOT / ".cache" / "docs-build"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as directory:
        directory = Path(directory)
        source = directory / "source"
        source.mkdir()
        for raw in git("ls-files", "-z").stdout.split(b"\x00"):
            if not raw:
                continue
            relative = Path(raw.decode())
            if relative.parts[:2] == ("docs", "theme"):
                target = directory / "theme" / Path(*relative.parts[2:])
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, target)
                continue
            is_doc = relative.parts[0] == "docs" or (len(relative.parts) == 1 and relative.suffix == ".md")
            is_license = relative.parts[0] == "LICENSES" or relative.as_posix() == "LICENSE"
            if not (is_doc or is_license):
                continue
            target = source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        output = directory / "site"
        (directory / "book.toml").write_text(configuration)
        # Ignore environment overrides that could escape the disposable tree or
        # suppress warnings. The checked-in book configuration is authoritative.
        env = {key: value for key, value in os.environ.items() if not key.startswith("MDBOOK_")}
        env["MDBOOK_LOG"] = "info"
        result = subprocess.run([*command, "build", str(directory)], cwd=ROOT, env=env, check=False, capture_output=True, text=True)
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        if result.returncode == 0:
            if re.search(r"\bWARN(?:ING)?\b", result.stdout + result.stderr):
                raise ValueError("mdBook emitted a build warning")
            if not (output / "index.html").is_file():
                raise ValueError("documentation builder did not produce index.html")
            site_url = config["output"]["html"]["site-url"]
            externalize_scripts(output, site_url)
            normalize_chapter_links(output)
            copy_notices(output)
            validate_site(output, site_url)
            published = ROOT / "site"
            if published.exists():
                shutil.rmtree(published)
            shutil.move(str(output), published)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
