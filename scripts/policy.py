#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Inspect repository objects and collaboration text against repository policy."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
CONFIG = "scripts/policy.toml"
VENDORS = ("third_party/", "web/vendor/")
METADATA = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".tif", ".tiff", ".bmp", ".ico",
    ".avif", ".heic", ".heif", ".jxl", ".jp2", ".pdf", ".ps", ".eps",
    ".woff", ".woff2", ".ttf", ".otf",
}


def git(*args, check=True):
    return subprocess.run(
        ["git", "--no-replace-objects", *args], cwd=ROOT, check=check, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class Inspector:
    def __init__(self):
        with (ROOT / CONFIG).open("rb") as handle:
            self.config = tomllib.load(handle)
        self.rules = [(item["id"], re.compile(item["pattern"])) for item in self.config["rules"]]
        self.failures = []
        self.checked = set()
        self.tags = set()

    def text(self, label, value):
        for name, pattern in self.rules:
            candidate = value
            if name == "credit":
                headers = self.config.get("ordinary_headers", [])
                candidate = "\n".join(
                    "" if any(re.fullmatch(item["pattern"], line) for item in headers) else line
                    for line in value.splitlines()
                )
            if pattern.search(candidate):
                self.failures.append(f"{label}: violates {name} policy")

    def blob(self, path, oid, data):
        if path.startswith(VENDORS):
            return
        self.text(f"filename {path!r}", path)
        if path == CONFIG:
            return
        key = (oid, Path(path).suffix.lower())
        if key in self.checked:
            return
        self.checked.add(key)
        self.text(f"content {path!r}", data.decode("utf-8", errors="replace"))
        if b"\x00" in data:
            for encoding in ("utf-16-le", "utf-16-be"):
                self.text(f"embedded text {path!r}", data.decode(encoding, errors="ignore"))
        if Path(path).suffix.lower() in METADATA:
            if shutil.which("exiftool") is None:
                self.failures.append(f"metadata {path!r}: exiftool is required")
                return
            scratch = ROOT / ".cache" / "policy"
            scratch.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=scratch) as directory:
                target = Path(directory) / ("asset" + Path(path).suffix.lower())
                target.write_bytes(data)
                result = subprocess.run(
                    ["exiftool", "-j", "-G1", "-a", "-u", str(target)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                if result.returncode:
                    self.failures.append(f"metadata {path!r}: inspection failed")
                else:
                    try:
                        records = json.loads(result.stdout)
                        for record in records:
                            record.pop("SourceFile", None)
                            for field in tuple(record):
                                if field.startswith(("File:", "System:", "ExifTool:")):
                                    del record[field]
                        self.text(f"metadata {path!r}", json.dumps(records, ensure_ascii=False))
                    except (ValueError, TypeError):
                        self.failures.append(f"metadata {path!r}: invalid inspector output")

    def tree(self, ref):
        for entry in git("ls-tree", "-rz", "--full-tree", ref).stdout.split(b"\x00"):
            if not entry:
                continue
            attributes, raw_path = entry.split(b"\t", 1)
            _, kind, oid = attributes.decode().split()
            path = raw_path.decode("utf-8", errors="replace")
            if kind != "blob":
                self.failures.append(f"{ref}: unsupported tracked object {path!r}")
                continue
            self.blob(path, oid, git("cat-file", "blob", oid).stdout)

    def index(self):
        for raw_path in git("ls-files", "-z", "--cached").stdout.split(b"\x00"):
            if not raw_path:
                continue
            path = raw_path.decode("utf-8", errors="strict")
            result = git("show", f":{path}", check=False)
            if result.returncode:
                self.failures.append(f"index: cannot read {path!r}")
                continue
            self.blob(path, f"index:{path}", result.stdout)

    def history(self, refs, allow_dependency=False):
        if git("rev-parse", "--is-shallow-repository").stdout.strip() == b"true":
            self.failures.append("history: shallow repositories cannot establish complete coverage")
            return
        revisions = git("rev-list", *refs).stdout.decode().splitlines()
        for revision in revisions:
            fields = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", revision).stdout.decode("utf-8", errors="replace").split("\x00", 4)
            if len(fields) != 5:
                self.failures.append(f"commit {revision}: invalid metadata")
                continue
            for index, role in ((0, "author"), (2, "committer")):
                name, email = fields[index:index + 2]
                dependency = self.config["dependency_identity"]
                if allow_dependency and name == dependency["name"] and email == dependency["email"]:
                    continue
                self.text(f"commit {revision} {role}", name + "\n" + email)
            self.text(f"commit {revision} message", fields[4])
            self.tree(revision)
        for line in git("for-each-ref", "--format=%(refname)%00%(objecttype)%00%(objectname)").stdout.decode().splitlines():
            name, kind, oid = line.split("\x00")
            self.text("reference", name)
            if kind == "tag":
                self.tag(oid)

    def tag(self, oid):
        if oid in self.tags:
            return
        self.tags.add(oid)
        text = git("cat-file", "tag", oid).stdout.decode("utf-8", errors="replace")
        self.text(f"tag object {oid}", text)
        header = text.split("\n\n", 1)[0]
        if "\ntype tag\n" in "\n" + header + "\n":
            target = re.search(r"^object ([0-9a-f]{40,64})$", header, re.MULTILINE)
            if target is None:
                self.failures.append(f"tag object {oid}: invalid target")
            else:
                self.tag(target.group(1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", action="store_true")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--ref", action="append", default=[])
    parser.add_argument("--commit-message", type=Path)
    parser.add_argument("--event", type=Path)
    parser.add_argument("--dependency-pr", action="store_true")
    args = parser.parse_args()
    inspector = Inspector()
    if args.index or not any((args.history, args.ref, args.commit_message, args.event)):
        inspector.index()
    if args.history or args.ref:
        inspector.history(args.ref or ["--all"], allow_dependency=args.dependency_pr)
    if args.commit_message:
        inspector.text("commit message", args.commit_message.read_text())
        for role in ("AUTHOR", "COMMITTER"):
            result = git("var", f"GIT_{role}_IDENT", check=False)
            if result.returncode:
                inspector.failures.append(f"{role.lower()} identity is not configured")
            else:
                inspector.text(role.lower(), result.stdout.decode())
    if args.event:
        event = json.loads(args.event.read_text())
        pr = event.get("pull_request", {})
        if not pr:
            inspector.failures.append("event: expected pull request")
        inspector.text("pull request title", pr.get("title") or "")
        inspector.text("pull request description", pr.get("body") or "")
    for failure in sorted(set(inspector.failures)):
        print(failure, file=sys.stderr)
    if inspector.failures:
        return 1
    print(f"repository policy: passed ({len(inspector.checked)} unique file objects inspected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
