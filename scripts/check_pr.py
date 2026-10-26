#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate pull-request metadata and its actual commit range."""

import argparse
import json
from pathlib import Path
import re
import sys

from commit_lint import validate
from policy import Inspector, git


def unreleased(text):
    match = re.search(r"^## \[Unreleased\]\s*\n(.*?)(?=^## \[|\Z)", text, re.MULTILINE | re.DOTALL)
    if not match:
        raise ValueError("missing Unreleased section")
    return re.split(r"^\[[^]]+\]:", match.group(1), maxsplit=1, flags=re.MULTILINE)[0].strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("event", type=Path)
    args = parser.parse_args()
    event = json.loads(args.event.read_text())
    pr = event["pull_request"]
    inspector = Inspector()
    inspector.text("pull request title", pr.get("title") or "")
    inspector.text("pull request description", pr.get("body") or "")
    error = validate(pr.get("title") or "")
    if error:
        inspector.failures.append(f"pull request title: {error}")
    labels = {item["name"] for item in pr.get("labels", [])}
    impacts = labels & {"semver:major", "semver:minor", "semver:patch"}
    if len(impacts) != 1:
        inspector.failures.append("pull request: exactly one SemVer impact label is required")
    base = pr["base"]["sha"]
    head = pr["head"]["sha"]
    if not all(re.fullmatch(r"[0-9a-f]{40}", value) for value in (base, head)):
        raise ValueError("invalid source revision")
    inspector.history([base])
    permitted = pr["user"]["login"] == inspector.config["dependency_identity"]["name"]
    inspector.history([f"{base}..{head}"], allow_dependency=permitted)
    for revision in git("rev-list", f"{base}..{head}").stdout.decode().splitlines():
        error = validate(git("show", "-s", "--format=%B", revision).stdout.decode())
        if error:
            inspector.failures.append(f"commit {revision}: {error}")
    if "changelog:not-needed" not in labels:
        before = git("show", f"{base}:CHANGELOG.md", check=False)
        after = git("show", f"{head}:CHANGELOG.md", check=False)
        if after.returncode:
            inspector.failures.append("pull request: CHANGELOG.md is missing")
        else:
            old = unreleased(before.stdout.decode()) if before.returncode == 0 else ""
            if old == unreleased(after.stdout.decode()):
                inspector.failures.append("pull request: update Unreleased or request the maintainer exception label")
    for failure in sorted(set(inspector.failures)):
        print(failure, file=sys.stderr)
    if inspector.failures:
        return 1
    print("pull request policy: passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
