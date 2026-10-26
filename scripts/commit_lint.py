#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Validate Conventional Commit subjects without a product build dependency."""

import argparse
from pathlib import Path
import re
import sys
import tomllib

from policy import git

CONFIG = tomllib.loads((Path(__file__).parent / "commits.toml").read_text())


def validate(message):
    lines = message.splitlines()
    if not lines:
        return "empty message"
    subject = lines[0]
    match = re.fullmatch(r"([a-z]+)(?:\(([a-z]+)\))?(!)?: (.+)", subject)
    if not match:
        return "expected a Conventional Commit subject"
    kind, scope, _, description = match.groups()
    if kind not in CONFIG["types"] or (scope and scope not in CONFIG["scopes"]):
        return "unsupported type or scope"
    if description != description.lower() or description.endswith("."):
        return "description must be lowercase with no trailing period"
    if len(subject) > CONFIG["subject_limit"]:
        return "subject exceeds configured limit"
    if len(lines) > 1 and lines[1]:
        return "separate subject and body with a blank line"
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--message", type=Path)
    parser.add_argument("--title")
    parser.add_argument("--range", dest="revision", default="--all")
    args = parser.parse_args()
    messages = []
    if args.message:
        messages.append(("message", args.message.read_text()))
    elif args.title is not None:
        messages.append(("title", args.title))
    else:
        for revision in git("rev-list", args.revision).stdout.decode().splitlines():
            messages.append((revision, git("show", "-s", "--format=%B", revision).stdout.decode()))
    failed = False
    for label, message in messages:
        error = validate(message)
        if error:
            print(f"{label}: {error}", file=sys.stderr)
            failed = True
    if failed:
        return 1
    print(f"commit lint: passed ({len(messages)} messages)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
