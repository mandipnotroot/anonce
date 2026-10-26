#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Create missing configured labels without overwriting existing repository labels."""

import argparse
import json
import subprocess
import tomllib

from policy import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="mandipnotroot/anonce")
    args = parser.parse_args()
    result = subprocess.run(
        ["gh", "label", "list", "--repo", args.repo, "--json", "name", "--limit", "1000"],
        check=True, stdout=subprocess.PIPE,
    )
    existing = {item["name"] for item in json.loads(result.stdout)}
    config = tomllib.loads((ROOT / ".github/labels.toml").read_text())
    created = 0
    for group in config["groups"]:
        for suffix in group["names"]:
            name = group["prefix"] + suffix
            if name in existing:
                continue
            subprocess.run(
                ["gh", "label", "create", name, "--repo", args.repo,
                 "--color", group["color"], "--description", group["description"]],
                check=True,
            )
            created += 1
    print(f"repository labels: {created} created; existing labels preserved")


if __name__ == "__main__":
    main()
