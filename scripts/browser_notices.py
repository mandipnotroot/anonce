#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Preserve original notices for the two local browser binaries."""

from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    destination = ROOT / "bin/browser-notices"
    destination.mkdir(parents=True, exist_ok=True)
    output = subprocess.check_output(
        ["go", "list", "-deps", "-f", "{{if .Module}}{{.Module.Path}} {{.Module.Dir}}{{end}}",
         "./cmd/browser-identity", "./cmd/browser-submission"], cwd=ROOT, text=True,
    )
    modules = dict(line.split(" ", 1) for line in output.splitlines() if line)
    for module, directory in sorted(modules.items()):
        source = Path(directory)
        materials = [file for file in source.iterdir()
                     if file.is_file() and file.name.split(".", 1)[0] in
                     ("LICENSE", "NOTICE", "PATENTS", "COPYING")]
        if not materials:
            raise ValueError("module license unavailable")
        for file in materials:
            name = module.replace("/", "_") + "_" + file.name
            (destination / name).write_bytes(file.read_bytes())
    goroot = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
    for name in ("LICENSE", "PATENTS"):
        (destination / ("Go_" + name)).write_bytes((goroot / name).read_bytes())
    print("Browser binary upstream notices preserved in bin/browser-notices")


if __name__ == "__main__":
    main()
