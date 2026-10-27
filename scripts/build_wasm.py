#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Build the public-only WASM verifier with matching, reviewed runtime support."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[1]


def checked_material(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("unreviewed Go runtime support or notice")
    return data


def check_wasm(data, maximum):
    if not data.startswith(b"\0asm\x01\0\0\0") or not 8 < len(data) <= maximum:
        raise ValueError("invalid or oversized WASM artifact")


def build(go):
    with (ROOT / "scripts/wasm.toml").open("rb") as handle:
        config = tomllib.load(handle)
    env = dict(os.environ, GOTOOLCHAIN=config["go_version"])
    info = json.loads(subprocess.check_output(
        [go, "env", "-json", "GOVERSION", "GOROOT"], cwd=ROOT, env=env,
    ))
    if info["GOVERSION"] != config["go_version"]:
        raise ValueError("WASM requires the pinned Go toolchain")
    goroot = Path(info["GOROOT"])
    materials = {
        "wasm_exec.js": checked_material(goroot / "lib/wasm/wasm_exec.js", config["loader_sha256"]),
        "LICENSE": checked_material(goroot / "LICENSE", config["license_sha256"]),
        "PATENTS": checked_material(goroot / "PATENTS", config["patents_sha256"]),
        "LICENSE.anonce": (ROOT / "LICENSE").read_bytes(),
    }
    destination = ROOT / "bin/wasm"
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".build-", dir=destination) as scratch:
        scratch = Path(scratch)
        output = scratch / "client.wasm"
        subprocess.run(
            [go, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", str(output), "./cmd/wasm"],
            cwd=ROOT, env=dict(env, GOOS="js", GOARCH="wasm", CGO_ENABLED="0"), check=True,
        )
        data = output.read_bytes()
        check_wasm(data, config["max_wasm_bytes"])
        materials["client.wasm"] = data
        sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(materials.items()))
        materials["SHA256SUMS"] = sums.encode()
        for name, data in materials.items():
            (scratch / name).write_bytes(data)
        # Validate everything before replacing any successful build's files.
        # This is a disposable local build directory, not a release publication.
        for name in materials:
            (scratch / name).replace(destination / name)
    print(f"WASM verifier: {len(materials['client.wasm'])} bytes; hashes and notices in bin/wasm")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    try:
        build(args.go)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"WASM build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
