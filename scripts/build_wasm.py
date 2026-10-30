#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Build a selected WASM component with matching, reviewed runtime support."""

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


def member_notices(go, env, config):
    materials = {}
    for module, suffix in (("golang.org/x/crypto", "x-crypto"), ("golang.org/x/sys", "x-sys")):
        info = json.loads(subprocess.check_output(
            [go, "list", "-m", "-json", module], cwd=ROOT, env=env,
        ))
        if not info.get("Replace") and not info.get("Dir"):
            # Platform-specific imports may leave an admitted module uncached.
            # Download the selected version, then apply the same source checks.
            subprocess.run([go, "mod", "download", module], cwd=ROOT, env=env, check=True)
            info = json.loads(subprocess.check_output(
                [go, "list", "-m", "-json", module], cwd=ROOT, env=env,
            ))
        if info.get("Replace") or not info.get("Dir"):
            raise ValueError("WASM member modules must use admitted module sources")
        for name, digest in (("LICENSE", "license_sha256"), ("PATENTS", "patents_sha256")):
            materials[f"{name}.{suffix}"] = checked_material(Path(info["Dir"]) / name, config[digest])
    return materials


def build(go, component):
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
    command, relative = {
        "member": ("./cmd/memberwasm", "bin/memberwasm"),
        "review": ("./cmd/reviewwasm", "bin/reviewwasm"),
    }[component]
    destination = ROOT / relative
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".build-", dir=destination) as scratch:
        scratch = Path(scratch)
        output = scratch / "client.wasm"
        subprocess.run(
            [go, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", str(output), command],
            cwd=ROOT, env=dict(env, GOOS="js", GOARCH="wasm", CGO_ENABLED="0"), check=True,
        )
        data = output.read_bytes()
        check_wasm(data, config["max_wasm_bytes"])
        if component == "member":
            # Both modules have the same reviewed Go notices. Check each original.
            materials.update(member_notices(go, env, config))
            for name in ("member-client.mjs", "member-worker.mjs", "protocol.mjs"):
                materials[name] = (ROOT / "internal/memberworker" / name).read_bytes()
        if component in ("member", "review"):
            materials.update(member_notices(go, env, config))
            module = json.loads(subprocess.check_output([go, "list", "-m", "-json", "github.com/cloudflare/circl"], cwd=ROOT, env=env))
            if module.get("Replace") or module.get("Version") != "v1.6.5":
                raise ValueError("unreviewed blind-signature module")
            materials["LICENSE.circl"] = (Path(module["Dir"]) / "LICENSE").read_bytes()
        materials["client.wasm"] = data
        sums = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(materials.items()))
        materials["SHA256SUMS"] = sums.encode()
        for name, data in materials.items():
            (scratch / name).write_bytes(data)
        # Validate everything before replacing any successful build's files.
        # This is a disposable local build directory, not a release publication.
        for name in materials:
            (scratch / name).replace(destination / name)
    print(f"WASM {component}: {len(materials['client.wasm'])} bytes; hashes and notices in {relative}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--component", choices=("member", "review"), required=True)
    args = parser.parse_args()
    try:
        build(args.go, args.component)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"WASM build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
