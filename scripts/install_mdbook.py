#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Install a checksum-pinned mdBook release and its published asset notices."""

import hashlib
import io
from pathlib import Path
import platform
import tarfile
import tomllib
from urllib.request import urlopen

from policy import ROOT

MAX_DOWNLOAD = 64 * 1024 * 1024


def manifest():
    return tomllib.loads((ROOT / "scripts/mdbook.toml").read_text())


def platform_key(system=None, machine=None):
    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)
    return f"{system}-{machine}"


def verified(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("mdBook artifact checksum mismatch")
    return data


def archive_member(data, member):
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        entry = archive.getmember(member)
        if not entry.isfile() or entry.size > MAX_DOWNLOAD:
            raise ValueError("mdBook archive member must be a bounded regular file")
        return archive.extractfile(entry).read(MAX_DOWNLOAD + 1)


def download(entry, cache):
    """Verify both downloads and cache hits before using their contents."""
    cache.mkdir(parents=True, exist_ok=True)
    target = cache / entry["sha256"]
    if target.exists():
        if target.stat().st_size > MAX_DOWNLOAD:
            raise ValueError("cached mdBook artifact exceeds the download limit")
        return verified(target.read_bytes(), entry["sha256"])
    if not entry["url"].startswith("https://"):
        raise ValueError("mdBook artifact URL must use HTTPS")
    with urlopen(entry["url"], timeout=60) as response:
        if not response.url.startswith("https://"):
            raise ValueError("mdBook artifact redirected outside HTTPS")
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("mdBook artifact exceeds the download limit")
    verified(data, entry["sha256"])
    target.write_bytes(data)
    return data


def notice_data(entry, cache):
    data = download(entry, cache)
    return archive_member(data, entry["member"]) if "member" in entry else data


def copy_notices(output):
    """Copy original notices without editing or relicensing upstream text."""
    config = manifest()
    cache = ROOT / ".cache/mdbook/downloads"
    target = output / "assets/upstream-licenses"
    target.mkdir(parents=True, exist_ok=True)
    for name, entry in config["notices"].items():
        # Builds are offline. Setup must already have verified every artifact.
        if not (cache / entry["sha256"]).is_file():
            raise ValueError("mdBook notices are missing; run make docs-setup")
        (target / f"{name}.txt").write_bytes(notice_data(entry, cache))


def main():
    config = manifest()
    entry = config["platforms"].get(platform_key())
    if entry is None:
        raise ValueError("mdBook installer supports Linux/macOS on x86_64 and aarch64")
    home = ROOT / ".cache/mdbook"
    cache = home / "downloads"
    binary = archive_member(download(entry, cache), "mdbook")
    # Verify every notice before replacing the installed executable.
    for notice in config["notices"].values():
        notice_data(notice, cache)
    target = home / "bin/mdbook"
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".new")
    temporary.write_bytes(binary)
    temporary.chmod(0o755)
    temporary.replace(target)
    print(f"mdBook {config['version']} installed in .cache/mdbook/bin")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
