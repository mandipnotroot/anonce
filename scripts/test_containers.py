# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit checks for local container policy and no-replace secret preparation."""

import copy
import os
from pathlib import Path
import tempfile
import unittest

from containers import EDGE_NETWORKS, INTERNAL_NETWORKS, NETWORKS, PORTS, POSTGRES_IMAGE, ROOT, SECRET_NAMES, check_engine_version, prepare_secrets, validate_config


def model():
    services = {}
    for name, networks in NETWORKS.items():
        application = name in PORTS
        service = {
            "networks": {network: {} for network in networks}, "read_only": True, "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"], "logging": {"driver": "none"}, "cpus": 1,
            "mem_limit": str((128 if application else 512) << 20), "memswap_limit": str((128 if application else 512) << 20),
            "pids_limit": 64 if application else 128, "healthcheck": {"test": ["CMD", "synthetic"]},
            "user": "65532:65532" if application else "999:999",
        }
        if application:
            service.update(ports=[{"host_ip": "127.0.0.1", "target": PORTS[name], "protocol": "tcp"}],
                           command=["-container-network", f"0.0.0.0:{PORTS[name]}"])
        else:
            side = name.removesuffix("-db")
            service.update(image=POSTGRES_IMAGE,
                           secrets=[{"source": f"{side}_{role}", "target": f"{role}_password"} for role in ("admin", "migration", "runtime")],
                           volumes=[{"type": "volume", "source": f"{side}-data", "target": "/var/lib/postgresql"},
                                    {"type": "bind", "source": str(ROOT / "deploy/postgres/bootstrap.sql"),
                                     "target": "/docker-entrypoint-initdb.d/10-bootstrap.sql", "read_only": True}],
                           environment={"POSTGRES_USER": f"{side}_admin", "POSTGRES_DB": side,
                                        "POSTGRES_PASSWORD_FILE": "/run/secrets/admin_password",
                                        "POSTGRES_INITDB_ARGS": "--auth-host=scram-sha-256 --auth-local=trust"})
        services[name] = service
    return {"services": services, "networks": {name: {"name": "synthetic_" + name, "internal": name in INTERNAL_NETWORKS} for name in INTERNAL_NETWORKS | EDGE_NETWORKS},
            "volumes": {name: {"name": "synthetic_" + name} for name in ("identity-data", "submission-data")},
            "secrets": {name: {"file": "/synthetic-secrets/" + name} for name in SECRET_NAMES}}


class ContainerPolicyTests(unittest.TestCase):
    def test_build_context_secret_exclusions_and_license(self):
        patterns = (ROOT / ".dockerignore").read_text().splitlines()
        self.assertIn("**", patterns)
        self.assertIn("!LICENSES/AGPL-3.0-only.txt", patterns)
        for pattern in ("**/.env", "**/.env.*", "**/.secrets/", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.keystore"):
            with self.subTest(pattern=pattern):
                self.assertIn(pattern, patterns)
                self.assertGreater(patterns.index(pattern), patterns.index("!internal/**"))
        self.assertIn("COPY LICENSES/AGPL-3.0-only.txt /licenses/anonce-LICENSE", (ROOT / "Dockerfile").read_text())

    def test_engine_loopback_boundary(self):
        for version in ("28.0.0", "29.9.2", "29.9.2\n", "28.1.0-test"):
            check_engine_version(version)
        for version in ("27.5.0", "5.0.0", "", "unknown", "29", "29.1", "29.0.0 extra"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                check_engine_version(version)

    def test_hardened_normalized_model(self):
        validate_config(model())
        numeric = model()
        for service in numeric["services"].values():
            service["mem_limit"] = int(service["mem_limit"])
            service["memswap_limit"] = int(service["memswap_limit"])
        validate_config(numeric)

    def test_unsafe_models_fail(self):
        changes = [
            ("server", "user", "0:0"), ("identity-db", "user", "0:0"),
            ("server", "ports", [{"host_ip": "0.0.0.0", "target": 8080, "protocol": "tcp"}]),
            ("identity-db", "ports", [{"host_ip": "127.0.0.1", "target": 5432, "protocol": "tcp"}]),
            ("identity-db", "image", "postgres:latest"), ("issuer", "networks", {"submission": {}}),
            ("server", "secrets", [{"source": "identity_admin"}]), ("ca", "volumes", [{"source": "/var/run/docker.sock"}]),
            ("server", "environment", {"PGPASSWORD": "synthetic-input"}),
            ("identity-db", "secrets", [{"source": "submission_admin", "target": "admin_password"}]),
            ("submission-db", "volumes", [{"type": "volume", "source": "identity-data", "target": "/var/lib/postgresql"}]),
            ("identity-db", "environment", {"POSTGRES_PASSWORD": "synthetic-input"}),
            ("server", "read_only", False), ("server", "cap_drop", []), ("server", "cap_add", ["NET_ADMIN"]),
            ("server", "security_opt", []), ("server", "logging", {"driver": "json-file"}),
            ("server", "privileged", True), ("server", "network_mode", "host"), ("server", "devices", ["synthetic"]),
            ("server", "mem_limit", "0"), ("server", "memswap_limit", "-1"), ("server", "cpus", 0),
            ("server", "pids_limit", -1), ("server", "healthcheck", {"test": ["NONE"], "disable": True}),
        ]
        for name, key, value in changes:
            with self.subTest(service=name, key=key):
                config = copy.deepcopy(model())
                config["services"][name][key] = value
                with self.assertRaises((ValueError, KeyError)):
                    validate_config(config)
        for key in ("services", "networks", "volumes", "secrets"):
            with self.subTest(key=key):
                config = model()
                config[key] = {}
                with self.assertRaises((ValueError, KeyError)):
                    validate_config(config)
        config = model()
        config["networks"]["identity"]["internal"] = False
        with self.assertRaises(ValueError):
            validate_config(config)
        for key in ("volumes", "networks"):
            config = model()
            items = list(config[key].values())
            items[0]["name"] = items[1]["name"]
            with self.subTest(alias=key), self.assertRaises(ValueError):
                validate_config(config)
        config = model()
        config["secrets"]["identity_admin"]["file"] = "/synthetic-secrets/submission_admin"
        with self.assertRaises(ValueError):
            validate_config(config)


class ContainerSecretTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / ".cache/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "secrets"

    def test_no_replace_and_distinct_scopes(self):
        prepare_secrets(self.path, create=True)
        before = {name: (self.path / name).read_bytes() for name in SECRET_NAMES}
        self.assertEqual(len(set(before.values())), 6)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o700)
        for name, value in before.items():
            self.assertRegex(value, rb"^[0-9a-f]{64}$")
            self.assertEqual((self.path / name).stat().st_mode & 0o777, 0o444)
        prepare_secrets(self.path, create=True)
        prepare_secrets(self.path)
        self.assertEqual(before, {name: (self.path / name).read_bytes() for name in SECRET_NAMES})

    def test_unsafe_directory(self):
        self.path.mkdir(mode=0o700)
        self.path.chmod(0o755)  # Check final permissions independently of the caller's umask.
        with self.assertRaises(ValueError):
            prepare_secrets(self.path, create=True)
        self.assertEqual(list(self.path.iterdir()), [])
        self.path.chmod(0o700)
        alias = self.path.parent / "alias"
        alias.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError):
            prepare_secrets(alias, create=True)

    def test_missing_malformed_duplicate_and_unsafe_files(self):
        prepare_secrets(self.path, create=True)
        source = self.path / SECRET_NAMES[0]
        original = source.read_bytes()
        for replacement in (b"", b"synthetic-input", b"x" * 64, original + b"\n", (self.path / SECRET_NAMES[1]).read_bytes()):
            with self.subTest(length=len(replacement)):
                source.chmod(0o600)
                source.write_bytes(replacement)
                source.chmod(0o444)
                with self.assertRaises(ValueError):
                    prepare_secrets(self.path)
        source.unlink()
        source.symlink_to(self.path / SECRET_NAMES[1])
        with self.assertRaises(OSError):
            prepare_secrets(self.path)
        source.unlink()
        os.mkfifo(source)
        with self.assertRaises(ValueError):
            prepare_secrets(self.path)
        source.unlink()
        with self.assertRaises(OSError):
            prepare_secrets(self.path)


if __name__ == "__main__":
    unittest.main()
