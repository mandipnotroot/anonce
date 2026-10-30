# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Unit checks for local container policy and no-replace secret preparation."""

import copy
import io
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from containers import EDGE_NETWORKS, INTERNAL_NETWORKS, NETWORKS, PORTS, POSTGRES_IMAGE, ROOT, SECRET_NAMES, Stack, account_checks, application_command, check_engine_version, main, prepare_secrets, validate_config, validate_state


def model():
    services = {}
    for name, networks in NETWORKS.items():
        application = name in PORTS
        service = {
            "networks": {network: {} for network in networks}, "read_only": True, "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"], "logging": {"driver": "none"}, "cpus": 1,
            "mem_limit": str((128 if application else 512) << 20), "memswap_limit": str((128 if application else 512) << 20),
            "pids_limit": 64 if application else 128, "healthcheck": {"test": ["CMD", "synthetic"]},
            "user": "1000:1000" if application else "999:999",
        }
        if application:
            service.update(image="synthetic-browser:local", ports=[{"host_ip": "127.0.0.1", "target": PORTS[name], "published":str(PORTS[name]), "protocol": "tcp"}],
                           command=application_command(name, "https://example.invalid/source"),
                           healthcheck={"test":["CMD", "/app/probe", name]},
                           secrets=[{"source":f"{name}_runtime", "target":"runtime_password"}],
                           volumes=[{"type":"bind", "source":f"/synthetic-state/{name}", "target":"/state", "read_only":True,
                                     "bind":{"create_host_path":False}}])
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
        dockerfile = (ROOT / "Dockerfile").read_text()
        self.assertIn('CMD ["/app/browser-identity"]',dockerfile)
        self.assertNotIn("./cmd/client",dockerfile)
        self.assertNotIn("./cmd/server",dockerfile)
        makefile = (ROOT / "Makefile").read_text()
        default = makefile.split("build: member-wasm\n",1)[1].split(".PHONY: dev-tools",1)[0]
        self.assertIn("./cmd/browser-identity ./cmd/browser-submission",default)
        self.assertNotIn("./cmd/client",default)
        self.assertNotIn("./cmd/server",default)

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
            ("submission", "user", "0:0"), ("identity-db", "user", "0:0"),
            ("submission", "ports", [{"host_ip": "0.0.0.0", "target": 8444, "protocol": "tcp"}]),
            ("identity-db", "ports", [{"host_ip": "127.0.0.1", "target": 5432, "protocol": "tcp"}]),
            ("identity-db", "image", "postgres:latest"), ("identity", "networks", {"submission": {}}),
            ("submission", "secrets", [{"source": "identity_admin", "target":"runtime_password"}]), ("identity", "volumes", [{"source": "/var/run/docker.sock"}]),
            ("submission", "environment", {"PGPASSWORD": "synthetic-input"}),
            ("identity-db", "secrets", [{"source": "submission_admin", "target": "admin_password"}]),
            ("submission-db", "volumes", [{"type": "volume", "source": "identity-data", "target": "/var/lib/postgresql"}]),
            ("identity-db", "environment", {"POSTGRES_PASSWORD": "synthetic-input"}),
            ("submission", "read_only", False), ("submission", "cap_drop", []), ("submission", "cap_add", ["NET_ADMIN"]),
            ("submission", "security_opt", []), ("submission", "logging", {"driver": "json-file"}),
            ("submission", "privileged", True), ("submission", "network_mode", "host"), ("submission", "devices", ["synthetic"]),
            ("submission", "mem_limit", "0"), ("submission", "memswap_limit", "-1"), ("submission", "cpus", 0),
            ("submission", "pids_limit", -1), ("submission", "healthcheck", {"test": ["NONE"], "disable": True}),
            ("identity", "command", application_command("submission", "https://example.invalid/source")),
            ("identity", "volumes", [{"type":"bind", "source":"/synthetic-state/submission", "target":"/state", "read_only":True}]),
            ("identity", "secrets", [{"source":"identity_migration", "target":"runtime_password"}]),
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


class MigrationOperatorTests(unittest.TestCase):
    def test_one_shot_operator_scope_and_cleanup(self):
        for side in ("identity", "submission"):
            with self.subTest(side=side):
                stack = Stack(env={})
                calls = []

                def run(args, **kwargs):
                    calls.append((args, kwargs))
                    return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

                with patch.object(stack, "config", return_value=model()), patch.object(stack, "run", side_effect=run):
                    stack.migrate(side, "sha256:" + "a" * 64)
                command, settings = calls[0]
                self.assertEqual(command[:3], ["docker", "run", "--rm"])
                self.assertEqual(command[command.index("--network") + 1], "synthetic_" + side)
                self.assertEqual(command[command.index("--mount") + 1],
                                 f"type=bind,src=/synthetic-secrets/{side}_migration,dst=/run/secrets/migration_password,readonly")
                for expected in ("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                                 "--memory", "128m", "--memory-swap", "--pids-limit", "64", "--user", "65532:65532",
                                 "--log-driver", "none"):
                    self.assertIn(expected, command)
                self.assertNotIn("--publish", command)
                self.assertNotIn("--env", command)
                self.assertEqual(command[-1], side)
                self.assertEqual(settings["timeout"], 90)
                self.assertEqual(calls[1][0], ["docker", "rm", "--force", command[command.index("--name") + 1]])

    def test_failures_and_invalid_targets(self):
        stack = Stack(env={})
        with patch.object(stack, "config", return_value=model()), patch.object(stack, "run") as run:
            for side in ("", "../identity", "postgres", "Identity"):
                with self.subTest(side=side), self.assertRaises(ValueError):
                    stack.migrate(side, "synthetic")
            run.assert_not_called()
            run.side_effect = [RuntimeError("synthetic failure"), SimpleNamespace(returncode=0)]
            with self.assertRaises(RuntimeError):
                stack.migrate("identity", "synthetic")
            self.assertEqual(run.call_args_list[-1].args[0][:3], ["docker", "rm", "--force"])


class AccountOperatorTests(unittest.TestCase):
    def test_submission_record_runtime_scope(self):
        stack = Stack(env={})
        with patch.object(stack, "config", return_value=model()), patch.object(stack, "migration_image", return_value="synthetic") as build, \
                patch.object(stack, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                patch.object(stack, "sql", return_value=SimpleNamespace(stdout=b"t\n")) as sql:
            account_checks(stack, "submission-record-test")
            build.assert_called_once_with("submission-record-test")
            self.assertEqual(run.call_count, 4)
            self.assertEqual(sql.call_count, 2)
            for index, side in enumerate(("identity", "submission")):
                command = run.call_args_list[index * 2].args[0]
                self.assertEqual(command[command.index("--network") + 1], "synthetic_" + side)
                self.assertEqual(command[command.index("--mount") + 1],
                                 f"type=bind,src=/synthetic-secrets/{side}_runtime,dst=/run/secrets/runtime_password,readonly")
        patterns = (ROOT / ".dockerignore").read_text().splitlines()
        for source in ("store_test.go", "postgres_test.go"):
            self.assertGreater(patterns.index("!internal/submission/records/" + source), patterns.index("**/*_test.go"))
        self.assertIn("test -x /out/submissionrecords.test", (ROOT / "Dockerfile").read_text())

    def test_member_backup_runtime_scope(self):
        stack = Stack(env={})
        with patch.object(stack, "config", return_value=model()), patch.object(stack, "migration_image", return_value="synthetic") as build, \
                patch.object(stack, "run", return_value=SimpleNamespace(returncode=0)) as run, \
                patch.object(stack, "sql", return_value=SimpleNamespace(stdout=b"t\n")):
            account_checks(stack, "member-backup-test")
            build.assert_called_once_with("member-backup-test")
            self.assertEqual(run.call_count, 4)
            for index, side in enumerate(("identity", "submission")):
                command = run.call_args_list[index * 2].args[0]
                self.assertEqual(command[command.index("--network") + 1], "synthetic_" + side)
                self.assertEqual(command[command.index("--mount") + 1],
                                 f"type=bind,src=/synthetic-secrets/{side}_runtime,dst=/run/secrets/runtime_password,readonly")
        patterns = (ROOT / ".dockerignore").read_text().splitlines()
        for source in ("store_test.go", "postgres_test.go"):
            self.assertGreater(patterns.index("!internal/identity/memberbackup/" + source), patterns.index("**/*_test.go"))
        self.assertIn("test -x /out/memberbackup.test", (ROOT / "Dockerfile").read_text())

    def test_runtime_scopes_and_cleanup(self):
        stack = Stack(env={})
        calls = []

        def run(args, **kwargs):
            calls.append((args, kwargs))
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

        with patch.object(stack, "config", return_value=model()), patch.object(stack, "migration_image", return_value="synthetic"), \
                patch.object(stack, "run", side_effect=run), patch.object(stack, "sql", return_value=SimpleNamespace(stdout=b"t\n")):
            account_checks(stack)
        self.assertEqual(len(calls), 4)
        for index, side in enumerate(("identity", "submission")):
            command, settings = calls[index * 2]
            self.assertEqual(command[command.index("--network") + 1], "synthetic_" + side)
            self.assertEqual(command[command.index("--env") + 1], f"ANONCE_TEST_SIDE={side}")
            self.assertEqual(command[command.index("--mount") + 1],
                             f"type=bind,src=/synthetic-secrets/{side}_runtime,dst=/run/secrets/runtime_password,readonly")
            self.assertEqual(command.count("--mount"), 1)
            self.assertNotIn("--publish", command)
            for expected in ("--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                             "--log-driver", "none", "--user", "65532:65532", "--memory", "512m"):
                self.assertIn(expected, command)
            self.assertTrue(settings["stream"])
            self.assertEqual(calls[index * 2 + 1][0], ["docker", "rm", "--force", command[command.index("--name") + 1]])

    def test_failure_cleanup_and_build_admission(self):
        stack = Stack(env={})
        with patch.object(stack, "config", return_value=model()), patch.object(stack, "migration_image", return_value="synthetic"), \
                patch.object(stack, "run", side_effect=[RuntimeError("synthetic failure"), SimpleNamespace(returncode=0)]) as run:
            with self.assertRaises(RuntimeError):
                account_checks(stack)
            self.assertEqual(run.call_args_list[-1].args[0][:3], ["docker", "rm", "--force"])
        with patch.object(stack, "run") as run:
            with self.assertRaises(ValueError):
                stack.migration_image("unrecognized")
            run.assert_not_called()
        patterns = (ROOT / ".dockerignore").read_text().splitlines()
        for source in (
            "store_test.go", "postgres_test.go", "selected_session_test.go",
            "selected_session_postgres_test.go", "all_sessions_test.go",
            "all_sessions_postgres_test.go",
            "session_disable_test.go", "session_disable_postgres_test.go",
        ):
            self.assertGreater(patterns.index("!internal/identity/accounts/" + source), patterns.index("**/*_test.go"))
        self.assertIn("test -x /out/account.test", (ROOT / "Dockerfile").read_text())


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


class BrowserStateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state"
        self.path.mkdir(mode=0o700)
        for side, names in (("identity", ("tls.crt", "tls.key", "receipt.pub", "bulletin.seed", "membership.seed", "membership.der", "administrator-invitation")),
                            ("submission", ("tls.crt", "tls.key", "receipt.seed", "bulletin.pub"))):
            directory = self.path / side
            directory.mkdir(mode=0o700)
            for name in names:
                (directory / name).write_bytes(b"synthetic non-key data")
                (directory / name).chmod(0o600)
        (self.path / "local-root.crt").write_bytes(b"synthetic public certificate")
        (self.path / "local-root.crt").chmod(0o600)

    def test_retains_keys_and_adds_only_public_trust_copies(self):
        before = {str(path.relative_to(self.path)):path.read_bytes() for path in self.path.rglob("*") if path.is_file()}
        validate_state(self.path)
        validate_state(self.path)
        for name, data in before.items():
            self.assertEqual((self.path / name).read_bytes(),data)
        for side in ("identity", "submission"):
            self.assertEqual((self.path / side / "local-root.crt").read_bytes(),before["local-root.crt"])

    def test_incomplete_state_is_not_reinitialized(self):
        (self.path / "identity/membership.seed").unlink()
        with self.assertRaises(ValueError):
            validate_state(self.path)
        self.assertFalse((self.path / "identity/membership.seed").exists())

    def test_unsafe_state_files_and_public_copy_changes(self):
        validate_state(self.path)
        source = self.path / "identity/tls.key"
        source.chmod(0o644)
        with self.assertRaises(ValueError):
            validate_state(self.path)
        source.chmod(0o600)
        source.unlink()
        source.symlink_to(self.path / "identity/membership.seed")
        with self.assertRaises(OSError):
            validate_state(self.path)
        source.unlink()
        os.mkfifo(source,mode=0o600)
        with self.assertRaises(ValueError):
            validate_state(self.path)

    def test_new_state_refuses_an_existing_browser_database(self):
        with tempfile.TemporaryDirectory() as directory:
            config = model()
            for side in ("identity", "submission"):
                config["services"][side]["volumes"][0]["source"] = str(Path(directory) / "state" / side)
            stack = Stack(env={})
            with patch.object(stack,"config",return_value=config), patch.object(stack,"sql",return_value=SimpleNamespace(stdout=b"t\n")), patch.object(stack,"run") as run:
                with self.assertRaises(ValueError):
                    stack.initialize("synthetic")
                run.assert_not_called()
                self.assertEqual(list((Path(directory) / "state").iterdir()),[])


class BrowserStartupTests(unittest.TestCase):
    def test_default_actions_use_the_compose_selected_secret_directory(self):
        for action in ("up","smoke","migrate-identity"):
            with self.subTest(action=action):
                stack = Mock()
                stack.config.return_value = model()
                stack.run.return_value = SimpleNamespace(stdout=b"29.9.2\n")
                with patch("containers.Stack",return_value=stack), patch("sys.argv",["containers.py",action]), \
                        patch("containers.prepare_secrets") as prepare, patch("sys.stdout",new=io.StringIO()):
                    main()
                if action == "migrate-identity":
                    prepare.assert_called_once_with(Path("/synthetic-secrets"))
                else:
                    prepare.assert_called_once_with(Path("/synthetic-secrets"),create=action=="up")
                if action == "up":
                    stack.start.assert_called_once_with()

    def test_migration_and_initialization_order(self):
        stack = Stack(env={})
        calls = []

        def compose(*args, **kwargs):
            calls.append(args)
            return SimpleNamespace(stdout=b"",returncode=0)

        with patch.object(stack,"config",return_value=model()), patch.object(stack,"compose",side_effect=compose), \
                patch.object(stack,"run",return_value=SimpleNamespace(stdout=("sha256:"+"a"*64).encode())), \
                patch.object(stack,"migration_image",return_value="migration"), \
                patch.object(stack,"migrate",side_effect=lambda side,image:calls.append(("migrate",side))), \
                patch.object(stack,"initialize",side_effect=lambda image:calls.append(("initialize",))):
            stack.start()
        self.assertLess(calls.index(("stop","identity","submission")),calls.index(("migrate","identity")))
        self.assertLess(calls.index(("migrate","submission")),calls.index(("initialize",)))
        app_start = next(index for index,args in enumerate(calls) if args[0]=="up" and args[-2:]==("identity","submission"))
        self.assertLess(calls.index(("initialize",)),app_start)

    def test_legacy_services_are_not_silently_retained_or_removed(self):
        stack = Stack(env={})
        with patch.object(stack,"config",return_value=model()), patch.object(stack,"compose",return_value=SimpleNamespace(stdout=b"server\n")) as compose:
            with self.assertRaises(ValueError):
                stack.start()
            compose.assert_called_once_with("ps","--all","--services")
if __name__ == "__main__":
    unittest.main()
