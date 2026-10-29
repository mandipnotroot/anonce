#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Local Compose lifecycle and explicit, real-container infrastructure checks."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
POSTGRES_IMAGE = "postgres:18.6-bookworm@sha256:5c4783a8cc3f0074912164f94dfa1be4e043438f0f707cf968d7af9a0d31a2c8"
INTERNAL_NETWORKS = {"identity", "submission", "signer"}
EDGE_NETWORKS = {"server-edge", "issuer-edge", "ca-edge"}
NETWORKS = {"server": {"submission", "server-edge"}, "issuer": {"identity", "signer", "issuer-edge"}, "ca": {"signer", "ca-edge"},
            "identity-db": {"identity"}, "submission-db": {"submission"}}
PORTS = {"server": 8080, "issuer": 8081, "ca": 8082}
SECRET_NAMES = tuple(f"{side}_{role}" for side in ("identity", "submission") for role in ("admin", "migration", "runtime"))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_engine_version(version):
    match = re.fullmatch(r"([0-9]+)\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?", version.strip())
    require(match is not None and int(match[1]) >= 28, "Docker Engine 28 or newer is required for loopback port publication")


def secret_directory(path, create=False):
    """Pin an owner-only directory; individual read-only bind secrets use 0444."""
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise ValueError("database secret directory must be owned by this user with mode 0700")
    return fd


def prepare_secrets(path, create=False):
    fd = secret_directory(path, create)
    try:
        values = []
        for name in SECRET_NAMES:
            if create:
                try:
                    output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=fd)
                except FileExistsError:
                    pass  # Validate, never replace a previously generated password.
                else:
                    with os.fdopen(output, "wb") as handle:
                        handle.write(secrets.token_hex(32).encode("ascii"))
                        handle.flush()
                        os.fsync(handle.fileno())
                        os.fchmod(handle.fileno(), 0o444)
            source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(source, "rb") as handle:
                info = os.fstat(handle.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_size == 64 and info.st_uid == os.getuid() and
                        stat.S_IMODE(info.st_mode) == 0o444, "invalid database secret file metadata")
                value = handle.read(65)
            require(re.fullmatch(rb"[0-9a-f]{64}", value) is not None, "invalid database secret encoding")
            values.append(value)
        require(not any(secrets.compare_digest(value, previous) for index, value in enumerate(values) for previous in values[:index]),
                "database passwords must all be distinct")
        if create:
            os.fsync(fd)
    finally:
        os.close(fd)


def validate_config(config):
    """Check the real Compose parser's normalized model, without contacting Docker."""
    services = config["services"]
    require(set(services) == set(NETWORKS), "unexpected Compose service set")
    require(set(config["networks"]) == INTERNAL_NETWORKS | EDGE_NETWORKS and
            all(item.get("internal", False) == (name in INTERNAL_NETWORKS) for name, item in config["networks"].items()),
            "database/signer networks must be internal with separate application edge networks")
    require(set(config["volumes"]) == {"identity-data", "submission-data"}, "database volumes must remain distinct")
    require(len({item["name"] for item in config["volumes"].values()}) == 2 and
            all(not item.get("external") and not item.get("driver_opts") for item in config["volumes"].values()),
            "database volumes must not alias shared or external storage")
    require(set(config["secrets"]) == set(SECRET_NAMES), "unexpected database secret set")
    require(all(Path(item["file"]).name == name for name, item in config["secrets"].items()) and
            len({str(Path(item["file"]).parent) for item in config["secrets"].values()}) == 1, "invalid database secret file mapping")
    require(len({item["name"] for item in config["networks"].values()}) == len(INTERNAL_NETWORKS | EDGE_NETWORKS), "network names overlap")
    for name, service in services.items():
        require(set(service["networks"]) == NETWORKS[name], "unexpected service network attachment")
        require(service.get("read_only") is True and service.get("cap_drop") == ["ALL"] and not service.get("cap_add") and
                "no-new-privileges:true" in service.get("security_opt", []), "missing container hardening")
        require(not service.get("privileged") and not service.get("network_mode") and not service.get("devices"), "unsafe container privilege")
        require(service.get("logging", {}).get("driver") == "none", "container logging must be disabled")
        memory, processes = (128 << 20, 64) if name in PORTS else (512 << 20, 128)
        require(service.get("cpus") == 1 and int(service.get("mem_limit", 0)) == memory and
                int(service.get("memswap_limit", 0)) == memory and service.get("pids_limit") == processes,
                "missing CPU, memory, swap, or process bound")
        require(service.get("healthcheck", {}).get("test") and not service["healthcheck"].get("disable"), "missing container healthcheck")
        if name in PORTS:
            require(service.get("user") == "65532:65532" and not service.get("volumes") and not service.get("secrets") and
                    not service.get("environment"), "application image must not receive database secrets or host mounts")
            ports = service.get("ports", [])
            require(len(ports) == 1 and ports[0]["host_ip"] == "127.0.0.1" and ports[0]["target"] == PORTS[name] and
                    ports[0]["protocol"] == "tcp", "application ports must publish only on IPv4 loopback")
            require("-container-network" in service["command"] and f"0.0.0.0:{PORTS[name]}" in service["command"], "invalid container bind opt-in")
        else:
            side = name.removesuffix("-db")
            require(service.get("image") == POSTGRES_IMAGE and service.get("user") == "999:999" and not service.get("ports"),
                    "database image, user, or port isolation changed")
            require({(item["source"], item["target"]) for item in service.get("secrets", [])} ==
                    {(f"{side}_{role}", f"{role}_password") for role in ("admin", "migration", "runtime")},
                    "database secret scopes overlap")
            volumes = service["volumes"]
            require(len(volumes) == 2 and any(item.get("type") == "volume" and item.get("source") == f"{side}-data" and
                    item.get("target") == "/var/lib/postgresql" for item in volumes), "invalid PostgreSQL 18 volume layout")
            require(any(item.get("type") == "bind" and item.get("read_only") is True and
                    item.get("source") == str(ROOT / "deploy/postgres/bootstrap.sql") and
                    item.get("target") == "/docker-entrypoint-initdb.d/10-bootstrap.sql" for item in volumes), "invalid database bootstrap mount")
            env = service["environment"]
            require(env.get("POSTGRES_USER") == f"{side}_admin" and env.get("POSTGRES_DB") == side and
                    env.get("POSTGRES_PASSWORD_FILE") == "/run/secrets/admin_password" and "POSTGRES_PASSWORD" not in env and
                    env.get("POSTGRES_INITDB_ARGS") == "--auth-host=scram-sha-256 --auth-local=trust", "unsafe database authentication configuration")


class Stack:
    def __init__(self, env=None, project=None):
        self.env = dict(os.environ if env is None else env)
        self.base = ["docker", "compose", "--file", str(ROOT / "compose.yaml")]
        if project:
            self.base.extend(["--project-name", project])

    def run(self, args, *, data=None, success=True, timeout=120, stream=False):
        result = subprocess.run(args, cwd=ROOT, env=self.env, input=data, stdout=None if stream else subprocess.PIPE,
                                stderr=None if stream else subprocess.PIPE, timeout=timeout, check=False)
        if success and result.returncode:
            raise RuntimeError("container command failed; check Docker daemon access and local Compose configuration")
        return result

    def compose(self, *args, **kwargs):
        if args and args[0] == "up":
            kwargs["stream"] = True  # Preserve build/startup diagnostics, never SQL/password output.
        return self.run([*self.base, *args], **kwargs)

    def config(self):
        config = json.loads(self.compose("config", "--format", "json").stdout)
        validate_config(config)
        return config

    def sql(self, side, role, query, *, allowed=True, host="127.0.0.1", database=None, credential=None):
        require(side in ("identity", "submission") and role in ("runtime", "migrator"), "invalid database check target")
        credential = credential or ("migration" if role == "migrator" else "runtime")
        require(credential in ("runtime", "migration"), "invalid database credential scope")
        # Passwords stay in container files, never shell variables, arguments, or output.
        script = r'''umask 077
passfile=$(mktemp /tmp/anonce-pgpass.XXXXXX)
trap 'rm -f "$passfile"' EXIT HUP INT TERM
printf '*:5432:*:anonce_%s:' "$1" > "$passfile"
cat "/run/secrets/$4"_password >> "$passfile"
printf '\n' >> "$passfile"
PGPASSFILE="$passfile" PGCONNECT_TIMEOUT=3 psql -XwqAt -v ON_ERROR_STOP=1 -v VERBOSITY=sqlstate -h "$2" -U "anonce_$1" -d "$3"
'''
        result = self.compose("exec", "-T", f"{side}-db", "sh", "-eu", "-c", script, "--", role, host, database or side, credential,
                              data=query.encode(), success=False)
        require(result.returncode == 0 if allowed else result.returncode != 0, "database privilege/authentication expectation failed")
        return result

    def smoke(self):
        config = self.config()
        instances = {}
        for name in NETWORKS:
            ids = self.compose("ps", "--all", "--quiet", name).stdout.decode().splitlines()
            require(len(ids) == 1, "expected one running container per service")
            item, = json.loads(self.run(["docker", "inspect", ids[0]]).stdout)
            require(item["State"]["Running"] and item["State"].get("Health", {}).get("Status") == "healthy", "container is not healthy")
            host = item["HostConfig"]
            require(host["ReadonlyRootfs"] and host["LogConfig"]["Type"] == "none" and not host["Privileged"] and
                    item["Config"]["User"] == config["services"][name]["user"] and set(host["CapDrop"]) == {"ALL"}, "running container hardening differs")
            require("no-new-privileges:true" in host["SecurityOpt"] and host["NanoCpus"] == 1_000_000_000 and
                    host["Memory"] == int(config["services"][name]["mem_limit"]) and host["MemorySwap"] == host["Memory"] and
                    host["PidsLimit"] == config["services"][name]["pids_limit"], "running container resource bounds differ")
            require(set(item["NetworkSettings"]["Networks"]) == {config["networks"][network]["name"] for network in NETWORKS[name]},
                    "unexpected live network attachment")
            instances[name] = item
            if name not in PORTS:
                require(not host["PortBindings"], "database port was published")
                side = name.removesuffix("-db")
                require(any(mount.get("Type") == "volume" and mount.get("Name") == config["volumes"][f"{side}-data"]["name"] and
                            mount.get("Destination") == "/var/lib/postgresql" for mount in item["Mounts"]), "live database volume differs")
                continue
            require(not item["Mounts"], "application container received host mounts or secrets")
            bindings = item["NetworkSettings"]["Ports"][f"{PORTS[name]}/tcp"]
            require(bindings is not None and len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1", "missing or non-loopback published endpoint")
            connection = http.client.HTTPConnection("127.0.0.1", int(bindings[0]["HostPort"]), timeout=5)
            try:
                for path, status in (("/healthz", 200), ("/readyz", 503), ("/api/v1/status", 200), ("/source", 302)):
                    connection.request("GET", path)
                    response = connection.getresponse()
                    body = response.read(8193)
                    require(response.status == status and len(body) <= 8192 and response.getheader("Cache-Control") == "no-store" and
                            response.getheader("Set-Cookie") is None, "invalid demonstration HTTP response")
                    if path == "/healthz":
                        require(body == b"ok", "invalid liveness response")
                    if path == "/api/v1/status":
                        require(json.loads(body)["demonstration"] is True, "container claims product readiness")
                    if path == "/source":
                        command = config["services"][name]["command"]
                        require(response.getheader("Location") == command[command.index("-source-url") + 1], "incorrect source discovery")
            finally:
                connection.close()
        require(not (set(instances["identity-db"]["NetworkSettings"]["Networks"]) &
                     set(instances["submission-db"]["NetworkSettings"]["Networks"])), "database networks overlap")
        for name, network in config["networks"].items():
            live, = json.loads(self.run(["docker", "network", "inspect", network["name"]]).stdout)
            require(live["Internal"] == (name in INTERNAL_NETWORKS), "live network routing differs")
        for side in ("identity", "submission"):
            result = self.sql(side, "runtime", "SELECT current_user, current_database(), has_database_privilege(current_user, current_database(), 'CREATE'), has_database_privilege(current_user, current_database(), 'TEMP'), has_schema_privilege(current_user, 'anonce', 'CREATE');")
            require(result.stdout.strip() == f"anonce_runtime|{side}|f|f|f".encode(), "runtime database privileges differ")
        return instances

    def migration_image(self, target="migration"):
        require(target in ("migration", "account-test"), "invalid database image target")
        image = self.run(["docker", "build", "--target", target, "--quiet", "."], timeout=600).stdout.decode().strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None, "invalid migration image identity")
        return image

    def migrate(self, side, image, *, allowed=True, database_side=None):
        require(side in ("identity", "submission"), "invalid migration service")
        database_side = database_side or side
        require(database_side in ("identity", "submission"), "invalid migration database")
        config = self.config()
        secret = config["secrets"][f"{database_side}_migration"]["file"]
        name = "anonce-migrate-" + secrets.token_hex(6)
        args = ["docker", "run", "--rm", "--name", name, "--network", config["networks"][database_side]["name"],
                "--network-alias", "migration-operator", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", "--log-driver", "none", "--cpus", "1",
                "--memory", "128m", "--memory-swap", "128m", "--pids-limit", "64",
                "--mount", f"type=bind,src={secret},dst=/run/secrets/migration_password,readonly", image, side]
        try:
            result = self.run(args, success=False, timeout=90)
            require((result.returncode == 0) == allowed, "database migration expectation failed")
            return result
        finally:
            # Only this invocation's randomly named operator container is eligible.
            self.run(["docker", "rm", "--force", name], success=False)


def database_checks(stack, instances):
    for side, other in (("identity", "submission"), ("submission", "identity")):
        failed_login = stack.sql(side, "runtime", "SELECT 1;", allowed=False, credential="migration")
        require(b"password authentication failed" in failed_login.stderr, "wrong-password authentication did not fail as expected")
        result = stack.sql(side, "runtime", "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, pg_has_role(current_user, 'anonce_owner', 'MEMBER') FROM pg_roles WHERE rolname = current_user;")
        require(result.stdout.strip() == b"f|f|f|f|f|f", "runtime role can escalate")
        result = stack.sql(side, "migrator", "CREATE TABLE anonce.without_owner(id integer);", allowed=False)
        require(b"42501" in result.stderr, "migration login inherited ownership without SET ROLE")
        result = stack.sql(side, "runtime", "SELECT 1;", allowed=False, database="postgres")
        require(b"permission denied for database" in result.stderr, "runtime accessed the default maintenance database")
        for query in ("SET ROLE anonce_owner;", "CREATE SCHEMA forbidden;", "CREATE TEMP TABLE forbidden(id integer);",
                      "CREATE TABLE public.forbidden(id integer);", "SELECT pg_read_file('/run/secrets/admin_password');"):
            result = stack.sql(side, "runtime", query, allowed=False)
            require(b"42501" in result.stderr, "privilege denial did not report insufficient privilege")
        stack.sql(side, "migrator", "SET ROLE anonce_owner; CREATE TABLE anonce.container_probe(id integer PRIMARY KEY); CREATE FUNCTION anonce.container_probe_function() RETURNS integer LANGUAGE sql AS 'SELECT 1';")
        for query in ("SELECT * FROM anonce.container_probe;", "SELECT anonce.container_probe_function();", "ALTER TABLE anonce.container_probe ADD COLUMN forbidden integer;"):
            result = stack.sql(side, "runtime", query, allowed=False)
            require(b"42501" in result.stderr, "owner-only object was accessible")
        stack.sql(side, "migrator", "SET ROLE anonce_owner; GRANT SELECT, INSERT ON anonce.container_probe TO anonce_runtime;")
        result = stack.sql(side, "runtime", "INSERT INTO anonce.container_probe VALUES (1); SELECT id FROM anonce.container_probe;")
        require(result.stdout.strip() == b"1", "explicit runtime grant failed")
        # A real TCP connection to the opposite instance must fail using this side's credential.
        network, = instances[f"{other}-db"]["NetworkSettings"]["Networks"].values()
        stack.sql(side, "runtime", "SELECT 1;", allowed=False, host=network["IPAddress"], database=other)


def migration_checks(stack):
    image = stack.migration_image()
    for side, other in (("identity", "submission"), ("submission", "identity")):
        table = f"anonce.{side}_schema_version"
        # A failed migration must not record success. The conflicting table is
        # synthetic and exists only in this invocation's disposable database.
        stack.sql(side, "migrator", "SET ROLE anonce_owner; CREATE TABLE anonce.storage_boundary(id integer);")
        stack.migrate(side, image, allowed=False)
        result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table};")
        require(result.stdout.strip() == b"0", "failed migration advanced history")
        stack.sql(side, "migrator", "SET ROLE anonce_owner; DROP TABLE anonce.storage_boundary;")
        if side == "identity":
            # Version 1 may already be published. A version-2 failure must leave
            # its history intact and roll back all new application objects.
            stack.sql(side, "migrator", "SET ROLE anonce_owner; CREATE TABLE anonce.account_sessions(id integer);")
            stack.migrate(side, image, allowed=False)
            result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table} ORDER BY id; SELECT to_regclass('anonce.accounts') IS NULL;")
            require(result.stdout.strip() == b"0\n1\nt", "failed account migration changed published state")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; DROP TABLE anonce.account_sessions;")
        # Simultaneous first applications exercise the actual locked Go runner.
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: stack.migrate(side, image), range(2)))
        stack.migrate(side, image)  # Already-current application is idempotent.
        result = stack.sql(side, "runtime", "SELECT service FROM anonce.storage_boundary;")
        require(result.stdout.strip() == side.encode(), "wrong storage boundary")
        result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table} ORDER BY id;")
        latest = 2 if side == "identity" else 1
        require(result.stdout.strip() == (b"0\n1\n2" if side == "identity" else b"0\n1"), "unexpected migration history")
        result = stack.sql(side, "migrator", "SET ROLE anonce_owner; SELECT bool_and(tableowner = 'anonce_owner') FROM pg_tables WHERE schemaname = 'anonce';")
        require(result.stdout.strip() == b"t", "migration objects have the wrong owner")
        for query in (f"SELECT * FROM {table};", f"DELETE FROM {table};", "DELETE FROM anonce.storage_boundary;",
                      "INSERT INTO anonce.storage_boundary VALUES (true, 'identity');", "ALTER TABLE anonce.storage_boundary ADD COLUMN forbidden integer;"):
            denied = stack.sql(side, "runtime", query, allowed=False)
            require(b"42501" in denied.stderr, "runtime accessed owner-only migration state")
        # The other history must not appear even in an identically named schema.
        result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT to_regclass('anonce.{other}_schema_version') IS NULL;")
        require(result.stdout.strip() == b"t", "service migration histories overlap")
        stack.migrate(other, image, allowed=False, database_side=side)
        # Reject future, duplicate, missing-baseline, and down-version records.
        for change, repair in (
            (f"INSERT INTO {table}(version_id, is_applied) VALUES ({latest + 1}, true)", f"DELETE FROM {table} WHERE version_id = {latest + 1}"),
            (f"INSERT INTO {table}(version_id, is_applied) VALUES (1, true)", f"DELETE FROM {table} WHERE id = (SELECT max(id) FROM {table})"),
            (f"UPDATE {table} SET is_applied = false WHERE version_id = 1", f"UPDATE {table} SET is_applied = true WHERE version_id = 1"),
            (f"UPDATE {table} SET version_id = -1 WHERE version_id = 0", f"UPDATE {table} SET version_id = 0 WHERE version_id = -1"),
        ):
            stack.sql(side, "migrator", "SET ROLE anonce_owner; " + change + ";")
            stack.migrate(side, image, allowed=False)
            stack.sql(side, "migrator", "SET ROLE anonce_owner; " + repair + ";")
        if side == "identity":
            swap = f"UPDATE {table} SET version_id = 3 - version_id WHERE version_id IN (1, 2);"
            stack.sql(side, "migrator", "SET ROLE anonce_owner; " + swap)
            stack.migrate(side, image, allowed=False)
            stack.sql(side, "migrator", "SET ROLE anonce_owner; " + swap)
            stack.sql(side, "migrator", f"SET ROLE anonce_owner; UPDATE {table} SET version_id = 2 WHERE version_id = 1;")
            stack.migrate(side, image, allowed=False)
            stack.sql(side, "migrator", f"SET ROLE anonce_owner; UPDATE {table} SET version_id = 1 WHERE version_id = 2 AND id = (SELECT min(id) FROM {table} WHERE version_id = 2);")
        stack.sql(side, "migrator", "SET ROLE anonce_owner; DELETE FROM anonce.storage_boundary;")
        stack.migrate(side, image, allowed=False)
        stack.sql(side, "migrator", f"SET ROLE anonce_owner; INSERT INTO anonce.storage_boundary VALUES (true, '{side}');")
        stack.migrate(side, image)


def account_checks(stack):
    image = stack.migration_image("account-test")
    config = stack.config()
    for side in ("identity", "submission"):
        secret = config["secrets"][f"{side}_runtime"]["file"]
        name = "anonce-accounts-" + secrets.token_hex(6)
        args = ["docker", "run", "--rm", "--name", name, "--network", config["networks"][side]["name"],
                "--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                "--log-driver", "none", "--cpus", "1", "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "128",
                "--env", f"ANONCE_TEST_SIDE={side}",
                "--mount", f"type=bind,src={secret},dst=/run/secrets/runtime_password,readonly", image]
        try:
            stack.run(args, timeout=120, stream=True)
        finally:
            stack.run(["docker", "rm", "--force", name], success=False)
    result = stack.sql("submission", "migrator", "SET ROLE anonce_owner; SELECT to_regclass('anonce.accounts') IS NULL AND to_regclass('anonce.account_sessions') IS NULL;")
    require(result.stdout.strip() == b"t", "identity account tables entered submission storage")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("secrets", "config", "up", "down", "smoke", "test", "migration-test", "account-test", "migrate-identity", "migrate-submission"))
    action = parser.parse_args().action
    directory = Path(os.environ.get("ANONCE_SECRETS_DIR", ROOT / ".secrets"))
    if action == "secrets":
        prepare_secrets(directory, create=True)
        print("Local database secrets prepared without replacing existing files.")
        return
    stack = Stack()
    if action == "config":
        stack.config()
        print("Compose configuration checks passed; no container execution.")
        return
    check_engine_version(stack.run(["docker", "info", "--format", "{{.ServerVersion}}"]).stdout.decode())
    if action in ("test", "migration-test", "account-test"):
        scratch = ROOT / ".cache/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="containers-", dir=scratch) as temporary:
            directory = Path(temporary) / "secrets"
            prepare_secrets(directory, create=True)
            env = dict(os.environ, ANONCE_SECRETS_DIR=str(directory), ANONCE_SOURCE_URL="https://source.example.invalid/anonce/test.tar.gz",
                       ANONCE_SERVER_PORT="0", ANONCE_ISSUER_PORT="0", ANONCE_CA_PORT="0")
            isolated = Stack(env, project="anonce-test-" + secrets.token_hex(6))
            isolated.config()
            try:
                isolated.compose("up", "--build", "--wait", "--wait-timeout", "120", timeout=600)
                database_checks(isolated, isolated.smoke())
                if action in ("migration-test", "account-test"):
                    migration_checks(isolated)
                if action == "account-test":
                    account_checks(isolated)
            finally:
                # Remove only this invocation's fresh disposable project and volumes.
                isolated.compose("down", "--volumes", "--remove-orphans")
        print("Real container liveness, isolation, PostgreSQL authentication and privilege checks passed.")
        if action in ("migration-test", "account-test"):
            print("Separate database migration, concurrency, failure, version and grant checks passed; full db-test remains unavailable.")
        if action == "account-test":
            print("Account/session persistence, expiry, revocation, concurrent disable, cancellation and runtime grant checks passed; browser authentication remains unavailable.")
        return
    if action.startswith("migrate-"):
        prepare_secrets(directory)
        stack.config()
        stack.migrate(action.removeprefix("migrate-"), stack.migration_image())
        print("Selected local database migrated; application readiness remains unavailable.")
        return
    if action == "down":
        stack.compose("down")  # Preserve all database volumes.
    else:
        prepare_secrets(directory)
        stack.config()
        if action == "up":
            stack.compose("up", "--build", "--wait", "--wait-timeout", "120", timeout=600)
        stack.smoke()
        print("Local infrastructure checks passed; application readiness remains unavailable.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as error:
        print(f"Container operation failed: {error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("Container operation failed. Check Docker access, .env, secret permissions, and docs/deployment.md; no secrets were printed.", file=sys.stderr)
        sys.exit(1)
