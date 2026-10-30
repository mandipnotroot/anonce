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
import ssl
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
POSTGRES_IMAGE = "postgres:18.6-bookworm@sha256:5c4783a8cc3f0074912164f94dfa1be4e043438f0f707cf968d7af9a0d31a2c8"
INTERNAL_NETWORKS = {"identity", "submission"}
EDGE_NETWORKS = {"identity-edge", "submission-edge"}
NETWORKS = {"submission": {"submission", "submission-edge"}, "identity": {"identity", "identity-edge"},
             "identity-db": {"identity"}, "submission-db": {"submission"}}
PORTS = {"identity": 8443, "submission": 8444}
SECRET_NAMES = tuple(f"{side}_{role}" for side in ("identity", "submission") for role in ("admin", "migration", "runtime"))


def application_command(side, source):
    return [f"/app/browser-{side}", "-container-network", "-listen", f"0.0.0.0:{PORTS[side]}",
            "-state", "/state", "-runtime", "/app/runtime", "-database",
            f"postgres://anonce_runtime@{side}-db:5432/{side}?sslmode=disable&connect_timeout=5",
            "-password-file", "/run/secrets/runtime_password", "-source-url", source]


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


def validate_state(directory):
    """Admit existing state without generating replacement keys or invitations."""
    root = secret_directory(directory)
    try:
        require(set(os.listdir(root)) == {"identity", "submission", "local-root.crt"}, "incomplete browser state; do not reinitialize")
        trust = os.open("local-root.crt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        with os.fdopen(trust, "rb") as handle:
            info = os.fstat(handle.fileno())
            require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 4096 and info.st_uid == os.getuid() and
                    stat.S_IMODE(info.st_mode) == 0o600, "invalid local browser trust file")
            public_root = handle.read(4097)
        for side in ("identity", "submission"):
            fd = os.open(side, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                info = os.fstat(fd)
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, "invalid service state directory")
                names = {"tls.crt": 4096, "tls.key": 4096, "receipt.pub": 32, "bulletin.seed": 32,
                         "membership.seed": 32, "membership.der": 1024, "administrator-invitation": 43} if side == "identity" else {
                             "tls.crt": 4096, "tls.key": 4096, "receipt.seed": 32, "bulletin.pub": 32}
                require(set(os.listdir(fd)) - {"local-root.crt"} == set(names), "incomplete service state; never generate replacement keys")
                for name, maximum in names.items():
                    source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                    with os.fdopen(source, "rb") as handle:
                        info = os.fstat(handle.fileno())
                        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum and info.st_uid == os.getuid() and
                                stat.S_IMODE(info.st_mode) == 0o600, "invalid browser state file metadata")
                # Compatibility adds only a public trust copy to complete older
                # initialization output. No signing key or invitation is changed.
                try:
                    target = os.open("local-root.crt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                except FileExistsError:
                    pass
                else:
                    with os.fdopen(target, "wb") as handle:
                        handle.write(public_root)
                        handle.flush()
                        os.fsync(handle.fileno())
                target = os.open("local-root.crt", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                with os.fdopen(target, "rb") as handle:
                    info = os.fstat(handle.fileno())
                    require(stat.S_ISREG(info.st_mode) and info.st_size == len(public_root) and info.st_uid == os.getuid() and
                            stat.S_IMODE(info.st_mode) == 0o600 and handle.read(4097) == public_root, "browser trust copies differ")
            finally:
                os.close(fd)
    finally:
        os.close(root)


class LocalTLSConnection(http.client.HTTPConnection):
    """Fixed loopback transport with real configured-name TLS verification."""
    def __init__(self, hostname, port, context):
        super().__init__("127.0.0.1", port, timeout=5)
        self.server_name, self.context = hostname, context

    def connect(self):
        super().connect()
        self.sock = self.context.wrap_socket(self.sock, server_hostname=self.server_name)


def validate_config(config):
    """Check the real Compose parser's normalized model, without contacting Docker."""
    services = config["services"]
    require(set(services) == set(NETWORKS), "unexpected Compose service set")
    require(set(config["networks"]) == INTERNAL_NETWORKS | EDGE_NETWORKS and
            all(item.get("internal", False) == (name in INTERNAL_NETWORKS) for name, item in config["networks"].items()),
            "database networks must be internal with separate application edge networks")
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
            require(re.fullmatch(r"[1-9][0-9]{0,8}:[1-9][0-9]{0,8}", str(service.get("user", ""))) is not None and
                    not service.get("environment"), "browser services require a non-root state owner without environment credentials")
            require({(item["source"], item["target"]) for item in service.get("secrets", [])} ==
                    {(f"{name}_runtime", "runtime_password")}, "browser runtime credential scope changed")
            mounts = service.get("volumes", [])
            require(len(mounts) == 1 and mounts[0].get("type") == "bind" and mounts[0].get("target") == "/state" and
                    mounts[0].get("read_only") is True and Path(mounts[0]["source"]).is_absolute() and
                    Path(mounts[0]["source"]).name == name and mounts[0].get("bind", {}).get("create_host_path") is False,
                    "browser services require one read-only, pre-existing own-state mount")
            ports = service.get("ports", [])
            require(len(ports) == 1 and ports[0]["host_ip"] == "127.0.0.1" and ports[0]["target"] == PORTS[name] and
                    ports[0]["protocol"] == "tcp" and str(ports[0].get("published", "")) in ("0",str(PORTS[name])),
                    "browser ports require fixed origins on IPv4 loopback, or zero for isolated tests")
            require("-container-network" in service["command"] and f"0.0.0.0:{PORTS[name]}" in service["command"], "invalid container bind opt-in")
            command = service["command"]
            require(len(command) == 14 and command == application_command(name, command[-1]), "browser startup command changed")
            require(service["healthcheck"]["test"] == ["CMD", "/app/probe", name], "browser health check must verify scoped TLS")
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
        self.env["ANONCE_APP_UID"] = str(os.getuid())
        self.env["ANONCE_APP_GID"] = str(os.getgid())
        self.base = ["docker", "compose", "--file", str(ROOT / "compose.yaml")]
        if project:
            self.base.extend(["--project-name", project])
            self.env["COMPOSE_PROJECT_NAME"] = project

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
            mounts = item["Mounts"]
            expected_state = config["services"][name]["volumes"][0]["source"]
            require(len(mounts) == 2 and {(mount["Destination"], mount["Source"], mount["RW"]) for mount in mounts} ==
                    {("/state", expected_state, False), ("/run/secrets/runtime_password", config["secrets"][f"{name}_runtime"]["file"], False)},
                    "browser received extra or writable mounts")
            bindings = item["NetworkSettings"]["Ports"][f"{PORTS[name]}/tcp"]
            require(bindings is not None and len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1", "missing or non-loopback published endpoint")
            hostname = "identity.localhost" if name == "identity" else "submit.localhost"
            trust = ssl.create_default_context(cafile=str(Path(expected_state) / "local-root.crt"))
            connection = LocalTLSConnection(hostname, int(bindings[0]["HostPort"]), trust)
            try:
                for path, status in (("/healthz", 200), ("/", 200), ("/api/browser/config", 200), ("/source", 302)):
                    connection.request("GET", path, headers={"Host": f"{hostname}:{PORTS[name]}"})
                    response = connection.getresponse()
                    body = response.read(8193)
                    require(response.status == status and len(body) <= 8192 and response.getheader("Cache-Control") == "no-store" and
                            response.getheader("Set-Cookie") is None, "invalid browser HTTP response")
                    if path == "/healthz":
                        require(body == b"ok", "invalid liveness response")
                    if path == "/":
                        require(b'type="module"' in body and (b"Synthetic" in body or b"synthetic" in body), "connected browser page is unavailable")
                    if path == "/api/browser/config":
                        peer = "https://submit.localhost:8444" if name == "identity" else "https://identity.localhost:8443"
                        require(peer in json.loads(body).values(), "browser peer origin differs")
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

    def initialize(self, image):
        config = self.config()
        directory = Path(config["services"]["identity"]["volumes"][0]["source"]).parent
        require(directory == Path(config["services"]["submission"]["volumes"][0]["source"]).parent, "browser state roots differ")
        directory.mkdir(mode=0o700, exist_ok=True)
        fd = secret_directory(directory)
        try:
            entries = os.listdir(fd)
            if entries:
                validate_state(directory)
                return
            for side, table in (("identity", "browser_credentials"), ("submission", "browser_bulletins")):
                result = self.sql(side, "runtime", f"SELECT EXISTS(SELECT 1 FROM anonce.{table});")
                require(result.stdout.strip() == b"f", "browser data exists without server state; restore the original state instead of generating keys")
            args = ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", f"{os.getuid()}:{os.getgid()}",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--log-driver", "none",
                    "--cpus", "1", "--memory", "128m", "--memory-swap", "128m", "--pids-limit", "64",
                    "--mount", f"type=bind,src={directory},dst=/state", "--entrypoint", "/app/browser-init", image, "-empty-directory", "/state"]
            self.run(args, timeout=30)
            validate_state(directory)
        finally:
            os.close(fd)

    def start(self, migrate=True):
        config = self.config()
        present = self.compose("ps", "--all", "--services").stdout.decode().split()
        require(set(present) <= set(NETWORKS), "unexpected services in this project; review the Compose project before startup")
        self.compose("build", timeout=600, stream=True)
        image = self.run(["docker", "image", "inspect", "--format", "{{.Id}}", config["services"]["identity"]["image"]]).stdout.decode().strip()
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None, "browser application image unavailable")
        self.compose("stop", "identity", "submission", timeout=30)
        self.compose("up", "-d", "--wait", "--wait-timeout", "120", "identity-db", "submission-db", timeout=180)
        if migrate:
            migration = self.migration_image()
            for side in ("identity", "submission"):
                self.migrate(side, migration)
        self.initialize(image)
        self.compose("up", "-d", "--wait", "--wait-timeout", "120", "identity", "submission", timeout=180)
        return config

    def migration_image(self, target="migration"):
        require(target in ("migration", "account-test", "member-backup-test", "submission-record-test"), "invalid database image target")
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
            # A version-3 failure must preserve version 2 and its account tables.
            stack.sql(side, "migrator", "SET ROLE anonce_owner; CREATE TABLE anonce.member_key_backups(id integer);")
            stack.migrate(side, image, allowed=False)
            result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table} ORDER BY id; SELECT to_regclass('anonce.accounts') IS NOT NULL AND to_regclass('anonce.account_sessions') IS NOT NULL;")
            require(result.stdout.strip() == b"0\n1\n2\nt", "failed backup migration changed published state")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; DROP TABLE anonce.member_key_backups;")
            # A version-4 failure must preserve existing session rows and roll
            # back the selector column as well as the migration history.
            stack.sql(side, "migrator", "SET ROLE anonce_owner; CREATE INDEX account_sessions_selector_unique ON anonce.account_sessions(expires_at);")
            stack.migrate(side, image, allowed=False)
            result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table} ORDER BY id; SELECT count(*) FROM information_schema.columns WHERE table_schema='anonce' AND table_name='account_sessions' AND column_name='session_id';")
            require(result.stdout.strip() == b"0\n1\n2\n3\n0", "failed selector migration changed published state")
            stack.sql(side, "runtime", "INSERT INTO anonce.accounts(id) VALUES (decode(repeat('ef',16),'hex')); INSERT INTO anonce.account_sessions(token_digest,account_id,expires_at) SELECT decode(repeat(value,32),'hex'),decode(repeat('ef',16),'hex'),statement_timestamp()+interval '1 hour' FROM (VALUES ('ab'),('cd')) AS tokens(value);")
            previous_sessions = stack.sql(side, "runtime", "SELECT encode(token_digest,'hex'),encode(account_id,'hex'),created_at,expires_at FROM anonce.account_sessions ORDER BY token_digest;").stdout
            stack.migrate(side, image, allowed=False)
            require(stack.sql(side, "runtime", "SELECT encode(token_digest,'hex'),encode(account_id,'hex'),created_at,expires_at FROM anonce.account_sessions ORDER BY token_digest;").stdout == previous_sessions, "failed selector migration changed session rows")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; DROP INDEX anonce.account_sessions_selector_unique;")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; CREATE TABLE anonce.browser_credentials(id integer);")
            stack.migrate(side, image, allowed=False)
            result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table} ORDER BY id; SELECT to_regclass('anonce.browser_rounds') IS NULL;")
            require(result.stdout.strip() == b"0\n1\n2\n3\n4\nt", "failed browser migration changed published identity state")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; DROP TABLE anonce.browser_credentials;")
        else:
            # A record-table conflict must roll back round creation and leave the
            # published boundary history unchanged.
            stack.sql(side, "migrator", "SET ROLE anonce_owner; CREATE TABLE anonce.submission_records(id integer);")
            stack.migrate(side, image, allowed=False)
            result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table} ORDER BY id; SELECT to_regclass('anonce.submission_rounds') IS NULL;")
            require(result.stdout.strip() == b"0\n1\nt", "failed submission migration changed published state")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; DROP TABLE anonce.submission_records;")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; CREATE TABLE anonce.browser_review_challenges(id integer);")
            stack.migrate(side, image, allowed=False)
            result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table} ORDER BY id; SELECT to_regclass('anonce.browser_bulletins') IS NULL;")
            require(result.stdout.strip() == b"0\n1\n2\nt", "failed browser migration changed published submission state")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; DROP TABLE anonce.browser_review_challenges;")
        # Simultaneous pending applications exercise the actual locked Go runner.
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: stack.migrate(side, image), range(2)))
        stack.migrate(side, image)  # Already-current application is idempotent.
        result = stack.sql(side, "runtime", "SELECT service FROM anonce.storage_boundary;")
        require(result.stdout.strip() == side.encode(), "wrong storage boundary")
        result = stack.sql(side, "migrator", f"SET ROLE anonce_owner; SELECT version_id FROM {table} ORDER BY id;")
        latest = 5 if side == "identity" else 3
        require(result.stdout.strip() == (b"0\n1\n2\n3\n4\n5" if side == "identity" else b"0\n1\n2\n3"), "unexpected migration history")
        if side == "identity":
            require(stack.sql(side, "runtime", "SELECT encode(token_digest,'hex'),encode(account_id,'hex'),created_at,expires_at FROM anonce.account_sessions ORDER BY token_digest;").stdout == previous_sessions, "selector upgrade changed existing session material")
            selectors = stack.sql(side, "runtime", "SELECT session_id FROM anonce.account_sessions ORDER BY token_digest;").stdout
            require(len(set(selectors.splitlines())) == 2, "selector upgrade did not independently backfill existing sessions")
            stack.migrate(side, image)
            require(stack.sql(side, "runtime", "SELECT session_id FROM anonce.account_sessions ORDER BY token_digest;").stdout == selectors, "repeated migration changed selectors")
            # Remove only this migration probe's rows before runtime test suites.
            stack.sql(side, "runtime", "DELETE FROM anonce.account_sessions WHERE account_id=decode(repeat('ef',16),'hex');")
            stack.sql(side, "migrator", "SET ROLE anonce_owner; DELETE FROM anonce.accounts WHERE id=decode(repeat('ef',16),'hex');")
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


def account_checks(stack, target="account-test"):
    require(target in ("account-test", "member-backup-test", "submission-record-test"), "invalid runtime test target")
    image = stack.migration_image(target)
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
    result = stack.sql("submission", "migrator", "SET ROLE anonce_owner; SELECT to_regclass('anonce.accounts') IS NULL AND to_regclass('anonce.account_sessions') IS NULL AND to_regclass('anonce.member_key_backups') IS NULL;")
    require(result.stdout.strip() == b"t", "identity account tables entered submission storage")
    result = stack.sql("identity", "migrator", "SET ROLE anonce_owner; SELECT to_regclass('anonce.submission_rounds') IS NULL AND to_regclass('anonce.submission_records') IS NULL;")
    require(result.stdout.strip() == b"t", "submission records entered identity storage")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("secrets", "config", "up", "down", "smoke", "test", "migration-test", "account-test", "member-backup-test", "submission-record-test", "migrate-identity", "migrate-submission"))
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
    if action in ("test", "migration-test", "account-test", "member-backup-test", "submission-record-test"):
        scratch = ROOT / ".cache/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="containers-", dir=scratch) as temporary:
            directory = Path(temporary) / "secrets"
            if action != "test":
                prepare_secrets(directory, create=True)
            env = dict(os.environ, ANONCE_SECRETS_DIR=str(directory), ANONCE_STATE_DIR=str(Path(temporary) / "state"),
                       ANONCE_SOURCE_URL="https://source.example.invalid/anonce/test.tar.gz",
                       ANONCE_IDENTITY_PORT="0", ANONCE_SUBMISSION_PORT="0")
            isolated = Stack(env, project="anonce-test-" + secrets.token_hex(6))
            isolated.config()
            try:
                if action in ("migration-test", "account-test", "member-backup-test", "submission-record-test"):
                    isolated.compose("up", "-d", "--wait", "--wait-timeout", "120", "identity-db", "submission-db", timeout=180)
                    migration_checks(isolated)
                    isolated.start(migrate=False)
                else:
                    isolated.run([sys.executable,str(ROOT / "scripts/containers.py"),"up"],timeout=600,stream=True)
                database_checks(isolated, isolated.smoke())
                if action == "test":
                    state = Path(env["ANONCE_STATE_DIR"])
                    before = {str(path.relative_to(state)):(path.stat().st_ino,path.stat().st_mtime_ns,path.stat().st_size)
                              for path in state.rglob("*") if path.is_file()}
                    marker = secrets.token_hex(16)
                    isolated.sql("identity", "runtime", f"INSERT INTO anonce.accounts(id) VALUES(decode('{marker}','hex'));")
                    isolated.start()
                    isolated.smoke()
                    after = {str(path.relative_to(state)):(path.stat().st_ino,path.stat().st_mtime_ns,path.stat().st_size)
                             for path in state.rglob("*") if path.is_file()}
                    require(before == after, "restart replaced existing server state")
                    persisted = isolated.sql("identity", "runtime", f"SELECT count(*) FROM anonce.accounts WHERE id=decode('{marker}','hex');")
                    require(persisted.stdout.strip() == b"1", "restart discarded persisted account data")
                if action in ("account-test", "member-backup-test", "submission-record-test"):
                    # The race suites use two eight-connection runtime pools.
                    # Release the browser pools first, preserving the existing
                    # sixteen-connection role limit instead of raising it for tests.
                    isolated.compose("stop", "identity", "submission", timeout=30)
                if action in ("account-test", "member-backup-test"):
                    account_checks(isolated)
                if action == "member-backup-test":
                    account_checks(isolated, "member-backup-test")
                if action == "submission-record-test":
                    account_checks(isolated, "submission-record-test")
            finally:
                # Remove only this invocation's fresh disposable project and volumes.
                isolated.compose("down", "--volumes", "--remove-orphans")
        print("Connected TLS browser pages, scoped runtime storage, container isolation and PostgreSQL privilege checks passed.")
        if action in ("migration-test", "account-test", "member-backup-test", "submission-record-test"):
            print("Separate database migration, concurrency, failure, version and grant checks passed; full db-test remains unavailable.")
        if action in ("account-test", "member-backup-test"):
            print("Account/session persistence, expiry, revocation, concurrency and runtime grants passed; browser ceremonies are checked separately by browser-test.")
        if action == "member-backup-test":
            print("Encrypted backup scope, revisions, tombstones, disable, cancellation and runtime grants passed.")
        if action == "submission-record-test":
            print("Atomic submission spending, retries, round admission, cancellation, rollback and runtime grants passed.")
        return
    if action.startswith("migrate-"):
        config = stack.config()
        prepare_secrets(Path(config["secrets"]["identity_runtime"]["file"]).parent)
        stack.migrate(action.removeprefix("migrate-"), stack.migration_image())
        print("Selected local database migrated; application readiness remains unavailable.")
        return
    if action == "down":
        stack.compose("down")  # Preserve all database volumes.
    else:
        config = stack.config()
        prepare_secrets(Path(config["secrets"]["identity_runtime"]["file"]).parent, create=action == "up")
        if action == "up":
            stack.start()
        stack.smoke()
        print("Connected browser application checks passed. Open https://identity.localhost:8443/ after trusting .browser/local-root.crt. Synthetic data only.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as error:
        print(f"Container operation failed: {error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("Container operation failed. Check Docker access, .env, secret permissions, and docs/deployment.md; no secrets were printed.", file=sys.stderr)
        sys.exit(1)
