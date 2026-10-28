-- SPDX-FileCopyrightText: 2026 Anonce Contributors
-- SPDX-License-Identifier: AGPL-3.0-only

-- Empty-volume bootstrap only, not an application migration or upgrade runner.
\set ON_ERROR_STOP on
\getenv db POSTGRES_DB
BEGIN;
CREATE ROLE anonce_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE anonce_migrator LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4;
CREATE ROLE anonce_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 16;

-- Fixed secret paths keep passwords out of arguments, SQL source, and diagnostics.
DO $$
DECLARE
    migration_password text := pg_read_file('/run/secrets/migration_password', 0, 65);
    runtime_password text := pg_read_file('/run/secrets/runtime_password', 0, 65);
BEGIN
    IF migration_password !~ '^[0-9a-f]{64}$' OR runtime_password !~ '^[0-9a-f]{64}$'
       OR migration_password = runtime_password THEN
        RAISE EXCEPTION 'invalid or duplicate local database passwords';
    END IF;
    EXECUTE format('ALTER ROLE anonce_migrator PASSWORD %L', migration_password);
    EXECUTE format('ALTER ROLE anonce_runtime PASSWORD %L', runtime_password);
END;
$$;

GRANT anonce_owner TO anonce_migrator WITH INHERIT FALSE;
ALTER DATABASE :"db" OWNER TO anonce_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
REVOKE ALL ON DATABASE postgres, template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO anonce_migrator, anonce_runtime;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA anonce AUTHORIZATION anonce_owner;
GRANT USAGE ON SCHEMA anonce TO anonce_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE anonce_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER ROLE anonce_runtime SET search_path = pg_catalog, anonce;
ALTER ROLE anonce_runtime SET statement_timeout = '5s';
ALTER ROLE anonce_runtime SET idle_in_transaction_session_timeout = '30s';
COMMIT;
