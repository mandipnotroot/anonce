-- SPDX-FileCopyrightText: 2026 Anonce Contributors
-- SPDX-License-Identifier: AGPL-3.0-only

-- +goose Up
CREATE TABLE anonce.accounts (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    disabled_at timestamptz,
    CHECK ((state = 'active' AND disabled_at IS NULL) OR
           (state = 'disabled' AND disabled_at IS NOT NULL))
);

CREATE TABLE anonce.account_sessions (
    token_digest bytea PRIMARY KEY CHECK (octet_length(token_digest) = 32),
    account_id bytea NOT NULL REFERENCES anonce.accounts(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    expires_at timestamptz NOT NULL,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '12 hours')
);
CREATE INDEX account_sessions_account ON anonce.account_sessions(account_id);
CREATE INDEX account_sessions_expiry ON anonce.account_sessions(expires_at, token_digest);

GRANT SELECT, INSERT ON anonce.accounts TO anonce_runtime;
GRANT UPDATE (state, disabled_at) ON anonce.accounts TO anonce_runtime;
GRANT SELECT, INSERT, DELETE ON anonce.account_sessions TO anonce_runtime;
