-- SPDX-FileCopyrightText: 2026 Anonce Contributors
-- SPDX-License-Identifier: AGPL-3.0-only

-- +goose Up
CREATE TABLE anonce.browser_credentials (
    account_id bytea PRIMARY KEY REFERENCES anonce.accounts(id),
    username text UNIQUE NOT NULL CHECK (username ~ '^[a-z0-9_]{3,32}$'),
    credential_id bytea UNIQUE NOT NULL CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    credential jsonb NOT NULL CHECK (octet_length(credential::text) <= 32768),
    administrator boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX browser_one_administrator ON anonce.browser_credentials(administrator) WHERE administrator;
CREATE TABLE anonce.browser_ceremonies (
    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
    kind text NOT NULL CHECK (kind IN ('register','login')),
    data jsonb NOT NULL CHECK (octet_length(data::text) <= 16384),
    expires_at timestamptz NOT NULL DEFAULT (statement_timestamp() + interval '2 minutes')
);
CREATE TABLE anonce.browser_memberships (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    code_digest bytea UNIQUE NOT NULL CHECK (octet_length(code_digest) = 32),
    expires_at timestamptz NOT NULL,
    account_id bytea UNIQUE REFERENCES anonce.accounts(id),
    public_key bytea UNIQUE CHECK (octet_length(public_key) = 32),
    certificate bytea CHECK (octet_length(certificate) BETWEEN 1 AND 1024),
    revoked boolean NOT NULL DEFAULT false,
    CHECK ((account_id IS NULL AND public_key IS NULL AND certificate IS NULL) OR
           (account_id IS NOT NULL AND public_key IS NOT NULL AND certificate IS NOT NULL))
);
CREATE TABLE anonce.browser_rounds (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    question text NOT NULL CHECK (octet_length(question) BETWEEN 1 AND 1024),
    reviewer_account bytea NOT NULL REFERENCES anonce.accounts(id),
    reviewer_key bytea UNIQUE CHECK (octet_length(reviewer_key) = 32),
    opens_at timestamptz NOT NULL,
    closes_at timestamptz NOT NULL CHECK (closes_at > opens_at),
    review_until timestamptz NOT NULL CHECK (review_until > closes_at AND review_until <= closes_at + interval '30 days'),
    response_limit integer NOT NULL CHECK (response_limit = 1),
    rsa_private bytea CHECK (octet_length(rsa_private) BETWEEN 1000 AND 4096),
    bulletin bytea CHECK (octet_length(bulletin) BETWEEN 564 AND 1587),
    CHECK ((rsa_private IS NULL) = (bulletin IS NULL))
);
CREATE TABLE anonce.browser_issue_challenges (
    nonce bytea PRIMARY KEY CHECK (octet_length(nonce) = 32),
    session_digest bytea NOT NULL CHECK (octet_length(session_digest) = 32),
    membership_id bytea NOT NULL REFERENCES anonce.browser_memberships(id),
    round_id bytea NOT NULL REFERENCES anonce.browser_rounds(id),
    challenge bytea NOT NULL CHECK (octet_length(challenge) = 113),
    expires_at timestamptz NOT NULL DEFAULT (statement_timestamp() + interval '2 minutes'),
    UNIQUE (membership_id, round_id)
);
CREATE TABLE anonce.browser_issuances (
    membership_id bytea NOT NULL REFERENCES anonce.browser_memberships(id),
    round_id bytea NOT NULL REFERENCES anonce.browser_rounds(id),
    PRIMARY KEY (membership_id, round_id)
);
GRANT SELECT, INSERT ON anonce.browser_credentials TO anonce_runtime;
GRANT UPDATE (credential) ON anonce.browser_credentials TO anonce_runtime;
GRANT SELECT, INSERT, DELETE ON anonce.browser_ceremonies TO anonce_runtime;
GRANT SELECT, INSERT ON anonce.browser_memberships TO anonce_runtime;
GRANT UPDATE (account_id, public_key, certificate, revoked) ON anonce.browser_memberships TO anonce_runtime;
GRANT SELECT, INSERT ON anonce.browser_rounds TO anonce_runtime;
GRANT UPDATE (reviewer_key, rsa_private, bulletin) ON anonce.browser_rounds TO anonce_runtime;
GRANT SELECT, INSERT, DELETE ON anonce.browser_issue_challenges TO anonce_runtime;
GRANT SELECT, INSERT ON anonce.browser_issuances TO anonce_runtime;
