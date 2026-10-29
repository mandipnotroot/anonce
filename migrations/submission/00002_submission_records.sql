-- SPDX-FileCopyrightText: 2026 Anonce Contributors
-- SPDX-License-Identifier: AGPL-3.0-only

-- +goose Up
CREATE TABLE anonce.submission_rounds (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    bulletin_digest bytea NOT NULL CHECK (octet_length(bulletin_digest) = 32),
    opens_at timestamptz NOT NULL CHECK (isfinite(opens_at)),
    closes_at timestamptz NOT NULL CHECK (isfinite(closes_at)),
    cancelled boolean NOT NULL DEFAULT false,
    CHECK (closes_at > opens_at)
);

CREATE TABLE anonce.submission_records (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    round_id bytea NOT NULL REFERENCES anonce.submission_rounds(id),
    spend_digest bytea NOT NULL CHECK (octet_length(spend_digest) = 32),
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 65536),
    accepted_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    UNIQUE (round_id, spend_digest)
);

GRANT SELECT, INSERT ON anonce.submission_rounds TO anonce_runtime;
GRANT UPDATE (cancelled) ON anonce.submission_rounds TO anonce_runtime;
GRANT SELECT, INSERT ON anonce.submission_records TO anonce_runtime;
