-- SPDX-FileCopyrightText: 2026 Anonce Contributors
-- SPDX-License-Identifier: AGPL-3.0-only

-- +goose Up
CREATE TABLE anonce.browser_bulletins (
    round_id bytea PRIMARY KEY REFERENCES anonce.submission_rounds(id),
    bulletin bytea NOT NULL CHECK (octet_length(bulletin) BETWEEN 564 AND 1587)
);
CREATE TABLE anonce.browser_review_challenges (
    digest bytea PRIMARY KEY CHECK (octet_length(digest) = 32),
    round_id bytea NOT NULL REFERENCES anonce.submission_rounds(id),
    cursor bytea NOT NULL CHECK (octet_length(cursor) = 16),
    expires_at timestamptz NOT NULL DEFAULT (statement_timestamp() + interval '2 minutes')
);
GRANT SELECT, INSERT ON anonce.browser_bulletins TO anonce_runtime;
GRANT SELECT, INSERT, DELETE ON anonce.browser_review_challenges TO anonce_runtime;
