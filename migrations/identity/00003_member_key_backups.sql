-- SPDX-FileCopyrightText: 2026 Anonce Contributors
-- SPDX-License-Identifier: AGPL-3.0-only

-- +goose Up
CREATE TABLE anonce.member_key_backups (
    account_id bytea PRIMARY KEY REFERENCES anonce.accounts(id),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    revision bigint NOT NULL CHECK (revision > 0),
    backup bytea,
    CHECK (backup IS NULL OR (
        octet_length(backup) = 108 AND
        substring(backup FROM 1 FOR 12) = decode('414e4f4e43454b5301020100', 'hex') AND
        substring(backup FROM 29 FOR 4) = decode('0000004c', 'hex')
    ))
);

GRANT SELECT, INSERT ON anonce.member_key_backups TO anonce_runtime;
GRANT UPDATE (revision, backup) ON anonce.member_key_backups TO anonce_runtime;
