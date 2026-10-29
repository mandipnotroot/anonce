-- SPDX-FileCopyrightText: 2026 Anonce Contributors
-- SPDX-License-Identifier: AGPL-3.0-only

-- +goose Up
CREATE TABLE anonce.storage_boundary (
    singleton boolean PRIMARY KEY CHECK (singleton),
    service text NOT NULL CHECK (service = 'identity')
);
INSERT INTO anonce.storage_boundary (singleton, service) VALUES (true, 'identity');
GRANT SELECT ON anonce.storage_boundary TO anonce_runtime;
