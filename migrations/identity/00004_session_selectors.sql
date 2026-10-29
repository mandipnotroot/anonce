-- SPDX-FileCopyrightText: 2026 Anonce Contributors
-- SPDX-License-Identifier: AGPL-3.0-only

-- +goose Up
ALTER TABLE anonce.account_sessions
    ADD COLUMN session_id uuid NOT NULL DEFAULT gen_random_uuid(),
    ADD CONSTRAINT account_sessions_selector_unique UNIQUE (session_id),
    ADD CONSTRAINT account_sessions_selector_nonzero
        CHECK (session_id <> '00000000-0000-0000-0000-000000000000'::uuid);
