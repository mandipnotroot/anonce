// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { decode } from "./common.mjs";

export function reviewOwnerActive(owner, current, visibility, reviewUntil, now = Date.now()) {
  if (owner !== current || visibility !== "visible" || !Number.isFinite(now) ||
      !Number.isFinite(reviewUntil) || now >= reviewUntil) {
    owner.close();
    return false;
  }
  return !owner.closed;
}

// A rejected answer must not hide later records. A closed or replaced owner is
// different: stop the read and never publish late plaintext, even after success.
export async function readReviewRecords(worker, records, isActive, append) {
  if (!isActive() || !Array.isArray(records) || records.length > 50) throw new Error("review unavailable");
  let rejected = 0;
  for (const record of records) {
    if (!isActive()) throw new Error("review unavailable");
    let envelope = null;
    try { envelope = decode(record?.envelope, 4145); } catch { /* Reject this record only. */ }
    const result = envelope === null ? null : await worker.call("decrypt", envelope);
    let text = null;
    if (result !== null) {
      try { if (isActive()) text = new TextDecoder("utf-8", { fatal: true }).decode(result.bytes); }
      catch { /* Invalid plaintext is not an answer. */ }
      finally { result.bytes.fill(0); }
    }
    if (!isActive()) throw new Error("review unavailable");
    if (text === null) rejected++;
    append(text);
  }
  return rejected;
}
