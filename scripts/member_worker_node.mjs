// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Test-only mapping of browser dedicated-worker APIs onto Node worker threads.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parentPort, workerData } from "node:worker_threads";

let inputs;
globalThis.postMessage = (message, transfers) => {
  if (Object.hasOwn(message, "result")) {
    assert.ok(inputs.every((view) => view.every((byte) => byte === 0)), "worker inputs not cleared before publication");
  }
  parentPort.postMessage(message, transfers);
};
globalThis.close = () => process.exit(0);
let fetched = false;
globalThis.fetch = async (url, options) => {
  assert.equal(url.href, new URL("./client.wasm", workerData.entry).href);
  assert.equal(fetched, false, "repeated or unexpected network request");
  fetched = true;
  assert.deepEqual(options, { credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer" });
  if (workerData.mode === "fetch-error") throw new Error("synthetic fetch failure");
  if (workerData.mode === "http-error") return new Response(null, { status: 404 });
  if (workerData.mode === "bad-wasm") return new Response(Uint8Array.of(1, 2, 3));
  if (workerData.mode === "oversized") return new Response(new Uint8Array(8 * 1024 * 1024 + 1));
  return new Response(readFileSync(url));
};
await import(workerData.entry);
parentPort.on("message", (data) => {
  inputs = data.inputs;
  void globalThis.onmessage({ data });
});
