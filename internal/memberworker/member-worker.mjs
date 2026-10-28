// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import "./wasm_exec.js";
import { command, record, result, version, wipe } from "./protocol.mjs";

let api = null;
let busy = false;
let stopped = false;
let lastID = 0;

function fail() {
  if (stopped) return;
  stopped = true;
  // Never reflect exceptions, URLs, key material, or inputs into diagnostics.
  globalThis.postMessage({ version, type: "failed" });
  globalThis.close();
}

globalThis.onmessageerror = fail;
globalThis.onmessage = async (event) => {
  const message = event.data;
  if (stopped) return;
  if (!command(message) || api === null || busy || message.id <= lastID) { fail(); return; }
  busy = true;
  lastID = message.id;
  let output;
  try {
    // Dispatch only the three named methods, never caller-selected properties.
    switch (message.method) {
      case "create": output = await api.create(...message.inputs); break;
      case "unlock": output = await api.unlock(...message.inputs); break;
      case "request": output = await api.request(); break;
    }
    if (!result(output, message.method)) { fail(); return; }
    wipe(message.inputs); // Clear worker snapshots before the owner can settle.
    if (!stopped) {
      const transfers = output === null ? [] : Object.values(output).map((view) => view.buffer);
      globalThis.postMessage({ version, id: message.id, result: output }, transfers);
    }
  } catch {
    fail();
  } finally {
    wipe(message.inputs);
    busy = false;
  }
};

async function boot() {
  // Fixed local assets only. No redirects, cookies, or caller-selected URLs.
  const response = await fetch(new URL("./client.wasm", import.meta.url), {
    credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer",
  });
  if (!response.ok || response.body === null) throw new Error("unavailable runtime");
  const maximum = 8 * 1024 * 1024;
  const bytes = new Uint8Array(maximum);
  const reader = response.body.getReader();
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value.byteLength > maximum - size) throw new Error("oversized runtime");
      bytes.set(value, size);
      size += value.byteLength;
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  const go = new globalThis.Go();
  const { instance } = await WebAssembly.instantiate(bytes.subarray(0, size), go.importObject);
  const running = go.run(instance);
  api = globalThis.anonceMember;
  if (!record(api, ["create", "unlock", "request", "lock", "close"])) throw new Error("unavailable bridge");
  globalThis.postMessage({ version, type: "ready" });
  // Any runtime exit is terminal. Recovery needs a new explicit instance.
  await running;
  fail();
}

boot().catch(fail);
