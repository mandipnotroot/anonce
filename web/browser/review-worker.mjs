// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import "/runtime/review/wasm_exec.js";
import { byteView } from "/assets/bytes.mjs";

let busy = false, api = null, last = 0;
const fail = () => { globalThis.postMessage({failed:true}); globalThis.close(); };
globalThis.onmessageerror = fail;
globalThis.onmessage = async ({data}) => {
  if (!api || busy || !data || Object.keys(data).length !== 3 || !Number.isSafeInteger(data.id) || data.id <= last || typeof data.method !== "string" || !Array.isArray(data.inputs) || data.inputs.length > 4 || data.inputs.some((v) => !byteView(v, 1, 8192))) { fail(); return; }
  busy = true; last = data.id;
  try {
    const result = await api(data.method, ...data.inputs);
    for (const bytes of data.inputs) bytes.fill(0);
    const transfers = result ? Object.values(result).filter((v) => v instanceof Uint8Array).map((v) => v.buffer) : [];
    globalThis.postMessage({id: data.id, result}, transfers);
  } catch { fail(); } finally { for (const bytes of data.inputs) bytes.fill(0); busy = false; }
};
async function boot() {
  const response = await fetch("/runtime/review/client.wasm", {credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer"});
  if (!response.ok) throw new Error("runtime unavailable");
  const bytes = new Uint8Array(8 * 1024 * 1024); const reader = response.body.getReader(); let size = 0;
  try { while (true) { const {value, done} = await reader.read(); if (done) break; if (value.length > bytes.length - size) throw new Error("runtime too large"); bytes.set(value, size); size += value.length; } } finally { await reader.cancel(); }
  const go = new Go(); const {instance} = await WebAssembly.instantiate(bytes.subarray(0, size), go.importObject); const running = go.run(instance); api = globalThis.anonceReview;
  if (typeof api !== "function") throw new Error("missing bridge"); globalThis.postMessage({ready: true}); await running; fail();
}
boot().catch(fail);
