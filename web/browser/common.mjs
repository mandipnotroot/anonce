// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

export const $ = (id) => document.getElementById(id);
export const say = (text) => { $("status").textContent = text; };
export const encode = (bytes) => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
export function decode(text, min = 1, max = min) {
  if (typeof text !== "string" || text.length > Math.ceil(max * 4 / 3) || !/^[A-Za-z0-9_-]+$/.test(text)) throw new Error("invalid data");
  const out = Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
  if (out.length < min || out.length > max || encode(out) !== text) throw new Error("invalid data");
  return out;
}
export function textBytes(text, max = 1024) {
  if (typeof text !== "string" || !text.isWellFormed() || text.length < 1 || text.length > max) throw new Error("invalid text");
  const bytes = new TextEncoder().encode(text); if (bytes.length > max) { bytes.fill(0); throw new Error("text too long"); } return bytes;
}
export async function api(path, body, origin = "", signal) {
  const local = !origin;
  const identity = document.body.hasAttribute("data-identity");
  const response = await fetch(origin + path, { method: body === undefined ? "GET" : "POST", credentials: local && identity ? "same-origin" : "omit", redirect: "error", referrerPolicy: "no-referrer", cache: "no-store", signal,
    headers: body === undefined ? {} : { "Content-Type": "application/json", ...(local && identity ? { "X-Anonce-CSRF": "1" } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!response.ok) {
    if (response.status === 401 && local && identity) dispatchEvent(new Event("anonce-session-ended"));
    throw Object.assign(new Error("Operation failed."), {status: response.status});
  }
  const reader = response.body.getReader(); let size = 0; const chunks = [];
  try { while (true) { const {value, done} = await reader.read(); if (done) break; size += value.length; if (size > 400000) throw new Error("oversized response"); chunks.push(value); } } finally { await reader.cancel(); }
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes));
}
export const handle = (fn) => async (event) => { event?.preventDefault(); try { await fn(event); } catch { say("Operation failed or was cancelled. Check sign-in, unlock state and round access. Do not repeat issuance after an uncertain result."); } };
export async function database() {
  return new Promise((resolve, reject) => { const request = indexedDB.open("anonce.local-encrypted-review.v1", 1); request.onupgradeneeded = () => request.result.createObjectStore("keys"); request.onerror = () => reject(new Error("storage unavailable")); request.onsuccess = () => resolve(request.result); });
}
export async function localRecord(key, value) {
  const db = await database(); try { return await new Promise((resolve, reject) => { const tx = db.transaction("keys", value === undefined ? "readonly" : "readwrite"); const request = value === undefined ? tx.objectStore("keys").get(key) : tx.objectStore("keys").put(value, key); tx.oncomplete = () => resolve(request.result); tx.onerror = tx.onabort = () => reject(new Error("storage failed")); }); } finally { db.close(); }
}
