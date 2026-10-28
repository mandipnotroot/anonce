// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { inputViews, record, result, version, wipe } from "./protocol.mjs";

let active = null;
const lockChannel = "anonce.member-lock.v1";

// Hosts can notify peers on logout/account switch even after their local owner
// expired. Success means posting succeeded, not that other contexts acknowledged.
export function lockMemberWorkers(...args) {
  if (args.length !== 0) return false;
  let channel = null;
  try {
    channel = new BroadcastChannel(lockChannel);
    channel.postMessage("lock");
    return true;
  } catch {
    return false;
  } finally {
    active?.close();
    channel?.close();
  }
}

// Development-only owner for a single dedicated member worker. No main-thread
// WASM fallback, persistence, automatic restart, or account authentication.
export class MemberWorkerSession {
  #worker = null;
  #pending = null;
  #next = 0;
  #started = false;
  #closed = false;
  #ready;
  #resolveReady;
  #startup;
  #operation;
  #lifetime;
  #channel = null;
  #pagehide = () => this.#stop();
  #listening = false;

  constructor() {
    this.#ready = new Promise((resolve) => { this.#resolveReady = resolve; });
    if (active !== null) {
      this.#stop();
      return;
    }
    active = this;
    try {
      // Required lifecycle facilities have no uncoordinated fallback. The fixed
      // channel deliberately contains no account, key, or session identifier.
      if (typeof globalThis.addEventListener !== "function" || typeof globalThis.removeEventListener !== "function") {
        this.#stop();
        return;
      }
      this.#channel = new BroadcastChannel(lockChannel);
      // Any traffic, including unknown versions or malformed data, locks locally.
      // Never inspect payloads or echo notifications back to other contexts.
      this.#channel.onmessage = this.#channel.onmessageerror = () => this.#stop();
      this.#listening = true;
      globalThis.addEventListener("pagehide", this.#pagehide);
      this.#worker = new Worker(new URL("./member-worker.mjs", import.meta.url), { type: "module", credentials: "omit" });
      this.#worker.onmessage = (event) => this.#message(event.data);
      this.#worker.onerror = (event) => { event.preventDefault(); this.#stop(); };
      this.#worker.onmessageerror = () => this.#stop();
      this.#startup = setTimeout(() => this.#stop(), 30_000);
      this.#lifetime = setTimeout(() => this.#stop(), 300_000);
    } catch {
      this.#stop();
    }
  }

  get ready() { return this.#ready; }

  create(...inputs) { return this.#call("create", inputs); }
  unlock(...inputs) { return this.#call("unlock", inputs); }
  request(...inputs) { return this.#call("request", inputs); }
  lock(...args) {
    if (args.length !== 0 || this.#closed) return null;
    try {
      this.#channel.postMessage("lock");
    } catch {
      // A failed notification must never prevent local termination.
    } finally {
      this.#stop();
    }
    return null;
  }
  close(...args) { if (args.length === 0) this.#stop(); return null; }

  #call(method, inputs) {
    // Busy/not-ready/closed calls retain and post nothing, even transiently.
    if (this.#closed || !this.#started || this.#pending !== null) return Promise.resolve(null);
    const views = inputViews(method, inputs);
    if (views === null) return Promise.resolve(null);
    if (this.#next === Number.MAX_SAFE_INTEGER) { this.#stop(); return Promise.resolve(null); }
    const snapshots = [];
    const promise = new Promise((resolve) => { this.#pending = { id: ++this.#next, method, resolve }; });
    try {
      for (const view of views) snapshots.push(new Uint8Array(view));
      this.#operation = setTimeout(() => this.#stop(), 120_000);
      this.#worker.postMessage({ version, id: this.#next, method, inputs: snapshots }, snapshots.map((view) => view.buffer));
    } catch {
      wipe(snapshots);
      this.#stop();
    }
    return promise;
  }

  #message(message) {
    if (this.#closed) return;
    if (!this.#started && record(message, ["version", "type"]) && message.version === version && message.type === "ready") {
      this.#started = true;
      clearTimeout(this.#startup);
      this.#resolveReady(true);
      return;
    }
    const pending = this.#pending;
    if (!this.#started || pending === null || !record(message, ["version", "id", "result"]) ||
        message.version !== version || message.id !== pending.id || !result(message.result, pending.method)) {
      this.#stop();
      return;
    }
    clearTimeout(this.#operation);
    this.#pending = null;
    pending.resolve(message.result);
  }

  #stop() {
    if (this.#closed) return;
    this.#closed = true;
    clearTimeout(this.#startup);
    clearTimeout(this.#operation);
    clearTimeout(this.#lifetime);
    if (this.#listening) {
      globalThis.removeEventListener("pagehide", this.#pagehide);
      this.#listening = false;
    }
    if (this.#channel !== null) {
      this.#channel.onmessage = this.#channel.onmessageerror = null;
      this.#channel.close();
      this.#channel = null;
    }
    if (this.#worker !== null) {
      this.#worker.onmessage = this.#worker.onerror = this.#worker.onmessageerror = null;
      this.#worker.terminate(); // Never wait behind a busy worker's event loop.
      this.#worker = null;
    }
    this.#resolveReady(false);
    this.#pending?.resolve(null);
    this.#pending = null;
    if (active === this) active = null;
  }
}
