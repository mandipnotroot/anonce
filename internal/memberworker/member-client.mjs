// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { inputViews, record, result, version, wipe } from "./protocol.mjs";

let active = null;

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

  constructor() {
    this.#ready = new Promise((resolve) => { this.#resolveReady = resolve; });
    if (active !== null) {
      this.#stop();
      return;
    }
    active = this;
    try {
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
  lock(...args) { if (args.length === 0) this.#stop(); return null; }
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
