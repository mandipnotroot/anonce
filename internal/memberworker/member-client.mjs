// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { inputViews, record, result, version, wipe } from "./protocol.mjs";

let active = null;
const lockChannel = "anonce.member-lock.v1";
const startupLimit = 30_000, operationLimit = 120_000, lifetimeLimit = 300_000;

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
  #document = null;
  #visibilitychange = () => this.#checkState();
  #visibilityListening = false;
  #clock = null;
  #born = null;
  #lastTime = null;

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
      this.#document = globalThis.document;
      if (typeof this.#document?.addEventListener !== "function" || typeof this.#document?.removeEventListener !== "function" ||
          !this.#checkVisibility()) {
        this.#stop();
        return;
      }
      const performance = globalThis.performance;
      const monotonic = performance.now.bind(performance), wall = Date.now.bind(Date);
      this.#clock = () => ({ monotonic: monotonic(), wall: wall() });
      if (this.#checkState() === null) return;
      this.#channel = new BroadcastChannel(lockChannel);
      // Any traffic, including unknown versions or malformed data, locks locally.
      // Never inspect payloads or echo notifications back to other contexts.
      this.#channel.onmessage = this.#channel.onmessageerror = () => this.#stop();
      this.#listening = true;
      globalThis.addEventListener("pagehide", this.#pagehide);
      this.#visibilityListening = true;
      this.#document.addEventListener("visibilitychange", this.#visibilitychange);
      if (this.#checkState() === null) return;
      this.#worker = new Worker(new URL("./member-worker.mjs", import.meta.url), { type: "module", credentials: "omit" });
      this.#worker.onmessage = (event) => this.#message(event.data);
      this.#worker.onerror = (event) => { event.preventDefault(); this.#stop(); };
      this.#worker.onmessageerror = () => this.#stop();
      this.#startup = setTimeout(() => this.#stop(), startupLimit);
      this.#lifetime = setTimeout(() => this.#stop(), lifetimeLimit);
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
    const time = this.#checkState();
    if (time === null || !this.#started || this.#pending !== null) return Promise.resolve(null);
    const views = inputViews(method, inputs);
    if (views === null) return Promise.resolve(null);
    if (this.#next === Number.MAX_SAFE_INTEGER) { this.#stop(); return Promise.resolve(null); }
    const snapshots = [];
    const promise = new Promise((resolve) => { this.#pending = { id: ++this.#next, method, resolve, time }; });
    try {
      for (const view of views) snapshots.push(new Uint8Array(view));
      this.#operation = setTimeout(() => this.#stop(), operationLimit);
      this.#worker.postMessage({ version, id: this.#next, method, inputs: snapshots }, snapshots.map((view) => view.buffer));
    } catch {
      wipe(snapshots);
      this.#stop();
    }
    return promise;
  }

  #message(message) {
    if (this.#checkState() === null) return;
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

  #checkState() {
    if (!this.#checkVisibility()) return null;
    try {
      const time = this.#clock();
      // Never coerce a clock result or replace a failed clock with the other one.
      // Wall time also catches elapsed time on platforms whose monotonic clock
      // pauses during sleep. Neither clock can preempt a suspended owner.
      const expired = (start, limit) => time.monotonic - start.monotonic >= limit || time.wall - start.wall >= limit;
      if (Number.isFinite(time.monotonic) && time.monotonic >= 0 && time.monotonic <= Number.MAX_SAFE_INTEGER &&
          Number.isSafeInteger(time.wall) &&
          (this.#lastTime === null || (time.monotonic >= this.#lastTime.monotonic && time.wall >= this.#lastTime.wall)) &&
          (this.#born === null || (!expired(this.#born, lifetimeLimit) && (this.#started || !expired(this.#born, startupLimit)))) &&
          (this.#pending === null || !expired(this.#pending.time, operationLimit))) {
        this.#born ??= time;
        this.#lastTime = time;
        return time;
      }
    } catch {
      // Missing/failed clocks must not leave an owner with timer-only custody.
    }
    this.#stop();
    return null;
  }

  #checkVisibility() {
    if (this.#closed) return false;
    try {
      if (this.#document?.visibilityState === "visible") return true;
    } catch {
      // Missing/failed visibility reads must not allow background key custody.
    }
    this.#stop();
    return false;
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
    if (this.#visibilityListening) {
      this.#document.removeEventListener("visibilitychange", this.#visibilitychange);
      this.#visibilityListening = false;
    }
    this.#document = null;
    this.#clock = null;
    this.#born = this.#lastTime = null;
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
