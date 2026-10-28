// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { randomInt } from "node:crypto";
import { getEventListeners } from "node:events";
import { test } from "node:test";
import { byteView, command, inputViews, result } from "../internal/memberworker/protocol.mjs";
import { lockMemberWorkers, MemberWorkerSession } from "../internal/memberworker/member-client.mjs";

const enrollment = () => ({ publicKey: new Uint8Array(32), csr: new Uint8Array(129) });
const setup = () => ({ ...enrollment(), backup: new Uint8Array(108) });

function harness(t) {
  const original = { Worker: globalThis.Worker, BroadcastChannel: globalThis.BroadcastChannel,
    document: globalThis.document, addEventListener: globalThis.addEventListener,
    removeEventListener: globalThis.removeEventListener, performance: globalThis.performance, setTimeout, clearTimeout };
  const dateNow = Date.now;
  const time = { monotonic: 10_000, wall: 1_700_000_000_000 };
  const timers = new Map();
  const workers = [];
  const channels = [];
  const notifications = [];
  const listeners = new Set();
  const visibilityListeners = new Set();
  const document = {
    visibilityState: "visible",
    addEventListener(type, listener) {
      assert.equal(type, "visibilitychange");
      visibilityListeners.add(listener);
    },
    removeEventListener(type, listener) {
      assert.equal(type, "visibilitychange");
      visibilityListeners.delete(listener);
    },
  };
  class BroadcastChannel {
    closed = false;
    posts = [];
    throwing = false;
    constructor(name) {
      assert.equal(name, "anonce.member-lock.v1");
      channels.push(this);
    }
    postMessage(data) {
      assert.equal(this.closed, false);
      if (this.throwing) throw new Error("synthetic notification failure");
      this.posts.push(structuredClone(data));
      for (const channel of channels) {
        if (channel !== this && !channel.closed) notifications.push(() => {
          if (!channel.closed) channel.onmessage?.({ data: structuredClone(data) });
        });
      }
    }
    close() { this.closed = true; }
  }
  class Worker {
    terminated = false;
    posts = [];
    throwing = false;
    constructor(url, options) {
      assert.equal(url.pathname.endsWith("/internal/memberworker/member-worker.mjs"), true);
      assert.deepEqual(options, { type: "module", credentials: "omit" });
      workers.push(this);
    }
    postMessage(message, transfers) {
      if (this.throwing) {
        this.failedInputs = message.inputs;
        throw new Error("synthetic transport failure");
      }
      this.posts.push(structuredClone(message, { transfer: transfers }));
    }
    terminate() { this.terminated = true; }
    send(data) { this.onmessage?.({ data: structuredClone(data) }); }
    ready() { this.send({ version: 1, type: "ready" }); }
    answer(value) { this.send({ version: 1, id: this.posts.at(-1).id, result: value }); }
  }
  globalThis.Worker = Worker;
  globalThis.performance = { now: () => time.monotonic };
  Date.now = () => time.wall;
  globalThis.BroadcastChannel = BroadcastChannel;
  globalThis.document = document;
  globalThis.addEventListener = (type, listener) => {
    assert.equal(type, "pagehide");
    listeners.add(listener);
  };
  globalThis.removeEventListener = (type, listener) => {
    assert.equal(type, "pagehide");
    listeners.delete(listener);
  };
  globalThis.setTimeout = (fn, delay) => {
    const id = {};
    timers.set(id, { fn, delay });
    return id;
  };
  globalThis.clearTimeout = (id) => timers.delete(id);
  const sessions = [];
  t.after(() => {
    for (const session of sessions) session.close();
    Object.assign(globalThis, original);
    Date.now = dateNow;
    assert.equal(timers.size, 0, "timer leaked");
    assert.equal(listeners.size, 0, "page listener leaked");
    assert.equal(visibilityListeners.size, 0, "visibility listener leaked");
    assert.ok(channels.every((channel) => channel.closed), "lock channel leaked");
  });
  return {
    workers,
    channels,
    document,
    visibilityListeners,
    time,
    open(Owner = MemberWorkerSession, ...args) { const session = new Owner(...args); sessions.push(session); return session; },
    deliver() { for (const notify of notifications.splice(0)) notify(); },
    pagehide(persisted) { for (const listener of [...listeners]) listener({ persisted }); },
    visibility(state) {
      document.visibilityState = state;
      for (const listener of [...visibilityListeners]) listener();
    },
    fire(delay) {
      const found = [...timers].find(([, timer]) => timer.delay === delay);
      assert.ok(found, "missing timeout");
      timers.delete(found[0]);
      found[1].fn();
    },
  };
}

test("member worker owner admission, snapshots, public results, and terminal lock", async (t) => {
  const h = harness(t);
  const session = h.open();
  const worker = h.workers[0];
  assert.equal(await session.create(Uint8Array.of(7)), null, "queued before startup");
  const denied = h.open();
  assert.equal(await denied.ready, false, "second live worker admitted");
  assert.equal(h.workers.length, 1);
  worker.ready();
  assert.equal(await session.ready, true);
  const password = Uint8Array.of(7, 0, 255);
  const pending = session.create(password);
  password.fill(0);
  assert.deepEqual([...worker.posts[0].inputs[0]], [7, 0, 255]);
  assert.equal(await session.request(), null, "busy call admitted");
  assert.equal(await session.unlock(password, new Uint8Array(108), new Uint8Array(32)), null);
  worker.answer(setup());
  assert.deepEqual(await pending, setup());
  assert.equal(worker.posts.length, 1);
  session.lock("extra"); session.close("extra");
  const requesting = session.request();
  worker.answer(enrollment());
  assert.deepEqual(await requesting, enrollment());
  const cancelled = session.create(Uint8Array.of(1));
  const late = worker.onmessage;
  session.lock(); session.lock(); session.close();
  assert.equal(worker.terminated, true);
  assert.equal(await cancelled, null);
  late({ data: { version: 1, id: worker.posts.at(-1).id, result: setup() } });
  assert.equal(await session.request(), null, "late response reopened owner");
  const replacement = h.open();
  assert.equal(h.workers.length, 2, "lock did not release singleton admission");
  h.workers[1].ready();
  assert.equal(await replacement.ready, true);
});

test("member worker closed Promise observes every terminal path after local cleanup", { timeout: 5000 }, async (t) => {
  const h = harness(t);
  const actions = {
    abort: (_session, _worker, _channel, controller) => controller.abort(),
    close: (session) => session.close(),
    lock: (session) => session.lock(),
    "global lock": () => lockMemberWorkers(),
    "peer lock": (_session, _worker, channel) => channel.onmessage({ data: "lock" }),
    "channel decode failure": (_session, _worker, channel) => channel.onmessageerror(),
    "notification failure": (session, _worker, channel) => { channel.throwing = true; session.lock(); },
    pagehide: () => h.pagehide(false),
    "cached pagehide": () => h.pagehide(true),
    visibility: () => h.visibility("hidden"),
    error: (_session, worker) => worker.onerror({ preventDefault() {} }),
    "message decode failure": (_session, worker) => worker.onmessageerror(),
    "invalid reply": (_session, worker) => worker.send({ version: 2 }),
    "startup timeout": () => h.fire(30_000),
    "operation timeout": () => h.fire(120_000),
    "lifetime timeout": () => h.fire(300_000),
    "clock failure": () => { h.time.wall = NaN; h.visibility("visible"); },
    "delayed deadline": () => { h.time.wall += 300_000; h.visibility("visible"); },
  };
  for (const state of ["startup", "idle", "pending"]) {
    for (const [name, act] of Object.entries(actions)) {
      if (name === "startup timeout" && state !== "startup") continue;
      if (name === "operation timeout" && state !== "pending") continue;
      const controller = new AbortController();
      const session = h.open(MemberWorkerSession, controller.signal), worker = h.workers.at(-1), channel = h.channels.at(-1);
      const closure = session.closed;
      assert.ok(closure instanceof Promise);
      assert.equal(session.closed, closure, "getter replaced the Promise");
      if (state !== "startup") { worker.ready(); assert.equal(await session.ready, true); }
      const pending = state === "pending" ? session.create(Uint8Array.of(7)) : null;
      const late = worker.onmessage;
      let observed = 0;
      const observation = closure.then((value) => {
        observed++;
        assert.equal(value, undefined, "closure exposed data or a reason");
        assert.equal(worker.terminated, true, "notified before requesting termination");
        assert.equal(worker.onmessage, null);
        assert.equal(worker.onerror, null);
        assert.equal(worker.onmessageerror, null);
        assert.equal(channel.closed, true);
        assert.equal(channel.onmessage, null);
        assert.equal(channel.onmessageerror, null);
        assert.equal(h.visibilityListeners.size, 0);
        assert.equal(getEventListeners(controller.signal, "abort").length, 0, "abort listener leaked");
      });
      await Promise.resolve();
      assert.equal(observed, 0, `${state}/${name}: live owner reported closed`);
      act(session, worker, channel, controller);
      assert.equal(observed, 0, "observer ran synchronously inside termination");
      await observation;
      assert.equal(await session.ready, state !== "startup", "closure changed readiness history");
      if (pending) assert.equal(await pending, null);
      session.close(); session.lock();
      late({ data: { version: 1, type: "ready" } });
      assert.equal(await session.request(), null);
      assert.equal(await session.closed, undefined, "late subscriber missed closure");
      assert.equal(observed, 1, "closure notified repeatedly");
      h.document.visibilityState = "visible";
      h.time.wall = 1_700_000_000_000;
      const replacement = h.open();
      h.workers.at(-1).ready();
      assert.equal(await replacement.ready, true, "closure retained singleton admission");
      replacement.close();
    }
  }
});

test("member worker abort admission rejects invalid and already-aborted signals before resources", async (t) => {
  const h = harness(t);
  const aborted = new AbortController();
  aborted.abort(new Proxy({}, { get() { assert.fail("abort reason inspected"); } }));
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  for (const args of [[null], [false], [1], ["signal"], [{}], [new EventTarget()],
    [Object.create(AbortSignal.prototype)], [revoked.proxy], [aborted.signal], [undefined, undefined]]) {
    const session = h.open(MemberWorkerSession, ...args);
    assert.equal(await session.ready, false);
    assert.equal(await session.closed, undefined);
    assert.equal(await session.request(), null);
    assert.equal(h.workers.length, 0);
    assert.equal(h.channels.length, 0);
    assert.equal(getEventListeners(aborted.signal, "abort").length, 0);
  }
  const controller = new AbortController();
  const live = h.open(MemberWorkerSession, controller.signal);
  const denied = h.open(MemberWorkerSession, controller.signal);
  assert.equal(await denied.closed, undefined);
  assert.equal(getEventListeners(controller.signal, "abort").length, 1, "denied owner registered a listener");
  controller.abort();
  assert.equal(await live.ready, false);
  assert.equal(await live.closed, undefined);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  const replacement = h.open(MemberWorkerSession, undefined);
  h.workers.at(-1).ready();
  assert.equal(await replacement.ready, true);
});

test("member worker abort is local, ignores shadowed properties and reasons, and never revives", async (t) => {
  const h = harness(t);
  const controller = new AbortController(), signal = controller.signal;
  for (const name of ["aborted", "reason", "addEventListener", "removeEventListener"]) {
    Object.defineProperty(signal, name, { get() { assert.fail(`shadowed signal ${name} read`); } });
  }
  const session = h.open(MemberWorkerSession, signal), worker = h.workers.at(-1);
  worker.ready();
  assert.equal(await session.ready, true);
  const created = session.create(Uint8Array.of(7));
  worker.answer(setup());
  assert.deepEqual(await created, setup());
  const pending = session.unlock(Uint8Array.of(7), new Uint8Array(108), new Uint8Array(32));
  const late = worker.onmessage;
  controller.abort(new Proxy({}, { get() { assert.fail("abort reason inspected"); } }));
  assert.equal(worker.terminated, true, "abort did not synchronously request termination");
  assert.equal(await pending, null);
  assert.equal(await session.closed, undefined);
  assert.equal(await session.ready, true, "abort rewrote settled readiness");
  assert.equal(h.channels[0].posts.length, 0, "local cancellation notified peers");
  late({ data: { version: 1, id: worker.posts.at(-1).id, result: enrollment() } });
  assert.equal(await session.request(), null);
  const replacement = h.open();
  h.workers.at(-1).ready();
  controller.abort();
  assert.equal(await replacement.ready, true);
  assert.equal(h.workers.at(-1).terminated, false, "old signal closed a replacement owner");
});

test("member worker rechecks abort state when event delivery is suppressed", async (t) => {
  const h = harness(t);
  for (const boundary of ["startup", "admission", "busy", "reply", "visibility"]) {
    const controller = new AbortController(), signal = controller.signal;
    signal.addEventListener("abort", (event) => event.stopImmediatePropagation());
    const session = h.open(MemberWorkerSession, signal), worker = h.workers.at(-1);
    if (boundary !== "startup") worker.ready();
    const pending = ["busy", "reply"].includes(boundary) ? session.create(Uint8Array.of(7)) : null;
    controller.abort();
    assert.equal(worker.terminated, false, "test did not suppress abort delivery");
    if (boundary === "startup") worker.ready();
    else if (boundary === "reply") worker.answer(setup());
    else if (boundary === "visibility") h.visibility("visible");
    else assert.equal(await session.request(), null);
    assert.equal(worker.terminated, true);
    assert.equal(await session.closed, undefined);
    assert.equal(await session.ready, boundary !== "startup");
    if (pending) assert.equal(await pending, null);
    assert.equal(getEventListeners(signal, "abort").length, 1, "owner abort listener leaked");
    assert.equal(h.channels.at(-1).posts.length, 0);
  }
});

test("member worker removes abort listeners on failed startup without cancelling the host signal", async (t) => {
  const h = harness(t);
  const Worker = globalThis.Worker;
  for (const failure of ["hidden", "clock", "worker"]) {
    const controller = new AbortController();
    h.document.visibilityState = failure === "hidden" ? "hidden" : "visible";
    h.time.wall = failure === "clock" ? NaN : 1_700_000_000_000;
    globalThis.Worker = failure === "worker" ? class { constructor() { throw new Error("synthetic startup failure"); } } : Worker;
    const session = h.open(MemberWorkerSession, controller.signal);
    assert.equal(await session.closed, undefined);
    assert.equal(await session.ready, false);
    assert.equal(getEventListeners(controller.signal, "abort").length, 0);
    assert.equal(controller.signal.aborted, false, "local cleanup cancelled host scope");
  }
});

test("member worker closed Promise settles for failed construction and denied owners", { timeout: 5000 }, async (t) => {
  const h = harness(t);
  const owner = h.open();
  const denied = h.open();
  assert.equal(await denied.closed, undefined);
  assert.equal(await denied.ready, false);
  let ownerClosed = false;
  void owner.closed.then(() => { ownerClosed = true; });
  await Promise.resolve();
  assert.equal(ownerClosed, false, "denied construction closed the active owner");
  owner.close();
  assert.equal(await owner.closed, undefined);
  const Worker = globalThis.Worker, Channel = globalThis.BroadcastChannel;
  for (const failure of ["hidden", "clock", "channel", "worker"]) {
    h.document.visibilityState = failure === "hidden" ? "hidden" : "visible";
    h.time.wall = failure === "clock" ? NaN : 1_700_000_000_000;
    globalThis.BroadcastChannel = failure === "channel" ? class { constructor() { throw new Error("synthetic channel failure"); } } : Channel;
    globalThis.Worker = failure === "worker" ? class { constructor() { throw new Error("synthetic startup failure"); } } : Worker;
    const session = h.open();
    assert.equal(await session.closed, undefined, failure);
    assert.equal(await session.ready, false);
  }
});

test("member worker closed Promise stays pending across rejected calls and successful work", async (t) => {
  const h = harness(t);
  const session = h.open(), worker = h.workers.at(-1);
  let closed = false;
  void session.closed.then(() => { closed = true; });
  assert.equal(await session.request(), null);
  worker.ready();
  assert.equal(await session.ready, true);
  assert.equal(await session.create(new Uint8Array()), null);
  const failed = session.unlock(Uint8Array.of(7), new Uint8Array(108), new Uint8Array(32));
  worker.answer(null); // Invalid backup/password, not terminal transport failure.
  assert.equal(await failed, null);
  const created = session.create(Uint8Array.of(7));
  assert.equal(await session.request(), null); // Busy admission is not terminal.
  worker.answer(setup());
  assert.deepEqual(await created, setup());
  const requested = session.request();
  worker.answer(enrollment());
  assert.deepEqual(await requested, enrollment());
  session.lock("extra"); session.close("extra");
  await Promise.resolve();
  assert.equal(closed, false, "nonterminal action reported closure");
  session.close();
  assert.equal(await session.closed, undefined);
  assert.equal(closed, true);
});

test("member worker rejects input types, arity, bounds, and hostile properties before posting", async (t) => {
  const h = harness(t);
  const session = h.open();
  const worker = h.workers[0];
  worker.ready();
  const hostile = new Proxy({}, { get() { assert.fail("input getter"); }, getPrototypeOf() { assert.fail("input prototype"); } });
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  const detached = new Uint8Array(32);
  structuredClone(detached.buffer, { transfer: [detached.buffer] });
  const invalid = [undefined, null, true, 1, 0n, Symbol(), {}, [], "secret", hostile, revoked.proxy,
    new ArrayBuffer(32), new DataView(new ArrayBuffer(32)), new Uint16Array(32), new Uint8ClampedArray(32),
    detached, new Uint8Array(), new Uint8Array(1025), new Uint8Array(new SharedArrayBuffer(32))];
  const forged = new SharedArrayBuffer(32); Object.setPrototypeOf(forged, ArrayBuffer.prototype);
  invalid.push(new Uint8Array(forged));
  const password = Uint8Array.of(1), backup = new Uint8Array(108), key = new Uint8Array(32);
  for (const value of invalid) {
    assert.equal(await session.create(value), null);
    assert.equal(await session.unlock(value, backup, key), null);
    assert.equal(await session.unlock(password, value, key), null);
    assert.equal(await session.unlock(password, backup, value), null);
  }
  for (const args of [[], [password, password]]) assert.equal(await session.create(...args), null);
  for (const args of [[], [password], [password, backup], [password, backup, key, key]]) assert.equal(await session.unlock(...args), null);
  assert.equal(await session.request(1), null);
  for (const size of [1, 107, 109, 1024]) assert.equal(await session.unlock(password, new Uint8Array(size), key), null);
  for (const size of [1, 31, 33, 1024]) assert.equal(await session.unlock(password, backup, new Uint8Array(size)), null);
  assert.equal(worker.posts.length, 0);
  const storage = Uint8Array.of(9, 7, 8, 9);
  const view = storage.subarray(1, 3);
  for (const name of ["buffer", "length", "byteLength", "byteOffset", "constructor", Symbol.iterator]) {
    Object.defineProperty(view, name, { get() { assert.fail("shadowed property"); } });
  }
  const pending = session.create(view);
  assert.deepEqual([...worker.posts[0].inputs[0]], [7, 8]);
  assert.deepEqual([...storage], [9, 7, 8, 9]);
  worker.answer(setup());
  assert.ok(await pending);
});

test("member worker timeouts terminate startup, operations, and total lifetime", async (t) => {
  const h = harness(t);
  for (const delay of [30_000, 120_000, 300_000]) {
    const session = h.open(), worker = h.workers.at(-1);
    let pending;
    if (delay !== 30_000) {
      worker.ready();
      assert.equal(await session.ready, true);
      pending = session.create(Uint8Array.of(1));
    }
    h.fire(delay);
    assert.equal(worker.terminated, true);
    if (pending) assert.equal(await pending, null);
    else assert.equal(await session.ready, false);
    assert.equal(await session.request(), null);
  }
});

test("member worker rejects delayed startup at either clock deadline without waiting for timers", async (t) => {
  const h = harness(t);
  for (const clock of ["monotonic", "wall"]) {
    for (const elapsed of [29_999, 30_000, 30_001]) {
      for (const boundary of ["ready", "call", "visibility"]) {
        const session = h.open(), worker = h.workers.at(-1), channel = h.channels.at(-1);
        h.time[clock] += elapsed;
        const late = worker.onmessage;
        if (boundary === "call") assert.equal(await session.request(), null);
        if (boundary === "visibility") h.visibility("visible");
        worker.ready();
        const expired = elapsed >= 30_000;
        assert.equal(await session.ready, !expired, `${clock}/${elapsed}/${boundary}`);
        assert.equal(worker.terminated, expired);
        if (expired) {
          late({ data: { version: 1, type: "ready" } });
          assert.equal(await session.request(), null, "late startup reopened owner");
          assert.deepEqual(channel.posts, [], "expiry notified peers");
        }
        session.close();
      }
    }
  }
});

test("member worker enforces delayed operation deadlines before replies and busy calls", async (t) => {
  const h = harness(t);
  for (const clock of ["monotonic", "wall"]) {
    for (const method of ["create", "unlock", "request"]) {
      for (const elapsed of [119_999, 120_000, 120_001]) {
        for (const boundary of ["reply", "busy", "visibility"]) {
          const session = h.open(), worker = h.workers.at(-1), channel = h.channels.at(-1);
          worker.ready();
          // Operation budgets start on admission, not at owner construction.
          h.time[clock] += 15_000;
          const inputs = { create: [Uint8Array.of(7)], unlock: [Uint8Array.of(7), new Uint8Array(108), new Uint8Array(32)], request: [] };
          const pending = session[method](...inputs[method]);
          const late = worker.onmessage, id = worker.posts.at(-1).id;
          h.time[clock] += elapsed;
          if (boundary === "busy") assert.equal(await session.create(Uint8Array.of(7)), null);
          if (boundary === "visibility") h.visibility("visible");
          const value = method === "create" ? setup() : enrollment();
          worker.answer(value);
          const expired = elapsed >= 120_000;
          assert.deepEqual(await pending, expired ? null : value, `${clock}/${method}/${elapsed}/${boundary}`);
          assert.equal(worker.terminated, expired);
          assert.equal(worker.posts.length, 1, "busy or expired call posted input");
          if (expired) {
            late({ data: { version: 1, id, result: value } });
            assert.equal(await session.request(), null, "late reply reopened owner");
            assert.deepEqual(channel.posts, [], "expiry notified peers");
          }
          session.close();
        }
      }
    }
  }
});

test("member worker lifetime is never renewed by successful work or delayed timers", async (t) => {
  const h = harness(t);
  for (const clock of ["monotonic", "wall"]) {
    for (const boundary of ["create", "unlock", "request", "reply", "visibility"]) {
      const session = h.open(), worker = h.workers.at(-1), channel = h.channels.at(-1);
      worker.ready();
      h.time[clock] += 299_999;
      const first = session.request();
      worker.answer(enrollment());
      assert.deepEqual(await first, enrollment(), "closed before lifetime deadline");
      const pending = boundary === "reply" ? session.request() : null;
      h.time[clock]++;
      const hostile = new Proxy({}, { get() { assert.fail("expired input inspected"); } });
      if (boundary === "create") assert.equal(await session.create(hostile), null);
      if (boundary === "unlock") assert.equal(await session.unlock(hostile, hostile, hostile), null);
      if (boundary === "request") assert.equal(await session.request(), null);
      if (boundary === "reply") { worker.answer(enrollment()); assert.equal(await pending, null); }
      if (boundary === "visibility") h.visibility("visible");
      assert.equal(worker.terminated, true, `${clock}/${boundary}`);
      assert.equal(worker.posts.length, boundary === "reply" ? 2 : 1);
      assert.deepEqual(channel.posts, []);
      const replacement = h.open();
      h.workers.at(-1).ready();
      assert.equal(await replacement.ready, true, "expiry retained owner admission");
      replacement.close();
    }
  }
});

test("member worker fails closed on unavailable or invalid clocks before worker startup", async (t) => {
  const h = harness(t);
  const performance = globalThis.performance, wall = Date.now;
  for (const clock of ["monotonic", "wall"]) {
    const hostile = { valueOf() { assert.fail("clock value coerced"); } };
    for (const value of [undefined, null, false, "10000", 1n, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, hostile,
      ...(clock === "monotonic" ? [-1] : [1.5])]) {
      const initial = h.time[clock];
      h.time[clock] = value;
      assert.equal(await h.open().ready, false, clock);
      h.time[clock] = initial;
    }
  }
  for (const value of [undefined, null, {}, { now: null }, { now() { throw new Error("synthetic clock failure"); } }]) {
    globalThis.performance = value;
    assert.equal(await h.open().ready, false);
  }
  globalThis.performance = performance;
  for (const value of [undefined, null, () => { throw new Error("synthetic clock failure"); }]) {
    Date.now = value;
    assert.equal(await h.open().ready, false);
  }
  Date.now = wall;
  assert.equal(h.workers.length, 0);
  assert.equal(h.channels.length, 0);
  const valid = h.open();
  h.workers.at(-1).ready();
  assert.equal(await valid.ready, true, "clock failure retained admission");
});

test("member worker clock failures and rollback terminate pending work locally", async (t) => {
  const h = harness(t);
  for (const clock of ["monotonic", "wall"]) {
    for (const failure of ["rollback", "invalid", "throw"]) {
      for (const boundary of ["ready", "call", "reply", "visibility"]) {
        const session = h.open(), worker = h.workers.at(-1), channel = h.channels.at(-1);
        h.time[clock] += 100;
        // Record a later reading, so rollback above construction time also fails.
        assert.equal(await session.request(), null);
        let pending;
        if (boundary !== "ready") {
          worker.ready();
          pending = session.create(Uint8Array.of(7));
        }
        const initial = h.time[clock];
        if (failure === "rollback") h.time[clock]--;
        if (failure === "invalid") h.time[clock] = NaN;
        if (failure === "throw") Object.defineProperty(h.time, clock, {
          configurable: true, get() { throw new Error("synthetic clock failure"); },
        });
        if (boundary === "ready") worker.ready();
        if (boundary === "call") assert.equal(await session.request(), null);
        if (boundary === "reply") worker.answer(setup());
        if (boundary === "visibility") h.visibility("visible");
        assert.equal(worker.terminated, true, `${clock}/${failure}/${boundary}`);
        assert.equal(await session.ready, boundary !== "ready");
        if (pending) assert.equal(await pending, null);
        assert.deepEqual(channel.posts, [], "clock failure notified peers");
        Object.defineProperty(h.time, clock, { configurable: true, writable: true, value: initial });
        assert.equal(await session.request(), null, "clock recovery reopened owner");
      }
    }
  }
});

test("member worker rechecks clocks after lifecycle registration and cleans up failed startup", async (t) => {
  const h = harness(t);
  const add = h.document.addEventListener;
  for (const clock of ["monotonic", "wall"]) {
    for (const change of [30_000, -1, NaN]) {
      const initial = h.time[clock];
      h.document.addEventListener = (type, listener) => {
        add(type, listener);
        h.time[clock] += change;
      };
      assert.equal(await h.open().ready, false, `${clock}/${change}`);
      assert.equal(h.workers.length, 0, "started after clock admission failed");
      assert.equal(h.visibilityListeners.size, 0);
      assert.ok(h.channels.every((channel) => channel.closed));
      h.time[clock] = initial;
    }
  }
});

test("member worker captures owner clocks without resetting deadlines on global replacement", async (t) => {
  const h = harness(t);
  const session = h.open(), worker = h.workers.at(-1);
  worker.ready();
  const pending = session.request();
  globalThis.performance = { now() { assert.fail("replacement monotonic clock used"); } };
  Date.now = () => { assert.fail("replacement wall clock used"); };
  h.time.wall += 120_000; // Monotonic time does not advance, as on some sleeping systems.
  worker.answer(enrollment());
  assert.equal(await pending, null);
  assert.equal(worker.terminated, true);
});

test("member worker lock notifies other owners without secrets, echo, or replacement", async (t) => {
  const h = harness(t);
  // Separate module instances model independent owner admission in other realms.
  // Actual browser origin/partition behavior is not established by this harness.
  const { MemberWorkerSession: Peer } = await import("../internal/memberworker/member-client.mjs?lock-peer");
  for (const state of ["startup", "idle", "pending"]) {
    const sender = h.open(), receiver = h.open(Peer);
    const [local, remote] = h.workers.slice(-2);
    const [source, destination] = h.channels.slice(-2);
    local.ready();
    let pending;
    if (state !== "startup") remote.ready();
    if (state === "pending") pending = receiver.unlock(Uint8Array.of(7), new Uint8Array(108), new Uint8Array(32));
    const late = remote.onmessage;
    sender.lock("extra");
    assert.deepEqual(source.posts, []);
    sender.lock(); sender.lock(); sender.close();
    assert.equal(local.terminated, true, "local lock waited for peer delivery");
    assert.deepEqual(source.posts, ["lock"], "notification contained additional data or repeated");
    h.deliver();
    assert.equal(remote.terminated, true);
    assert.equal(await receiver.ready, state !== "startup");
    if (pending) assert.equal(await pending, null);
    assert.equal(await receiver.request(), null);
    assert.deepEqual(destination.posts, [], "received lock echoed");
    late({ data: { version: 1, type: "ready" } });
    assert.equal(await receiver.request(), null);
    const replacement = h.open(Peer);
    h.workers.at(-1).ready();
    h.deliver();
    assert.equal(await replacement.ready, true, "old notification locked a new owner");
    replacement.close();
  }
});

test("member worker local disposal and pagehide close resources without broadcasting", async (t) => {
  const h = harness(t);
  for (const action of ["close", "pagehide", "cached-pagehide"]) {
    const session = h.open(), worker = h.workers.at(-1), channel = h.channels.at(-1);
    worker.ready();
    const pending = session.create(Uint8Array.of(1));
    if (action === "close") session.close();
    else h.pagehide(action === "cached-pagehide");
    assert.equal(worker.terminated, true);
    assert.equal(await pending, null);
    assert.equal(await session.request(), null, "page lifecycle resurrected session");
    assert.equal(channel.closed, true);
    assert.equal(channel.onmessage, null);
    assert.equal(channel.onmessageerror, null);
    session.lock();
    assert.deepEqual(channel.posts, [], "local disposal broadcast or closed session reused");
  }
});

test("member worker visibility loss terminates startup, idle, unlocked, and pending sessions locally", async (t) => {
  const h = harness(t);
  for (const state of ["startup", "idle", "unlocked", "pending-create", "pending-unlock", "pending-request"]) {
    const session = h.open(), worker = h.workers.at(-1), channel = h.channels.at(-1);
    const visibility = [...h.visibilityListeners][0];
    const late = worker.onmessage;
    let pending;
    if (state !== "startup") {
      worker.ready();
      assert.equal(await session.ready, true);
    }
    if (state === "unlocked") {
      pending = session.create(Uint8Array.of(7));
      worker.answer(setup());
      assert.ok(await pending);
      pending = null;
    }
    if (state === "pending-create") pending = session.create(Uint8Array.of(7));
    if (state === "pending-unlock") pending = session.unlock(Uint8Array.of(7), new Uint8Array(108), new Uint8Array(32));
    if (state === "pending-request") pending = session.request();
    h.visibility("visible");
    assert.equal(worker.terminated, false, "visible notification closed session");
    h.visibility("hidden");
    assert.equal(worker.terminated, true, state);
    assert.equal(await session.ready, state !== "startup");
    if (pending) assert.equal(await pending, null);
    assert.equal(h.visibilityListeners.size, 0);
    assert.equal(channel.closed, true);
    assert.deepEqual(channel.posts, [], "backgrounding notified peers");
    h.visibility("visible");
    visibility(); // A queued old event cannot resurrect the instance.
    late({ data: { version: 1, type: "ready" } });
    assert.equal(await session.request(), null, "visibility restored old instance");
    const replacement = h.open();
    h.workers.at(-1).ready();
    visibility();
    assert.equal(await replacement.ready, true, "stale event closed replacement");
    replacement.close();
  }
});

test("member worker rejects hidden or unavailable visibility before starting a worker", async (t) => {
  const h = harness(t);
  for (const state of ["hidden", "prerender", "", undefined, null, true, { toString() { assert.fail("state coerced"); } }]) {
    h.document.visibilityState = state;
    const session = h.open();
    assert.equal(await session.ready, false);
    assert.equal(await session.create(Uint8Array.of(7)), null);
  }
  h.document.visibilityState = "visible";
  const documents = [undefined, null, {}, { visibilityState: "visible" },
    { ...h.document, addEventListener: undefined }, { ...h.document, removeEventListener: undefined }];
  const throwing = { ...h.document, get visibilityState() { throw new Error("synthetic visibility failure"); } };
  documents.push(throwing);
  for (const document of documents) {
    globalThis.document = document;
    assert.equal(await h.open().ready, false);
  }
  assert.equal(h.workers.length, 0);
  assert.equal(h.channels.length, 0, "allocated lock channel for invisible page");
  globalThis.document = h.document;
  const visible = h.open();
  h.workers.at(-1).ready();
  assert.equal(await visible.ready, true, "failed startup retained admission");
});

test("member worker visibility registration failures clean up without starting a worker", async (t) => {
  const h = harness(t);
  const add = h.document.addEventListener;
  for (const failure of ["throw", "hidden"]) {
    h.document.visibilityState = "visible";
    h.document.addEventListener = (type, listener) => {
      add(type, listener);
      if (failure === "throw") throw new Error("synthetic visibility registration failure");
      h.document.visibilityState = "hidden";
    };
    assert.equal(await h.open().ready, false);
    assert.equal(h.workers.length, 0, "started after visibility registration failed");
    assert.equal(h.visibilityListeners.size, 0);
    assert.ok(h.channels.every((channel) => channel.closed));
  }
});

test("member worker rechecks visibility before input admission and response publication", async (t) => {
  const h = harness(t);
  for (const boundary of ["create", "unlock", "request", "startup-call", "busy", "ready", "result", "read-failure"]) {
    h.document.visibilityState = "visible";
    const session = h.open(), worker = h.workers.at(-1);
    let pending;
    if (boundary !== "ready" && boundary !== "startup-call") worker.ready();
    if (boundary === "result" || boundary === "busy") pending = session.create(Uint8Array.of(7));
    h.document.visibilityState = "hidden"; // No notification delivered yet.
    const hostile = new Proxy({}, { get() { assert.fail("hidden-page input inspected"); } });
    if (boundary === "read-failure") Object.defineProperty(h.document, "visibilityState", {
      configurable: true, get() { throw new Error("synthetic visibility failure"); },
    });
    if (boundary === "create") assert.equal(await session.create(hostile), null);
    if (boundary === "unlock") assert.equal(await session.unlock(hostile, hostile, hostile), null);
    if (["request", "read-failure", "startup-call", "busy"].includes(boundary)) assert.equal(await session.request(), null);
    if (boundary === "ready") { worker.ready(); assert.equal(await session.ready, false); }
    if (boundary === "result") { worker.answer(setup()); assert.equal(await pending, null); }
    if (boundary === "busy") assert.equal(await pending, null);
    assert.equal(worker.terminated, true, boundary);
    assert.equal(worker.posts.length, boundary === "result" || boundary === "busy" ? 1 : 0);
    Object.defineProperty(h.document, "visibilityState", { configurable: true, writable: true, value: "visible" });
    assert.equal(await session.request(), null);
  }
});

test("member worker pins its owner document and background locking does not notify peers", async (t) => {
  const h = harness(t);
  const local = h.open(), localWorker = h.workers.at(-1);
  const { MemberWorkerSession: Peer } = await import("../internal/memberworker/member-client.mjs?visibility-peer");
  // A separate visible document models a peer page in another realm.
  const peerDocument = new EventTarget();
  peerDocument.visibilityState = "visible";
  globalThis.document = peerDocument;
  const peer = h.open(Peer), peerWorker = h.workers.at(-1);
  localWorker.ready(); peerWorker.ready();
  h.visibility("hidden");
  h.deliver();
  assert.equal(localWorker.terminated, true, "read replacement global document instead of owner");
  assert.equal(peerWorker.terminated, false, "backgrounding locked visible peer");
  assert.equal(h.visibilityListeners.size, 0, "removed listener from wrong document");
  const pending = peer.request();
  peerWorker.answer(enrollment());
  assert.ok(await pending);
});

test("member worker local close isolates peers and queued locks cannot target later owners", async (t) => {
  const h = harness(t);
  const { MemberWorkerSession: Peer } = await import("../internal/memberworker/member-client.mjs?queued-peer");
  const sender = h.open(), remote = h.open(Peer);
  const [localWorker, remoteWorker] = h.workers;
  localWorker.ready(); remoteWorker.ready();
  sender.close();
  h.deliver();
  assert.equal(remoteWorker.terminated, false, "local close locked another owner");
  const nextSender = h.open();
  h.workers.at(-1).ready();
  nextSender.lock(); // Queued specifically for the old remote channel.
  const late = h.channels[1].onmessage;
  remote.close();
  const replacement = h.open(Peer), replacementWorker = h.workers.at(-1);
  replacementWorker.ready();
  h.deliver();
  late({ data: "lock" });
  assert.equal(replacementWorker.terminated, false, "stale lock affected a replacement");
  assert.equal(await replacement.ready, true);
});

test("member worker lock channel failures terminate locally with no fallback", async (t) => {
  const h = harness(t);
  for (const failure of ["post", "decode", "unknown", "malformed"]) {
    const session = h.open(), worker = h.workers.at(-1), channel = h.channels.at(-1);
    worker.ready();
    const pending = session.create(Uint8Array.of(1));
    if (failure === "post") { channel.throwing = true; session.lock(); }
    if (failure === "decode") channel.onmessageerror();
    if (failure === "unknown") channel.onmessage({ data: "unknown-version" });
    if (failure === "malformed") channel.onmessage({ get data() { assert.fail("notification data inspected"); } });
    assert.equal(worker.terminated, true);
    assert.equal(await pending, null);
    assert.equal(await session.request(), null);
    assert.equal(channel.closed, true);
    assert.deepEqual(channel.posts, []);
  }
  const facilities = { BroadcastChannel: globalThis.BroadcastChannel,
    addEventListener: globalThis.addEventListener, removeEventListener: globalThis.removeEventListener };
  for (const missing of Object.keys(facilities)) {
    globalThis[missing] = undefined;
    const before = h.workers.length;
    const session = h.open();
    assert.equal(await session.ready, false);
    assert.equal(await session.create(Uint8Array.of(1)), null);
    assert.equal(h.workers.length, before, "started without required coordination");
    Object.assign(globalThis, facilities);
  }
  globalThis.BroadcastChannel = class { constructor() { throw new Error("synthetic channel failure"); } };
  const before = h.workers.length;
  assert.equal(await h.open().ready, false);
  assert.equal(h.workers.length, before);
  Object.assign(globalThis, facilities);
  globalThis.addEventListener = (type, listener) => {
    facilities.addEventListener(type, listener);
    throw new Error("synthetic lifecycle registration failure");
  };
  assert.equal(await h.open().ready, false);
  assert.equal(h.workers.length, before, "worker started after lifecycle registration failed");
});

test("member worker global lock works without a live local owner and reports posting failures", async (t) => {
  const h = harness(t);
  const { MemberWorkerSession: Peer } = await import("../internal/memberworker/member-client.mjs?global-peer");
  const remote = h.open(Peer), worker = h.workers.at(-1);
  worker.ready();
  assert.equal(lockMemberWorkers("extra"), false);
  assert.equal(h.channels.length, 1);
  assert.equal(lockMemberWorkers(), true);
  assert.deepEqual(h.channels.at(-1).posts, ["lock"]);
  assert.equal(h.channels.at(-1).closed, true);
  h.deliver();
  assert.equal(worker.terminated, true);
  assert.equal(await remote.request(), null);
  const successful = h.open(), successfulWorker = h.workers.at(-1);
  successfulWorker.ready();
  const cancelling = successful.request();
  assert.equal(lockMemberWorkers(), true);
  assert.equal(await cancelling, null);
  assert.equal(successfulWorker.terminated, true);
  h.deliver();
  const Channel = globalThis.BroadcastChannel;
  for (const failure of ["construction", "post"]) {
    globalThis.BroadcastChannel = Channel;
    const local = h.open(), localWorker = h.workers.at(-1);
    localWorker.ready();
    const pending = local.create(Uint8Array.of(1));
    globalThis.BroadcastChannel = failure === "construction"
      ? class { constructor() { throw new Error("synthetic notification failure"); } }
      : class extends Channel { constructor(name) { super(name); this.throwing = true; } };
    assert.equal(lockMemberWorkers(), false);
    assert.equal(localWorker.terminated, true, "posting failure prevented local lock");
    assert.equal(await pending, null);
    assert.equal(h.channels.at(-1).closed, true);
  }
});

test("member worker protocol and transport failures never publish output or restart", async (t) => {
  const h = harness(t);
  const failures = [null, {}, { version: 2, id: 1, result: setup() }, { version: 1, id: 2, result: setup() },
    { version: 1, type: "ready" }, { version: 1, type: "failed" },
    { version: 1, id: 1, result: enrollment() }, { version: 1, id: 1, result: { ...setup(), privateKey: new Uint8Array(64) } },
    { version: 1, id: 1, result: { ...setup(), backup: new Uint8Array(109) } }];
  for (const message of failures) {
    const session = h.open(), worker = h.workers.at(-1);
    worker.ready();
    const pending = session.create(Uint8Array.of(1));
    worker.send(message);
    assert.equal(await pending, null);
    assert.equal(worker.terminated, true);
    assert.equal(await session.request(), null);
  }
  for (const pendingNext of [false, true]) {
    const session = h.open(), worker = h.workers.at(-1);
    worker.ready();
    const first = session.request();
    worker.answer(null);
    assert.equal(await first, null);
    const next = pendingNext ? session.request() : null;
    worker.send({ version: 1, id: 1, result: enrollment() });
    if (next) assert.equal(await next, null, "stale reply settled newer request");
    assert.equal(worker.terminated, true, "duplicate/stale reply ignored instead of closing");
  }
  for (const type of ["error", "messageerror", "post", "close-before-ready", "invalid-startup"]) {
    const session = h.open(), worker = h.workers.at(-1);
    if (type === "close-before-ready") session.close();
    else if (type === "invalid-startup") worker.send({ version: 2, type: "ready" });
    else {
      worker.ready();
      if (type === "post") worker.throwing = true;
      const pending = session.create(Uint8Array.of(7));
      if (type === "error") worker.onerror({ preventDefault() {} });
      if (type === "messageerror") worker.onmessageerror();
      assert.equal(await pending, null);
      if (type === "post") assert.ok(worker.failedInputs.every((input) => input.every((byte) => byte === 0)), "failed snapshot not cleared");
    }
    assert.equal(worker.terminated, true);
  }
  globalThis.Worker = class { constructor() { throw new Error("synthetic startup failure"); } };
  const failed = h.open();
  assert.equal(await failed.ready, false);
  assert.equal(await failed.create(Uint8Array.of(1)), null);
});

test("member worker bounded protocol parser regression corpus", () => {
  const password = Uint8Array.of(1), backup = new Uint8Array(108), key = new Uint8Array(32);
  const valid = { version: 1, id: 1, method: "unlock", inputs: [password, backup, key] };
  assert.equal(command(valid), true);
  for (const value of [null, undefined, true, 1, "request", [], {}, { ...valid, extra: 1 },
    { ...valid, version: 2 }, { ...valid, id: 0 }, { ...valid, id: -1 }, { ...valid, id: 1.5 },
    { ...valid, id: Number.MAX_SAFE_INTEGER + 1 }, { ...valid, method: "__proto__" },
    { ...valid, method: "close" }, { ...valid, method: {} }, { ...valid, inputs: [password] }]) {
    assert.equal(command(value), false);
  }
  for (let size = 0; size <= 1025; size++) {
    const bytes = new Uint8Array(size);
    assert.equal(inputViews("create", [bytes]) !== null, size >= 1 && size <= 1024);
    assert.equal(command({ ...valid, inputs: [password, bytes, key] }), size === 108);
    assert.equal(command({ ...valid, inputs: [password, backup, bytes] }), size === 32);
    assert.equal(byteView(bytes, 32) !== null, size === 32);
  }
  assert.equal(result(null, "create"), true);
  assert.equal(result(setup(), "create"), true);
  assert.equal(result(enrollment(), "unlock"), true);
  assert.equal(result(setup(), "request"), false);
  for (const value of [undefined, false, [], {}, { ...enrollment(), csr: new Uint8Array(130) },
    { ...enrollment(), publicKey: new Uint8Array(new SharedArrayBuffer(32)) }]) assert.equal(result(value, "request"), false);
});

test("member worker bounded command fuzzing", () => {
  // Generated metadata supplies an independent admission oracle. Each iteration
  // has at most four views of at most 1025 elements; no KDF or I/O occurs.
  const choose = (values) => values[randomInt(values.length)];
  for (let iteration = 0; iteration < 2048; iteration++) {
    const method = choose(["create", "unlock", "request", "close", "__proto__", "", null]);
    const version = randomInt(3), id = choose([-1, 0, 1, 2, 1.5, Number.MAX_SAFE_INTEGER + 1]);
    const metadata = Array.from({ length: randomInt(5) }, () => ({
      size: choose([0, 1, 31, 32, 33, 107, 108, 109, 1024, 1025]), type: randomInt(3),
    }));
    const inputs = metadata.map(({ size, type }) => type === 0 ? new Uint8Array(size) : type === 1 ? new Uint16Array(size) : null);
    const value = { version, id, method, inputs };
    const extra = randomInt(2) === 0;
    if (extra) value.extra = true;
    let expected = false;
    if (!extra && version === 1 && (id === 1 || id === 2)) {
      if (method === "request") expected = metadata.length === 0;
      if (method === "create") expected = metadata.length === 1 && metadata[0].type === 0 && metadata[0].size >= 1 && metadata[0].size <= 1024;
      if (method === "unlock") expected = metadata.length === 3 && metadata.every(({ type }) => type === 0) &&
        metadata[0].size >= 1 && metadata[0].size <= 1024 && metadata[1].size === 108 && metadata[2].size === 32;
    }
    assert.equal(command(value), expected, "command admission differs from generated bounds");
  }
});
