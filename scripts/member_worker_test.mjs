// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { randomInt } from "node:crypto";
import { test } from "node:test";
import { byteView, command, inputViews, result } from "../internal/memberworker/protocol.mjs";
import { MemberWorkerSession } from "../internal/memberworker/member-client.mjs";

const enrollment = () => ({ publicKey: new Uint8Array(32), csr: new Uint8Array(129) });
const setup = () => ({ ...enrollment(), backup: new Uint8Array(108) });

function harness(t) {
  const original = { Worker: globalThis.Worker, setTimeout, clearTimeout };
  const timers = new Map();
  const workers = [];
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
    assert.equal(timers.size, 0, "timer leaked");
  });
  return {
    workers,
    open() { const session = new MemberWorkerSession(); sessions.push(session); return session; },
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
