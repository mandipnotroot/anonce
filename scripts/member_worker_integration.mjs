// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// These checks execute the production worker/client with Node API adapters.
// They are not browser delivery, CSP, or supported-device evidence.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { Worker as NodeWorker } from "node:worker_threads";

const config = readFileSync(new URL("./wasm.toml", import.meta.url), "utf8");
assert.equal(process.version, /^node_version = "([^"]+)"$/m.exec(config)?.[1]);
const directory = resolve(process.argv[2]);
const expected = ["LICENSE", "LICENSE.anonce", "LICENSE.x-crypto", "LICENSE.x-sys", "PATENTS", "PATENTS.x-crypto", "PATENTS.x-sys",
  "client.wasm", "member-client.mjs", "member-worker.mjs", "protocol.mjs", "wasm_exec.js"].sort();
const names = [];
for (const line of readFileSync(join(directory, "SHA256SUMS"), "utf8").trimEnd().split("\n")) {
  const match = /^([a-f0-9]{64})  ([A-Za-z0-9_.-]+)$/.exec(line);
  assert.ok(match);
  const [, digest, name] = match;
  assert.ok(expected.includes(name));
  names.push(name);
  assert.equal(createHash("sha256").update(readFileSync(join(directory, name))).digest("hex"), digest);
}
assert.deepEqual(names.sort(), expected);
const native = JSON.parse(readFileSync(0, "utf8"));
const decode = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const encode = (bytes) => Buffer.from(bytes).toString("hex");
const password = decode(native.password), backup = decode(native.backup), key = decode(native.publicKey);
const exits = [];
const workers = [];
let mode;
// Node supplies BroadcastChannel, but not Window/Document lifecycle facilities.
const lifecycle = new EventTarget();
globalThis.addEventListener = lifecycle.addEventListener.bind(lifecycle);
globalThis.removeEventListener = lifecycle.removeEventListener.bind(lifecycle);
globalThis.document = new EventTarget();
globalThis.document.visibilityState = "visible";
globalThis.Worker = class {
  constructor(url, options) {
    assert.equal(url.href, pathToFileURL(join(directory, "member-worker.mjs")).href);
    assert.deepEqual(options, { type: "module", credentials: "omit" });
    this.thread = new NodeWorker(new URL("./member_worker_node.mjs", import.meta.url), { workerData: { entry: url.href, mode } });
    this.thread.on("message", (data) => this.onmessage?.({ data }));
    this.thread.on("error", () => this.onerror?.({ preventDefault() {} }));
    exits.push(new Promise((resolve) => this.thread.once("exit", resolve)));
    workers.push(this);
  }
  postMessage(message, transfers) { this.thread.postMessage(message, transfers); }
  terminate() { this.terminated = true; void this.thread.terminate(); }
};
const { MemberWorkerSession } = await import(pathToFileURL(join(directory, "member-client.mjs")));
const sessions = [];
const open = () => { const session = new MemberWorkerSession(); sessions.push(session); return session; };
let exported;
try {
  const session = open();
  assert.equal(await session.ready, true);
  assert.equal(globalThis.Go, undefined, "runtime loaded into owner realm");
  assert.equal(globalThis.anonceMember, undefined, "private session loaded into owner realm");
  assert.equal(await session.request(), null);
  const snapshot = password.slice();
  const restoring = session.unlock(snapshot, backup, key);
  snapshot.fill(0);
  assert.equal(await session.create(password), null, "concurrent operation admitted");
  const restored = await restoring;
  assert.equal(encode(restored.publicKey), native.publicKey);
  assert.equal(encode(restored.csr), native.csr);
  assert.equal(encode(backup), native.backup);
  restored.csr.fill(0); restored.publicKey.fill(0);
  assert.equal(encode((await session.request()).csr), native.csr);
  session.lock();
  assert.equal(workers.at(-1).terminated, true);
  assert.equal(await session.request(), null);

  const fresh = open();
  assert.equal(await fresh.ready, true);
  const wrong = password.slice(); wrong[0] ^= 1;
  const mismatch = key.slice(); mismatch[31] ^= 1;
  const corrupt = backup.slice(); corrupt[107] ^= 1;
  for (const inputs of [[wrong, backup, key], [password, backup, mismatch], [password, corrupt, key]]) {
    assert.equal(await fresh.unlock(...inputs), null);
    assert.equal(await fresh.request(), null, "restoration failure created replacement key");
  }
  wrong.fill(0);
  const setup = await fresh.create(password);
  assert.notEqual(encode(setup.publicKey), native.publicKey);
  exported = { backup: encode(setup.backup), csr: encode(setup.csr), publicKey: encode(setup.publicKey) };
  fresh.close();
  const again = open();
  assert.equal(await again.ready, true);
  assert.equal(encode((await again.unlock(password, setup.backup, setup.publicKey)).csr), exported.csr);
  again.close();

  // Owner termination does not wait for a lock message queued behind Argon2id.
  const cancelled = open();
  assert.equal(await cancelled.ready, true);
  const pending = cancelled.create(password);
  cancelled.lock();
  assert.equal(await pending, null);
  assert.equal(workers.at(-1).terminated, true);
  assert.equal(await cancelled.request(), null);

  // Exercise the actual BroadcastChannel API with a live WASM worker, not only
  // the controlled channel harness. Node does not model browser partitioning.
  const notifier = new BroadcastChannel("anonce.member-lock.v1");
  try {
    for (const state of ["startup", "pending"]) {
      const remote = open(), worker = workers.at(-1);
      let pending;
      if (state === "pending") {
        assert.equal(await remote.ready, true);
        pending = remote.create(password);
      }
      const exited = new Promise((resolve) => worker.thread.once("exit", resolve));
      notifier.postMessage("lock");
      if (pending) assert.equal(await pending, null);
      else await remote.ready; // Startup may win the race with notification delivery.
      await exited;
      assert.equal(worker.terminated, true);
      assert.equal(await remote.request(), null);
    }
  } finally {
    notifier.close();
  }
  const hidden = open();
  assert.equal(await hidden.ready, true);
  const hiding = hidden.create(password);
  lifecycle.dispatchEvent(new Event("pagehide"));
  assert.equal(await hiding, null);
  assert.equal(workers.at(-1).terminated, true);

  const background = open();
  assert.equal(await background.ready, true);
  const backgroundWorker = workers.at(-1);
  assert.ok(await background.unlock(password, backup, key));
  const backgroundPending = background.request();
  globalThis.document.visibilityState = "hidden";
  globalThis.document.dispatchEvent(new Event("visibilitychange"));
  assert.equal(await backgroundPending, null);
  assert.equal(backgroundWorker.terminated, true);
  assert.equal(await open().ready, false, "hidden page started a worker");
  globalThis.document.visibilityState = "visible";
  globalThis.document.dispatchEvent(new Event("visibilitychange"));
  assert.equal(await background.request(), null, "visible page revived its old session");

  // Synthetic clock jumps exercise actual worker replies without a long sleep or
  // firing owner timers. They are not real browser/OS suspension measurements.
  const performance = globalThis.performance, wall = Date.now;
  try {
    for (const boundary of ["startup", "operation", "lifetime-reply", "lifetime-call"]) {
      let monotonic = performance.now(), now = wall();
      globalThis.performance = { now: () => monotonic };
      Date.now = () => now;
      const expired = open(), worker = workers.at(-1);
      if (boundary === "startup") {
        now += 30_000;
        assert.equal(await expired.ready, false, "late worker startup accepted");
      } else {
        assert.equal(await expired.ready, true);
        if (boundary === "lifetime-reply") monotonic += 299_999;
        const response = new Promise((resolve) => worker.thread.once("message", resolve));
        const pending = expired.unlock(password, backup, key);
        if (boundary === "operation") now += 120_000;
        if (boundary === "lifetime-reply") monotonic++;
        const message = await response;
        assert.equal(encode(message.result.csr), native.csr, "worker did not produce a valid restoration reply");
        if (boundary === "lifetime-call") {
          assert.ok(await pending);
          now += 300_000;
          assert.equal(await expired.request(), null, "expired worker admitted more work");
        } else {
          assert.equal(await pending, null, "overdue worker result published");
        }
      }
      assert.equal(worker.terminated, true);
      assert.equal(await expired.request(), null, "expired worker restarted");
    }
  } finally {
    globalThis.performance = performance;
    Date.now = wall;
  }

  for (const failure of ["fetch-error", "http-error", "bad-wasm", "oversized"]) {
    mode = failure;
    const failed = open();
    assert.equal(await failed.ready, false);
    assert.equal(await failed.create(password), null);
    assert.equal(workers.at(-1).terminated, true);
  }
  mode = undefined;
  // Exercise the real worker's replay and malformed-command fail-closed paths.
  for (const malformed of [{ version: 2, id: 1, method: "request", inputs: [] },
    { version: 1, id: 1, method: "unlock", inputs: [password] },
    { version: 1, id: 1, method: "close", inputs: [] },
    { version: 1, id: 1, method: "request", inputs: [] }]) {
    const victim = open();
    assert.equal(await victim.ready, true);
    await victim.request(); // Consumes id 1, including while locked.
    const worker = workers.at(-1);
    const failed = new Promise((resolve) => {
      const listener = (data) => {
        if (data.type === "failed") { worker.thread.off("message", listener); resolve(); }
      };
      worker.thread.on("message", listener);
    });
    worker.thread.postMessage(malformed);
    await failed;
    assert.equal(worker.terminated, true);
    assert.equal(await victim.request(), null);
  }
} finally {
  password.fill(0);
  for (const session of sessions) session.close();
  await Promise.all(exits);
}
process.stdout.write(JSON.stringify(exported));
