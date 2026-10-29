// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";
import { ReviewWorker } from "../web/browser/review-client.mjs";

function harness(t) {
  const names = ["Worker", "BroadcastChannel", "document", "addEventListener", "removeEventListener", "performance"];
  const original = Object.fromEntries(names.map((name) => [name, globalThis[name]]));
  const dateNow = Date.now, time = { wall: 1_700_000_000_000, monotonic: 1000 }, workers = [], owners = [];
  const page = new EventTarget(), document = new EventTarget();
  document.visibilityState = "visible";
  class Worker {
    terminated = false;
    posts = [];
    constructor() { workers.push(this); }
    postMessage(message) { this.posts.push(message); }
    terminate() { this.terminated = true; }
    send(data) { this.onmessage({ data }); }
  }
  Object.assign(globalThis, { Worker, document, performance: { now: () => time.monotonic },
    BroadcastChannel: class { close() {} },
    addEventListener: page.addEventListener.bind(page), removeEventListener: page.removeEventListener.bind(page) });
  Date.now = () => time.wall;
  t.after(() => { for (const owner of owners) owner.close(); Object.assign(globalThis, original); Date.now = dateNow; });
  const start = () => { const owner = new ReviewWorker(true); owners.push(owner); return owner; };
  return { start, workers, document, time, page };
}

test("a live cryptographic rejection is distinguishable from terminal owner closure", async (t) => {
  const h = harness(t), owner = h.start(), worker = h.workers[0];
  worker.send({ ready: true });
  assert.equal(await owner.ready, true);
  const result = owner.call("decrypt", new Uint8Array(4145));
  worker.send({ id: worker.posts[0].id, result: null });
  assert.equal(await result, null);
  assert.equal(owner.closed, false);
  owner.close();
  assert.equal(owner.closed, true);
  assert.equal(worker.terminated, true);
});

test("closure, hidden state, replacement admission, and deadlines terminate pending work", async (t) => {
  for (const action of ["close", "hide", "pagehide", "wall-expiry", "monotonic-expiry", "backward-clock", "invalid-clock"]) {
    await t.test(action, async (t) => {
      const h = harness(t), owner = h.start(), worker = h.workers[0];
      worker.send({ ready: true });
      assert.equal(await owner.ready, true);
      const pending = owner.call("decrypt", new Uint8Array(4145));
      if (action === "close") owner.close();
      else if (action === "hide") { h.document.visibilityState = "hidden"; h.document.dispatchEvent(new Event("visibilitychange")); }
      else if (action === "pagehide") h.page.dispatchEvent(new Event("pagehide"));
      else if (action === "wall-expiry") h.time.wall += 300000;
      else if (action === "monotonic-expiry") h.time.monotonic += 300000;
      else if (action === "backward-clock") h.time.wall--;
      else h.time.monotonic = Number.NaN;
      assert.equal(owner.closed, true);
      assert.equal(await pending, null);
      assert.equal(worker.terminated, true);
      assert.equal(await owner.call("decrypt", new Uint8Array(4145)), null);
    });
  }
});

test("replacement owners require closure and explicit visible startup", async (t) => {
  const h = harness(t), original = h.start(), rejected = h.start();
  assert.equal(await rejected.ready, false);
  assert.equal(rejected.closed, true);
  assert.equal(original.closed, false);
  original.close();
  h.document.visibilityState = "hidden";
  const hidden = h.start();
  assert.equal(await hidden.ready, false);
  h.document.visibilityState = "visible";
  const replacement = h.start();
  assert.equal(replacement.closed, false);
  assert.equal(original.closed, true);
  h.workers.at(-1).send({ ready: true });
  assert.equal(await replacement.ready, true);
});
