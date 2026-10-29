// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";
import { mountMemberForms } from "../internal/memberwasm/testdata/member-forms.mjs";

function harness(t, save = () => {}) {
  const elements = new Map();
  for (const id of ["member-setup", "setup-fields", "setup-passphrase", "setup-confirmation", "member-lock", "form-status"]) {
    const element = new EventTarget();
    Object.assign(element, { value: "", disabled: true, textContent: "", attributes: {},
      setAttribute(name, value) { this.attributes[name] = value; }, focus() { this.focused = true; } });
    elements.set(id, element);
  }
  const sessions = [], records = [];
  const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
  const make = () => {
    const closure = deferred(), work = deferred(), startup = deferred();
    const session = { ready: startup.promise, closed: closure.promise, startup, work, calls: [], stopped: false,
      createWithPassphrase(...inputs) { this.calls.push(inputs); return work.promise; },
      lock() { this.notified = true; this.close(); },
      close() { this.stopped = true; closure.resolve(); startup.resolve(false); work.resolve(null); } };
    sessions.push(session);
    return session;
  };
  const dispose = mountMemberForms({ getElementById: (id) => elements.get(id) }, make, (value) => { save(value); records.push(value); });
  t.after(dispose);
  const get = (id) => elements.get(id);
  return { get, sessions, records, dispose,
    submit(first = "synthetic", second = first) {
      get("setup-passphrase").value = first;
      get("setup-confirmation").value = second;
      const event = new Event("submit", { cancelable: true });
      get("member-setup").dispatchEvent(event);
      assert.equal(event.defaultPrevented, true);
      assert.equal(get("setup-passphrase").value, "");
      assert.equal(get("setup-confirmation").value, "");
    },
    lock() { get("member-lock").dispatchEvent(new Event("click")); },
  };
}
const tick = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
const setup = () => ({ publicKey: new Uint8Array(32), csr: new Uint8Array(129), backup: new Uint8Array(108) });

test("synthetic setup clears independent entries before startup and saves encrypted/public results only", async (t) => {
  const h = harness(t);
  assert.equal(h.get("setup-fields").disabled, false);
  h.submit("é", "e\u0301");
  const session = h.sessions[0];
  assert.equal(h.get("setup-fields").disabled, true);
  assert.equal(h.get("member-lock").disabled, false);
  h.submit("ignored");
  assert.equal(h.sessions.length, 1);
  session.startup.resolve(true);
  await tick();
  assert.deepEqual(session.calls, [["é", "e\u0301"]]);
  const value = setup();
  session.work.resolve(value);
  await tick();
  assert.deepEqual(h.records, [value]);
  assert.equal(h.get("member-setup").attributes["aria-busy"], "false");
  assert.equal(h.get("member-lock").focused, true);
  h.submit();
  assert.equal(h.sessions.length, 1, "unlocked setup replaced the key");
  h.lock();
  assert.equal(session.stopped, true);
  assert.equal(session.notified, true);
  assert.equal(h.get("setup-fields").disabled, true);
  h.submit();
  assert.equal(h.sessions.length, 1, "locked setup replaced the saved backup");
});

test("synthetic setup failure, lock, peer closure, and disposal never publish late work", async (t) => {
  for (const state of ["startup", "pending", "peer", "failure", "dispose"]) {
    await t.test(state, async (t) => {
      const h = harness(t);
      h.submit();
      const session = h.sessions[0];
      if (state !== "startup") { session.startup.resolve(true); await tick(); }
      if (state === "peer") session.close();
      else if (state === "dispose") h.dispose();
      else if (state === "failure") session.work.resolve(null);
      else h.lock();
      await tick();
      session.startup.resolve(true);
      session.work.resolve(setup());
      await tick();
      assert.equal(h.records.length, 0);
      assert.equal(session.stopped, true);
      assert.equal(h.get("member-lock").disabled, true);
      assert.equal(h.get("setup-fields").disabled, state === "dispose");
    });
  }
});

test("synthetic setup handles failed backup retention without exposing diagnostics", async (t) => {
  const h = harness(t, () => { throw new Error("synthetic sensitive diagnostic"); });
  h.submit();
  h.sessions[0].startup.resolve(true);
  await tick();
  h.sessions[0].work.resolve(setup());
  await tick();
  assert.equal(h.records.length, 0);
  assert.equal(h.sessions[0].stopped, true);
  assert.equal(h.get("form-status").textContent.includes("diagnostic"), false);
});
