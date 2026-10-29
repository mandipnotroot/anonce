// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";
import { mountMemberForms } from "../internal/memberwasm/testdata/member-forms.mjs";

function harness(t, save = () => {}, load = () => null) {
  const elements = new Map();
  for (const id of ["member-setup", "setup-fields", "setup-passphrase", "setup-confirmation", "member-lock", "form-status",
    "member-restore", "restore-fields", "unlock-passphrase"]) {
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
      unlockWithPassphrase(...inputs) { this.unlockInputs = inputs; return work.promise; },
      lock() { this.notified = true; this.close(); },
      close() { this.stopped = true; closure.resolve(); startup.resolve(false); work.resolve(null); } };
    sessions.push(session);
    return session;
  };
  const root = new EventTarget();
  Object.assign(root, { visibilityState: "visible", getElementById: (id) => elements.get(id) });
  const dispose = mountMemberForms(root, make, (value) => { save(value); records.push(value); }, load);
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
    restore(text = "synthetic") {
      get("unlock-passphrase").value = text;
      const event = new Event("submit", { cancelable: true });
      get("member-restore").dispatchEvent(event);
      assert.equal(event.defaultPrevented, true);
      assert.equal(get("unlock-passphrase").value, "");
    },
    visibility(state) { root.visibilityState = state; root.dispatchEvent(new Event("visibilitychange")); },
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

test("synthetic restoration snapshots a bounded backup and required expected key without replacing them", async (t) => {
  const source = setup();
  source.backup.fill(7); source.publicKey.fill(9);
  const h = harness(t, () => assert.fail("restoration saved a replacement"), () => source);
  assert.equal(h.get("setup-fields").disabled, true);
  assert.equal(h.get("restore-fields").disabled, false);
  h.restore(" é😀 ");
  source.backup.fill(0); source.publicKey.fill(0);
  const session = h.sessions[0];
  h.restore(); h.submit();
  assert.equal(h.sessions.length, 1);
  session.startup.resolve(true);
  await tick();
  const [text, backup, expected] = session.unlockInputs;
  assert.equal(text, " é😀 ");
  assert.deepEqual(backup, new Uint8Array(108).fill(7));
  assert.deepEqual(expected, new Uint8Array(32).fill(9));
  assert.equal(session.calls.length, 0, "restoration generated a replacement key");
  session.work.resolve({ publicKey: new Uint8Array(32), csr: new Uint8Array(129) });
  await tick();
  assert.equal(h.records.length, 0);
  assert.equal(h.get("restore-fields").disabled, true);
  assert.ok(backup.every((byte) => byte === 0) && expected.every((byte) => byte === 0), "owned snapshots retained");
  h.lock();
  assert.equal(h.get("restore-fields").disabled, false);
  assert.equal(h.get("unlock-passphrase").focused, true);
  assert.equal(h.get("setup-fields").disabled, true);
});

test("synthetic restoration failure and lifecycle cancellation never generate or save keys", async (t) => {
  for (const state of ["startup", "pending", "peer", "failure", "dispose", "hidden"]) {
    await t.test(state, async (t) => {
      const h = harness(t, () => assert.fail("saved on restoration"), setup);
      h.restore();
      const session = h.sessions[0];
      if (state !== "startup") { session.startup.resolve(true); await tick(); }
      if (state === "peer") session.close();
      else if (state === "dispose") h.dispose();
      else if (state === "hidden") h.visibility("hidden");
      else if (state === "failure") session.work.resolve(null);
      else h.lock();
      await tick();
      session.startup.resolve(true); session.work.resolve(setup());
      await tick();
      assert.equal(session.calls.length, 0);
      assert.equal(h.records.length, 0);
      assert.equal(session.stopped, true);
      assert.equal(h.get("setup-fields").disabled, true);
      assert.equal(h.get("restore-fields").disabled, state === "dispose" || state === "hidden");
      if (state === "hidden") {
        h.visibility("visible");
        assert.equal(h.sessions.length, 1, "foregrounding restarted key custody");
        assert.equal(h.get("restore-fields").disabled, false);
      }
    });
  }
});

test("synthetic restoration rejects missing, wrong-sized, shared, and failed sources before worker startup", async (t) => {
  const invalid = [null, {}, { backup: new Uint8Array(108) },
    { backup: new Uint8Array(108), publicKey: new Uint8Array(31) },
    { backup: new Uint8Array(109), publicKey: new Uint8Array(32) },
    { backup: new Uint8Array(new SharedArrayBuffer(108)), publicKey: new Uint8Array(32) }];
  for (const record of invalid) {
    const h = harness(t, () => assert.fail("saved invalid source"), () => record);
    h.restore(); await tick();
    assert.equal(h.sessions.length, 0);
    assert.equal(h.records.length, 0);
    assert.equal(h.get("unlock-passphrase").value, "");
  }
  const h = harness(t, () => assert.fail("saved failed source"), () => { throw new Error("synthetic private diagnostic"); });
  h.submit(); h.restore(); await tick();
  assert.equal(h.sessions.length, 0);
  assert.equal(h.get("setup-fields").disabled, true);
  assert.equal(h.get("form-status").textContent.includes("diagnostic"), false);
});

test("synthetic forms clear idle fields on visibility loss and remove handlers on disposal", async (t) => {
  for (const existing of [false, true]) {
    const h = harness(t, () => {}, () => existing ? setup() : null);
    for (const id of ["setup-passphrase", "setup-confirmation", "unlock-passphrase"]) h.get(id).value = "synthetic";
    h.visibility("hidden");
    for (const id of ["setup-passphrase", "setup-confirmation", "unlock-passphrase"]) assert.equal(h.get(id).value, "");
    h.submit(); h.restore();
    assert.equal(h.sessions.length, 0);
    h.visibility("visible");
    assert.equal(h.get("setup-fields").disabled, existing);
    assert.equal(h.get("restore-fields").disabled, !existing);
    h.dispose();
    h.visibility("visible");
    assert.equal(h.get("setup-fields").disabled, true);
    assert.equal(h.get("restore-fields").disabled, true);
  }
});

test("synthetic restoration bounded generated source admission and text forwarding", async (t) => {
  // No KDF or I/O. Byte/profile parsing and UTF-8 validation stay in the worker's
  // separately fuzzed shared paths; this sweep checks only controller admission.
  for (let i = 0; i < 256; i++) {
    const backupSize = i % 4 === 0 ? 108 : i % 110;
    const keySize = i % 4 === 0 ? 32 : i % 34;
    const source = { backup: new Uint8Array(backupSize), publicKey: new Uint8Array(keySize) };
    const h = harness(t, () => assert.fail("generated replacement"), () => source);
    const text = ["", "é", "e\u0301", "\uD800", "😀".repeat(257), "a".repeat(1025)][i % 6];
    h.restore(text); await tick();
    const valid = backupSize === 108 && keySize === 32;
    assert.equal(h.sessions.length, valid ? 1 : 0);
    if (valid) {
      h.sessions[0].startup.resolve(true); await tick();
      assert.equal(h.sessions[0].unlockInputs[0], text);
      h.lock(); await tick();
    }
    h.dispose();
  }
});
