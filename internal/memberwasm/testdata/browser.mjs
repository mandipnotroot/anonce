// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Test-only host. Synthetic input only, no uploads, persistence, or product routes.
import { lockMemberWorkers, MemberWorkerSession } from "/member-client.mjs";
import { mountMemberForms } from "/member-forms.mjs";

let formBackup = null;
const mountForms = () => mountMemberForms(document, () => new MemberWorkerSession(), (created) => {
  formBackup = { backup: created.backup.slice(), publicKey: created.publicKey.slice(), csr: created.csr.slice() };
}, () => formBackup);
let disposeForms = mountForms();
globalThis.addEventListener("pagehide", () => { disposeForms(); formBackup = null; });
// Only encrypted/public output is available to the synthetic driver.
export function formRecord() {
  return formBackup === null ? null : Object.fromEntries(Object.entries(formBackup).map(([name, bytes]) => [name, encode(bytes)]));
}
// Synthetic new-page/substitution fixtures only. The expected key is supplied
// independently by the driver, never extracted from the backup being restored.
export function seedFormRecord(record) {
  disposeForms();
  formBackup = record === null ? null : { backup: decode(record.backup), publicKey: decode(record.publicKey), csr: decode(record.csr) };
  disposeForms = mountForms();
}

const decode = (hex) => Uint8Array.from(hex.match(/../g), (pair) => Number.parseInt(pair, 16));
const encode = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
function check(condition) { if (!condition) throw new Error("browser member check failed"); }
const sessions = new Set();
async function open(...args) {
  const session = new MemberWorkerSession(...args);
  sessions.add(session);
  check(await session.ready);
  return session;
}
function closeAll() { for (const session of sessions) session.close(); sessions.clear(); }
globalThis.addEventListener("pagehide", closeAll);

export async function run(native) {
  const password = decode(native.password), backup = decode(native.backup), key = decode(native.publicKey);
  let heartbeat = 0;
  const timer = setInterval(() => heartbeat++, 10);
  document.getElementById("status").textContent = "Running synthetic member-worker checks.";
  try {
    check(globalThis.Go === undefined && globalThis.anonceMember === undefined);
    const session = await open();
    check(await session.request() === null);
    check(await session.backup(password) === null);
    check(await session.backupConfirmed(password, password) === null);
    const denied = new MemberWorkerSession();
    check(await denied.ready === false);
    check(await denied.closed === undefined);
    const snapshot = password.slice();
    const restoring = session.unlock(snapshot, backup, key);
    snapshot.fill(0);
    check(await session.request() === null); // No queued concurrent work.
    const restored = await restoring;
    check(restored !== null && encode(restored.publicKey) === native.publicKey && encode(restored.csr) === native.csr);
    restored.csr.fill(0);
    check(encode((await session.request()).csr) === native.csr);
    const replacement = password.slice(); replacement[0] ^= 1;
    let rebackup;
    try {
      check(await session.backupConfirmed(replacement, password) === null);
      check(encode((await session.request()).csr) === native.csr);
      const snapshot = replacement.slice();
      const confirmation = replacement.slice();
      const exporting = session.backupConfirmed(snapshot, confirmation);
      snapshot.fill(0); confirmation.fill(0);
      check(await session.backup(password) === null);
      rebackup = await exporting;
      check(rebackup !== null && Object.keys(rebackup).join() === "backup" && rebackup.backup.length === 108);
    } finally { replacement.fill(0); }
    const backupExport = encode(rebackup.backup);
    session.close();
    check(await session.closed === undefined);
    check(await session.request() === null);

    const text = " é😀\0".repeat(128); // Synthetic 1024-byte UTF-8 input, not user entry.
    const textSetup = await open();
    check(await textSetup.createWithPassphrase("é", "e\u0301") === null);
    check(await textSetup.request() === null);
    const textCreated = await textSetup.createWithPassphrase(text, text);
    check(textCreated !== null);
    textSetup.close();
    const byteRestore = await open(), textBytes = new TextEncoder().encode(text);
    try {
      check(encode((await byteRestore.unlock(textBytes, textCreated.backup, textCreated.publicKey)).csr) === encode(textCreated.csr));
    } finally { textBytes.fill(0); byteRestore.close(); }
    const textExport = await open();
    check(await textExport.unlock(password, backup, key) !== null);
    check(await textExport.backupWithPassphrase(text, text.slice(0, -1) + "x") === null);
    check(encode((await textExport.request()).csr) === native.csr);
    const textBackup = (await textExport.backupWithPassphrase(text, text)).backup;
    textExport.close();
    const textRestore = await open();
    check(await textRestore.unlockWithPassphrase("wrong synthetic input", textBackup, key) === null);
    check(await textRestore.request() === null);
    check(encode((await textRestore.unlockWithPassphrase(text, textBackup, key)).csr) === native.csr);
    const textPending = textRestore.backupWithPassphrase(text, text);
    textRestore.close();
    check(await textPending === null);

    const fresh = await open();
    const wrong = password.slice(); wrong[0] ^= 1;
    const mismatch = key.slice(); mismatch[31] ^= 1;
    const corrupt = backup.slice(); corrupt[107] ^= 1;
    try {
      for (const inputs of [[wrong, backup, key], [password, backup, mismatch], [password, corrupt, key]]) {
        check(await fresh.unlock(...inputs) === null);
        check(await fresh.request() === null); // Never create a replacement on failure.
      }
      check(await fresh.createConfirmed(password, wrong) === null);
      check(await fresh.request() === null);
    } finally { wrong.fill(0); }
    const before = heartbeat;
    const createInput = password.slice(), confirmation = password.slice();
    const creating = fresh.createConfirmed(createInput, confirmation);
    createInput.fill(0); confirmation.fill(0);
    const setup = await creating;
    check(setup !== null && encode(setup.publicKey) !== native.publicKey);
    check(heartbeat > before); // UI event loop progressed during full-cost WASM work.
    const exported = { backup: encode(setup.backup), publicKey: encode(setup.publicKey), csr: encode(setup.csr), backupExport,
      textBackup: encode(textBackup) };
    fresh.lock();
    check(await fresh.closed === undefined);
    check(await fresh.request() === null);
    const again = await open();
    check(encode((await again.unlock(password, setup.backup, setup.publicKey)).csr) === exported.csr);
    again.close();

    const cancelled = await open();
    const pending = cancelled.create(password);
    cancelled.close();
    check(await cancelled.closed === undefined);
    check(await pending === null && await cancelled.request() === null);
    check(encode(backup) === native.backup && encode(key) === native.publicKey);
    check(globalThis.Go === undefined && globalThis.anonceMember === undefined);
    document.getElementById("status").textContent = "Synthetic member-worker checks completed.";
    return exported;
  } finally {
    clearInterval(timer);
    password.fill(0);
    closeAll();
  }
}

let peerResult = null;
export async function openPeer() {
  const session = await open();
  const password = Uint8Array.of(7); // Synthetic only, never user-supplied.
  try { check(await session.create(password) !== null); } finally { password.fill(0); }
  // Observe idle owner closure without polling or a second notification channel.
  peerResult = session.closed.then(async (value) => value === undefined && await session.request() === null);
  return true;
}
export async function peerLocked() {
  try { return await peerResult; } finally { peerResult = null; closeAll(); }
}
export function notify() { return lockMemberWorkers(); }

let visibilitySession = null, hiddenObserved = false, closureObserved = false;
document.addEventListener("visibilitychange", (event) => {
  if (event.isTrusted && document.visibilityState === "hidden") hiddenObserved = true;
});
export async function startVisibility(native) {
  hiddenObserved = false;
  closureObserved = false;
  visibilitySession = await open();
  void visibilitySession.closed.then((value) => { check(value === undefined); closureObserved = true; });
  const password = decode(native.password);
  try {
    const restored = await visibilitySession.unlock(password, decode(native.backup), decode(native.publicKey));
    check(restored !== null && encode(restored.csr) === native.csr);
    return true;
  } finally { password.fill(0); }
}
export async function visibilityLocked() {
  return hiddenObserved && closureObserved && await visibilitySession.request() === null;
}
export async function hiddenStartup() {
  const session = new MemberWorkerSession();
  try { return await session.ready === false; } finally { session.close(); }
}

export async function deadlines(native) {
  // Advance only the owner clock, without waiting for or firing timeout callbacks.
  // This models delayed tasks, not actual browser/OS suspension or clock changes.
  const wall = Date.now, password = decode(native.password);
  let offset = 0;
  Date.now = () => wall() + offset;
  try {
    const startup = new MemberWorkerSession();
    sessions.add(startup);
    offset = 30_000;
    check(await startup.ready === false);
    check(await startup.closed === undefined);
    check(await startup.request() === null);
    for (const boundary of ["operation", "lifetime", "rollback"]) {
      offset = 0;
      const session = await open();
      if (boundary === "operation") {
        const pending = session.unlock(password, decode(native.backup), decode(native.publicKey));
        offset = 120_000;
        check(await pending === null);
      } else {
        check(await session.unlock(password, decode(native.backup), decode(native.publicKey)) !== null);
        offset = boundary === "lifetime" ? 300_000 : -30_000;
        check(await session.request() === null);
      }
      check(await session.closed === undefined);
      offset = 0;
      check(await session.request() === null); // Clock recovery never revives an owner.
    }
    // Restoring still requires a new explicit owner with the same trusted key.
    const restored = await open();
    check(encode((await restored.unlock(password, decode(native.backup), decode(native.publicKey))).csr) === native.csr);
    return true;
  } finally {
    Date.now = wall;
    password.fill(0);
    closeAll();
  }
}

export async function cancellation(native) {
  const password = decode(native.password), backup = decode(native.backup), key = decode(native.publicKey);
  try {
    for (const state of ["startup", "idle", "pending"]) {
      const controller = new AbortController();
      const session = new MemberWorkerSession(controller.signal);
      sessions.add(session);
      if (state !== "startup") check(await session.ready === true);
      if (state === "idle") check(encode((await session.unlock(password, backup, key)).csr) === native.csr);
      const pending = state === "pending" ? session.unlock(password, backup, key) : null;
      controller.abort("synthetic cancellation");
      check(await session.closed === undefined);
      check(await session.ready === (state !== "startup"));
      if (pending) check(await pending === null);
      check(await session.request() === null);
      const denied = new MemberWorkerSession(controller.signal);
      sessions.add(denied);
      check(await denied.ready === false && await denied.closed === undefined);
    }
    const restored = await open(new AbortController().signal);
    check(encode((await restored.unlock(password, backup, key)).csr) === native.csr);
    check(encode(backup) === native.backup && encode(key) === native.publicKey);
    return true;
  } finally {
    password.fill(0);
    closeAll();
  }
}

export async function pendingNavigation() {
  const session = await open();
  const password = Uint8Array.of(7);
  void session.create(password);
  password.fill(0);
  return true;
}

export async function pagePolicy() {
  // These probes must be blocked before any HTTP request or execution. No secrets
  // enter them. Do not disable CSP in the driver to make a test pass.
  globalThis.inlineProbe = false;
  const script = document.createElement("script");
  script.textContent = "globalThis.inlineProbe = true";
  document.body.append(script);
  script.remove();
  let blocked = false;
  try { await fetch("/forbidden-probe"); } catch { blocked = true; }
  let wasmBlocked = false;
  try { await WebAssembly.compile(Uint8Array.of(0, 97, 115, 109, 1, 0, 0, 0)); } catch { wasmBlocked = true; }
  return !globalThis.inlineProbe && blocked && wasmBlocked;
}
