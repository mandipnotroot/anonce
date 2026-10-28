// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Test-only host. No user entry, uploads, storage, key display, or product routes.
import { lockMemberWorkers, MemberWorkerSession } from "/member-client.mjs";

const decode = (hex) => Uint8Array.from(hex.match(/../g), (pair) => Number.parseInt(pair, 16));
const encode = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
function check(condition) { if (!condition) throw new Error("browser member check failed"); }
const sessions = new Set();
async function open() {
  const session = new MemberWorkerSession();
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
    const denied = new MemberWorkerSession();
    check(await denied.ready === false);
    const snapshot = password.slice();
    const restoring = session.unlock(snapshot, backup, key);
    snapshot.fill(0);
    check(await session.request() === null); // No queued concurrent work.
    const restored = await restoring;
    check(restored !== null && encode(restored.publicKey) === native.publicKey && encode(restored.csr) === native.csr);
    restored.csr.fill(0);
    check(encode((await session.request()).csr) === native.csr);
    session.close();
    check(await session.request() === null);

    const fresh = await open();
    const wrong = password.slice(); wrong[0] ^= 1;
    const mismatch = key.slice(); mismatch[31] ^= 1;
    const corrupt = backup.slice(); corrupt[107] ^= 1;
    try {
      for (const inputs of [[wrong, backup, key], [password, backup, mismatch], [password, corrupt, key]]) {
        check(await fresh.unlock(...inputs) === null);
        check(await fresh.request() === null); // Never create a replacement on failure.
      }
    } finally { wrong.fill(0); }
    const before = heartbeat;
    const setup = await fresh.create(password);
    check(setup !== null && encode(setup.publicKey) !== native.publicKey);
    check(heartbeat > before); // UI event loop progressed during full-cost WASM work.
    const exported = { backup: encode(setup.backup), publicKey: encode(setup.publicKey), csr: encode(setup.csr) };
    fresh.lock();
    check(await fresh.request() === null);
    const again = await open();
    check(encode((await again.unlock(password, setup.backup, setup.publicKey)).csr) === exported.csr);
    again.close();

    const cancelled = await open();
    const pending = cancelled.create(password);
    cancelled.close();
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

let peerChannel = null, peerResult = null;
export async function openPeer() {
  const session = await open();
  const password = Uint8Array.of(7); // Synthetic only, never user-supplied.
  try { check(await session.create(password) !== null); } finally { password.fill(0); }
  peerChannel = new BroadcastChannel("anonce.member-lock.v1");
  peerResult = new Promise((resolve) => {
    peerChannel.onmessage = () => {
      // Allow the owner's independently registered notification handler to run.
      setTimeout(async () => resolve(await session.request() === null), 0);
    };
  });
  return true;
}
export async function peerLocked() {
  try { return await peerResult; } finally { peerChannel?.close(); peerChannel = null; closeAll(); }
}
export function notify() { return lockMemberWorkers(); }

let visibilitySession = null, hiddenObserved = false;
document.addEventListener("visibilitychange", (event) => {
  if (event.isTrusted && document.visibilityState === "hidden") hiddenObserved = true;
});
export async function startVisibility(native) {
  hiddenObserved = false;
  visibilitySession = await open();
  const password = decode(native.password);
  try {
    const restored = await visibilitySession.unlock(password, decode(native.backup), decode(native.publicKey));
    check(restored !== null && encode(restored.csr) === native.csr);
    return true;
  } finally { password.fill(0); }
}
export async function visibilityLocked() {
  return hiddenObserved && await visibilitySession.request() === null;
}
export async function hiddenStartup() {
  const session = new MemberWorkerSession();
  try { return await session.ready === false; } finally { session.close(); }
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
