// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Development-only Node checks, not browser custody or responsiveness evidence.
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { createRequire } from "node:module";

const config = readFileSync(new URL("./wasm.toml", import.meta.url), "utf8");
assert.equal(process.version, /^node_version = "([^"]+)"$/m.exec(config)?.[1], "use the pinned development Node runtime");
const directory = resolve(process.argv[2]);
const expectedFiles = ["LICENSE", "LICENSE.anonce", "LICENSE.x-crypto", "LICENSE.x-sys", "PATENTS", "PATENTS.x-crypto", "PATENTS.x-sys", "client.wasm", "member-client.mjs", "member-worker.mjs", "protocol.mjs", "wasm_exec.js"].sort();
const lines = readFileSync(join(directory, "SHA256SUMS"), "utf8").trimEnd().split("\n");
const names = [];
for (const line of lines) {
  const match = /^([a-f0-9]{64})  ([A-Za-z0-9_.-]+)$/.exec(line);
  assert.ok(match, "invalid artifact manifest");
  const [, digest, name] = match;
  assert.ok(expectedFiles.includes(name), "unexpected artifact");
  names.push(name);
  assert.equal(createHash("sha256").update(readFileSync(join(directory, name))).digest("hex"), digest, "artifact integrity failure");
}
assert.deepEqual(names.sort(), expectedFiles);
globalThis.crypto ??= webcrypto;
globalThis.fetch = () => assert.fail("unexpected network request");
createRequire(import.meta.url)(join(directory, "wasm_exec.js"));
const bytes = readFileSync(join(directory, "client.wasm"));
async function start() {
  const go = new globalThis.Go();
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
  return { go, running: go.run(instance) };
}
const native = JSON.parse(readFileSync(0, "utf8"));
const decode = (hex) => new Uint8Array(Buffer.from(hex, "hex"));
const encode = (bytes) => Buffer.from(bytes).toString("hex");
const password = decode(native.password);
const backup = decode(native.backup);
const publicKey = decode(native.publicKey);
const first = await start();
const api = globalThis.anonceMember;
assert.deepEqual(Object.keys(api).sort(), ["backup", "close", "create", "lock", "request", "unlock"]);
assert.equal(globalThis.anonce, undefined, "member module must not install the public verifier");
assert.equal(await api.request(), null, "initial session must be locked");
assert.equal(await api.backup(password), null, "locked export admitted");
const hostile = new Proxy({}, { get() { assert.fail("object input inspected"); }, getPrototypeOf() { assert.fail("object prototype inspected"); } });
const revoked = Proxy.revocable({}, {});
revoked.revoke();
const invalid = [null, undefined, true, 1, 0n, Symbol("invalid"), () => {}, {}, [], "secret", hostile, revoked.proxy, new ArrayBuffer(32), new DataView(new ArrayBuffer(32)), new Uint16Array(32), new Uint8ClampedArray(32), new Uint8Array(), new Uint8Array(1025)];
if (typeof SharedArrayBuffer !== "undefined") {
  invalid.push(new Uint8Array(new SharedArrayBuffer(32)));
  const forged = new SharedArrayBuffer(32);
  Object.setPrototypeOf(forged, ArrayBuffer.prototype);
  invalid.push(new Uint8Array(forged));
}
const detached = new Uint8Array(32);
structuredClone(detached.buffer, { transfer: [detached.buffer] });
invalid.push(detached);
for (const value of invalid) {
  assert.equal(await api.create(value), null, "invalid password type/size accepted");
  assert.equal(await api.backup(value), null, "invalid export password accepted");
  assert.equal(await api.unlock(value, backup, publicKey), null);
  assert.equal(await api.unlock(password, value, publicKey), null);
  assert.equal(await api.unlock(password, backup, value), null);
}
for (const args of [[], [password, "extra"]]) assert.equal(await api.create(...args), null);
for (const args of [[], [password, "extra"]]) assert.equal(await api.backup(...args), null);
for (const args of [[], [password], [password, backup], [password, backup, publicKey, "extra"]]) assert.equal(await api.unlock(...args), null);
for (const size of [0, 107, 109, 1024, 1025]) assert.equal(await api.unlock(password, new Uint8Array(size), publicKey), null);
for (const size of [0, 31, 33, 1024, 1025]) assert.equal(await api.unlock(password, backup, new Uint8Array(size)), null);
assert.equal(api.close("extra"), null);
assert.equal(api.lock("extra"), null);
assert.equal(await api.request("extra"), null);

// Restore a native backup, including non-UTF-8/NUL password bytes. Shadowed
// properties must not be inspected, including on a valid nonzero-offset view.
const storage = new Uint8Array(password.length + 4);
storage.set(password, 2);
const view = storage.subarray(2, 2 + password.length);
for (const name of ["buffer", "byteLength", "byteOffset", "length", "constructor"]) {
  Object.defineProperty(view, name, { get() { assert.fail("shadowed input property inspected"); } });
}
const restored = await api.unlock(view, backup, publicKey);
assert.deepEqual(Object.keys(restored).sort(), ["csr", "publicKey"]);
assert.equal(encode(restored.publicKey), native.publicKey);
assert.equal(encode(restored.csr), native.csr);
assert.equal(encode(password), native.password, "caller input changed");
assert.equal(encode(backup), native.backup, "caller backup changed");
api.lock("extra");
api.close("extra");
assert.equal(encode((await api.request()).publicKey), native.publicKey, "invalid control arity changed session state");
assert.equal(await api.create(password), null, "unlocked session replaced");
assert.equal(await api.unlock(password, backup, publicKey), null, "unlocked restoration admitted");
restored.publicKey.fill(0);
restored.csr.fill(0);
assert.equal(encode((await api.request()).csr), native.csr, "public output aliased session state");
// Re-export the restored key under a different synthetic password. This is not
// key rotation or deletion of the original backup.
const replacement = password.slice(); replacement[0] ^= 1;
const exportInput = replacement.slice();
const exporting = api.backup(exportInput);
exportInput.fill(0);
// The direct WASM call may finish before returning its Promise. Deterministic
// pending admission is checked natively and through the dedicated worker owner.
const rebackup = await exporting;
assert.deepEqual(Object.keys(rebackup), ["backup"]);
assert.equal(rebackup.backup.length, 108);
assert.notEqual(encode(rebackup.backup.subarray(12, 28)), native.backup.slice(24, 56), "export reused salt");
assert.notEqual(encode(rebackup.backup.subarray(32, 44)), native.backup.slice(64, 88), "export reused nonce");
const backupExport = encode(rebackup.backup);
api.lock();
assert.equal(await api.unlock(password, rebackup.backup, publicKey), null, "old password opened new backup");
assert.equal(encode((await api.unlock(replacement, rebackup.backup, publicKey)).csr), native.csr);
rebackup.backup.fill(0);
const cancelledExport = api.backup(replacement);
api.lock();
await cancelledExport; // Direct bridge work can finish before the lock event turn.
assert.equal(await api.request(), null, "export revived locked session");
replacement.fill(0);
api.lock();
api.lock();
assert.equal(await api.request(), null);

// Failure never creates a replacement key or returns public material.
const wrong = password.slice(); wrong[0] ^= 1;
const mismatch = publicKey.slice(); mismatch[0] ^= 1;
const corrupt = backup.slice(); corrupt[corrupt.length - 1] ^= 1;
const wrongPurpose = backup.slice(); wrongPurpose[10] ^= 1;
for (const args of [[wrong, backup, publicKey], [password, backup, mismatch], [password, corrupt, publicKey], [password, wrongPurpose, publicKey]]) {
  assert.equal(await api.unlock(...args), null);
  assert.equal(await api.request(), null);
}

// Setup snapshots caller bytes before returning. Generated backup opens both in
// WASM and natively, without a raw-private-key or arbitrary-signing interface.
const ownedPassword = password.slice();
const creating = api.create(ownedPassword);
ownedPassword.fill(0);
const setup = await creating;
assert.deepEqual(Object.keys(setup).sort(), ["backup", "csr", "publicKey"]);
assert.ok(setup.backup instanceof Uint8Array && setup.backup.length === 108);
assert.ok(setup.csr instanceof Uint8Array && setup.csr.length === 129);
assert.ok(setup.publicKey instanceof Uint8Array && setup.publicKey.length === 32);
assert.notEqual(encode(setup.publicKey), native.publicKey, "setup reused existing member key");
const result = { backup: encode(setup.backup), csr: encode(setup.csr), publicKey: encode(setup.publicKey), backupExport };
api.lock();
assert.equal(encode((await api.unlock(password, setup.backup, setup.publicKey)).csr), result.csr);
api.lock();

// A promise is not a preemptible KDF. Lock can arrive before or after publication,
// but the session must remain locked after pending work settles.
const pending = api.create(password);
assert.equal(await api.create(password), null, "second setup admitted");
api.lock();
await pending;
assert.equal(await api.request(), null, "pending setup unlocked after lock");
const closing = api.create(password);
api.close();
await closing;
await first.running;
assert.equal(globalThis.anonceMember, undefined);
assert.equal(first.go.exited, true);

const sentinel = Object.freeze({ existing: true });
globalThis.anonceMember = sentinel;
const collision = await start();
await collision.running;
assert.equal(globalThis.anonceMember, sentinel, "namespace overwritten");
delete globalThis.anonceMember;
const fresh = await start();
assert.equal(await globalThis.anonceMember.request(), null);
assert.ok(await globalThis.anonceMember.create(Uint8Array.of(1)), "minimum password length rejected");
globalThis.anonceMember.close();
await fresh.running;
password.fill(0); storage.fill(0); wrong.fill(0);
process.stdout.write(JSON.stringify(result));
