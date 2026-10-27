// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Development-only runtime test. No npm dependencies or browser assets are built.
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { createRequire } from "node:module";

const config = readFileSync(new URL("./wasm.toml", import.meta.url), "utf8");
assert.equal(process.version, /^node_version = "([^"]+)"$/m.exec(config)?.[1], "use the pinned development Node runtime");
const directory = resolve(process.argv[2]);
const expected = ["LICENSE", "LICENSE.anonce", "PATENTS", "client.wasm", "wasm_exec.js"].sort();
const lines = readFileSync(join(directory, "SHA256SUMS"), "utf8").trimEnd().split("\n");
assert.equal(lines.length, expected.length);
const names = [];
for (const line of lines) {
  const match = /^([a-f0-9]{64})  ([A-Za-z0-9_.]+)$/.exec(line);
  assert.ok(match, "invalid artifact manifest");
  const [, digest, name] = match;
  assert.ok(expected.includes(name), "unexpected artifact");
  names.push(name);
  assert.equal(createHash("sha256").update(readFileSync(join(directory, name))).digest("hex"), digest, "artifact integrity failure");
}
assert.deepEqual(names.sort(), expected);

globalThis.crypto ??= webcrypto;
globalThis.fetch = () => assert.fail("unexpected network request");
createRequire(import.meta.url)(join(directory, "wasm_exec.js"));
const bytes = readFileSync(join(directory, "client.wasm"));
assert.ok(WebAssembly.validate(bytes));
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(bytes, go.importObject);
const running = go.run(instance);
assert.deepEqual(Object.keys(globalThis.anonce).sort(), ["close", "verifyCSR"]);
const verify = globalThis.anonce.verifyCSR;
const hostile = new Proxy({}, { get() { assert.fail("object input was inspected"); } });
for (const args of [[], [null], [undefined], [true], [129], [0n], [Symbol("invalid")], [() => {}], [{}], [[]], [new Uint8Array(129)], [new String("0".repeat(258))], [hostile], ["0".repeat(258), "extra"], ["0".repeat(1024 * 1024)], ["é".repeat(258)], ["😀".repeat(129)]]) {
  assert.equal(verify(...args), null, "invalid bridge input must fail without output");
}
// Invalid shutdown arguments must not terminate the runtime.
assert.equal(globalThis.anonce.close("extra"), null);
const vectors = JSON.parse(readFileSync(0, "utf8"));
assert.ok(vectors.length > 390, "missing native public corpus");
for (const { input, want } of vectors) {
  assert.equal(verify(input), want, "native/WASM result mismatch");
}
globalThis.anonce.close();
await running;
assert.equal(globalThis.anonce, undefined, "shutdown must remove the bridge");
assert.equal(go.exited, true);

// Do not overwrite an existing namespace, even with another WASM instance.
const sentinel = Object.freeze({ existing: true });
globalThis.anonce = sentinel;
const second = new globalThis.Go();
const loaded = await WebAssembly.instantiate(bytes, second.importObject);
await second.run(loaded.instance);
assert.equal(globalThis.anonce, sentinel);
delete globalThis.anonce;
console.log(`WASM bridge and ${vectors.length} native public vectors passed`);
