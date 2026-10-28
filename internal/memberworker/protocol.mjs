// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// This is a local development transport, not an account or enrollment protocol.
export const version = 1;
const typed = Object.getPrototypeOf(Uint8Array.prototype);
const getter = (name) => Object.getOwnPropertyDescriptor(typed, name).get;
const length = getter("byteLength");
const buffer = getter("buffer");
const offset = getter("byteOffset");
const tag = getter(Symbol.toStringTag);
const bufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;

export function byteView(value, minimum, maximum = minimum) {
  if (!ArrayBuffer.isView(value) || Reflect.apply(tag, value, []) !== "Uint8Array") return null;
  const backing = Reflect.apply(buffer, value, []);
  try {
    Reflect.apply(bufferLength, backing, []); // Reject shared memory, even with a forged prototype.
    const size = Reflect.apply(length, value, []);
    if (size < minimum || size > maximum) return null;
    return new Uint8Array(backing, Reflect.apply(offset, value, []), size);
  } catch {
    return null; // Detached or nonordinary backing buffer.
  }
}

export function inputViews(method, inputs) {
  if (!Array.isArray(inputs)) return null;
  const sizes = { create: [[1, 1024]], unlock: [[1, 1024], [108, 108], [32, 32]], request: [] };
  if (!Object.hasOwn(sizes, method) || inputs.length !== sizes[method].length) return null;
  const views = sizes[method].map(([min, max], i) => byteView(inputs[i], min, max));
  return views.every((view) => view !== null) ? views : null;
}

// Records here come from structured cloning, not arbitrary caller objects.
export function record(value, keys) {
  return value !== null && typeof value === "object" &&
    Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

export function command(value) {
  return record(value, ["version", "id", "method", "inputs"]) && value.version === version &&
    Number.isSafeInteger(value.id) && value.id > 0 && typeof value.method === "string" &&
    inputViews(value.method, value.inputs) !== null;
}

export function result(value, method) {
  if (value === null) return true;
  const keys = method === "create" ? ["publicKey", "csr", "backup"] : ["publicKey", "csr"];
  return record(value, keys) && byteView(value.publicKey, 32) !== null &&
    byteView(value.csr, 129) !== null && (method !== "create" || byteView(value.backup, 108) !== null);
}

export function wipe(views) {
  for (const view of views) {
    // Transferred snapshots are detached in the sending realm.
    if (view.byteLength !== 0) view.fill(0);
  }
}
