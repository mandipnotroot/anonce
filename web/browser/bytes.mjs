// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

const typed = Object.getPrototypeOf(Uint8Array.prototype);
const get = (name) => Object.getOwnPropertyDescriptor(typed, name).get;
const tag = get(Symbol.toStringTag), buffer = get("buffer"), length = get("byteLength"), offset = get("byteOffset");
const ordinary = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
export function byteView(value, min, max = min) {
  try { if (!ArrayBuffer.isView(value) || Reflect.apply(tag, value, []) !== "Uint8Array") return null; const backing = Reflect.apply(buffer, value, []); Reflect.apply(ordinary, backing, []); const size = Reflect.apply(length, value, []); return size >= min && size <= max ? new Uint8Array(backing, Reflect.apply(offset, value, []), size) : null; } catch { return null; }
}
