// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";
import { encode } from "../web/browser/common.mjs";
import { readReviewRecords } from "../web/browser/review-records.mjs";

const record = () => ({ envelope: encode(new Uint8Array(4145)) });
const plaintext = (text) => ({ bytes: new TextEncoder().encode(text) });

test("one rejected ciphertext does not suppress later valid answers", async () => {
  const first = plaintext("synthetic first answer"), last = plaintext("synthetic later answer");
  const results = [first, null, last], calls = [], output = [];
  const worker = { async call(method, bytes) { calls.push(method); assert.equal(bytes.length, 4145); return results.shift(); } };
  assert.equal(await readReviewRecords(worker, [record(), record(), record()], () => true, (text) => output.push(text)), 1);
  assert.deepEqual(output, ["synthetic first answer", null, "synthetic later answer"]);
  assert.deepEqual(calls, ["decrypt", "decrypt", "decrypt"]);
  assert.ok(first.bytes.every((b) => b === 0));
  assert.ok(last.bytes.every((b) => b === 0));
});

test("malformed record encodings are rejected without invoking the worker", async (t) => {
  for (const value of [null, {}, { envelope: "!" }, { envelope: "AA" }, { envelope: encode(new Uint8Array(4146)) }]) {
    await t.test(JSON.stringify(value)?.slice(0, 30) ?? "null", async () => {
      const output = [];
      let calls = 0;
      const worker = { async call() { calls++; return plaintext("synthetic valid answer"); } };
      assert.equal(await readReviewRecords(worker, [value, record()], () => true, (text) => output.push(text)), 1);
      assert.equal(calls, 1);
      assert.deepEqual(output, [null, "synthetic valid answer"]);
    });
  }
});

test("invalid UTF-8 clears owned plaintext and does not suppress the next record", async () => {
  const invalid = { bytes: new Uint8Array([0xff]) }, results = [invalid, plaintext("synthetic valid answer")], output = [];
  const worker = { async call() { return results.shift(); } };
  assert.equal(await readReviewRecords(worker, [record(), record()], () => true, (text) => output.push(text)), 1);
  assert.equal(invalid.bytes[0], 0);
  assert.deepEqual(output, [null, "synthetic valid answer"]);
});

test("closed, hidden, or replaced owners publish neither rejection placeholders nor late plaintext", async (t) => {
  for (const result of [null, plaintext("synthetic late answer")]) {
    await t.test(result === null ? "rejected result" : "valid result", async () => {
      let active = true, settle;
      const output = [];
      const worker = { call() { return new Promise((resolve) => { settle = resolve; }); } };
      const pending = readReviewRecords(worker, [record(), record()], () => active, (text) => output.push(text));
      active = false;
      settle(result);
      await assert.rejects(pending, /review unavailable/);
      assert.deepEqual(output, []);
      if (result) assert.ok(result.bytes.every((b) => b === 0));
    });
  }
});

test("admission, cancellation between records, and worker errors fail closed", async () => {
  let calls = 0;
  const worker = { async call() { calls++; return null; } };
  for (const records of [null, {}, Array.from({ length: 51 }, record)]) {
    await assert.rejects(readReviewRecords(worker, records, () => true, () => assert.fail()), /review unavailable/);
  }
  await assert.rejects(readReviewRecords(worker, [], () => false, () => assert.fail()), /review unavailable/);
  assert.equal(calls, 0);
  let active = true;
  await assert.rejects(readReviewRecords(worker, [record(), record()], () => active, () => { active = false; }), /review unavailable/);
  assert.equal(calls, 1);
  const failed = { async call() { throw new Error("synthetic worker failure"); } };
  await assert.rejects(readReviewRecords(failed, [record()], () => true, () => assert.fail()), /synthetic worker failure/);
});

test("a full rejected page does not prevent a later valid page from being read", async () => {
  const output = [];
  const worker = { async call() { return null; } };
  assert.equal(await readReviewRecords(worker, Array.from({ length: 50 }, record), () => true, (text) => output.push(text)), 50);
  worker.call = async () => plaintext("synthetic later page");
  assert.equal(await readReviewRecords(worker, [record()], () => true, (text) => output.push(text)), 0);
  assert.equal(output.length, 51);
  assert.equal(output.at(-1), "synthetic later page");
});

test("bounded generated record encodings admit only canonical fixed-size envelopes", async () => {
  for (let i = 0; i < 128; i++) {
    const size = 4144 + i % 3, suffix = i % 5 === 0 ? "=" : "";
    const envelope = encode(new Uint8Array(size).fill(i)) + suffix;
    let calls = 0;
    const worker = { async call() { calls++; return null; } };
    assert.equal(await readReviewRecords(worker, [{ envelope }], () => true, () => {}), 1);
    assert.equal(calls, Number(size === 4145 && suffix === ""));
  }
});
