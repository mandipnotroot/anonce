// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Test-only Chromium driver using its private DevTools pipe. No npm dependencies,
// debugging TCP listener, sandbox bypass, CSP bypass, or persisted test secrets.
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { readFileSync, readSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const root = resolve(import.meta.dirname, "..");
const config = readFileSync(join(root, "scripts/browser.toml"), "utf8");
const wasmConfig = readFileSync(join(root, "scripts/wasm.toml"), "utf8");
assert.equal(process.version, /^node_version = "([^"]+)"$/m.exec(wasmConfig)?.[1]);
const executable = process.env.MEMBER_BROWSER;
assert.ok(executable, "set MEMBER_BROWSER to the reviewed Chromium executable");
const browserVersion = /^version = "([^"]+)"$/m.exec(config)?.[1];
let installedVersion;
try {
  installedVersion = execFileSync(executable, ["--version"], { timeout: 10_000, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
} catch { throw new Error("reviewed Chromium executable unavailable"); }
assert.ok(installedVersion === browserVersion, "unreviewed Chromium version");
const origin = process.argv[3];
assert.match(origin, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
const inputBytes = Buffer.alloc(4096);
let inputSize = 0;
while (inputSize < inputBytes.length) {
  const count = readSync(0, inputBytes, inputSize, inputBytes.length - inputSize, null);
  if (count === 0) break;
  inputSize += count;
}
assert.ok(inputSize < inputBytes.length);
let input;
try { input = JSON.parse(inputBytes.subarray(0, inputSize)); }
catch { throw new Error("invalid synthetic browser fixture"); }
finally { inputBytes.fill(0); }

const scratch = join(root, ".cache/tests");
mkdirSync(scratch, { recursive: true, mode: 0o700 });
const profile = mkdtempSync(join(scratch, "member-browser-"));
const child = spawn(executable, [
  "--headless", "--remote-debugging-pipe", `--user-data-dir=${profile}`,
  "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
  "--disable-component-update", "--disable-sync", "--disable-extensions",
  "--disable-breakpad", "--disable-crash-reporter", "about:blank",
], { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
let next = 0, buffer = Buffer.alloc(0), exited = false;
const pending = new Map(), listeners = new Set();
function failPending() {
  for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new Error("browser pipe closed")); }
  pending.clear();
}
const stopped = new Promise((resolve) => {
  child.once("error", () => { exited = true; failPending(); resolve(); });
  child.once("exit", () => { exited = true; failPending(); resolve(); });
});
const kill = () => { if (!exited) child.kill("SIGKILL"); };
const lifetime = setTimeout(kill, 150_000); // Finish cleanup before the native driver's deadline.
process.once("SIGTERM", kill);
process.once("SIGINT", kill);
child.stdio[3].on("error", failPending);
child.stdio[4].on("error", failPending);
child.stdio[4].on("data", (data) => {
  buffer = Buffer.concat([buffer, data]);
  if (buffer.length > 1024 * 1024) { child.kill("SIGKILL"); failPending(); return; }
  let end;
  while ((end = buffer.indexOf(0)) !== -1) {
    let message;
    try { message = JSON.parse(buffer.subarray(0, end).toString()); }
    catch { child.kill("SIGKILL"); failPending(); return; }
    buffer = buffer.subarray(end + 1);
    if (message.id) {
      const entry = pending.get(message.id);
      if (!entry) continue;
      clearTimeout(entry.timer);
      pending.delete(message.id);
      if (message.error) entry.reject(new Error("browser command failed"));
      else entry.resolve(message.result);
    } else {
      for (const listener of listeners) listener(message);
    }
  }
});
function send(method, params = {}, sessionId) {
  if (exited) return Promise.reject(new Error("browser unavailable"));
  const id = ++next;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("browser command timed out")); }, 120_000);
    pending.set(id, { resolve, reject, timer });
    child.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + "\0");
  });
}
async function evaluate(session, expression) {
  const value = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, session);
  assert.ok(!value.exceptionDetails, "browser evaluation failed");
  return value.result.value;
}
async function until(check) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) { if (await check()) return; await delay(25); }
  throw new Error("browser condition timed out");
}
let unexpectedRequest = false;
const allowedPaths = new Set(["/", "/browser.mjs", "/member-forms.mjs", "/member-client.mjs", "/member-worker.mjs", "/protocol.mjs", "/wasm_exec.js", "/client.wasm"]);
listeners.add((message) => {
  if (message.method !== "Network.requestWillBeSent") return;
  const request = message.params.request;
  const url = new URL(request.url);
  if (url.origin !== origin || !allowedPaths.has(url.pathname) || url.search || request.method !== "GET" || request.postData) unexpectedRequest = true;
});
async function page() {
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  await send("Network.enable", {}, sessionId);
  await send("Page.enable", {}, sessionId);
  // Enable monitoring before navigating; there is no interception or CSP bypass.
  await send("Page.navigate", { url: origin + "/" }, sessionId);
  await until(async () => await evaluate(sessionId, "document.readyState === 'complete' && document.getElementById('status') !== null"));
  await activate({ targetId, sessionId });
  return { targetId, sessionId };
}
async function activate(page) {
  await send("Target.activateTarget", { targetId: page.targetId });
  await until(async () => await evaluate(page.sessionId, "document.visibilityState === 'visible'"));
}
const workerIDs = async () => (await send("Target.getTargets")).targetInfos.filter((target) => target.type === "worker").map((target) => target.targetId);
async function workersGone(workers) {
  await until(async () => !(await workerIDs()).some((id) => workers.includes(id)));
}
const moduleCall = (call) => `import('/browser.mjs').then(m => m.${call})`;
async function enter(session, id, text) {
  await evaluate(session, `document.getElementById(${JSON.stringify(id)}).focus()`);
  await send("Input.insertText", { text }, session);
}
async function press(session, key) {
  await send("Input.dispatchKeyEvent", { type: "keyDown", key, code: key, text: key === "Enter" ? "\r" : "", windowsVirtualKeyCode: key === "Enter" ? 13 : 9 }, session);
  await send("Input.dispatchKeyEvent", { type: "keyUp", key, code: key, windowsVirtualKeyCode: key === "Enter" ? 13 : 9 }, session);
}
async function setupForm(session) {
  const passphrase = "synthetic browser passphrase é😀";
  const clear = "document.querySelectorAll('input[type=password]').values().every(e => e.value === '')";
  // Real keyboard input/submit, with distinct confirmation fields and safe errors.
  await enter(session, "setup-passphrase", passphrase);
  await press(session, "Tab");
  assert.equal(await evaluate(session, "document.activeElement.id"), "setup-confirmation");
  await send("Input.insertText", { text: "different synthetic passphrase" }, session);
  await press(session, "Enter");
  assert.equal(await evaluate(session, clear), true);
  await until(async () => await evaluate(session, "document.getElementById('form-status').textContent.startsWith('Setup failed.')"));
  assert.equal(await evaluate(session, moduleCall("formRecord()")), null);
  await enter(session, "setup-passphrase", passphrase);
  await enter(session, "setup-confirmation", passphrase);
  await press(session, "Enter");
  assert.equal(await evaluate(session, clear), true);
  await until(async () => await evaluate(session, "document.getElementById('form-status').textContent.startsWith('Synthetic member key unlocked.')"));
  assert.equal(await evaluate(session, "document.activeElement.id"), "member-lock");
  const record = await evaluate(session, moduleCall("formRecord()"));
  assert.ok(record !== null && Object.keys(record).sort().join() === "backup,csr,publicKey");
  await press(session, "Enter"); // Explicit lock keeps only encrypted/public page data.
  await until(async () => await evaluate(session, "document.getElementById('member-lock').disabled"));
  assert.equal(await evaluate(session, clear), true);
  const tree = await send("Accessibility.getFullAXTree", {}, session);
  for (const name of ["Local unlock passphrase", "Confirm local unlock passphrase", "Lock / cancel local work"]) {
    assert.ok(tree.nodes.some((node) => node.name?.value === name), "missing accessible form control name");
  }
  return { formBackup: record.backup, formPublicKey: record.publicKey, formCSR: record.csr };
}
async function restoreForm(page) {
  const session = page.sessionId, passphrase = "synthetic browser passphrase é😀";
  const original = await evaluate(session, moduleCall("formRecord()"));
  const clear = "document.querySelectorAll('input[type=password]').values().every(e => e.value === '')";
  for (const failure of ["password", "binding", "ciphertext"]) {
    const record = { ...original };
    if (failure === "binding") record.publicKey = (record.publicKey.startsWith("00") ? "01" : "00") + record.publicKey.slice(2);
    if (failure === "ciphertext") record.backup = record.backup.slice(0, -2) + (record.backup.endsWith("00") ? "01" : "00");
    await evaluate(session, moduleCall(`seedFormRecord(${JSON.stringify(record)})`));
    assert.equal(await evaluate(session, "document.getElementById('setup-fields').disabled"), true);
    await enter(session, "unlock-passphrase", failure === "password" ? "wrong synthetic passphrase" : passphrase);
    await press(session, "Enter");
    assert.equal(await evaluate(session, clear), true);
    await until(async () => await evaluate(session, "document.getElementById('form-status').textContent.startsWith('Unlock failed.')"));
    assert.ok(JSON.stringify(await evaluate(session, moduleCall("formRecord()"))) === JSON.stringify(record), "failed unlock replaced the encrypted record");
    await until(async () => (await workerIDs()).length === 0);
  }
  await evaluate(session, moduleCall(`seedFormRecord(${JSON.stringify(original)})`));
  await enter(session, "unlock-passphrase", passphrase);
  // Cancel in the same task as submit, before startup can produce any output.
  await evaluate(session, "document.getElementById('member-restore').requestSubmit(); document.getElementById('member-lock').click()");
  assert.equal(await evaluate(session, clear), true);
  assert.equal(await evaluate(session, "document.getElementById('restore-fields').disabled"), false);
  await until(async () => (await workerIDs()).length === 0);

  // A separate page gets only ciphertext and an independently retained setup key,
  // modeling host-supplied restoration without manual key files or key generation.
  const fresh = await newFormPage(original);
  await enter(fresh.sessionId, "unlock-passphrase", passphrase);
  await press(fresh.sessionId, "Enter");
  assert.equal(await evaluate(fresh.sessionId, clear), true);
  const tree = await send("Accessibility.getFullAXTree", {}, fresh.sessionId);
  assert.ok(tree.nodes.some((node) => node.name?.value === "Local passphrase for restoration"), "missing accessible restoration field name");
  await until(async () => await evaluate(fresh.sessionId, "document.getElementById('form-status').textContent.startsWith('Synthetic backup restored and key matched.')"));
  assert.equal(await evaluate(fresh.sessionId, "document.activeElement.id"), "member-lock");
  const unlockedWorkers = await workerIDs();
  assert.ok(unlockedWorkers.length > 0);
  await activate(page); // A real hidden-page transition must lock the form owner too.
  await workersGone(unlockedWorkers);
  await activate(fresh);
  assert.equal(await evaluate(fresh.sessionId, "document.getElementById('restore-fields').disabled"), false);
  assert.equal(await evaluate(fresh.sessionId, "document.getElementById('setup-fields').disabled"), true);
  assert.equal(await evaluate(fresh.sessionId, clear), true);
  assert.ok(JSON.stringify(await evaluate(fresh.sessionId, moduleCall("formRecord()"))) === JSON.stringify(original), "restoration changed the saved key/backup");
  const screenshot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true }, fresh.sessionId);
  writeFileSync(join(scratch, "member-forms.png"), Buffer.from(screenshot.data, "base64"));
  await send("Target.closeTarget", { targetId: fresh.targetId });
  await activate(page);
}
async function newFormPage(record) {
  const fresh = await page();
  await evaluate(fresh.sessionId, moduleCall(`seedFormRecord(${JSON.stringify(record)})`));
  return fresh;
}
let output;
try {
  await send("Target.setDiscoverTargets", { discover: true });
  const main = await page();
  assert.equal(await evaluate(main.sessionId, moduleCall("pagePolicy()")), true, "page CSP probes failed");
  output = await evaluate(main.sessionId, moduleCall(`run(${JSON.stringify(input)})`));
  assert.equal(await evaluate(main.sessionId, moduleCall(`deadlines(${JSON.stringify(input)})`)), true, "owner deadline checks failed");
  assert.equal(await evaluate(main.sessionId, moduleCall(`cancellation(${JSON.stringify(input)})`)), true, "owner cancellation checks failed");
  Object.assign(output, await setupForm(main.sessionId));
  await restoreForm(main);
  await until(async () => (await workerIDs()).length === 0);
  const peer = await page();
  assert.equal(await evaluate(peer.sessionId, moduleCall("openPeer()")), true);
  assert.equal(await evaluate(main.sessionId, moduleCall("notify()")), true);
  assert.equal(await evaluate(peer.sessionId, moduleCall("peerLocked()")), true, "same-origin peer remained unlocked");
  await send("Target.closeTarget", { targetId: peer.targetId });

  await activate(main);
  assert.equal(await evaluate(main.sessionId, moduleCall(`startVisibility(${JSON.stringify(input)})`)), true);
  const visibleWorkers = await workerIDs();
  assert.ok(visibleWorkers.length > 0, "no unlocked visibility-test worker observed");
  const foreground = await page(); // Real tab activation, not a synthetic lifecycle event.
  await until(async () => await evaluate(main.sessionId, "document.visibilityState === 'hidden'"));
  await workersGone(visibleWorkers); // Observe event-driven termination before calling the owner again.
  assert.equal(await evaluate(main.sessionId, moduleCall("visibilityLocked()")), true, "hidden page retained its session");
  assert.equal(await evaluate(main.sessionId, moduleCall("hiddenStartup()")), true, "hidden page started a worker");
  assert.equal((await workerIDs()).length, 0, "hidden startup left a worker");
  await activate(main);
  assert.equal(await evaluate(main.sessionId, moduleCall("visibilityLocked()")), true, "foregrounding revived old session");
  // Explicit restoration on a new owner remains available after returning.
  assert.equal(await evaluate(main.sessionId, moduleCall(`startVisibility(${JSON.stringify(input)})`)), true);
  await send("Target.closeTarget", { targetId: foreground.targetId });
  await evaluate(main.sessionId, moduleCall("notify()"));

  assert.equal(await evaluate(main.sessionId, moduleCall("pendingNavigation()")), true);
  const workers = await workerIDs();
  assert.ok(workers.length > 0, "no real browser worker observed");
  await send("Page.navigate", { url: "about:blank" }, main.sessionId);
  await workersGone(workers);
  assert.equal(unexpectedRequest, false, "unexpected page request");
} finally {
  clearTimeout(lifetime);
  process.removeListener("SIGTERM", kill);
  process.removeListener("SIGINT", kill);
  input.password = "";
  if (!exited) {
    // Closing the pipe's owning browser also stops its workers and renderer processes.
    void send("Browser.close").catch(() => {});
    await Promise.race([stopped, delay(5000, undefined, { ref: false })]);
    if (!exited) child.kill("SIGKILL");
    await stopped;
  }
  failPending();
  rmSync(profile, { recursive: true, force: true }); // Only this run's owned scratch directory.
}
process.stdout.write(JSON.stringify(output));
