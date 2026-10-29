// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import assert from "node:assert/strict";
import { test } from "node:test";
import { mountSessions } from "../web/browser/sessions.mjs";
import { api as commonAPI } from "../web/browser/common.mjs";

const id = (n) => Buffer.alloc(16, n).toString("base64url");
const info = (n, current = false) => ({id:id(n), current, created_at:"2026-10-29T10:00:00Z", expires_at:"2026-10-29T11:00:00Z"});
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return {promise, resolve}; };
class Element extends EventTarget {
  children = []; disabled = false; hidden = false; checked = false; textContent = "";
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  focus() { this.focused = true; }
}
function harness(t) {
  const elements = new Map(["sessions", "session-actions", "session-list", "session-refresh", "session-verify", "confirm-logout-all", "logout-all", "logout"].map((s) => [s,new Element()]));
  const root = Object.assign(new EventTarget(), {visibilityState:"visible", getElementById:(id) => elements.get(id), createElement:() => new Element()});
  const messages = [], calls = [], statuses = [];
  let list = [info(1,true),info(2)], failure = null, waiting = null, locks = 0, leaves = 0, verified = 0, interval, closed = false;
  const host = Object.assign(new EventTarget(), {BroadcastChannel:class { constructor(name) { assert.equal(name,"anonce.account-session.v1"); host.channel = this; } postMessage(v) { messages.push(v); } close() { closed = true; } }, setInterval(fn,ms) { assert.equal(ms,30000); interval = fn; return 1; }, clearInterval(n) { assert.equal(n,1); }});
  const controls = mountSessions(root, host, {
    async api(path, body) { calls.push({path,body}); if (waiting) return waiting.promise; if (failure) throw Object.assign(new Error("synthetic"),{status:failure}); if (path.endsWith("/sessions")) return list; if (path.endsWith("/revoke")) { list = list.filter((s) => s.id !== body.id); return {removed:true}; } return {}; },
    lock() { locks++; }, async reauthenticate() { verified++; if (waiting) await waiting.promise; }, signedOut() { leaves++; }, say(s) { statuses.push(s); },
  });
  t.after(() => controls.dispose());
  return {controls,root,host,calls,messages,statuses,get:(id) => elements.get(id), click:(id) => elements.get(id).onclick(), tick:() => interval(),
    set list(v) { list=v; }, set failure(v) { failure=v; }, set waiting(v) { waiting=v; }, get waiting() { return waiting; },
    get locks() { return locks; }, get leaves() { return leaves; }, get verified() { return verified; }, get closed() { return closed; }};
}
test("bounded inventory renders times and current marker, never selectors as visible text", async (t) => {
  const h=harness(t); assert.equal(h.get("sessions").hidden,true); await h.controls.refresh();
  const rows=h.get("session-list").children; assert.equal(rows.length,2); assert.match(rows[0].children[0].textContent,/Current session/); assert.equal(rows[0].children.length,1);
  assert.equal(rows[1].children[1].textContent,"Sign out this other session"); assert.ok(!rows[1].children[0].textContent.includes(id(2)));
  await rows[1].children[1].onclick(); assert.deepEqual(h.calls.find((c)=>c.body),{path:"/api/browser/sessions/revoke",body:{id:id(2)}}); assert.equal(h.get("session-list").children.length,1); assert.equal(h.get("session-refresh").focused,true);
});
test("all-session sign-out requires explicit confirmation and locks before transport", async (t) => {
  const h=harness(t); await h.controls.refresh(); await h.click("logout-all"); assert.equal(h.locks,0);
  h.get("confirm-logout-all").checked=true; h.get("confirm-logout-all").onchange(); assert.equal(h.get("logout-all").disabled,false);
  h.waiting=deferred(); const operation=h.click("logout-all"); assert.equal(h.locks,1); assert.equal(h.get("session-actions").disabled,true);
  assert.equal(h.calls.at(-1).path,"/api/browser/logout-all"); await h.click("logout"); assert.equal(h.calls.length,2);
  h.waiting.resolve({signed_out:true}); await operation; assert.equal(h.leaves,1); assert.deepEqual(h.messages,["signed-out"]); assert.equal(h.get("sessions").hidden,true); assert.equal(h.get("confirm-logout-all").checked,false);
});
test("single-session logout locks and clears controls without deleting encrypted records", async (t) => {
  const h=harness(t); await h.controls.refresh(); await h.click("logout"); assert.equal(h.locks,1); assert.equal(h.calls.at(-1).path,"/api/browser/logout"); assert.equal(h.leaves,1); assert.equal(h.get("session-list").children.length,0);
});
for (const status of [403,503]) test(`failed sign-out ${status} stays locked and never retries automatically`, async (t) => {
  const h=harness(t); await h.controls.refresh(); h.failure=status; h.get("confirm-logout-all").checked=true; await h.click("logout-all");
  assert.equal(h.locks,1); assert.equal(h.leaves,0); assert.equal(h.calls.length,2); assert.deepEqual(h.messages,[]); assert.equal(h.get("session-list").children.length,0);
  assert.match(h.statuses.at(-1),status===403?/Verify your passkey/:/uncertain/);
});
test("reauthentication is separate from revocation and does not auto-repeat an action", async (t) => {
  const h=harness(t); await h.controls.refresh(); await h.click("session-verify"); assert.equal(h.verified,1); assert.equal(h.locks,1); assert.ok(h.calls.every((c)=>c.body===undefined)); assert.match(h.statuses.at(-1),/expiry is unchanged/);
});
test("late inventory and reauthentication cannot repopulate a signed-out page", async (t) => {
  const h=harness(t); await h.controls.refresh(); h.waiting=deferred(); const work=h.click("session-verify"); h.host.channel.onmessage({data:"signed-out"}); h.waiting.resolve([info(1,true)]); await work;
  assert.equal(h.get("sessions").hidden,true); assert.equal(h.get("session-list").children.length,0); assert.deepEqual(h.statuses,[]); assert.equal(h.leaves,1); assert.deepEqual(h.messages,[]);
  const pending=h.controls.refresh(); h.controls.reset(); await pending; assert.equal(h.get("sessions").hidden,true);
});
test("visible heartbeat and foreground events observe revoked sessions, not transient failures", async (t) => {
  const h=harness(t); await h.controls.refresh(); h.root.visibilityState="hidden"; await h.tick(); assert.equal(h.calls.length,1);
  h.root.visibilityState="visible"; h.failure=503; await h.tick(); assert.equal(h.leaves,0); h.failure=401; await h.tick(); assert.equal(h.leaves,1); await h.tick(); assert.equal(h.calls.length,3);
});
test("malformed and generated over-bound inventories fail before rendering partial metadata", async (t) => {
  const h=harness(t);
  for (const list of [null,[],[info(1)],[info(1,true),info(1)],Array.from({length:17},(_,i)=>info(i+1,i===0)),[{...info(1,true),id:"bad"}],[{...info(1,true),created_at:"invalid"}]]) {
    h.list=list; await assert.rejects(h.controls.refresh()); assert.equal(h.get("session-list").children.length,0);
  }
  for (let length=1;length<=16;length++) { h.list=Array.from({length},(_,i)=>info(i+1,i===0)); await h.controls.refresh(); assert.equal(h.get("session-list").children.length,length); }
});
test("disposal closes coordination and suppresses delayed inventory", async (t) => {
  const h=harness(t); h.waiting=deferred(); const work=h.controls.refresh(); h.controls.dispose(); h.waiting.resolve([info(1,true)]); await work; assert.equal(h.closed,true); assert.equal(h.get("sessions").hidden,true);
});
test("failed confirmation clears the checkbox before transport and requires another explicit choice", async (t) => {
  const h=harness(t); await h.controls.refresh(); h.get("confirm-logout-all").checked=true; h.failure=403; await h.click("logout-all");
  assert.equal(h.get("confirm-logout-all").checked,false); assert.equal(h.get("logout-all").disabled,true); await h.click("logout-all"); assert.equal(h.calls.length,2);
});
test("same-partition notices contain no credentials and never echo", async (t) => {
  const h=harness(t); await h.controls.refresh(); h.host.channel.onmessage({data:{account:"ignored"}}); assert.equal(h.leaves,0);
  h.host.channel.onmessage({data:"signed-out"}); assert.equal(h.leaves,1); assert.deepEqual(h.messages,[]); assert.equal(h.get("session-list").children.length,0);
});
test("only identity-local unauthorized responses announce session invalidation", async (t) => {
  const names=["document","fetch","dispatchEvent"], descriptors=names.map((name)=>Object.getOwnPropertyDescriptor(globalThis,name));
  t.after(()=>names.forEach((name,index)=>{ if (descriptors[index]) Object.defineProperty(globalThis,name,descriptors[index]); else delete globalThis[name]; }));
  const events=[]; let request, identity=true;
  globalThis.document={body:{hasAttribute:()=>identity}};
  globalThis.dispatchEvent=(event)=>events.push(event.type);
  globalThis.fetch=async (url,options)=>{ request={url,options}; return new Response("{}",{status:401}); };
  await assert.rejects(commonAPI("/api/browser/sessions"),{status:401}); assert.deepEqual(events,["anonce-session-ended"]); assert.equal(request.options.credentials,"same-origin");
  await assert.rejects(commonAPI("/api/browser/review/read",{},"https://submit.localhost:8444"),{status:401}); assert.equal(events.length,1); assert.equal(request.options.credentials,"omit"); assert.equal(request.options.headers["X-Anonce-CSRF"],undefined);
  identity=false; await assert.rejects(commonAPI("/api/browser/submit",{}),{status:401}); assert.equal(events.length,1); assert.equal(request.options.credentials,"omit");
});
