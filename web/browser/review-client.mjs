// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { byteView } from "./bytes.mjs";

let active = null;
export class ReviewWorker {
  #worker; #pending = null; #next = 0; #closed = false; #started = false; #born = Date.now(); #monotonic = performance.now(); #lastWall = this.#born; #lastMono = this.#monotonic; #ready; #resolve; #timer; #operation; #secret; #channel;
  #hide = () => { if (this.#secret && document.visibilityState !== "visible") this.close(); };
  #leave = () => this.close();
  constructor(secret = false) {
    this.#secret = secret;
    this.#ready = new Promise((resolve) => { this.#resolve = resolve; });
    if (active || secret && document.visibilityState !== "visible") { this.close(); return; }
    active = this;
    try {
    if (secret) { this.#channel = new BroadcastChannel("anonce.member-lock.v1"); this.#channel.onmessage = this.#channel.onmessageerror = () => this.close(); }
    this.#worker = new Worker("/assets/review-worker.mjs", { type: "module", credentials: "omit" });
    this.#worker.onerror = (event) => { event.preventDefault(); this.close(); };
    this.#worker.onmessageerror = () => this.close();
    this.#worker.onmessage = ({data}) => {
      if (!this.#live()) return;
      if (data?.ready === true && Object.keys(data).length === 1 && !this.#started) { this.#started = true; clearTimeout(this.#operation); this.#resolve(true); return; }
      if (!this.#pending || data?.id !== this.#pending.id || Object.keys(data).length !== 2) { this.close(); return; }
      const wall = Date.now() - this.#pending.wall, elapsed = performance.now() - this.#pending.monotonic;
      if (wall >= 120000 || elapsed >= 120000 || !validResult(data.result,this.#pending.method)) { this.close(); return; }
      const pending = this.#pending; this.#pending = null; clearTimeout(this.#operation); pending.resolve(data.result);
    };
    this.#timer = setTimeout(() => this.close(), 300000);
    this.#operation = setTimeout(() => this.close(), 30000);
    addEventListener("pagehide", this.#leave); document.addEventListener("visibilitychange", this.#hide);
    } catch { this.close(); }
  }
  get ready() { return this.#ready; }
  get closed() { return !this.#live(); }
  #live() { if (this.#closed) return false; const now=Date.now(),mono=performance.now(),wall=now-this.#born,elapsed=mono-this.#monotonic; if (!Number.isFinite(wall) || !Number.isFinite(elapsed) || now<this.#lastWall || mono<this.#lastMono || wall >= 300000 || elapsed >= 300000 || this.#secret && document.visibilityState !== "visible") { this.close(); return false; } this.#lastWall=now;this.#lastMono=mono;return true; }
  call(method, ...inputs) {
    if (!this.#live() || !this.#started || this.#pending || inputs.length > 4 || typeof method !== "string" || inputs.some((v) => !byteView(v, 1, 8192))) return Promise.resolve(null);
    const snapshots = inputs.map((v) => new Uint8Array(v));
    if(this.#next===Number.MAX_SAFE_INTEGER){this.close();return Promise.resolve(null);}
    const result = new Promise((resolve) => { this.#pending = {id: ++this.#next, resolve, method, wall:Date.now(), monotonic:performance.now()}; });
    clearTimeout(this.#operation); this.#operation = setTimeout(() => this.close(), 120000);
    try { this.#worker.postMessage({id: this.#next, method, inputs: snapshots}, snapshots.map((v) => v.buffer)); } catch { this.close(); }
    return result;
  }
  close() { if (this.#closed) return; this.#closed = true; this.#worker?.terminate(); this.#channel?.close(); clearTimeout(this.#timer); clearTimeout(this.#operation); this.#pending?.resolve(null); this.#pending = null; this.#resolve(false); removeEventListener("pagehide", this.#leave); document.removeEventListener("visibilitychange", this.#hide); if (active === this) active = null; }
}

function validResult(value,method){
  if(value===null)return true;
  if(!value||Object.getPrototypeOf(value)!==Object.prototype)return false;
  const sizes={prepare:{blinded:384},encrypt:{token:504,envelope:4145},submission:{token:504,envelope:4145},reviewerCreate:{publicKey:32,backup:108},proof:{bytes:32},decrypt:{bytes:[1,4000]}};
  if(Object.hasOwn(sizes,method)){const fields=sizes[method];return Object.keys(value).length===Object.keys(fields).length&&Object.entries(fields).every(([key,size])=>Array.isArray(size)?byteView(value[key],...size)!==null:byteView(value[key],size)!==null);}
  if(method==="inspect")return Object.keys(value).length===2&&byteView(value.id,16)!==null&&typeof value.question==="string"&&value.question.length>0&&value.question.length<=1024&&value.question.isWellFormed();
  const field={finalize:"authorized",receipt:"verified",reviewerUnlock:"unlocked",reviewerBind:"unlocked"}[method];return field!==undefined&&Object.keys(value).length===1&&value[field]===true;
}
