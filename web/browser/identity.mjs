// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { MemberWorkerSession, lockMemberWorkers } from "/runtime/member/member-client.mjs";
import { ReviewWorker } from "./review-client.mjs";
import { readReviewRecords, reviewOwnerActive } from "./review-records.mjs";
import { $, api, decode, encode, handle, localRecord, say, textBytes } from "./common.mjs";
import { mountSessions } from "./sessions.mjs";

let config, account, member = null, unlocked = false, backup = null, review = null, incoming = null, rounds = [], authentication = null, generation = 0;
const selected = new URL(location.href).searchParams.get("round");
const lock = () => { generation++; member?.lock(); member = null; unlocked = false; review?.close(); review = null; lockMemberWorkers(); for (const input of document.querySelectorAll('input[type="password"]')) input.value = ""; for (const output of document.querySelectorAll(".plaintext")) output.textContent = ""; authentication?.abort(); $("issue").disabled = $("enroll").disabled = true; };
function signedOut() {
  lock(); account = backup = incoming = null; rounds = []; sessions.reset();
  for (const id of ["workspace-nav", "vault", "reviews", "administration", "authorization"]) $(id).hidden = true;
  $("account").textContent = ""; $("invitation").textContent = ""; $("rounds").replaceChildren();
  $("setup").disabled = $("unlock").disabled = true;
  $("username").focus();
  say("Create an account or sign in with a user-verifying passkey. Local keys are locked; encrypted backups are unchanged.");
}
const sessions = mountSessions(document, window, {api, lock, reauthenticate: () => authenticate("reauthenticate"), signedOut, say,
  observeAccount: (user) => { if (account && user.name !== account.name) signedOut(); }});
addEventListener("anonce-session-ended", signedOut);
$("cancel").onclick = () => { lock(); say("Local keys locked and pending local work discarded. Server actions already admitted are not undone."); };
addEventListener("pagehide", lock);
document.addEventListener("visibilitychange", () => { if (document.visibilityState !== "visible") { for (const input of document.querySelectorAll('input[type="password"]')) input.value = ""; for (const output of document.querySelectorAll(".plaintext")) output.textContent = ""; } });
async function refresh() {
  const version = generation, next = await api("/api/browser/me"); let nextBackup = null;
  if (version !== generation) return;
  if (account && account.name !== next.name) { signedOut(); return; }
  try { nextBackup = await api("/api/browser/backup"); } catch (error) { if (error.status !== 404) throw error; }
  const nextRounds = (await api("/api/browser/rounds")) ?? [];
  await sessions.refresh(); if (version !== generation) return;
  account = next; backup = nextBackup; rounds = nextRounds; $("account").textContent = `Signed in as ${account.name}${account.administrator ? " (administrator)" : ""}.`;
  for (const id of ["workspace-nav", "vault", "reviews"]) $(id).hidden = false;
  $("administration").hidden = !account.administrator; $("logout").disabled = false; $("cancel").disabled = false;
  $("setup").disabled = backup !== null; $("unlock").disabled = backup === null;
  $("enroll").disabled = !unlocked;
  renderRounds();
  if (incoming && selected) { const r = rounds.find((r) => r.id === selected && r.bulletin); if (r) { $("authorization").hidden = false; $("authorize-question").textContent = r.question; $("issue").disabled = !unlocked; } }
}
function credentialJSON(credential) {
  const response = credential.response;
  const out = {id: credential.id, rawId: encode(new Uint8Array(credential.rawId)), type: credential.type, clientExtensionResults: {}, response: {clientDataJSON: encode(new Uint8Array(response.clientDataJSON))}};
  for (const field of ["attestationObject", "authenticatorData", "signature", "userHandle"]) if (response[field]) out.response[field] = encode(new Uint8Array(response[field]));
  if (response.getTransports) out.response.transports = response.getTransports();
  return out;
}
async function authenticate(kind) {
  const name = $("username").value, bootstrap = $("bootstrap").value;
  lock(); const version = generation, controller = new AbortController(); authentication = controller; $("bootstrap").value = "";
  say("Confirm the passkey ceremony in your browser.");
  const options = await api(`/api/browser/auth/${kind}/begin`, kind === "reauthenticate" ? {} : {name, bootstrap}, "", controller.signal);
  if (version !== generation) throw new Error("cancelled");
  const publicKey = kind === "register" ? PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey) : PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey);
  const credential = kind === "register" ? await navigator.credentials.create({publicKey, signal: controller.signal}) : await navigator.credentials.get({publicKey, signal: controller.signal});
  if (version !== generation) throw new Error("cancelled");
  await api(`/api/browser/auth/${kind}/finish`, credentialJSON(credential), "", controller.signal);
  if (version !== generation) throw new Error("cancelled");
  authentication = null; if (kind !== "reauthenticate") { account = backup = null; await refresh(); if (version === generation) say("Account authenticated. Unlock the member key separately when needed."); }
}
$("authentication").onsubmit = handle(() => authenticate("register")); $("login").onclick = handle(() => authenticate("login"));
async function startMember() {
  member?.close(); const current = new MemberWorkerSession(); member = current;
  current.closed.then(() => { if (member === current) { unlocked = false; $("issue").disabled = $("enroll").disabled = true; say("Member key locked. Restore it explicitly to continue."); } });
  if (!await current.ready || member !== current) throw new Error("worker unavailable"); return current;
}
$("member").onsubmit = handle(async () => {
  if (backup || !account) throw new Error("backup already exists or signed out"); const version = generation, passphrase = $("passphrase").value, confirmation = $("confirmation").value; $("member").reset();
  const current = await startMember(); say("Generating and encrypting the member key locally."); const result = await current.createWithPassphrase(passphrase, confirmation); if (!result) throw new Error("setup failed");
  if (version !== generation) throw new Error("cancelled");
  await api("/api/browser/backup", {public_key: encode(result.publicKey), backup: encode(result.backup), revision: 0});
  if (version !== generation) throw new Error("cancelled");
  await localRecord(`member-public:${account.name}`, encode(result.publicKey)); if (version !== generation) throw new Error("cancelled"); unlocked = true; await refresh(); if (version === generation) say("Encrypted member backup stored. The member key is unlocked locally. Verify membership with your invitation next.");
});
$("unlock").onclick = handle(async () => {
  const version = generation, record = backup, passphrase = $("passphrase").value; $("member").reset(); if (!record || !account) throw new Error("no backup");
  unlocked = false; $("issue").disabled = $("enroll").disabled = true; say("Restoring and validating the member key locally.");
  const pinned = await localRecord(`member-public:${account.name}`); if (version !== generation || pinned && pinned !== record.public_key) throw new Error("key binding changed or cancelled");
  const current = await startMember(); const result = await current.unlockWithPassphrase(passphrase, decode(record.backup,108), decode(pinned ?? record.public_key,32));
  if (!result || version !== generation) throw new Error("restoration failed"); unlocked = true; await refresh(); if (version === generation) say("Member key restored and matched to its expected public binding. Ready to authorize.");
});
$("enrollment").onsubmit = handle(async () => { const version = generation, code = $("code").value; $("code").value = ""; if (!unlocked) throw new Error("locked"); say("Verifying the single-use membership invitation."); const request = await member.request(); if (!request || version !== generation) throw new Error("locked"); await api("/api/browser/enroll", {code, csr: encode(request.csr)}); if (version === generation) say("Membership verified. You may authorize one response to each open published review."); });
$("invite").onclick = handle(async () => { const version = generation, result = await api("/api/browser/invitations", {}); if (version === generation) $("invitation").textContent = `Single-use invitation: ${result.code}\nExpires in 24 hours. Deliver privately to one eligible member. It is shown only here.`; });
$("round").onsubmit = handle(async () => { say("Creating the review draft."); await api("/api/browser/rounds", {question: $("question").value, reviewer: $("reviewer").value, opens: new Date($("opens").value).toISOString(), closes: new Date($("closes").value).toISOString(), review_until: new Date($("review-until").value).toISOString(), response_limit: Number($("limit").value)}); await refresh(); say("Draft created. The assigned reviewer must prepare its key before publication."); });
$("refresh").onclick = handle(refresh);
function button(text, fn) { const b = document.createElement("button"); b.type = "button"; b.textContent = text; b.onclick = handle(fn); return b; }
function field(form, text, id, autocomplete) { const label = document.createElement("label"); label.htmlFor = id; label.textContent = text; const input = document.createElement("input"); input.id = id; input.type = "password"; input.required = true; input.maxLength = 1024; input.autocomplete = autocomplete; form.append(label,input); return input; }
function renderRounds() {
  $("rounds").replaceChildren();
  for (const r of rounds) {
    const card = document.createElement("section"), heading = document.createElement("h3"); heading.textContent = r.question; card.append(heading);
    const state = document.createElement("p"); state.textContent = r.bulletin ? "Published. One response per member." : r.reviewer_key ? "Draft: reviewer key prepared." : "Draft: waiting for the assigned reviewer."; card.append(state);
    if (r.bulletin) {
      const link = document.createElement("a"); link.href = `${config.submission_origin}/?round=${r.id}`; link.referrerPolicy = "no-referrer"; link.rel = "noreferrer"; link.textContent = "Open common response link"; card.append(link);
      if (account.administrator) card.append(button("Deliver signed publication", async () => { await api("/api/browser/publish", {bulletin:r.bulletin},config.submission_origin); say("Signed common bulletin delivered to the anonymous service."); }));
    } else if (account.administrator) card.append(button("Confirm one-response limit and publish", async () => { const result = await api("/api/browser/publish",{round:r.id,response_limit:1}); await api("/api/browser/publish",result,config.submission_origin); await refresh(); say("Published the common form and reviewer key. Share its common response link."); }));
    if (r.assigned) {
      const form = document.createElement("form"); const pass = field(form,"Local reviewer-key passphrase",`review-pass-${r.id}`,r.bulletin ? "current-password" : "new-password"); let confirmation;
      if (!r.bulletin) confirmation = field(form,"Confirm reviewer-key passphrase",`review-confirm-${r.id}`,"new-password");
      const submit = document.createElement("button"); submit.textContent = r.bulletin ? "Unlock and read encrypted answers" : "Set up private review access"; form.append(submit);
      const output = document.createElement("div"); output.className = "plaintext";
      form.onsubmit = handle(async () => {
        const version = generation, p = pass.value, c = confirmation?.value; form.reset(); review?.close(); const current = new ReviewWorker(true); review = current; if (!await current.ready || version !== generation) throw new Error("worker unavailable");
        const key = `review:${account.name}:${r.id}`; let stored = await localRecord(key); const password = textBytes(p);
        try {
          if (version !== generation) throw new Error("cancelled");
          if (!r.bulletin) {
            if (!stored) { const confirm = textBytes(c); let generated; try { const operation = current.call("reviewerCreate",password,confirm,decode(r.id,16)); password.fill(0); confirm.fill(0); generated = await operation; } finally { confirm.fill(0); } if (!generated || version !== generation) throw new Error("setup failed"); stored = {public_key:encode(generated.publicKey),backup:encode(generated.backup)}; await localRecord(key,stored); }
            if (version !== generation) throw new Error("cancelled");
            await api("/api/browser/reviewer",{round:r.id,public_key:stored.public_key}); current.close(); if (version !== generation) return; await refresh(); if (version === generation) say("Round reviewer key prepared. Its encrypted copy is only in this browser. Do not clear browser storage; no server backup or recovery exists.");
          } else {
            if (!stored) throw new Error("review key is unavailable in this browser"); const raw = decode(r.bulletin,564,1587); const operation = current.call("reviewerUnlock",password,decode(stored.backup,108),raw,decode(config.bulletin_key,32)); password.fill(0); const unlocked = await operation; if (!unlocked || version !== generation) throw new Error("unlock failed");
            const reviewUntil = Date.parse(r.review_until);
            const isActive = () => version === generation && reviewOwnerActive(current, review, document.visibilityState, reviewUntil);
            output.replaceChildren(); let cursor = encode(new Uint8Array(16)), rejected = 0;
            while (true) { if (!isActive()) throw new Error("locked"); const challenge = await api("/api/browser/review/challenge",{round:r.id,cursor},config.submission_origin); const proof = await current.call("proof",decode(challenge.challenge,81)); if (!proof || !isActive()) throw new Error("locked"); let page; try { page = await api("/api/browser/review/read",{round:r.id,proof:encode(proof.bytes)},config.submission_origin); } finally { proof.bytes.fill(0); }
              rejected += await readReviewRecords(current, page.records ?? [], isActive, (text) => { const paragraph = document.createElement("p"); paragraph.textContent = text ?? "Encrypted answer unavailable: this record could not be decrypted."; output.append(paragraph); });
              if (!page.records || page.records.length < 50) break; cursor = page.cursor;
            }
            if (!isActive()) throw new Error("locked");
            say(`Answers decrypted locally.${rejected ? ` ${rejected} encrypted answer(s) could not be decrypted; other records were still read.` : ""} Text may identify its author. Results clear when this page is hidden or locked.`);
          }
        } finally { password.fill(0); }
      }); card.append(form,output);
    }
    $("rounds").append(card);
  }
}
addEventListener("message", handle(async (event) => {
  if (!config || !selected || event.origin !== config.submission_origin || event.source !== window.opener || incoming || !event.data || Object.keys(event.data).sort().join() !== "blinded,round,type" || event.data.type !== "issue" || event.data.round !== selected) return;
  decode(event.data.blinded,384); incoming = event.data; await refresh();
}));
$("issue").onclick = handle(async () => {
  if (!incoming || !unlocked) throw new Error("not ready"); $("issue").disabled = true;
  const version = generation, current = member, request = incoming;
  const r = rounds.find((r) => r.id === selected && r.bulletin); if (!r) throw new Error("round unavailable");
  const result = await api("/api/browser/challenge",{round:selected,blinded:request.blinded});
  if (version !== generation) throw new Error("cancelled");
  const signed = await current.authorize(decode(result.challenge,113),decode(r.bulletin,564,1587),decode(config.bulletin_key,32),decode(request.blinded,384)); if (!signed || version !== generation) throw new Error("locked");
  const issued = await api("/api/browser/issue",{challenge:result.challenge,signature:encode(signed.signature),blinded:request.blinded});
  if (version !== generation) throw new Error("cancelled");
  window.opener.postMessage({type:"issued",round:selected,signature:issued.signature},config.submission_origin); incoming = null; lock(); say("Authorization delivered to the anonymous response page. Return there to encrypt and submit.");
});
handle(async () => {
  config = await api("/api/browser/config");
  if (!PublicKeyCredential.parseCreationOptionsFromJSON || !PublicKeyCredential.parseRequestOptionsFromJSON) { say("This MVP requires a browser with WebAuthn JSON support and a user-verifying authenticator."); return; }
  $("register").disabled = $("login").disabled = false; $("cancel").disabled = false;
  if (selected) { decode(selected,16); if (window.opener) window.opener.postMessage({type:"ready",round:selected},config.submission_origin); }
  try { await refresh(); say("Signed in. Local keys remain locked until you unlock them."); } catch { say("Create an account or sign in with a user-verifying passkey."); }
})();
