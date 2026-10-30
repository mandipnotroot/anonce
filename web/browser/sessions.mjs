// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

import { decode } from "./common.mjs";

// Account-only controls. The channel contains no account, selector or bearer data.
export function mountSessions(root, host, { api, lock, reauthenticate, signedOut, say, observeAccount = () => {} }) {
  const get = (id) => root.getElementById(id);
  let active = false, busy = false, generation = 0, channel = null, disposed = false;
  const controls = () => {
    get("session-actions").disabled = !active || busy;
    get("logout").disabled = !active || busy;
    get("logout-all").disabled = !get("confirm-logout-all").checked;
  };
  const reset = () => { generation++; active = false; busy = false; get("sessions").hidden = true; get("session-list").replaceChildren(); get("confirm-logout-all").checked = false; controls(); };
  const leave = () => { reset(); signedOut(); };
  const notify = () => { try { channel?.postMessage("signed-out"); } catch { /* Local cleanup must not depend on notification delivery. */ } };
  try { channel = new host.BroadcastChannel("anonce.account-session.v1"); channel.onmessage = ({data}) => { if (data === "signed-out") leave(); }; channel.onmessageerror = leave; } catch { /* Server checks still enforce revocation. */ }
  async function refresh() {
    const version = generation;
    get("session-list").replaceChildren();
    const list = await api("/api/browser/sessions");
    if (disposed || version !== generation) return;
    if (!Array.isArray(list) || list.length < 1 || list.length > 16 || list.filter((s) => s.current === true).length !== 1) throw new Error("invalid sessions");
    const ids = new Set();
    for (const s of list) {
      decode(s.id, 16);
      if (ids.has(s.id) || typeof s.current !== "boolean" || !Number.isFinite(Date.parse(s.created_at)) || !Number.isFinite(Date.parse(s.expires_at))) throw new Error("invalid session");
      ids.add(s.id);
    }
    active = true; get("sessions").hidden = false;
    for (const s of list) {
      const item = root.createElement("li"), text = root.createElement("p");
      text.textContent = `${s.current ? "Current session. " : "Other session. "}Authenticated ${new Date(s.created_at).toLocaleString()}. Expires ${new Date(s.expires_at).toLocaleString()}.`;
      item.append(text);
      if (!s.current) {
        const button = root.createElement("button"); button.type = "button"; button.textContent = "Sign out this other session";
        button.onclick = () => run(async () => {
          const result = await api("/api/browser/sessions/revoke", {id:s.id});
          if (version !== generation) return;
          await refresh();
          if (version !== generation) return;
          say(result.removed ? "Other session signed out. Already loaded keys, text and admitted work cannot be recalled." : "Session was not removed. It may already be gone or have changed. The list has been refreshed.");
        }, true);
        item.append(button);
      }
      get("session-list").append(item);
    }
    controls();
  }
  async function run(operation, focusRefresh = false) {
    if (!active || busy || disposed) return;
    busy = true; controls(); const version = generation;
    try { await operation(); }
    catch (error) {
      if (version !== generation) return;
      if (error.status === 401) { leave(); return; }
      get("session-list").replaceChildren();
      say(error.status === 403 ? "Verify your passkey again, then explicitly choose the session action. Verification is required within five minutes." : "Session action failed or its result is uncertain. Refresh the session list or sign in again before choosing another action. Local keys remain locked after a sign-out attempt.");
    } finally { if (version === generation) { busy = false; controls(); if (focusRefresh) get("session-refresh").focus(); } }
  }
  get("session-refresh").onclick = () => run(refresh);
  get("session-verify").onclick = () => run(async () => { const version = generation; lock(); await reauthenticate(); if (version !== generation) return; await refresh(); if (version === generation) say("Passkey verified. Original session expiry is unchanged. Choose the session action explicitly; local keys remain locked."); });
  get("confirm-logout-all").onchange = controls;
  async function logout(everywhere) {
    if (everywhere && !get("confirm-logout-all").checked) return;
    get("confirm-logout-all").checked = false; controls();
    lock();
    await api(everywhere ? "/api/browser/logout-all" : "/api/browser/logout", {});
    notify(); leave();
  }
  get("logout").onclick = () => run(() => logout(false));
  get("logout-all").onclick = () => run(() => logout(true));
  // Revocation is enforced server-side immediately for new admission. A visible
  // page observes it on foregrounding and every 30 seconds while running.
  let checking = false;
  const check = async () => {
    if (!active || busy || checking || root.visibilityState !== "visible") return;
    checking = true; const version = generation;
    try { const user = await api("/api/browser/me"); if (version === generation && active && !disposed) observeAccount(user); } catch (error) { if (version === generation && !disposed && error.status === 401) leave(); } finally { checking = false; }
  };
  root.addEventListener("visibilitychange", check); host.addEventListener("focus", check);
  const timer = host.setInterval(check, 30000);
  reset();
  return { refresh, reset, dispose() { disposed = true; reset(); host.clearInterval(timer); channel?.close(); root.removeEventListener("visibilitychange", check); host.removeEventListener("focus", check); } };
}
