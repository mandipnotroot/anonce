// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Test-only form composition. Delivery, custody, and persistence are not product APIs.
export function mountMemberForms(root, makeSession, saveBackup, loadBackup) {
  const get = (id) => root.getElementById(id);
  const form = get("member-setup"), fields = get("setup-fields");
  const password = get("setup-passphrase"), confirmation = get("setup-confirmation");
  const restore = get("member-restore"), restoreFields = get("restore-fields"), unlockPassword = get("unlock-passphrase");
  const lock = get("member-lock"), status = get("form-status");
  let owner = null, busy = false, unlocked = false, saved = false, disposed = false, generation = 0;
  // A failing source blocks setup rather than silently replacing an existing key.
  try { saved = loadBackup() !== null; } catch { saved = true; }
  const clearInputs = () => { password.value = confirmation.value = unlockPassword.value = ""; };
  const focusEntry = () => (saved ? unlockPassword : password).focus();
  const render = (message) => {
    const unavailable = disposed || root.visibilityState !== "visible" || busy || unlocked;
    fields.disabled = unavailable || saved;
    restoreFields.disabled = unavailable || !saved;
    lock.disabled = disposed || owner === null;
    form.setAttribute("aria-busy", String(busy));
    restore.setAttribute("aria-busy", String(busy));
    status.textContent = message;
  };
  const stop = () => {
    generation++;
    const previous = owner;
    owner = null;
    busy = unlocked = false;
    clearInputs();
    previous?.close();
    render("Locked. Only a synthetic encrypted backup, if created, remains in page memory.");
  };
  const perform = async (event, restoring) => {
    event.preventDefault();
    if (disposed || root.visibilityState !== "visible" || busy || unlocked || saved !== restoring) { clearInputs(); return; }
    // Independent fields, exact text, no trimming or normalization. The worker
    // validates UTF-8 bounds and shared Go performs confirmation before setup.
    let first = restoring ? unlockPassword.value : password.value, second = restoring ? "" : confirmation.value;
    clearInputs();
    const current = ++generation;
    const snapshots = [];
    busy = true;
    const progress = restoring ? "Unlocking the synthetic encrypted backup. Lock cancels this operation." :
      "Preparing a synthetic member key and encrypted backup. Lock cancels this operation.";
    render(progress);
    try {
      if (restoring) {
        // The trusted test adapter returns only encrypted/public material, never
        // an unlock secret. Bound and snapshot it before asynchronous startup.
        const record = loadBackup();
        for (const [value, size] of [[record?.backup, 108], [record?.publicKey, 32]]) {
          if (!(value instanceof Uint8Array) || value.length !== size || !(value.buffer instanceof ArrayBuffer)) {
            throw new Error("unavailable synthetic backup");
          }
          snapshots.push(new Uint8Array(value));
        }
      }
      const session = makeSession();
      owner = session;
      render(progress);
      void session.closed.then(() => { if (owner === session) stop(); });
      if (!await session.ready || current !== generation) return;
      const pending = restoring ? session.unlockWithPassphrase(first, snapshots[0], snapshots[1]) :
        session.createWithPassphrase(first, second);
      first = second = ""; // Immutable/runtime copies cannot be erased.
      const created = await pending;
      if (current !== generation) return;
      if (created === null) {
        stop();
        render(restoring ? "Unlock failed. Check the local passphrase and trusted backup. No replacement key was created." :
          "Setup failed. Enter matching passphrases of 1–1024 UTF-8 bytes. No replacement key was saved.");
        focusEntry();
        return;
      }
      // This synchronous test adapter retains only encrypted/public material.
      // A saved synthetic backup is not enrollment or a durable account backup.
      if (!restoring) { saveBackup(created); saved = true; }
      busy = false;
      unlocked = true;
      render(restoring ? "Synthetic backup restored and key matched. Local key unlocked; no account sign-in or enrollment occurred." :
        "Synthetic member key unlocked. Encrypted backup is in page memory only, not saved to an account.");
      lock.focus();
    } catch {
      if (current === generation) {
        stop();
        render(restoring ? "Unlock unavailable. A bounded encrypted backup and trusted expected public key are required. No replacement key was created." :
          "Setup unavailable. No account backup or enrollment was completed.");
        focusEntry();
      }
    } finally {
      first = second = "";
      for (const bytes of snapshots) bytes.fill(0);
      if (current === generation && busy) stop();
    }
  };
  const submit = (event) => { void perform(event, false); };
  const unlock = (event) => { void perform(event, true); };
  const lockNow = () => { owner?.lock(); stop(); focusEntry(); };
  const visibility = () => {
    if (root.visibilityState !== "visible") stop();
    else if (owner === null) render("Locked. Restore explicitly with the local passphrase; returning does not unlock the key.");
  };
  form.addEventListener("submit", submit);
  restore.addEventListener("submit", unlock);
  lock.addEventListener("click", lockNow);
  root.addEventListener("visibilitychange", visibility);
  clearInputs();
  render("Locked. Use synthetic passphrases only. Nothing is sent to a server.");
  return () => {
    disposed = true;
    stop();
    form.removeEventListener("submit", submit);
    restore.removeEventListener("submit", unlock);
    lock.removeEventListener("click", lockNow);
    root.removeEventListener("visibilitychange", visibility);
  };
}
