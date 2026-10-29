// SPDX-FileCopyrightText: 2026 Anonce Contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Test-only form composition. Delivery, custody, and persistence are not product APIs.
export function mountMemberForms(root, makeSession, saveBackup) {
  const get = (id) => root.getElementById(id);
  const form = get("member-setup"), fields = get("setup-fields");
  const password = get("setup-passphrase"), confirmation = get("setup-confirmation");
  const lock = get("member-lock"), status = get("form-status");
  let owner = null, busy = false, unlocked = false, saved = false, disposed = false, generation = 0;
  const clearInputs = () => { password.value = confirmation.value = ""; };
  const render = (message) => {
    fields.disabled = disposed || busy || unlocked || saved;
    lock.disabled = disposed || owner === null;
    form.setAttribute("aria-busy", String(busy));
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
  const submit = async (event) => {
    event.preventDefault();
    if (disposed || busy || unlocked || saved) { clearInputs(); return; }
    // Independent fields, exact text, no trimming or normalization. The worker
    // validates UTF-8 bounds and shared Go performs confirmation before setup.
    let first = password.value, second = confirmation.value;
    clearInputs();
    const current = ++generation;
    busy = true;
    render("Preparing a synthetic member key and encrypted backup. Lock cancels this operation.");
    try {
      const session = makeSession();
      owner = session;
      render("Preparing a synthetic member key and encrypted backup. Lock cancels this operation.");
      void session.closed.then(() => { if (owner === session) stop(); });
      if (!await session.ready || current !== generation) return;
      const pending = session.createWithPassphrase(first, second);
      first = second = ""; // Immutable/runtime copies cannot be erased.
      const created = await pending;
      if (current !== generation) return;
      if (created === null) {
        stop();
        render("Setup failed. Enter matching passphrases of 1–1024 UTF-8 bytes. No replacement key was saved.");
        password.focus();
        return;
      }
      // This synchronous test adapter retains only encrypted/public material.
      // A saved synthetic backup is not enrollment or a durable account backup.
      saveBackup(created);
      saved = true;
      busy = false;
      unlocked = true;
      render("Synthetic member key unlocked. Encrypted backup is in page memory only, not saved to an account.");
      lock.focus();
    } catch {
      if (current === generation) {
        stop();
        render("Setup unavailable. No account backup or enrollment was completed.");
        password.focus();
      }
    } finally {
      first = second = "";
      if (current === generation && busy) stop();
    }
  };
  const lockNow = () => { owner?.lock(); stop(); password.focus(); };
  form.addEventListener("submit", submit);
  lock.addEventListener("click", lockNow);
  clearInputs();
  render("Locked. Use synthetic passphrases only. Nothing is sent to a server.");
  return () => {
    disposed = true;
    stop();
    form.removeEventListener("submit", submit);
    lock.removeEventListener("click", lockNow);
  };
}
