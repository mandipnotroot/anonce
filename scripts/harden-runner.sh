#!/bin/sh
# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
set -eu
umask 077
ulimit -c 0
test -d .git
test "$(git rev-parse --is-inside-work-tree)" = true
git config --local core.hooksPath .githooks
git config --local protocol.file.allow never
if test -n "${GITHUB_ENV:-}"; then
  echo 'PYTHONDONTWRITEBYTECODE=1' >> "$GITHUB_ENV"
  echo 'PIP_DISABLE_PIP_VERSION_CHECK=1' >> "$GITHUB_ENV"
  echo "BASH_ENV=$GITHUB_WORKSPACE/scripts/ci-shell.sh" >> "$GITHUB_ENV"
fi
# Apply process defaults in each later shell too; a child cannot change its parent.
if test -n "${GITHUB_WORKSPACE:-}" && git config --local --get-all http.https://github.com/.extraheader > /dev/null; then
  echo 'unexpected persisted checkout credentials' >&2
  exit 1
fi
echo 'runner checks: passed; no network-isolation claim'
