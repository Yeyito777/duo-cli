# Installations

The same `main` runs on every machine. Machine-specific settings live in the
untracked `config/local.env`, a bash fragment that `bin/duo` sources when it
exists. Write each setting as `VAR="${VAR:-value}"` so an explicit environment
variable still wins. Without the file, the defaults in this repository apply.

## whale (primary)

No `config/local.env`. Enrolled state lives in this tool's `config/`.
Runtime: `.venv` from `requirements.lock` with `--require-hashes`.

## macOS Desktop Exocortex

Installed September 20, 2026 from existing UofT source with a fresh Python 3.13
runtime using `requirements-macos.lock` and pip's `--require-hashes`.

Uses the **existing enrolled device state** at `~/Desktop/uoft/.private/duo`;
no new pairing, device enrollment, or credential copy was performed.
`config/local.env` there:

```bash
umask 077
DUO_STATE_DIR="${DUO_STATE_DIR:-${UOFT_ROOT:-$HOME/Desktop/uoft}/.private/duo}"
```

Only inspect and approve the exact pending request matching a user-authorized
login. Approval requires a fresh exact ID and fingerprint. Verified Push code
must come from that login and be passed through stdin. No bulk approval.

Tests: `.venv/bin/python -m unittest discover -s tests`.

### October 15 upstream authentication update

- Upstream `c813a7e` integrated; local launcher/state-path setup preserved in
  checkpoint `local/pre-auth-update-20261015` (`e8576b8`).
- Upstream adds the bounded `own-login` protocol used by Quercus/UTmail
  automatic re-login, including public-IP retry and audit/locking checks.
- Installing that code is not authorization to execute it. Continue following
  the active tool policy; this update performed no pairing or Duo approval.

### October 22 reconciliation

The Mac-only commits (backup branch `mac-local`, `aa04624`) were folded into
`main`: the state-dir default moved from `bin/duo` into the Mac's
`config/local.env`, so whale keeps its tool-local `config/` state.
