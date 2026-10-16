# Local Exocortex installation

Installed September 20, 2026 from existing UofT source with a fresh Python 3.13
runtime using `requirements-macos.lock` and pip's `--require-hashes`.

Uses the **existing enrolled device state** at `~/Desktop/uoft/.private/duo`;
no new pairing, device enrollment, or credential copy was performed.
Override with `DUO_STATE_DIR` or `UOFT_ROOT`.

Only inspect and approve the exact pending request matching a user-authorized
login. Approval requires a fresh exact ID and fingerprint. Verified Push code
must come from that login and be passed through stdin. No bulk approval.

Tests: `.venv/bin/python -m unittest discover -s tests`.
