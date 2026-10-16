# duo-cli

`duo-cli` is a deliberately small external tool for viewing pending Duo Push
requests and approving **one exact request** on a separately enrolled local
emulated device. It has no watcher, daemon, `latest`, wildcard, bulk drain,
denial, or passcode feature. Its one automatic approval path is `own-login`,
reserved for the `utmail` and `quercus` helper tools re-logging into U of T (see
below and [SECURITY.md](SECURITY.md)).

> **Unsupported private protocol; tenant authorization required.** Duo provides
> no official API for clients to list or approve Duo Mobile Push requests. This
> tool adapts an unsupported private device protocol and is not affiliated with
> or supported by Duo. Use it only for a device you own and only after the
> account holder and applicable tenant/organization administrator explicitly
> authorize a separately enrolled emulated device. It may break without notice,
> violate policy, or weaken MFA.

## Exact approval safety contract

The ordinary runtime surface is limited to:

```bash
duo requests
duo request REQUEST_ID
duo approve REQUEST_ID --confirm-fingerprint FINGERPRINT
```

`requests` and `request` are read-only. `approve` is the only ordinary mutation.
It accepts only a documented safe ASCII exact ID (`[A-Za-z0-9._~-]`, 1–128
characters), never a prefix, `latest`, wildcard, `all`, URL, percent escape, or
Unicode lookalike. It sends one direct private-protocol equivalent of
`Duo.reply(urgid, "approve", code=...)` for that exact ID only.

An approval requires the exact public fingerprint returned by a prior
`duo request REQUEST_ID` review:

```bash
duo request req-alpha-01
# Copy its Fingerprint exactly.
duo approve req-alpha-01 --confirm-fingerprint sha256:...
```

While holding one non-blocking exclusive local-state lock, the client:

1. reads pending requests and selects exactly one exact ID;
2. requires the caller's prior, code-independent fingerprint to match;
3. renders sanitized context, then refetches under the same lock;
4. refuses absent, duplicate-ID, expired, non-pending, unknown-semantics, or
   changed public/private context; and only then
5. sends one approval for that ID.

The public fingerprint covers only displayed context and is deliberately
independent of any low-entropy Verified Push code. A private process-memory
comparison token (never rendered or serialized) detects a changed code/context
between the two reads. Re-running a handled request is refused.

### Positive Verified Push semantics

The pinned calsh source documents code-bearing attributes and
`verified_push_info` / `step_up_code_info`, but does **not** document a safe
implicit rule that no marker means ordinary push. This tool fails closed unless
the transaction has one positive discriminator:

- explicit boolean `verified_push`, `requires_code`, or
  `verification_required` set to `false` means ordinary push;
- those flags set to `true`, a known code-bearing attribute, a documented
  verified/step-up information object, or an explicit verified-push transaction
  type means code-required;
- the exact current U of T traditional-prompt ordinary-login shape observed in
  live tenant validation (`type=Login`, `phone_notification_type=visible_notification`,
  and explicit proximity booleans) is ordinary only when no positive code-required
  marker is present; nested U of T attribute groups are parsed read-only for context;
- absent, malformed, unfamiliar, or conflicting semantics are `unknown` and
  cannot be approved.

For an explicit code-required request, code is never accepted in argv. Supply
exact bounded UTF-8 bytes on stdin, with no newline or trimming:

```bash
printf %s '492' | duo approve req-code-02 \
  --confirm-fingerprint sha256:... --code-stdin
```

The code must be a 1–64 character ASCII unreserved token. The client reads stdin
only after it has proved the selected transaction is code-required; it never
guesses, displays, logs, fingerprints publicly, or stores the code.

## Own-login (utmail and quercus only)

```bash
duo own-login begin --caller utmail|quercus --json   # before opening the login page
printf %s CODE | UOFT_UTORID=... duo own-login approve TICKET --json
duo own-login end TICKET --outcome completed|failed
```

When `utmail` or `quercus` finds its persistent U of T session expired, it starts
the weblogin itself, reads the Verified Push code from its own Duo page, and
asks `own-login approve` to approve the one matching request. Approval requires
a live ticket from `begin` (≤180 s), exactly one pending request that appeared
after the ticket, service `Weblogin Standard`/`Azure AD Standard`, the expected
UTORid, this machine's public IP as host, and a code-required Verified Push.
At most 6 attempts per rolling 24 h; every step is appended to
`config/own-login-audit.jsonl` without codes. A live ticket also serves as the
lock so two tools never log in at once. No other caller may use this command.

## Install

This directory is an independent Git repository and does not alter the parent
Exocortex repository.

```bash
git clone https://github.com/Yeyito777/duo-cli.git \
  ~/Workspace/exocortex/external-tools/duo-cli
cd ~/Workspace/exocortex/external-tools/duo-cli
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
chmod +x bin/duo
./bin/duo --help
```

`duo login --qr FILE` also requires the `zbarimg` executable (`zbar` on Arch
Linux; `zbar-tools` on Debian/Ubuntu).

`requirements.lock` is a fully resolved, hash-pinned Linux/x86_64 CPython lock
for the supported dependencies. Do not install from an unreviewed replacement.

The default state directory is this tool's `config/`; use a different private
tool-local path before a command if needed:

```bash
duo --state-dir /private/path requests
# or: DUO_STATE_DIR=/private/path duo requests
```

State is one atomic `enrollment.json` containing the key and minimum response
fields, rather than independently committed key/response files. All operations
are anchored to a verified `O_DIRECTORY|O_NOFOLLOW` directory FD. The directory
is current-user-owned mode `0700`; the enrollment record and lock are regular,
current-user-owned mode `0600`; writes fsync both file and directory. The tool
rejects symlinks and unsafe state. `logout` safely removes the atomic state (and
only safely removable legacy split remnants), with no Duo network call.

## Output and exit status

Human and `--json` output expose only terminal-safe useful metadata: exact ID,
status, service/application, account/username, host/location, received/expiry
time when supplied, explicit verification semantic, and public fingerprint.
JSON has `schemaVersion: 1`. Errors are on stderr: success `0`, runtime/auth/
not-found `1`, and usage `2`. The tool does not log raw payloads, transaction
URLs, device keys, activation values, cookies, codes, headers, or state content.

## Setup lifecycle — stop before pairing unless authorized

The external-tool convention requires authentication lifecycle commands:

```bash
duo login --qr FILE
duo logout
```

`login --qr FILE` performs a **real** pairing if invoked. It does not prompt for
credentials and refuses existing state. Before any network activity it accepts
only the pinned calsh-documented canonical normal-Duo host form
`api-XXXXXXXX.duosecurity.com` (eight lower-case hex characters); arbitrary
domains, userinfo, ports, IPs, localhost, queries, fragments, redirects, and
environment proxies are rejected/disabled. Duo Federal is not enabled because
the pinned source does not document its canonical activation/API host form.

The QR decoder is resolved to a trusted absolute regular root/current-user-owned
file that is not group/world writable; QR input must be private and decode to
exactly one ASCII activation symbol. Do not invoke this command without explicit
tenant approval for the separate local device.

## Attribution, tests, and limitations

The subset in `src/duo_cli/real_backend.py` is a small MIT adaptation of
[`Yubo-Cao/calsh`](https://github.com/Yubo-Cao/calsh), pinned to commit
[`84b048c9a8a8ccd21bae0558f520a548907d11e7`](https://github.com/Yubo-Cao/calsh/commit/84b048c9a8a8ccd21bae0558f520a548907d11e7).
It does **not** wrap calsh's `duo approve`, `approve-once`, `watch`,
`duo-approve`, daemon, or broad `duo-headless` CLI. See [NOTICE](NOTICE),
[LICENSE](LICENSE), and [SECURITY.md](SECURITY.md).

All tests use fakes, fixtures, and HTTP/session spies: no test decodes a real QR,
contacts Duo, reads a real account, or uses local enrollment state.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
bash -n bin/duo
git diff --check
```
