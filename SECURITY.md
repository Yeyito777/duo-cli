# Security constraints

## Unsupported protocol and authorization

Duo has no official API for listing or approving Duo Mobile Push requests. This
tool speaks an unsupported private device protocol adapted from a pinned
third-party source. It can stop working or be rejected without notice. Use it
only after the account holder and applicable tenant/organization administrator
explicitly authorize a separately enrolled emulated device. It is never a way to
bypass authorization policy.

## Local enrollment is a high-value secret

`enrollment.json` contains the private key and account/device response fields
that identify the local emulated device. Anyone who obtains it may be able to
answer pushes for that device. This factor is weaker than a normal phone-based
Duo deployment: it lacks a distinct physical-device and biometric boundary.

Never use it on a shared/untrusted machine; put it in cloud sync, Git, tickets,
chat, shell history, or unencrypted backup; or relax its permissions. If exposed,
revoke the device through the authorized Duo administration process, then run
`duo logout` to remove local state.

All state operations use one verified directory FD opened with
`O_DIRECTORY|O_NOFOLLOW`, current-user ownership, directory mode `0700`,
regular non-symlink state/lock files mode `0600`, `*at`/`dir_fd` operations, and
file-plus-directory `fsync`. Enrollment is committed atomically as one file;
interrupted verified temporary files are cleaned safely. Every command holds one
non-blocking exclusive lock.

## Exact approval policy

- Review `duo request EXACT_ID` yourself, then provide its exact public
  fingerprint to `duo approve`. An ID or fingerprint does not prove a request is
  legitimate.
- IDs are restricted to an exact ASCII unreserved grammar and are never
  normalized, guessed, URL-decoded, prefix-matched, or interpreted as a
  wildcard. The backend validates again before creating an encoded path/header.
- The public fingerprint intentionally omits all Verified Push code material.
  A private process-memory comparison token catches changed code/context between
  reads without emitting a brute-forceable value.
- A transaction without a positive ordinary-push/code-required protocol marker
  is unknown and cannot be approved. Do not override this condition.
- Verified Push code is accepted only as bounded exact UTF-8 stdin with
  `--code-stdin`, after a positive code-required marker. It is never an argv
  parameter, output, log entry, state value, or public fingerprint input.
- Never automate, schedule, daemonize, or wrap `duo approve`. The only
  automated approval path is the own-login exception below.

## Own-login exception (approved by the owner, Oct 13 2026)

`duo own-login` lets exactly two callers, the `utmail` and `quercus` helper
tools, approve the Verified Push of a U of T login **they started themselves**
after their persistent session expired. Nothing else may call it: vimbrowser,
MarkUs, LibCal, other tools, and agents still use the manual
`request` → `approve` flow. The caller name is self-declared and is an audit
label, not authentication; the boundary is that only those two tools' code
invokes this command.

Flow and checks:

1. `own-login begin --caller utmail|quercus` runs before the tool opens the
   login page. It refuses if another own-login ticket is still live (this is the
   lock that keeps two tools from logging in at once), if the daily cap is
   reached, or if any Duo request is already pending. It writes a ticket (random
   ID, caller, start time) that lives at most 180 seconds.
2. `own-login approve TICKET` approves only when **all** of these hold:
   - the ticket matches and is younger than 180 seconds;
   - within 20 seconds there is **exactly one** pending, unexpired request;
   - its service is `Weblogin Standard` or `Azure AD Standard`;
   - its account is the UTORid in `UOFT_UTORID` (the account the caller just
     typed into weblogin);
   - its received time is no earlier than 30 seconds before the ticket began;
   - it is a code-required Verified Push;
   - its host equals this machine's public IP (fetched from
     `https://api.ipify.org`, no proxies or redirects, up to 3 tries; failure refuses);
   - the code on stdin (read by the caller from its own Duo page) matches any
     code Duo exposes, and the request is unchanged on a decisive refetch.

   Any failure sends no approval, consumes the ticket, and the caller reports
   its normal "session required" error. One approval per ticket.
3. `own-login end TICKET --outcome completed|failed` releases the ticket early.

Cap: at most 6 `begin`s (so at most 6 approvals) per rolling 24 hours.

Audit: every begin, approval, refusal, and end is appended to
`own-login-audit.jsonl` in the state directory (mode `0600`, append-only):
time, event, caller, ticket ID, and for approvals the service, host, and
request ID; refusals carry the sanitized reason. An approval whose request
broke in transit is logged as `unknown`, not `refused`: Duo may have applied
it. An `end` after a successful approval takes its caller from the ticket's
`begin` entry. Codes, passwords, and raw
payloads are never written.

## Transport and setup containment

The adapter accepts only calsh-documented canonical normal-Duo API hosts,
rejects arbitrary URL components/hosts, disables redirects and environment proxy
settings (`Session.trust_env = False`), and validates every signing input as safe
ASCII before signing. QR setup resolves a trusted absolute decoder binary and
requires exactly one private QR symbol. Real enrollment remains unsupported by
Duo and must not be attempted without separately documented tenant authorization.

## Sensitive values deliberately excluded from output

The codebase has no logging facility beyond the code-free own-login audit log.
It does not render exception reprs or raw payloads, protocol URLs, private keys,
account keys, activation codes/QR data, cookies, signed headers, or Verified Push
codes. Terminal rendering is bounded printable ASCII; untrusted Unicode/control
data is escaped. Report defects using the offline fixture style in `tests/`,
never live state or protocol traces.
