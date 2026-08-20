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
- Never automate, schedule, daemonize, or wrap `duo approve`.

## Transport and setup containment

The adapter accepts only calsh-documented canonical normal-Duo API hosts,
rejects arbitrary URL components/hosts, disables redirects and environment proxy
settings (`Session.trust_env = False`), and validates every signing input as safe
ASCII before signing. QR setup resolves a trusted absolute decoder binary and
requires exactly one private QR symbol. Real enrollment remains unsupported by
Duo and must not be attempted without separately documented tenant authorization.

## Sensitive values deliberately excluded from output

The codebase has no logging facility. It does not render exception reprs or raw
payloads, protocol URLs, private keys, account keys, activation codes/QR data,
cookies, signed headers, or Verified Push codes. Terminal rendering is bounded
printable ASCII; untrusted Unicode/control data is escaped. Report defects using
the offline fixture style in `tests/`, never live state or protocol traces.
