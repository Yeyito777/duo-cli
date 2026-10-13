"""Safe command surface for viewing and exactly approving one Duo request."""

from __future__ import annotations

import argparse
import hmac
import os
from pathlib import Path
import re
import sys
import time
from typing import Callable, Sequence

from .backend import DuoBackend
from .errors import (
    AlreadyHandledError,
    AmbiguousRequestError,
    ContextChangedError,
    DuoCliError,
    RequestNotFoundError,
    ProtocolSemanticsError,
    UsageError,
    VerifiedPushError,
)
from . import own_login
from .models import CODE_RE, URGID_RE, PendingRequest, VerificationMode
from .real_backend import RealDuoBackend
from .render import emit_json, render_request, render_requests
from .state import ExclusiveStateLock, StateDirectory, StatePaths, default_state_dir


BackendFactory = Callable[[StateDirectory], DuoBackend]
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="duo",
        description="View pending requests and approve exactly one request on an explicitly enrolled local Duo device.",
    )
    parser.add_argument(
        "--state-dir",
        metavar="DIR",
        default=os.environ.get("DUO_STATE_DIR", str(default_state_dir())),
        help="private tool-local state directory (default: DUO_STATE_DIR or this tool's config/)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    requests = sub.add_parser("requests", help="list pending requests (read-only)")
    requests.add_argument("--json", action="store_true", help="emit schemaVersion 1 JSON")

    request = sub.add_parser("request", help="show one pending request by exact opaque ID (read-only)")
    request.add_argument("request_id", metavar="REQUEST_ID")
    request.add_argument("--json", action="store_true", help="emit schemaVersion 1 JSON")

    approve = sub.add_parser("approve", help="approve exactly one current request by exact opaque ID")
    approve.add_argument("request_id", metavar="REQUEST_ID")
    approve.add_argument(
        "--confirm-fingerprint",
        metavar="FINGERPRINT",
        required=True,
        help="exact code-independent fingerprint previously returned by `duo request REQUEST_ID`",
    )
    approve.add_argument("--code-stdin", action="store_true", help="read required Verified Push code as exact bounded UTF-8 from stdin")
    approve.add_argument("--json", action="store_true", help="emit schemaVersion 1 JSON")

    login = sub.add_parser(
        "login",
        help="SETUP ONLY: explicitly pair a separately authorized local emulated device from a QR image",
    )
    login.add_argument("--qr", metavar="FILE", required=True, help="local activation QR image; it is never echoed")
    login.add_argument("--json", action="store_true", help="emit schemaVersion 1 JSON")

    own = sub.add_parser(
        "own-login",
        help="utmail/quercus only: approve the Verified Push of a U of T login that tool itself started",
    )
    own_sub = own.add_subparsers(dest="own_action", required=True)
    own_begin = own_sub.add_parser("begin", help="start a short own-login ticket (cap, lock, no pending requests)")
    own_begin.add_argument("--caller", required=True, choices=sorted(own_login.CALLERS))
    own_begin.add_argument("--json", action="store_true", help="emit schemaVersion 1 JSON")
    own_approve = own_sub.add_parser(
        "approve",
        help="approve the single matching request; code from the caller's own Duo page on stdin; account from UOFT_UTORID",
    )
    own_approve.add_argument("ticket", metavar="TICKET")
    own_approve.add_argument("--json", action="store_true", help="emit schemaVersion 1 JSON")
    own_end = own_sub.add_parser("end", help="release the ticket and record the login outcome")
    own_end.add_argument("ticket", metavar="TICKET")
    own_end.add_argument("--outcome", required=True, choices=["completed", "failed"])
    own_end.add_argument("--json", action="store_true", help="emit schemaVersion 1 JSON")

    logout = sub.add_parser("logout", help="remove local enrollment state only; makes no Duo network call")
    logout.add_argument("--json", action="store_true", help="emit schemaVersion 1 JSON")
    return parser


def _validate_exact_id(request_id: str) -> str:
    # IDs are opaque and not normalized: no trim, case fold, prefix matching, or
    # wildcard interpretation is ever performed.
    if not isinstance(request_id, str) or not URGID_RE.fullmatch(request_id):
        raise UsageError("REQUEST_ID must use the documented exact ASCII unreserved-ID grammar.")
    return request_id


def _validate_fingerprint(value: str) -> str:
    if not isinstance(value, str) or not FINGERPRINT_RE.fullmatch(value):
        raise UsageError("--confirm-fingerprint must be one exact sha256: fingerprint returned by `duo request`.")
    return value


def _read_code_stdin() -> str:
    """Read one exact bounded code only after code-required semantics are proven."""
    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        raise VerifiedPushError("Verified Push requires UTF-8 code bytes on stdin; retry with `--code-stdin` and a pipe.")
    raw = stream.read(65)
    if not raw or len(raw) > 64:
        raise VerifiedPushError("Verified Push code stdin must contain one non-empty value of at most 64 bytes, without a newline.")
    try:
        code = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerifiedPushError("Verified Push code stdin must be exact UTF-8.") from exc
    if not CODE_RE.fullmatch(code):
        raise VerifiedPushError("Verified Push code stdin has unsupported characters; do not trim or retry with an argv code.")
    return code


def _select_exact(transactions: Sequence[PendingRequest], request_id: str) -> PendingRequest:
    matches = [item for item in transactions if item.request_id == request_id]
    if len(matches) > 1:
        raise AmbiguousRequestError(
            "Duo returned multiple pending entries with that exact ID. Refusing to choose one; no approval was sent."
        )
    if not matches:
        raise RequestNotFoundError("Request ID is not currently pending. Run `duo requests` and use an exact listed ID.")
    selected = matches[0]
    if not selected.is_pending:
        raise AlreadyHandledError("Request ID is already handled or no longer pending; refusing an idempotent re-approval.")
    if selected.is_expired:
        raise AlreadyHandledError("Request ID has expired; refusing approval.")
    return selected


def _approval_mode_for(request: PendingRequest, code_stdin: bool) -> bool:
    if request.verification is VerificationMode.UNKNOWN:
        raise ProtocolSemanticsError(
            "This transaction has no positive ordinary-push or code-required protocol discriminator. "
            "Refusing approval; no reply was sent."
        )
    if request.verification is VerificationMode.ORDINARY:
        if code_stdin:
            raise UsageError("--code-stdin is only accepted for an explicitly code-required Verified Push.")
        return False
    if not code_stdin:
        raise VerifiedPushError(
            "This request requires a Verified Push code. Read it from the original sign-in flow and retry "
            "with `duo approve REQUEST_ID --confirm-fingerprint FINGERPRINT --code-stdin < code-file`; "
            "the client will not guess one."
        )
    return True


def _verify_code(request: PendingRequest, supplied_code: str) -> None:
    if request._known_code is not None and not hmac.compare_digest(supplied_code, request._known_code):
        raise VerifiedPushError(
            "The supplied Verified Push code does not match the selected request context. Recheck the original "
            "sign-in flow; no approval was sent."
        )


def _run_requests(args: argparse.Namespace, backend: DuoBackend) -> None:
    backend.load()
    pending = [item for item in backend.transactions() if item.is_pending and not item.is_expired]
    if args.json:
        # A review fingerprint is intentionally issued only by the one-request
        # detail view, so an approval flow is `requests` -> `request` -> approve.
        emit_json({"requests": [item.to_dict(include_fingerprint=False) for item in pending]})
    else:
        print(render_requests(pending))


def _run_request(args: argparse.Namespace, backend: DuoBackend) -> None:
    request_id = _validate_exact_id(args.request_id)
    backend.load()
    selected = _select_exact(backend.transactions(), request_id)
    if args.json:
        emit_json({"request": selected.to_dict()})
    else:
        print(render_request(selected))


def _run_approve(args: argparse.Namespace, backend: DuoBackend) -> None:
    request_id = _validate_exact_id(args.request_id)
    confirmed_fingerprint = _validate_fingerprint(args.confirm_fingerprint)
    backend.load()

    # First complete read/renderable snapshot.  It deliberately precedes the
    # decisive read so a stale, changed, expired, or duplicate request cannot be
    # approved just because a caller knew its ID earlier.
    first = _select_exact(backend.transactions(), request_id)
    if not hmac.compare_digest(confirmed_fingerprint, first.fingerprint):
        raise ContextChangedError(
            "The supplied review fingerprint does not match the current request context. Run `duo request REQUEST_ID` "
            "again; no approval was sent."
        )
    requires_code = _approval_mode_for(first, args.code_stdin)
    # Human callers see the fingerprinted context before the decisive refetch
    # and the one permitted reply. JSON keeps one valid schema-versioned object
    # and carries the same context in its eventual `approved` field.
    if not args.json:
        print(render_request(first), flush=True)

    approval_code = _read_code_stdin() if requires_code else None
    if approval_code is not None:
        _verify_code(first, approval_code)

    # Decisive refetch while the process-wide state lock remains held. The
    # public review fingerprint is code-independent; an unrendered process-local
    # comparison token additionally detects a changed challenge code.
    second = _select_exact(backend.transactions(), request_id)
    if not hmac.compare_digest(confirmed_fingerprint, second.fingerprint) or not first.same_private_context(second):
        raise ContextChangedError(
            "Request context changed between safety reads. Inspect `duo request REQUEST_ID` again; no approval was sent."
        )
    if _approval_mode_for(second, args.code_stdin):
        assert approval_code is not None
        _verify_code(second, approval_code)

    # This is the only ordinary mutation in v1: one direct internal
    # Duo.reply(urgid, "approve", code=...) call for the selected exact ID.
    backend.reply(second.request_id, "approve", code=approval_code)
    if args.json:
        emit_json({"approved": second.to_dict()})
    else:
        print(f"Approved. Request ID: {second.request_id}")


def _run_own_login(args: argparse.Namespace, state: StateDirectory, backend_factory: BackendFactory) -> None:
    if args.own_action == "end":
        removed = own_login.end(state, args.ticket, args.outcome, now=time.time())
        if args.json:
            emit_json({"ownLogin": {"ended": True, "ticketReleased": removed}})
        else:
            print("Own-login ended.")
        return
    backend = backend_factory(state)
    if args.own_action == "begin":
        result = own_login.begin(state, backend, args.caller, now=time.time())
        if args.json:
            emit_json({"ownLogin": result})
        else:
            print(f"Ticket: {result['ticket']}")
        return
    approved = own_login.approve(
        state,
        backend,
        args.ticket,
        read_code=_read_code_stdin,
        verify_code=_verify_code,
    )
    if args.json:
        emit_json({"approved": approved.to_dict()})
    else:
        print(f"Approved own login. Request ID: {approved.request_id}")


def _run_login(args: argparse.Namespace, backend: DuoBackend) -> None:
    qr_file = Path(args.qr).expanduser()
    backend.login_from_qr(qr_file)
    if args.json:
        emit_json({"login": {"status": "enrolled"}})
    else:
        print("Local emulated Duo device enrolled.")


def _run_logout(args: argparse.Namespace, state: StateDirectory) -> None:
    removed = state.remove_enrollment()
    if args.json:
        emit_json({"logout": {"status": "logged-out", "removedLocalState": removed}})
    else:
        print("Logged out." if removed else "Logged out. No local enrollment state was present.")


def main(argv: Sequence[str] | None = None, *, backend_factory: BackendFactory = RealDuoBackend) -> int:
    args = _parser().parse_args(argv)
    paths = StatePaths(Path(args.state_dir))
    try:
        # There is one non-blocking exclusive lock for every subcommand,
        # including reads and setup lifecycle actions.
        wait = 15.0 if args.command == "own-login" else 0.0
        with ExclusiveStateLock(paths, wait_seconds=wait) as state:
            if args.command == "own-login":
                _run_own_login(args, state, backend_factory)
                return 0
            if args.command == "logout":
                _run_logout(args, state)
                return 0
            backend = backend_factory(state)
            if args.command == "requests":
                _run_requests(args, backend)
            elif args.command == "request":
                _run_request(args, backend)
            elif args.command == "approve":
                _run_approve(args, backend)
            elif args.command == "login":
                _run_login(args, backend)
            else:  # argparse's required subcommand check makes this defensive.
                raise UsageError("Unknown command.")
    except DuoCliError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2 if isinstance(exc, UsageError) else 1
    except Exception:
        # Never expose exception reprs: they may contain protocol material,
        # paths, or URL fragments. A post attempt can have an unknown outcome.
        print("Error: Unexpected internal failure; operation outcome may be unknown. Inspect Duo before retrying.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
