"""The one narrow automation exception: approving a tool's own U of T login.

`utmail` and `quercus` may start an unattended U of T weblogin when their
persistent session has expired. They call ``begin`` before opening the login
page, then ``approve`` with the Verified Push code read from their own Duo page.
Approval happens only when every check below passes; anything unexpected is a
refusal and the calling tool falls back to its normal "session required" error.
See SECURITY.md ("Own-login exception").
"""

from __future__ import annotations

from datetime import datetime, timezone
import hmac
import ipaddress
import json
import os
import re
import secrets
import time
from typing import Callable, Sequence

from .backend import DuoBackend
from .errors import BusyError, DuoCliError, UsageError
from .models import PendingRequest, VerificationMode, _parse_expiry
from .state import StateDirectory


CALLERS = frozenset({"utmail", "quercus"})
SERVICES = frozenset({"Weblogin Standard", "Azure AD Standard"})
ACCOUNT_ENV = "UOFT_UTORID"
DAILY_CAP = 6
TICKET_TTL_SECONDS = 180
REQUEST_WAIT_SECONDS = 20
RECEIVED_SKEW_SECONDS = 30
TICKET_FILE = "own-login-ticket.json"
AUDIT_FILE = "own-login-audit.jsonl"
PUBLIC_IP_URL = "https://api.ipify.org"
TICKET_RE = re.compile(r"^[0-9a-f]{32}$")
ACCOUNT_RE = re.compile(r"^[a-z0-9]{1,32}$")
_MAX_AUDIT_BYTES = 4_000_000


class OwnLoginRefused(DuoCliError):
    """A check failed; no approval was sent."""


def fetch_public_ip() -> str:
    """This machine's public IPv4 address, as Duo sees the login's origin."""
    try:
        import requests
    except ImportError as exc:
        raise DuoCliError("Duo runtime dependencies are missing.") from exc
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.get(PUBLIC_IP_URL, timeout=(5, 5), allow_redirects=False)
        text = response.text.strip() if response.status_code == 200 else ""
    except requests.RequestException:
        text = ""
    finally:
        session.close()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        raise OwnLoginRefused("Could not determine this machine's public IP address; refusing approval.") from None


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def _audit(state: StateDirectory, now: float, event: str, **fields: object) -> None:
    # Append-only: entries are never rewritten. No code, secret, or raw payload
    # is ever passed here.
    entry = {"time": _iso(now), "event": event, **{k: v for k, v in fields.items() if v is not None}}
    state.append_private_file(AUDIT_FILE, (json.dumps(entry, sort_keys=True) + "\n").encode("ascii"))


def attempts_in_last_day(state: StateDirectory, now: float) -> int:
    raw = state.read_private_file(AUDIT_FILE, limit=_MAX_AUDIT_BYTES) or b""
    count = 0
    for line in raw.splitlines():
        try:
            entry = json.loads(line)
            when = datetime.fromisoformat(entry["time"]).timestamp()
        except (ValueError, KeyError, TypeError):
            continue
        if entry.get("event") == "begin" and now - when < 86_400:
            count += 1
    return count


def _load_ticket(state: StateDirectory) -> dict | None:
    raw = state.read_private_file(TICKET_FILE, limit=4096)
    if raw is None:
        return None
    try:
        ticket = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(ticket, dict) or not isinstance(ticket.get("startedAt"), (int, float)):
        return None
    return ticket


def _live(ticket: dict | None, now: float) -> bool:
    return ticket is not None and 0 <= now - ticket["startedAt"] <= TICKET_TTL_SECONDS


def _pending(backend: DuoBackend) -> list[PendingRequest]:
    return [item for item in backend.transactions() if item.is_pending and not item.is_expired]


def begin(state: StateDirectory, backend: DuoBackend, caller: str, *, now: float) -> dict:
    """Open a short login ticket: the cap, lock, and clean-slate checks."""
    if caller not in CALLERS:
        raise UsageError("own-login is only available to utmail and quercus.")
    if _live(_load_ticket(state), now):
        raise BusyError("Another own-login is in progress; retry after it finishes.")
    if attempts_in_last_day(state, now) >= DAILY_CAP:
        _audit(state, now, "refused", caller=caller, reason="daily cap reached")
        raise OwnLoginRefused(f"Daily own-login cap ({DAILY_CAP} per 24h) reached; log in manually.")
    backend.load()
    if _pending(backend):
        _audit(state, now, "refused", caller=caller, reason="requests already pending")
        raise OwnLoginRefused("Duo requests are already pending; refusing to start an own-login.")
    ticket = {"id": secrets.token_hex(16), "caller": caller, "startedAt": now}
    state.write_private_file(TICKET_FILE, json.dumps(ticket).encode("ascii"))
    _audit(state, now, "begin", caller=caller, ticket=ticket["id"])
    return {"ticket": ticket["id"], "expiresAt": _iso(now + TICKET_TTL_SECONDS)}


def _check(request: PendingRequest, ticket: dict, account: str, public_ip: Callable[[], str]) -> None:
    if request.service not in SERVICES:
        raise OwnLoginRefused("Pending request is not for an allowed U of T login service.")
    owner = (request.account or "").split(" (", 1)[0].strip().casefold()
    if owner != account:
        raise OwnLoginRefused("Pending request is for a different account.")
    received = _parse_expiry(request.received_at)
    if received is None or received.timestamp() < ticket["startedAt"] - RECEIVED_SKEW_SECONDS:
        raise OwnLoginRefused("Pending request did not appear after this login began.")
    if request.verification is not VerificationMode.CODE_REQUIRED:
        raise OwnLoginRefused("Pending request is not a Verified Push; refusing approval.")
    if request.host != public_ip():
        raise OwnLoginRefused("Pending request did not come from this machine's public IP.")


def approve(
    state: StateDirectory,
    backend: DuoBackend,
    ticket_id: str,
    *,
    read_code: Callable[[], str],
    verify_code: Callable[[PendingRequest, str], None],
    now: Callable[[], float] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    public_ip: Callable[[], str] | None = None,
    environ: dict[str, str] | None = None,
) -> PendingRequest:
    """Approve exactly the one Verified Push belonging to this ticket's login."""
    now = now or time.time
    public_ip = public_ip or fetch_public_ip
    if not TICKET_RE.fullmatch(ticket_id):
        raise UsageError("TICKET must be the value printed by `duo own-login begin`.")
    ticket = _load_ticket(state)
    started = now()
    if ticket is None or not hmac.compare_digest(str(ticket.get("id", "")), ticket_id):
        raise OwnLoginRefused("No matching own-login ticket; no approval was sent.")
    caller = ticket.get("caller")
    try:
        if not _live(ticket, started):
            raise OwnLoginRefused("Own-login ticket expired; no approval was sent.")
        account = (environ if environ is not None else os.environ).get(ACCOUNT_ENV, "").strip().casefold()
        if not ACCOUNT_RE.fullmatch(account):
            raise OwnLoginRefused(f"{ACCOUNT_ENV} must name the account the caller logged in as.")
        backend.load()
        deadline = min(started + REQUEST_WAIT_SECONDS, ticket["startedAt"] + TICKET_TTL_SECONDS)
        pending: Sequence[PendingRequest] = _pending(backend)
        while not pending and now() < deadline:
            sleep(2.0)
            pending = _pending(backend)
        if len(pending) != 1:
            raise OwnLoginRefused(f"Expected exactly one pending Duo request, found {len(pending)}.")
        first = pending[0]
        _check(first, ticket, account, public_ip)
        code = read_code()
        verify_code(first, code)
        # Decisive refetch, as in `duo approve`: the request must be unchanged.
        second = _pending(backend)
        if len(second) != 1 or second[0].request_id != first.request_id or not first.same_private_context(second[0]):
            raise OwnLoginRefused("Pending request changed between safety reads; no approval was sent.")
        backend.reply(first.request_id, "approve", code=code)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, DuoCliError) else "unexpected internal failure"
        _audit(state, now(), "refused", caller=caller, ticket=ticket_id, reason=reason)
        state.remove_private_file(TICKET_FILE)
        raise
    _audit(
        state,
        now(),
        "approved",
        caller=caller,
        ticket=ticket_id,
        service=first.service,
        host=first.host,
        requestId=first.request_id,
    )
    # One approval per ticket; the ticket also stops acting as the login lock.
    state.remove_private_file(TICKET_FILE)
    return first


def end(state: StateDirectory, ticket_id: str, outcome: str, *, now: float) -> bool:
    """Release the login lock early and record how the login ended."""
    if not TICKET_RE.fullmatch(ticket_id):
        raise UsageError("TICKET must be the value printed by `duo own-login begin`.")
    ticket = _load_ticket(state)
    removed = False
    if ticket is not None and hmac.compare_digest(str(ticket.get("id", "")), ticket_id):
        removed = state.remove_private_file(TICKET_FILE)
    _audit(state, now, "end", caller=(ticket or {}).get("caller"), ticket=ticket_id, outcome=outcome)
    return removed
