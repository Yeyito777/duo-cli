"""Typed, terminal-safe boundary between the private protocol and the CLI."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import hmac
import json
import re
import secrets
from typing import Any


# The private protocol is not a general URL/header transport. This is the
# documented unreserved RFC 3986 token grammar we accept for an URGID; it is
# deliberately stricter than "opaque string" so it is safe both as one encoded
# path segment and as the txId header value.
URGID_RE = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
CODE_RE = re.compile(r"^[A-Za-z0-9._~-]{1,64}$")
_PROCESS_COMPARISON_KEY = secrets.token_bytes(32)


class VerificationMode(StrEnum):
    """Only explicit protocol semantics are approvable."""

    ORDINARY = "ordinary-push"
    CODE_REQUIRED = "code-required"
    UNKNOWN = "unknown"


def sanitize_text(value: object, *, limit: int = 256) -> str | None:
    """Render untrusted metadata as bounded printable ASCII only.

    This prevents control sequences, bidirectional controls, and arbitrary
    Unicode terminal behavior. Backslash escapes are display text, not decoded
    terminal controls. Opaque IDs never pass through this function.
    """
    if value is None or not isinstance(value, (str, int, float, bool)):
        return None
    rendered: list[str] = []
    for character in str(value):
        point = ord(character)
        if 0x20 <= point <= 0x7E:
            rendered.append(character)
        elif point <= 0xFFFF:
            rendered.append(f"\\u{point:04x}")
        else:
            rendered.append(f"\\U{point:08x}")
    text = "".join(rendered)
    if not text:
        return None
    return text[:limit]


def _normalise_name(name: object) -> str:
    # Attribute names are never rendered and only ASCII alphanumerics count.
    return "".join(ch for ch in str(name).casefold() if ch.isascii() and ch.isalnum())


def flatten_attributes(value: object) -> dict[str, object]:
    """Adapt observed/documented attribute shapes without retaining raw data.

    Duo's current U of T payload groups attributes as nested ``[[name, value]]``
    pairs, while pinned clients also document dictionaries and lists of
    ``{"name": ..., "value": ...}`` objects. Traversal is deliberately bounded.
    """
    result: dict[str, object] = {}

    def visit(item: object, depth: int) -> None:
        if depth > 6 or len(result) >= 64:
            return
        if isinstance(item, dict):
            name = item.get("name", item.get("key"))
            if name is not None and "value" in item:
                result[str(name)] = item["value"]
                return
            for key, child in list(item.items())[:64]:
                if isinstance(child, (dict, list, tuple)):
                    visit(child, depth + 1)
                else:
                    result[str(key)] = child
            return
        if isinstance(item, (list, tuple)):
            if len(item) == 2 and isinstance(item[0], str) and not isinstance(item[1], (dict, list, tuple)):
                result[item[0]] = item[1]
                return
            for child in list(item)[:64]:
                visit(child, depth + 1)

    visit(value, 0)
    return result


def _first(attrs: dict[str, object], *names: str) -> str | None:
    wanted = {_normalise_name(name) for name in names}
    for key, value in attrs.items():
        if _normalise_name(key) in wanted:
            result = sanitize_text(value)
            if result is not None:
                return result
    return None


def _top(raw: dict[str, Any], *names: str) -> str | None:
    for name in names:
        if name in raw:
            result = sanitize_text(raw[name])
            if result is not None:
                return result
    return None


_CODE_KEYS = {
    "code",
    "verificationcode",
    "pin",
    "stepupcode",
    "numericalcode",
    "ovrcode",
    "displaycode",
}
_ORDINARY_TYPE_VALUES = {"push", "ordinary_push", "ordinary-push"}
_CODE_TYPE_VALUES = {"verified_push", "verified-push", "verifiedpush", "step_up", "step-up"}


def _known_code(value: object) -> str | None:
    # This value remains only in the frozen request object/process memory. It is
    # neither rendered nor used to derive the public fingerprint.
    return value if isinstance(value, str) and CODE_RE.fullmatch(value) else None


def _verification_mode(raw: dict[str, Any], attrs: dict[str, object]) -> tuple[VerificationMode, str | None]:
    """Classify only positive, explicit ordinary/code-required markers.

    calsh documents code-bearing attributes and ``verified_push_info`` /
    ``step_up_code_info`` but does not document an implicit "no marker means
    ordinary" rule. This client therefore requires an explicit ``False``
    verified/required flag or a documented-type value for ordinary push. Any
    absent, malformed, conflicting, or unfamiliar semantic marker is UNKNOWN
    and cannot be approved.
    """
    modes: set[VerificationMode] = set()
    code: str | None = None

    for key in ("verified_push", "requires_code", "verification_required"):
        if key not in raw:
            continue
        value = raw[key]
        if type(value) is bool:
            modes.add(VerificationMode.CODE_REQUIRED if value else VerificationMode.ORDINARY)
        else:
            # A present but non-boolean semantic marker is not interpretable.
            return VerificationMode.UNKNOWN, None

    for key in ("transaction_type", "push_type"):
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, str):
            return VerificationMode.UNKNOWN, None
        normalized = value.casefold()
        if normalized in _ORDINARY_TYPE_VALUES:
            modes.add(VerificationMode.ORDINARY)
        elif normalized in _CODE_TYPE_VALUES:
            modes.add(VerificationMode.CODE_REQUIRED)
        else:
            return VerificationMode.UNKNOWN, None

    for key, value in attrs.items():
        if _normalise_name(key) in _CODE_KEYS:
            modes.add(VerificationMode.CODE_REQUIRED)
            code = _known_code(value)

    for key in ("step_up_code_info", "verified_push_info", "display_data"):
        if key not in raw:
            continue
        modes.add(VerificationMode.CODE_REQUIRED)
        info = raw[key]
        if isinstance(info, dict):
            for item in ("correct_answer", "code", "value", "answer"):
                candidate = _known_code(info.get(item))
                if candidate is not None:
                    code = candidate
                    break
        else:
            candidate = _known_code(info)
            if candidate is not None:
                code = candidate

    # The currently observed U of T traditional-prompt payload marks an
    # ordinary login notification with this exact combination. ``type=Login``
    # is display context, not a generic transaction semantic. We recognize it
    # only when no positive code-required marker above was present; verified
    # pushes carrying ``step_up_code_info`` therefore remain code-required.
    if not modes:
        if (
            raw.get("type") == "Login"
            and raw.get("phone_notification_type") == "visible_notification"
            and type(raw.get("is_proximity_push")) is bool
            and type(raw.get("is_strict_proximity_push")) is bool
        ):
            modes.add(VerificationMode.ORDINARY)

    if len(modes) != 1:
        return VerificationMode.UNKNOWN, None
    return modes.pop(), code


def _parse_expiry(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        numeric = float(value)
        if numeric > 10_000_000_000:
            numeric /= 1000
        return datetime.fromtimestamp(numeric, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        pass
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc) if parsed.tzinfo else None


@dataclass(frozen=True)
class PendingRequest:
    """Sanitized display context plus private in-memory comparison material."""

    request_id: str
    service: str | None
    account: str | None
    host: str | None
    location: str | None
    received_at: str | None
    expires_at: str | None
    status: str
    verification: VerificationMode
    _known_code: str | None = None

    @classmethod
    def from_transaction(cls, raw: object) -> "PendingRequest":
        if not isinstance(raw, dict):
            raise ValueError("transaction is not an object")
        request_id = raw.get("urgid")
        if not isinstance(request_id, str) or not URGID_RE.fullmatch(request_id):
            raise ValueError("transaction urgid is outside the safe documented grammar")
        attrs = flatten_attributes(raw.get("attributes"))
        verification, known_code = _verification_mode(raw, attrs)
        status = (_top(raw, "status", "state") or "pending").casefold()
        return cls(
            request_id=request_id,
            service=_first(attrs, "Application", "Service", "App", "Integration")
            or _top(raw, "application", "service", "app", "summary"),
            account=_first(attrs, "Username", "Account", "User") or _top(raw, "username", "account", "user"),
            host=_first(attrs, "Host", "Hostname", "Server", "IP Address") or _top(raw, "host", "hostname", "server"),
            location=_first(attrs, "Location", "Approximate Location", "Geo") or _top(raw, "location", "geo"),
            received_at=_first(attrs, "Time", "Received At", "Received") or _top(raw, "received_at", "received", "time"),
            expires_at=_first(attrs, "Expires At", "Expires", "Expiration", "Expiry") or _top(raw, "expires_at", "expires", "expiration", "expiry"),
            status=status,
            verification=verification,
            _known_code=known_code,
        )

    @property
    def requires_code(self) -> bool:
        return self.verification is VerificationMode.CODE_REQUIRED

    @property
    def is_pending(self) -> bool:
        return self.status in {"", "pending", "waiting", "awaiting"}

    @property
    def is_expired(self) -> bool:
        expiry = _parse_expiry(self.expires_at)
        return expiry is not None and expiry <= datetime.now(timezone.utc)

    def _public_fields(self) -> dict[str, object]:
        result: dict[str, object] = {"id": self.request_id, "status": self.status, "verification": self.verification.value}
        optional = {
            "service": self.service,
            "account": self.account,
            "host": self.host,
            "location": self.location,
            "receivedAt": self.received_at,
            "expiresAt": self.expires_at,
        }
        result.update({key: value for key, value in optional.items() if value is not None})
        return result

    @property
    def fingerprint(self) -> str:
        """Public review token: deliberately independent of any challenge code."""
        encoded = json.dumps(self._public_fields(), sort_keys=True, separators=(",", ":")).encode("ascii")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    @property
    def comparison_token(self) -> bytes:
        """Private process-local comparison token, never included in output."""
        private = dict(self._public_fields())
        private["knownCode"] = self._known_code
        encoded = json.dumps(private, sort_keys=True, separators=(",", ":")).encode("ascii")
        return hmac.digest(_PROCESS_COMPARISON_KEY, encoded, "sha256")

    def same_private_context(self, other: "PendingRequest") -> bool:
        return hmac.compare_digest(self.comparison_token, other.comparison_token)

    def to_dict(self, *, include_fingerprint: bool = True) -> dict[str, object]:
        result = self._public_fields()
        if include_fingerprint:
            result["fingerprint"] = self.fingerprint
        return result
