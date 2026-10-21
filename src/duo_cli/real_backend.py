"""Narrow, unsupported private-protocol adapter for one enrolled local device.

This is a limited MIT adaptation of ``bin/duo-headless`` in Yubo-Cao/calsh at
commit 84b048c9a8a8ccd21bae0558f520a548907d11e7. It retains only the needed
``Duo.load()``, ``Duo.transactions()``, and exact
``Duo.reply(urgid, "approve", code=...)`` mechanics. It intentionally omits
calsh's broad CLI, watch, daemon, notification, deny, passcode, and bulk
approver behavior. See NOTICE, README.md, and SECURITY.md.

No official Duo API provides these operations. This unsupported private protocol
must only be used for a separately enrolled device explicitly authorized by the
applicable account holder and tenant administrator.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import email.utils
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import urllib.parse
from typing import Any

from .errors import AuthenticationError, DuoCliError, OutcomeUnknownError
from .models import CODE_RE, URGID_RE, PendingRequest
from .state import StateDirectory


DEFAULT_DEVICE_NAME = "Exocortex local Duo device"
DUO_APP_VERSION = "4.107.0"
IOS_VERSION = "18.5"
IOS_BUILD = "22F76"
USER_AGENT = f"DuoMobileApp/{DUO_APP_VERSION} (arm64; iOS {IOS_VERSION}); Client: Foundation"

# calsh's pinned documentation identifies only api-XXXXXXXX.duosecurity.com
# (eight hexadecimal customer prefix). Duo Federal is deliberately unsupported
# here because it is not documented by the pinned source used for this adapter.
API_HOST_RE = re.compile(r"^api-[0-9a-f]{8}\.duosecurity\.com$")
MOBILE_HOST_RE = re.compile(r"^m-[0-9a-f]{8}\.duosecurity\.com$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~-]{1,512}$")
DATE_RE = re.compile(r"^[A-Za-z]{3}, [0-9]{2} [A-Za-z]{3} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [+-][0-9]{4}$")
MAX_QR_SYMBOL_BYTES = 1024


def _dependencies() -> tuple[Any, Any, Any, Any]:
    try:
        import requests
        from Crypto.Hash import SHA512
        from Crypto.PublicKey import RSA
        from Crypto.Signature import pkcs1_15
    except ImportError as exc:
        raise DuoCliError("Duo runtime dependencies are missing. Install requirements.lock in an isolated venv.") from exc
    return requests, SHA512, RSA, pkcs1_15


def validate_api_host(host: object) -> str:
    """Accept only the canonical normal-Duo API host documented by calsh."""
    if not isinstance(host, str) or not host.isascii() or not API_HOST_RE.fullmatch(host):
        raise AuthenticationError("Duo enrollment host is not a supported canonical Duo API host.")
    return host


def _validate_token(value: object, *, label: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or len(value) > maximum or not value.isascii() or not TOKEN_RE.fullmatch(value):
        raise AuthenticationError(f"Duo {label} contains unsupported characters.")
    return value


def _validate_code(value: object) -> str:
    if not isinstance(value, str) or not CODE_RE.fullmatch(value):
        raise DuoCliError("Verified Push code has unsupported characters.")
    return value


def _activation_params(pubkey_pem: str, device_name: str = DEFAULT_DEVICE_NAME) -> dict[str, str]:
    return {
        "customer_protocol": "1",
        "pubkey": pubkey_pem,
        "pkpush": "rsa-sha512",
        "app_id": "com.duosecurity.DuoMobile",
        "app_version": DUO_APP_VERSION,
        "ble_status": "allowed",
        "build_version": IOS_BUILD,
        "device_name": device_name,
        "full_disk_encryption": "true",
        "jailbroken": "false",
        "language": "en",
        "manufacturer": "Apple",
        "model": "arm64",
        "notification_status": "not_determined",
        "passcode_status": "true",
        "platform": "iOS",
        "region": "US",
        "security_patch_level": "",
        "touchid_status": "true",
        "version": IOS_VERSION,
    }


class Duo:
    """The small signed-request subset adapted from pinned calsh source."""

    def __init__(self, state: StateDirectory, *, session: Any | None = None):
        self.state = state
        self._session_value = session
        self.key: Any = None
        self.host: str | None = None
        self.akey: str | None = None
        self.pkey: str | None = None

    def _session(self) -> Any:
        if self._session_value is None:
            requests, _, _, _ = _dependencies()
            self._session_value = requests.Session()
        # Never inherit HTTP(S)_PROXY, netrc, CA bundle, or other environment
        # transport configuration for this private-authentication protocol.
        self._session_value.trust_env = False
        return self._session_value

    def load(self) -> None:
        """Load and validate the one atomic enrollment record through its dir FD."""
        try:
            record = json.loads(self.state.read_enrollment().decode("utf-8"))
            if not isinstance(record, dict) or record.get("schemaVersion") != 1:
                raise ValueError("schema")
            key_pem = record["privateKeyPem"]
            response = record["response"]
            if not isinstance(key_pem, str) or not key_pem.isascii() or not isinstance(response, dict):
                raise ValueError("shape")
            host = validate_api_host(response["host"])
            akey = _validate_token(response["akey"], label="account key")
            pkey = _validate_token(response["pkey"], label="public key ID")
            _, _, RSA, _ = _dependencies()
            key = RSA.import_key(key_pem.encode("ascii"))
        except (UnicodeDecodeError, ValueError, KeyError, TypeError, IndexError) as exc:
            raise AuthenticationError(
                "Local Duo enrollment state is unreadable or incomplete. Remove it with `duo logout` only "
                "if you intend to set up a new separately authorized device."
            ) from exc
        self.key, self.host, self.akey, self.pkey = key, host, akey, pkey

    def _validate_signing_inputs(self, method: str, path: str, when: str, params: dict[str, str]) -> None:
        if method not in {"GET", "POST"} or not isinstance(path, str) or not path.isascii():
            raise DuoCliError("Refusing malformed private-protocol signing input.")
        if path != "/push/v2/device/transactions" and not re.fullmatch(
            r"/push/v2/device/transactions/[A-Za-z0-9._~-]{1,128}", path
        ):
            raise DuoCliError("Refusing malformed private-protocol request path.")
        if not isinstance(when, str) or not DATE_RE.fullmatch(when):
            raise DuoCliError("Refusing malformed private-protocol request date.")
        validate_api_host(self.host)
        _validate_token(self.akey, label="account key")
        _validate_token(self.pkey, label="public key ID")
        for name, value in params.items():
            if not isinstance(name, str) or not name.isascii() or not re.fullmatch(r"[A-Za-z_]{1,64}", name):
                raise DuoCliError("Refusing malformed private-protocol parameter name.")
            if not isinstance(value, str) or not value.isascii() or len(value) > 1024 or not TOKEN_RE.fullmatch(value):
                raise DuoCliError("Refusing malformed private-protocol parameter value.")

    def _sign(self, method: str, path: str, when: str, params: dict[str, str]) -> str:
        """RSA-SHA512 signing adaptation of calsh's Duo._sign implementation."""
        self._validate_signing_inputs(method, path, when, params)
        _, SHA512, _, pkcs1_15 = _dependencies()
        assert self.key is not None and self.host is not None and self.pkey is not None
        # Duo canonicalizes form/query parameters by key before checking the
        # signature.  The ordinary transaction shapes happened to be inserted
        # in sorted order already, masking this requirement; Verified Push adds
        # code fields after pkpush and otherwise produces HTTP 401/40103.
        canonical_params = sorted(params.items())
        message = (
            when
            + "\n"
            + method
            + "\n"
            + self.host
            + "\n"
            + path
            + "\n"
            + urllib.parse.urlencode(canonical_params)
        ).encode("ascii")
        signature = pkcs1_15.new(self.key).sign(SHA512.new(message))
        token = base64.b64encode(signature).decode("ascii")
        return "Basic " + base64.b64encode((self.pkey + ":" + token).encode("ascii")).decode("ascii")

    def _response_json(self, response: Any, *, operation: str) -> dict[str, Any]:
        # Do not call raise_for_status: its message embeds a transaction URL.
        if not 200 <= response.status_code < 300:
            # Duo's ordinary error JSON has bounded public diagnostics such as a
            # numeric code and short message.  Surface only those allowlisted
            # scalar fields; never echo raw response text, headers, URLs, or
            # protocol payloads.
            detail = ""
            try:
                body = response.json()
            except (ValueError, TypeError):
                body = None
            if isinstance(body, dict):
                code = body.get("code")
                message = body.get("message")
                code_text = str(code) if isinstance(code, (int, str)) else ""
                message_text = message if isinstance(message, str) else ""
                if (
                    code_text.isascii()
                    and re.fullmatch(r"[A-Za-z0-9._~-]{1,32}", code_text)
                    and message_text.isascii()
                    and 1 <= len(message_text) <= 160
                    and all(character.isprintable() for character in message_text)
                ):
                    detail = f"; Duo code {code_text}: {message_text}"
            raise DuoCliError(
                f"Duo {operation} request was rejected (HTTP {response.status_code}{detail})."
            )
        try:
            body = response.json()
        except (ValueError, TypeError) as exc:
            raise DuoCliError(f"Duo {operation} returned an invalid response.") from exc
        if not isinstance(body, dict) or body.get("stat") != "OK":
            raise DuoCliError(f"Duo {operation} was not accepted.")
        return body

    def _request(self, method: str, path: str, params: dict[str, str], *, operation: str, txid: str | None = None) -> dict[str, Any]:
        assert self.host is not None
        validate_api_host(self.host)
        when = email.utils.format_datetime(datetime.datetime.now(datetime.timezone.utc))
        wire_params = dict(sorted(params.items()))
        headers = {
            "Authorization": self._sign(method, path, when, wire_params),
            "x-duo-date": when,
            "host": self.host,
            "User-Agent": USER_AGENT,
        }
        if txid is not None:
            if not URGID_RE.fullmatch(txid):
                raise DuoCliError("Refusing unsafe txId header value.")
            headers["txId"] = txid
        try:
            response = self._session().request(
                method,
                f"https://{self.host}{path}",
                params=wire_params if method == "GET" else None,
                data=wire_params if method == "POST" else None,
                headers=headers,
                timeout=15,
                allow_redirects=False,
                verify=True,
            )
        except Exception as exc:
            requests, _, _, _ = _dependencies()
            if operation == "approval":
                # The approval may have reached Duo before the connection broke.
                raise OutcomeUnknownError(
                    f"Duo {operation} request failed in transit; the approval may or may not have been applied. "
                    "Run `duo requests` before retrying."
                ) from exc
            if isinstance(exc, requests.RequestException):
                raise DuoCliError(f"Duo {operation} request failed; check connectivity and enrollment.") from exc
            raise DuoCliError(f"Duo {operation} transport failed.") from exc
        return self._response_json(response, operation=operation)

    def transactions(self) -> dict[str, Any]:
        if self.key is None:
            raise AuthenticationError("Local Duo device was not loaded.")
        assert self.akey is not None
        params = {"akey": self.akey, "fips_status": "1", "hsm_status": "true", "pkpush": "rsa-sha512"}
        return self._request("GET", "/push/v2/device/transactions", params, operation="transactions")

    def reply(self, urgid: str, answer: str, code: str | None = None) -> dict[str, Any]:
        """One exact approve request; all path/header inputs are strictly safe."""
        if answer != "approve":
            raise DuoCliError("This minimal client only permits an explicit approve reply.")
        if self.key is None:
            raise AuthenticationError("Local Duo device was not loaded.")
        if not isinstance(urgid, str) or not URGID_RE.fullmatch(urgid):
            raise DuoCliError("Refusing unsafe exact request ID.")
        assert self.akey is not None
        encoded_urgid = urllib.parse.quote(urgid, safe="")
        params = {"akey": self.akey, "answer": "approve", "fips_status": "1", "hsm_status": "true", "pkpush": "rsa-sha512"}
        if code is not None:
            code = _validate_code(code)
            # Compatibility parameter shape is retained from pinned calsh; the
            # caller supplies the code only via bounded stdin and it is never logged.
            params.update({"txid_code": code, "step_up_code": code, "pin_data": code, "verification_code": code})
        return self._request(
            "POST",
            "/push/v2/device/transactions/" + encoded_urgid,
            params,
            operation="approval",
            txid=urgid,
        )

    @staticmethod
    def _secure_regular_file(path: Path, *, label: str) -> Path:
        try:
            resolved = path.expanduser().resolve(strict=True)
            info = resolved.lstat()
        except OSError as exc:
            raise DuoCliError(f"Cannot securely access {label}.") from exc
        if not resolved.is_absolute() or not stat.S_ISREG(info.st_mode):
            raise DuoCliError(f"{label.capitalize()} must resolve to an absolute regular file.")
        allowed = {os.getuid()} if hasattr(os, "getuid") else set()
        if hasattr(os, "getuid"):
            allowed.add(0)
        if (allowed and info.st_uid not in allowed) or stat.S_IMODE(info.st_mode) & 0o022:
            raise DuoCliError(f"{label.capitalize()} must be root/current-user owned and not group/world writable.")
        return resolved

    def _trusted_qr_decoder(self) -> Path:
        candidate = shutil.which("zbarimg")
        if not candidate:
            raise DuoCliError("QR decoding requires zbarimg. Install it, then retry `duo login --qr FILE`.")
        return self._secure_regular_file(Path(candidate), label="QR decoder")

    def _decode_qr(self, qr_file: Path) -> str:
        # QR content is activation material. Require a private ordinary file and
        # never display it; the decoder path itself is independently trusted.
        try:
            input_info = qr_file.expanduser().lstat()
        except OSError as exc:
            raise DuoCliError("The supplied QR file cannot be read.") from exc
        if not stat.S_ISREG(input_info.st_mode) or stat.S_ISLNK(input_info.st_mode) or not _is_current_or_root(input_info):
            raise DuoCliError("The supplied QR path must be a current-user/root-owned regular file, not a symlink.")
        if stat.S_IMODE(input_info.st_mode) & 0o077:
            raise DuoCliError("The supplied QR file must not be group/world accessible.")
        decoder = self._trusted_qr_decoder()
        try:
            process = subprocess.run(
                [os.fspath(decoder), "--quiet", "--raw", "--", os.fspath(qr_file.expanduser())],
                capture_output=True,
                text=False,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DuoCliError("Could not decode the supplied QR file.") from exc
        symbols = [line for line in process.stdout.splitlines() if line]
        if process.returncode != 0 or len(symbols) != 1 or len(symbols[0]) > MAX_QR_SYMBOL_BYTES:
            raise DuoCliError("The supplied QR file must decode to exactly one usable Duo activation symbol.")
        try:
            return symbols[0].decode("ascii")
        except UnicodeDecodeError as exc:
            raise DuoCliError("The supplied QR does not contain ASCII activation data.") from exc

    def _parse_activation_code(self, raw: str) -> tuple[str, str]:
        """Strictly validate the two QR encodings documented by pinned calsh."""
        try:
            if raw.startswith(("http://", "https://")):
                parsed = urllib.parse.urlsplit(raw)
                if (
                    parsed.scheme != "https"
                    or parsed.username is not None
                    or parsed.password is not None
                    or parsed.port is not None
                    or parsed.query
                    or parsed.fragment
                    or parsed.hostname is None
                    or parsed.netloc != parsed.hostname
                    or not MOBILE_HOST_RE.fullmatch(parsed.hostname)
                ):
                    raise ValueError("activation URL")
                pieces = parsed.path.split("/")
                if len(pieces) != 3 or pieces[1] != "activate":
                    raise ValueError("activation path")
                code = pieces[2]
                host = "api-" + parsed.hostname[2:]
            else:
                if "://" in raw:
                    raise ValueError("unexpected URL")
                code, encoded_host = raw.split("-", 1)
                encoded_host += "=" * (-len(encoded_host) % 4)
                host = base64.b64decode(encoded_host, validate=True).decode("ascii")
            if not TOKEN_RE.fullmatch(code):
                raise ValueError("activation code")
            return code, validate_api_host(host)
        except (ValueError, UnicodeDecodeError, IndexError, binascii.Error) as exc:
            raise DuoCliError("The supplied QR does not contain a supported canonical Duo activation value.") from exc

    def activate_from_qr(self, qr_file: Path) -> None:
        """Explicit pairing only; save one atomic record only after server success."""
        self.state.assert_empty_for_enrollment()
        activation_code, host = self._parse_activation_code(self._decode_qr(qr_file))
        requests, _, RSA, _ = _dependencies()
        self.host = host
        self.key = RSA.generate(2048)
        public_key = self.key.publickey().export_key("PEM").decode("ascii")
        try:
            response = self._session().request(
                "POST",
                f"https://{host}/push/v2/activation/{urllib.parse.quote(activation_code, safe='')}",
                params=_activation_params(public_key),
                headers={"User-Agent": USER_AGENT},
                timeout=15,
                allow_redirects=False,
                verify=True,
            )
        except Exception as exc:
            if isinstance(exc, requests.RequestException):
                raise DuoCliError("Duo activation request failed; check connectivity and tenant authorization.") from exc
            raise DuoCliError("Duo activation transport failed.") from exc
        body = self._response_json(response, operation="activation")
        info = body.get("response")
        if not isinstance(info, dict):
            raise DuoCliError("Duo activation returned incomplete enrollment data.")
        try:
            returned_host = info.get("host", host)
            if returned_host != host:
                raise ValueError("host mismatch")
            record = {
                "schemaVersion": 1,
                "privateKeyPem": self.key.export_key("PEM").decode("ascii"),
                "response": {
                    "host": validate_api_host(returned_host),
                    "akey": _validate_token(info["akey"], label="account key"),
                    "pkey": _validate_token(info["pkey"], label="public key ID"),
                },
            }
            encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
        except (KeyError, TypeError, UnicodeEncodeError, ValueError) as exc:
            raise DuoCliError("Duo activation returned incomplete enrollment data.") from exc
        self.state.write_enrollment_atomic(encoded)


def _is_current_or_root(info: os.stat_result) -> bool:
    return not hasattr(os, "getuid") or info.st_uid in {os.getuid(), 0}


class RealDuoBackend:
    """Production implementation of the intentionally small backend boundary."""

    def __init__(self, state: StateDirectory):
        self.duo = Duo(state)

    def load(self) -> None:
        self.duo.load()

    def transactions(self) -> list[PendingRequest]:
        body = self.duo.transactions()
        response = body.get("response")
        raw_transactions = response.get("transactions") if isinstance(response, dict) else None
        if not isinstance(raw_transactions, list):
            raise DuoCliError("Duo transactions response was incomplete; no approval was sent.")
        try:
            return [PendingRequest.from_transaction(item) for item in raw_transactions]
        except ValueError as exc:
            raise DuoCliError("Duo returned a malformed transaction; no approval was sent.") from exc

    def reply(self, urgid: str, answer: str, code: str | None = None) -> None:
        self.duo.reply(urgid, answer, code=code)

    def login_from_qr(self, qr_file: Path) -> None:
        self.duo.activate_from_qr(qr_file)
