from __future__ import annotations

import base64
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.duo_cli.errors import AuthenticationError, DuoCliError
from src.duo_cli.models import PendingRequest, VerificationMode
from src.duo_cli.real_backend import Duo, validate_api_host
from src.duo_cli.state import ExclusiveStateLock, StatePaths


class FakeResponse:
    def __init__(self, status_code: int = 200, body: object | None = None):
        self.status_code = status_code
        self.body = {"stat": "OK", "response": {"transactions": []}} if body is None else body

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class SessionSpy:
    def __init__(self, responses: list[FakeResponse]):
        self.responses = responses
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        self.trust_env = True

    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.responses.pop(0)


class FakeRequests:
    class RequestException(Exception):
        pass


class FakeHash:
    messages: list[bytes] = []

    @classmethod
    def new(cls, message: bytes):
        cls.messages.append(message)
        return message


class FakeSigner:
    def sign(self, digest: bytes) -> bytes:
        return b"deterministic-signature"


class FakePkcs:
    @staticmethod
    def new(key: object) -> FakeSigner:
        return FakeSigner()


class ModelAndPrivateProtocolTests(unittest.TestCase):
    def fixture(self, *, code: str, verified: bool = True) -> PendingRequest:
        return PendingRequest.from_transaction(
            {
                "urgid": "opaque-id",
                "verified_push": verified,
                "attributes": {
                    "Application": "Portal\x1b[31m",
                    "Verification Code": code,
                    "Host": "portal.example.edu",
                },
                "raw_payload": {"cookie": "never exposed"},
            }
        )

    def test_public_fingerprint_is_code_independent_under_bruteforce_regression(self) -> None:
        baseline = self.fixture(code="000")
        baseline_output = json.dumps(baseline.to_dict(), sort_keys=True)
        for integer in range(1000):
            candidate = self.fixture(code=f"{integer:03d}")
            self.assertEqual(candidate.fingerprint, baseline.fingerprint)
            self.assertEqual(json.dumps(candidate.to_dict(), sort_keys=True), baseline_output)
        self.assertFalse(baseline.same_private_context(self.fixture(code="001")))
        self.assertNotIn("Verification Code", baseline_output)

    def test_terminal_safe_metadata_and_positive_verification_discriminator(self) -> None:
        ordinary = PendingRequest.from_transaction({"urgid": "ordinary-id", "verified_push": False, "attributes": {"Application": "A\x1b[2J"}})
        code_required = self.fixture(code="777")
        unknown = PendingRequest.from_transaction({"urgid": "unknown-id", "attributes": {"Application": "No marker"}})
        self.assertEqual(ordinary.verification, VerificationMode.ORDINARY)
        self.assertEqual(code_required.verification, VerificationMode.CODE_REQUIRED)
        self.assertEqual(unknown.verification, VerificationMode.UNKNOWN)
        self.assertNotIn("\x1b", ordinary.to_dict()["service"])
        self.assertIn("\\u001b", ordinary.to_dict()["service"])

    def test_current_utoronto_legacy_payload_is_parsed_and_bounded(self) -> None:
        ordinary = PendingRequest.from_transaction(
            {
                "urgid": "uoft-observed-id",
                "type": "Login",
                "phone_notification_type": "visible_notification",
                "is_proximity_push": False,
                "is_strict_proximity_push": False,
                "expiration": 4_102_444_800,
                "summary": "Device Management Portal",
                "attributes": [
                    [["Organization", "University of Toronto"], ["Integration", "Device Management Portal"]],
                    [["Username", "fixture-user"], ["IP Address", "192.0.2.1"], ["Location", "Toronto, ON"], ["Time", 4_102_444_700.5]],
                ],
            }
        )
        self.assertEqual(ordinary.verification, VerificationMode.ORDINARY)
        self.assertEqual(ordinary.service, "Device Management Portal")
        self.assertEqual(ordinary.account, "fixture-user")
        self.assertEqual(ordinary.host, "192.0.2.1")
        self.assertEqual(ordinary.location, "Toronto, ON")
        self.assertEqual(ordinary.received_at, "4102444700.5")
        self.assertEqual(ordinary.expires_at, "4102444800")

        verified = PendingRequest.from_transaction(
            {
                "urgid": "uoft-step-up-id",
                "type": "Login",
                "phone_notification_type": "visible_notification",
                "is_proximity_push": False,
                "is_strict_proximity_push": False,
                "step_up_code_info": {"num_digits": 3},
                "attributes": [[["Integration", "Protected Portal"]]],
            }
        )
        self.assertEqual(verified.verification, VerificationMode.CODE_REQUIRED)

    def test_unsafe_urgids_are_rejected_at_protocol_boundary(self) -> None:
        for identifier in ("bad/identifier", "bad?identifier", "bad#identifier", "%2f", "unicodé", "bad identifier", "bad\nidentifier"):
            with self.assertRaises(ValueError):
                PendingRequest.from_transaction({"urgid": identifier, "verified_push": False})

    def test_host_validation_rejects_arbitrary_domains_ports_ips_and_userinfo(self) -> None:
        self.assertEqual(validate_api_host("api-0123abcd.duosecurity.com"), "api-0123abcd.duosecurity.com")
        for host in (
            "api-0123abcd.duosecurity.com:443",
            "api-0123abcd.duosecurity.com.",
            "api-0123abcd.duofederal.com",
            "127.0.0.1",
            "localhost",
            "user@api-0123abcd.duosecurity.com",
            "api-evil.duosecurity.com",
            "API-0123ABCD.DUOSECURITY.COM",
        ):
            with self.assertRaises(AuthenticationError):
                validate_api_host(host)

    def test_strict_qr_parser_rejects_malicious_hosts_and_url_components_offline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExclusiveStateLock(StatePaths(Path(temporary))) as state:
            duo = Duo(state)
            code, host = duo._parse_activation_code("https://m-0123abcd.duosecurity.com/activate/fixturecode")
            self.assertEqual((code, host), ("fixturecode", "api-0123abcd.duosecurity.com"))
            for raw in (
                "http://m-0123abcd.duosecurity.com/activate/fixturecode",
                "https://user@m-0123abcd.duosecurity.com/activate/fixturecode",
                "https://m-0123abcd.duosecurity.com:443/activate/fixturecode",
                "https://127.0.0.1/activate/fixturecode",
                "https://m-0123abcd.duosecurity.com/activate/fixturecode?x=1",
                "https://m-0123abcd.duosecurity.com/activate/fixturecode#x",
                "https://m-0123abcd.evil.example/activate/fixturecode",
            ):
                with self.assertRaises(DuoCliError):
                    duo._parse_activation_code(raw)

    def test_signed_request_uses_session_spy_no_proxies_no_redirects_and_expected_path(self) -> None:
        FakeHash.messages.clear()
        spy = SessionSpy([FakeResponse()])
        with tempfile.TemporaryDirectory() as temporary, ExclusiveStateLock(StatePaths(Path(temporary))) as state:
            duo = Duo(state, session=spy)
            duo.key = object()
            duo.host = "api-0123abcd.duosecurity.com"
            duo.akey = "fake-akey"
            duo.pkey = "fake-pkey"
            with patch("src.duo_cli.real_backend._dependencies", return_value=(FakeRequests, FakeHash, object(), FakePkcs)):
                body = duo.transactions()
        self.assertEqual(body["stat"], "OK")
        self.assertFalse(spy.trust_env)
        args, kwargs = spy.calls[0]
        self.assertEqual(args, ("GET", "https://api-0123abcd.duosecurity.com/push/v2/device/transactions"))
        self.assertEqual(kwargs["allow_redirects"], False)
        self.assertEqual(kwargs["verify"], True)
        self.assertEqual(kwargs["params"], {"akey": "fake-akey", "fips_status": "1", "hsm_status": "true", "pkpush": "rsa-sha512"})
        self.assertIsNone(kwargs["data"])
        signed = FakeHash.messages[0].decode("ascii").split("\n")
        self.assertEqual(signed[1:4], ["GET", "api-0123abcd.duosecurity.com", "/push/v2/device/transactions"])
        self.assertEqual(signed[4], "akey=fake-akey&fips_status=1&hsm_status=true&pkpush=rsa-sha512")
        self.assertIn("Authorization", kwargs["headers"])

    def test_reply_path_is_one_encoded_segment_and_unsafe_values_never_reach_session(self) -> None:
        FakeHash.messages.clear()
        spy = SessionSpy([FakeResponse()])
        with tempfile.TemporaryDirectory() as temporary, ExclusiveStateLock(StatePaths(Path(temporary))) as state:
            duo = Duo(state, session=spy)
            duo.key, duo.host, duo.akey, duo.pkey = object(), "api-0123abcd.duosecurity.com", "fake-akey", "fake-pkey"
            with patch("src.duo_cli.real_backend._dependencies", return_value=(FakeRequests, FakeHash, object(), FakePkcs)):
                duo.reply("opaque-id", "approve", code="777")
                for identifier in ("bad/id", "bad?id", "bad#id", "%2f", "unicodé"):
                    with self.assertRaises(DuoCliError):
                        duo.reply(identifier, "approve")
        args, kwargs = spy.calls[0]
        self.assertEqual(args, ("POST", "https://api-0123abcd.duosecurity.com/push/v2/device/transactions/opaque-id"))
        self.assertEqual(kwargs["headers"]["txId"], "opaque-id")
        self.assertEqual(len(spy.calls), 1)

    def test_malformed_signing_values_are_rejected_before_crypto_or_transport(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExclusiveStateLock(StatePaths(Path(temporary))) as state:
            duo = Duo(state, session=SessionSpy([]))
            duo.key, duo.host, duo.akey, duo.pkey = object(), "api-0123abcd.duosecurity.com", "fake-akey", "fake-pkey"
            with patch("src.duo_cli.real_backend._dependencies", return_value=(FakeRequests, FakeHash, object(), FakePkcs)):
                with self.assertRaises(DuoCliError):
                    duo._sign("GET", "/push/v2/device/transactions", "bad-date", {"akey": "fake-akey"})
                with self.assertRaises(DuoCliError):
                    duo._sign("GET", "/push/v2/device/transactions", "Wed, 19 Aug 2026 01:02:03 +0000", {"akey": "bad/value"})
                duo.pkey = "bad\nheader"
                with self.assertRaises(DuoCliError):
                    duo._sign("GET", "/push/v2/device/transactions", "Wed, 19 Aug 2026 01:02:03 +0000", {"akey": "fake-akey"})

    def test_redirect_and_protocol_failure_are_rejected_without_followup(self) -> None:
        for response in (FakeResponse(status_code=302), FakeResponse(body={"stat": "FAIL"}), FakeResponse(body=ValueError("bad json"))):
            spy = SessionSpy([response])
            with tempfile.TemporaryDirectory() as temporary, ExclusiveStateLock(StatePaths(Path(temporary))) as state:
                duo = Duo(state, session=spy)
                duo.key, duo.host, duo.akey, duo.pkey = object(), "api-0123abcd.duosecurity.com", "fake-akey", "fake-pkey"
                with patch("src.duo_cli.real_backend._dependencies", return_value=(FakeRequests, FakeHash, object(), FakePkcs)):
                    with self.assertRaises(DuoCliError):
                        duo.transactions()
            self.assertEqual(len(spy.calls), 1)
            self.assertFalse(spy.trust_env)

    def test_loaded_state_rejects_invalid_host_before_crypto_or_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExclusiveStateLock(StatePaths(Path(temporary))) as state:
            state.write_enrollment_atomic(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "privateKeyPem": "not-used-before-host-validation",
                        "response": {"host": "localhost", "akey": "akey", "pkey": "pkey"},
                    }
                ).encode("ascii")
            )
            with self.assertRaises(AuthenticationError):
                Duo(state).load()

    def test_qr_decoder_must_resolve_to_secure_absolute_regular_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExclusiveStateLock(StatePaths(Path(temporary))) as state:
            decoder = Path(temporary) / "zbarimg"
            decoder.write_bytes(b"fake")
            decoder.chmod(0o777)
            with patch("src.duo_cli.real_backend.shutil.which", return_value=str(decoder)):
                with self.assertRaises(DuoCliError):
                    Duo(state)._trusted_qr_decoder()
            decoder.chmod(0o755)
            with patch("src.duo_cli.real_backend.shutil.which", return_value=str(decoder)):
                self.assertEqual(Duo(state)._trusted_qr_decoder(), decoder.resolve())

    def test_qr_decoder_requires_exactly_one_symbol_with_a_subprocess_fake(self) -> None:
        class Result:
            def __init__(self, code: int, output: bytes):
                self.returncode = code
                self.stdout = output

        with tempfile.TemporaryDirectory() as temporary, ExclusiveStateLock(StatePaths(Path(temporary))) as state:
            root = Path(temporary)
            decoder = root / "zbarimg"
            decoder.write_bytes(b"fake")
            decoder.chmod(0o755)
            qr = root / "activation.png"
            qr.write_bytes(b"not-a-real-qr")
            qr.chmod(0o600)
            duo = Duo(state)
            with patch("src.duo_cli.real_backend.shutil.which", return_value=str(decoder)):
                with patch("src.duo_cli.real_backend.subprocess.run", return_value=Result(0, b"one\ntwo\n")):
                    with self.assertRaises(DuoCliError):
                        duo._decode_qr(qr)
                with patch("src.duo_cli.real_backend.subprocess.run", return_value=Result(0, b"one\n")):
                    self.assertEqual(duo._decode_qr(qr), "one")

    def test_fd_anchored_state_rejects_symlinked_root_and_commits_one_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            link = root / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(DuoCliError):
                with ExclusiveStateLock(StatePaths(link)):
                    pass
            with ExclusiveStateLock(StatePaths(real)) as state:
                state.write_enrollment_atomic(b'{"schemaVersion":1}')
                self.assertEqual(state.read_enrollment(), b'{"schemaVersion":1}')
                self.assertFalse((real / "key.pem").exists())
                self.assertFalse((real / "response.json").exists())
                self.assertEqual((real / "enrollment.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
