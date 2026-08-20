from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.duo_cli.cli import main
from src.duo_cli.errors import BusyError, DuoCliError
from src.duo_cli.models import PendingRequest
from src.duo_cli.state import ExclusiveStateLock, StatePaths


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "transactions.json"
FIXTURES = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def request(name: str, **changes: object) -> PendingRequest:
    raw = copy.deepcopy(FIXTURES[name])
    raw.update(changes)
    return PendingRequest.from_transaction(raw)


class FakeBackend:
    """Offline fake; it never has an HTTP session, QR decoder, or account."""

    def __init__(self, batches: list[list[PendingRequest]], *, fail_transactions: bool = False):
        self.batches = batches
        self.fail_transactions = fail_transactions
        self.transaction_calls = 0
        self.load_calls = 0
        self.replies: list[tuple[str, str, str | None]] = []
        self.login_files: list[Path] = []

    def load(self) -> None:
        self.load_calls += 1

    def transactions(self) -> list[PendingRequest]:
        if self.fail_transactions:
            raise RuntimeError("private https://secret.invalid/path should never be rendered")
        index = min(self.transaction_calls, len(self.batches) - 1)
        self.transaction_calls += 1
        return list(self.batches[index])

    def reply(self, urgid: str, answer: str, code: str | None = None) -> None:
        self.replies.append((urgid, answer, code))

    def login_from_qr(self, qr_file: Path) -> None:
        self.login_files.append(qr_file)


class CliSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temporary.name) / "state"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def invoke(
        self,
        argv: list[str],
        backend: FakeBackend,
        *,
        code_stdin: bytes | None = None,
    ) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(code_stdin), encoding="utf-8") if code_stdin is not None else None
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with patch("sys.stdin", stdin) if stdin is not None else _no_patch():
                code = main(
                    ["--state-dir", str(self.state_dir), *argv],
                    backend_factory=lambda _state: backend,
                )
        return code, stdout.getvalue(), stderr.getvalue()

    @staticmethod
    def approval_args(item: PendingRequest, *, code_stdin: bool = False) -> list[str]:
        args = ["approve", item.request_id, "--confirm-fingerprint", item.fingerprint]
        if code_stdin:
            args.append("--code-stdin")
        return args

    def test_requests_is_read_only_and_json_is_versioned_and_sanitized(self) -> None:
        backend = FakeBackend([[request("plain"), request("expired")]])
        code, stdout, stderr = self.invoke(["requests", "--json"], backend)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        payload = json.loads(stdout)
        self.assertEqual(payload["schemaVersion"], 1)
        self.assertEqual([item["id"] for item in payload["requests"]], ["req-alpha-01"])
        self.assertEqual(payload["requests"][0]["service"], "Campus VPN")
        self.assertNotIn("fingerprint", payload["requests"][0])
        self.assertNotIn("must-not-be-rendered", stdout)
        self.assertEqual(backend.replies, [])

    def test_human_request_list_renders_the_actual_verification_mode(self) -> None:
        backend = FakeBackend([[request("plain"), request("verified")]])
        code, stdout, stderr = self.invoke(["requests"], backend)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("verification: ordinary-push", stdout)
        self.assertIn("verification: code-required", stdout)
        self.assertNotIn("Fingerprint:", stdout)
        self.assertEqual(backend.replies, [])

    def test_request_requires_documented_exact_id_grammar(self) -> None:
        backend = FakeBackend([[request("plain")]])
        for identifier in ("req/alpha", "req?alpha", "req#alpha", "%2f", "unicodé", "req alpha"):
            code, stdout, stderr = self.invoke(["request", identifier], backend)
            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn("ASCII unreserved-ID", stderr)
        self.assertEqual(backend.replies, [])

    def test_approve_requires_prior_exact_fingerprint_and_refetches_once(self) -> None:
        selected = request("plain")
        backend = FakeBackend([[selected], [selected]])
        code, stdout, stderr = self.invoke(self.approval_args(selected), backend)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(backend.transaction_calls, 2)
        self.assertEqual(backend.replies, [("req-alpha-01", "approve", None)])
        self.assertIn("Fingerprint:", stdout)
        self.assertIn("Approved. Request ID: req-alpha-01", stdout)

    def test_approve_refuses_stale_review_fingerprint_before_reply(self) -> None:
        selected = request("plain")
        backend = FakeBackend([[selected]])
        args = ["approve", selected.request_id, "--confirm-fingerprint", "sha256:" + "0" * 64]
        code, stdout, stderr = self.invoke(args, backend)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("review fingerprint", stderr)
        self.assertEqual(backend.replies, [])

    def test_approve_refuses_changed_public_or_private_context_before_any_reply(self) -> None:
        first = request("plain")
        changed = request("plain", attributes={"Application": "Different Service"}, verified_push=False)
        backend = FakeBackend([[first], [changed]])
        code, stdout, stderr = self.invoke(self.approval_args(first), backend)
        self.assertEqual(code, 1)
        self.assertIn("Campus VPN", stdout)
        self.assertIn("context changed", stderr)
        self.assertEqual(backend.replies, [])

    def test_approve_refuses_private_verified_code_change_with_same_public_fingerprint(self) -> None:
        first = request("verified")
        changed = request(
            "verified",
            attributes={
                "Application": "Research Portal",
                "Username": "student@example.edu",
                "Location": "Toronto, ON",
                "Verification Code": "493",
            },
            verified_push=True,
        )
        self.assertEqual(first.fingerprint, changed.fingerprint)
        backend = FakeBackend([[first], [changed]])
        code, _stdout, stderr = self.invoke(self.approval_args(first, code_stdin=True), backend, code_stdin=b"492")
        self.assertEqual(code, 1)
        self.assertIn("context changed", stderr)
        self.assertEqual(backend.replies, [])

    def test_approve_refuses_absent_duplicate_expired_or_handled_requests(self) -> None:
        selected = request("plain")
        absent = FakeBackend([[selected], []])
        code, _stdout, stderr = self.invoke(self.approval_args(selected), absent)
        self.assertEqual(code, 1)
        self.assertIn("not currently pending", stderr)

        duplicate = FakeBackend([[selected, selected]])
        code, _stdout, stderr = self.invoke(self.approval_args(selected), duplicate)
        self.assertEqual(code, 1)
        self.assertIn("multiple pending entries", stderr)

        expired = request("expired")
        expired_backend = FakeBackend([[expired]])
        code, _stdout, stderr = self.invoke(self.approval_args(expired), expired_backend)
        self.assertEqual(code, 1)
        self.assertIn("expired", stderr)

        handled = request("plain", status="approved")
        handled_backend = FakeBackend([[handled]])
        code, _stdout, stderr = self.invoke(self.approval_args(handled), handled_backend)
        self.assertEqual(code, 1)
        self.assertIn("already handled", stderr)
        for item in (absent, duplicate, expired_backend, handled_backend):
            self.assertEqual(item.replies, [])

    def test_unknown_or_unmarked_semantics_never_approves(self) -> None:
        unknown = request("unknown")
        backend = FakeBackend([[unknown]])
        code, _stdout, stderr = self.invoke(self.approval_args(unknown), backend)
        self.assertEqual(code, 1)
        self.assertIn("no positive ordinary-push", stderr)
        self.assertEqual(backend.replies, [])

        # This fixture represents a code-needing transaction with no positive
        # protocol marker. The tool cannot infer that safely and still refuses.
        hidden_code = request("unknown", attributes={"Application": "Could need code"})
        backend = FakeBackend([[hidden_code]])
        code, _stdout, stderr = self.invoke(self.approval_args(hidden_code, code_stdin=True), backend, code_stdin=b"492")
        self.assertEqual(code, 1)
        self.assertIn("no positive ordinary-push", stderr)
        self.assertEqual(backend.replies, [])

    def test_verified_push_requires_exact_code_stdin_and_never_renders_code(self) -> None:
        selected = request("verified")
        no_stdin = FakeBackend([[selected]])
        code, _stdout, stderr = self.invoke(self.approval_args(selected), no_stdin)
        self.assertEqual(code, 1)
        self.assertIn("requires a Verified Push code", stderr)
        self.assertEqual(no_stdin.replies, [])

        wrong = FakeBackend([[selected]])
        code, _stdout, stderr = self.invoke(self.approval_args(selected, code_stdin=True), wrong, code_stdin=b"111")
        self.assertEqual(code, 1)
        self.assertIn("does not match", stderr)
        self.assertEqual(wrong.replies, [])

        matching = FakeBackend([[selected], [selected]])
        args = [*self.approval_args(selected, code_stdin=True), "--json"]
        code, stdout, stderr = self.invoke(args, matching, code_stdin=b"492")
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(matching.replies, [("req-code-02", "approve", "492")])
        self.assertNotIn('"492"', stdout)

    def test_code_argv_is_rejected_by_parser_and_stdin_is_not_read_for_ordinary_push(self) -> None:
        selected = request("plain")
        with self.assertRaises(SystemExit) as raised, redirect_stderr(io.StringIO()):
            main(["--state-dir", str(self.state_dir), "approve", selected.request_id, "--code", "492"])
        self.assertEqual(raised.exception.code, 2)

        backend = FakeBackend([[selected]])
        code, _stdout, stderr = self.invoke(self.approval_args(selected, code_stdin=True), backend, code_stdin=b"must-not-be-read")
        self.assertEqual(code, 2)
        self.assertIn("only accepted", stderr)
        self.assertEqual(backend.replies, [])

    def test_unexpected_exception_is_sanitized_at_cli_boundary(self) -> None:
        backend = FakeBackend([[]], fail_transactions=True)
        code, stdout, stderr = self.invoke(["requests"], backend)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertIn("Unexpected internal failure", stderr)
        self.assertNotIn("secret.invalid", stderr)

    def test_setup_login_contract_is_fake_only_and_logout_is_fd_anchored(self) -> None:
        backend = FakeBackend([[]])
        path = self.state_dir / "not-decoded-in-test.png"
        code, stdout, stderr = self.invoke(["login", "--qr", str(path), "--json"], backend)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(backend.login_files, [path])
        self.assertEqual(json.loads(stdout)["login"]["status"], "enrolled")

        paths = StatePaths(self.state_dir)
        with ExclusiveStateLock(paths) as state:
            state.write_enrollment_atomic(b'{"placeholder":true}')
            self.assertEqual(state.read_enrollment(), b'{"placeholder":true}')
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["--state-dir", str(self.state_dir), "logout"])
        self.assertEqual(code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(stdout.getvalue(), "Logged out.\n")
        with ExclusiveStateLock(paths) as state:
            with self.assertRaises(DuoCliError):
                state.read_enrollment()

    def test_state_lock_rejects_an_overlapping_command(self) -> None:
        paths = StatePaths(self.state_dir)
        with ExclusiveStateLock(paths):
            with self.assertRaises(BusyError):
                with ExclusiveStateLock(paths):
                    self.fail("second exclusive lock must not be acquired")


class _no_patch:
    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False


if __name__ == "__main__":
    unittest.main()
