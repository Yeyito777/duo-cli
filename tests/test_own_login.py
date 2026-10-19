from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.duo_cli import own_login
from src.duo_cli.cli import _verify_code, main
from src.duo_cli.errors import BusyError, OutcomeUnknownError, UsageError, VerifiedPushError
from src.duo_cli.models import PendingRequest
from src.duo_cli.state import ExclusiveStateLock, StatePaths

from tests.test_cli import FakeBackend


START = 1_800_000_000.0
IP = "203.0.113.7"


def uoft(urgid: str = "req-uoft-01", **attributes: object) -> PendingRequest:
    attrs = {
        "Application": "Weblogin Standard",
        "Username": "lineroau (Test Student)",
        "Host": IP,
        "Time": str(START + 5),
    }
    attrs.update(attributes)
    raw: dict = {"urgid": urgid, "status": "pending", "verified_push": True, "attributes": attrs}
    if attrs.pop("ordinary", None):
        raw["verified_push"] = False
    return PendingRequest.from_transaction(raw)


class OwnLoginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.paths = StatePaths(Path(self.temporary.name) / "state")
        self.clock = START

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def begin(self, backend: FakeBackend, caller: str = "utmail") -> str:
        with ExclusiveStateLock(self.paths) as state:
            return own_login.begin(state, backend, caller, now=self.clock)["ticket"]

    def approve(self, backend: FakeBackend, ticket: str, *, code: str = "295", account: str = "lineroau", ip: str = IP):
        with ExclusiveStateLock(self.paths) as state:
            return own_login.approve(
                state,
                backend,
                ticket,
                read_code=lambda: code,
                verify_code=_verify_code,
                now=lambda: self.clock,
                sleep=self.advance,
                public_ip=lambda: ip,
                environ={own_login.ACCOUNT_ENV: account},
            )

    def advance(self, seconds: float) -> None:
        self.clock += seconds

    def audit(self) -> list[dict]:
        path = self.paths.root / own_login.AUDIT_FILE
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def ticket_exists(self) -> bool:
        return (self.paths.root / own_login.TICKET_FILE).exists()

    def test_approves_the_single_matching_request_and_audits_without_code(self) -> None:
        backend = FakeBackend([[], [uoft()]])
        ticket = self.begin(backend)
        self.clock += 10
        approved = self.approve(backend, ticket)
        self.assertEqual(approved.request_id, "req-uoft-01")
        self.assertEqual(backend.replies, [("req-uoft-01", "approve", "295")])
        self.assertFalse(self.ticket_exists())
        events = self.audit()
        self.assertEqual([e["event"] for e in events], ["begin", "approved"])
        self.assertEqual(events[1]["caller"], "utmail")
        self.assertEqual(events[1]["service"], "Weblogin Standard")
        self.assertEqual(events[1]["host"], IP)
        self.assertEqual(events[1]["requestId"], "req-uoft-01")
        self.assertNotIn("295", (self.paths.root / own_login.AUDIT_FILE).read_text())

    def test_end_after_approval_still_records_the_caller(self) -> None:
        backend = FakeBackend([[], [uoft()]])
        ticket = self.begin(backend, "quercus")
        self.clock += 10
        self.approve(backend, ticket)
        with ExclusiveStateLock(self.paths) as state:
            self.assertFalse(own_login.end(state, ticket, "completed", now=self.clock))
        end = self.audit()[-1]
        self.assertEqual((end["event"], end["caller"], end["outcome"]), ("end", "quercus", "completed"))

    def test_approval_with_unknown_outcome_is_audited_as_unknown(self) -> None:
        class LostReply(FakeBackend):
            def reply(self, urgid: str, answer: str, code: str | None = None) -> None:
                super().reply(urgid, answer, code)
                raise OutcomeUnknownError("in transit")

        backend = LostReply([[], [uoft()]])
        ticket = self.begin(backend)
        self.clock += 10
        with self.assertRaises(OutcomeUnknownError):
            self.approve(backend, ticket)
        self.assertEqual(self.audit()[-1]["event"], "unknown")
        self.assertFalse(self.ticket_exists())

    def test_waits_briefly_for_the_push_to_arrive(self) -> None:
        backend = FakeBackend([[], [], [], [uoft()]])
        ticket = self.begin(backend)
        self.approve(backend, ticket)
        self.assertEqual(len(backend.replies), 1)

    def test_each_mismatch_refuses_without_reply_and_consumes_the_ticket(self) -> None:
        cases = {
            "service": ([uoft(Application="MarkUs")], {}),
            "account": ([uoft(Username="someoneelse (Other)")], {}),
            "host": ([uoft()], {"ip": "198.51.100.1"}),
            "env account": ([uoft()], {"account": ""}),
            "ordinary push": ([uoft(ordinary=True)], {}),
            "two pending": ([uoft(), uoft("req-uoft-02")], {}),
            "none pending": ([], {}),
            "stale request": ([uoft(Time=str(START - 120))], {}),
            "missing time": ([uoft(Time="")], {}),
        }
        for name, (pending, overrides) in cases.items():
            with self.subTest(name):
                self.paths = StatePaths(Path(self.temporary.name) / name.replace(" ", "-"))
                backend = FakeBackend([[], pending])
                ticket = self.begin(backend)
                with self.assertRaises(own_login.OwnLoginRefused):
                    self.approve(backend, ticket, **overrides)
                self.assertEqual(backend.replies, [])
                self.assertFalse(self.ticket_exists())
                self.assertEqual(self.audit()[-1]["event"], "refused")
                # A consumed ticket cannot be retried.
                with self.assertRaises(own_login.OwnLoginRefused):
                    self.approve(FakeBackend([[uoft()]]), ticket)

    def test_known_code_mismatch_refuses(self) -> None:
        backend = FakeBackend([[], [uoft(**{"Verification Code": "111"})]])
        ticket = self.begin(backend)
        with self.assertRaises(VerifiedPushError):
            self.approve(backend, ticket, code="295")
        self.assertEqual(backend.replies, [])

    def test_ticket_expires_and_wrong_ticket_is_refused(self) -> None:
        backend = FakeBackend([[], [uoft()]])
        ticket = self.begin(backend)
        with self.assertRaises(own_login.OwnLoginRefused):
            self.approve(backend, "0" * 32)
        self.clock += own_login.TICKET_TTL_SECONDS + 1
        with self.assertRaises(own_login.OwnLoginRefused):
            self.approve(backend, ticket)
        self.assertEqual(backend.replies, [])
        with self.assertRaises(UsageError):
            self.approve(backend, "not-a-ticket")

    def test_live_ticket_is_a_lock_until_ended_or_expired(self) -> None:
        first = self.begin(FakeBackend([[]]), "utmail")
        with self.assertRaises(BusyError):
            self.begin(FakeBackend([[]]), "quercus")
        with ExclusiveStateLock(self.paths) as state:
            self.assertTrue(own_login.end(state, first, "failed", now=self.clock))
        self.begin(FakeBackend([[]]), "quercus")
        self.clock += own_login.TICKET_TTL_SECONDS + 1
        self.begin(FakeBackend([[]]), "utmail")

    def test_daily_cap_counts_attempts_in_a_rolling_day(self) -> None:
        for _ in range(own_login.DAILY_CAP):
            self.begin(FakeBackend([[]]))
            self.clock += own_login.TICKET_TTL_SECONDS + 1
        with self.assertRaisesRegex(own_login.OwnLoginRefused, "cap"):
            self.begin(FakeBackend([[]]))
        self.clock = START + 86_400 + 1
        self.begin(FakeBackend([[]]))

    def test_begin_requires_allowed_caller_and_no_pending_requests(self) -> None:
        with self.assertRaises(UsageError):
            self.begin(FakeBackend([[]]), "vimbrowser")
        with self.assertRaises(own_login.OwnLoginRefused):
            self.begin(FakeBackend([[uoft()]]))
        self.assertFalse(self.ticket_exists())

    def test_cli_round_trip_reads_code_from_stdin_and_never_prints_it(self) -> None:
        backend = FakeBackend([[], [uoft()]])

        def run(argv: list[str], stdin: bytes | None = None) -> tuple[int, str, str]:
            out, err = io.StringIO(), io.StringIO()
            patches = [patch.object(own_login, "fetch_public_ip", lambda: IP), patch("time.time", lambda: START)]
            if stdin is not None:
                patches.append(patch("sys.stdin", io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8")))
            with redirect_stdout(out), redirect_stderr(err), patch.dict("os.environ", {"UOFT_UTORID": "lineroau"}):
                for item in patches:
                    item.start()
                try:
                    code = main(["--state-dir", str(self.paths.root), *argv], backend_factory=lambda _s: backend)
                finally:
                    for item in patches:
                        item.stop()
            return code, out.getvalue(), err.getvalue()

        code, out, err = run(["own-login", "begin", "--caller", "quercus", "--json"])
        self.assertEqual((code, err), (0, ""))
        ticket = json.loads(out)["ownLogin"]["ticket"]
        code, out, err = run(["own-login", "approve", ticket, "--json"], stdin=b"295")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out)["approved"]["id"], "req-uoft-01")
        self.assertNotIn("295", out)
        code, out, err = run(["own-login", "end", ticket, "--outcome", "completed", "--json"])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual([e["event"] for e in self.audit()], ["begin", "approved", "end"])



class PublicIpTests(unittest.TestCase):
    def fetch(self, outcomes: list):
        import requests

        calls, sleeps = [], []

        class Response:
            def __init__(self, status: int, text: str) -> None:
                self.status_code, self.text = status, text

        class Session:
            trust_env = True

            def get(self, url, **kwargs):
                calls.append((url, kwargs, self.trust_env))
                outcome = outcomes.pop(0)
                if isinstance(outcome, Exception):
                    raise outcome
                return Response(*outcome)

            def close(self) -> None:
                pass

        with patch.object(requests, "Session", Session):
            try:
                return own_login.fetch_public_ip(sleep=sleeps.append), calls, sleeps
            except own_login.OwnLoginRefused as error:
                return error, calls, sleeps

    def test_transient_failures_are_retried_with_the_same_strict_request(self) -> None:
        import requests

        result, calls, sleeps = self.fetch([requests.ConnectionError("down"), (503, ""), (200, IP + "\n")])
        self.assertEqual(result, IP)
        self.assertEqual(sleeps, [1.0, 1.0])
        for url, kwargs, trust_env in calls:
            self.assertEqual(url, own_login.PUBLIC_IP_URL)
            self.assertFalse(kwargs["allow_redirects"])
            self.assertFalse(trust_env)

    def test_still_refuses_after_bounded_attempts(self) -> None:
        result, calls, _ = self.fetch([(200, "not-an-ip"), (429, ""), (200, "")])
        self.assertIsInstance(result, own_login.OwnLoginRefused)
        self.assertEqual(len(calls), own_login.PUBLIC_IP_ATTEMPTS)


if __name__ == "__main__":
    unittest.main()
