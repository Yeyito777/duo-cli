"""Narrow backend abstraction; production never exposes a broad calsh CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, Sequence

from .models import PendingRequest


class DuoBackend(Protocol):
    """The only protocol actions this v1 CLI needs."""

    def load(self) -> None:
        """Load one already-enrolled local emulated device."""

    def transactions(self) -> Sequence[PendingRequest]:
        """Read currently pending server transactions without mutation."""

    def reply(self, urgid: str, answer: str, code: str | None = None) -> None:
        """Answer exactly one opaque transaction ID."""

    def login_from_qr(self, qr_file: Path) -> None:
        """Explicit setup-only device activation from a local QR image."""
