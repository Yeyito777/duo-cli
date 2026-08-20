"""Human and schema-versioned JSON rendering of already-sanitized context."""

from __future__ import annotations

import json
from typing import Iterable

from . import SCHEMA_VERSION
from .models import PendingRequest


def emit_json(payload: dict[str, object]) -> None:
    print(json.dumps({"schemaVersion": SCHEMA_VERSION, **payload}, sort_keys=True, ensure_ascii=True))


def _line(label: str, value: object) -> str:
    return f"  {label:<12} {value}"


def render_request(request: PendingRequest) -> str:
    fields = request.to_dict()
    labels = {
        "id": "Request ID:",
        "status": "Status:",
        "service": "Service:",
        "account": "Account:",
        "host": "Host:",
        "location": "Location:",
        "receivedAt": "Received:",
        "expiresAt": "Expires:",
        "verification": "Verification:",
        "fingerprint": "Fingerprint:",
    }
    order = ("id", "status", "service", "account", "host", "location", "receivedAt", "expiresAt", "verification", "fingerprint")
    return "\n".join(_line(labels[key], fields[key]) for key in order if key in fields)


def render_requests(requests: Iterable[PendingRequest]) -> str:
    lines: list[str] = []
    for request in requests:
        fields = request.to_dict(include_fingerprint=False)
        details = [f"status: {fields['status']}"]
        for key, label in (("service", "service"), ("account", "account"), ("host", "host"), ("location", "location")):
            if key in fields:
                details.append(f"{label}: {fields[key]}")
        details.append(f"verification: {fields['verification']}")
        lines.append(f"  {fields['id']}  " + " · ".join(details))
    return "\n".join(lines) if lines else "  No pending requests."
