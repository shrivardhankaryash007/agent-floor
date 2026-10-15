"""Metadata-only event log: one JSON line per event, no free-text fields."""

import os
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

EventKind = Literal[
    "run_start",
    "run_end",
    "floor_missing",
    "policy_error",
    "violation",
    "owner_prompt",
    "probe",
]


class Event(BaseModel):
    """One metadata-only event; extra="forbid" is the privacy contract (gap E6)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: str
    kind: EventKind
    run_id: str
    tier: Literal["green", "amber", "red", "black"] | None = None
    reason_code: str | None = None
    path_class: str | None = None
    domain: str | None = None
    latency_ms: float | None = None
    count: int | None = None
    policy_hash: str | None = None
    exit_code: int | None = None


def state_dir() -> Path:
    """Return the state directory, honouring $AGENT_FLOOR_STATE."""
    configured = os.environ.get("AGENT_FLOOR_STATE")
    return Path(configured) if configured else Path.home() / ".local/state/agent-floor"


def append(event: Event, *, now: datetime) -> Path:
    """Append one event to the UTC-dated JSONL file and return its path."""
    directory = state_dir() / "events"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    path = directory / f"{now.astimezone(UTC).date().isoformat()}.jsonl"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
            stream.write(event.model_dump_json() + "\n")
    except BaseException:
        # fdopen owns the descriptor after construction.
        raise
    return path


def read_events(day: date) -> list[Event]:
    """Return the events logged on `day`, skipping malformed lines."""
    path = state_dir() / "events" / f"{day.isoformat()}.jsonl"
    try:
        rows = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events: list[Event] = []
    for row in rows:
        try:
            events.append(Event.model_validate_json(row))
        except ValueError:
            continue
    return events
