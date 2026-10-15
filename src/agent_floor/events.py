"""Metadata-only event log: one JSON line per event, no free-text fields."""

from datetime import date, datetime
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
    raise NotImplementedError


def append(event: Event, *, now: datetime) -> Path:
    """Append one event to the UTC-dated JSONL file and return its path."""
    raise NotImplementedError


def read_events(day: date) -> list[Event]:
    """Return the events logged on `day`, skipping malformed lines."""
    raise NotImplementedError
