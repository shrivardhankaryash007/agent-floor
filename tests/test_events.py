"""Locked contract for P2: metadata-only event log."""

import json
import stat
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_floor.events import Event, append, read_events, state_dir

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)


def make_event(kind: str = "run_start", **fields: object) -> Event:
    """An event with every optional field left as None unless given."""
    return Event(ts="2026-10-15T12:00:00.000000Z", kind=kind, run_id="run-1", **fields)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_event_has_no_free_text_field() -> None:
    with pytest.raises(ValidationError):
        make_event(message="the agent tried to read ~/.ssh")
    with pytest.raises(ValidationError):
        make_event(kind="chatter")
    assert set(Event.model_fields) == {
        "ts",
        "kind",
        "run_id",
        "tier",
        "reason_code",
        "path_class",
        "domain",
        "latency_ms",
        "count",
        "policy_hash",
        "exit_code",
    }


def test_state_dir_honours_env(tmp_path: Path) -> None:
    assert state_dir() == tmp_path / "state"


def test_state_dir_default(fake_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_FLOOR_STATE")
    assert state_dir() == fake_home / ".local" / "state" / "agent-floor"


def test_append_writes_one_json_line_to_utc_dated_file(tmp_path: Path) -> None:
    path = append(make_event(policy_hash="0123456789abcdef"), now=NOW)
    assert path == tmp_path / "state" / "events" / "2026-10-15.jsonl"
    lines = path.read_text().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["kind"] == "run_start"
    assert row["policy_hash"] == "0123456789abcdef"
    assert set(row) <= set(Event.model_fields)


def test_append_uses_the_utc_date_not_local(tmp_path: Path) -> None:
    late_evening = datetime(2026, 10, 15, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
    path = append(make_event(), now=late_evening)
    assert path.name == "2026-10-16.jsonl"


def test_append_modes_are_private_and_reapplied(tmp_path: Path) -> None:
    path = append(make_event(), now=NOW)
    assert mode(path.parent) == 0o700
    assert mode(path) == 0o600
    path.chmod(0o644)
    append(make_event("run_end", exit_code=0), now=NOW)
    assert mode(path) == 0o600
    assert len(path.read_text().splitlines()) == 2


def test_read_events_round_trips_and_skips_malformed_lines() -> None:
    first = make_event(tier="amber", path_class="instruction")
    path = append(first, now=NOW)
    with path.open("a") as fh:
        fh.write("{not json\n")
        fh.write('{"kind": "run_end"}\n')
    append(make_event("run_end", exit_code=7, latency_ms=12.5), now=NOW)
    events = read_events(date(2026, 10, 15))
    assert [e.kind for e in events] == ["run_start", "run_end"]
    assert events[0] == first
    assert events[1].exit_code == 7
