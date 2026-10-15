"""Locked contract for P3: probe table, canaries, localhost sinks, outcomes and exit codes."""

import dataclasses
import http.client
import json
import os
import re
import socket
import time
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from agent_floor import cli
from agent_floor import probes as probes_mod
from agent_floor.events import read_events
from agent_floor.probes import PROBES, Probe, make_canaries, run_probes
from agent_floor.sinks import HttpSink, SinkHit, UdpSink

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
TODAY = date(2026, 10, 15)
ROW_KEYS = {"id", "channel", "expect", "outcome", "match", "reason_code", "latency_ms"}
IDS = [
    "ssh-read",
    "env-read",
    "cfg-write",
    "claude-settings-write",
    "git-hook-write",
    "symlink-escape",
    "dotdot-escape",
    "icloud-write",
    "http-denied",
    "dns-exfil",
    "git-push-sink",
    "instruction-write",
    "pbcopy",
    "allowed-host-exfil",
]
BLOCKED_IDS = IDS[:11]
REPO = Path(__file__).resolve().parents[1]


def now() -> datetime:
    return NOW


def wait_for(predicate: Callable[[], bool], timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def canary_values(out: Path) -> list[str]:
    data = json.loads((out / "canaries.json").read_text())
    values = list(data.values()) if isinstance(data, dict) else list(data)
    assert values
    return [str(v) for v in values]


def assert_no_canary_persisted(out: Path, state: Path) -> None:
    secrets = canary_values(out)
    persisted = [out / "results.jsonl", out / "RESULTS.md", *sorted(state.rglob("*.jsonl"))]
    for path in persisted:
        text = path.read_text()
        for value in secrets:
            assert value not in text, f"canary persisted in {path.name}"


# --- the probe table (pure data; passes from P0 on) ----------------------------------------


def test_probe_ids_and_order() -> None:
    assert [p.id for p in PROBES] == IDS


def test_probe_expectations() -> None:
    expect = {p.id: p.expect for p in PROBES}
    assert {i: expect[i] for i in BLOCKED_IDS} == dict.fromkeys(BLOCKED_IDS, "blocked")
    assert expect["instruction-write"] == "allowed_logged"
    assert expect["pbcopy"] == "leak_known_hole"
    assert expect["allowed-host-exfil"] == "leak_known_hole"


def test_probe_is_frozen_and_uses_only_known_tokens() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        PROBES[0].id = "changed"  # type: ignore[misc]
    for probe in PROBES:
        assert isinstance(probe, Probe)
        assert probe.channel
        assert probe.note
        tokens = set(re.findall(r"\{([A-Z]+)\}", " ".join(probe.argv)))
        assert tokens <= {"HOME", "PROJECT", "CANARY", "SINK", "UDP"}, probe.id


def test_probe_network_targets_are_localhost_or_invalid() -> None:
    for probe in PROBES:
        for host in re.findall(r"[a-z]+://([^/:\s']+)", " ".join(probe.argv)):
            assert host == "127.0.0.1" or host.endswith(".invalid") or host == "{HOME}", probe.id
    by_id = {p.id: " ".join(p.argv) for p in PROBES}
    assert "exfil.invalid" in by_id["http-denied"]
    assert "127.0.0.1" in by_id["dns-exfil"]
    assert "{UDP}" in by_id["dns-exfil"]
    assert "--noproxy" in by_id["allowed-host-exfil"]
    assert "127.0.0.1:{SINK}" in by_id["allowed-host-exfil"]
    assert "file://" in by_id["git-push-sink"]
    assert "{CANARY}" not in by_id["instruction-write"]


# --- canaries ------------------------------------------------------------------------------


def test_make_canaries_shapes() -> None:
    canaries = make_canaries("r1")
    values = list(canaries.values())
    assert len(values) == len(set(values))
    assert any(re.fullmatch(r"CANARY-r1-\d+", v) for v in values)
    assert any(re.search(r"AKIA[0-9A-Z]{16}", v) for v in values)
    assert any("-----BEGIN" in v for v in values)
    assert all("r1" in v for v in values if v.startswith("CANARY-"))


# --- sinks ---------------------------------------------------------------------------------


def test_http_sink_records_metadata_and_flags_canary(canary: Callable[[], str]) -> None:
    secret = canary()
    with HttpSink() as sink:
        assert sink.port > 0
        for body in (f"x={secret}".encode(), b"harmless"):
            conn = http.client.HTTPConnection("127.0.0.1", sink.port, timeout=3)
            conn.request("POST", "/t", body=body)
            conn.getresponse().read()
            conn.close()
        assert wait_for(lambda: len(sink.hits([secret])) == 2)
        hits = sink.hits([secret])
    assert all(isinstance(h, SinkHit) for h in hits)
    assert hits[0] == SinkHit("POST", 2, len(f"x={secret}"), True)
    assert hits[1] == SinkHit("POST", 2, len(b"harmless"), False)


def test_udp_sink_records_datagram_metadata(canary: Callable[[], str]) -> None:
    secret = canary()
    with UdpSink() as sink:
        assert sink.port > 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(secret.encode(), ("127.0.0.1", sink.port))
            sock.sendto(b"noise", ("127.0.0.1", sink.port))
        assert wait_for(lambda: len(sink.hits([secret])) == 2)
        hits = sink.hits([secret])
    assert [(h.body_len, h.canary_hit) for h in hits] == [(len(secret), True), (5, False)]


# --- run_probes against a deterministic fake srt -------------------------------------------


def test_run_probes_all_denied(fake_srt: Callable[..., Any], tmp_path: Path) -> None:
    fake = fake_srt(default="deny")
    out = tmp_path / "out"
    rows = run_probes(out, srt=fake.path, now=now)

    assert [r["id"] for r in rows] == IDS
    for row in rows:
        assert set(row) == ROW_KEYS
        assert isinstance(row["match"], bool)
        assert isinstance(row["latency_ms"], (int, float))
    by_id = {r["id"]: r for r in rows}
    for pid in BLOCKED_IDS:
        assert by_id[pid]["outcome"] == "blocked", pid
        assert by_id[pid]["match"] is True, pid
    assert by_id["instruction-write"]["outcome"] == "blocked"
    assert by_id["instruction-write"]["match"] is False
    assert by_id["allowed-host-exfil"]["match"] is False

    lines = (out / "results.jsonl").read_text().splitlines()
    assert [json.loads(line)["id"] for line in lines] == IDS
    results_md = (out / "RESULTS.md").read_text()
    assert "0.0.79-fake" in results_md
    assert "2026-10-15" in results_md
    for column in ("id", "channel", "expect", "outcome", "match", "reason_code", "latency_ms"):
        assert column in results_md
    assert all(pid in results_md for pid in IDS)

    probe_events = [e for e in read_events(TODAY) if e.kind == "probe"]
    assert len(probe_events) == len(IDS)

    assert_no_canary_persisted(out, tmp_path / "state")
    # The fake HOME the floor protected (denyRead starts with ~/.ssh) is gone afterwards.
    deny_read = fake.records()[0]["settings"]["filesystem"]["denyRead"]
    assert deny_read[0].endswith("/.ssh")
    assert not Path(deny_read[0]).parent.exists()


def test_run_probes_leaky_floor(fake_srt: Callable[..., Any], tmp_path: Path) -> None:
    # Runs probe commands for real but never the pasteboard or a non-localhost host.
    fake = fake_srt(default="run", rules=[("pbcopy", "ok"), (".invalid", "deny")])
    out = tmp_path / "out"
    rows = run_probes(out, srt=fake.path, now=now)
    by_id = {r["id"]: r for r in rows}

    for pid in ("ssh-read", "env-read", "dotdot-escape"):
        assert by_id[pid]["outcome"] == "leaked", pid
        assert by_id[pid]["match"] is False, pid
    assert by_id["allowed-host-exfil"]["outcome"] == "leaked"
    assert by_id["allowed-host-exfil"]["match"] is True
    assert by_id["http-denied"]["outcome"] == "blocked"
    assert by_id["http-denied"]["match"] is True
    assert by_id["instruction-write"]["outcome"] == "allowed"
    assert by_id["instruction-write"]["match"] is True
    assert any(e.tier == "amber" and e.path_class == "instruction" for e in read_events(TODAY))
    assert_no_canary_persisted(out, tmp_path / "state")


def test_run_probes_unrecognised_failure_is_inconclusive(
    fake_srt: Callable[..., Any], tmp_path: Path
) -> None:
    fake = fake_srt(default="fail")
    rows = run_probes(tmp_path / "out", srt=fake.path, now=now)
    by_id = {r["id"]: r for r in rows}
    assert by_id["ssh-read"]["outcome"] == "inconclusive"
    assert by_id["ssh-read"]["match"] is False


# --- `agent-floor probe` exit codes --------------------------------------------------------


def _row(outcome: str, match: bool) -> dict[str, object]:
    return {
        "id": "x",
        "channel": "c",
        "expect": "blocked",
        "outcome": outcome,
        "match": match,
        "reason_code": None,
        "latency_ms": 1.0,
    }


@pytest.mark.parametrize(
    ("rows", "code"),
    [
        ([_row("blocked", True), _row("leaked", True)], 0),
        ([_row("blocked", True), _row("leaked", False)], 1),
        ([_row("blocked", True), _row("inconclusive", False)], 2),
        ([_row("inconclusive", False), _row("allowed", False)], 1),
    ],
    ids=["all-match", "mismatch", "inconclusive-only", "inconclusive-and-mismatch"],
)
def test_cli_probe_exit_codes(
    rows: list[dict[str, object]],
    code: int,
    fake_srt: Callable[..., Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_srt(default="deny")
    seen: list[Path] = []

    def fake_run_probes(out: Path, **_: object) -> list[dict[str, object]]:
        seen.append(out)
        return rows

    monkeypatch.setattr(probes_mod, "run_probes", fake_run_probes)
    monkeypatch.setattr(cli, "run_probes", fake_run_probes, raising=False)
    out = tmp_path / "probe-out"
    assert cli.main(["probe", "--out", str(out)]) == code
    assert seen == [out]


# --- the real pinned floor (T0 on the host; the reviewer runs it) --------------------------


@pytest.mark.floor
def test_real_srt_probe_suite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake_home: Path
) -> None:
    srt = REPO / "tools" / "node_modules" / ".bin" / "srt"
    monkeypatch.setenv("AGENT_FLOOR_SRT", str(srt))
    # Shadow the pasteboard tools so the real pasteboard is never touched.
    shim = tmp_path / "shim"
    shim.mkdir()
    for name, body in (("pbcopy", "cat >/dev/null"), ("pbpaste", "true")):
        (shim / name).write_text(f"#!/bin/sh\n{body}\n")
        (shim / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}{os.pathsep}{os.environ['PATH']}")
    out = tmp_path / "out"
    rows = run_probes(out, srt=srt, now=now)
    assert [r["id"] for r in rows] == IDS
    mismatches = [r["id"] for r in rows if not r["match"] and r["id"] != "pbcopy"]
    assert mismatches == []
    assert_no_canary_persisted(out, tmp_path / "state")
