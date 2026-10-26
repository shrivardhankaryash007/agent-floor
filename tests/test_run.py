"""Locked contract for P2: fail-closed `run`, env scrubbing, srt discovery and the CLI."""

import json
import re
from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from agent_floor.cli import main
from agent_floor.errors import FloorUnavailableError
from agent_floor.events import read_events
from agent_floor.policy import compile_srt, load_policy, policy_hash
from agent_floor.run import (
    ENV_ALWAYS,
    ENV_NEVER,
    ENV_NEVER_PREFIXES,
    VENDOR_ENV_EXCEPTIONS,
    find_srt,
    run,
    scrub_env,
)

NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
TODAY = date(2026, 10, 15)
TS = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")


def now() -> datetime:
    return NOW


# --- constants -----------------------------------------------------------------------------


def test_env_constants() -> None:
    assert ENV_ALWAYS == (
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "TERM",
        "LANG",
        "LC_ALL",
        "TMPDIR",
        "COLORTERM",
    )
    assert ENV_NEVER_PREFIXES == ("AWS_",)
    for name in ("GITHUB_TOKEN", "my_secret", "OPENAI_API_KEY", "PGPASSWORD", "AUTH_HEADER"):
        assert ENV_NEVER.search(name)
    assert not ENV_NEVER.search("EDITOR")


def test_vendor_exception_pins_exactly_one_name() -> None:
    assert VENDOR_ENV_EXCEPTIONS == ("CLAUDE_CODE_OAUTH_TOKEN",)


def test_token_passes_only_when_allowed_and_excepted() -> None:
    name = "CLAUDE_CODE_OAUTH_TOKEN"
    assert scrub_env({name: "FAKE-x"}, allow=[name]) == {name: "FAKE-x"}


def test_token_dropped_when_not_in_allow() -> None:
    name = "CLAUDE_CODE_OAUTH_TOKEN"
    assert scrub_env({name: "FAKE-x"}, allow=[]) == {}


def test_other_token_like_names_still_dropped_even_if_allowed() -> None:
    names = (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "CLAUDE_CODE_OAUTH_TOKEN_2",
        "claude_code_oauth_token",
        "AWS_SECRET_ACCESS_KEY",
        "MY_SESSION_COOKIE",
    )
    env = {name: "FAKE-x" for name in names}
    assert scrub_env(env, allow=names) == {}


def test_env_never_regex_and_prefixes_unchanged() -> None:
    assert (
        ENV_NEVER.pattern
        == r"(?i)(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE|SESSION)"
    )
    assert ENV_NEVER_PREFIXES == ("AWS_",)


def test_secret_read_set_unchanged() -> None:
    from agent_floor.policy import SECRET_READ

    assert SECRET_READ == (
        "~/.ssh",
        "~/.aws",
        "~/.config/gh",
        "~/.netrc",
        "~/.zsh_history",
        "~/.bash_history",
        "~/.docker/config.json",
        "~/.npmrc",
        "~/.pypirc",
        "**/.env",
        "**/.env.*",
    )


# --- scrub_env -----------------------------------------------------------------------------


def test_scrub_env_keeps_always_and_allowed_only() -> None:
    env = {
        "PATH": "/usr/bin",
        "HOME": "/h",
        "TERM": "xterm",
        "EDITOR": "vi",
        "PAGER": "less",
        "SSH_AUTH_SOCK": "/s",
    }
    assert scrub_env(env, ["EDITOR"]) == {
        "PATH": "/usr/bin",
        "HOME": "/h",
        "TERM": "xterm",
        "EDITOR": "vi",
    }


def test_scrub_env_allow_cannot_override_never() -> None:
    env = {
        "PATH": "/usr/bin",
        "GITHUB_TOKEN": "x",
        "my_api_key": "x",
        "AWS_REGION": "x",
        "SESSION_ID": "x",
        "BROWSER_COOKIE": "x",
    }
    allow = ["GITHUB_TOKEN", "my_api_key", "AWS_REGION", "SESSION_ID", "BROWSER_COOKIE"]
    assert scrub_env(env, allow) == {"PATH": "/usr/bin"}


def test_scrub_env_does_not_invent_missing_names() -> None:
    assert scrub_env({}, ["EDITOR"]) == {}


# --- find_srt ------------------------------------------------------------------------------


def test_find_srt_uses_env(fake_srt: Callable[..., Any]) -> None:
    fake = fake_srt()
    assert find_srt() == fake.path


def test_find_srt_env_path_missing_fails_closed() -> None:
    # The autouse fixture points AGENT_FLOOR_SRT at a path that does not exist.
    with pytest.raises(FloorUnavailableError):
        find_srt()


def test_find_srt_version_failure_fails_closed(fake_srt: Callable[..., Any]) -> None:
    fake_srt(version_exit=1)
    with pytest.raises(FloorUnavailableError):
        find_srt()


# --- run -----------------------------------------------------------------------------------


def test_run_invokes_srt_with_settings_and_returns_child_code(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path], fake_home: Path
) -> None:
    fake = fake_srt(exit_code=7)
    path = policy_file()
    code = run(["claude", "-p", "say ok"], policy_path=path, now=now)
    assert code == 7
    (rec,) = fake.records()
    argv = rec["argv"]
    assert argv[0] == str(fake.path)
    assert argv[1] == "--settings"
    assert argv[3] == "--"
    assert argv[4:] == ["claude", "-p", "say ok"]
    expected = compile_srt(load_policy(path, today=TODAY), home=fake_home)
    assert rec["settings"] == json.loads(json.dumps(expected))
    assert rec["settings_mode"] == 0o600
    assert not Path(argv[2]).exists()


def test_run_executes_child_and_passes_stdout_through(
    fake_srt: Callable[..., Any],
    policy_file: Callable[..., Path],
    capfd: pytest.CaptureFixture[str],
) -> None:
    fake_srt()
    code = run(["sh", "-c", "echo floor-out; exit 4"], policy_path=policy_file(), now=now)
    assert code == 4
    assert "floor-out" in capfd.readouterr().out


def test_run_deletes_settings_file_when_child_fails(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path]
) -> None:
    fake = fake_srt(default="fail")
    assert run(["true"], policy_path=policy_file(), now=now) == 1
    (rec,) = fake.records()
    assert not Path(rec["argv"][2]).exists()


def test_run_scrubs_env(
    fake_srt: Callable[..., Any],
    policy_file: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = fake_srt(exit_code=0)
    monkeypatch.setenv("GITHUB_TOKEN", "fake-not-a-token")
    monkeypatch.setenv("AWS_PROFILE", "fake")
    monkeypatch.setenv("EDITOR", "vi")
    monkeypatch.setenv("PAGER", "less")
    run(["true"], policy_path=policy_file(env_allow=["EDITOR", "GITHUB_TOKEN"]), now=now)
    keys = set(fake.records()[0]["env_keys"])
    assert {"PATH", "HOME", "EDITOR"} <= keys
    assert not keys & {"GITHUB_TOKEN", "AWS_PROFILE", "PAGER"}


def test_run_records_metadata_only_events(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path]
) -> None:
    fake_srt(exit_code=5)
    path = policy_file()
    run(["true"], policy_path=path, now=now)
    events = read_events(TODAY)
    assert [e.kind for e in events] == ["run_start", "run_end"]
    start, end = events
    assert start.run_id == end.run_id
    assert start.policy_hash == policy_hash(load_policy(path, today=TODAY))
    assert end.exit_code == 5
    assert end.latency_ms is not None
    assert end.latency_ms >= 0
    assert all(TS.match(e.ts) for e in events)


def test_run_invalid_policy_runs_nothing(
    fake_srt: Callable[..., Any], tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    fake = fake_srt()
    code = run(["true"], policy_path=tmp_path / "missing.toml", now=now)
    assert code == 3
    err = capfd.readouterr().err
    assert "agent-floor: policy invalid:" in err
    assert "nothing was run" in err
    assert fake.records() == []
    assert [e.kind for e in read_events(TODAY)] == ["policy_error"]


def test_run_without_srt_fails_closed_and_never_runs_cmd(
    policy_file: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    marker = tmp_path / "marker"
    cmd = bin_dir / "fake-cmd"
    cmd.write_text(f"#!/bin/sh\ntouch {marker}\n")
    cmd.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    code = run(["fake-cmd"], policy_path=policy_file(), now=now)
    assert code == 3
    assert not marker.exists()
    err = capfd.readouterr().err
    assert "refusing to run unsandboxed (fail-closed)" in err
    assert "npm ci --ignore-scripts" in err
    assert [e.kind for e in read_events(TODAY)] == ["floor_missing"]


def test_run_with_broken_srt_fails_closed(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path]
) -> None:
    fake = fake_srt(version_exit=2)
    assert run(["true"], policy_path=policy_file(), now=now) == 3
    assert fake.records() == []


# --- cli -----------------------------------------------------------------------------------


def test_cli_run_passes_command_after_double_dash(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path]
) -> None:
    fake = fake_srt()
    policy_file()
    assert main(["run", "--", "sh", "-c", "exit 6"]) == 6
    assert fake.records()[0]["argv"][4:] == ["sh", "-c", "exit 6"]


def test_cli_run_without_srt_returns_3(policy_file: Callable[..., Path]) -> None:
    policy_file()
    assert main(["run", "--", "true"]) == 3


def test_cli_doctor_reports_versions(
    fake_srt: Callable[..., Any],
    policy_file: Callable[..., Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake_srt()
    path = policy_file()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    claude = bin_dir / "claude"
    claude.write_text("#!/bin/sh\necho 9.9.9-fake\n")
    claude.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert set(report) == {"srt", "policy_hash", "clis"}
    assert "0.0.79-fake" in report["srt"]
    assert report["policy_hash"] == policy_hash(load_policy(path, today=date.today()))
    assert set(report["clis"]) == {"claude", "codex", "agy"}
    assert isinstance(report["clis"]["claude"], str)
    assert report["clis"]["codex"] is None
    assert report["clis"]["agy"] is None


def test_cli_doctor_without_policy_returns_3(
    fake_srt: Callable[..., Any], capsys: pytest.CaptureFixture[str]
) -> None:
    fake_srt()
    assert main(["doctor"]) == 3
    report = json.loads(capsys.readouterr().out)
    assert report["policy_hash"] is None


def test_cli_doctor_without_srt_returns_3(
    policy_file: Callable[..., Path], capsys: pytest.CaptureFixture[str]
) -> None:
    policy_file()
    assert main(["doctor"]) == 3
    assert json.loads(capsys.readouterr().out)["srt"] is None
