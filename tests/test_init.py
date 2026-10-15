"""`agent-floor init`: first run writes a valid policy, installs srt, never clobbers."""

import io
import subprocess
from collections.abc import Callable
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from agent_floor import cli
from agent_floor.errors import FloorUnavailableError
from agent_floor.init import (
    SUPPORTED_CLIS,
    detect_clis,
    ensure_srt,
    render_policy,
    run_init,
)
from agent_floor.policy import compile_srt, load_policy

TODAY = date(2026, 10, 15)


def _domains(policy_text: str, tmp_path: Path) -> list[str]:
    """Load rendered policy text and return the compiled allowed domains."""
    path = tmp_path / "policy.toml"
    path.write_text(policy_text)
    network = compile_srt(load_policy(path, today=TODAY), home=tmp_path)["network"]
    assert isinstance(network, dict)
    return list(network["allowedDomains"])


def test_supported_clis_order() -> None:
    """Detection order is fixed so output is reproducible."""
    assert SUPPORTED_CLIS == ("claude", "codex", "agy")


def test_detect_clis_uses_which_in_supported_order() -> None:
    """Only CLIs `which` resolves are returned, in SUPPORTED_CLIS order."""
    found = {"agy": "/x/agy", "claude": "/x/claude"}
    assert detect_clis(which=lambda name: found.get(name)) == ["claude", "agy"]
    assert detect_clis(which=lambda name: None) == []


def test_render_claude_only(tmp_path: Path) -> None:
    """Claude alone: its hosts, no codex/agy hosts, both residual flags off, pty on."""
    text = render_policy([tmp_path], ["claude"], today=TODAY)
    domains = _domains(text, tmp_path)
    assert "api.anthropic.com" in domains
    assert "claude.ai" in domains
    assert "chatgpt.com" not in domains
    assert "*.googleusercontent.com" not in domains
    policy = load_policy(tmp_path / "policy.toml", today=TODAY)
    assert policy.allow_pty is True
    assert policy.weaker_network_isolation is False
    assert policy.allow_local_binding is False


def test_render_all_three_sets_s1_flags_and_hosts(tmp_path: Path) -> None:
    """S1: codex needs weaker network isolation, agy needs local binding plus Google hosts."""
    text = render_policy([tmp_path], ["claude", "codex", "agy"], today=TODAY)
    domains = _domains(text, tmp_path)
    for host in (
        "api.openai.com",
        "chatgpt.com",
        "auth.openai.com",
        "*.googleusercontent.com",
        "*.gstatic.com",
    ):
        assert host in domains
    policy = load_policy(tmp_path / "policy.toml", today=TODAY)
    assert policy.weaker_network_isolation is True
    assert policy.allow_local_binding is True


def test_render_codex_alone_does_not_enable_agy_flag(tmp_path: Path) -> None:
    """Each residual flag is on only for the CLI that needs it."""
    text = render_policy([tmp_path], ["codex"], today=TODAY)
    _domains(text, tmp_path)
    policy = load_policy(tmp_path / "policy.toml", today=TODAY)
    assert policy.weaker_network_isolation is True
    assert policy.allow_local_binding is False


def test_render_rejects_unknown_cli_and_empty_list(tmp_path: Path) -> None:
    """An unknown CLI name or an empty list is a ValueError, never a silent empty policy."""
    with pytest.raises(ValueError, match="cursor"):
        render_policy([tmp_path], ["cursor"], today=TODAY)
    with pytest.raises(ValueError, match="at least one"):
        render_policy([tmp_path], [], today=TODAY)


def test_render_home_relative_and_absolute_project_dirs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dirs under HOME become ~/..., others stay absolute; both survive a TOML round trip."""
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    outside = tmp_path / "other" / 'we"ird'
    outside.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    text = render_policy([home / "code", outside], ["claude"], today=TODAY)
    path = tmp_path / "policy.toml"
    path.write_text(text)
    policy = load_policy(path, today=TODAY)
    assert policy.project_dirs == [Path("~/code"), outside]


def test_ensure_srt_noop_when_present() -> None:
    """A working srt means npm is never run."""
    calls: list[list[str]] = []

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    assert ensure_srt(Path("/t"), find=lambda: Path("/srt"), runner=runner, which=lambda n: "/npm")
    assert calls == []


def test_ensure_srt_installs_pinned_deps_then_rechecks(tmp_path: Path) -> None:
    """Missing srt: `npm ci --ignore-scripts` in tools/, then find again."""
    seen: dict[str, Any] = {"argv": None, "cwd": None, "finds": 0}

    def find() -> Path:
        seen["finds"] += 1
        if seen["argv"] is None:
            raise FloorUnavailableError("srt unavailable")
        return Path("/srt")

    def runner(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen["argv"], seen["cwd"] = argv, kwargs.get("cwd")
        return subprocess.CompletedProcess(argv, 0)

    assert ensure_srt(tmp_path, find=find, runner=runner, which=lambda n: "/usr/bin/npm")
    assert seen["argv"] == ["/usr/bin/npm", "ci", "--ignore-scripts"]
    assert Path(seen["cwd"]) == tmp_path
    assert seen["finds"] == 2


def test_ensure_srt_false_without_npm_or_on_failure(tmp_path: Path) -> None:
    """No npm, a failing npm, or srt still missing afterwards: False, never an exception."""

    def missing() -> Path:
        raise FloorUnavailableError("srt unavailable")

    def failing(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 1)

    def passing(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0)

    assert not ensure_srt(tmp_path, find=missing, runner=passing, which=lambda n: None)
    assert not ensure_srt(tmp_path, find=missing, runner=failing, which=lambda n: "/npm")
    assert not ensure_srt(tmp_path, find=missing, runner=passing, which=lambda n: "/npm")


def _init(
    tmp_path: Path, clis: list[str], doctor: Callable[[], int], order: list[str] | None = None
) -> tuple[int, str, Path]:
    config = tmp_path / "cfg" / "policy.toml"
    out = io.StringIO()

    def srt() -> bool:
        if order is not None:
            order.append("srt")
        return True

    def wrapped_doctor() -> int:
        if order is not None:
            order.append("doctor")
        return doctor()

    code = run_init(
        [tmp_path],
        clis,
        config_path=config,
        today=TODAY,
        ensure_srt=srt,
        doctor=wrapped_doctor,
        out=out,
    )
    return code, out.getvalue(), config


def test_run_init_writes_private_policy_installs_then_doctors(tmp_path: Path) -> None:
    """New policy: mode 0600, parent created, srt step before doctor, doctor's code returned."""
    order: list[str] = []
    code, text, config = _init(tmp_path, ["claude", "codex"], lambda: 0, order)
    assert code == 0
    assert order == ["srt", "doctor"]
    assert config.stat().st_mode & 0o777 == 0o600
    load_policy(config, today=TODAY)
    assert str(config) in text
    assert "agent-floor run -- claude" in text
    assert "agent-floor run -- codex -s danger-full-access" in text


def test_run_init_never_overwrites_existing_policy(tmp_path: Path) -> None:
    """An existing policy is left byte-identical; doctor still runs and its code wins."""
    config = tmp_path / "cfg" / "policy.toml"
    config.parent.mkdir()
    config.write_text("# owner wrote this\n")
    code, text, _ = _init(tmp_path, ["claude"], lambda: 3)
    assert code == 3
    assert config.read_text() == "# owner wrote this\n"
    assert "unchanged" in text


def test_run_init_reports_srt_failure_but_still_runs_doctor(tmp_path: Path) -> None:
    """A failed srt install is reported with the manual fix; doctor decides the exit code."""
    config = tmp_path / "cfg" / "policy.toml"
    out = io.StringIO()
    order: list[str] = []
    code = run_init(
        [tmp_path],
        ["claude"],
        config_path=config,
        today=TODAY,
        ensure_srt=lambda: False,
        doctor=lambda: order.append("doctor") or 3,  # type: ignore[func-returns-value]
        out=out,
    )
    assert code == 3
    assert order == ["doctor"]
    assert "npm ci --ignore-scripts" in out.getvalue()


@pytest.fixture
def fake_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Fake HOME and config dir; srt install and doctor stubbed so no network or real srt."""
    home = tmp_path / "home"
    work = home / "code" / "proj"
    work.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENT_FLOOR_CONFIG", str(tmp_path / "cfg"))
    monkeypatch.setattr(cli, "_ensure_srt", lambda: True)
    monkeypatch.setattr(cli, "_doctor", lambda: 0)
    monkeypatch.chdir(work)
    return work


def test_cli_init_defaults_to_cwd_parent(fake_env: Path, tmp_path: Path) -> None:
    """No --project-dir and no tty: the project dir is cwd's parent."""
    assert cli.main(["init", "--cli", "claude"]) == 0
    policy = load_policy(tmp_path / "cfg" / "policy.toml", today=date.today())
    assert policy.project_dirs == [Path("~/code")]


def test_cli_init_explicit_project_dir(fake_env: Path, tmp_path: Path) -> None:
    """--project-dir is repeatable and used verbatim."""
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    assert (
        cli.main(["init", "--cli", "claude", "--project-dir", str(a), "--project-dir", str(b)]) == 0
    )
    policy = load_policy(tmp_path / "cfg" / "policy.toml", today=date.today())
    assert policy.project_dirs == [a, b]


def test_cli_init_rejects_missing_project_dir(fake_env: Path, tmp_path: Path) -> None:
    """A project dir that does not exist is a usage error (2) and writes nothing."""
    code = cli.main(["init", "--cli", "claude", "--project-dir", str(tmp_path / "nope")])
    assert code == 2
    assert not (tmp_path / "cfg" / "policy.toml").exists()


def test_cli_init_without_any_cli_is_usage_error(
    fake_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing on PATH and no --cli: exit 2, nothing written, message names the fix."""
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert cli.main(["init"]) == 2
    assert not (tmp_path / "cfg" / "policy.toml").exists()


def test_cli_init_detects_from_path(
    fake_env: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no --cli, CLIs found on PATH drive the policy."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("codex",):
        exe = bin_dir / name
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
    monkeypatch.setenv("PATH", str(bin_dir))
    assert cli.main(["init"]) == 0
    policy = load_policy(tmp_path / "cfg" / "policy.toml", today=date.today())
    assert policy.weaker_network_isolation is True


def test_install_docs_exist_and_are_linked() -> None:
    """INSTALL-FOR-AGENTS.md has the exact commands and both entry docs point at it."""
    repo = Path(__file__).resolve().parents[1]
    guide = (repo / "docs" / "INSTALL-FOR-AGENTS.md").read_text()
    for needle in ("uv sync", "agent-floor init", "agent-floor doctor", "agent-floor probe"):
        assert needle in guide
    assert "INSTALL-FOR-AGENTS.md" in (repo / "AGENTS.md").read_text()
    assert "INSTALL-FOR-AGENTS.md" in (repo / "README.md").read_text()
