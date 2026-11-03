"""Regression tests for review 2026-11-03 findings F4, F2 and the tlsTerminate guard."""

from collections.abc import Callable
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from agent_floor import run as run_module
from agent_floor.cli import main
from agent_floor.errors import PolicyError
from agent_floor.events import read_events
from agent_floor.policy import (
    INSTALL_ROOT,
    check_project_dirs,
    compile_srt,
    floor_paths,
    load_policy,
)
from agent_floor.run import run

TODAY = date(2026, 11, 3)


def now() -> datetime:
    return datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def rule(rule_id: str, tier: str, kind: str, pattern: str, extra: str = "") -> str:
    return (
        "[[rules]]\n"
        f'id = "{rule_id}"\n'
        f'tier = "{tier}"\n'
        f'kind = "{kind}"\n'
        f'pattern = "{pattern}"\n'
        "added = 2026-10-01\n"
        'reason = "review regression rule"\n'
        f"{extra}\n"
    )


# --- F4: an expired exception must not delete the rule it superseded ----------------------


def test_expired_exception_restores_superseded_deny(
    policy_file: Callable[..., Path], fake_home: Path
) -> None:
    path = policy_file(
        rule("deny-private", "black", "read", "~/private")
        + rule(
            "tmp-allow",
            "green",
            "read",
            "~/private",
            'supersedes = "deny-private"\nexpires = 2026-10-31',
        )
    )
    policy = load_policy(path, today=TODAY)
    assert [r.id for r in policy.rules] == ["deny-private"]
    fs = compile_srt(policy, home=fake_home)["filesystem"]
    assert isinstance(fs, dict)
    assert str(fake_home / "private") in fs["denyRead"]


def test_live_exception_still_supersedes(policy_file: Callable[..., Path]) -> None:
    path = policy_file(
        rule("deny-private", "black", "read", "~/private")
        + rule(
            "tmp-allow",
            "green",
            "read",
            "~/private",
            'supersedes = "deny-private"\nexpires = 2026-11-03',
        )
    )
    assert [r.id for r in load_policy(path, today=TODAY).rules] == ["tmp-allow"]


def test_expired_rule_with_unknown_supersedes_still_raises(
    policy_file: Callable[..., Path],
) -> None:
    path = policy_file(
        rule("old", "green", "net", "x.invalid", 'supersedes = "ghost"\nexpires = 2026-01-01')
    )
    with pytest.raises(PolicyError, match="unknown supersedes"):
        load_policy(path, today=TODAY)


# --- F2: a project dir may not contain the floor's own code, srt or policy ----------------


def test_floor_paths_cover_install_root_policy_dir_and_srt_package(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    (package / "dist").mkdir(parents=True)
    (package / "package.json").write_text("{}")
    cli = package / "dist" / "cli.js"
    cli.write_text("")
    link = tmp_path / "srt"
    link.symlink_to(cli)
    paths = floor_paths(tmp_path / "cfg" / "policy.toml", link)
    assert paths == (INSTALL_ROOT, (tmp_path / "cfg").resolve(), cli.resolve(), package.resolve())


@pytest.mark.parametrize("which", ["equal", "ancestor"])
def test_check_project_dirs_refuses_dir_holding_floor_path(tmp_path: Path, which: str) -> None:
    target = (tmp_path / "a" / "b").resolve()
    project = target if which == "equal" else target.parent
    with pytest.raises(PolicyError, match="floor path"):
        check_project_dirs([project], [target], home=tmp_path)


def test_check_project_dirs_allows_sibling_and_child(tmp_path: Path) -> None:
    target = (tmp_path / "a").resolve()
    check_project_dirs([tmp_path / "b", target / "child"], [target], home=tmp_path)


def test_run_refuses_project_dir_holding_install_root(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path]
) -> None:
    fake = fake_srt()
    path = policy_file(project_dirs=[str(INSTALL_ROOT.parent)])
    assert run(["true"], policy_path=path, now=now) == 3
    assert fake.records() == []
    events = read_events(TODAY)
    assert [(e.kind, e.reason_code) for e in events] == [("policy_error", "floor_path_writable")]


def test_run_refuses_project_dir_holding_policy(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path], tmp_path: Path
) -> None:
    fake = fake_srt()
    path = policy_file(project_dirs=[str(tmp_path)])
    assert run(["true"], policy_path=path, now=now) == 3
    assert fake.records() == []


def test_run_refuses_project_dir_holding_srt(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path]
) -> None:
    fake = fake_srt()
    path = policy_file(project_dirs=[str(fake.path.parent)])
    assert run(["true"], policy_path=path, now=now) == 3
    assert fake.records() == []


def test_run_still_runs_with_disjoint_project_dir(
    fake_srt: Callable[..., Any], policy_file: Callable[..., Path]
) -> None:
    fake = fake_srt(exit_code=0)
    assert run(["true"], policy_path=policy_file(), now=now) == 0
    assert len(fake.records()) == 1


def test_compile_denies_writes_to_floor_paths(
    policy_file: Callable[..., Path], fake_home: Path, tmp_path: Path
) -> None:
    path = policy_file(rule("no-keys", "black", "write", "~/keys"))
    floor = floor_paths(path)
    fs = compile_srt(load_policy(path, today=TODAY), home=fake_home, floor=floor)["filesystem"]
    assert isinstance(fs, dict)
    assert str(INSTALL_ROOT) in fs["denyWrite"]
    assert str((tmp_path / "config").resolve()) in fs["denyWrite"]
    assert fs["denyWrite"][-1] == str(fake_home / "keys")


def test_init_refuses_project_dir_holding_install_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["init", "--project-dir", str(INSTALL_ROOT.parent), "--cli", "claude"])
    assert code == 2
    assert "floor path" in capsys.readouterr().err
    assert not (tmp_path / "config" / "policy.toml").exists()


# --- tlsTerminate guard (srt 0.0.79 MITM path runs on node-forge 1.4.0) -------------------


def test_compile_never_emits_tls_terminate(
    policy_file: Callable[..., Path], fake_home: Path
) -> None:
    path = policy_file(
        rule("net-a", "green", "net", "example.invalid"),
        header_extra=(
            "allow_pty = true\nweaker_network_isolation = true\nallow_local_binding = true"
        ),
    )
    network = compile_srt(load_policy(path, today=TODAY), home=fake_home)["network"]
    assert isinstance(network, dict)
    assert "tlsTerminate" not in network


def test_run_refuses_settings_with_tls_terminate(
    fake_srt: Callable[..., Any],
    policy_file: Callable[..., Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = fake_srt()
    original = run_module.compile_srt

    def with_tls(*args: Any, **kwargs: Any) -> dict[str, object]:
        settings = original(*args, **kwargs)
        network = settings["network"]
        assert isinstance(network, dict)
        network["tlsTerminate"] = {}
        return settings

    monkeypatch.setattr(run_module, "compile_srt", with_tls)
    assert run(["true"], policy_path=policy_file(), now=now) == 3
    assert fake.records() == []
