"""Locked contract for P1: policy loading, validation, compilation to srt settings."""

import re
from collections.abc import Callable
from datetime import date
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_floor.errors import AgentFloorError, FloorUnavailableError, PolicyError
from agent_floor.policy import (
    INSTRUCTION_GLOBS,
    PROTECTED_WRITE,
    SECRET_READ,
    SYNC_DIRS,
    VENDOR_STATE_WRITE,
    Policy,
    Rule,
    classify_write,
    compile_srt,
    default_policy_path,
    load_policy,
    policy_hash,
)

TODAY = date(2026, 10, 15)


def rule(
    rid: str,
    tier: str,
    kind: str,
    pattern: str,
    *,
    extra: str = "",
) -> str:
    """Render one [[rules]] TOML table."""
    return (
        "[[rules]]\n"
        f'id = "{rid}"\n'
        f'tier = "{tier}"\n'
        f'kind = "{kind}"\n'
        f'pattern = "{pattern}"\n'
        "added = 2026-10-01\n"
        f'reason = "because the owner said so"\n'
        f"{extra}\n"
    )


def expand(pattern: str, home: Path) -> str:
    """The compile contract: a leading ~ is expanded against `home`, globs stay literal."""
    if pattern == "~":
        return str(home)
    if pattern.startswith("~/"):
        return str(home) + pattern[1:]
    return pattern


PolicyFactory = Callable[..., Path]


# --- constants (pure data; these pass from P0 on) ---------------------------------------


def test_errors_hierarchy() -> None:
    assert issubclass(PolicyError, AgentFloorError)
    assert issubclass(FloorUnavailableError, AgentFloorError)
    assert issubclass(AgentFloorError, Exception)


def test_protected_write_contents() -> None:
    assert PROTECTED_WRITE == (
        "~/.config/agent-floor",
        "~/.claude/settings.json",
        "~/.claude/settings.local.json",
        "~/.claude/hooks",
        "~/.codex/config.toml",
        "~/.gemini/settings.json",
        "**/.claude/settings*.json",
        "**/.mcp.json",
        "**/.git/hooks",
        "~/.zshrc",
        "~/.bashrc",
        "~/.profile",
        "~/Library/LaunchAgents",
    )


def test_vendor_state_write_contents() -> None:
    assert VENDOR_STATE_WRITE == (
        "~/.claude",
        "~/.claude.json",
        "~/.claude.json.lock",
        "~/.codex",
        "~/.gemini/antigravity",
        "~/.gemini/antigravity-cli",
    )


def test_secret_read_sync_and_instruction_contents() -> None:
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
    assert SYNC_DIRS == (
        "~/Library/Mobile Documents",
        "~/Library/CloudStorage",
        "~/Google Drive",
        "~/Dropbox",
    )
    assert INSTRUCTION_GLOBS == (
        "**/AGENTS.md",
        "**/CLAUDE.md",
        "**/GEMINI.md",
        "**/.agents/skills/**",
        "**/.claude/skills/**",
        "**/memory/**",
        "**/plans/**/*.md*",
    )


def test_rule_model_rejects_bad_id_short_reason_and_extra_keys() -> None:
    good = {
        "id": "gh-api",
        "tier": "amber",
        "kind": "net",
        "pattern": "api.github.com",
        "added": TODAY,
        "reason": "release notes",
    }
    assert Rule(**good).supersedes is None
    with pytest.raises(ValidationError):
        Rule(**{**good, "id": "GH"})
    with pytest.raises(ValidationError):
        Rule(**{**good, "reason": "short"})
    with pytest.raises(ValidationError):
        Rule(**{**good, "note": "free text is not allowed"})
    with pytest.raises(ValidationError):
        Policy(version=2, project_dirs=[], env_allow=[], rules=[])  # type: ignore[arg-type]


# --- default_policy_path -----------------------------------------------------------------


def test_default_policy_path_honours_env(tmp_path: Path) -> None:
    assert default_policy_path() == tmp_path / "config" / "policy.toml"


def test_default_policy_path_falls_back_to_home(
    fake_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AGENT_FLOOR_CONFIG")
    assert default_policy_path() == fake_home / ".config" / "agent-floor" / "policy.toml"


# --- load_policy ---------------------------------------------------------------------------


def test_load_valid_policy(policy_file: PolicyFactory, fake_home: Path) -> None:
    path = policy_file(rule("gh-api", "amber", "net", "api.github.com"), env_allow=["EDITOR"])
    policy = load_policy(path, today=TODAY)
    assert policy.version == 1
    assert policy.env_allow == ["EDITOR"]
    assert [r.id for r in policy.rules] == ["gh-api"]
    assert policy.weaker_network_isolation is False
    assert policy.allow_local_binding is False


def test_load_missing_file_raises_policy_error(tmp_path: Path) -> None:
    missing = tmp_path / "nope.toml"
    with pytest.raises(PolicyError, match=re.escape(str(missing))):
        load_policy(missing, today=TODAY)


def test_load_bad_toml_raises_policy_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("version = = 1\n")
    with pytest.raises(PolicyError, match=re.escape(str(bad))):
        load_policy(bad, today=TODAY)


@pytest.mark.parametrize(
    "rules",
    [
        rule("BAD_ID", "green", "net", "example.invalid"),
        rule("ok-id", "purple", "net", "example.invalid"),
        rule("ok-id", "green", "exec", "example.invalid"),
        rule("ok-id", "green", "net", "example.invalid", extra='note = "free text"'),
        rule("ok-id", "green", "net", "example.invalid").replace(
            "because the owner said so", "short"
        ),
    ],
    ids=["bad-id", "bad-tier", "bad-kind", "extra-key", "short-reason"],
)
def test_load_invalid_rule_raises_policy_error(policy_file: PolicyFactory, rules: str) -> None:
    path = policy_file(rules)
    with pytest.raises(PolicyError, match=re.escape(str(path))):
        load_policy(path, today=TODAY)


def test_load_wrong_version_raises_policy_error(policy_file: PolicyFactory) -> None:
    path = policy_file()
    path.write_text(path.read_text().replace("version = 1", "version = 2"))
    with pytest.raises(PolicyError):
        load_policy(path, today=TODAY)


def test_expired_rules_are_dropped_and_today_is_still_live(policy_file: PolicyFactory) -> None:
    path = policy_file(
        rule("old-rule", "green", "net", "old.invalid", extra="expires = 2026-10-14")
        + rule("edge-rule", "green", "net", "edge.invalid", extra="expires = 2026-10-15")
        + rule("open-rule", "green", "net", "open.invalid")
    )
    policy = load_policy(path, today=TODAY)
    assert [r.id for r in policy.rules] == ["edge-rule", "open-rule"]


def test_conflicting_tiers_raise(policy_file: PolicyFactory) -> None:
    path = policy_file(
        rule("allow-x", "green", "net", "x.invalid") + rule("deny-x", "black", "net", "x.invalid")
    )
    with pytest.raises(PolicyError, match=r"conflict: ") as info:
        load_policy(path, today=TODAY)
    assert "allow-x" in str(info.value)
    assert "deny-x" in str(info.value)


def test_same_pattern_different_kind_is_not_a_conflict(policy_file: PolicyFactory) -> None:
    path = policy_file(
        rule("read-x", "black", "read", "~/x") + rule("write-x", "green", "write", "~/x")
    )
    assert len(load_policy(path, today=TODAY).rules) == 2


def test_supersedes_resolves_conflict_and_drops_superseded(policy_file: PolicyFactory) -> None:
    path = policy_file(
        rule("allow-x", "green", "net", "x.invalid")
        + rule("deny-x", "black", "net", "x.invalid", extra='supersedes = "allow-x"')
    )
    policy = load_policy(path, today=TODAY)
    assert [r.id for r in policy.rules] == ["deny-x"]


def test_expired_rule_cannot_conflict(policy_file: PolicyFactory) -> None:
    path = policy_file(
        rule("allow-x", "green", "net", "x.invalid", extra="expires = 2026-09-01")
        + rule("deny-x", "black", "net", "x.invalid")
    )
    assert [r.id for r in load_policy(path, today=TODAY).rules] == ["deny-x"]


def test_unknown_supersedes_raises(policy_file: PolicyFactory) -> None:
    path = policy_file(rule("deny-x", "black", "net", "x.invalid", extra='supersedes = "ghost"'))
    with pytest.raises(PolicyError, match="ghost"):
        load_policy(path, today=TODAY)


# --- compile_srt ---------------------------------------------------------------------------


def _compile(policy_file: PolicyFactory, fake_home: Path, rules: str = "", **kw: object) -> dict:
    policy = load_policy(policy_file(rules, **kw), today=TODAY)
    return compile_srt(policy, home=fake_home)


def test_compile_keys_and_order(policy_file: PolicyFactory, fake_home: Path) -> None:
    out = _compile(policy_file, fake_home)
    assert set(out) == {"filesystem", "network", "enableWeakerNetworkIsolation"}
    assert list(out["filesystem"]) == ["denyRead", "allowRead", "allowWrite", "denyWrite"]
    assert list(out["network"]) == [
        "allowedDomains",
        "deniedDomains",
        "allowLocalBinding",
        "deniedDomainReasons",
    ]


def test_compile_empty_policy_has_builtins(policy_file: PolicyFactory, fake_home: Path) -> None:
    out = _compile(policy_file, fake_home)
    fs = out["filesystem"]
    assert fs["denyRead"] == [expand(p, fake_home) for p in SECRET_READ]
    assert fs["allowRead"] == []
    assert fs["allowWrite"] == [
        str((fake_home / "project").resolve()),
        "/tmp",
        "/private/tmp",
        *[expand(p, fake_home) for p in VENDOR_STATE_WRITE],
    ]
    assert fs["denyWrite"] == [expand(p, fake_home) for p in (*PROTECTED_WRITE, *SYNC_DIRS)]
    net = out["network"]
    assert net["allowedDomains"] == []
    assert net["deniedDomains"] == []
    assert net["deniedDomainReasons"] == {}
    assert net["allowLocalBinding"] is False
    assert out["enableWeakerNetworkIsolation"] is False


def test_compile_rules_land_in_the_right_lists(policy_file: PolicyFactory, fake_home: Path) -> None:
    rules = (
        rule("deny-notes", "black", "read", "~/notes")
        + rule("red-read", "red", "read", "**/secrets.txt")
        + rule("green-read", "green", "read", "~/ok-to-read")
        + rule("gen-out", "green", "write", "~/gen-out")
        + rule("amb-out", "amber", "write", "**/scratch")
        + rule("no-keys", "black", "write", "~/keys")
        + rule("red-write", "red", "write", "**/vault")
    )
    fs = _compile(policy_file, fake_home, rules)["filesystem"]
    assert fs["denyRead"] == [
        *[expand(p, fake_home) for p in SECRET_READ],
        str(fake_home) + "/notes",
        "**/secrets.txt",
    ]
    assert fs["allowRead"] == []
    assert fs["allowWrite"][-2:] == [str(fake_home) + "/gen-out", "**/scratch"]
    assert fs["denyWrite"][-2:] == [str(fake_home) + "/keys", "**/vault"]


def test_compile_network_lists(policy_file: PolicyFactory, fake_home: Path) -> None:
    rules = (
        rule("gh-api", "amber", "net", "api.github.com")
        + rule("pypi", "green", "net", "pypi.org")
        + rule("gh-api-two", "amber", "net", "api.github.com")
        + rule("bad-host", "red", "net", "paste.invalid")
        + rule("worse-host", "black", "net", "drop.invalid")
    )
    net = _compile(policy_file, fake_home, rules)["network"]
    assert net["allowedDomains"] == ["api.github.com", "pypi.org"]
    assert net["deniedDomains"] == ["paste.invalid", "drop.invalid"]
    assert set(net["deniedDomainReasons"]) == {"paste.invalid", "drop.invalid"}
    assert net["deniedDomainReasons"]["paste.invalid"] == (
        "agent-floor red: because the owner said so (rule bad-host); ask the owner"
    )


def test_compile_protected_write_wins_over_policy_allow(
    policy_file: PolicyFactory, fake_home: Path
) -> None:
    fs = _compile(
        policy_file, fake_home, rule("open-settings", "green", "write", "~/.claude/settings.json")
    )["filesystem"]
    assert str(fake_home) + "/.claude/settings.json" in fs["denyWrite"]


def test_compile_instruction_files_stay_writable(
    policy_file: PolicyFactory, fake_home: Path
) -> None:
    fs = _compile(policy_file, fake_home)["filesystem"]
    for glob in INSTRUCTION_GLOBS:
        assert glob not in fs["denyWrite"]


def test_compile_resolves_and_expands_project_dirs(
    policy_file: PolicyFactory, fake_home: Path
) -> None:
    (fake_home / "other").mkdir()
    dirs = [str(fake_home / "project" / ".." / "project"), "~/other"]
    fs = _compile(policy_file, fake_home, project_dirs=dirs)["filesystem"]
    assert fs["allowWrite"][:2] == [
        str((fake_home / "project").resolve()),
        str((fake_home / "other").resolve()),
    ]


def test_compile_emits_opt_in_network_flags(policy_file: PolicyFactory, fake_home: Path) -> None:
    out = _compile(
        policy_file,
        fake_home,
        header_extra="weaker_network_isolation = true\nallow_local_binding = true\n",
    )
    assert out["enableWeakerNetworkIsolation"] is True
    assert out["network"]["allowLocalBinding"] is True


# --- classify_write ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        (".zshrc", "protected"),
        ("project/.mcp.json", "protected"),
        ("project/.claude/settings.local.json", "protected"),
        ("project/.git/hooks", "protected"),
        ("Dropbox", "sync"),
        ("Library/Mobile Documents", "sync"),
        ("project/AGENTS.md", "instruction"),
        ("project/.claude/skills/x/SKILL.md", "instruction"),
        ("project/plans/p/plan.mdx", "instruction"),
        ("project/src/main.py", "normal"),
        # In both protected and instruction globs: protected is checked first.
        ("project/memory/.mcp.json", "protected"),
    ],
)
def test_classify_write(fake_home: Path, rel: str, expected: str) -> None:
    assert classify_write(fake_home / rel) == expected


# --- policy_hash ---------------------------------------------------------------------------


def test_policy_hash_is_stable_short_hex_and_sensitive(
    policy_file: PolicyFactory, tmp_path: Path
) -> None:
    a = load_policy(policy_file(rule("gh-api", "amber", "net", "api.github.com")), today=TODAY)
    b = load_policy(
        policy_file(rule("gh-api", "amber", "net", "api.github.com"), path=tmp_path / "copy.toml"),
        today=TODAY,
    )
    c = load_policy(
        policy_file(rule("gh-api", "green", "net", "api.github.com"), path=tmp_path / "c.toml"),
        today=TODAY,
    )
    assert re.fullmatch(r"[0-9a-f]{16}", policy_hash(a))
    assert policy_hash(a) == policy_hash(b)
    assert policy_hash(a) != policy_hash(c)
