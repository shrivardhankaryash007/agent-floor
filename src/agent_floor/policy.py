"""Owner policy: load the tiered TOML, add built-in protections and compile srt settings."""

import hashlib
import json
import os
import tomllib
from datetime import date
from fnmatch import fnmatch
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from agent_floor.errors import PolicyError

Tier = Literal["green", "amber", "red", "black"]
Kind = Literal["read", "write", "net"]
WriteClass = Literal["protected", "instruction", "sync", "normal"]

# Always denied for writes, whatever the policy says; srt lets denyWrite win over allowWrite.
PROTECTED_WRITE: tuple[str, ...] = (
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

# S1: the vendor CLIs hang or exit 1 unless their state dirs are writable.
VENDOR_STATE_WRITE: tuple[str, ...] = (
    "~/.claude",
    "~/.claude.json",
    "~/.claude.json.lock",
    "~/.codex",
    "~/.gemini/antigravity",
    "~/.gemini/antigravity-cli",
)

SECRET_READ: tuple[str, ...] = (
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

# Sync clients upload whatever lands here, so a write is an exfil channel.
SYNC_DIRS: tuple[str, ...] = (
    "~/Library/Mobile Documents",
    "~/Library/CloudStorage",
    "~/Google Drive",
    "~/Dropbox",
)

INSTRUCTION_GLOBS: tuple[str, ...] = (
    "**/AGENTS.md",
    "**/CLAUDE.md",
    "**/GEMINI.md",
    "**/.agents/skills/**",
    "**/.claude/skills/**",
    "**/memory/**",
    "**/plans/**/*.md*",
)


class Rule(BaseModel):
    """One owner rule: a tiered read, write or network pattern."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9-]{3,40}$")
    tier: Tier
    kind: Kind
    pattern: str
    added: date
    reason: str = Field(min_length=8)
    supersedes: str | None = None
    expires: date | None = None


class Policy(BaseModel):
    """The owner policy file after validation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: Literal[1]
    project_dirs: list[Path]
    env_allow: list[str]
    rules: list[Rule]
    # S1: codex needs the first, agy the second; both are residual holes, so opt-in only.
    weaker_network_isolation: bool = False
    allow_local_binding: bool = False


def default_policy_path() -> Path:
    """Return the owner policy path, honouring $AGENT_FLOOR_CONFIG."""
    config = os.environ.get("AGENT_FLOOR_CONFIG")
    if config:
        return Path(config) / "policy.toml"
    return Path.home() / ".config" / "agent-floor" / "policy.toml"


def load_policy(path: Path, *, today: date) -> Policy:
    """Load, validate and de-conflict the policy TOML at `path`."""
    from pydantic import ValidationError

    try:
        with path.open("rb") as source:
            raw = tomllib.load(source)
        policy = Policy.model_validate(raw)
    except (OSError, tomllib.TOMLDecodeError, ValidationError) as exc:
        detail = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
        raise PolicyError(f"{path}: {detail}") from exc

    all_ids = {rule.id for rule in policy.rules}
    superseded: set[str] = set()
    for rule in policy.rules:
        if rule.supersedes is not None:
            if rule.supersedes not in all_ids:
                raise PolicyError(f"{path}: unknown supersedes id: {rule.supersedes}")
            superseded.add(rule.supersedes)

    live = [rule for rule in policy.rules if (rule.expires is None or rule.expires >= today)]
    live = [rule for rule in live if rule.id not in superseded]
    seen: dict[tuple[str, str], Rule] = {}
    for rule in live:
        key = (rule.kind, rule.pattern)
        prior = seen.get(key)
        if prior is not None and prior.tier != rule.tier:
            raise PolicyError(f"{path}: conflict: {prior.id} vs {rule.id}")
        seen[key] = rule
    return policy.model_copy(update={"rules": live})


def _expand(pattern: str, home: Path) -> str:
    """Expand only a leading home marker; keep glob syntax literal."""
    if pattern == "~":
        return str(home)
    if pattern.startswith("~/"):
        return str(home) + pattern[1:]
    return pattern


def compile_srt(policy: Policy, *, home: Path) -> dict[str, object]:
    """Compile a policy plus built-in protections into an srt settings dict."""
    deny_read = [
        *(_expand(item, home) for item in SECRET_READ),
        *(
            _expand(rule.pattern, home)
            for rule in policy.rules
            if rule.kind == "read" and rule.tier in ("black", "red")
        ),
    ]
    allow_write = [
        *(str(Path(_expand(str(path), home)).resolve()) for path in policy.project_dirs),
        "/tmp",  # noqa: S108 - explicitly required writable temp location
        "/private/tmp",
        *(_expand(item, home) for item in VENDOR_STATE_WRITE),
        *(
            _expand(rule.pattern, home)
            for rule in policy.rules
            if rule.kind == "write" and rule.tier in ("green", "amber")
        ),
    ]
    deny_write = [
        *(_expand(item, home) for item in (*PROTECTED_WRITE, *SYNC_DIRS)),
        *(
            _expand(rule.pattern, home)
            for rule in policy.rules
            if rule.kind == "write" and rule.tier in ("black", "red")
        ),
    ]
    allowed_domains = sorted(
        {
            rule.pattern
            for rule in policy.rules
            if rule.kind == "net" and rule.tier in ("green", "amber")
        }
    )
    denied_rules = [
        rule for rule in policy.rules if rule.kind == "net" and rule.tier in ("black", "red")
    ]
    denied_domains = list(dict.fromkeys(rule.pattern for rule in denied_rules))
    reasons = {
        rule.pattern: f"agent-floor red: {rule.reason} (rule {rule.id}); ask the owner"
        for rule in denied_rules
    }
    return {
        "filesystem": {
            "denyRead": deny_read,
            "allowRead": [],
            "allowWrite": allow_write,
            "denyWrite": deny_write,
        },
        "network": {
            "allowedDomains": allowed_domains,
            "deniedDomains": denied_domains,
            "allowLocalBinding": policy.allow_local_binding,
            "deniedDomainReasons": reasons,
        },
        "enableWeakerNetworkIsolation": policy.weaker_network_isolation,
    }


def classify_write(path: Path) -> WriteClass:
    """Classify a write target as protected, sync, instruction or normal."""
    # normpath folds `..` so `proj/../.claude/settings.json` is not tagged "normal";
    # symlinks are left to srt, which enforces on the resolved path.
    target = os.path.normpath(path.as_posix())
    home = Path.home()
    groups: tuple[tuple[WriteClass, tuple[str, ...]], ...] = (
        ("protected", PROTECTED_WRITE),
        ("sync", SYNC_DIRS),
        ("instruction", INSTRUCTION_GLOBS),
    )
    for label, patterns in groups:
        if any(fnmatch(target, _expand(pattern, home)) for pattern in patterns):
            return label
    return "normal"


def policy_hash(policy: Policy) -> str:
    """Return the first 16 hex chars of the sha256 of the canonical policy JSON."""
    payload = json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]
