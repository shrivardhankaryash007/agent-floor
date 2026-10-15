"""Owner policy: load the tiered TOML, add built-in protections and compile srt settings."""

from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

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
    raise NotImplementedError


def load_policy(path: Path, *, today: date) -> Policy:
    """Load, validate and de-conflict the policy TOML at `path`."""
    raise NotImplementedError


def compile_srt(policy: Policy, *, home: Path) -> dict[str, object]:
    """Compile a policy plus built-in protections into an srt settings dict."""
    raise NotImplementedError


def classify_write(path: Path) -> WriteClass:
    """Classify a write target as protected, sync, instruction or normal."""
    raise NotImplementedError


def policy_hash(policy: Policy) -> str:
    """Return the first 16 hex chars of the sha256 of the canonical policy JSON."""
    raise NotImplementedError
