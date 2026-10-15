"""`agent-floor run`: compile the policy, scrub the env and exec the command under srt."""

import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path

ENV_ALWAYS: tuple[str, ...] = (
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

# Policy env_allow cannot override these; a leaked env var is the cheapest exfil target.
ENV_NEVER: re.Pattern[str] = re.compile(
    r"(?i)(TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|AUTH|COOKIE|SESSION)"
)
ENV_NEVER_PREFIXES: tuple[str, ...] = ("AWS_",)

# S1: all three vendor CLIs start with only ENV_ALWAYS, so no exception is needed.
VENDOR_ENV_EXCEPTIONS: tuple[str, ...] = ()


def scrub_env(env: Mapping[str, str], allow: Sequence[str]) -> dict[str, str]:
    """Keep ENV_ALWAYS plus allowed names, never anything matching ENV_NEVER."""
    raise NotImplementedError


def find_srt() -> Path:
    """Locate a working srt binary or raise FloorUnavailableError."""
    raise NotImplementedError


def run(cmd: Sequence[str], *, policy_path: Path, now: Callable[[], datetime]) -> int:
    """Run `cmd` under srt with the compiled policy; fail closed with 3."""
    raise NotImplementedError
