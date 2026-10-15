"""`agent-floor run`: compile the policy, scrub the env and exec the command under srt."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from agent_floor.errors import FloorUnavailableError, PolicyError
from agent_floor.events import Event, EventKind, append
from agent_floor.policy import compile_srt, load_policy, policy_hash

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


def _timestamp(now: datetime) -> str:
    """Format a timestamp in the event contract's UTC representation."""
    return now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def scrub_env(env: Mapping[str, str], allow: Sequence[str]) -> dict[str, str]:
    """Keep ENV_ALWAYS plus allowed names, never anything matching ENV_NEVER."""
    permitted = set(ENV_ALWAYS) | set(allow)
    result: dict[str, str] = {}
    for name, value in env.items():
        if name not in permitted:
            continue
        if name not in VENDOR_ENV_EXCEPTIONS and (
            ENV_NEVER.search(name) or name.startswith(ENV_NEVER_PREFIXES)
        ):
            continue
        result[name] = value
    return result


def find_srt() -> Path:
    """Locate a working srt binary or raise FloorUnavailableError."""
    configured = os.environ.get("AGENT_FLOOR_SRT")
    candidates = [Path(configured)] if configured else []
    if not configured:
        candidates.append(Path(__file__).resolve().parents[2] / "tools/node_modules/.bin/srt")
        located = shutil.which("srt")
        if located:
            candidates.append(Path(located))
    for candidate in candidates:
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        try:
            result = subprocess.run(  # noqa: S603 - fixed resolved binary, run without a shell
                [str(candidate), "--version"], capture_output=True, check=False
            )
        except OSError:
            continue
        if result.returncode == 0:
            return candidate
    raise FloorUnavailableError("srt unavailable")


def _event(kind: EventKind, run_id: str, now: Callable[[], datetime], **fields: object) -> None:
    """Append a typed event with only the supplied metadata."""
    instant = now()
    # Fields are internal fixed call sites; Pydantic validates the event schema at runtime.
    append(Event(ts=_timestamp(instant), kind=kind, run_id=run_id, **fields), now=instant)  # type: ignore[arg-type]


def run(cmd: Sequence[str], *, policy_path: Path, now: Callable[[], datetime]) -> int:
    """Run `cmd` under srt with the compiled policy; fail closed with 3."""
    run_id = str(uuid.uuid4())
    timestamp = now
    try:
        policy = load_policy(policy_path, today=now().date())
        settings = compile_srt(policy, home=Path.home())
        digest = policy_hash(policy)
    except PolicyError as exc:
        _event("policy_error", run_id, timestamp, reason_code="policy_invalid")
        print(f"agent-floor: policy invalid: {exc}; nothing was run", file=sys.stderr)
        return 3
    try:
        srt = find_srt()
    except FloorUnavailableError:
        _event("floor_missing", run_id, timestamp, reason_code="srt_unavailable")
        print(
            "agent-floor: sandbox floor unavailable; refusing to run unsandboxed "
            "(fail-closed). Fix: cd tools && npm ci --ignore-scripts",
            file=sys.stderr,
        )
        return 3

    descriptor, settings_name = tempfile.mkstemp(prefix="agent-floor-", suffix=".json")
    settings_path = Path(settings_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(settings, stream)
        _event("run_start", run_id, timestamp, policy_hash=digest)
        started = time.monotonic()
        try:
            result = subprocess.run(  # noqa: S603 - owner's command is passed as argv, no shell
                [str(srt), "--settings", str(settings_path), "--", *cmd],
                env=scrub_env(os.environ, policy.env_allow),
                check=False,
            )
            code = result.returncode
        except OSError:
            code = 127
        latency = (time.monotonic() - started) * 1000
        _event("run_end", run_id, timestamp, exit_code=code, latency_ms=latency)
        return code
    finally:
        settings_path.unlink(missing_ok=True)
