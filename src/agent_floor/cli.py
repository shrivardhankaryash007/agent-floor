"""Command-line entry point: `agent-floor run|doctor|probe`."""

import argparse
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, date, datetime

from agent_floor.errors import FloorUnavailableError, PolicyError
from agent_floor.policy import default_policy_path, load_policy, policy_hash
from agent_floor.run import find_srt, run


def _version(command: str) -> str | None:
    """Return a CLI version line, or None if it is not installed or fails."""
    path = shutil.which(command)
    if path is None:
        return None
    try:
        result = subprocess.run(  # noqa: S603 - fixed resolved binary, run without a shell
            [path, "--version"], capture_output=True, text=True, check=False
        )
    except OSError:
        return None
    return (
        result.stdout.strip().splitlines()[0]
        if result.returncode == 0 and result.stdout.strip()
        else None
    )


def _doctor() -> int:
    """Print machine-readable floor, policy and CLI status."""
    try:
        srt = find_srt()
        result = subprocess.run(  # noqa: S603 - fixed resolved binary, run without a shell
            [str(srt), "--version"], capture_output=True, text=True, check=False
        )
        srt_version = result.stdout.strip() if result.returncode == 0 else None
    except FloorUnavailableError:
        srt_version = None
    try:
        policy = load_policy(default_policy_path(), today=date.today())
        digest = policy_hash(policy)
    except PolicyError:
        digest = None
    report = {
        "srt": srt_version,
        "policy_hash": digest,
        "clis": {"claude": _version("claude"), "codex": _version("codex"), "agy": _version("agy")},
    }
    print(json.dumps(report))
    return 0 if srt_version is not None and digest is not None else 3


def main(argv: Sequence[str] | None = None) -> int:
    """Parse `argv` and dispatch to run, doctor or probe; return the exit code."""
    parser = argparse.ArgumentParser(prog="agent-floor")
    commands = parser.add_subparsers(dest="command", required=True)
    run_parser = commands.add_parser("run")
    run_parser.add_argument("cmd", nargs=argparse.REMAINDER)
    commands.add_parser("doctor")
    commands.add_parser("probe")
    args = parser.parse_args(argv)
    if args.command == "run":
        command = list(args.cmd)
        if command and command[0] == "--":
            command.pop(0)
        if not command:
            parser.error("run requires a command after --")
        return run(command, policy_path=default_policy_path(), now=lambda: datetime.now(UTC))
    if args.command == "doctor":
        return _doctor()
    return 0


if __name__ == "__main__":
    sys.exit(main())
