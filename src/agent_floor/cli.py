"""Command-line entry point: `agent-floor run|doctor|probe`."""

from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Parse `argv` and dispatch to run, doctor or probe; return the exit code."""
    raise NotImplementedError
