"""The shipped starter policy must load, or first run fails closed for every new user."""

from datetime import date
from pathlib import Path

from agent_floor.policy import compile_srt, load_policy

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "policy.toml"


def test_example_policy_loads_and_compiles(tmp_path: Path) -> None:
    """The starter policy validates and allows the Claude API host."""
    policy = load_policy(EXAMPLE, today=date(2026, 10, 15))
    settings = compile_srt(policy, home=tmp_path)
    network = settings["network"]
    assert isinstance(network, dict)
    assert "api.anthropic.com" in network["allowedDomains"]


def test_allow_pty_is_emitted_only_when_on(tmp_path: Path) -> None:
    """allowPty reaches srt only when the policy opts in; otherwise the key is absent."""
    policy = load_policy(EXAMPLE, today=date(2026, 10, 15))
    assert compile_srt(policy, home=tmp_path)["allowPty"] is True
    off = policy.model_copy(update={"allow_pty": False})
    assert "allowPty" not in compile_srt(off, home=tmp_path)
