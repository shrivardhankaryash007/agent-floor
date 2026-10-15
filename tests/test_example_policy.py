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
