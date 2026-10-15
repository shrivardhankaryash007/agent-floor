"""Locked contract for P4: honest public docs and the weekly probe launchd template."""

import plistlib
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ALLOWED_PHRASES = ("not a guarantee of security",)
SECURE_WORD = re.compile(r"(?i)\bsecure\w*")


def read(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def test_readme_names_the_four_known_holes_first() -> None:
    head = read("README.md")[:1200].lower()
    assert "api host" in head  # the model API host
    assert "allowed host" in head  # allowed hosts before M2
    assert "clipboard" in head
    assert "credential" in head  # the agent CLI's own credentials


def test_no_security_claims_outside_allowed_phrases() -> None:
    for rel in ("README.md", "docs/THREAT-MODEL.md"):
        text = read(rel)
        for phrase in ALLOWED_PHRASES:
            text = text.replace(phrase, "")
        assert not SECURE_WORD.search(text), rel


def test_security_policy_is_private_reporting() -> None:
    assert "private" in read("SECURITY.md").lower()


def test_threat_model_has_trust_boundaries() -> None:
    assert "trust boundar" in read("docs/THREAT-MODEL.md").lower()


def test_weekly_probe_plist() -> None:
    raw = (REPO / "ops" / "com.agent-floor.weekly-probe.plist").read_bytes()
    plist = plistlib.loads(raw)
    interval = plist["StartCalendarInterval"]
    assert interval["Weekday"] == 1
    assert interval["Hour"] == 9
    assert interval.get("Minute", 0) == 0
    args = plist["ProgramArguments"]
    assert args[0].endswith("agent-floor")
    assert "probe" in args
    assert "--out" in args
