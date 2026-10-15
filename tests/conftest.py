"""Shared T0 fixtures: fake HOME, canaries, a localhost sink and a fake srt; never the real ones."""

import itertools
import json
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
PINNED_SRT = REPO / "tools" / "node_modules" / ".bin" / "srt"

FAKE_SRT_SCRIPT = """\
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

CFG = json.loads(Path({cfg!r}).read_text())
args = sys.argv[1:]
if args[:1] == ["--version"]:
    print(CFG["version"])
    sys.exit(CFG["version_exit"])
rec = {{"argv": sys.argv, "env_keys": sorted(os.environ), "settings": None, "settings_mode": None}}
if "--settings" in args:
    settings_path = args[args.index("--settings") + 1]
    rec["settings_path"] = settings_path
    if os.path.exists(settings_path):
        rec["settings"] = json.loads(Path(settings_path).read_text())
        rec["settings_mode"] = stat.S_IMODE(os.stat(settings_path).st_mode)
with open(CFG["record"], "a") as fh:
    fh.write(json.dumps(rec) + "\\n")
cmd = args[args.index("--") + 1 :] if "--" in args else []
joined = " ".join(cmd)
action = CFG["default"]
for needle, act in CFG["rules"]:
    if needle in joined:
        action = act
        break
if action == "deny":
    sys.stderr.write("fake-srt: Operation not permitted\\n")
    sys.exit(1)
if action == "ok":
    sys.exit(0)
if action == "fail":
    sys.stderr.write("fake-srt: boom\\n")
    sys.exit(1)
if CFG["exit_code"] is not None:
    sys.exit(CFG["exit_code"])
sys.exit(subprocess.call(cmd))
"""


@dataclass
class FakeSrt:
    """Handle to a fake srt script; `records()` returns one dict per non --version call."""

    path: Path
    record: Path

    def records(self) -> list[dict[str, Any]]:
        """Return what the fake srt saw, in call order."""
        if not self.record.exists():
            return []
        lines = self.record.read_text().splitlines()
        return [json.loads(line) for line in lines if line.strip()]


@dataclass
class LocalSink:
    """Test-only localhost HTTP sink, independent of agent_floor."""

    port: int
    requests: list[tuple[str, str, bytes]] = field(default_factory=list)

    @property
    def url(self) -> str:
        """Base URL of the sink."""
        return f"http://127.0.0.1:{self.port}/"


@pytest.fixture
def fake_home(tmp_path: Path) -> Path:
    """A throwaway HOME with .ssh/, .claude/ and a project dir inside it."""
    home = tmp_path / "home"
    for sub in (".ssh", ".claude", "project"):
        (home / sub).mkdir(parents=True)
    return home


@pytest.fixture
def git_project(fake_home: Path) -> Path:
    """The fake project, git-initialised (opt-in, since it shells out to git)."""
    project = fake_home / "project"
    subprocess.run(["git", "init", "-q", str(project)], check=True)
    return project


@pytest.fixture(autouse=True)
def _isolate(tmp_path: Path, fake_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point every agent-floor path and HOME at tmp so no test touches the real host."""
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("AGENT_FLOOR_CONFIG", str(tmp_path / "config"))
    monkeypatch.setenv("AGENT_FLOOR_STATE", str(tmp_path / "state"))
    # A path that never exists, so a test that forgot fake_srt fails closed, not on real srt.
    monkeypatch.setenv("AGENT_FLOOR_SRT", str(tmp_path / "no-srt-configured"))
    py_tmp = tmp_path / "pytmp"
    py_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(py_tmp))


@pytest.fixture
def canary(request: pytest.FixtureRequest) -> Callable[[], str]:
    """Factory of unique fake canary strings `CANARY-<id>-<n>`."""
    label = "".join(ch for ch in request.node.name if ch.isalnum())[:24] or "t"
    counter = itertools.count(1)
    return lambda: f"CANARY-{label}-{next(counter)}"


@pytest.fixture
def http_sink() -> Iterator[LocalSink]:
    """A tiny 127.0.0.1:0 HTTP server that records (method, path, body)."""
    sink = LocalSink(port=0)

    class Handler(BaseHTTPRequestHandler):
        def _record(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            sink.requests.append((self.command, self.path, body))
            self.send_response(204)
            self.end_headers()

        do_GET = _record  # noqa: N815 - http.server dispatches on this exact name
        do_POST = _record  # noqa: N815 - http.server dispatches on this exact name

        def log_message(self, format: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sink.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield sink
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def fake_srt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[..., FakeSrt]:
    """Factory writing an executable fake srt and pointing AGENT_FLOOR_SRT at it.

    Rules are (substring, action) pairs matched against the joined command; actions are
    "deny" (EPERM text, exit 1), "ok" (exit 0, nothing run), "fail" (exit 1, no violation)
    and "run" (exec the command, or exit `exit_code` when it is set).
    """

    def make(
        *,
        version: str = "0.0.79-fake",
        version_exit: int = 0,
        exit_code: int | None = None,
        default: str = "run",
        rules: Sequence[tuple[str, str]] = (),
    ) -> FakeSrt:
        base = tmp_path / "fake-srt"
        base.mkdir(exist_ok=True)
        cfg = base / "cfg.json"
        record = base / "record.jsonl"
        cfg.write_text(
            json.dumps(
                {
                    "version": version,
                    "version_exit": version_exit,
                    "exit_code": exit_code,
                    "default": default,
                    "rules": [list(r) for r in rules],
                    "record": str(record),
                }
            )
        )
        script = base / "srt"
        script.write_text(f"#!{sys.executable}\n" + FAKE_SRT_SCRIPT.format(cfg=str(cfg)))
        script.chmod(0o755)
        monkeypatch.setenv("AGENT_FLOOR_SRT", str(script))
        return FakeSrt(path=script, record=record)

    return make


@pytest.fixture
def policy_file(tmp_path: Path, fake_home: Path) -> Callable[..., Path]:
    """Factory writing a policy TOML to $AGENT_FLOOR_CONFIG/policy.toml."""

    def make(
        rules: str = "",
        *,
        project_dirs: Sequence[str] | None = None,
        env_allow: Sequence[str] = (),
        header_extra: str = "",
        path: Path | None = None,
    ) -> Path:
        target = path or tmp_path / "config" / "policy.toml"
        target.parent.mkdir(parents=True, exist_ok=True)
        dirs = project_dirs if project_dirs is not None else [str(fake_home / "project")]
        text = (
            "version = 1\n"
            f"project_dirs = {json.dumps(list(dirs))}\n"
            f"env_allow = {json.dumps(list(env_allow))}\n"
            f"{header_extra}\n"
            f"{rules or 'rules = []'}\n"
        )
        target.write_text(text)
        return target

    return make


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip `floor` tests unless the pinned srt is installed in tools/."""
    if PINNED_SRT.exists():
        return
    skip = pytest.mark.skip(reason="pinned srt absent (cd tools && npm ci --ignore-scripts)")
    for item in items:
        if "floor" in item.keywords:
            item.add_marker(skip)
