# Deep adversarial review — 2026-11-03

Scope: `src/agent_floor/*`, `tests/*`, `examples/policy.toml`, CI, STATUS/RESULTS/ADR 0001/THREAT-MODEL/INSTALL docs, and the
pinned srt 0.0.79 package source (installed with `npm ci --ignore-scripts` and read on Linux to check how srt
reads the settings agent-floor writes). No source code was changed.

## TL;DR

The launcher's own fail-closed checks hold up: a missing or broken srt, an unreadable or invalid policy, and an
unwritable event log all stop the run before the command starts, and srt 0.0.79 itself refuses a missing, empty
or invalid `--settings` file. No event field carries content. **But four problems weaken or silently remove the
floor in setups this repo creates or documents:**

1. **The built-in `**/…` deny globs only apply under the launch directory** (srt resolves a relative pattern against
   its cwd). `**/.env` read-deny and the `**/.git/hooks`, `**/.mcp.json`, `**/.claude/settings*.json` write-denies do
   nothing for any project dir other than the one you launched from. srt's own mandatory denies (`.git/config`,
   `.vscode`, `.claude/commands`, …) are anchored at cwd the same way. The probe suite cannot see this because it
   always launches from inside its only project.
2. **A floored agent can rewrite the floor.** The editable install runs `src/agent_floor/*.py` and
   `tools/node_modules/.bin/srt` from the clone. `agent-floor init` with no `--project-dir` picks the clone's parent
   directory, so by default the clone sits inside the write scope. One write turns every later `agent-floor run`,
   including dispatcher runs, into an unsandboxed exec with exit 0 and normal-looking events.
3. **Every seat can write every vendor's state.** For example, a floored codex executor can add a stdio
   `mcpServers` entry to `~/.claude.json`. The owner's next unfloored `claude` then runs that command outside the
   floor.
4. **An expired exception permanently deletes the deny rule it replaced.** When a `supersedes` rule expires, the
   black/red rule it superseded does not come back.

On probe honesty: `dns-exfil` passes even when nothing ran. "Amber = logged" and "instruction writes are logged"
are not implemented anywhere. The `probe` events are deleted along with the fake HOME. Details and confidence
scores follow, most severe first.

## Gates run (Linux container)

| Check | Result |
| --- | --- |
| `uv run ruff check .` | pass |
| `uv run ruff format --check` | pass (26 files) |
| `uv run mypy --strict src` | pass (9 files) |
| `shasum -a 256 -c tests/LOCKED.sha256` (as `sha256sum -c`) | all 7 OK |
| `uv run pytest -q` | **115 passed, 1 failed**: `test_real_srt_probe_suite` |

The one failure comes from the environment. I installed `tools/node_modules` to read srt's source, so the `floor`
marker no longer skipped. On Linux, srt cannot sandbox (no bubblewrap), every row came back `inconclusive`, and the
test failed. CI avoids this with `--deselect`. Note the passing count is 115/116, not the 89 in STATUS.md, which is
out of date (P5 added tests). The skip predicate checks only whether srt is present, not the OS (see F14).

---

## Findings

Severity: Critical / High / Medium / Low. Confidence 0–100 means how sure I am that the defect exists and
behaves as described. Where the result depends on owner setup I could not see, the finding says so.

### F1 — High — Relative `**/` deny globs are anchored at the launch cwd, not applied globally (conf 85)

- **Where:** `src/agent_floor/policy.py:28-30,57-58` (the `**/…` entries in `PROTECTED_WRITE` and `SECRET_READ`),
  compiled unchanged into srt settings by `compile_srt` (`policy.py:162-188`, `_expand` leaves them relative).
- **Mechanism:** srt 0.0.79 resolves any pattern that is not absolute and not `~` against `process.cwd()`
  (`dist/sandbox/sandbox-utils.js` `normalizePathForSandbox`, the `path.resolve(process.cwd(), pattern)` branch).
  srt's README states the same rule: `"denyRead": ["**/build/**"]` means "every `build/` directory under the
  current directory". I fed agent-floor's compiled lists into srt's own macOS profile generator
  (`wrapCommandWithSandboxMacOS`) from a cwd `A`. It emitted
  `(regex "^<A>/(.*/)?\\.env(/.*)?$")` and `(regex "^<A>/(.*/)?\\.git/hooks(/.*)?$")`: denies anchored at `A`,
  not filesystem-wide.
- **Effect:** Reads are allowed by default, so:
  - Every `.env` and `.env.*` outside the launch directory is readable, in sibling project dirs and anywhere
    on disk.
  - `.git/hooks`, `.mcp.json` and `.claude/settings*.json` in any writable project dir other than the launch
    directory are writable.
  - srt's own mandatory write-denies (`macGetMandatoryDenyEntries`: `.git/config`, `.gitmodules`, `.vscode`,
    `.idea`, `.claude/commands`, `.claude/agents`, rc files) are anchored at cwd the same way, and
    `PROTECTED_WRITE` has no `.git/config` entry. A sibling repo's `.git/config` is therefore writable, and
    `core.fsmonitor` or `core.hooksPath` there runs code the next time the owner runs git outside the floor.
- **Failure scenario:** policy `project_dirs = [<workspace>]` (the example policy's shape). A dispatcher runs
  `agent-floor run -- codex …` with cwd = `<workspace>/repoA`. An injected instruction runs
  `cat <workspace>/repoB/.env` (allowed) and
  `git -C <workspace>/repoB config core.fsmonitor '<cmd>'` (allowed).
- **Why tests miss it:** `run_probes` does `os.chdir(project)` (`probes.py:218`), so `env-read` and
  `git-hook-write` only ever target the launch directory. `tests/test_policy.py` checks the compiled strings, not
  how srt interprets them.
- **Fix direction:** Emit absolute patterns. Either expand each `**/x` once per `project_dirs` entry and once for
  HOME, or use a root-anchored `/**/x` (fine on macOS Seatbelt; srt skips it on Linux). Add `**/.git/config`.
  Add probe rows that launch from a different cwd than the target project.
- **Not verified:** a live Seatbelt run on macOS. The evidence is srt's profile generator plus its README.
  Confidence is 85 rather than higher only because the real `sandbox-exec` run was not observed.

### F2 — High — The floor's own code and srt binary are writable from inside the floor under the default install (conf 85)

- **Where:** `src/agent_floor/cli.py:236-241` (`init` defaults the project dir to `Path.cwd().parent`);
  `src/agent_floor/run.py:68` (srt resolved at `parents[2]/tools/node_modules/.bin/srt`, inside the clone);
  `docs/INSTALL-FOR-AGENTS.md` (`uv tool install --editable .`, so the running code is the clone's `src/`);
  `PROTECTED_WRITE` (`policy.py:21-35`) protects `~/.config/agent-floor` but neither the install location nor
  `$AGENT_FLOOR_CONFIG`.
- **Failure scenario:**
  1. The owner clones the repo, `cd`s into it and runs `agent-floor init`. The project dir becomes the clone's
     parent, which contains the clone. The same holds whenever the named project dir is a workspace root that
     holds the clone.
  2. A floored agent edits `src/agent_floor/run.py` so `run()` calls `subprocess.run(cmd)`, or overwrites the srt
     CLI that the `tools/node_modules/.bin/srt` symlink points to.
  3. Every later `agent-floor run`, including the dispatchers' default executor path, runs unsandboxed. It still
     logs `run_start` and `run_end` and returns the command's exit code, so nothing looks wrong.
- **Related vectors, same root cause:**
  - The srt CLI is `#!/usr/bin/env node` and runs with the scrubbed but inherited `PATH`
    (`run.py:21,127`). Any `PATH` entry inside a project dir lets an agent plant `node`.
  - If a dispatcher sets `AGENT_FLOOR_CONFIG` to a directory inside a project dir, the agent can edit its next
    policy. The protected-path list uses the literal `~/.config/agent-floor` (`policy.py:22`, `default_policy_path`
    at `policy.py:111-116`), and the probe `cfg-write` checks only that path.
- **Fix direction:**
  - Add `Path(__file__).resolve().parents[2]` (the install root), the resolved srt realpath and its package
    directory, and `default_policy_path().parent` to `denyWrite` at compile time.
  - Have `init` refuse a project dir that contains the install root.
  - Optionally record and check a hash of the srt package before exec.
- **Not verified:** where the owner's clone and dispatcher policies actually live. The default-`init` case is
  confirmed by reading the code.

### F3 — High — All seats get all vendors' state dirs writable; `~/.claude.json` and `~/.claude/*` give persistence outside the floor (conf 80)

- **Where:** `VENDOR_STATE_WRITE` (`policy.py:38-45`) is added to `allowWrite` for every policy, whatever CLI it is
  for (`policy.py:174`). `PROTECTED_WRITE` covers only `~/.claude/settings*.json` and `~/.claude/hooks` under
  `~/.claude`, and srt's mandatory `.claude/commands` and `.claude/agents` denies are cwd-anchored (F1).
- **Verified (script):** a policy with no rules compiles with `~/.claude.json` in `allowWrite` and nothing
  matching `commands`, `agents`, `skills` or `CLAUDE.md` in `denyWrite`.
- **Failure scenario:** a floored codex or agy executor writes a user-scope stdio entry into `~/.claude.json`
  `mcpServers`, or a command into `~/.claude/commands/`, an agent into `~/.claude/agents/`, or instructions into
  `~/.claude/CLAUDE.md`. STATUS says claude runs unfloored by default on dispatch and is the owner's daily
  driver, so the next interactive `claude` starts that MCP command outside any floor. The same applies to
  `~/.codex/` (everything except `config.toml`, e.g. `AGENTS.md` and prompts) from the claude and agy seats.
  THREAT-MODEL A8 says the external seat policies black-list `~/.codex` for claude and agy, but nothing in this
  repo restricts `~/.claude` or `~/.claude.json` for the codex seat.
- **Fix direction:**
  - Emit only the running seat's vendor state (derive it from `cmd[0]` or a policy field).
  - Add `~/.claude/commands`, `~/.claude/agents`, `~/.claude/skills`, `~/.claude/plugins` and `~/.claude/CLAUDE.md`
    to `PROTECTED_WRITE` as absolute paths.
  - Treat `~/.claude.json` as protected for non-claude seats.
- **Not verified:** that the current Claude Code and Codex versions read exactly these paths. This is from vendor
  documentation and is the reason for confidence 80. The external seat policies were also not seen.

### F4 — Medium-High — An expired `supersedes` rule permanently removes the rule it superseded (conf 95)

- **Where:** `policy.py:131-140`. The `superseded` set is built from all rules, including expired ones, before
  expired rules are filtered out.
- **Verified (script):** with black `read` rule `deny-private` and green rule `tmp-allow` (`supersedes =
  "deny-private"`, `expires = 2026-10-31`), loaded on 2026-11-03, the live rules are `[]` and the path is not in
  `denyRead`.
- **Effect:** H2 ("stale rules resolved by expiry") is inverted for this case. A time-boxed exception becomes a
  permanent removal. Read and in-project write denies are the ones that matter, because reads are allowed by
  default and project dirs are writable.
- **Fix direction:** compute `superseded` only from live (unexpired) rules. Add a locked test for "exception
  expires, deny returns".

### F5 — Medium — srt version pin is not enforced at runtime; PATH fallback accepts any `srt` (conf 95)

- **Where:** `run.py:63-83` accepts any executable whose `--version` exits 0. It never compares against 0.0.79 or
  `tools/package.json`. `cli.py:43-63` (`doctor`) exits 0 for any version.
- **Verified (script):** a shell script that prints `9.9.9` for `--version` and otherwise does
  `shift 3; exec "$@"` is accepted by `find_srt()`. `run()` then executes the command directly, with no sandbox.
- **Failure scenarios:**
  1. `tools/node_modules` is missing or stale (e.g. `uv tool install .` without `--editable`, where `parents[2]`
     is inside the tool venv). The first `srt` on `PATH` is then used, whatever its version or origin.
  2. `AGENT_FLOOR_SRT` (set by the probe job or a dispatcher) points at the wrong binary.
  Plain failures are fail-closed. A wrong-but-working binary is not, and THREAT-MODEL N3 ("mitigated by exact
  version pinning") overstates what the code enforces.
- **Fix direction:**
  - Require `--version` output to equal the version in `tools/package.json`; exit 3 otherwise.
  - Drop or gate the `shutil.which("srt")` fallback.
  - Have `doctor` report a mismatch as exit 3.

### F6 — Medium — `project_dirs` is not validated: relative entries follow the launch cwd; `/` and HOME are accepted (conf 90)

- **Where:** `policy.py:101` (`list[Path]`, no constraints), `policy.py:171` (`.resolve()` against the process
  cwd), `init.py:269-276` (`_project_path(HOME)` renders `"~/."`).
- **Verified (script):** `project_dirs = ["."]` launched from `/` compiles to `allowWrite[0] == "/"`.
  `_project_path(Path.home())` returns `~/.`, which compiles to HOME.
- **Failure scenarios:**
  - A dispatcher launches from an unexpected cwd and the write scope moves with it.
  - A clone placed directly in HOME, plus `init` with no `--project-dir`, makes all of HOME writable. That
    exposes `~/.zshenv`, `~/.bash_profile` and `~/.gitconfig`, which are not in `PROTECTED_WRITE`, while srt's
    rc-file denies only cover the cwd (F1).
  - INSTALL says "never guess `~` or `/`", but nothing enforces it.
- **Fix direction:** reject relative paths, `/`, HOME and any ancestor of HOME at load time with a
  `PolicyError` (exit 3).

### F7 — Medium (honesty) — "amber = logged" and "instruction writes are logged" are not implemented (conf 95)

- **Where:** `compile_srt` treats green and amber identically (`policy.py:178,193`). No code path emits an event
  for amber traffic or for writes. `classify_write` (`policy.py:225`) is called only from tests, and `run()` emits
  only `run_start`, `run_end`, `policy_error` and `floor_missing`. The `violation` and `owner_prompt` kinds are
  never emitted.
- **Probe:** `instruction-write` reaches `allowed_logged` with `match=True` because `probes.py:272-281` writes the
  event itself, with `tier="amber"` and `path_class="instruction"`. That event says nothing about what the floor
  logged. With a no-op srt (a script that execs the command directly), this row still reports `allowed / True`.
- **Docs contradicted:** `examples/policy.toml` ("amber = allowed and logged"), THREAT-MODEL A2 ("instruction-file
  writes are logged in week 1"), INSTALL ("Use `amber` so each use is logged"), `init.py` rule reasons
  ("logged because push is an exfil path").
- **Fix direction:** either implement the logging (e.g. srt `parentProxy` or violation monitoring) or reword the
  docs to "allowed (logging planned)". Change the probe to check an event the run path itself wrote.

### F8 — Medium (honesty) — `dns-exfil` passes vacuously (conf 95)

- **Where:** `probes.py:244-246`. For `dns-exfil`, "no UDP sink hit" becomes `blocked` before the exit code or
  stderr is examined.
- **Verified (live):** on Linux, srt cannot start a sandbox. All 13 other rows came back `inconclusive` and
  `dns-exfil` came back `blocked / udp_no_sink_hit / match=True`. A missing `nc`, a typo in the argv, or srt
  failing outright all report "blocked". The `_blocked_reason` branch for `udp_unavailable` (`probes.py:389`) is
  unreachable for this probe.
- **Also:** the row sends one datagram to 127.0.0.1. That is not DNS, and no row shows that UDP *could* reach the
  sink when allowed, so there is no positive control.
- **Fix direction:**
  - Require the sandboxed command to have run: a sentinel on stdout before `nc`, or a check that `nc` exists.
  - Report `inconclusive` otherwise.
  - Add an `allow_local_binding = true` control row that is expected to leak.

### F9 — Low-Medium (honesty) — The probe policy is stricter than what dispatch runs and cannot see F1 (conf 90)

- **Where:** `probes.py:201-212`. The probe policy sets none of `weaker_network_isolation`,
  `allow_local_binding` or `allow_pty`, uses a single project dir, and launches with cwd = that project.
- **Effect:** "14/14 match" (RESULTS.md, weekly job) describes a configuration nobody runs. STATUS itself records
  that on dispatch the loopback hole is live. The probe's cwd choice hides F1 entirely.
- **Fix direction:**
  - Parameterise the probe policy per seat, mirroring the dispatch seat flags.
  - Add a second project dir and launch from a third directory.

### F10 — Low — Probe events are written into the fake HOME and then deleted (conf 95)

- **Where:** `probes.py:215` sets `HOME=fake_home`. `events.state_dir()` (`events.py:39-42`) then resolves to
  `fake_home/.local/state/agent-floor` unless `AGENT_FLOOR_STATE` is set, and `probes.py:299` removes `fake_home`.
- **Verified (script):** with `AGENT_FLOOR_STATE` unset, no events reached the real state dir. The `probe` events
  and every `run_*` event from the run were lost. The tests set `AGENT_FLOOR_STATE`, so they hide this.
- **Fix:** capture `state_dir()` before switching HOME and pin it with `AGENT_FLOOR_STATE`.

### F11 — Low — The default probe output dir is not git-ignored and receives canaries (conf 95)

- **Where:** `cli.py:82` defaults `--out probe-out`. `.gitignore` lists `out/` and `probe-runs/` only, and
  `git check-ignore probe-out` reports nothing. `probes.py:287` writes `canaries.json` there.
- **Effect:** `agent-floor probe` run from the repo root, followed by `git add -A`, commits canary files. AGENTS.md
  rule 4 forbids committing them.
- **Fix:** add `probe-out/` to `.gitignore`, or change the default to `out/`.

### F12 — Low — CI installs srt with install scripts enabled (conf 95)

- **Where:** `.github/workflows/ci.yml` runs `npm ci --prefix tools` without `--ignore-scripts`.
- **Effect:** contradicts AGENTS.md and the N5 mitigation ("install scripts disabled"). A compromised transitive
  dependency would run in CI.
- **Fix:** add `--ignore-scripts`.

### F13 — Low — The `CLAUDE_CODE_OAUTH_TOKEN` exception is not limited to the Claude seat (conf 90)

- **Where:** `run.py:39-40,55`. The comment says "Only the Claude seat policy may allow this", but any policy that
  lists the name in `env_allow` passes the token, including codex and agy seats. "Double-gated" means only "in the
  exception list and in `env_allow`".
- **Fix:** gate on the seat (e.g. `cmd[0]` basename is `claude`) or a policy `seat` field. Add a test for a codex
  command with the name allowed.

### F14 — Low — Assorted correctness and test-coverage gaps (conf 70–95)

- **`agent-floor probe` without srt** raises an uncaught `FloorUnavailableError` (`cli.py:68`) and exits 1, which
  the documented contract (0/1/2) defines as "a probe mismatched". The weekly job cannot tell "floor missing" from
  "floor leaked". Verified. (conf 95)
- **`run_end` logging failure loses the child's exit code.** If `append` raises after the command ran
  (`run.py:133-134`, e.g. disk full or the log made unwritable mid-run), the traceback replaces the child's exit
  code with 1. Found by reading the code; not reproducible here because the container runs as root. (conf 70)
- **Probe event timestamps** use `now().astimezone().isoformat()` (`probes.py:269`), not the
  `%Y-%m-%dT%H:%M:%S.%fZ` UTC contract `run._timestamp` uses. (conf 95)
- **The `floor` test marker skips only when srt is absent** (`tests/conftest.py:230-236`), not on non-macOS, so
  a Linux checkout with `tools/node_modules` fails the suite. CI works around this by name. (conf 95)
- **`render_policy` always writes `allow_pty = true`** (`init.py:294`), including for headless dispatch, where the
  example policy and THREAT-MODEL N6 say to turn it off. (conf 90)
- **`ENV_NEVER` (`run.py:34-37`) misses common credential names**: `*_PAT`, `*_DSN`, `PGPASS*`, `*_PRIVATE*`,
  `DATABASE_URL`. This matters only if the owner allows them, so it is hardening, not a bug. (conf 90)

## Areas checked with no defect found

- **Fail-closed on startup:**
  - A policy error exits 3 before any exec (`run.py:97-104`).
  - A missing or non-executable srt, or a nonzero `--version` exit, exits 3 (`run.py:72-83,105-114`).
  - An invalid `AGENT_FLOOR_SRT` does not fall through to other candidates.
  - An unwritable event log raises before `run_start`, so nothing runs.
  - Unexpected exceptions produce a traceback, not an exec.
- **srt's own handling of settings (0.0.79 source):**
  - An explicit `--settings` that is missing, empty, unreadable or schema-invalid is refused (`dist/cli.js`
    `refuseSettings`, `utils/config-loader.js`).
  - Every key agent-floor emits is in srt's schema, so none is silently dropped.
- **Argv handling:** the command goes after `--` as a list, no shell anywhere. argparse `REMAINDER` plus the single
  `--` pop cannot inject srt flags, because srt sees its own `--` before the user command.
- **Settings temp file:** mode 0600, removed in `finally`. It is in `$TMPDIR` (on macOS outside `/tmp`, so not
  writable from inside), and srt reads it once.
- **Event privacy:**
  - `Event` is `extra="forbid"` and every call site passes fixed codes, numbers or hashes.
  - `policy_error` prints the first line of the parser error to stderr only, never to the event log.
  - Probe stdout and stderr are captured in memory, and `SinkHit` keeps lengths and booleans only.
  - **No path by which prompt, file, env or secret content reaches events was found.** Hardening suggestion: make
    `reason_code`, `path_class` and `domain` `Literal` or pattern-constrained so a future call site cannot put free
    text into them.
- **Probe positive controls:** with a no-op srt, 12 of 14 rows mismatch, so the suite as a whole does fail on a
  missing floor. The exceptions are F7 and F8.

## Could not verify

- **Live macOS Seatbelt behaviour** of any finding (no macOS here). F1 rests on srt 0.0.79's own profile
  generator and README, not on a `sandbox-exec` run.
- **The real-srt probe suite** (`test_real_srt_probe_suite`, `agent-floor probe`): it needs macOS. On Linux srt
  needs bubblewrap, which is absent, and the Linux floor is out of scope anyway.
- **The owner's machine layout:** where the clone lives relative to the project dirs (F2), the external dispatcher
  seat policies and their `AGENT_FLOOR_CONFIG` location (F2, F3, A8), and the weekly launchd job.
- **Vendor CLI behaviour:** that current Claude Code reads user-scope `mcpServers` from `~/.claude.json` and loads
  `~/.claude/{commands,agents,skills}` unfloored, and that Codex reads `~/.codex/AGENTS.md` (F3).
- **The `run_end` exit-code loss** (F14): it needs a non-root user to make the log unwritable mid-run.
- **TIOCSTI** keystroke injection with `allow_pty` (THREAT-MODEL N6, already listed as unverified), and the
  `node-forge` audit status (N5).
- **The M1 owner daily-drive gate** (out of scope).
