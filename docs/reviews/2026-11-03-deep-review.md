# Deep fail-open review — 2026-11-03

Findings only. No source, test, config or other docs file was changed. Second pass on this branch: it builds on
the first pass (F1–F14, line references corrected) and adds F15–F25 from a review focused on fail-open behaviour.

## 1. TL;DR

- **Verdict:** the launcher's startup checks fail closed. A missing or broken srt, a missing or invalid policy, and
  an unwritable event log all stop the run before the command starts, and srt 0.0.79 itself refuses a missing,
  empty or invalid `--settings` file and missing sandbox dependencies. **The fail-open problems are in what the
  floor protects once it runs**, and in how results are reported.
- **The floor is weaker than it looks in setups this repo creates or documents:**
  - The `**/…` deny globs only apply under the launch directory (F1).
  - The floor's own code and srt can be written from inside it under the default `init` (F2).
  - Every seat can write every vendor's state, which is a path to persistence outside the floor (F3).
  - An expired exception permanently deletes the deny rule it replaced (F4).
- **Silent "success" paths:**
  - A command killed by SIGTERM or SIGINT is reported as exit 0 (F15).
  - `dns-exfil` passes even when nothing ran (F8).
  - "amber = logged" is not implemented, but the probe reports it as working (F7).
  - A logging failure turns exit 3 into exit 1 (F19).
- **Input-dependent fail-open:**
  - All `~` denies are keyed to `$HOME`, not to the account's home (F16).
  - `env_allow` can pass loader variables (e.g. `NODE_OPTIONS`) into the srt process, which runs **outside** the
    sandbox (F17).
  - Reads are allowed by default, and the secret-read deny list leaves out common credential stores (F18).
- **Count:** 25 findings: **0 critical, 4 high, 8 medium, 13 low.** 22 are verified (traced or reproduced) and 3
  (F22–F24) are plausible; F17 and F25 also have plausible parts. Details are in §3.

## 2. Scope & method

**Read in full:**
- `src/agent_floor/` (all 9 modules) and `tests/` (conftest and all test modules).
- `examples/policy.toml`, `.github/workflows/ci.yml`, `.gitignore`, `tests/LOCKED.sha256`, `tools/package.json`.
- `AGENTS.md`, `docs/THREAT-MODEL.md`, plus skims of STATUS, RESULTS, INSTALL and ADR 0001.

**Read selectively in pinned srt 0.0.79** (installed with `cd tools && npm ci --ignore-scripts`, not committed):
- `dist/cli.js`: settings loading, refusal paths, child exit handling.
- `sandbox/sandbox-utils.js` (`normalizePathForSandbox`) and `sandbox/macos-sandbox-utils.js`
  (`macGetMandatoryDenyEntries`).
- `sandbox/sandbox-manager.js` (dependency check) and `sandbox/domain-pattern.js`.

**Ran (Linux container, Python 3.12, uv):**

| Check | Result |
| --- | --- |
| `uv run ruff check .` | pass |
| `uv run ruff format --check .` | pass (27 files) |
| `uv run mypy --strict src` | pass (9 files) |
| `sha256sum -c tests/LOCKED.sha256` | all 7 OK |
| `uv run pytest -q` | **115 passed, 1 failed**: `test_real_srt_probe_suite` |

The one failure comes from the environment. Once `tools/node_modules` exists, the `floor` marker stops skipping
(F14), and on Linux srt refuses to run without bubblewrap. CI hides this with `--deselect`.

**Scripted checks** were run against the library API, with throwaway temp dirs and no real HOME or secrets. They
covered compiled settings for edge-case policies, expiry with `supersedes`, `scrub_env` behaviour,
`classify_write` and `HOME=""`.

**Could not cover:**
- **Live macOS Seatbelt runs.** No macOS was available. F1 is traced through srt's own profile generator, not
  observed in `sandbox-exec`.
- **The owner's machine layout:** clone location, dispatcher seat policies, `AGENT_FLOOR_CONFIG` and
  `AGENT_FLOOR_STATE` values, the weekly launchd job.
- **Current vendor CLI behaviour** (which files Claude Code, Codex and Antigravity load at startup).
- **Non-root permission failures** (the container runs as root).
- **TIOCSTI** under `allow_pty`.

## 3. Findings table

V = verified (traced end-to-end or reproduced). P = plausible (mechanism traced, trigger not reproduced).
Confidence (0–100) is how sure I am that the defect exists and behaves as described.

| ID | Sev | Where | Summary | V/P | Conf |
| --- | --- | --- | --- | --- | --- |
| F1 | high | `policy.py:28-30,57-58` | `**/` deny globs (and srt's own mandatory denies) are anchored at the launch cwd, not global | V (trace) | 85 |
| F2 | high | `cli.py:99-104`, `run.py:68` | Floor's own code and srt binary are writable from inside the floor under the default `init` | V (trace) | 85 |
| F3 | high | `policy.py:38-45,174` | Every seat can write every vendor's state dirs (`~/.claude.json`, `~/.claude/*`, `~/.codex/*`) | V (compile) | 80 |
| F4 | high | `policy.py:131-140` | An expired `supersedes` exception permanently removes the deny it replaced | V (repro) | 95 |
| F5 | medium | `run.py:63-83`, `cli.py:42-63` | srt version pin is not enforced; any `srt` on PATH that answers `--version` is accepted | V (repro) | 95 |
| F6 | medium | `policy.py:88,101,171`, `init.py:24-31` | Policy values unvalidated: relative or `/`/HOME `project_dirs`, empty write pattern, net `*` | V (repro) | 90 |
| F7 | medium | `policy.py:178,193`, `probes.py:267-286` | "amber = logged" / "instruction writes logged" not implemented; probe self-certifies it | V (trace) | 95 |
| F8 | medium | `probes.py:244-246` | `dns-exfil` reports `blocked` even when nothing ran | V (repro) | 95 |
| F15 | medium | `run.py:125-135` + srt `cli.js` exit handler | A command killed by SIGTERM or SIGINT is reported as exit 0 / success | V (srt source) | 85 |
| F16 | medium | `run.py:99`, `policy.py:111-116,151-157` | All `~` denies and the policy path follow `$HOME`; empty or foreign HOME misplaces them | V (repro) | 85 |
| F17 | medium | `run.py:34-40,48-60` | `env_allow` can pass loader vars (`NODE_OPTIONS`, `DYLD_*`) to srt, which runs unsandboxed | V (scrub) / P (exploit) | 75 |
| F18 | medium | `policy.py:47-59` | Reads are allowed by default, and `SECRET_READ` misses common credential stores | V (compile) | 90 |
| F9 | low | `probes.py:201-218` | Probe policy is stricter than dispatch and launches from its only project (cannot see F1) | V (trace) | 90 |
| F10 | low | `probes.py:215,299`, `events.py:39-42` | Probe events go to the fake HOME and are deleted with it | V (repro) | 95 |
| F11 | low | `cli.py:82`, `.gitignore` | Default `probe-out/` is not git-ignored and receives `canaries.json` | V | 95 |
| F12 | low | `ci.yml` | CI runs `npm ci` with install scripts enabled | V | 95 |
| F13 | low | `run.py:40,55` | `CLAUDE_CODE_OAUTH_TOKEN` exception is not limited to the Claude seat | V | 90 |
| F14 | low | various | Grab-bag: `probe` without srt exits 1, timestamp format, `floor` marker, `allow_pty` default | V | 70–95 |
| F19 | low | `run.py:102,108,134` | Event-append failure turns exit 3 into 1 and replaces the child's exit code with 1 | V (trace) | 85 |
| F20 | low | `run.py:98`, `cli.py:53,93` | Rule expiry uses the UTC date in `run` and the local date in `doctor`; exceptions outlive their date | V | 95 |
| F21 | low | `policy.py:225-239` | `classify_write` labels files *inside* protected dirs as `normal` | V (repro) | 95 |
| F22 | low | `probes.py:375-384` | Any EPERM text in stderr counts as `floor_denied`, including srt failing to start | P | 70 |
| F23 | low | `run.py:125` | SIGTERM to the launcher leaves srt and the agent running, with no `run_end` | P | 70 |
| F24 | low | `run.py:116` | With `TMPDIR` unset, the settings file sits in `/tmp`, which every floored run can write | P | 55 |
| F25 | low | `events.py:62-75` | `read_events` silently skips malformed lines; the log has no write protection if relocated | V (skip) / P (tamper) | 80 |

## 4. Finding details

Ordered by severity. Each finding gives: where, trigger, what happens vs. what should happen, and a fix in prose.

### Verified findings

#### F1 — high — `**/` deny globs only protect the launch directory (conf 85)

- **Where:**
  - The `**/…` entries in `PROTECTED_WRITE` (`policy.py:28-30`) and `SECRET_READ` (`policy.py:57-58`).
  - They pass through `compile_srt` unchanged (`_expand`, `policy.py:151-157`, only rewrites `~`).
- **Mechanism (srt 0.0.79):**
  - `normalizePathForSandbox` resolves any non-absolute, non-`~` pattern with `path.resolve(process.cwd(), …)`
    (`sandbox-utils.js` ~line 407).
  - `macGetMandatoryDenyEntries` anchors its own mandatory denies at cwd (`anchoredGlobEntry(cwd, …)`,
    `macos-sandbox-utils.js:21-45`). These cover `.git/config`, `.git/hooks`, `.vscode`, `.claude/commands` and
    similar paths.
- **Trigger:**
  - `project_dirs` is a workspace that holds several repos (the example policy's shape).
  - The agent is launched with cwd = `<workspace>/repoA`.
- **What happens:**
  - Every `.env` / `.env.*` outside `repoA` is readable.
  - In sibling repos, `.git/hooks`, `.mcp.json`, `.claude/settings*.json` and `.git/config` are writable.
  - `.git/config` has keys that run code the next time the owner uses git **outside** the floor.
- **Should:** the built-in denies should apply in every writable dir and to every read.
- **Why tests miss it:**
  - `run_probes` `chdir`s into its only project (`probes.py:218`).
  - The policy tests assert compiled strings, not how srt interprets them.
- **Fix:**
  - Emit absolute patterns: expand each `**/x` once per `project_dirs` entry and once for HOME, or use a
    root-anchored form where the platform supports it.
  - Add `.git/config` to `PROTECTED_WRITE`.
  - Add probe rows that launch from a cwd other than the target project.

#### F2 — high — The floor can rewrite itself under the default install (conf 85)

- **Where:**
  - `cli.py:99-104`: `init` defaults the project dir to `Path.cwd().parent`.
  - `run.py:68`: srt is resolved at `<clone>/tools/node_modules/.bin/srt`.
  - INSTALL uses `uv tool install --editable .`, so the code that runs is the clone's `src/`.
  - `PROTECTED_WRITE` (`policy.py:21-35`) protects only the literal `~/.config/agent-floor`.
- **Trigger:**
  - The owner runs `agent-floor init` from inside the clone. The project dir becomes the clone's parent, which
    contains the clone.
  - The same happens whenever a project dir is any ancestor of the clone.
- **What happens:**
  - A floored agent can modify `src/agent_floor/run.py` or the srt package.
  - Every later `agent-floor run` then runs unsandboxed, while still logging normal `run_start` / `run_end` and
    returning the child's code.
- **Same root cause:**
  - srt is `#!/usr/bin/env node` and resolves `node` through the inherited `PATH` (`run.py:21`, kept by
    `scrub_env`). A `PATH` entry inside a project dir lets a floored agent substitute the interpreter.
  - `AGENT_FLOOR_CONFIG` pointing inside a project dir makes the policy editable, and `cfg-write` probes only the
    default path.
- **Should:** the install root, the resolved srt package, `node` and the active policy directory should never be
  writable from inside the floor.
- **Fix:**
  - At compile time, add the install root (`Path(__file__).resolve().parents[2]`), srt's realpath and package dir,
    and `default_policy_path().parent` to `denyWrite`.
  - Have `init` and `load_policy` refuse a project dir that contains any of them.
  - Optionally hash-check the srt package before exec.

#### F3 — high — Every seat can write every vendor's state (conf 80)

- **Where:** `VENDOR_STATE_WRITE` (`policy.py:38-45`) goes into `allowWrite` for every policy (`policy.py:174`),
  whichever CLI the policy is for.
- **Verified:** a rule-less policy compiles with `~/.claude`, `~/.claude.json` and `~/.codex` in `allowWrite`.
  Nothing in `denyWrite` covers `~/.claude/{commands,agents,skills,plugins}`, `~/.claude/CLAUDE.md` or
  `~/.codex/AGENTS.md`.
- **Trigger:** a floored codex or agy executor, or any seat, writes user-scope configuration that another vendor
  CLI loads at startup. Examples are an MCP server entry in `~/.claude.json`, or a command or agent file.
- **What happens:** the owner's next **unfloored** interactive session (STATUS: claude runs unfloored on dispatch
  and is the daily driver) loads it outside any floor.
- **Should:** a seat should only write its own vendor's state. Startup-loaded config files should be protected
  for every seat.
- **Note:** THREAT-MODEL A8 says the external claude and agy seat policies deny `~/.codex`. Nothing in this repo
  does the reverse for the codex seat.
- **Fix:**
  - Emit only the running seat's vendor state, keyed on a policy `seat` field or on `cmd[0]`.
  - Add the startup-loaded vendor paths above to `PROTECTED_WRITE`.

#### F4 — high — An expired exception permanently deletes the rule it replaced (conf 95)

- **Where:** `policy.py:131-140`. `superseded` is built from **all** rules, including expired ones, before expired
  rules are filtered out.
- **Reproduced:** black read rule `deny-private` on `~/private`, plus a green rule that supersedes it with
  `expires = 2026-10-31`. Loaded on 2026-11-03, the live rule set is `[]` and `~/private` is missing from
  `denyRead`.
- **Should:** when the exception expires, the deny should come back. This is the H2 "stale rules resolved by
  expiry" intent.
- **Fix:** compute `superseded` from live (unexpired) rules only. Add a locked test for "exception expires, deny
  returns".

#### F5 — medium — The srt version pin is not enforced at runtime (conf 95)

- **Where:**
  - `find_srt` (`run.py:63-83`) accepts any executable whose `--version` exits 0.
  - It falls back to `shutil.which("srt")` when the pinned path is missing.
  - `_doctor` (`cli.py:42-63`) treats any version string as healthy, including an empty one, since `""` is not
    `None`.
- **Reproduced:** a stub that answers `--version` and runs its arguments directly is accepted. `run()` then
  executes the command with no sandbox and logs a normal run.
- **Triggers:**
  - A non-editable install (`parents[2]` lands inside the venv, so the pinned path never exists) plus any `srt`
    on PATH.
  - A stale `tools/node_modules`.
  - A wrong `AGENT_FLOOR_SRT`.
- **Should:** run only the version pinned in `tools/package.json`, otherwise exit 3. THREAT-MODEL N3 ("mitigated
  by exact version pinning") currently overstates what the code enforces.
- **Fix:**
  - Compare the `--version` output with the pin.
  - Drop or explicitly gate the PATH fallback.
  - Have `doctor` exit 3 on a mismatch or an empty version.

#### F6 — medium — Policy values are not validated (conf 90)

- **Where:** `Policy.project_dirs: list[Path]` and `Rule.pattern: str` have no constraints (`policy.py:88,101`).
  Relative entries are resolved against the launcher's cwd (`policy.py:171`).
- **Reproduced:**
  - `project_dirs = ["."]` launched from `/` compiles to `allowWrite[0] == "/"`.
  - A green write rule with `pattern = ""` compiles to `""`, which srt resolves to cwd.
  - A green net rule `"*"` compiles to `allowedDomains = ["*"]`, which srt's `matchesDomainPattern` treats as
    match-all.
  - `init`'s `_project_path(Path.home())` (`init.py:24-31`) renders `"~/."`, which means the whole of HOME.
- **What happens:** the write scope or the network allowlist silently widens, depending on cwd or a typo. INSTALL
  says "never guess `~` or `/`", but nothing enforces it.
- **Should:** load should fail with a `PolicyError` (exit 3).
- **Fix:** reject the following at load time:
  - relative `project_dirs`, `/`, HOME and any ancestor of HOME
  - empty patterns
  - bare `*` (or `*` without a dot-suffix) in net allow rules

#### F7 — medium — "amber = logged" is not implemented, and the probe certifies it anyway (conf 95)

- **Where:**
  - `compile_srt` treats green and amber identically (`policy.py:178,193`).
  - `run()` emits only `run_start`, `run_end`, `policy_error` and `floor_missing`. The `violation` and
    `owner_prompt` event kinds are never emitted.
  - `classify_write` is only called from tests.
  - The `instruction-write` probe writes its own `tier="amber"`, `path_class="instruction"` event
    (`probes.py:267-286`), and `_matches` only checks that `AGENTS.md` exists (`probes.py:400`).
- **What happens:** the row reports `allowed / match=True` even with a no-op srt. These docs claim behaviour that
  does not exist:
  - `examples/policy.toml`
  - THREAT-MODEL A2
  - INSTALL
  - the `init` rule reasons ("logged because push is an exfil path")
- **Fix:** either implement logging (e.g. srt violation monitoring or a parent proxy), or reword the docs to "allowed;
  logging planned". Make the probe check an event written by the run path, not by the probe itself.

#### F8 — medium — `dns-exfil` passes vacuously (conf 95)

- **Where:** `probes.py:244-246`. "No UDP sink hit" becomes `blocked` before the exit code or stderr is looked at,
  so the `udp_unavailable` branch (`probes.py:389`) can never be reached.
- **Reproduced:** on Linux, srt refuses to start and every other row is `inconclusive`. `dns-exfil` reports
  `blocked / match=True`.
- **Same result when:** `nc` is missing, the argv is wrong, or srt fails outright.
- **Missing positive control:** no row shows that UDP reaches the sink when it is allowed.
- **Fix:**
  - Require evidence that the command ran (a sentinel, or a preflight check that `nc` exists). Otherwise report
    `inconclusive`.
  - Add an allowed-UDP control row.

#### F15 — medium — SIGTERM or SIGINT on the agent reads as success (conf 85)

- **Where:** srt 0.0.79 `dist/cli.js`, child `exit` handler. If the child died from SIGINT or SIGTERM, srt calls
  `process.exit(0)`. `run()` returns that code and logs `run_end exit_code=0` (`run.py:130-135`).
- **Triggers:**
  - A dispatcher or watchdog timeout that sends SIGTERM to the process group.
  - A user's Ctrl-C.
  - The agent signalling itself.
- **Should:** a signal death should surface as non-zero (conventionally 128+signal). Dispatchers should not record
  a killed run as a clean exit.
- **Fix:** agent-floor cannot see the child's signal through srt. Options:
  - Ask srt upstream to propagate it.
  - Have agent-floor record that it forwarded a signal and map that run to a non-zero code.
  - At minimum, document that exit 0 does not mean "completed".

#### F16 — medium — `~` denies follow `$HOME`, not the account's home (conf 85)

- **Where:**
  - `compile_srt(policy, home=Path.home())` (`run.py:99`).
  - `default_policy_path()` (`policy.py:111-116`).
  - `Path.home()` honours the `HOME` env var.
- **Reproduced:** with `HOME=""`, `Path.home()` is `/`. The compiled `denyRead` and `denyWrite` become `//.ssh`,
  `//.config/agent-floor` and so on (srt collapses these to `/.ssh`), so the real `~/.ssh`, `~/.aws` and policy
  dir are not denied.
- **Triggers:**
  - A dispatcher that sets `HOME` to a per-seat directory. The real home's secrets are then neither denied nor
    out of reach, because reads are allowed by default.
  - A launch environment where `HOME` is empty.
- **Should:** denies should cover the real account home whatever `HOME` says, or the run should refuse when
  `HOME` is empty or differs from the passwd entry.
- **Fix:**
  - Compile the built-in `~` denies for both `Path.home()` and `pwd.getpwuid(os.getuid()).pw_dir` when they
    differ.
  - Refuse (exit 3) on an empty or relative `HOME`.

#### F17 — medium — `env_allow` can inject code into the unsandboxed srt process (conf 75)

- **Where:**
  - `scrub_env` (`run.py:48-60`) blocks names only by the `ENV_NEVER` substring regex and the `AWS_` prefix.
  - The scrubbed env goes to srt itself (`run.py:125-129`).
  - srt is a Node process that runs **outside** the sandbox it creates.
- **Verified:** `NODE_OPTIONS`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `DATABASE_URL` and `GITHUB_PAT` all pass
  when allowed.
- **Trigger (plausible):** the owner allows `NODE_OPTIONS`, e.g. for a memory flag or a Yarn PnP `--require`, and
  its value points at a file in a writable project dir. That file then runs in the srt host process before any
  sandbox exists. An agent that can edit it escapes on the next run.
- **Should:** loader and preload variables should never reach the floor's own process.
- **Fix:**
  - Add a hard block for `NODE_OPTIONS`, `NODE_PATH`, `LD_*` and `DYLD_*`.
  - Alternatively, launch srt with a minimal fixed env and pass the allowed names only to the inner command, if
    srt supports that.
  - Consider adding `*_PAT`, `*_DSN`, `DATABASE_URL` and `PGPASS*` to `ENV_NEVER`.

#### F18 — medium — Reads are allowed by default and the secret deny list is short (conf 90)

- **Where:** `SECRET_READ` (`policy.py:47-59`) is the only read restriction. `allowRead` is empty and everything
  else is readable.
- **Not in the list:**
  - git, GnuPG, Kubernetes and gcloud credential files
  - the macOS keychain directory
  - package-registry and Terraform tokens
  - other vendors' credential files (THREAT-MODEL A8 acknowledges this for CLI credentials)
- **Trigger:** any prompt-injected read of these files, followed by the acknowledged allowed-host exfil hole
  (`allowed-host-exfil`, e.g. via amber `github.com`).
- **Should:** fail closed on reads outside the project and the seat's needs, or at least deny the common credential
  stores.
- **Fix:**
  - Extend `SECRET_READ` with the standard credential paths, and deny other seats' vendor credential files per
    seat.
  - Longer term, move to an allow-list for reads under HOME.

#### F9 — low — The probe policy does not match what dispatch runs (conf 90)

- **Where:** `probes.py:201-218`. The probe policy uses none of `weaker_network_isolation`, `allow_local_binding`
  or `allow_pty`. It has a single project dir and launches from inside it.
- **Effect:** "14/14 match" describes a configuration nobody runs, and the setup cannot see F1.
- **Fix:** run the probe once per seat with that seat's flags, add a second project dir, and launch from a third
  directory.

#### F10 — low — Probe events are deleted with the fake HOME (conf 95)

- **Where:** `probes.py:215` switches `HOME` to the fake home. `state_dir()` (`events.py:39-42`) then follows it,
  and `probes.py:299` deletes the fake home.
- **Reproduced:** with `AGENT_FLOOR_STATE` unset, no events reach the real state dir. The tests set
  `AGENT_FLOOR_STATE`, which hides this.
- **Fix:** pin `AGENT_FLOOR_STATE` to the real `state_dir()` before switching HOME.

#### F11 — low — The default probe output dir is not git-ignored (conf 95)

- **Where:** `cli.py:82` defaults to `probe-out`. `.gitignore` covers only `out/` and `probe-runs/`, and
  `probes.py:287` writes `canaries.json` there.
- **Effect:** running `agent-floor probe` from the repo root and then `git add -A` commits canaries, against
  AGENTS.md rule 4.
- **Fix:** ignore `probe-out/`, or make `out/` the default.

#### F12 — low — CI runs `npm ci` with install scripts enabled (conf 95)

- **Where:** `.github/workflows/ci.yml` runs `npm ci --prefix tools` without `--ignore-scripts`.
- **Effect:** this contradicts AGENTS.md and the THREAT-MODEL N5 mitigation.
- **Fix:** add `--ignore-scripts`.

#### F13 — low — The OAuth-token exception is not limited to the Claude seat (conf 90)

- **Where:** `run.py:40,55`.
- **Effect:** any policy that lists `CLAUDE_CODE_OAUTH_TOKEN` in `env_allow` passes it, including codex and agy
  seats. The code comment says only the Claude seat may.
- **Fix:** also gate on the seat (a policy field, or the `cmd[0]` basename). Add a test for a codex command.

#### F14 — low — Grab-bag (conf 70–95)

- **`agent-floor probe` without srt** raises an uncaught `FloorUnavailableError` (`cli.py:68`) and exits 1. Exit 1
  is the documented "mismatch" code, so the weekly job cannot tell "floor missing" from "floor leaked". Verified,
  95.
- **Probe event timestamps** use local `isoformat()` (`probes.py:269`), not the UTC `…Z` contract in
  `run._timestamp`. Verified, 95.
- **The `floor` test marker** skips only when srt is absent (`tests/conftest.py:230-236`), not on non-macOS.
  Verified, 95.
- **`render_policy` always writes `allow_pty = true`** (`init.py:49`), including for headless dispatch, where N6
  says it should be off. Verified, 90.

#### F19 — low — Logging failures change exit codes (conf 85)

- **Where:**
  - `run.py:102` and `run.py:108` append the `policy_error` / `floor_missing` event *before* `return 3`.
  - `run.py:134` appends `run_end` before returning the child's code.
  - `append` raising (unwritable or full state dir, `AGENT_FLOOR_STATE` pointing at a file) propagates as a
    traceback, which gives exit 1.
- **Effect:**
  - A refused run exits 1 instead of 3. A dispatcher that keys on 3 for "floor refused" sees an ordinary command
    failure. Nothing runs, so this is fail-closed but misreported.
  - After a completed run, the child's real exit code (0 or otherwise) is replaced by 1.
- **Fix:**
  - Wrap these appends so their failure cannot change the decided exit code. Still exit 3 on refusal, and print a
    metadata-only stderr note.
  - Keep `run_start` strict, as it is now.

#### F20 — low — Exceptions outlive their expiry date (conf 95)

- **Where:**
  - `run` evaluates expiry with `now().date()`, where `now` is `datetime.now(UTC)` (`cli.py:93`, `run.py:98`).
  - `doctor` and `init` use the local `date.today()` (`cli.py:53`).
- **Effect:** east of UTC (e.g. IST, +5:30), a rule with `expires = D` stays live in `run` until 05:30 local on
  D+1. `doctor`'s `policy_hash` can then differ from the one `run` logs.
- **Fix:** pick one clock, the owner's local date, and use it in both places. Document whether expiry is inclusive.

#### F21 — low — `classify_write` misses files inside protected dirs (conf 95)

- **Where:** `policy.py:225-239` uses `fnmatch` against patterns without a `/**` suffix.
- **Reproduced:** each of these returns `normal`:
  - `~/.claude/hooks/x.sh`
  - `~/.config/agent-floor/policy.toml`
  - `<proj>/.git/hooks/pre-commit`
  - `~/Dropbox/a`
- **Effect:** there is no runtime impact today, because only tests call it. It is the classifier the planned amber
  logging would use, and it fails open to `normal`. The parametrized test only checks the directory paths
  themselves.
- **Fix:** match the pattern or any path beneath it. Add child-path cases to the test.

#### F25 — low — The event log reader skips malformed lines silently (conf 80)

- **Where:** `read_events` (`events.py:62-75`) drops lines that fail validation.
- **Effect:** a truncated, corrupted or tampered log reads as clean, with fewer events.
- **Plausible part:** the state dir is not in `PROTECTED_WRITE`. If `AGENT_FLOOR_STATE` points inside a project
  dir, the agent can rewrite its own audit trail.
- **Fix:**
  - Count and report skipped lines.
  - Add `state_dir()` to `denyWrite` at compile time.

### Plausible findings (mechanism traced, trigger not reproduced)

#### F22 — low — The probe classifier confuses srt startup failure with a deny (conf 70)

- **Where:** `_blocked_reason` (`probes.py:375-384`) treats any `operation not permitted` / `eperm` text in stderr
  as `floor_denied`.
- **Trigger:** srt or `sandbox-exec` fails to *apply* the sandbox and prints an EPERM-style message. One example
  is a nested Seatbelt (ADR 0001).
- **What happens:** every `blocked` row then reports `match=True` although nothing ran.
- **Mitigation:** the suite still fails overall, because the leak rows mismatch. The per-row results are still
  misleading.
- **Not confirmed:** I did not see the exact macOS message. The test fake srt uses this same string for "deny".
- **Fix:** require a positive sentinel that the sandboxed command started before classifying a denial.

#### F23 — low — Killing the launcher orphans the run (conf 70)

- **Where:** `subprocess.run` (`run.py:125`).
- **What happens:**
  - The default SIGTERM action kills Python without forwarding the signal to srt.
  - On KeyboardInterrupt, `subprocess.run` SIGKILLs srt, which cannot then clean up its child.
  - Either way the agent keeps running (still sandboxed), with no `run_end` and possibly a stale settings file.
- **Fix:** install SIGTERM and SIGINT handlers that forward the signal to srt, wait for it, and log `run_end`.

#### F24 — low — The settings file may sit in a directory floored agents can write (conf 55)

- **Where:** `tempfile.mkstemp` (`run.py:116`) uses `$TMPDIR`, falling back to `/tmp`. `/tmp` and `/private/tmp`
  are in every policy's `allowWrite` (`policy.py:172-173`).
- **Trigger:** `TMPDIR` is unset (some cron or launchd contexts), and a concurrent floored run replaces the file
  between `json.dump` and srt reading it. The window is short.
- **Fix:** create the settings file in a private `0700` directory outside every `allowWrite` (e.g. under
  `state_dir()`), or pass the settings over a pipe or fd if srt supports that.

## 5. Things checked and found OK

- **Startup fails closed:**
  - A policy error exits 3 before any exec (`run.py:97-104`).
  - A missing or non-executable srt, or a nonzero `--version`, exits 3.
  - An invalid `AGENT_FLOOR_SRT` does not fall through to other candidates.
  - An unwritable log raises before `run_start`, so nothing runs.
  - An unexpected exception gives a traceback, never an exec.
- **srt 0.0.79 also fails closed:**
  - It refuses a missing, empty, unreadable or schema-invalid `--settings` file (`cli.js` `refuseSettings`).
  - It refuses when sandbox dependencies are missing (`sandbox-manager.js` ~line 490 throws, and the CLI exits 1).
  - Every key agent-floor emits is in srt's schema.
- **Argv handling:** the command goes after `--` as a list with no shell in agent-floor. The single `--` pop
  cannot inject srt flags.
- **Settings file:** created `0600` and removed in `finally`. F24 covers the `/tmp` case.
- **Event privacy:**
  - `Event` is `extra="forbid"` and every call site passes fixed codes, numbers or hashes.
  - `policy_error` text goes to stderr only.
  - Probe output is captured in memory, and `SinkHit` keeps only lengths and booleans.
  - No path was found by which content reaches the log. Hardening: make `reason_code`, `path_class` and `domain`
    `Literal` or pattern-constrained.
- **Policy load:** `OSError`, `TOMLDecodeError` and `ValidationError` all map to `PolicyError`. Unknown keys are
  rejected (`extra="forbid"`). A `supersedes` id that does not exist is rejected. A same-pattern tier conflict is
  rejected.
- **Deny precedence:** red and black write rules go to `denyWrite`, which srt applies over `allowWrite`.
- **`init`:** it never overwrites an existing policy (`O_EXCL`) and removes a partial file on error.
- **`ensure_srt`:** it uses `--ignore-scripts` and never raises.
- **Probe positive controls:** with a no-op srt, 12 of 14 rows mismatch, so the suite as a whole does fail. The
  exceptions are F7 and F8.
- **Secrets in the repo:** none found. Canaries are the documented fake `CANARY-…`, AWS-shaped and PEM-header
  strings.
- **Locked tests:** the hashes match, and no locked file was modified.

## 6. Open questions for the owner

1. **Clone location and `init`:** where does the clone live relative to the dispatcher's `project_dirs`? Did you
   run `init` from inside the clone? This decides whether F2 is live today.
2. **Dispatcher environment:**
   - Do the dispatchers set `HOME`, `TMPDIR`, `AGENT_FLOOR_CONFIG` or `AGENT_FLOOR_STATE`? To what? (F2, F16,
     F24, F25)
   - Is anything like `NODE_OPTIONS` in any seat's `env_allow`? (F17)
3. **Launch cwd:** what cwd do dispatched runs use? Is it always the single project dir, or a workspace root with
   sibling repos? (F1)
4. **Seat isolation:** should the codex and agy seats be able to write `~/.claude*` at all? Is a per-seat
   `VENDOR_STATE_WRITE` acceptable? (F3)
5. **Signal semantics:** do dispatchers treat exit 0 as "task completed"? If so, F15 should be fixed before
   relying on exit codes.
6. **Amber logging:** should amber logging be implemented for slice 1, or should the docs be reworded now? (F7)
7. **Reads:** is an allow-list for reads under HOME on the roadmap (M2 or later), or is the deny list the long-term
   design? (F18)
8. **Expiry clock:** should expiry use your local date or UTC? (F20)
