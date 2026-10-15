# Install agent-floor

agent-floor reduces what a coding agent can read, write and reach inside srt; it does not make the host secure.

## Prerequisites

- macOS on Apple silicon or Intel. Linux is not supported yet.
- `uv --version`
- `node --version` (18 or newer)
- `npm --version`
- At least one installed CLI: `claude --version`, `codex --version`, or `agy --version`.

## Install

Ask the user which directory agents may write to. Never guess `~` or `/`.

```sh
git clone <repo-url> && cd agent-floor
```

Expected: the repository is cloned and the shell is in its root.

```sh
uv sync
```

Expected: the project environment and dependencies are installed.

```sh
uv tool install --editable .
```

Expected: `agent-floor` is on PATH (if `agent-floor --help` is not found, run `uv tool update-shell` and open a new shell). Every command below uses the bare `agent-floor`; without this step prefix each with `uv run`.

```sh
agent-floor init --project-dir <dir the user names>
```

Expected: a policy is written (or an existing policy is left unchanged), the required runtime install is attempted, run commands are printed, and doctor runs.

## Verify

```sh
agent-floor doctor
```

Expect exit 0 and JSON with non-null `srt` and `policy_hash`.

```sh
agent-floor probe --out /tmp/af-probe
```

Expect exit 0.

## First run

- Claude Code: `agent-floor run -- claude`
- Codex: `agent-floor run -- codex -s danger-full-access` (Codex's Seatbelt cannot nest inside the macOS floor.)
- Antigravity: `agent-floor run -- agy`

Interactive use needs `allow_pty = true`, which init sets.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Exit 3: srt missing | Run `cd tools && npm ci --ignore-scripts`. |
| Exit 3: policy invalid | Fix the policy file named in the error message. |
| A host is denied | Add a `[[rules]]` block for the host; do not disable the floor. |
| Running init again | Safe: init never overwrites an existing policy. |
| Relocate policy | Set `AGENT_FLOOR_CONFIG` to the config directory. |

## Rules for the agent

- Never edit `~/.claude/settings.json`, `~/.codex/config.toml`, or `~/.gemini/settings.json`.
- Never put secrets in the policy.
- Do not make the repository public.

## WebFetch and MCP servers

Tested 2026-10-15 on macOS with srt 0.0.79, a fake HOME, no model and no real account. Everything an agent starts inherits the floor's network allowlist, so the rule is: a host works only if the policy has a `[[rules]]` block for it.

| Case | Result | How known |
| --- | --- | --- |
| Local stdio MCP server (a process the CLI spawns) | Works, same as outside the floor | Tested with `claude mcp list` |
| Remote HTTP/SSE MCP server on a host not in the policy | "Failed to connect" | Tested |
| Any non-listed host, via a child process | 403 from the proxy | Tested with curl |
| `npx`-launched MCP server | Fails by default: `registry.npmjs.org` is denied and `~/.npm` is not writable | Tested for both causes |
| WebFetch to a non-listed host | Expected to fail the same way (it runs in the CLI's own process) | Inferred, not tested: it needs a live model session |

Fixes, each one a deliberate widening:

1. Remote MCP server or a WebFetch target: add a block to `~/.config/agent-floor/policy.toml`, for example

   ```toml
   [[rules]]
   id = "mcp-example"
   tier = "amber"
   kind = "net"
   pattern = "mcp.example.com"
   added = 2026-10-15
   reason = "remote MCP server the owner uses"
   ```

   Use `amber` so each use is logged. WebFetch needs the target's host, so only allow hosts the owner names; allowing many hosts for WebFetch also widens where an injected instruction can send data.
2. `npx` servers: prefer installing the server once, outside the floor, and launching it by absolute path. Otherwise allow `registry.npmjs.org` and add a writable cache dir under a project dir with `env_allow = ["NPM_CONFIG_CACHE"]` and `NPM_CONFIG_CACHE=<project dir>/.npm-cache` set when launching.
3. A stdio server that needs an API key: put the key in that server's own `env` block in the CLI's MCP config. The floor strips key-like names only from the environment it passes to the CLI.
