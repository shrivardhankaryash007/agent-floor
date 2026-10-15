# agent-floor — Agent Operating Rules

A thin, fail-closed launcher that runs coding-agent CLIs (Claude Code, Codex, Antigravity)
inside a pinned OS sandbox floor (Anthropic `sandbox-runtime`, "srt"). It reduces what an agent
can read, write and reach. It does not make anything "secure"; never claim that.

Governed by the workspace Coding Constitution
(`~/dev/standards/coding-constitution/CODING-CONSTITUTION.md`) and handoff contract
(`~/dev/standards/agentic-os/HANDOFF-CONTRACT.md`). Plan of record:
`~/dev/plans/agent-safety-layer/plan.mdx`; work packets live in its `packets/` folder.

## Hard rules

1. **Fail closed.** If srt is missing or the policy is invalid, refuse to run (exit 3). Never fall
   back to running a command unsandboxed.
2. **Metadata-only logs.** Events carry codes, classes, hosts, counts and hashes. No file
   contents, command output, prompts, env values or free text. `Event` has no free-text field on
   purpose.
3. **Testing tiers** (see `~/dev/.agents/skills/safe-adversarial-testing/SKILL.md`):
   - T0, on the host: fake `HOME`, canary strings, `127.0.0.1` sinks only.
   - T1, only in a throwaway Docker container: anything that touches real OS state (pasteboard,
     live model attacks).
   - T2 (real accounts, real secrets, third-party hosts): never.
4. **No real secrets in fixtures.** Canaries look like `CANARY-<run>-<n>`; AWS- and PEM-shaped
   fakes are invalid everywhere. Never commit raw probe output (`out/`, `probe-runs/` are ignored).
5. **Never edit the owner's vendor configs** (`~/.claude/settings.json`, `~/.codex/config.toml`,
   `~/.gemini/settings.json`). Vendor inner sandboxes are relaxed per invocation only, inside the
   floor (e.g. `codex -s danger-full-access`, because Seatbelt cannot nest: ADR 0001).
6. **Locked tests.** Files listed in `tests/LOCKED.sha256` are the contract. Executors make them
   pass; they do not edit them. `shasum -a 256 -c tests/LOCKED.sha256` must pass.
7. **srt version bumps** go through `tools/package.json` (exact pin) plus a full probe run whose
   result is recorded.
8. **Stays private** until slice 1 passes plan gates g2–g7. Disclose vendor-sandbox findings to
   the vendor privately first.

## Gates before "done"

```bash
uv run ruff check && uv run ruff format --check && uv run mypy --strict src && uv run pytest -q
shasum -a 256 -c tests/LOCKED.sha256
```

Install the floor with `cd tools && npm ci --ignore-scripts`. Agent setup guide: [docs/INSTALL-FOR-AGENTS.md](docs/INSTALL-FOR-AGENTS.md).
