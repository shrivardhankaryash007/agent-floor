---
status_version: 2
project: agent-floor
updated: 2026-10-21
---

# agent-floor Status

## Current Slice

- req: slice 1 (week 1): P0–P4 done and merged on main; next is the M1 exit gate
- state: P0–P4 merged; full gate green (89 passed, 96% cov, ruff, mypy --strict, LOCKED ok); real-floor probe table in docs/RESULTS.md
- owner: owner
- plan: `~/dev/plans/agent-safety-layer/plan.mdx` (packets in `packets/`)
- goal: a fail-closed launcher that runs claude, codex and agy inside a pinned srt floor, with
  metadata-only events and a T0 probe suite. It reduces exposure; it does not make anything secure.

## Verified Baseline

- `tools/node_modules/.bin/srt --version` → 0.0.79. Path:
  `tools/node_modules/.bin/srt` (relative to the repo root) (2026-10-15)
- `uv run pytest -q --cov=agent_floor --cov-fail-under=80` → 89 passed, 95.7% coverage (2026-10-15)
- `agent-floor probe` on real srt 0.0.79: 14/14 rows match expectation (docs/RESULTS.md); pbcopy row uses an in-project shim, not the real pasteboard (needs T1)
- `shasum -a 256 -c tests/LOCKED.sha256` → OK

## Decisions

- ADR 0001: srt 0.0.79 is the floor, called through its CLI; Fence 0.1.67 is the comparator
  (S3 found no taint gating in Fence).

## Next

- **M1 exit gate:** one real working day under `agent-floor run -- claude` (owner), then review prompts/hour and false positives.
- Weekly probe job is LIVE (2026-10-20) as workspace job `com.yashshrivardhankar.agent-floor-probe`
  (`~/dev/scripts/launchd/`, Mondays 09:00, dated runs under `~/.local/state/agent-floor/probes/`, `latest` symlink).
  First launchd run: exit 0, 14/14 rows match. `ops/` template fixed: it lacked node on PATH, so it would have exited 1 with no results.
- **Workspace consumer (S2, 2026-10-21):** `~/dev` dispatchers run codex and agy executors under
  `agent-floor run --` by default, with headless per-seat policies in `~/dev/scripts/floor-policies/`.
  Claude is opt-in: headless `claude -p` reports "Not logged in" inside srt, which is a class-3
  owner item on the Desk. The weekly job also runs `dispatch_floor_probe.py` (6/6 match). A live
  floored codex dispatch ran its shell with `~/.ssh` blocked. ADR:
  `~/dev/docs/decisions/2026-10-20-dispatch-floor-flag.md`. This repo is unchanged by S2.

## Known residuals

- P3 review found: srt deny paths do not match through the `/var` -> `/private/var` symlink; probe fake HOME is resolved. Real HOME is under `/Users`, unaffected, but any symlinked HOME is a risk to check in `doctor`.
- Packet P3 omitted `cli.py` from writable files; the reviewer wired `probe`.

- Allowed-host exfiltration leaks on both floors. This is the M2 target.
- Claude OAuth token refresh fails inside the floor; refresh outside it once.
- `enableWeakerNetworkIsolation` (codex) and `allowLocalBinding` (agy) are opt-in holes.
  On dispatch these holes are live by default: the agy floored dispatch probe row reaches a loopback sink (curl rc=0), and the secret read is still blocked.
- `npm audit`: 2 high findings in `node-forge` (srt dependency), tracked as N5.

## Dirty / In-Flight

- Remote: github.com/shrivardhankaryash007/agent-floor, PRIVATE (owner-approved 2026-10-15). It goes public only after slice 1 passes gates g2–g7.

## Next Action

- Dispatch P1, then P2, P3 and P4, to the coding executor (registry coding default) with the
  packets as briefs.

## 2026-10-15 P5 init + install guide

`agent-floor init`, one-step srt install (`npm ci --ignore-scripts` from init) and `docs/INSTALL-FOR-AGENTS.md` merged. Gate green: 109 passed, 95% coverage, ruff, mypy --strict, LOCKED. Clean-HOME dry run: `docs/DRY-RUN-2026-10-15.md` (also lists Linux gaps). Open: vendor login hosts unverified without an account; WebFetch untested. Repo is still private.
