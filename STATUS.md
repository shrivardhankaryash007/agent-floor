---
status_version: 2
project: agent-floor
updated: 2026-10-15
---

# agent-floor Status

## Current Slice

- req: slice 1 (week 1): P0 done; P1–P4 ready for the coding executor
- state: scaffold plus locked red tests committed; spikes S1–S3 recorded
- owner: owner
- plan: `~/dev/plans/agent-safety-layer/plan.mdx` (packets in `packets/`)
- goal: a fail-closed launcher that runs claude, codex and agy inside a pinned srt floor, with
  metadata-only events and a T0 probe suite. It reduces exposure; it does not make anything secure.

## Verified Baseline

- `tools/node_modules/.bin/srt --version` → 0.0.79. Path:
  `tools/node_modules/.bin/srt` (relative to the repo root) (2026-10-15)
- `uv run pytest -q` → 78 failed (73 NotImplementedError, 5 FileNotFoundError in test_docs), 11 passed (constants); 89 total, locked red, 2026-10-15
- `shasum -a 256 -c tests/LOCKED.sha256` → OK

## Decisions

- ADR 0001: srt 0.0.79 is the floor, called through its CLI; Fence 0.1.67 is the comparator
  (S3 found no taint gating in Fence).

## Known residuals

- Allowed-host exfiltration leaks on both floors. This is the M2 target.
- Claude OAuth token refresh fails inside the floor; refresh outside it once.
- `enableWeakerNetworkIsolation` (codex) and `allowLocalBinding` (agy) are opt-in holes.
- `npm audit`: 2 high findings in `node-forge` (srt dependency), tracked as N5.

## Dirty / In-Flight

- Remote: github.com/shrivardhankaryash007/agent-floor, PRIVATE (owner-approved 2026-10-15). It goes public only after slice 1 passes gates g2–g7.

## Next Action

- Dispatch P1, then P2, P3 and P4, to the coding executor (registry coding default) with the
  packets as briefs.
