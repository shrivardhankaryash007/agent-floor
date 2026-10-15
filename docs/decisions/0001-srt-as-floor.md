# ADR 0001: srt (via its CLI) is the sandbox floor; Fence is the comparator

- Status: accepted (2026-10-15, P0)
- Evidence: `docs/spikes/2026-10-S1-S3.md`

## Context

agent-floor needs an OS-level floor under three vendor CLIs on macOS. The workspace stack is locked
to Python (Constitution §3). Writing a Seatbelt and proxy layer in Python would take weeks and be
less tested than existing floors. Two mature options exist: Anthropic's `@anthropic-ai/sandbox-runtime`
(srt, Node) and Fence (Go, Apache-2.0).

## Decision

Use srt 0.0.79, pinned exactly in `tools/package.json` and called as a subprocess CLI from Python.
This is a deliberate deviation from the Python stack lock: Python owns policy, events and probes;
the Node dependency is confined to `tools/` and installed with `npm ci --ignore-scripts`.

## Why srt over Fence

| Factor | srt 0.0.79 | Fence 0.1.67 |
|---|---|---|
| All three CLIs start (S1) | yes, with documented relaxations | not tested (no need after S3) |
| Parent can observe allowed egress (S2) | yes: `network.parentProxy` | no equivalent found |
| Taint-gated egress (Q1 pre-mortem) | no | no (S3 taint test leaked) |
| Probe set with a P1-shaped policy (S3) | 11 blocked, 1 logged, 1 known hole | `code` template: 3 extra leaks, all config |
| Missing settings | refuses to run (fail-closed) | falls back to a default config |
| Extra layer | none | command deny list (caught `git push`) |
| Provenance | the floor Claude Code ships | third-party |

Fence did not ship taint-gated egress, so the pre-mortem pivot (contribute upstream plus a broker)
did not fire. The command deny list is a candidate idea for a later slice, not adopted.

## Consequences

- Relaxations S1 forced, all opt-in per policy and logged as residuals:
  - `enableWeakerNetworkIsolation` (codex TLS via trustd)
  - `allowLocalBinding` (agy; loopback then bypasses the proxy)
  - writable vendor state directories
- Codex runs inside the floor with `-s danger-full-access` because nested Seatbelt fails (exit 71).
- `npm audit` flags 2 high findings in `node-forge` (srt dependency). These are tracked as N5 and
  re-checked on every srt bump.
- Reverse: swap `find_srt()` and `compile_srt()` for a Fence equivalent. Policy and events are
  floor-agnostic.
