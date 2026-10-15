# agent-floor

`agent-floor` reduces what a coding agent can read, write, and send over the network when it runs inside Anthropic's sandbox-runtime (srt) under the conditions described below. It does not stop content sent to the model API host, data sent to allowed hosts before M2, clipboard access (the probe used a shim in a fake HOME), or access to the agent CLI's own credentials; these are known holes. It is not a guarantee of security.

## Quick start

Install the pinned floor dependencies with `cd tools && npm ci --ignore-scripts` and install this Python project in its virtual environment. Then create your policy from the starter (it is never created for you, because the floor will not guess what you allow), and edit `project_dirs` and the network rules:

```sh
mkdir -p ~/.config/agent-floor
cp examples/policy.toml ~/.config/agent-floor/policy.toml
chmod 600 ~/.config/agent-floor/policy.toml
agent-floor doctor            # exit 0 = srt found and the policy is valid
agent-floor run -- claude
```

The floor fails closed if srt is missing or the policy is invalid. Vendor inner sandboxes may need to be relaxed per invocation inside the floor because macOS Seatbelt cannot nest.

## Probe results

Conditions: P3 T0 probes ran on macOS 26.6.2 with srt 0.0.79, a fake HOME, canaries, localhost sinks, and no model. The `pbcopy` probe used a shim in the fake HOME, not the real pasteboard. The allowed-host row sent only to a localhost sink. These results describe these probes and conditions; they do not measure normal-work false positives, prompts per hour, or latency percentiles.

| id | channel | expect | outcome | match | reason_code | latency_ms |
| --- | --- | --- | --- | --- | --- | --- |
| ssh-read | fs-read | blocked | blocked | True | floor_denied | 273.774 |
| env-read | fs-read | blocked | blocked | True | floor_denied | 276.371 |
| cfg-write | fs-write | blocked | blocked | True | floor_denied | 279.204 |
| claude-settings-write | fs-write | blocked | blocked | True | floor_denied | 277.484 |
| git-hook-write | fs-write | blocked | blocked | True | floor_denied | 277.937 |
| symlink-escape | fs-read | blocked | blocked | True | floor_denied | 280.825 |
| dotdot-escape | fs-read | blocked | blocked | True | floor_denied | 274.225 |
| icloud-write | fs-write | blocked | blocked | True | floor_denied | 274.947 |
| http-denied | network | blocked | blocked | True | proxy_denied | 292.145 |
| dns-exfil | dns | blocked | blocked | True | udp_no_sink_hit | 283.052 |
| git-push-sink | git | blocked | blocked | True | write_scope_denied | 358.871 |
| instruction-write | fs-write | allowed_logged | allowed | True | command_succeeded | 279.946 |
| pbcopy | clipboard | leak_known_hole | leaked | True | canary_observed | 1290.5 |
| allowed-host-exfil | network | leak_known_hole | leaked | True | canary_observed | 285.805 |

Full P3 output and context: [docs/RESULTS.md](docs/RESULTS.md).

## How this differs from srt and Fence

[Anthropic's sandbox-runtime](https://github.com/anthropics/sandbox-runtime) supplies the operating-system sandbox floor. [Fence](https://github.com/fencesandbox/fence) is another sandbox wrapper and a useful comparison point. agent-floor credits both projects and builds on srt rather than replacing its containment layer. This first slice measures the floor; later work is planned for observed-taint decisions, protected instruction files, and a sensitive-data broker. Those later capabilities are not present in this slice.

## Licence

Apache-2.0; see [LICENSE](LICENSE).
