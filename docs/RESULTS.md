srt: 0.0.79 | macOS: 26.6.2 | date: 2026-10-15

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
