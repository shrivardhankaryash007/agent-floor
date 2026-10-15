# Threat model

## Assets

- Owner files, credentials, and project data outside the permitted write scope.
- Integrity of agent-floor policy, vendor configuration, and instruction files.
- Data sent to network destinations, including model APIs and allowed hosts.
- Metadata-only event records and probe outcomes.

## Attacker

Assume one injected instruction appears in any input the agent reads: a repository file, web page, tool result, or other untrusted content. It may direct the agent to read files, change configuration, run commands, or send data. This model does not assume that the model follows every instruction or that the layer can inspect the model's intent.

## Trust boundaries

| Boundary | Trust and enforcement |
| --- | --- |
| Owner TTY → launcher | The owner starts the command and chooses the repository; the launcher compiles policy and refuses to run when srt or policy validation fails. |
| Launcher → OS floor | srt applies the Seatbelt profile and network proxy. The OS floor is the containment boundary for file and network access described by the policy. |
| OS floor → agent CLI | The CLI and its tools may follow injected instructions. The CLI's own credentials must remain available to it, so this access is a known residual risk. |
| Agent CLI → vendor API | Model requests leave the machine for the vendor API host. The API host is an accepted, exfil-capable destination. |
| Agent CLI → other allowed hosts | Before M2, an allowed destination can receive data after untrusted input is read. The current probe demonstrates this using a localhost sink. |

## Gap disposition

Statuses below reflect the plan's disposition, not proof that every planned mitigation is complete. In particular, M2–M4 items are deferred work.

| # | Gap | Status |
| --- | --- | --- |
| A1 | Safety layer is the prize | Resolved in P1/P3: protected policy and vendor configuration paths; cfg-write probe. |
| A2 | Persistence via memory/AGENTS.md/skills/plans | Partly resolved: instruction-file writes are logged in week 1; red after taint is planned for M2. |
| A3 | Cross-agent/vendor taint | Deferred to M3. |
| A4 | Exfil beyond HTTP | Partly resolved/measured: DNS, git push, and synced-folder probes; allowed-host and clipboard paths remain holes; browser behavior is unverified. |
| A5 | Worker-to-researcher query leaks secrets | Deferred to M3; typed query design is planned. |
| A6 | Backdoors, typosquats, destructive commands | Destructive writes are scope-limited; typosquat checks deferred to M4; runtime backdoor detection dropped. |
| A7 | Path tricks (symlink, `..`, TOCTOU) | Resolved by OS path enforcement; symlink-escape and dotdot-escape probes. |
| A8 | Secrets already exposed | Partly resolved: environment scrub and read-deny paths; CLI credentials remain accessible; broker-held tokens deferred to M4. |
| A9 | Local models are injectable | Resolved as a design principle: local-model output is treated as untrusted; implementation is planned for M3/M4. |
| H1 | Approval fatigue | Measured through owner-prompt events; target is at most two prompts/hour on a normal day. |
| H2 | Stale or contradictory rules | Resolved in P1 with dated rules, supersession, expiry, and conflict rejection. |
| E1 | Fail-open vs fail-closed | Decided in Q2: OS floor and proxy fail closed; M2 decision service falls back to static policy assuming taint. |
| E2 | Latency, false positives | Measurement planned; this P3 table gives per-probe latency, not normal-work false positives or latency percentiles. |
| E3 | macOS enforcement options | Resolved: Seatbelt through srt; Endpoint Security dropped; containers reserved for T1. |
| E4 | Vendor CLI churn | Managed with a weekly launchd probe template and a planned doctor command; adapters need ongoing maintenance. |
| E5 | Antigravity logs | Verified for structure; post-hoc adapter feasible, interception planned for M2. |
| E6 | Logs are sensitive | Resolved by metadata-only event schema and redaction tests. |
| V1 | Use existing benchmarks | Resolved for planned M3 evaluation with AgentDojo and InjecAgent; neither measures OS containment. |
| V2 | Safe adversarial testing as a skill | Resolved by the safe-adversarial-testing skill, used for P3. |
| S1 | Employment-contract IP clause | Resolved by owner review on 2026-10-15. |
| S2 | Avoid unsupported security claims; SECURITY.md | Resolved by this wording policy and private reporting instructions. |
| S3 | Licence | Decided: Apache-2.0. |
| S4 | Differentiate or merge with #2 | Decided: keep #28 and #2 separate; compiler may become a later milestone. |
| S5 | About one hour/day steering | Addressed with a weekly unattended launchd probe schedule; failures surface for owner review. |
| M1 | Inter-agent envelope | Deferred to M3. |
| N1 | Nested Seatbelt fails | Resolved operationally per invocation: disable the inner sandbox where required; codex uses `-s danger-full-access` inside the floor. |
| N6 | Interactive TUIs need tty ioctls (`setRawMode EPERM` without them) | Opt-in `allow_pty`. Residual: srt then allows ioctl/read/write on `/dev/ptmx` and every `/dev/ttys*`, so a tool inside could write to your other terminals; keystroke injection (TIOCSTI) on macOS is unverified. Off for headless `-p` runs. |
| N2 | Agent CLI model API host must be allowed | Accepted and documented residual risk; model API traffic is trusted by the plan. |
| N3 | srt is beta and its API changes | Mitigated by exact version pinning and a probe run for version bumps. |
| N4 | Cost of live-model testing | Managed by the zero-extra-spend rule; T1 is capped at 50 tasks. |
| N5 | Supply chain of the layer | Mitigated by lockfile integrity hashes, install scripts disabled, and audit on srt bumps; audit findings remain to be rechecked. |
