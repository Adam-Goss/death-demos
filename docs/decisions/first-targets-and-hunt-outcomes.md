# First targets and hunt outcomes

Supports [Choose the first targets and hunt outcomes](https://github.com/Adam-Goss/death-demos/issues/7). Evidence base: `docs/research/vulnerable-lab-targets.md`. Choices below are Adam's, given this session.

## Decisions

| Question | Decision |
| --- | --- |
| Initial catalogue | **DVWA only** (Docker Compose: PHP/Apache + MariaDB). |
| Host execution | **Required for every first-milestone exercise.** App/API-only abuse is not sufficient for milestone 1. |
| Consequence | Juice Shop, crAPI and WebGoat are **deferred**, not rejected. crAPI version choice (stable v1.1.6 preferred) is parked until it enters the catalogue. SaaS-style API authorization coverage is **absent from milestone 1**. |
| Fresh target | **All target-owned state replaced** (DB volume, uploaded files, app files), not DB reseed only. Ingested Elastic evidence must survive. Attacker-side state cleared separately. |
| Orchestration | Manual from attacker VM. Automated attacks stay deferred. |

## Exercise 1: command injection to shell process

- **Observable behaviour:** attacker submits a crafted value to DVWA's command-execution page (difficulty `low`); the Apache/PHP worker spawns a shell and a child process beyond the intended `ping`.
- **Required evidence (all correlated by time window, source IP, container identity):**
  1. Apache access log entry: source, method, path, status, query/body indicator. Body visibility not assumed; verify (POST body is not in default combined format).
  2. Host-level process event: parent web worker -> shell -> child, with command line, container attribution.
  3. Network event for any outbound connection the injected command makes (blocked/allowed per lab egress policy).
- **Expected hunt/detection result:** web-server worker spawning a shell/child process, linked to the triggering HTTP request. Hunt starts from either side (process -> request, request -> process).
- **Limitations:**
  - Execution is inside the app's container; **not** evidence of container escape or Proxmox host compromise.
  - No authenticated-user or object fields exist in DVWA logs; identity evidence is session/IP only.
  - Container attribution and sensor visibility are **unproven** until telemetry validation.
  - Only the `low` path's shell invocation was source-inspected; other difficulty levels untested.

## Exercise 2 (candidate, unvalidated): file upload to web shell

Not source-inspected in the research. Included only as a possible second host-execution outcome (uploaded file written, then executed by the web worker). **Needs a research/validation pass before acceptance.** Also tests the all-state-replaced reset (uploaded file must vanish).

## Acceptance checks for the catalogue entry

- Fresh deploy from code reaches a known state.
- Exercise 1 produces all three evidence types in Elastic.
- Reset replaces DB and file state; prior events remain searchable; forwarding completion confirmed before reset.
- Measured resource use recorded (no sizing claimed here).

## Open

- Retention, loss tolerance and forwarding-completion check mechanism (depends on telemetry/reset tickets).
- Whether milestone 2 adds an API-authorization target (crAPI) to cover SaaS-style behaviour.
