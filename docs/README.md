# Documentation index

Start with the [project README](../README.md) for the architecture and the day-to-day guide, and [GLOSSARY.md](../GLOSSARY.md) for the vocabulary.

## Decisions (why it is built this way)

| Doc | Covers |
| --- | --- |
| [ADR 0001: isolate the attack lab behind a firewall VM](adr/0001-isolate-the-attack-lab-behind-a-firewall-vm.md) | The boundary: one firewall VM, isolated zones, VPN admin path, exercise and maintenance modes. |
| [ADR 0002: Guacamole gateway for browser access](adr/0002-guacamole-gateway-for-browser-access.md) | A dedicated gateway VM brokers GUI and terminal access to the attacker and targets. |
| [First targets and hunt outcomes](decisions/first-targets-and-hunt-outcomes.md) | DVWA only; Exercise 1 (command injection to shell process) and what evidence it must produce. |
| [Deployment and reset lifecycle](decisions/deployment-and-reset-lifecycle.md) | Tofu + Ansible, destroy-and-rebuild resets, Elastic isolated from target operations. |
| [Telemetry contracts and budgets](decisions/telemetry-contracts-and-budgets.md) | What is collected, field contracts, retention, sizing placeholders. |
| [Operator commands and the target interface](decisions/operator-commands-and-target-interface.md) | `labops.py`, exercise IDs, drain markers, reset, shutdown, evidence deletion. |
| [Acceptance checks and build plan](decisions/acceptance-checks-and-build-plan.md) | Milestones M0-M6, checks A0-A10, handoff rules. |

## Research

[Proxmox lab options](research/proxmox-lab-options.md), [OPNsense vs pfSense](research/opnsense-vs-pfsense.md), [vulnerable lab targets](research/vulnerable-lab-targets.md), [Elastic lab evidence](research/elastic-lab-evidence.md).

## Site

[Site inventory](inventory/site-inventory.md): the Proxmox host, network, storage and authority the lab was designed against.

## Runbooks (how it was built and verified, with evidence)

| Runbook | Milestone | Acceptance |
| --- | --- | --- |
| [M1 foundations](runbooks/m1-foundations.md) | Layout, encrypted state, scoped tokens | A1 |
| [M2 firewall and networks](runbooks/m2-firewall-and-networks.md) | Firewall VM, zones, VPN, modes, config seed and template | A2 |
| [M3 Elastic](runbooks/m3-elastic.md) | Elastic VM, ingestion, retention, snapshots | A3 |
| [M4 target](runbooks/m4-target.md) | DVWA target, Fleet and evidence arrival | A4, A5 |
| [M5 attacker and operator commands](runbooks/m5-attacker-operator.md) | Attacker VM, markers, drain, reset, shutdown | A6 (partial) |
| [M6 end-to-end validation](runbooks/m6-end-to-end-validation.md) | From-scratch rebuild, hunt, reset, outage, teardown, measurement | A6-A10 |
| [Guacamole gateway](runbooks/guacamole-gateway.md) | Browser GUI/terminal access, TOTP, live evidence | #51 |

## Working on the repo

[Issue tracker](agents/issue-tracker.md), [triage labels](agents/triage-labels.md), [domain docs](agents/domain.md) (how agents and contributors use the glossary and ADRs).
