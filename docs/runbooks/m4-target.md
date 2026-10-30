# M4 Target VM with DVWA and evidence arrival

Issue #23. A4 and A5 live checks completed **2026-10-30** on target `t1`, rebuild generation **1**. M3/#22 was accepted before this deployment. M5 ([#24](m5-attacker-operator.md)) and M6 ([#25](m6-end-to-end-validation.md)) followed and are complete.

The target is VM **2011**, `10.77.11.10`, in `lab-targets`, with one NIC on `vmbr2011`, 2 vCPU, 4 GB RAM and a 30 GB disk. It was cloned from bare Debian template **2301**. Docker Compose runs the two digest-pinned DVWA/MariaDB images in `network/plan.json`, with DVWA security `low`, the default seeded database, HTTP port 80 and no published database port. MariaDB's health check gates application startup. The enrolment token was issued during provisioning; the template contains no Agent or token.

## Repeat the deployment

Run commands from WSL with LF scripts. The shared environment and secrets are ignored by Git. Keep the original Elastic secrets/CA backup; **do not run the full Elastic role with a new empty secrets directory**. This milestone's `elastic-evidence.yml` only reapplies evidence pipelines, lifecycle settings and Fleet policies.

```bash
. ../env.sh
export PATH="$HOME/.local/bin:/snap/bin:$PATH"
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
export TF_VAR_node_name=ludus
export TF_VAR_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)"
```

1. If absent, create template 2301 in the Proxmox node shell with `scripts/make-target-template.sh`. This run bootstrapped the same parameters through the authenticated Proxmox API. The stored Debian image was imported by its resolved path `/mnt/pve/iso-files/template/iso/debian-13-genericcloud-amd64.img`. No template was booted or enrolled.
2. Keep `scripts/elastic-tunnel.sh` running in another terminal. It forwards Elasticsearch 19200 and Fleet 18220 through the VPN/SSH admin path. Retrieve the **public** CA from the existing Elastic VM if needed; never generate a replacement CA for this operation.
3. Run `scripts/lab.sh init targets`, then `(cd ansible && ansible-galaxy collection install -r requirements.yml && ansible-playbook playbooks/elastic-evidence.yml)`.
4. Point `secrets/env.sh` at the shared environment; run `bash scripts/install-tick-timer.sh` and confirm cron is active. Enter `python3 scripts/labmode.py maintenance --minutes 60 --reason "M4 provision"`, then `scripts/target.sh provision t1`.
5. Return with `python3 scripts/labmode.py exercise none`. With the M2 probe vantages available, run the full `REVERIFY=1 scripts/a2-verify.sh exercise none lab` before `python3 scripts/labmode.py select t1`. See the M2 runbook for probe setup. Recheck the real Docker port from the attacker, VPN and home vantages.
6. After enrolment/registration, run `python3 scripts/firewall_flow.py` and `bash scripts/install-flow-timer.sh`. Keep WSL, cron, the VPN and the Elastic SSH tunnel running.
7. Generate controlled HTTP/process/network activity from the attacker vantage and run `python3 scripts/a4_verify.py t1 1 --window 60 --lag-window 2` and `scripts/a5-verify.sh t1`. The separate lag window measures steady-state collection after the startup backlog; the alert must also be proven to fire on delayed events.

A target reset remains a full rebuild. Do not use an unguarded generation bump: M5 owns the drain/reset interface. This milestone did not reset a previously exercised target or change Elastic evidence.

## Evidence configuration verified live

- The controller downloads checksum-pinned integration archives. `endpoint` **9.5.0** is installed using Kibana's supported bundled-package installer, because ZIP upload rejects its special assets. `system` **3.2.0**, `auditd_manager` **1.21.0**, `docker` **2.16.0**, `apache` **3.0.2** and `filestream` **2.5.1** are uploaded. The uploader verifies installation state, uses exact versions and retries Kibana's upload cooldown.
- One target policy contains Defend in DataCollection mode (protections off for the exercise), Auditd Manager with explicit exec/connect rules and unicast rule management, Docker logs, System metrics, and two standalone Filestream policies for Apache access/error. Apache 3.0.2 supplies parsing pipelines, with its legacy logfile reader and metrics disabled. Rendered Filestream configuration has the correct paths/pipelines and **64-byte** fingerprints.
- Defend session data supplies the container-entry leader and process ancestry. Native Endpoint events do not have `container.id` in this deployment. The exact container identity is available through the System process metric for the same target, generation, entry-leader PID and start time (proof below).
- Fleet 9 supplies its own final pipeline. Integration events call `lab-stamp` through Fleet's supported `global@custom` ingest hook; the firewall stream uses the final pipeline directly. The append-only Agent registry preserves old generation mappings. Pipeline updates exclude Elasticsearch's system-managed creation/modification fields.
- `@timestamp` is source time; `event.created` is collection time; `event.ingested` is ingestion time. Auditd/Docker/Filestream processors add collection time when the integration omits it. Separate fields can have equal values when no delay is measurable. Controller/VM clock skew below one second can invert collection versus ingestion ordering for firewall rows.
- All observed visible data streams use `lab-evidence-90d` or `lab-metrics-14d`. Observed names include `metrics-system.process.summary` and `logs-elastic_agent.auditbeat`. Endpoint's hidden internal action/diagnostic streams keep vendor retention, with zero replicas for the single node. Final cluster health was **green**, zero unassigned shards.
- Added Docker's documented `production.cloudfront.docker.com` to maintenance update sources after its image pull was blocked. [Docker documents this CDN](https://docs.docker.com/desktop/enterprise/allow-list/). It is available only in the timed maintenance mode; exercise-mode denies were reverified afterward.

## Firewall collection and limits

`scripts/firewall_flow.py` reads parsed flow rows through the authenticated OPNsense admin API and writes through the lab-CA-verified Elasticsearch tunnel. It adds source/destination, action, observer and rule fields. Generation selection uses enrolment-time boundaries and event time, not the generation current when a row is polled. A separate atomic checkpoint at `.state/firewall-flow-checkpoint.json` retains the latest 2,000 collected event IDs; successful writes and pre-existing rows are recorded independently of evidence documents. It is shared under a lock by cron and manual collection. Preserve this file with controller state when moving checkouts: resetting it can replay the current source window. The initial two validation runs indexed **29 then 0** new events.

The cron worker polls every five seconds for 55 seconds under a lock, then restarts on the next minute. The working API window is **100 rows**; larger responses were truncated by the live appliance. Bursts beyond the window or controller/VPN/tunnel outages can lose firewall collection. This is **not a durable or lossless shipper**; monitor `.state/firewall-flow.log`, including its full-window warnings. A durable forwarding path should be considered if outage/volume measurements show unacceptable loss. No additional ingestion port or cross-zone rule was opened for collection. This is not transactional exactly-once delivery: a crash between an Elasticsearch acknowledgement and the checkpoint rename can leave a narrow retry window. The checkpoint is collection progress, not a durable log queue.

Final review found that ES IDs alone would replay rows after rollover or deliberate evidence deletion. The independent checkpoint fixes both normal cases. Verification rolled the firewall stream to `.ds-logs-lab_firewall.flow-default-2026.10.30-000002`: a retained row stayed at **one** document across backing indices, with **zero** replays in the new index. A simulated empty evidence store received **zero** writes for a checkpointed row. No real evidence was deleted for this check.

Events arriving before Agent registration can be unstamped; no historical backfill is claimed. The acceptance activity below was generated after registration and the custom hook were active. Initial delayed events did fire the ingest-lag rule; subsequent steady-state checks had zero events over 120 seconds.

## A4 evidence

Unedited output: `python3 scripts/a4_verify.py t1 1 --window 60 --lag-window 2`. The three manual rows are answered immediately afterward.

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| t1 | defend process | exercise | > 0 tagged lab.target_id=t1 gen=1 | 6664 events | elastic logs-endpoint.events.process-* |
| t1 | defend process times | exercise | all three times present; ingestion distinct from source and collection | 2026-10-30T06:09:43.880Z/2026-10-30T06:09:43.888Z/2026-10-30T06:09:52Z | elastic logs-endpoint.events.process-* |
| t1 | defend network | exercise | > 0 tagged lab.target_id=t1 gen=1 | 183 events | elastic logs-endpoint.events.network-* |
| t1 | defend network times | exercise | all three times present; ingestion distinct from source and collection | 2026-10-30T06:01:57.340Z/2026-10-30T06:01:57.340Z/2026-10-30T06:02:20Z | elastic logs-endpoint.events.network-* |
| t1 | auditd | exercise | > 0 tagged lab.target_id=t1 gen=1 | 11544 events | elastic logs-auditd_manager.auditd-* |
| t1 | auditd times | exercise | all three times present; ingestion distinct from source and collection | 2026-10-30T06:09:44.684Z/2026-10-30T06:09:44.687Z/2026-10-30T06:09:48Z | elastic logs-auditd_manager.auditd-* |
| t1 | docker container logs | exercise | > 0 tagged lab.target_id=t1 gen=1 | 116 events | elastic logs-docker.container_logs-* |
| t1 | docker container logs times | exercise | all three times present; ingestion distinct from source and collection | 2026-10-30T05:57:00.629Z/2026-10-30T05:57:09.233Z/2026-10-30T05:57:12Z | elastic logs-docker.container_logs-* |
| t1 | apache access | exercise | > 0 tagged lab.target_id=t1 gen=1 | 21 events | elastic logs-apache.access-* |
| t1 | apache access times | exercise | all three times present; ingestion distinct from source and collection | 2026-10-30T06:01:16.000Z/2026-10-30T06:01:20.166Z/2026-10-30T06:01:30Z | elastic logs-apache.access-* |
| t1 | apache error | exercise | > 0 tagged lab.target_id=t1 gen=1 | 8 events | elastic logs-apache.error-* |
| t1 | apache error times | exercise | all three times present; ingestion distinct from source and collection | 2026-10-30T05:57:05.147Z/2026-10-30T05:57:05.147Z/2026-10-30T05:57:12Z | elastic logs-apache.error-* |
| t1 | firewall flow logs | exercise | > 0 tagged lab.target_id=t1 gen=1 | 409 events | elastic logs-lab_firewall.flow-* |
| t1 | firewall flow logs times | exercise | all three times present; ingestion distinct from source and collection | 2026-10-30T06:09:48+00:00/2026-10-30T06:09:52.538411+00:00/2026-10-30T06:09:52.174910559Z | elastic logs-lab_firewall.flow-* |
| t1 | ingest lag | exercise | 0 events > 120 s | 0 events | elastic search |
| t1 | ingest-lag rule lab-ingest-lag | exercise | enabled | enabled | kibana alerting (Basic) |
| t1 | apache POST body / query visibility | exercise | recorded by hand | SKIP: manual, exercise from the attacker (runbook A4 procedure) | - |
| t1 | filestream 1,024-byte fingerprint | exercise | recorded by hand | SKIP: manual, write a <1 KB request log line and look for it (runbook) | - |
| t1 | defend + auditd coexistence | exercise | recorded by hand | SKIP: manual, both sources present AND exec rule events seen (runbook) | - |

phase=A4 target=t1 generation=1 rows=16 manual=3 PASS-WITH-SKIPS

### Manual A4 checks

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | t1:80 → logs-apache.access | exercise | query visible; POST body visibility measured | PASS: logged query marker `m4-701d2ebf67ca4403b6f63f89e0434bca`; body-only marker absent from the returned event sources | Apache combined format + Filestream + Apache pipeline |
| controller via target SSH | fresh 149-byte access-log fixture → logs-apache.access | exercise | first line collected below the default 1,024-byte threshold | PASS: one event from `/var/log/dvwa/apache2/access.log.m4-fingerprint`, a 149-byte copy of a real validation request line | rendered fingerprint length 64 |
| attacker | DVWA low command injection → Defend and Auditd | exercise | both sensors collect the shell/child without conflict | PASS: `apache2` container entry leader → `dash` → `id`; five Auditd `id` events in the 06:01:10–06:01:25 UTC validation window | Defend + Auditd Manager; no auditd daemon |
| Elastic rule scheduler | lab-ingest-lag | exercise | >120-second ingestion lag raises an alert under Basic | PASS: execution succeeded with one active alert on actual delayed startup events; steady-state two-minute lag window returned zero delayed events | Kibana .es-query rule, 1-minute schedule |

The fingerprint fixture is controlled validation data copied from a real request line; it is not an additional HTTP request. POST bodies are **not collected** by combined-format logging. No body logging was enabled.

Container attribution proof in Elastic: the 06:01:15.230Z `id` event has parent `dash` running the injected command and `process.entry_leader.entry_meta.type=container`, with Apache entry-leader PID **3858**, start **05:41:27.630Z**. The System process metric for that target/generation/PID, start **05:41:27.000Z**, has `container.name=dvwa-dvwa-1` and `container.id=898bb426e33c19e276f9db011cb11b94e1a61ecbc1dce024a4f2efb52aaddaa7`. This requires a process-metric pivot; no direct Endpoint container-ID field is claimed. M6 still owns the complete timed bidirectional hunt.

Recorded rule execution:

```json
{
  "name": "Opaleye ingest lag > 120s",
  "enabled": true,
  "execution_status": {
    "status": "active",
    "last_execution_date": "2026-10-30T05:52:22.788Z",
    "last_duration": 937
  },
  "last_run": {
    "outcome": "succeeded",
    "outcome_order": 0,
    "warning": null,
    "outcome_msg": null,
    "alerts_count": {
      "new": 0,
      "ignored": 0,
      "recovered": 0,
      "active": 1
    }
  }
}
```

## A5 evidence

Unedited output in exercise mode:

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | t1:22 app image digest | exercise | ghcr.io/digininja/dvwa@sha256:8029450682bd70e2e8cd1ffe8e46dd1885ff2a913296091cebfa8ba0a7d36498 | ghcr.io/digininja/dvwa@sha256:8029450682bd70e2e8cd1ffe8e46dd1885ff2a913296091cebfa8ba0a7d36498 | in-guest (OK) |
| operator | t1:22 db image digest | exercise | docker.io/library/mariadb@sha256:d769e37960821dfdcf096954f6e7ac89f747e116c1bba98e48edd265dfc7deae | docker.io/library/mariadb@sha256:d769e37960821dfdcf096954f6e7ac89f747e116c1bba98e48edd265dfc7deae | in-guest (OK) |
| operator | t1:22 login page | exercise | 200 | 200 | in-guest (OK) |
| operator | t1:22 security level | exercise | low | low | in-guest (OK) |
| operator | t1:22 database created | exercise | yes | yes | in-guest (OK) |
| operator | t1:22 agent state (2=HEALTHY) | exercise | 2 | 2 | in-guest (OK) |
| operator | t1:22 no enrolment token on disk outside the agent's own store | exercise | 0 | 0 | in-guest (OK) |

phase=A5 target=t1 PASS

The second provision was a Tofu no-op and an Ansible no-op except the explicit registration:

```text
PLAY RECAP *********************************************************************
t1                         : ok=23   changed=1    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0

```

## Isolation rechecks and cleanup

- Exercise, no target selected: `phase=lab mode=exercise selected=none rows=39 skipped=0 PASS`
- Exercise, t1 selected: `phase=lab mode=exercise selected=t1 rows=39 skipped=0 PASS`

### VPN to real target

ok: rules match the probe matrix (exercise)
| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | t1:22 | exercise | allow | allow | firewall:opt4 |
| operator | t1:80 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |

phase=vpn mode=exercise selected=t1 rows=2 skipped=0 PASS


### Home/public to real target

ok: rules match the probe matrix (exercise)
| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| workstation | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |
| public | t1:80 | exercise | deny | deny | firewall:wan (deny logged: yes) |

phase=home mode=exercise selected=t1 rows=2 skipped=0 PASS


The full lab matrices each passed **39 rows with zero skips**, including actual target egress, target-to-target denial, attacker selection, ingestion, DNS/NTP and IPv6 checks. Target-focused VPN and home/public rows also passed, with denied flows logged. Two broader VPN rows were not revalidated: adding Linux routes alone did not override Windows WireGuard's allowed-IP policy, so those packets did not reach the firewall. Their prior accepted M2 evidence remains the baseline; they are not reported as new passes here.

Temporary probe VMs **2291** (attacker) and **2292** (t2) were stopped and destroyed after validation. Their names/tags were checked before deletion. Temporary WSL routes and source aliases were removed. The firewall remains in **exercise** mode, **t1 selected**, no expiry, re-verification clear. Firewall 2000, Elastic 2003, target 2011 and templates remain; no M5 attacker VM was deployed.

Validation: Python compilation, Bash syntax and both Ansible syntax checks passed; **232 tests passed under WSL**. The review base is `83761b6`, covering standards and issue #23 requirements. Full outage/reset/hunt and sizing checks belong to the later milestones.
