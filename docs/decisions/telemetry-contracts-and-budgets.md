# Telemetry contracts, retention and resource budgets

Supports [Decide telemetry contracts, retention, and resource budgets](https://github.com/Adam-Goss/death-demos/issues/9). Builds on ADR 0001, `docs/decisions/first-targets-and-hunt-outcomes.md`, `docs/decisions/deployment-and-reset-lifecycle.md`, `docs/research/elastic-lab-evidence.md`. Choices below are Adam's, given this session.

## Decisions

| Question | Decision |
| --- | --- |
| Host evidence | **Fleet-managed Elastic Agent with Elastic Defend and Auditd Manager** on the target VM. Defend is the primary process/network source; auditd uses explicit rules. |
| Application logs | **Same agent**: Docker container logs plus Filestream on Apache logs. Validate POST body/query visibility and the 1,024-byte Filestream fingerprint default; neither is assumed. |
| Network evidence | **Firewall VM flow logs** (ADR 0001) plus Defend connection events. No sensor VM or Packetbeat in milestone 1. Docker-bridge-internal traffic out of scope. |
| Elastic | **One pinned Stack version, self-managed Basic license, single node** (Elasticsearch, Kibana, Fleet Server) on the Elastic VM. No replicas, ML or Enterprise features as baseline dependencies. Exact version pinned at implementation. |
| Ingestion auth | **TLS with lab CA** on Agent to Fleet and Agent to Elasticsearch. Enrollment tokens per rebuild, revocable, injected at provision time, never baked into images; old agent record and token retired on rebuild. Firewall allows target to ingestion endpoint ports only. |
| Concurrency | **1 operator, 1 active exercise, 4 VMs** (firewall, attacker, target, Elastic). |

## Correlation and time

- Lab fields in a documented lab schema (not ECS): `lab.target_id` (stable), `lab.rebuild_generation` (increments per rebuild), `lab.exercise_id` (set by operator command that also writes a marker event). Native agent/host/container IDs kept.
- `@timestamp` (source), `event.created`, `event.ingested` kept separate.
- Time from lab NTP on the firewall VM. **Ingest-lag alert when `event.ingested - @timestamp` > 2 minutes.**
- `target_id` and `rebuild_generation` stamped via agent policy/custom fields at provision time.

## Retention

| Evidence class | Retention |
| --- | --- |
| Endpoint (Defend), auditd, Apache/app logs, firewall flow logs | **90 days** |
| Agent/system metrics, including the Agent's own monitoring streams (`*-elastic_agent.*`, e.g. `status_change` and `filebeat_input` observed on the Fleet Server at A3) | **14 days** |

The per-stream list is `network/plan.json` `elastic.datasets` (expected names, confirmed against real data at A4); a stream not on it is flagged by `a3-verify.sh services`. Lifecycle set per data stream; it is a minimum, not an exact expiry. Disk watermark (below) is the real limit. Revisit after measuring GB per exercise.

## Outage, buffering and loss

- Direct Agent to Elasticsearch. **No Logstash, no Filebeat disk queue** initially.
- **Tolerated loss:** events not yet shipped at a target reset, and events beyond the Agent memory queue during an Elastic outage. No lossless claim.
- Operator practice: no reset during an Elastic outage.
- **Drain check:** a drain marker event emitted on the target after the last exercise event, confirmed in Elasticsearch with matching `rebuild_generation`. Override requires acknowledged loss (per #8).
- Add Logstash or a disk queue only if testing shows unacceptable loss.
- Tests: Elastic down 5 minutes then restored; reset with marker; duplicates after agent restart.

## Backup and survival

- Evidence survives **target resets** by design (separate stack and pool, #8).
- Against Elastic VM/disk failure or operator error: **Elasticsearch snapshots daily to a repository on separate storage** (second disk, NAS or home share), **14 days retained**.
- Elastic config and secrets backed up separately, with the offline key from #8.
- **Proxmox VM snapshots are not the evidence backup.**
- Without separate storage, evidence is lost on disk failure; that risk is accepted explicitly.

## Capacity

| Item | Placeholder (replace with measurements) |
| --- | --- |
| Elastic VM | 4 vCPU / 8 GB RAM (ES heap 4 GB), 100 GB data disk |
| Target VM | 2 vCPU / 4 GB |
| Firewall VM | 1-2 vCPU / 2 GB |
| Attacker VM | 2 vCPU / 4 GB |
| Total | about 9-10 vCPU / 18 GB |

- Elasticsearch disk watermarks at defaults. At **high watermark: alert and stop new exercises**. Nothing auto-deleted; deletion only via evidence deletion.
- **Validation workload:** one idle day plus three runs of Exercise 1. Record indexed bytes per evidence class, and CPU/RAM of Elasticsearch, Kibana, Fleet Server and Defend overhead.
- If the host cannot fit the placeholders, reopen sizing rather than silently shrinking.

## Open

- **Hardware facts not yet gathered.** Verify allocatable vCPU/RAM/storage, disk type and separate backup storage (`pveversion`, `lscpu`, `free -h`, `pvesm status`) before implementation.
- Auditd Manager and Defend coexistence: explicit rules plus conflict check during validation. Add rules only if Defend misses the shell spawn.
- Whether Basic-license Kibana rules can deliver the ingest-lag alert and exercise-block signal; verify at implementation.
- Exact Stack version and feature entitlements frozen at implementation.
