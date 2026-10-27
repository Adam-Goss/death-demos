# Elastic collection and evidence preservation

Research date: 2026-10-27. Resolves [Research Elastic collection and evidence preservation](https://github.com/Adam-Goss/death-demos/issues/4), under [Plan the Proxmox attack and detection lab](https://github.com/Adam-Goss/death-demos/issues/2). These are evidence and options, not an approved architecture. No infrastructure was deployed or benchmarked.

## Findings that constrain the design

**The requested lab is feasible, but application, host, and network evidence require distinct collection choices.** Target reset can preserve events already indexed on the separate Elastic VM; it cannot guarantee collection of events still buffered on the target. Docker metrics do not establish what a user or process did. A collector does not create missing application audit records.

### Collection options

| Evidence | Supported option | Important boundary |
| --- | --- | --- |
| Application stdout/stderr | Docker integration container logs | Requires Docker socket discovery and access to container log files; verify the selected logging driver and paths. CPU/network counters are separate metrics, not request or execution history. [Docker integration](https://www.elastic.co/docs/reference/integrations/docker/) |
| Application/access/audit files | Custom Logs (Filestream), or a matching product integration | JSON and multiline parsing are available. Current Filestream defaults wait for 1,024 bytes before fingerprint-based ingestion: tiny exercise logs can appear missing. Test rotation and fingerprints. [Filestream](https://www.elastic.co/docs/reference/integrations/filestream) |
| Linux OS records | System integration and relevant journald/auth/syslog inputs | Collection needs permissions and actual configured log sources. A containerized reader needs host mounts; journald additionally needs a compatible `journalctl` binary. Metrics alone do not replace OS logs. [System integration](https://www.elastic.co/docs/reference/integrations/system) |
| Process/file/connection events | Elastic Defend on the Linux workload VM | Requires Fleet and Fleet Server; standalone Elastic Agent is unsupported for Defend. [Installation](https://www.elastic.co/docs/solutions/security/configure-elastic-defend/install-elastic-defend) |
| Selected Linux audit events | Auditd Manager, or an existing audit daemon with a suitable reader | Rules determine coverage and overhead. Auditd Manager can conflict with another audit consumer and replaces existing rules when configured with rules. Do not enable multiple managers blindly. [Auditd Manager](https://www.elastic.co/docs/reference/integrations/auditd_manager) |
| Observed network transactions/flows | Network Packet Capture integration / Packetbeat on a workload VM or mirrored sensor | Only traffic delivered to the capture interface is visible. TLS parsing reveals handshake information, not encrypted HTTP payloads. [Capture placement](https://www.elastic.co/docs/reference/beats/packetbeat/configuration-interfaces), [TLS behaviour](https://www.elastic.co/docs/reference/integrations/network_traffic/) |

For SaaS-style account or tenant abuse, **application audit context is essential**: a successful HTTP status and normal process behaviour may not reveal an authorization violation. This is a design inference, to validate against each chosen application's logs. Candidate required fields include actor, account/tenant, operation, object, outcome, and request correlation; none are assumed to exist automatically.

Elastic Defend records selective telemetry: events can be aggregated, truncated, or deduplicated. It is not an exhaustive forensic recorder. Its host process data can support container detections, as demonstrated by Elastic's own container rule using `logs-endpoint.events.process*`; that does not guarantee complete container metadata or every event for the eventual workload/kernel. Validate the actual event schema and visibility. [Capture limitations](https://www.elastic.co/docs/solutions/security/manage-elastic-defend/event-capture-elastic-defend/), [container process rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/linux/execution_container_management_binary_launched_inside_container)

**Defend for Containers is a different product path**: current documentation describes a beta, Enterprise-level integration for Kubernetes with specific Linux kernel features. It is not a drop-in requirement for Docker Compose workloads. Host-based Defend remains an option to evaluate independently. [Defend for Containers requirements](https://www.elastic.co/docs/reference/integrations/cloud_defend)

For a separate sensor VM, merely attaching it to the same virtual network is not a demonstrated capture solution. Mirroring or traffic traversal must deliver packets to it; include east-west VM traffic, same-host Docker bridge traffic, NAT identity, and both directions in validation. This is an architectural inference from Packetbeat's documented capture model. Process connection telemetry and packet-derived events answer different questions. Keep HTTP/application logs even when TLS metadata is collected.

## Management and ingestion choices

1. **Fleet-managed Elastic Agent:** centrally managed integrations; required if choosing Elastic Defend. Fleet APIs can configure agent and integration policies, making code-driven setup possible. [Fleet APIs](https://www.elastic.co/docs/reference/fleet/fleet-api-docs)
2. **Standalone Elastic Agent:** configuration-file management for supported integrations; unsuitable for Defend. Compare the actual feature requirements before choosing. [Agent/Beats capability comparison](https://www.elastic.co/docs/reference/fleet/beats-agent-comparison)
3. **Beats and optional Logstash:** useful when explicit disk buffering or custom processing is required. Elastic documents both Agent → Elasticsearch and Agent → Logstash → Elasticsearch patterns; Logstash adds resource and operational costs. [Reference architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures)

Elastic Agent can run in Linux containers, including Fleet Server, but container upgrades replace the image rather than use Fleet's agent upgrade mechanism. Persist the agent state directory: losing it causes re-enrollment and can duplicate collected logs. Docker eligibility for Agent does not establish eligibility for every integration. [Container deployment and state](https://www.elastic.co/docs/reference/fleet/elastic-agent-container)

**Separate administration from shipping credentials.** Use validated TLS for Agent–Fleet and Agent–Elasticsearch links, with a trusted CA distributed by provisioning. Fleet enrollment tokens enroll agents; Fleet subsequently provides communication and, where applicable, output API keys. Enrollment tokens are reusable until revoked, so they are not harmless image-template content. [TLS](https://www.elastic.co/docs/reference/fleet/secure-connections), [enrollment credentials](https://www.elastic.co/docs/reference/fleet/fleet-enrollment-tokens)

For standalone agents, Elastic documents unique API keys with `monitor` plus `auto_configure` and `create_doc` on the required data streams. Narrow patterns to the intended datasets; avoid administrator, read, overwrite, and delete privileges on targets. Fleet-managed output privileges need equivalent review through their generated policy/keys. [Standalone shipping permissions](https://www.elastic.co/docs/reference/fleet/grant-access-to-elasticsearch)

**Inference:** root compromise of a source VM can stop or alter local collection, read its secrets, and submit fabricated events with its shipping identity. Restricted keys help protect already-indexed records from deletion; they do not ensure truthfulness or prevent storage exhaustion. Independent network observation and externally monitored ingestion gaps provide additional evidence, not a proof of completeness. Keep backend and hypervisor management credentials off targets.

## Retention, reset, and failure semantics

The new backend can use supported packages or Docker on its dedicated VM. Docker deployment requires persistent Elasticsearch data volumes, pinned images, appropriate host settings, memory limits and file permissions. A single-node option is simpler, but has no node-level redundancy: replicas cannot allocate to their own primary's node. [Self-managed options](https://www.elastic.co/docs/deploy-manage/deploy/self-managed), [Docker data and resource settings](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod), [single-node resilience](https://www.elastic.co/docs/deploy-manage/production-guidance/availability-and-resilience/resilience-in-small-clusters)

Recommended contract for later decision:

- Target reset owns application state and, if chosen, workload VM state. It must exclude Elastic disks, data streams, saved investigations, and lifecycle policies.
- Before a normal reset, verify a known exercise marker reached Elasticsearch and record the reset boundary. This is a proposed acceptance mechanism, not a guarantee that every source event arrived.
- Keep stable logical target identity and a fresh exercise/reset identifier alongside native host, agent, and container identifiers. A VM rollback or clone can reuse names/state; IP addresses alone cannot distinguish runs. Decide how enrollment identities and file-reading checkpoints are regenerated versus preserved.
- Use source time and ingestion time separately. ECS defines `@timestamp`, `event.created`, and `event.ingested`; their differences help expose delay and clock problems. Add lab-specific identifiers through a documented schema rather than treating them as standard ECS fields. [ECS timestamps](https://www.elastic.co/docs/reference/ecs/ecs-principles-implementation)

**Retention is not a backup or an exact expiry timestamp.** Data stream lifecycle retention establishes a minimum retention interval, with deletion tied to backing-index lifecycle. Existing ILM-managed streams require their ILM policies to be adjusted. Select duration per evidence class and confirm the effective configuration; do not assume target reset controls retention. [Retention semantics](https://www.elastic.co/guide/en/elasticsearch/reference/current/tutorial-manage-data-stream-retention.html), [existing streams and ILM](https://www.elastic.co/guide/en/elasticsearch/reference/current/tutorial-manage-existing-data-stream.html)

For recoverability beyond target reset, use Elasticsearch snapshots to a repository outside the relevant failure domain. Elastic explicitly does not support filesystem copies of its data directory as a substitute. A Proxmox VM snapshot is therefore not the documented Elasticsearch backup strategy. Preserve configuration and secrets separately because snapshots omit some node/security configuration files. [Data-directory precautions](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/path), [snapshot contents](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore)

### Buffering limits

| Path | Verified property | Consequence |
| --- | --- | --- |
| Elastic Agent output | Configurable memory queue; Agent capability documentation does not expose configurable internal disk queues | An enabled Agent is not proof of durable offline storage. [Output queue](https://www.elastic.co/docs/reference/fleet/elasticsearch-output), [capability comparison](https://www.elastic.co/docs/reference/fleet/beats-agent-comparison) |
| Filebeat | Explicit disk queue persists pending events across restart | Queue survives only while its backing disk survives; target rollback/deletion can discard it. [Disk queue](https://www.elastic.co/docs/reference/beats/filebeat/configuring-internal-queue) |
| Logstash | Persistent queue is available but disabled by default | Enable and size it deliberately if chosen; it protects events received by that queue, not events never collected. [Resiliency](https://www.elastic.co/docs/reference/logstash/queues-data-resiliency) |

An outage can outlast memory/disk buffers or local log rotation. Packet capture cannot replay packets never recorded. Define tolerated loss, outage duration, reset-during-outage behaviour, ingestion-lag alerts, and duplicate handling; then test them. Do not promise lossless forwarding.

## Licensing and sizing inputs

New self-managed installs default to a non-expiring Basic license. Basic supports installing/enabling prebuilt rules, exceptions, and duplicating rules for customization; direct editing of prebuilt rules requires Enterprise in the current comparison. Individual integrations and advanced features have separate requirements. The Defend integration is marked Basic, but that does not make every protection/response feature free. Machine-learning-dependent capabilities and Enterprise container protection must not become accidental baseline dependencies. Freeze exact versions and feature entitlements before implementation; online examples can display a different or prerelease package from the chosen release. [Default license](https://www.elastic.co/docs/get-started/evaluate-elastic), [rule feature tiers](https://www.elastic.co/docs/solutions/security/detect-and-alert/install-prebuilt-rules), [Defend package](https://www.elastic.co/docs/reference/integrations/endpoint), [self-managed subscription matrix](https://www.elastic.co/subscriptions)

No defensible VM sizing follows from “good hardware.” Gather allocatable vCPU/RAM/storage, disk performance, target count/concurrency, average and burst ingest, retention, rule/query load, and backup budget. Measure indexed bytes per representative exercise and idle day before finalizing capacity. Include OS/cache, Elasticsearch, Kibana, Fleet Server, any Logstash queue, and sensor overhead. Elastic's published Agent ingestion measurements explicitly exclude Defend overhead and vary by integrations; they are not a whole-lab sizing estimate. [Agent resource caveats](https://www.elastic.co/docs/reference/fleet/install-elastic-agents)

## Decisions now ready for discussion

- Does the first exercise need host process/file evidence via Fleet-managed Defend, audit-based collection, or both? Which protection mode permits the intended exercise?
- Where can network evidence be observed, and is flow/TLS metadata sufficient alongside application logs?
- What loss and outage budget justifies direct ingestion versus durable intermediate buffering?
- What identifies a logical target and a distinct reset/exercise, and what must be confirmed before reset?
- How long is each evidence class retained, and must it also survive Elastic VM/disk failure?
- Which release, license baseline, available hardware budget, and measured validation workload constrain the implementation?

These questions fit the existing network, lifecycle, exercise, and evidence decision tickets. No final collector/topology/retention choice was made by this research.
