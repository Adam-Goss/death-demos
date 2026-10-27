# Attack and detection lab

The lab hosts deliberately vulnerable workloads for manual attacks and evidence-based detection work.

## Language

**Target**:
A vulnerable workload VM and the application services it hosts.

**Attacker VM**:
The dedicated VM from which the operator runs manual attacks against targets.

**Exercise mode**:
The lab's normal operating state, with attacker and target Internet egress denied.

**Maintenance mode**:
A time-limited state for controlled package and image updates after exercises stop.

**Admin path**:
The authenticated route from the operator's trusted workstation to lab administration interfaces.

**Ingestion endpoint**:
The restricted Elastic-facing service to which lab systems forward telemetry; it is separate from the Elastic management interface.

**Target reset**:
Rebuilding a target VM from pinned inputs after confirming telemetry forwarding has drained; it never touches Elastic evidence.

**Lab shutdown**:
Powering off all lab guests without destroying anything.

**Evidence deletion**:
A separate, explicitly confirmed operation that removes ingested Elastic evidence; no reset or shutdown performs it.

**Exercise ID**:
The operator-set identifier (`lab.exercise_id`) for one manual attack run, written to Elastic with a marker event so evidence is searchable per run.

**Rebuild generation**:
A counter (`lab.rebuild_generation`) that increments on each target rebuild, distinguishing runs on a target with stable name, IP and logical ID.

**Drain marker**:
A marker event emitted on the target after its last exercise event; its arrival in Elasticsearch is the check that forwarding has drained before a target reset.
