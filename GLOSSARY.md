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
