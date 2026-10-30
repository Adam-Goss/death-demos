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

**Lab startup**:
Powering the lab guests back on after a lab shutdown, firewall first; it never rebuilds anything.

**Attacker-side state**:
The exercise working files on the Attacker VM (`/srv/exercise`); cleared by its own command, never by a target reset.

**Evidence deletion**:
A separate, explicitly confirmed operation that removes ingested Elastic evidence; no reset or shutdown performs it.

**Exercise ID**:
The operator-set identifier (`lab.exercise_id`) for one manual attack run, written to Elastic with a marker event so evidence is searchable per run.

**Rebuild generation**:
A counter (`lab.rebuild_generation`) that increments on each target rebuild, distinguishing runs on a target with stable name, IP and logical ID.

**Drain marker**:
A marker event emitted on the target after its last exercise event; its arrival in Elasticsearch is the check that forwarding has drained before a target reset.

**Gateway VM**:
The dedicated VM running Apache Guacamole on the admin path; the operator's browser route to the Attacker VM (RDP desktop) and the targets (SSH terminal); direct SSH over the VPN remains.

**Gateway zone**:
The isolated network (`10.77.2.0/24`) holding the Gateway VM; the firewall allows the operator in over the VPN, RDP out to the Attacker VM and SSH out to targets only.

**Brokered access**:
GUI or terminal access to a lab guest through the Gateway VM. The firewall VM and Elastic are not brokered; they keep their direct VPN routes.

**Analysis zone**:
The isolated network (`10.77.20.0/24`) holding FLARE-VM and REMnux; only the Gateway VM may open a connection into it, it reaches only the ingestion endpoint, and it has no Internet unless the operator switches it on for a limited time (`labops.py analysis-online`).

**Analysis reset**:
Reverting FLARE-VM and REMnux to their clean Proxmox snapshot (`labops.py analysis-reset`): Internet forced off, drain marker confirmed first, fresh Agent enrolment afterwards, `lab.rebuild_generation` incremented; no rebuild and it never touches Elastic evidence.

**Sample ID**:
The operator-set identifier (`lab.sample_id`) for one malware sample under analysis, written to Elastic with marker events so analysis-zone evidence is searchable per sample.
