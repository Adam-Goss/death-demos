# Deployment and target reset lifecycle

Supports [Decide deployment and target reset lifecycle](https://github.com/Adam-Goss/death-demos/issues/8). Builds on ADR 0001, `docs/decisions/first-targets-and-hunt-outcomes.md`, `docs/research/proxmox-lab-options.md`. Choices below are Adam's, given this session.

## Decisions

| Question | Decision |
| --- | --- |
| Provisioning stack | **OpenTofu/Terraform (BPG provider) + Ansible.** Tofu owns Proxmox objects (VMs, pool, firewall objects); Ansible owns in-guest config and Docker Compose. One authoritative tool per resource. |
| Reset contract | **Destroy and rebuild the target VM from pinned inputs.** Recovers from guest-OS compromise; replaces all target-owned state. No snapshot rollback, no container-only recreate. |
| Evidence independence | **Elastic has its own Tofu state/stack and Proxmox pool.** Target and firewall operations cannot address it. Destroy guard on Elastic resources. |
| Proxmox access | **API token only, no node SSH** for routine deployment. Role scoped to lab pool/storage paths; credentials never in target images. |
| Target identity | **Stable name, IP and VMID; same logical target ID.** Fresh Elastic agent enrolment per rebuild; old agent record retired. A rebuild-generation field distinguishes runs. |
| Failed/partial provisioning | **Re-apply converges.** A failed target is destroyed and rebuilt, never hand-repaired. Elastic/firewall failures: re-apply, then documented manual recovery with no automatic destroy. |
| State and secrets | **Operator workstation, encrypted per-stack state** (firewall/network, Elastic, targets). Encryption key recoverable offline. Repo holds code only; secrets never baked into images. |

## Distinct operations

| Operation | Meaning | Must not |
| --- | --- | --- |
| **Target reset** | Confirm telemetry forwarding is drained, then rebuild the target VM only. Refuses if the drain check fails unless operator overrides with acknowledged loss. | Touch Elastic, firewall VM or attacker VM. Attacker-side state is cleared separately. |
| **Lab shutdown** | Power off all guests. Nothing destroyed. | Delete or reset anything. |
| **Evidence deletion** | Separate, guarded, explicitly confirmed command against the Elastic stack. | Be reachable from reset or shutdown, or from a broad destroy of other stacks. |

## Open (not decided here)

- Installed PVE version/storage/pool conventions (BPG targets PVE 9.x); **verify before implementation**.
- Image approach (cloud image + first boot vs Packer template) and pinning/checksum record.
- Drain-check mechanism and loss tolerance (telemetry ticket).
- Elastic backup/retention against disk failure or operator error (distinct from reset safety).
- Exact Proxmox role ACLs, derived once resource model exists.
