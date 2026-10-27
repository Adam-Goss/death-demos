# Proxmox provisioning and reset options

Research date: 2026-10-27. Context: [Research Proxmox provisioning and reset options](https://github.com/Adam-Goss/death-demos/issues/3), within [Plan the Proxmox attack and detection lab](https://github.com/Adam-Goss/death-demos/issues/2).

**Finding:** reproducible VM provisioning, Docker configuration, and independent target resets are feasible. The remaining choices concern the installed Proxmox version, automation ownership, enforcement boundary, and reset contract. This report supplies options; it does **not** select the architecture or claim a tested deployment.

## Provisioning and configuration options

| Option | Verified capability and maintenance evidence | Decision implication |
| --- | --- | --- |
| Terraform or OpenTofu with BPG's Proxmox provider | Community-maintained, not Proxmox-affiliated. The project targets and acceptance-tests PVE 9.x; PVE 8.x has limited support without priority testing, and 7.x is unsupported. Release `v0.118.1` was published on 2026-10-27. The 0.x line does not promise compatibility between every minor version. [Project](https://github.com/bpg/terraform-provider-proxmox/blob/main/README.md), [release](https://github.com/bpg/terraform-provider-proxmox/releases/tag/v0.118.1). | Strong candidate when a reviewed desired-state plan and explicit resource lifecycle are wanted. Pin a tested version; do not apply PVE 9 assumptions to an unknown host. |
| Ansible `community.proxmox` | Modules cover VM creation/deletion/power, networking, ACLs, and firewall management. The rendered documentation describes collection 2.0.0 and requires ansible-core 2.17+; GitHub has a newer 2.1.0 release dated 2026-10-06. The KVM module requires `proxmoxer >= 2.3` and `requests`. [Collection](https://docs.ansible.com/projects/ansible/latest/collections/community/proxmox/index.html), [module](https://docs.ansible.com/projects/ansible/latest/collections/community/proxmox/proxmox_kvm_module.html), [release](https://github.com/ansible-collections/community.proxmox/releases/tag/2.1.0). | Viable single-language provisioning/configuration alternative. Verify the selected collection's actual compatibility; documentation and release versions currently differ. Explicitly design inventory, update/delete semantics, and recovery from partial runs. |
| Telmate's Proxmox provider | Exposes QEMU and LXC resources. Its README lists limitations including failed-looking VM update tasks and an LXC `rootfs` requirement. Release `v3.0.2-rc10` was published on 2026-08-30; despite the `rc` suffix, GitHub marks it non-prerelease. [Project](https://github.com/Telmate/terraform-provider-proxmox), [release](https://github.com/Telmate/terraform-provider-proxmox/releases/tag/v3.0.2-rc10). | A live alternative, not grounds to claim either abandonment or universal compatibility. Assess its exact resource/schema support against the installed PVE release before choosing it. |
| Ansible for guest configuration and Compose | `community.docker.docker_compose_v2` manages Compose applications, requires Compose plugin 2.18+, and can wait for service health. Its documentation describes only partial idempotence and warns that Compose output changes can break compatibility. [Module](https://docs.ansible.com/projects/ansible/latest/collections/community/docker/docker_compose_v2_module.html). | Can complement either VM-provisioning approach. Pin compatible tools and make normal convergence distinct from intentional reset/restart. |

**Inference:** assign one authoritative tool to each resource. For example, allowing both Ansible and a Terraform provider to continually rewrite the same VM/network settings creates avoidable ownership ambiguity. This is a proposed design criterion, not a settled stack choice.

## Images and bootstrap

Proxmox supports cloud-init images, initial networking/SSH configuration, templates, and linked clones. Cloud-init supplies first-boot configuration; it is not itself a complete ongoing configuration-management contract. Custom snippets need snippet-capable storage and must exist on every node to which the VM may migrate. [Proxmox cloud-init documentation source](https://github.com/proxmox/pve-docs/blob/master/qm-cloud-init.adoc).

Two viable image approaches:

- **Distribution cloud image plus configured first boot:** fewer image-building components. Record image origin/checksum and bootstrap inputs so replacing a target does not silently change its starting state. The reproducibility requirement is an inference from the need to replay exercises.
- **Packer-built template:** the Proxmox ISO builder installs/provisions an image and converts it to a VM template. The builder does not manage that template's later lifecycle. This adds a template build/version/retirement responsibility, useful if installed packages and initial state need tighter control. Plugin `v1.2.4` was published on 2026-07-21. [Builder](https://developer.hashicorp.com/packer/integrations/hashicorp/proxmox/latest/components/builder/iso), [release](https://github.com/hashicorp/packer-plugin-proxmox/releases/tag/v1.2.4).

Most BPG operations use the API. Its documentation identifies snippet uploads, certain file uploads/imports, and LXC id mapping as SSH cases; API-based image download/import alternatives exist. Thus “API-only” must be assessed against the selected bootstrap path, not assumed for every provider resource. [Provider authentication and SSH requirements](https://www.bpg.sh/docs/), [snippet limitation](https://www.bpg.sh/docs/guides/known-issues/).

## Isolation and network enforcement

Proxmox's documentation discourages Docker directly on the hypervisor and recommends nesting application containers in QEMU VMs where strong isolation is required. Current source documentation also describes direct OCI-based containers as a technology preview. That newer capability does not establish it as the right trust boundary for deliberately compromised applications. [Proxmox FAQ](https://github.com/proxmox/pve-docs/blob/master/pve-faq.adoc), [container documentation](https://github.com/proxmox/pve-docs/blob/master/pct.adoc).

**Design inference:** Docker inside dedicated target VMs is a plausible boundary for this lab. A VM remains vulnerable to hypervisor bugs or misconfiguration; it is not an absolute containment guarantee. Decide whether separate applications share a target VM according to expected compromise scope and reset coupling.

Proxmox firewall rules can apply to hosts and guests, with IPv4/IPv6 support. Guest enforcement requires the relevant interface firewall flag as well as the general firewall enable option. The documentation distinguishes the legacy `pve-firewall` from the nftables `proxmox-firewall`: forward and VNet-level rules are ignored by the legacy backend. The source currently labels the nftables implementation a technology preview. Verify the installed package and its matching manual before designing around newer features. [Firewall documentation source](https://github.com/proxmox/pve-docs/blob/master/pve-firewall.adoc).

Docker introduces its own bridge-network filtering and NAT. Published container traffic can bypass the paths used by `ufw`; checking only guest `ufw` policy is insufficient evidence of isolation. [Docker firewall documentation](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

**Design implications:** define both IPv4 and IPv6 allowed flows; protect hypervisor administration separately; identify where target-to-target, target-to-Elastic, and outbound traffic are enforced. A private bridge/VLAN naming convention alone is not the acceptance test. Exercise the real packet paths, including published Docker ports and any management or maintenance route. Whether to use host rules, an independent router/firewall VM, or both remains open.

## Credentials and state

Proxmox API tokens support expiry/revocation and privilege separation. A separated token's effective permissions are the intersection of its own ACLs and its user's ACLs. Roles are scoped by path; pools can group managed resources. Required privileges are documented per API method. [Proxmox permission model](https://github.com/proxmox/pve-docs/blob/master/pveum.adoc).

**Design implication:** derive a role from the selected operations and target pool/storage paths. Do not label a copied provider example “least privilege.” Consider separate bootstrap credentials for infrastructure/network preparation versus routine target management; exact ACLs await the resource model. Keep control-plane credentials out of target images.

Terraform state/plan files can contain secret values; marking values sensitive is not equivalent to encrypting those files. Backend protection and secret handling must be designed explicitly. OpenTofu offers state/plan encryption but requires recoverable key management; encryption does not protect against lost state, replay, or the person running the command. [Terraform sensitive data](https://developer.hashicorp.com/terraform/language/manage-sensitive-data), [OpenTofu encryption](https://opentofu.org/docs/language/state/encryption/).

## Reset choices and evidence preservation

Proxmox supports full and linked clones; full clones avoid dependence on the source, while linked clones depend on their template/storage chain. Snapshot capabilities depend on storage, and VM snapshot configuration is stored with the VM. [VM cloning/snapshots](https://github.com/proxmox/pve-docs/blob/master/qm.adoc), [storage capabilities](https://github.com/proxmox/pve-docs/blob/master/pvesm.adoc).

| Reset contract | Benefits and limitations for this lab — design analysis |
| --- | --- |
| Recreate application containers and seed data | Fast and convenient for application-only changes. Compose lifecycle flags distinguish stopping, removing containers, and removing volumes; recreation alone is not proof that persistent data has been reset. It does not restore a compromised guest OS. [Compose module semantics](https://docs.ansible.com/projects/ansible/latest/collections/community/docker/docker_compose_v2_module.html). |
| Roll back target VM to a known clean snapshot | Returns target state toward a defined baseline. Must account for supported disk/storage configuration, retained credentials, and guest/collector state moving backwards. Validate log identity/cursors and duplicates rather than assuming a snapshot preserves collection continuity. |
| Destroy and rebuild target VM from pinned inputs | Re-establishes an explicit baseline and exercises reproducibility. Costs provisioning time; packages, images, seed data, and any required offline/update access must be available. Agent enrolment and target identity require deliberate handling. |

**Required separation, derived from the user's requirement:** evidence-bearing Elastic resources must sit outside target reset/destruction operations. Separate lifecycle/state ownership is one option; a distinct VM alone does not prevent a broad infrastructure destroy from deleting both. Define shutdown, target reset, and evidence deletion as different operations.

Reset safety applies to **already ingested** evidence. Events only buffered on the target can disappear when that target is rolled back or rebuilt. The telemetry decision must specify receipt verification, tolerable loss, and identity across resets; this research does not promise lossless forwarding. Preserving Elastic through target resets is also distinct from backing it up against disk failure or operator deletion.

## Facts and decisions still required

No Proxmox host was accessed; no infrastructure was deployed. Public documentation proves capabilities, not this installation's configuration. Proxmox HTML manuals were inaccessible through the research browser, so the project's first-party documentation source was used; master may describe features newer than the installed release.

Before finalising site-specific implementation, obtain:

1. Installed PVE/package versions; standalone versus cluster; architecture and supported guest images.
2. Allocatable CPU/RAM/storage; storage backends, snapshot/clone support, disk layouts, and VMID/pool conventions.
3. Bridges, VLANs, routing, IPv6, current firewall backend, management path, and authority to change shared networking.
4. Automation execution location, API trust/certificate setup, credential storage, permitted API scopes, and whether node SSH is acceptable.
5. Target compromise scope, reset speed requirement, image/package availability during maintenance, and retention/backup requirements for Elastic.

The existing network, lifecycle, and telemetry decision tickets can absorb these findings. Sharper questions now available: **Must routine deployment avoid host SSH? Which installed firewall backend enforces each flow? Is application recreation sufficient, or must reset recover from guest compromise? Who owns templates and persistent Elastic resources?** No new architecture decision has been made by this research.
