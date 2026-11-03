# Allow one isolated Windows VM for malware analysis

The lab keeps Windows and Active Directory out of scope: the targets are Linux workloads and the lab has no domain. Malware analysis needs a Windows analysis machine (FLARE-VM) beside a Linux one (REMnux). We amend the out-of-scope line narrowly: **one isolated Windows analysis VM is in scope; no Active Directory, no domain join, no other Windows guest.** Windows elsewhere in the lab stays out of scope.

The VM lives in its own **analysis zone** on the firewall VM, with the same default-deny policy as every other zone ([ADR 0001](0001-isolate-the-attack-lab-behind-a-firewall-vm.md)):

- no route to the attacker, targets, home LAN, Proxmox or any other zone;
- only the Gateway VM may initiate a connection into the zone (RDP to FLARE, SSH to both);
- FLARE and REMnux may talk to each other, because REMnux serves fake Internet services (INetSim) to the sample;
- the zone may reach only the ingestion endpoint for telemetry;
- Internet is off by default and switched on by one time-limited operator command for any public IPv4 address only (private ranges, the home LAN, Proxmox and the other zones stay blocked, IPv6 stays disabled). The operator goes offline before detonating a sample; this is documented, not enforced.

A sample can tamper with its own host, so telemetry from the zone is best-effort evidence, and recovery is a revert to a clean Proxmox snapshot, never a repair. The analysis zone adds no Elastic Defend (it conflicts with analysis tools and may kill the sample).

The detailed design is in [issue #52](https://github.com/Adam-Goss/death-demos/issues/52) and the runbook [malware-analysis.md](../runbooks/malware-analysis.md).
