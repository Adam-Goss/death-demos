# M3 Elastic VM and ingestion runbook

Issue #22. Exit = check A3 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Inputs: [telemetry contracts](../decisions/telemetry-contracts-and-budgets.md), [lifecycle](../decisions/deployment-and-reset-lifecycle.md).

**Status: code and offline tests done; A3 evidence NOT yet collected (needs the live lab).** M4 does not start before the A3 tables below are filled in and reviewed.

## Decisions

| Item | Choice |
| --- | --- |
| Stack pin | Elasticsearch, Kibana, Elastic Agent (Fleet Server) **9.5.5**, Basic license, single node. Package sha512 in `network/plan.json` `elastic.packages` (taken from artifacts.elastic.co `.sha512` files, 2026-10-28); Ansible refuses a mismatch |
| VM | VMID 2003, pool `lab-elastic`, `10.77.3.10` on `vmbr2003`, 4 vCPU / 8 GB (heap 4 GB), disks on `iso-files`: OS 20 GB (`vda`), data 100 GB (`vdb`, `/var/lib/elasticsearch`), snapshots 100 GB (`vdc`, `/srv/es-snapshots`). The #9 placeholders; replaced after A10 |
| Image | Debian cloud image to a template (VMID 2300, pool `lab-elastic`) with `scripts/make-elastic-template.sh`, cloned over the API |
| Packages | Elastic has **no Internet, even in maintenance mode**. Ansible downloads on the workstation, checks the pinned sha512, copies over SSH |
| TLS | Lab CA generated on the workstation under `secrets/elastic/ca/` (gitignored, never in the repo or an image). Server cert SAN `10.77.3.10`, `elastic.lab`. Agents pin the CA SHA-256 fingerprint (set on the Fleet output); the CA file is passed at enrolment (M4) |
| Secrets | `elastic`, `kibana_system` passwords and Kibana encryption keys generated on first run into `secrets/elastic/`, reused after; Elastic's keystores hold them on the VM |
| Retention | ILM `lab-evidence-90d` and `lab-metrics-14d` (delete after 90/14 d from rollover: a minimum, the disk watermark is the real limit). Set per data stream through `<stream>@custom` component templates, with 0 replicas. Dataset lists in `network/plan.json` |
| Snapshots | Repository `lab-snapshots` (fs on the second disk), SLM `lab-daily` at 02:30, 14 days kept. **Not separate hardware**: one host, one storage pool; risk accepted in the [site inventory](../inventory/site-inventory.md). Point the snapshot disk's `datastore_id` at other storage when it exists |
| Config backup | `ansible-playbook playbooks/elastic-config-backup.yml` fetches `/etc/elasticsearch`, `/etc/kibana`, `/etc/lab-ca` to `secrets/elastic/config-backup.tgz` (keep it with the offline state key); snapshots omit these |
| Destroy guard | `prevent_destroy` on the VM; `lab.sh destroy elastic` refuses; `destroy all` skips Elastic; firewall/targets tokens have no ACL on `lab-elastic` (A3 probes this). Evidence deletion is a separate guarded command (M5/A9) |

## Run

1. Node, as root: `scripts/bootstrap-proxmox.sh` (pool/token for `elastic` already exist from M1), then `scripts/make-elastic-template.sh`.
2. Workstation: `export TF_VAR_node_name=ludus TF_VAR_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)"`; `scripts/lab.sh apply elastic`. Re-apply is a no-op.
3. VPN up. The firewall gives the operator only 5601 and 22 on Elastic (probes p32, p45, p48, p49), so API calls from the workstation go through an SSH tunnel: in another terminal `scripts/elastic-tunnel.sh` (forwards 19200/18220 to the VM's own 9200/8220; the VM must be reachable by SSH first). Then `cd ansible && ansible-galaxy collection install -r requirements.yml && ansible-playbook playbooks/elastic.yml`. Re-runnable; failures: re-run, then the manual path below.
4. Operator opens `https://10.77.3.10:5601` (user `elastic`, password in `secrets/elastic/elastic.password`; trust `secrets/elastic/ca/ca.crt`).
5. Evidence (destroy the elastic probe guest first, it holds the same address: `TF_VAR_probe_zones='["attacker","t1","t2"]'`, then `lab.sh apply firewall`): `scripts/a3-verify.sh services`; `labmode.py select t1`; `a3-verify.sh net lab`, `net vpn`, `net home` (vantage setup as in the [M2 runbook](m2-firewall-and-networks.md#how-to-rerun-a2)). Set `PROXMOX_VE_API_TOKEN_FIREWALL`, `_TARGETS`, `PVE_NODE` for the token-scope rows.

## Known gaps

- **Attacker and t2 reach ingestion ports** (p17, p50-p52): the M2 rules let all lab zones (attacker, t1, t2) send telemetry. #9 says "target to ingestion only"; narrowing attacker out is an M2 rule change, not done here. Raise before A3 sign-off.
- **Fleet Server install is one-shot** (gated on the Agent being installed): a changed flag, cert or version needs a manual `elastic-agent uninstall` first. Not auto-reconverged.
- **A3 shows config, not streams**: no evidence data streams exist until M4, so the per-stream lifecycle row only proves the `@custom` templates; A4 re-checks real streams. The restore test uses a throwaway index, not an SLM-made snapshot.
- **Destroy guard** is proven by `lab.sh` refusal, the `prevent_destroy` setting and the token-scope rows (SKIP without Proxmox env), not by a live `tofu plan`.

- **Integration packages** (`auditd_manager`, `docker`, `apache`, firewall flow logs) are not in Kibana's bundled set and Elastic has no Internet (`xpack.fleet.isAirGapped: true`). M4 uploads them as zip packages from the workstation (`POST /api/fleet/epm/packages`). Bundled: `fleet_server`, `endpoint`, `system`, `elastic_agent`.
- **Dataset names in `plan.json` are expected, not observed.** `a3-verify.sh services` fails if a data stream exists without a lab policy; A4 confirms the real names (esp. Defend `logs-endpoint.events.*`, whether its template includes `@custom`) and extends the lists.
- **Ingest-lag alert and exercise block** (Basic-license ability): decided at A4, with the scheduled-script fallback from #9.
- **Firewall syslog to Elastic** (flow logs) arrives with A4.
- Unverified on the live VM: `elastic-agent install` flags for 9.5.5, the Kibana `xpack.fleet.*` preconfiguration keys, and the `@custom` settings merge. Fix by re-running; do not hand-edit.
- First SSH uses `StrictHostKeyChecking=accept-new`; the host key changes on every recreate (`ssh-keygen -R 10.77.3.10`).

## Manual recovery (no auto-destroy)

Re-run the playbook. If Elasticsearch will not start: `journalctl -u elasticsearch` on the VM, fix the code, re-run. Never `tofu destroy`; losing the VM is losing evidence (restore from `lab-snapshots` into a rebuilt VM, config from `config-backup.tgz`).

## A3 evidence

Not collected yet. Paste the unedited output of each run here, one table per run:

- `a3-verify.sh services`
- `a3-verify.sh net lab` / `net vpn` / `net home`
