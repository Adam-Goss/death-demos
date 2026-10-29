# M3 Elastic VM and ingestion runbook

Issue #22. Exit = check A3 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Inputs: [telemetry contracts](../decisions/telemetry-contracts-and-budgets.md), [lifecycle](../decisions/deployment-and-reset-lifecycle.md).

**Status: VM built, play converges (re-run changes nothing). A3 `services`, `net vpn`, `net lab` and `net home` PASS (2026-10-29). `net lab` PASS (9 rows). `net home` PASS (1 row).** All A3 tables below are filled in (re-run 2026-10-29 after the attacker ingestion rule was removed).

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
5. Evidence (first `ansible-playbook playbooks/elastic-config-backup.yml`: `services` checks the archive holds the keystores, certificates and configs; destroy the elastic probe guest first, it holds the same address: `TF_VAR_probe_zones='["attacker","t1","t2"]'`, then `lab.sh apply firewall`): `scripts/a3-verify.sh services`; `labmode.py select t1`; `a3-verify.sh net lab`, `net vpn`, `net home` (vantage setup as in the [M2 runbook](m2-firewall-and-networks.md#how-to-rerun-a2)). Set `PROXMOX_VE_API_TOKEN_FIREWALL`, `_TARGETS`, `PVE_NODE` for the token-scope rows.

## Known gaps

- **Attacker ingestion access removed (resolved at A3).** The M2 rules let the attacker reach 9200/8220; the adversary must not write to the evidence store, so `netpolicy.py` now allows only t1/t2 to ingest (probes p17, p51 now `deny`). Re-verified below. t2 keeps ingestion; no M4/M5 flow needs attacker telemetry.
- **Fleet Server install is one-shot** (gated on the Agent being installed): a changed flag, cert or version needs a manual `elastic-agent uninstall` first. Not auto-reconverged.
- **A3 shows config, not streams**: no evidence data streams exist until M4, so the per-stream lifecycle row only proves the `@custom` templates; A4 re-checks real streams. The restore test uses a throwaway index, not an SLM-made snapshot.
- **Destroy guard** is proven by `lab.sh` refusal, the `prevent_destroy` setting and the token-scope rows (SKIP without Proxmox env), not by a live `tofu plan`.

- M4 code now provides the upload and the `lab-stamp` pipeline (see [M4 runbook](m4-target.md)); the M3 play creates the pipeline, so re-run `playbooks/elastic.yml` once before M4.
- **Integration packages** (`auditd_manager`, `docker`, `apache`, firewall flow logs) are not in Kibana's bundled set and Elastic has no Internet (`xpack.fleet.isAirGapped: true`). M4 uploads them as zip packages from the workstation (`POST /api/fleet/epm/packages`). Bundled: `fleet_server`, `endpoint`, `system`, `elastic_agent`.
- **Dataset names in `plan.json` are expected, not observed.** `a3-verify.sh services` fails if a data stream exists without a lab policy; A4 confirms the real names (esp. Defend `logs-endpoint.events.*`, whether its template includes `@custom`) and extends the lists.
- **Ingest-lag alert and exercise block** (Basic-license ability): decided at A4, with the scheduled-script fallback from #9.
- **Firewall syslog to Elastic** (flow logs) arrives with A4.
- Unverified on the live VM: `elastic-agent install` flags for 9.5.5, the Kibana `xpack.fleet.*` preconfiguration keys, and the `@custom` settings merge. Fix by re-running; do not hand-edit.
- First SSH uses `StrictHostKeyChecking=accept-new`; the host key changes on every recreate (`ssh-keygen -R 10.77.3.10`).

## Manual recovery (no auto-destroy)

Re-run the playbook. If Elasticsearch will not start: `journalctl -u elasticsearch` on the VM, fix the code, re-run. Never `tofu destroy`; losing the VM is losing evidence (restore from `lab-snapshots` into a rebuilt VM, config from `config-backup.tgz`).

## Live-run findings (2026-10-29, first apply)

Fixed in code, each found by the live run: timesyncd drop-in dir missing; `elasticsearch-keystore create` hung on its overwrite prompt (package already creates the keystore); Elasticsearch 9 only reads SSL files under `/etc/elasticsearch` (certs copied to `/etc/elasticsearch/certs`); ES now also binds `127.0.0.1` so the SSH tunnel works; Kibana keystore CLI needs a readable working directory; `xpack.fleet.packages` must list `fleet_server` (only it is bundled; `system` fails the registry lookup) and the Fleet Server package policy is ensured by API when Kibana's first setup failed; `elastic_agent` streams added to `plan.json` and existing streams adopt the lab policy; `a3-verify.sh net` row total honours `ONLY_DST`. Workstation notes: run Ansible with `ANSIBLE_CONFIG=ansible/ansible.cfg` when the checkout is world-writable (WSL on `/mnt/c`); the firewall must be in a mode (`labmode.py exercise`) before the operator can reach Elastic:22/5601.

## A3 evidence

Unedited output, re-run after the attacker was removed from the ingestion rules. Operator vantage, exercise mode, target t1 selected.

### `a3-verify.sh services`

| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | elastic:9200 version | exercise | 9.5.5 | 9.5.5 | elasticsearch |
| operator | elastic:9200 nodes | exercise | 1 | 1 | elasticsearch |
| operator | elastic:9200 unassigned shards | exercise | 0 | 0 | elasticsearch |
| operator | elastic:9200 status | exercise | green | green | elasticsearch |
| operator | elastic:9200 license | exercise | basic/active | basic/active | elasticsearch |
| operator | elastic:5601 kibana | exercise | available | available | kibana |
| operator | elastic:5601 version | exercise | 9.5.5 | 9.5.5 | kibana |
| operator | elastic:8220 fleet server | exercise | HEALTHY | HEALTHY | fleet-server |
| operator | elastic:9200 (tunnel) TLS with lab CA | exercise | verified | verified | server certificate chain |
| operator | elastic:9200 (tunnel) TLS without lab CA | exercise | rejected | rejected | client trust store |
| operator | elastic:5601 TLS with lab CA | exercise | verified | verified | server certificate chain |
| operator | elastic:5601 TLS without lab CA | exercise | rejected | rejected | client trust store |
| operator | elastic:8220 (tunnel) TLS with lab CA | exercise | verified | verified | server certificate chain |
| operator | elastic:8220 (tunnel) TLS without lab CA | exercise | rejected | rejected | client trust store |
| operator | ilm lab-evidence-90d delete | exercise | 90d | 90d | ilm policy |
| operator | ilm lab-metrics-14d delete | exercise | 14d | 14d | ilm policy |
| operator | @custom templates (evidence, 12) | exercise | all use lab-evidence-90d | all use lab-evidence-90d | component templates |
| operator | @custom templates (metrics, 31) | exercise | all use lab-metrics-14d | all use lab-metrics-14d | component templates |
| operator | existing data streams (18) | exercise | all on a lab policy | all on a lab policy | ilm per data stream |
| operator | snapshot repository lab-snapshots | exercise | verified | verified | elasticsearch snapshot repo |
| operator | slm lab-daily | exercise | 0 30 2 * * ? / 14d | 0 30 2 * * ? / 14d | slm policy |
| operator | snapshot restore test (3 docs) | exercise | 3 | 3 | snapshot repo |
| operator | config backup (keystores, certs, configs) | exercise | complete | complete | secrets/elastic/config-backup.tgz |
| operator | lab.sh destroy elastic | exercise | refused | refused | scripts/lab.sh guard |
| operator | elastic VM prevent_destroy | exercise | set | set | tofu lifecycle |
| firewall token | proxmox vm 2003 (elastic) | exercise | deny | deny | proxmox pool ACL |
| targets token | proxmox vm 2003 (elastic) | exercise | deny | deny | proxmox pool ACL |

phase=a3 rows=27 skipped=0 PASS

### `a3-verify.sh net vpn`

ok: rules match the probe matrix (exercise)
| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| operator | elastic:5601 | exercise | allow | allow | firewall:opt4 |
| operator | elastic:22 | exercise | allow | allow | firewall:opt4 |
| operator | elastic:9200 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |
| operator | elastic:8220 | exercise | deny | deny | firewall:opt4 (deny logged: yes) |

phase=vpn mode=exercise selected=t1 rows=4 skipped=0 PASS

### `a3-verify.sh net lab`

Probe guests in attacker/t1/t2 (no elastic probe), created and destroyed afterwards. attacker -> elastic:9200 and :8220 are now `deny` (blocks logged); t1/t2 still allowed.

ok: rules match the probe matrix (exercise)
| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| attacker | elastic:5601 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| attacker | elastic:9200 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| t1 | elastic:9200 | exercise | allow | allow | firewall:opt2 |
| t1 | elastic:8220 | exercise | allow | allow | firewall:opt2 |
| t1 | elastic:5601 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t1 | elastic:22 | exercise | deny | deny | firewall:opt2 (deny logged: yes) |
| t2 | elastic:9200 | exercise | allow | allow | firewall:opt3 |
| attacker | elastic:8220 | exercise | deny | deny | firewall:lan (deny logged: yes) |
| t2 | elastic:8220 | exercise | allow | allow | firewall:opt3 |

phase=lab mode=exercise selected=t1 rows=9 skipped=0 PASS

### `a3-verify.sh net home`

Source aliases `192.168.0.50`, `203.0.113.55` and host routes to the lab targets via the firewall WAN `192.168.0.82` were added in WSL as root (`ip addr add ... dev eth6`, `ip route add`) and removed afterwards. Do not use `New-NetIPAddress` on a DHCP Wi-Fi interface: it disables DHCP and drops the primary address.

ok: rules match the probe matrix (exercise)
| source | destination/port | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| workstation | elastic:5601 | exercise | deny | deny | firewall:wan (deny logged: yes) |

phase=home mode=exercise selected=t1 rows=1 skipped=0 PASS
