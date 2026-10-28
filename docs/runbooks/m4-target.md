# M4 Target VM with DVWA and evidence arrival runbook

Issue #23. Exit = checks **A4, A5** in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md). Inputs: [telemetry contracts](../decisions/telemetry-contracts-and-budgets.md), [first targets](../decisions/first-targets-and-hunt-outcomes.md), [lifecycle](../decisions/deployment-and-reset-lifecycle.md), [M3 runbook](m3-elastic.md).

**Status: code and offline tests only. A4 and A5 evidence is NOT collected.** Written without the VPN and before A3 (M3, PR #35) was run on the live lab; nothing here has touched the firewall, Proxmox or Elastic. Every "unverified" item below is a hypothesis that the first live run settles by editing code and re-running, not by hand repair. **M5 does not start until the A4/A5 tables at the bottom are filled in and reviewed**, and M4 itself should not start live work before A3 is signed off.

## Decisions

| Item | Choice |
| --- | --- |
| Target | `t1`: VMID 2011, pool `lab-targets`, `10.77.11.10` on `vmbr2011`, 2 vCPU / 4 GB, 30 GB OS disk on `iso-files`, cloned from template 2301 (`scripts/make-target-template.sh`; a bare Debian cloud image, no Agent, no token). All in `network/plan.json` (`targets.t1`) |
| App | DVWA from the upstream [compose.yml](https://github.com/digininja/DVWA/blob/a1978a2fed195acd093010af6395f86a281537ca/compose.yml) shape, both images **pinned by digest** in `target_stack.dvwa.images` (resolved 2026-10-28 from the registries: `ghcr.io/digininja/dvwa` `latest`, `mariadb:10`). Not built locally. `DEFAULT_SECURITY_LEVEL=low` (Exercise 1). Published `80:80`. DB credentials are DVWA's published defaults, DB port unpublished |
| Reset = rebuild | Raising the generation replaces the whole VM (`replace_triggered_by`): OS, Docker volumes, uploads, app files. No destroy guard on this stack. `scripts/target.sh bump` increments; it **refuses without `--acknowledge-no-drain-check`** until M5 provides the drain check |
| Evidence sources | One Fleet agent policy per target (`lab-target-t1`): **Elastic Defend** (preset `DataCollection`: events only, no protections, so the exercise can run and be observed), **Auditd Manager** (explicit rules: `execve`/`execveat`, `connect`), **Docker** container logs, **Apache** access/error via Filestream on `/var/log/dvwa/apache2/` (bind-mounted over the image's stdout symlinks), **System** metrics (14 d). Docker and Apache *metrics* are disabled. Defined in `scripts/fleetctl.py` |
| Integration packages | `auditd_manager`, `docker`, `apache` are **not bundled** and Elastic has no Internet: `fleetctl.py fetch-packages` downloads the zips on the workstation (sha256 pinned in `target_stack.integrations`), `upload-packages` posts them to Kibana. Bundled: `endpoint`, `system` |
| Enrolment | Token issued per rebuild by `fleetctl.py issue-token t1 <generation>` (name `t1-gen<N>`), which first **deletes the target's older tokens and unenrols its older agents (revoke)**. It is printed to stdout, held in Ansible memory on `no_log` tasks, passed to `elastic-agent install`, never written to a file, template or image. Agent tarball: workstation download with the plan's sha512, copied over SSH. Agent trusts `/etc/lab-ca/ca.crt` |
| Lab fields | `lab.target_id` and `lab.rebuild_generation` are stamped by the **`lab-stamp` final ingest pipeline**, set as `index.final_pipeline` in the M3 `<stream>@custom` templates (with `lab.*` mappings). It maps `agent.id` to the target and generation; `register-agent` appends after each enrolment and **never prunes**, so late events of an old generation keep their generation. This deviates from "agent policy custom fields" in #9 because Defend events cannot carry policy-level custom fields; one mechanism covers every source. The pipeline is created by the M3 play only if absent, so re-running it never wipes the registry. `lab.exercise_id` is mapped but set by M5 |
| Times | `@timestamp` stays the source time; `event.created` is the integration's; `event.ingested` is set by the pipeline only if missing. A4 checks the three are present and distinct |
| Ingest lag | `fleetctl.py lag-rule` creates Kibana rule `lab-ingest-lag` (ES\|QL rule, every 1 min, `event.ingested - @timestamp > 120 s`, no actions: it shows in Rules/Alerts). **Whether Basic licence allows an ES\|QL rule is unverified**; fallback is the scheduled check `fleetctl.py ingest-lag` (exit 1 on lag), usable from cron on the workstation with the tunnel up |
| Update sources | The DVWA image is on `ghcr.io`, which was not an allowed maintenance destination. **Added `ghcr.io` and `pkg-containers.githubusercontent.com` to `update_sources`** (M2 policy change: takes effect at the next `labmode.py maintenance`, re-run `a2-verify.sh maintenance none lab` to re-record). Elastic still gets no egress |

## Run (when the lab is available)

1. Preconditions: A3 passed; `scripts/make-target-template.sh` run on the node as root (pool `lab-targets` exists from M1); the elastic probe guest at `10.77.11.10` destroyed (`TF_VAR_probe_zones='["attacker","elastic","t2"]'`, `lab.sh apply firewall`) because it holds the same address.
2. Elastic side, VPN up, `scripts/elastic-tunnel.sh` running in another terminal: `cd ansible && ansible-playbook playbooks/elastic.yml` (re-run once so the `@custom` templates and `lab-stamp` exist), then `ansible-playbook playbooks/elastic-evidence.yml` (fetch and upload zips, policy, lag rule; the `lab-stamp` pipeline comes from the M3 play).
3. Target: `labmode.py maintenance --minutes 60 --reason "M4 provision"` (`labmode.py tick` timer running), `export TF_VAR_node_name=ludus TF_VAR_ssh_public_key="$(cat ~/.ssh/id_ed25519.pub)"`, `scripts/target.sh provision t1`. Re-run is safe (token issued only when the Agent is missing; DB created once per VM). Then `labmode.py exercise`, `REVERIFY=1 scripts/a2-verify.sh exercise t1 lab`, `labmode.py select t1`.
4. Generate traffic from the attacker VM (browse `http://10.77.11.10/`, log in `admin`/`password`, open Command Injection with a benign `127.0.0.1; id`).
5. Evidence: `scripts/a5-verify.sh t1`, `scripts/a4-verify.sh t1`, then the manual A4 rows below. Paste unedited output into the tables at the bottom.

A rebuild (after M5's drain check exists): `scripts/target.sh bump t1`, then step 3.

## Manual A4 rows (no script can answer these)

- **Apache POST body / query visibility.** From the attacker: `curl 'http://10.77.11.10/vulnerabilities/exec/?ip=1'` and a POST to `/login.php`. Expect the query string in `logs-apache.access` and **no POST body** (combined format). Do not enable body logging without a decision: it captures credentials.
- **1,024-byte Filestream fingerprint.** Fingerprint length is set to 64 in the Apache streams; confirm a fresh, tiny access log still shows its first request in Elastic.
- **Defend + auditd coexistence.** Both agents' data arrive and the shell spawn of Exercise 1 appears in Defend `logs-endpoint.events.process` with container attribution (`container.id` or cgroup). Add auditd rules only if Defend misses the spawn (#9). `auditd` the daemon is deliberately not installed; Auditd Manager owns the audit socket.
- **Firewall flow logs** arrive tagged with `lab.target_id`: **not built here.** The firewall's syslog destination to Elastic and its ingest are untouched by this code (they need the live firewall); recorded as an A4 gap, not a pass.

## Known gaps and unverified assumptions

- **Nothing ran live.** Unverified until the first run: Fleet API payload shapes in `fleetctl.py` (input keys such as `auditd-auditd`, `docker-filestream`, `apache-filestream`, stream var names, the Defend `integration_config` preset, ES\|QL rule params); the `<stream>@custom` and `index.final_pipeline` merge into Defend's templates; `elastic-agent install` flags on 9.5.5; Debian 13 `docker-compose` package providing Compose v2; DVWA `setup.php` token markup and the "Setup successful" text; DVWA's `latest` image matching the compose commit a1978a2 (it is whatever `latest` was on 2026-10-28; the digest is the pin).
- Dataset names in `plan.json` are still expected, not observed (see M3). `a3-verify.sh services` fails on any data stream outside a lab policy, which is how a wrong name shows up.
- **Attacker and t2 can reach ingestion ports** (M3 gap, unchanged). t2 has no VM.
- `elastic-tunnel.sh` is needed for ES calls from the workstation; Kibana (5601) is direct.
- Image digests pin the images, not the packages Debian `apt` installs at provision time (Debian is the moving part; recorded in the evidence if it matters).
- **Events before `register-agent` runs are unstamped** (the pipeline maps `agent.id`, known only after enrolment). Backfill is not built; A4 uses events after registration.
- A4 requires `@timestamp` and `event.ingested` distinct; `event.created` is shown but may be absent for Defend. The ingest-lag rule's firing is not tested, only that it exists.
- `ghcr.io` in `update_sources`, `target.sh bump` and the `lab.exercise_id` mapping go slightly past M4's scope; kept because the image and rebuild flow need them.
- Enrolment token appears briefly in the target's process list during `elastic-agent install`.
- Host key changes on each rebuild; `target.sh` clears the old one.
- A5 "no token on disk" greps the places our code touches; the Agent's own encrypted store under `/opt/Elastic` is expected and out of scope.

## Manual recovery (no hand repair)

A target that fails or drifts is rebuilt: `bump` (acknowledging loss) and `provision`. If the Elastic side fails: fix the code, re-run `elastic-evidence.yml`. Never `tofu destroy` Elastic.

## A4 evidence

**Not collected.** Paste the unedited `scripts/a4-verify.sh t1` table, then the manual rows (source, destination/port, mode, expected, actual, enforcement point).

## A5 evidence

**Not collected.** Paste the unedited `scripts/a5-verify.sh t1` table, plus the Ansible recap of a second `target.sh provision t1` showing no changes except the unconditional `fleetctl register-agent`.
