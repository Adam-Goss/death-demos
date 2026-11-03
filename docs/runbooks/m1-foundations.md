# M1 foundations runbook

Issue #20. Exit = check A1 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md).

## Layout

- `tofu/stacks/{firewall,elastic,targets,attacker,gateway}`: one OpenTofu stack each, own encrypted local state in `.state/<stack>.tfstate` (gitignored, workstation only), own pool `lab-<stack>`, own token. The attacker (M5) and the Guacamole gateway (#51) were first planned inside `targets` and are separate stacks, so a target reset can never rebuild them.
- `ansible/`: in-guest config only; never targets the Proxmox node.
- `scripts/bootstrap-proxmox.sh`: one-time, root, node shell. Pools, role `OpaleyeDeploy`, per-stack user + privilege-separated token. No `Sys.*`/`Permissions.*`. Storage `iso-files`, never `local` (see inventory).
- `scripts/lab.sh`: ordered runner (firewall, elastic, targets). `destroy all` skips Elastic; `destroy elastic` is refused (evidence deletion is a separate guarded command, M3).
- `scripts/a1-verify.sh`: prints the A1 evidence table.
- `tests/static-checks.sh`: offline guards (encryption enforced, no ssh block, no secrets, scoped role).

## State key

OpenTofu native AES-GCM encryption, PBKDF2 key from `OPALEYE_STATE_PASSPHRASE`, passed via `TF_ENCRYPTION` by `lab.sh`. Repo has no key provider, so running `tofu` without the wrapper fails closed. **Offline recovery:** generate with `openssl rand -base64 32`, print/store it on paper or an offline medium; losing it loses all state.

## Run

1. On the node: `BRIDGES="" scripts/bootstrap-proxmox.sh`; copy the three token secrets to the workstation secrets store.
2. Workstation env: `OPALEYE_STATE_PASSPHRASE`, `PROXMOX_VE_ENDPOINT`, `PROXMOX_VE_API_TOKEN_{FIREWALL,ELASTIC,TARGETS}`, optional `PROXMOX_VE_INSECURE=true`.
3. `scripts/lab.sh init all && scripts/lab.sh apply all`, then `scripts/a1-verify.sh`.
4. Re-run bootstrap with `BRIDGES="<bridge>"` once M2 creates lab bridges.

## A1 evidence

Collected 2026-10-28 on node `ludus` with `scripts/a1-verify.sh`. Token secrets are not recorded.

| source | destination | mode | expected | actual | enforcement point |
| --- | --- | --- | --- | --- | --- |
| firewall token | GET /pools/lab-firewall | n/a | 200 | 200 | PVE pool ACL |
| firewall token | GET /pools/lab-elastic | n/a | 403 | 403 | PVE pool ACL |
| firewall token | GET /pools/lab-targets | n/a | 403 | 403 | PVE pool ACL |
| firewall token | GET /storage/local | n/a | 403 | 403 | PVE storage ACL |
| firewall token | POST /access/users | n/a | 403 | 403 | no User.Modify |
| elastic token | GET /pools/lab-elastic | n/a | 200 | 200 | PVE pool ACL |
| elastic token | GET /pools/lab-firewall | n/a | 403 | 403 | PVE pool ACL |
| elastic token | GET /pools/lab-targets | n/a | 403 | 403 | PVE pool ACL |
| elastic token | GET /storage/local | n/a | 403 | 403 | PVE storage ACL |
| elastic token | POST /access/users | n/a | 403 | 403 | no User.Modify |
| targets token | GET /pools/lab-targets | n/a | 200 | 200 | PVE pool ACL |
| targets token | GET /pools/lab-firewall | n/a | 403 | 403 | PVE pool ACL |
| targets token | GET /pools/lab-elastic | n/a | 403 | 403 | PVE pool ACL |
| targets token | GET /storage/local | n/a | 403 | 403 | PVE storage ACL |
| targets token | POST /access/users | n/a | 403 | 403 | no User.Modify |

Offline checks:
ok   firewall: has versions.tf, main.tf, outputs.tf
ok   firewall: state encryption enforced
ok   firewall: own local state path
ok   firewall: provider pinned
ok   firewall: no SSH block (API token only)
ok   firewall: no hardcoded token
ok   elastic: has versions.tf, main.tf, outputs.tf
ok   elastic: state encryption enforced
ok   elastic: own local state path
ok   elastic: provider pinned
ok   elastic: no SSH block (API token only)
ok   elastic: no hardcoded token
ok   targets: has versions.tf, main.tf, outputs.tf
ok   targets: state encryption enforced
ok   targets: own local state path
ok   targets: provider pinned
ok   targets: no SSH block (API token only)
ok   targets: no hardcoded token
ok   bootstrap script exists
ok   ordered runner exists
ok   A1 verifier exists
ok   ansible.cfg exists
ok   gitignore covers state, tfvars, keys
ok   role has no Sys./Permissions.Modify privileges
ok   ACLs never granted on '/' root path
ok   token privilege separation on
ok   one token per stack
ok   no PVE token secrets (uuid) in repo
ok   no private keys in repo
ok   no tfstate/tfvars tracked

Ordered deploy then no-op re-apply (fresh state each time is the operator's call):
no-op firewall: yes
no-op elastic: yes
no-op targets: yes
node SSH used: no (provider has no ssh block; scripts never call ssh)

Result:

- [x] Fresh checkout + state key deploys stacks in order (`lab.sh init all` + `apply all`)
- [x] Re-apply is a no-op (`No changes` for all three stacks)
- [x] Token cannot reach outside lab pools (cross-pool 403, `/storage/local` 403, user create 403)
- [x] No node SSH used (provider has no `ssh` block; bootstrap ran once in the node's own shell)
- [x] No secrets in repo/images (static scan; no images exist yet)

Limits: negative probes cover pool, storage and user-create paths only; cross-pool VM create/delete is untested until M2 has VMs. Lock files committed after the first `tofu init`.
