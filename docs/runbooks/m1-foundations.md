# M1 foundations runbook

Issue #20. Exit = check A1 in [acceptance checks](../decisions/acceptance-checks-and-build-plan.md).

## Layout

- `tofu/stacks/{firewall,elastic,targets}`: one OpenTofu stack each, own encrypted local state in `.state/<stack>.tfstate` (gitignored, workstation only), own pool `lab-<stack>`, own token. Attacker VM lives in `targets` (M5), as separate resources.
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

Not yet recorded: needs the live node. Paste `a1-verify.sh` output here, plus the `tofu plan` no-op result, then tick:

- [ ] Fresh checkout + state key deploys stacks in order
- [ ] Re-apply is a no-op
- [ ] Token cannot reach outside lab pools
- [ ] No node SSH used
- [ ] No secrets in repo/images
