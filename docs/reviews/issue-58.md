# Issue 58 whole-repository review

Review completed 2026-11-04 after #52, #59, and #61 were merged.

| Area | Scope reviewed | Result |
| --- | --- | --- |
| Operator commands and verifiers | `scripts/*.py`, `scripts/*.sh` | No additional defects found; policy and unit checks pass. |
| Infrastructure as code | `tofu/stacks/*` | Static checks pass; state isolation, provider pinning, token separation, and destroy guards pass. |
| In-guest configuration | `ansible/` | Syntax and static checks pass; no unsafe privilege or root ACL findings. |
| Policy and config | `network/plan.json`, seed generation, `netpolicy.py` | Exercise and maintenance lint plus seed check pass. |
| Malware analysis zone | analysis stack, roles, flows, probes, runbook | Live evidence is recorded in `docs/runbooks/malware-analysis.md`; isolation and online/offline checks pass. |
| Tests | `tests/*`, `tests/static-checks.sh` | 67 tests pass; static checks pass. Added `tests/conftest.py` to make plain pytest collection reliable. |
| Cross-cutting safety | isolation, secrets, dead-man, evidence deletion | No additional offline findings; no secrets detected. |

## Windows failure classification

The previously reported 32 Windows failures are launcher failures, not product defects: tests that spawn repository shell scripts receive the WSL `bash.exe` launcher, which cannot execute a `C:/...` checkout path. The affected tests are the shell-spawning cases in `test_a2_verify`, `test_elastic_plan`, `test_labops`, `test_netpolicy`, `test_ops_timers`, `test_script_exec`, `test_static_checks`, and `test_target_plan`. They are resolved by Git Bash or `OPALEYE_BASH`; this is documented in the README. Python-only tests are unaffected.

## Verification

`pytest -q`, `bash tests/static-checks.sh`, both `netpolicy.py lint` modes, `opnsense_seed.py check`, and `git diff --check` pass. Live A2 evidence for the analysis zone and the remaining lab matrices is recorded in the runbooks; this checkout has no live Proxmox credentials, so a new probe run cannot be initiated here.
