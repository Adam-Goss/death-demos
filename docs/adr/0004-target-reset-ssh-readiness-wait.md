# ADR 0004: Wait for target SSH before provisioning

## Status

Accepted

## Decision

Keep the existing reset contract: the rebuild generation is bumped before
provisioning, and a failed provision is recoverable by rerunning
`bash scripts/target.sh provision <target>`. Add a bounded SSH readiness wait
to `target.sh provision` before the Ansible target play, using `LABOPS_SSH_WAIT`
with a 240 second default.

## Rationale

The generation is the OpenTofu replacement trigger, so provisioning at the old
generation cannot replace the VM. A two-phase generation commit would broaden
the state machine and risk the registry and drain contracts. The observed
failure was commonly a short boot race: OpenTofu had completed while `sshd`
was not listening yet. Waiting for the same operator SSH path used by Ansible
removes that race while preserving the documented, idempotent recovery path
for genuine provisioning failures.
