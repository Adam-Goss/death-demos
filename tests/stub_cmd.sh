#!/usr/bin/env bash
# Stand-in for lab.sh / ansible-playbook in labops tests: records argv and the TF_VAR it was given.
printf '%s\n' "$(printf '%s|' "$@")TF=${TF_VAR_rebuild_generations:-}" >> "$STUB_LOG"
exit "${STUB_CMD_RC:-0}"
