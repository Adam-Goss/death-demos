#!/usr/bin/env bash
# Stand-in for scripts/target.sh in labops tests: a generation counter per target; bump/provision are recorded.
f="$STUB_GEN_DIR/$2"
[ -f "$f" ] || echo 1 > "$f"
case $1 in
  generation) cat "$f" ;;
  bump) printf 'bump|%s\n' "$*" >> "$STUB_LOG"; [ "${STUB_FAIL:-}" = bump ] && exit 1; echo $(( $(cat "$f") + 1 )) > "$f" ;;
  provision) printf 'provision|%s\n' "$*" >> "$STUB_LOG"; [ "${STUB_FAIL:-}" = provision ] && exit 1; exit 0 ;;
esac
