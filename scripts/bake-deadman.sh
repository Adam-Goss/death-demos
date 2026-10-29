#!/bin/sh
# Bake the dead-man files into a COPY of a verified nano disk (#42).
# Run as root on a FreeBSD build host; the firewall need not exist or be reachable.
# Usage: bake-deadman.sh pristine-nano.raw prepared-nano.raw
set -eu
cd "$(dirname "$0")/.."
[ "$(uname -s)" = FreeBSD ] && [ "$(id -u)" = 0 ] || {
  echo "baking the UFS nano disk needs root on a FreeBSD build host" >&2; exit 1;
}
base=${1:?usage: bake-deadman.sh pristine-nano.raw prepared-nano.raw}
out=${2:?usage: bake-deadman.sh pristine-nano.raw prepared-nano.raw}
[ -f "$base" ] || { echo "missing pristine nano disk: $base" >&2; exit 1; }
[ ! "$base" -ef "$out" ] || { echo "input and output disks must differ" >&2; exit 1; }
# Keep the fetcher's checksum cache pristine; publish only after a clean unmount.
work=$(mktemp "${out}.XXXXXXXX")
mountpoint=$(mktemp -d /tmp/opaleye-nano.XXXXXXXX)
device=
mounted=
cleanup() {
  if [ -n "$mounted" ]; then umount "$mountpoint" || return 1; fi
  if [ -n "$device" ]; then mdconfig -d -u "$device" || return 1; fi
  rmdir "$mountpoint"
  rm -f "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
cp "$base" "$work"
device=$(mdconfig -a -t vnode -f "$work")
partition=
# The nano image's BSD partition starts at sector 0: fstyp identifies both md0
# and md0a as UFS. Select partition providers, not overlapping disk aliases.
for candidate in $(gpart show -p "$device" | awk '$4 == "freebsd-ufs" {print "/dev/" $3}'); do
  [ -z "$partition" ] || { echo "multiple UFS partitions; refusing ambiguous nano disk" >&2; exit 1; }
  partition=$candidate
done
[ -n "$partition" ] || { echo "no UFS root partition in nano disk" >&2; exit 1; }
mount -t ufs "$partition" "$mountpoint"
mounted=yes
sh scripts/install-deadman.sh "$mountpoint"
umount "$mountpoint"
mounted=
mdconfig -d -u "$device"
device=
mv "$work" "$out"
echo "$out baked with the dead-man script and configd action"
