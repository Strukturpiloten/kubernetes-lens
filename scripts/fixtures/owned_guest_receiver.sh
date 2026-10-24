#!/usr/bin/bash
# Original finite staging receiver; no caller text is executed as a command.
set -Eeuo pipefail
export LC_ALL=C
umask 077
# Preserve one diagnostic descriptor; utility/Bash stderr is never a wire log.
exec 3>&2 2> /dev/null
readonly root=/var/lib/kubernetes-lens-stage
readonly receiver=/var/lib/kubernetes-lens-stage/receiver
readonly boot_path=/proc/sys/kernel/random/boot_id
fail() {
  printf '%s\n' stage-receiver-refused >&3
  exit 1
}
[[ $# == 0 && $EUID == 0 && $BASH_VERSION == 5.3.9* ]] || fail
# Trusted guest OS tools/loader are part of the pinned whole-image boundary.
# Refuse an unavailable utility/profile rather than installing anything.
for tool in stat sha256sum dd wc cmp mv chmod flock cat; do
  [[ -f /usr/bin/$tool && ! -L /usr/bin/$tool ]] || fail
  [[ $(/usr/bin/stat -c '%u:%a' /usr/bin/$tool) == 0:755 ]] || fail
done
version=$(/usr/bin/dd --version)
[[ $version == 'dd (coreutils) 9.10'$'\n'* ]] || fail
[[ $(/usr/bin/flock --version) == 'flock from util-linux 2.41.5' ]] || fail
for path in / /usr /usr/bin /var /var/lib "$root"; do
  [[ -d $path && ! -L $path ]] || fail
  [[ $(/usr/bin/stat -c %u "$path") == 0 ]] || fail
  mode=$(/usr/bin/stat -c %a "$path")
  (((8#$mode & 8#022) == 0)) || fail
done
[[ $(/usr/bin/stat -c %a "$root") == 700 ]] || fail
for name in table plan.json checks.sha256 stage-kind.header stage-kubectl.header stage-node-oci.header; do
  [[ -f $root/$name && ! -L $root/$name && $(/usr/bin/stat -c '%u:%a:%h' "$root/$name") == 0:400:1 ]] || fail
done
[[ -f $receiver && ! -L $receiver && $(/usr/bin/stat -c '%u:%a:%h' "$receiver") == 0:500:1 ]] || fail
[[ -f $root/lock && ! -L $root/lock && $(/usr/bin/stat -c '%u:%a:%h' "$root/lock") == 0:600:1 ]] || fail
cd "$root"
/usr/bin/sha256sum --check --status checks.sha256 || fail
exec 9<> lock
/usr/bin/flock -n 9 || fail
# All state writers hold FD9; contention never poisons the active owner.
mapfile -t table < table
[[ ${#table[@]} == 7 && ${table[0]} == kubernetes-lens-owned-guest-table-v1 ]] || fail
readonly owner=${table[1]} profile=${table[2]} plan=${table[3]}
[[ $owner =~ ^[0-9a-f]{32}$ && $plan =~ ^[0-9a-f]{64}$ ]] || fail
[[ $profile == legacy-1.20.15 || $profile == modern-1.37.0 ]] || fail
boot=$(/usr/bin/cat "$boot_path")
[[ $boot =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || fail
readonly boot
state_write() {
  [[ ! -e state.new && ! -L state.new ]] || fail
  (
    set -o noclobber
    printf 'v1 %s %s %s %s %s %s\n' "$owner" "$plan" "$profile" "$boot" "$1" "$2" > state.new
  ) || fail
  /usr/bin/mv -T state.new state || fail
}
if [[ ! -e state && ! -L state ]]; then
  # Only a pristine first use can establish the boot-bound cursor.
  for name in kind kubectl node.oci.tar header.in payload.in extra.in; do [[ ! -e $name && ! -L $name ]] || fail; done
  state_write ready 0
fi
[[ -f state && ! -L state && $(/usr/bin/stat -c '%u:%a:%h' state) == 0:600:1 ]] || fail
state=$(/usr/bin/cat state)
prefix="v1 $owner $plan $profile $boot ready "
[[ $state == "$prefix"[012] ]] || fail
cursor=${state#"$prefix"}
# Shell command substitution strips LF/NUL; authenticate exact stored bytes too.
/usr/bin/cmp -s state <(printf '%s\n' "$state") || fail
# No retry after any uncertain operation, including SIGKILL/disconnect/lost ACK.
state_write inflight "$cursor"
poison() {
  trap - ERR HUP INT TERM
  state_write poisoned "$cursor" 2> /dev/null || true
  fail
}
trap poison ERR HUP INT TERM
readonly phases=(stage-kind stage-kubectl stage-node-oci)
readonly roles=(kind kubectl node-oci)
readonly names=(kind kubectl node.oci.tar)
readonly lengths=(11 14 15)
entry=${table[cursor + 4]}
[[ $entry =~ ^${roles[cursor]}\ ([1-9][0-9]{0,9})\ ([0-9a-f]{64})$ ]] || poison
size=${BASH_REMATCH[1]} sha=${BASH_REMATCH[2]}
((size <= 2147483648 && (cursor == 2 || size <= 134217728))) || poison
# Payload/header names are fixed. No caller path/hash/length or shell token exists.
for name in header.in payload.in extra.in "${names[cursor]}"; do [[ ! -e $name && ! -L $name ]] || poison; done
(
  set -o noclobber
  : > header.in
  : > payload.in
  : > extra.in
) || poison
exec 8> payload.in
identity=$(/usr/bin/stat -Lc '%d:%i:%u:%a:%h' /proc/self/fd/8)
/usr/bin/dd bs=1 count="${lengths[cursor]}" status=none > header.in || poison
[[ $(/usr/bin/wc -c < header.in) == "${lengths[cursor]}" ]] || poison
/usr/bin/cmp -s header.in "${phases[cursor]}.header" || poison
/usr/bin/dd bs=65536 count="${size}B" iflag=fullblock status=none >&8 || poison
[[ $(/usr/bin/stat -c '%d:%i:%u:%a:%h' payload.in) == "$identity" ]] || poison
[[ $(/usr/bin/wc -c < payload.in) == "$size" ]] || poison
[[ $(/usr/bin/sha256sum payload.in) == "$sha  payload.in" ]] || poison
/usr/bin/dd bs=1 count=1 status=none > extra.in || poison
[[ $(/usr/bin/wc -c < extra.in) == 0 ]] || poison
[[ $(/usr/bin/stat -c '%d:%i:%u:%a:%h' payload.in) == "$identity" ]] || poison
exec 8>&-
if ((cursor == 2)); then mode=600; else mode=700; fi
/usr/bin/chmod "$mode" payload.in || poison
[[ ! -e ${names[cursor]} && ! -L ${names[cursor]} ]] || poison
/usr/bin/mv -T payload.in "${names[cursor]}" || poison
# Retain one header/sentinel per cursor by fixed rename, avoiding deletion/retry.
/usr/bin/mv -T header.in "header.$cursor" || poison
/usr/bin/mv -T extra.in "extra.$cursor" || poison
if ((cursor == 2)); then state_write complete 3; else state_write ready "$((cursor + 1))"; fi
printf '{"schema":"kubernetes-lens-owned-guest-stage-reply-v1","owner":"%s","plan_sha256":"%s","phase":"%s","role":"%s","bytes":%s,"sha256":"%s","state":"staged"}\n' \
  "$owner" "$plan" "${phases[cursor]}" "${roles[cursor]}" "$size" "$sha" || poison
trap - ERR HUP INT TERM
