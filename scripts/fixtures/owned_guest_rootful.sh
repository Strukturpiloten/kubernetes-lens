#!/usr/bin/bash
set -Eeuo pipefail
export LC_ALL=C
umask 077
readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage
readonly credits=$root/state/credits captures=$root/captures
readonly fd_max=1073741816 pid_max=32768
readonly hard_nofile_max=9999999999
prerequisite_mode=0
rootful_admitted=0
record_guard_fuel=0
declare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null postlog_reason=null k_site='' i_admitted=0 i_return=null i_round=0
exec 3>&2 2> /dev/null
fail() {
  if [[ $BASH_SUBSHELL == 0 && ${rootful_admitted:-0} == 1 && ${rootful_intent:-} == execution-v1 && ${mode:-} == work && -z $postlog_failure ]]; then
    case $postlog_site in [rifnje]) postlog_failure=pl1.$postlog_site ;; [a-dghk]) postlog_failure=pl2.$postlog_site ;; esac
    if [[ $postlog_site == r ]]; then
      case ${1:-} in
        block | filesystem | inv-drift | inv-empty | inv-fd-access | inv-fd-form | inv-fd-range | inv-nf-form | inv-nf-range | inv-pid-range | inv-proc-form | inv-proc-pid | inv-proc-read | inv-proc-task | inv-snap-size | inv-task-empty | inv-task-form | inv-task-read | inv-task-tid | inv-tid-count | mapper | memory | mount | mount-both | mount-proc | mount-root | namespace | nr-open-form | nr-open-range | pid-max) printf -v postlog_reason '"%s"' "$1" ;;
        *) postlog_reason='"unlabelled"' ;;
      esac
    fi
    if [[ $postlog_site == k ]]; then
      case $k_site in [a-o]) printf -v postlog_reason '"k4.%s"' "$k_site" ;; esac
      if [[ $k_site == i && $i_round == [12] ]]; then
        local +x atom=''
        case $i_admitted:$i_return in
          0:null) atom=p ;;
          1:64) atom=c ;;
          1:65) atom=n ;;
          1:66) atom=v ;;
          1:67) atom=r ;;
          1:*)
            if [[ $i_return =~ ^[1-9][0-9]{0,2}$ ]] && ((i_return <= 255)); then atom=x.$i_return; fi
            ;;
        esac
        [[ -z $atom ]] || printf -v postlog_reason '"k4.i.%s.%s"' "$i_round" "$atom"
      fi
    fi
    if [[ $postlog_site == n || $postlog_site == k && $k_site == [acehjmo] ]]; then
      printf -v postlog_native '{"return_status":%s,"command_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s}' "$postlog_rc" "$postlog_tool" "$postlog_out" "$postlog_err"
    fi
  fi
  case ${1:-} in
    [a-p])
      if [[ -z $guard_reason && ${poll_active:-0} == 1 && $1 == [gp] ]]; then guard_reason=pg2.$1.$name.$poll_state.$i.$pid.$start; fi
      guard_reason=${guard_reason:-pg1.$1}
      ;;
  esac
  if [[ ${rootful_admitted:-0} == 1 && -d $root/state && ${mode:-work} != cleanup ]]; then printf '%s\n' poisoned > "$root/state/poison" || true; fi
  printf '%s\n' rootful-receiver-refused >&3
  if [[ ${prerequisite_mode:-0} == 1 && ${mode:-work} != cleanup && $# == 1 ]]; then
    case $1 in
      entry | source | paths | packages | exec-closure | eof | fresh-state | pid-limits | pid-max | nr-open-form | nr-open-range | namespace | mount | mount-both | mount-proc | mount-root | memory | block | mapper | filesystem | inventory | inv-pid-range | inv-proc-task | inv-proc-read | inv-proc-pid | inv-proc-form | inv-task-empty | inv-tid-count | inv-task-read | inv-task-tid | inv-task-form | inv-nf-form | inv-nf-range | inv-fd-access | inv-fd-form | inv-fd-range | inv-snap-size | inv-empty | inv-drift | podman-info | podman-profile | pkg-jq-ver | pkg-sd-ver | pkg-sd-query | pkg-kernel | rpm-shape | rpm-bash | rpm-jq | rpm-coreutils | rpm-systemd | rpm-podman | rpm-skopeo | rpm-crun | rpm-conmon | rpm-netavark | rpm-aardvark | rpm-util-linux | rpm-libcap | pkg-sd-q[123456789] | pkg-sd-q[123456789][0123456789] | pkg-sd-q1[0123456789][0123456789] | pkg-sd-q2[01234][0123456789] | pkg-sd-q25[012345])
        printf 'rootful-prerequisite-code-v1:%s\n' "$1" >&3
        ;;
    esac
  fi
  exit 1
}
package_tuple_failure() {
  [[ ${prerequisite_mode:-0} == 1 && ${mode:-work} != cleanup ]] || fail packages
  local remaining row i rows=0 first=13
  ((${#packages} <= 4096)) || fail rpm-shape
  remaining=$packages
  for ((i = 0; i < 13; i++)); do
    row=${remaining%%$'\n'*}
    if ((i < 12 && first == 13)); then
      case "$i:$row" in
        '0:bash 5.3.9-3.fc44') ;;
        '1:jq 1.8.1-3.fc44') ;;
        '2:coreutils 9.10-5.fc44') ;;
        '3:systemd 259.9-1.fc44') ;;
        '4:podman 5.8.7-1.fc44') ;;
        '5:skopeo 1.22.3-1.fc44') ;;
        '6:crun 1.28-1.fc44') ;;
        '7:conmon 2.2.1-2.fc44') ;;
        '8:netavark 1.17.2-1.fc44') ;;
        '9:aardvark-dns 1.17.1-1.fc44') ;;
        '10:util-linux 2.41.5-1.fc44') ;;
        '11:libcap 2.78-1.fc44') ;;
        *) first=$i ;;
      esac
    fi
    if [[ $remaining != *$'\n'* ]]; then
      rows=$((i + 1))
      break
    fi
    remaining=${remaining#*$'\n'}
  done
  ((rows == 12)) || fail rpm-shape
  case $first in
    0) fail rpm-bash ;;
    1) fail rpm-jq ;;
    2) fail rpm-coreutils ;;
    3) fail rpm-systemd ;;
    4) fail rpm-podman ;;
    5) fail rpm-skopeo ;;
    6) fail rpm-crun ;;
    7) fail rpm-conmon ;;
    8) fail rpm-netavark ;;
    9) fail rpm-aardvark ;;
    10) fail rpm-util-linux ;;
    11) fail rpm-libcap ;;
    *) fail rpm-shape ;;
  esac
}

claim() {
  local name=$1
  [[ $name == prerequisite || $name == execution || $name == volume || $name == node || $name == logs ]] || fail
  set -o noclobber
  if { printf '%s %s %s\n' "$owner" "$plan" "$boot" > "$root/state/$name-claimed"; } 2> /dev/null; then
    set +o noclobber
  else
    set +o noclobber
    fail
  fi
}
declare -A cursor=()
take() {
  local domain=$1 max=$2 i
  set -o noclobber
  for ((i = ${cursor[$domain]:-0}; i < max; i++)); do
    if { printf '%s %s %s\n' "$owner" "$plan" "$boot" > "$credits/$domain.$i"; } 2> /dev/null; then
      set +o noclobber
      token=$i
      cursor[$domain]=$((i + 1))
      return 0
    fi
  done
  set +o noclobber
  return 1
}
grant_utility() {
  local domain=utility-work maximum=680
  [[ ${mode:-work} != cleanup ]] || {
    domain=utility-cleanup
    maximum=64
  }
  take "$domain" "$maximum" || return 1
  utility_ticket=$domain.$token
}
utility_launch() {
  local ticket=$1
  shift
  case $1 in
    /usr/bin/base64 | /usr/bin/dd | /usr/bin/cmp | /usr/bin/stat | /usr/bin/sha256sum | /usr/bin/jq | /usr/bin/mkdir | /usr/bin/cat | /usr/bin/rpm | /usr/lib/systemd/systemd | /usr/bin/readlink | /usr/bin/tee | /usr/bin/setpriv | /usr/bin/flock | /usr/sbin/getcap) ;;
    *) fail ;;
  esac
  [[ $ticket =~ ^utility-(work|cleanup)\.[0-9]{1,3}$ ]] || fail
  read_file "$credits/$ticket"
  [[ $REPLY == "$owner $plan $boot" ]] || fail
  set -o noclobber
  if { printf '%s %s %s\n' "$owner" "$plan" "$boot" > "$credits/used.$ticket"; } 2> /dev/null; then set +o noclobber; else
    set +o noclobber
    fail
  fi
  if [[ ${utility_exec:-0} == 1 ]]; then
    [[ -z ${utility_identity:-} ]] || record_identity "$utility_identity"
    exec "$@"
  fi
  if [[ $BASH_SUBSHELL == 0 && ${rootful_admitted:-0} == 1 && ${rootful_intent:-} == execution-v1 && ${mode:-} == work && $postlog_site == k && $k_site == i && $1 == /usr/bin/jq ]]; then i_admitted=1; fi
  "$@"
}
u() {
  case $1 in
    /usr/bin/base64 | /usr/bin/dd | /usr/bin/cmp | /usr/bin/stat | /usr/bin/sha256sum | /usr/bin/jq | /usr/bin/mkdir | /usr/bin/cat | /usr/bin/rpm | /usr/lib/systemd/systemd | /usr/bin/readlink | /usr/bin/tee | /usr/bin/setpriv | /usr/bin/flock | /usr/sbin/getcap) ;;
    *) fail ;;
  esac
  grant_utility || fail
  utility_launch "$utility_ticket" "$@"
}

read_file() {
  local path=$1
  [[ -f $path && ! -L $path ]] || fail
  REPLY=$(< "$path")
}
uptime_now() {
  local rest
  read -r UPTIME rest < /proc/uptime
  UPTIME=${UPTIME%%.*}
  [[ $UPTIME =~ ^[0-9]+$ ]] || fail
}
clock_check() {
  uptime_now
  local limit
  read_file "$root/state/deadlines"
  read -r work_limit cleanup_limit <<< "$REPLY"
  limit=$work_limit
  [[ $mode == cleanup ]] && limit=$cleanup_limit
  [[ $limit =~ ^[0-9]+$ ]] || fail
  ((UPTIME < limit)) || fail "${1:-}"
}
capture_stream() {
  local maximum=$1 destination=$2 dd_ticket=$3 stat_ticket=$4 size
  [[ -z ${stdout_fd:-} ]] || exec {stdout_fd}>&-
  [[ -z ${stderr_fd:-} ]] || exec {stderr_fd}>&-
  exec 3>&-
  set -o noclobber
  utility_launch "$dd_ticket" /usr/bin/dd bs=4096 count="$((maximum + 1))B" iflag=fullblock status=none > "$destination" || return 1
  set +o noclobber
  size=$(utility_launch "$stat_ticket" /usr/bin/stat -c %s "$destination") || return 1
  [[ $size =~ ^[0-9]+$ ]] || return 1
  if ((size > maximum)); then
    exit 23
  fi
  ((size <= maximum))
}
process_identity() {
  local pid=$1 record tail
  [[ $pid =~ ^[1-9][0-9]{0,4}$ ]] || fail
  ((pid < pid_max)) || fail
  IFS= read -r record < "/proc/$pid/stat" || fail
  [[ ${record%% *} == "$pid" ]] || fail
  tail=${record##*) }
  local -a parts
  read -ra parts <<< "$tail"
  ((${#parts[@]} >= 20)) && [[ ${parts[19]} =~ ^[0-9]+$ && ${parts[1]} =~ ^[0-9]+$ ]] || fail
  PROC_START=${parts[19]}
}
record_identity() {
  local path=$1 pid=$BASHPID
  [[ $path == "$root/state/logs-"*.identity ]] || fail
  process_identity "$pid"
  set -o noclobber
  if printf '%s %s\n' "$pid" "$PROC_START" > "$path"; then set +o noclobber; else
    set +o noclobber
    fail
  fi
}
logs_collector() {
  local maximum=$1 destination=$2 name=$3 dd_ticket=$4 stat_ticket=$5 tee_ticket=$6
  local raw_fd forward_fd tee_fd dd_pid tee_pid dd_status=0 tee_status=0 size
  [[ -z ${stdout_fd:-} ]] || exec {stdout_fd}>&-
  [[ -z ${stderr_fd:-} ]] || exec {stderr_fd}>&-
  exec 3>&-
  record_identity "$root/state/logs-$name.identity"
  set -o noclobber
  exec {raw_fd}> "$destination" || fail
  set +o noclobber
  exec {forward_fd}>&1
  exec {tee_fd}> >(
    local utility_exec=1 utility_identity=$root/state/logs-$name-tee.identity
    exec 1>&$raw_fd {raw_fd}>&-
    utility_launch "$tee_ticket" /usr/bin/tee --output-error=warn-nopipe "/proc/self/fd/$forward_fd"
  )
  tee_pid=$!
  (
    local utility_exec=1 utility_identity=$root/state/logs-$name-dd.identity
    exec 1>&$tee_fd {raw_fd}>&- {forward_fd}>&- {tee_fd}>&-
    utility_launch "$dd_ticket" /usr/bin/dd bs=1 count="$((maximum + 1))" status=none
  ) <&0 &
  dd_pid=$!
  exec {raw_fd}>&- {forward_fd}>&- {tee_fd}>&-
  wait "$dd_pid" || dd_status=$?
  wait "$tee_pid" || tee_status=$?
  size=$(utility_launch "$stat_ticket" /usr/bin/stat -c %s "$destination") || fail
  if [[ ! $size =~ ^[0-9]+$ ]] || ((dd_status != 0 || tee_status != 0 || size > maximum)); then
    printf '%s\n' poisoned > "$root/state/poison"
    printf '%s %s %s failed\n' "$dd_status" "$tee_status" "$size" > "$root/state/logs-$name.closed"
    return 1
  fi
  printf '%s %s %s eof\n' "$dd_status" "$tee_status" "$size" > "$root/state/logs-$name.closed"
}
logs_exec_failure() {
  local status=${1:-1}
  [[ $status =~ ^[0-9]{1,3}$ ]] && ((status > 0 && status <= 255)) || status=1
  printf '%s\n' poisoned > "$root/state/poison" || true
  exit "$status"
}
logs_native() {
  [[ $BASH_SUBSHELL == 0 ]] || logs_exec_failure
  shopt -s execfail || logs_exec_failure
  local stdout_tee stderr_tee
  grant_utility || logs_exec_failure
  stdout_tee=$utility_ticket
  grant_utility || logs_exec_failure
  stderr_tee=$utility_ticket
  claim logs
  record_identity "$root/state/logs-native.identity"
  set -o noclobber
  if printf '%s %s %s\n' "$owner" "$plan" "$boot" > "$root/state/logs-binding"; then set +o noclobber; else
    set +o noclobber
    logs_exec_failure
  fi
  if exec {stdout_fd}> >(logs_collector "$maximum" "$out" out "$stdout_dd" "$stdout_stat" "$stdout_tee"); then :; else
    logs_exec_failure "$?"
  fi
  if exec {stderr_fd}> >(logs_collector "$error_max" "$err" err "$stderr_dd" "$stderr_stat" "$stderr_tee" >&3); then :; else
    logs_exec_failure "$?"
  fi
  if exec 1>&$stdout_fd 2>&$stderr_fd {stdout_fd}>&- {stderr_fd}>&- 3>&-; then :; else
    logs_exec_failure "$?"
  fi
  set +e || logs_exec_failure
  if exec /usr/bin/podman --remote=false logs -f "$node"; then
    logs_exec_failure
  else
    logs_exec_failure "$?"
  fi
}
pace_close() {
  if [[ -n ${pace_fd:-} ]]; then
    exec {pace_fd}>&- || exit 1
    unset pace_fd
  fi
}
logs_retirement() {
  local name pid start actual tail record i state marker=0 line a b size closure
  local +x poll_active=1 poll_state=u
  [[ ! -e $root/state/poison ]] || fail a
  [[ -p /proc/self/fd/0 ]] || fail
  exec {pace_fd}<> /proc/self/fd/0 || fail
  [[ /proc/self/fd/0 -ef /proc/self/fd/$pace_fd ]] || fail
  for name in native out err out-dd out-tee err-dd err-tee; do
    poll_state=u
    read_file "$root/state/logs-$name.identity"
    read -r pid start <<< "$REPLY"
    [[ $pid =~ ^[1-9][0-9]{0,4}$ && $start =~ ^[0-9]+$ ]] || fail b
    ((pid < pid_max)) || fail c
    for ((i = 0; i < 4096; i++)); do
      clock_check p
      if ((i && work_limit - UPTIME > 1)); then
        if IFS= read -rd '' -n 1 -t 0.01 -u "$pace_fd" line; then
          fail
        else
          actual=$?
        fi
        ((actual == 142)) && [[ -z $line ]] || fail
        clock_check p
      fi
      [[ -d /proc/$pid ]] || break
      IFS= read -r record < "/proc/$pid/stat" || fail d
      [[ ${record%% *} == "$pid" ]] || fail e
      tail=${record##*) }
      local -a parts
      read -ra parts <<< "$tail"
      ((${#parts[@]} >= 20)) && [[ ${parts[19]} =~ ^[0-9]+$ ]] || fail f
      [[ ${parts[19]} == "$start" ]] || break
      case ${parts[0]} in
        [RSDZTtXI]) poll_state=${parts[0]} ;;
        *) poll_state=u ;;
      esac
    done
    ((i < 4096)) || fail g
  done
  for name in out err; do
    read_file "$root/state/logs-$name.closed"
    read -r a b size closure <<< "$REPLY"
    [[ $a == 0 && $b == 0 && $size =~ ^[0-9]+$ && $closure == eof ]] || fail h
    if [[ $name == out ]]; then ((size <= 16384)) || fail i; else ((size <= 4096)) || fail j; fi
  done
  read_file "$root/state/logs-captures"
  read -r out err <<< "$REPLY"
  [[ $out == "$captures"/work.*.out && $err == "$captures"/work.*.err ]] || fail k
  for name in "$out" "$err"; do
    [[ -f $name && ! -L $name ]] || fail l
    while IFS= read -r line || [[ -n $line ]]; do
      if [[ $line =~ Reached\ target\ .*Multi-User\ System.*|detected\ cgroup\ v1 ]]; then marker=1; fi
    done < "$name"
  done
  ((marker)) || fail m
  state=retired-wait-and-signal-cause-unavailable
  [[ ! -e $root/state/poison ]] || fail o
  pace_close
  poll_active=0
  clock_check p
  printf '%s\n' "$state" > "$root/state/logs-retirement"
}

# shellcheck disable=SC2329
emit_logs_evidence() {
  local name path pid start dd_status tee_status size closure item comma='' identities='' collectors=''
  local state=${guard_reason:-not-established} marker=false wrapper_status=null eof maximum
  for name in native out err out-dd out-tee err-dd err-tee; do
    path=$root/state/logs-$name.identity
    item=null
    if [[ -e $path ]]; then
      read_file "$path"
      [[ $REPLY =~ ^([1-9][0-9]{0,4})\ ([1-9][0-9]{0,18})$ ]] || fail
      pid=${BASH_REMATCH[1]}
      start=${BASH_REMATCH[2]}
      ((pid < pid_max && start > 0 && start < 9223372036854775807)) || fail
      printf -v item '{"pid":%s,"start":%s}' "$pid" "$start"
    fi
    identities+="$comma\"$name\":$item"
    comma=,
  done
  comma=''
  for name in out err; do
    path=$root/state/logs-$name.closed
    item=null
    if [[ -e $path ]]; then
      read_file "$path"
      read -r dd_status tee_status size closure <<< "$REPLY"
      [[ $dd_status =~ ^[0-9]{1,3}$ && $tee_status =~ ^[0-9]{1,3}$ && $size =~ ^[0-9]{1,5}$ ]] || fail
      maximum=16384
      [[ $name != err ]] || maximum=4096
      ((dd_status <= 255 && tee_status <= 255 && size <= maximum + 1)) || fail
      eof=false
      [[ $closure != eof ]] || eof=true
      [[ $closure == eof || $closure == failed ]] || fail
      printf -v item '{"dd_status":%s,"tee_status":%s,"bytes":%s,"source_eof":%s}' "$dd_status" "$tee_status" "$size" "$eof"
    fi
    collectors+="$comma\"$name\":$item"
    comma=,
  done
  if [[ -e $root/state/logs-retirement ]]; then
    read_file "$root/state/logs-retirement"
    state=$REPLY
    [[ $state == direct-wait-zero || $state == retired-wait-and-signal-cause-unavailable ]] || fail
    marker=true
  fi
  printf -v logs_json '{"state":"%s","identities":{%s},"collectors":{%s},"startup_marker":%s,"wrapper_observed_child_wait_status":%s,"signal_cause":null}' "$state" "$identities" "$collectors" "$marker" "$wrapper_status"
  ((${#logs_json} <= 4096)) || fail
}

native() {
  local maximum=$1 error_max=$2 domain=$mode max=70 action i slots rc helper_error=0 stdout_pid stderr_pid
  local stdout_fd stderr_fd stdout_dd stdout_stat stderr_dd stderr_stat
  shift 2
  [[ $postlog_site != k ]] || postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null
  [[ $domain == cleanup ]] && max=5
  [[ $domain == work || $domain == cleanup ]] || fail
  clock_check
  read_file "$root/state/mode"
  [[ $REPLY == "$domain" ]] || fail
  [[ $domain == cleanup || ! -e $root/state/poison ]] || fail
  take "$domain" "$max" || fail
  action=$domain.$token
  slots=$(((maximum + error_max) / 4096))
  ((maximum >= 4096 && maximum % 4096 == 0 && error_max >= 4096 && error_max % 4096 == 0)) || fail
  local output_domain=output-work output_max=245
  [[ $domain != cleanup ]] || {
    output_domain=output-cleanup
    output_max=10
  }
  for ((i = 0; i < slots; i++)); do take "$output_domain" "$output_max" || fail; done
  take sentinel 150 || fail
  take sentinel 150 || fail
  out=$captures/$action.out err=$captures/$action.err
  tool_status=-1 stdout_status=-1 stderr_status=-1
  [[ ! -e $out && ! -L $out && ! -e $err && ! -L $err ]] || fail
  grant_utility || fail
  stdout_dd=$utility_ticket
  grant_utility || fail
  stdout_stat=$utility_ticket
  grant_utility || fail
  stderr_dd=$utility_ticket
  grant_utility || fail
  stderr_stat=$utility_ticket
  if [[ ${stream_logs:-0} == 1 ]]; then
    (($# == 5)) && [[ $domain == work && $maximum == 16384 && $error_max == 4096 &&
      $1 == /usr/bin/podman && $2 == --remote=false && $3 == logs && $4 == -f && $5 == "$node" ]] || fail
    printf '%s %s\n' "$out" "$err" > "$root/state/logs-captures"
    logs_native
  fi
  exec {stdout_fd}> >(capture_stream "$maximum" "$out" "$stdout_dd" "$stdout_stat")
  stdout_pid=$!
  exec {stderr_fd}> >(capture_stream "$error_max" "$err" "$stderr_dd" "$stderr_stat")
  stderr_pid=$!
  if (
    exec 1>&$stdout_fd 2>&$stderr_fd
    exec {stdout_fd}>&- {stderr_fd}>&- 3>&-
    "$@"
  ); then rc=0; else rc=$?; fi
  tool_status=$rc
  [[ $postlog_site != [nk] ]] || postlog_tool=$tool_status
  printf '%s\n' "$rc" > "$captures/$action.status"
  exec {stdout_fd}>&- {stderr_fd}>&-
  if wait "$stdout_pid"; then stdout_status=0; else
    stdout_status=$?
    helper_error=1
  fi
  [[ $postlog_site != [nk] ]] || postlog_out=$stdout_status
  if wait "$stderr_pid"; then stderr_status=0; else
    stderr_status=$?
    helper_error=1
  fi
  [[ $postlog_site != [nk] ]] || postlog_err=$stderr_status
  if ((helper_error)); then
    [[ $domain == cleanup ]] || printf '%s\n' poisoned > "$root/state/poison"
    return 125
  fi
  clock_check
  return "$rc"
}

info_check() {
  # jq uses --arg.
  # shellcheck disable=SC2016
  u /usr/bin/jq -e --arg root "$root" '.host.security.rootless == false and .host.serviceIsRemote == false and .host.cgroupVersion == "v2" and .host.os == "linux" and .host.arch == "amd64" and .version.Version == "5.8.7" and .host.networkBackend == "netavark" and .host.cgroupManager == "cgroupfs" and .store.graphDriverName == "overlay" and .store.graphRoot == ($root+"/storage") and .store.runRoot == "/run/kubernetes-lens-rootful/storage" and .store.graphStatus["Backing Filesystem"] == "xfs"' "$1" > /dev/null || fail podman-profile
}
inventory() {
  local process pid tid task record tail hard _soft a b c rest fd count=0
  SNAP=''
  shopt -s nullglob
  for process in /proc/[0-9]*; do
    pid=${process##*/}
    ((pid > 0 && pid < pid_max)) || fail inv-pid-range
    [[ -d $process/task && -r $process/task && -x $process/task ]] || fail inv-proc-task
    IFS= read -r record < "$process/stat" || fail inv-proc-read
    [[ ${record%% *} == "$pid" ]] || fail inv-proc-pid
    tail=${record##*) }
    read -ra fields <<< "$tail"
    ((${#fields[@]} >= 20)) && [[ ${fields[19]} =~ ^[0-9]+$ ]] || fail inv-proc-form
    SNAP+="$pid:${fields[19]}:"
    local -a tasks=()
    for task in "$process"/task/[0-9]*; do tasks+=("$task"); done
    ((${#tasks[@]} > 0)) || fail inv-task-empty
    for task in "${tasks[@]}"; do
      tid=${task##*/}
      ((tid > 0 && tid < pid_max && ++count < pid_max)) || fail inv-tid-count
      IFS= read -r record < "$task/stat" || fail inv-task-read
      [[ ${record%% *} == "$tid" ]] || fail inv-task-tid
      tail=${record##*) }
      read -ra fields <<< "$tail"
      ((${#fields[@]} >= 20)) && [[ ${fields[19]} =~ ^[0-9]+$ ]] || fail inv-task-form
      SNAP+="$tid:${fields[19]}:"
      hard=''
      while read -r a b c _soft rest; do
        if [[ $a == Max && $b == open && $c == files ]]; then
          read -r hard rest <<< "$rest"
          break
        fi
      done < "$task/limits"
      [[ $hard =~ ^[0-9]{1,10}$ ]] || fail inv-nf-form
      ((hard <= hard_nofile_max)) || fail inv-nf-range
      SNAP+="$hard:"
      [[ -d $task/fd && -r $task/fd && -x $task/fd ]] || fail inv-fd-access
      for fd in "$task"/fd/[0-9]*; do
        fd=${fd##*/}
        [[ $fd =~ ^[0-9]{1,10}$ ]] || fail inv-fd-form
        ((fd < fd_max)) || fail inv-fd-range
        SNAP+="$fd,"
      done
      SNAP+=';'
      ((${#SNAP} <= 33554432)) || fail inv-snap-size
    done
    SNAP+='|'
  done
  ((count > 0)) || fail inv-empty
}
receive_packet() {
  [[ ! -e $root/state/request.in && ! -L $root/state/request.in && ! -e $root/state/request.extra && ! -L $root/state/request.extra ]] || fail
  set -o noclobber
  exec 8> "$root/state/request.in"
  exec 7> "$root/state/request.extra"
  set +o noclobber
  u /usr/bin/dd bs=4096 count=1 iflag=fullblock status=none >&8 || fail
  u /usr/bin/dd bs=1 count=1 status=none >&7 || fail
  exec 8>&- 7>&-
  local size
  size=$(u /usr/bin/stat -c %s "$root/state/request.extra") || fail
  [[ $size == 0 ]] || fail
  size=''
  size=$(u /usr/bin/stat -c %s "$root/state/request.in") || fail
  ((size > 0 && size <= 4096)) || fail
  read_file "$root/state/request.in"
  packet=$REPLY
  [[ ${#packet} -lt 4096 ]] || fail
  u /usr/bin/cmp -s "$root/state/request.in" <(printf '%s\n' "$packet") || fail
}
prerequisite_eof() {
  [[ ! -e $root/state/prerequisite.extra && ! -L $root/state/prerequisite.extra ]] || fail eof
  set -o noclobber
  exec 8> "$root/state/prerequisite.extra"
  set +o noclobber
  u /usr/bin/dd bs=1 count=1 status=none >&8 || fail eof
  exec 8>&-
  local size
  size=$(u /usr/bin/stat -c %s "$root/state/prerequisite.extra") || fail eof
  [[ $size == 0 ]] || fail eof
  size=''
}

resource_check() {
  [[ $# == 0 || $# == 1 && $1 == vm-live-v1 ]] || fail
  local value before namespace proc_ok=0 root_ok=0 total=0 swap=0 a b c d e rest entry
  read -r value < /proc/sys/kernel/pid_max
  [[ $value == 32768 ]] || fail pid-max
  read -r value < /proc/sys/fs/nr_open
  [[ $value =~ ^[0-9]{1,10}$ ]] || fail nr-open-form
  ((value > 0 && value <= fd_max)) || fail nr-open-range
  namespace=$(u /usr/bin/stat -Lc '%d:%i' /proc/1/ns/pid) || fail
  value=$(u /usr/bin/stat -Lc '%d:%i' /proc/self/ns/pid) || fail namespace
  [[ $value == "$namespace" ]] || fail namespace
  value=''
  while read -r a b rest; do
    if [[ $a == NSpid: ]]; then
      [[ $b == "$BASHPID" && -z $rest ]] || fail namespace
      proc_ok=1
    fi
  done < /proc/self/status
  ((proc_ok == 1)) || fail namespace
  proc_ok=0
  while read -r a b c d e rest; do
    [[ $e == /proc && $rest == *' - proc proc '* ]] && proc_ok=1
    [[ $e == / && $rest == *' - xfs /dev/vda4 '* ]] && root_ok=1
  done < /proc/self/mountinfo
  ((proc_ok == 1 && root_ok == 1)) || {
    case $proc_ok:$root_ok in
      0:0) fail mount-both ;;
      0:1) fail mount-proc ;;
      1:0) fail mount-root ;;
      *) fail mount ;;
    esac
  }
  while read -r a b rest; do
    [[ $a == MemTotal: ]] && total=$b
    [[ $a == SwapTotal: ]] && swap=$b
  done < /proc/meminfo
  ((total >= 3145728 && total <= 4194304 && swap == 0)) || fail memory
  shopt -s nullglob
  local devices=(/sys/class/block/*)
  ((${#devices[@]} == 5)) || fail block
  for entry in "${devices[@]}"; do
    case ${entry##*/} in vda | vda1 | vda2 | vda3 | vda4) ;; *) fail block ;; esac
    value=$(u /usr/bin/readlink -f "$entry") || fail block
    [[ $value == /sys/devices/pci*'/virtio'*'/block/vda'* ]] || fail block
    value=''
  done
  [[ -d /dev/mapper && ! -L /dev/mapper ]] || fail mapper
  value=$(u /usr/bin/stat -c '%u:%g:%a' /dev/mapper) || fail mapper
  [[ $value == 0:0:755 ]] || fail mapper
  value=''
  local mapper=(/dev/mapper/*)
  [[ ${#mapper[@]} == 1 && ${mapper[0]} == /dev/mapper/control && ! -L /dev/mapper/control && -c /dev/mapper/control ]] || fail mapper
  value=$(u /usr/bin/stat -c '%t:%T:%u:%g:%a:%h' /dev/mapper/control) || fail mapper
  [[ $value == a:ec:0:0:600:1 ]] || fail mapper
  value=''
  read -r value < /sys/class/misc/device-mapper/dev
  [[ $value == 10:236 ]] || fail mapper
  local fs_values block_size blocks available inodes free_inodes required
  fs_values=$(u /usr/bin/stat -f -c '%S %b %a %c %d' "$root") || fail
  read -r block_size blocks available inodes free_inodes <<< "$fs_values"
  for value in "$block_size" "$blocks" "$available" "$inodes" "$free_inodes"; do [[ $value =~ ^[0-9]{1,12}$ ]] || fail filesystem; done
  ((block_size > 0 && blocks > 0 && block_size * blocks <= 34359738368 && available > 0 && inodes > 0 && free_inodes >= 4096)) || fail filesystem
  if [[ ! -e $root/state/node-claimed ]]; then
    required=$((2 * expanded_image_bytes + archive_bytes + 1073741824))
    [[ -f $stage/state ]] || required=$((required + stage_payload_bytes))
    ((available * block_size >= required)) || fail filesystem
  fi
  printf '%s\n' "$fs_values" > "$root/state/actual-filesystem"
  if (($# == 0)); then
    inventory
    before=$SNAP
    inventory
    [[ $SNAP == "$before" ]] || fail inv-drift
  fi
}
network_routes() {
  [[ ! -e /sys/class/net/klbr0 && ! -L /sys/class/net/klbr0 && -f /proc/net/route && -r /proc/net/route ]] || fail
  local name destination _gateway _flags _ref _use _metric mask rest d m p pm
  while read -r name destination _gateway _flags _ref _use _metric mask rest; do
    [[ $destination =~ ^[0-9A-F]{8}$ && $mask =~ ^[0-9A-F]{8}$ ]] || continue
    d=$((16#$destination))
    m=$((16#$mask))
    ((m == 0)) && continue
    for p in 0x00001eac 0x0000f40a 0x0000600a; do
      pm=0x0000ffff
      (((d & m & pm) != (p & m & pm))) || fail
    done
  done < /proc/net/route || fail
}
private_environment() {
  export HOME=$root/home TMPDIR=$root/tmp XDG_CONFIG_HOME=$root/config XDG_DATA_HOME=$root/data XDG_RUNTIME_DIR=/run/kubernetes-lens-rootful
  export CONTAINERS_STORAGE_CONF=$root/config/storage.conf CONTAINERS_CONF=$root/config/containers.conf
  export CONTAINERS_REGISTRIES_CONF=$root/config/registries.conf CONTAINERS_POLICY=$root/config/policy.json REGISTRY_AUTH_FILE=$root/config/auth.json
  export PATH=$root/bin:/usr/bin:/usr/sbin KUBECONFIG=$root/state/kubeconfig KIND_EXPERIMENTAL_PROVIDER=podman
  unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy CONTAINER_HOST CONTAINER_CONNECTION DOCKER_HOST SSH_AUTH_SOCK CONTAINERS_CONF_OVERRIDE STORAGE_DRIVER STORAGE_OPTS KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER KIND_EXPERIMENTAL_DOCKER_NETWORK
}
exact() {
  local i=0 part
  (($# == ${#args[@]})) || return 1
  for part in "$@"; do
    [[ ${args[i]} == "$part" ]] || return 1
    ((i += 1))
  done
}
provider_classify() {
  local label="io.x-k8s.kind.cluster=$cluster" role='{{ index .Config.Labels "io.x-k8s.kind.role"}}'
  action='' maximum=4096 error_max=4096
  if exact --version; then
    action=version
  elif exact info --format json; then
    action=info
    maximum=16384
  elif exact ps -a --filter "label=$label" --format '{{.Names}}'; then
    action=list
  elif exact inspect --type=image "$alias"; then
    action=image
    maximum=16384
  elif exact network inspect kind; then
    action=network
  elif exact volume create --label "$node=true"; then
    action=volume
  elif exact logs -f "$node"; then
    action=logs
    maximum=16384
  elif exact inspect --format "$role" "$node"; then
    action=role
  elif exact inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}},{{.GlobalIPv6Address}}{{end}}' "$node"; then
    action=ip
  elif exact inspect --format '{{ json .NetworkSettings.Ports }}' "$node"; then
    action=ports
  elif exact rm -f -v "$node"; then
    action=delete
  elif exact volume ls --filter "label=$node" --quiet; then
    action="volume-list"
  elif [[ -n $volume ]] && exact volume rm --force "$volume"; then
    action="volume-delete"
  else
    local -a before=(run --name "$node" --hostname "$node" --label io.x-k8s.kind.role=control-plane --privileged --tmpfs /tmp --tmpfs /run --volume "$volume:/var:suid,exec,dev" --volume /lib/modules:/lib/modules:ro -e KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER --detach --tty --net kind --label "$label" -e container=podman)
    [[ $profile == modern-1.37.0 ]] && before+=(--cgroupns=private)
    before+=(--volume /dev/mapper:/dev/mapper --publish=127.0.0.1:6443:6443/tcp -e KUBECONFIG=/etc/kubernetes/admin.conf "$alias")
    if [[ -n $volume ]] && exact "${before[@]}"; then
      action=run
    else
      local -a prefix=(exec --privileged "$node") interactive=(exec --privileged -i "$node")
      if exact "${prefix[@]}" cat /kind/version; then
        action="node-version"
      elif exact "${prefix[@]}" mkdir -p /kind; then
        action=kubeadm-dir
      elif exact "${interactive[@]}" cp /dev/stdin /kind/kubeadm.conf; then
        action=config
      elif exact "${prefix[@]}" cat /kind/manifests/default-cni.yaml; then
        action=cni
      elif exact "${prefix[@]}" cat /kind/manifests/default-storage.yaml; then
        action=storage
        [[ $profile != modern-1.37.0 ]] || maximum=8192
      elif exact "${prefix[@]}" cat /etc/kubernetes/admin.conf; then
        action=kubeconfig
        maximum=65536
      elif exact "${interactive[@]}" kubectl create --kubeconfig=/etc/kubernetes/admin.conf -f -; then
        action=cni-install
      elif exact "${interactive[@]}" kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f -; then
        action=storage-install
      elif [[ $profile == legacy-1.20.15 ]] && exact "${prefix[@]}" kubeadm init --skip-phases=preflight --config=/kind/kubeadm.conf --skip-token-print --v=6; then
        action=init
        maximum=32768
        error_max=32768
      elif [[ $profile == modern-1.37.0 ]] && exact "${prefix[@]}" kubeadm init --config=/kind/kubeadm.conf --skip-token-print --v=6; then
        action=init
        maximum=32768
        error_max=32768
      elif [[ $profile == legacy-1.20.15 ]] && exact "${prefix[@]}" kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/master-; then
        action=untaint
      elif [[ $profile == modern-1.37.0 ]] && exact "${prefix[@]}" kubectl --kubeconfig=/etc/kubernetes/admin.conf taint nodes --all node-role.kubernetes.io/control-plane-; then
        action=untaint
      elif [[ $profile == modern-1.37.0 ]] && exact "${prefix[@]}" kubectl --kubeconfig=/etc/kubernetes/admin.conf label nodes --all node.kubernetes.io/exclude-from-external-load-balancers-; then
        action=unlabel
      else
        return 1
      fi
    fi
  fi
  [[ -n $action ]]
}
translate_run() {
  provider_classify && [[ $action == run && $image_id =~ ^[0-9a-f]{64}$ ]] || return 1
  executed_args=("${args[@]:0:${#args[@]}-1}" --pull=never -e SYSTEMD_COLORS=0 "$image_id")
}

provider() {
  args=("$@")
  volume=''
  if [[ -f $root/state/volume ]]; then
    read_file "$root/state/volume"
    volume=$REPLY
  fi
  [[ -z $volume || $volume =~ ^[0-9a-f]{64}$ ]] || fail
  provider_classify || fail
  read_file "$root/state/mode"
  mode=$REPLY
  if [[ $mode == cleanup ]]; then
    case $action in list | delete | volume-list | volume-delete) ;; *) fail ;; esac
  else
    case $action in delete | volume-list | volume-delete) fail ;; esac
  fi
  if [[ $profile == modern-1.37.0 && $action == init ]]; then
    args[7]=--v=0
  fi
  if [[ $action == volume ]]; then claim volume; fi
  if [[ $action == run ]]; then
    claim node
    resource_check
    native 16384 4096 /usr/bin/podman --remote=false inspect --type=image "$alias" || fail
    # jq uses --arg.
    # shellcheck disable=SC2016
    u /usr/bin/jq -e --arg id "$image_id" 'length==1 and .[0].Id==$id' "$out" > /dev/null || fail
    remember image-inspect "$out"
    printf '%s\0' "${args[@]}" > "$root/state/incoming-run.argv"
    translate_run || fail
    args=("${executed_args[@]}")
    printf '%s\0' "${args[@]}" > "$root/state/executed-run.argv"
  fi
  local rc=0
  if [[ $action == logs ]]; then
    [[ $BASH_SUBSHELL == 0 ]] || logs_exec_failure
    stream_logs=1 native "$maximum" "$error_max" /usr/bin/podman --remote=false "${args[@]}" || rc=$?
    return "$rc"
  fi
  native "$maximum" "$error_max" /usr/bin/podman --remote=false "${args[@]}" || rc=$?
  if ((rc == 0)); then
    case $action in
      volume)
        read_file "$out"
        [[ $REPLY =~ ^[0-9a-f]{64}$ && ! -e $root/state/volume ]] || fail
        (
          set -o noclobber
          printf '%s\n' "$REPLY" > "$root/state/volume"
        ) || fail
        ;;
      image)
        # shellcheck disable=SC2016
        u /usr/bin/jq -e --arg id "$image_id" 'length==1 and .[0].Id==$id' "$out" > /dev/null || fail
        ;;
      run)
        read_file "$out"
        [[ $REPLY =~ ^[0-9a-f]{64}$ ]] || fail
        (
          set -o noclobber
          printf '%s\n' "$REPLY" > "$root/state/node-id"
        ) || fail
        ;;
      network) network_check "$out" ;;
      info) info_check "$out" ;;
    esac
  fi
  u /usr/bin/cat "$out" || fail
  u /usr/bin/cat "$err" >&3 || fail
  return "$rc"
}
network_check() {
  local actual
  # jq uses --arg.
  # shellcheck disable=SC2016
  u /usr/bin/jq -e --arg owner "$owner" 'length==1 and .[0].name=="kind" and (.[0].id|test("^[0-9a-f]{64}$")) and .[0].driver=="bridge" and .[0].network_interface=="klbr0" and .[0].ipv6_enabled==false and .[0].dns_enabled==false and .[0].subnets==[{"subnet":"172.30.0.0/16","gateway":"172.30.0.1"}] and .[0].labels["io.kubernetes-lens.issue2.owner"]==$owner' "$1" > /dev/null || fail
  actual=$(u /usr/bin/jq -er '.[0].id' "$1") || fail
  [[ -f $root/state/network-created ]] || fail
  if [[ ! -e $root/state/network-id ]]; then
    set -o noclobber
    printf '%s\n' "$actual" > "$root/state/network-id"
    set +o noclobber
  fi
  read_file "$root/state/network-id"
  [[ $actual == "$REPLY" ]] || fail
}

preserve_kind_create_failure() {
  [[ ${kind_failure_wrapper_status:--1} =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 0
  ((kind_failure_wrapper_status > 0 && kind_failure_wrapper_status <= 255)) || return 0
  [[ ${kind_failure_err+x} && ${kind_stdout_status+x} && ${kind_stderr_status+x} ]] || return 1
  [[ $kind_stdout_status =~ ^(-1|0|[1-9][0-9]{0,2})$ && $kind_stderr_status =~ ^(-1|0|[1-9][0-9]{0,2})$ ]] || return 1
  ((kind_stdout_status <= 255 && kind_stderr_status <= 255)) || return 1
  [[ $mode == work && $source_status == not-reached && $kind_failure_err == "$captures"/work.*.err && -f $kind_failure_err && ! -L $kind_failure_err ]] || return 1
  local size ticket i needed=3 prefix_bytes=0 eof=null truncated=false overflow=false
  local destination=$root/state/kind-create-stderr-prefix attribution=$root/state/kind-create-attribution
  [[ ! -e $destination && ! -L $destination && ! -e $attribution && ! -L $attribution ]] || return 1
  grant_utility || return 1
  ticket=$utility_ticket
  size=$(utility_launch "$ticket" /usr/bin/stat -c %s "$kind_failure_err") || return 1
  [[ $size =~ ^[0-9]{1,5}$ ]] && ((size <= 32769)) || return 1
  if ((size > 0)); then
    needed=7
    prefix_bytes=$size
    ((prefix_bytes <= 4096)) || prefix_bytes=4096
  fi
  kind_failure_tickets=()
  for ((i = 0; i < needed; i++)); do
    grant_utility || return 1
    kind_failure_tickets+=("$utility_ticket")
  done
  ((size <= 4096)) || truncated=true
  ((size != 32769)) || overflow=true
  [[ $kind_stderr_status != 0 ]] || eof=true
  if ((size > 0)); then
    ticket=${kind_failure_tickets[0]}
    kind_failure_tickets=("${kind_failure_tickets[@]:1}")
    (
      set -o noclobber
      utility_launch "$ticket" /usr/bin/dd if="$kind_failure_err" bs=1 count=4096 status=none > "$destination"
    ) || return 1
  fi
  (
    set -o noclobber
    printf '{"schema":"kind-create-failure-attribution-v1","kind_child_wait_status":%s,"native_wrapper_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s,"stderr_captured_bytes":%s,"stderr_prefix_bytes":%s,"stderr_source_eof":%s,"stderr_overflow_sentinel":%s,"stderr_prefix_truncated":%s,"provider_child_wait_status":null,"provider_wrapper_status":null}\n' "$create_status" "$kind_failure_wrapper_status" "$kind_stdout_status" "$kind_stderr_status" "$size" "$prefix_bytes" "$eof" "$overflow" "$truncated" > "$attribution"
  ) || return 1
  ((size == 0)) || printf '%s\n' "$destination" > "$root/state/evidence.kind-create-stderr-prefix"
  printf '%s\n' "$attribution" > "$root/state/evidence.kind-create-attribution"
}

remember() {
  case $1 in
    kind-create-failure)
      [[ $# == 1 ]] || fail
      preserve_kind_create_failure
      return $?
      ;;
    kind-create-evidence)
      [[ $# == 1 ]] || fail
      emit_kind_create_failure_evidence
      return $?
      ;;
  esac
  if [[ $# == 1 && $1 == node-init-stdout-prefix ]]; then
    [[ ${prefix_claimed:-0} == 0 ]] || return 0
    [[ $source_status == not-reached && $create_status =~ ^[0-9]{1,3}$ ]] || return 0
    ((create_status >= 0 && create_status <= 255)) || return 0
    [[ ! -e $root/state/logs-retirement && -e $root/state/logs-captures && -e $root/state/logs-out.closed ]] || return 0
    local source error action dd_status tee_status size closure extra destination=$root/state/node-init-stdout-prefix
    read_file "$root/state/logs-captures"
    read -r source error extra <<< "$REPLY"
    action=${source#"$captures"/work.}
    action=${action%.out}
    [[ -z $extra && $action =~ ^[0-9]{1,2}$ && $source == "$captures/work.$action.out" && $error == "$captures/work.$action.err" && -f $source && ! -L $source ]] || fail
    ((10#$action < 70)) || fail
    read_file "$root/state/logs-out.closed"
    read -r dd_status tee_status size closure extra <<< "$REPLY"
    [[ -z $extra && $dd_status =~ ^[0-9]{1,3}$ && $tee_status =~ ^[0-9]{1,3}$ && $size =~ ^[0-9]{1,5}$ && ($closure == eof || $closure == failed) ]] || fail
    ((dd_status <= 255 && tee_status <= 255 && size <= 16385)) || fail
    ((size > 0)) || return 0
    [[ ! -e $destination && ! -L $destination ]] || fail
    [[ $mode == cleanup ]] || return 0
    prefix_claimed=1 prefix_tickets=()
    local i
    for ((i = 0; i < 4; i++)); do
      grant_utility || return 0
      prefix_tickets+=("$utility_ticket")
    done
    set -o noclobber
    utility_launch "${prefix_tickets[0]}" /usr/bin/dd if="$source" bs=1 count=16384 status=none > "$destination" || fail
    set +o noclobber
    printf '%s\n' "$destination" > "$root/state/evidence.node-init-stdout-prefix"
    return 0
  fi
  case $1 in podman-info | manifest | config | image-inspect | network-inspect | node-inspect) ;; *) fail ;; esac
  [[ $2 == "$captures"/work.*.out && -f $2 && ! -L $2 ]] || fail
  printf '%s\n' "$2" > "$root/state/evidence.$1"
}
emit_kind_create_failure_evidence() {
  local name path size sha encoded index=0
  for name in kind-create-stderr-prefix kind-create-attribution; do
    [[ -e $root/state/evidence.$name ]] || continue
    read_file "$root/state/evidence.$name"
    path=$REPLY
    [[ $path == "$root/state/$name" && -f $path && ! -L $path ]] || fail
    ((index + 3 <= ${#kind_failure_tickets[@]})) || fail
    size=$(utility_launch "${kind_failure_tickets[index]}" /usr/bin/stat -c %s "$path") || fail
    index=$((index + 1))
    [[ $size =~ ^[0-9]+$ ]] || fail
    ((size > 0 && (total += size) <= 131072)) || fail
    [[ $name != kind-create-stderr-prefix ]] || ((size <= 4096)) || fail
    [[ $name != kind-create-attribution ]] || ((size <= 1024)) || fail
    sha=$(utility_launch "${kind_failure_tickets[index]}" /usr/bin/sha256sum "$path") || fail
    index=$((index + 1))
    sha=${sha%% *}
    encoded=$(utility_launch "${kind_failure_tickets[index]}" /usr/bin/base64 -w0 "$path") || fail
    index=$((index + 1))
    files+="$comma\"$name\":{\"bytes\":$size,\"sha256\":\"$sha\",\"base64\":\"$encoded\"}"
    comma=,
  done
}

# Called by finish from the fixed EXIT trap; not a standalone entrypoint.
# shellcheck disable=SC2329
emit_evidence() {
  local name path size sha encoded total=0 comma='' files=''
  local -a pay
  for name in podman-info manifest config image-inspect network-inspect node-inspect node-init-stdout-prefix; do
    [[ $name != node-init-stdout-prefix ]] || remember node-init-stdout-prefix
    [[ -e $root/state/evidence.$name ]] || continue
    read_file "$root/state/evidence.$name"
    path=$REPLY
    pay=(u)
    if [[ $name == node-init-stdout-prefix ]]; then
      pay=(utility_launch "${prefix_tickets[1]}")
      [[ $path == "$root/state/node-init-stdout-prefix" && -f $path && ! -L $path ]] || fail
    else
      [[ $path == "$captures"/work.*.out && -f $path && ! -L $path ]] || fail
    fi
    size=$("${pay[@]}" /usr/bin/stat -c %s "$path") || fail
    [[ $size =~ ^[0-9]+$ ]] || fail
    ((size > 0 && size <= 131072 && (total += size) <= 131072)) || fail
    [[ $name != node-init-stdout-prefix ]] || ((size <= 16384)) || fail
    [[ $name != node-init-stdout-prefix ]] || pay[1]=${prefix_tickets[2]}
    sha=$("${pay[@]}" /usr/bin/sha256sum "$path") || fail
    sha=${sha%% *}
    [[ $name != node-init-stdout-prefix ]] || pay[1]=${prefix_tickets[3]}
    encoded=$("${pay[@]}" /usr/bin/base64 -w0 "$path") || fail
    files+="$comma\"$name\":{\"bytes\":$size,\"sha256\":\"$sha\",\"base64\":\"$encoded\"}"
    comma=,
  done
  remember kind-create-evidence
  printf -v evidence_json '{"schema":"kubernetes-lens-owned-rootful-evidence-v1","owner":"%s","plan_sha256":"%s","source_spec_sha256":"%s","files":{%s}}' "$owner" "$plan" "$spec_sha" "$files"
  ((${#evidence_json} <= 262144)) || fail
}

# Exact comparisons are prepaid by the trusted serial host schedule:10/5/3.
# Here-string redirection is local to cmp and preserves the stage payload stdin.
record_compare() {
  [[ $# == 2 && ${record_guard_fuel:-0} =~ ^[0-9]+$ && $record_guard_fuel -gt 0 && ${#2} -le 255 && $2 != *$'\n'* ]] || fail
  [[ -f $1 && ! -L $1 && -O $1 ]] || fail
  record_guard_fuel=$((record_guard_fuel - 1))
  /usr/bin/cmp -s -- "$1" - <<< "$2" || fail
}
closed_record() {
  local path=$1 value=''
  [[ -f $path && ! -L $path && -O $path ]] || fail
  IFS= read -r -n 257 value < "$path" || fail
  [[ ${#value} -le 255 && $value =~ ^[0-9]+\ [0-9]+$ ]] || fail
  record_compare "$path" "$value"
  REPLY=$value
}
expect_record() {
  record_compare "$1" "$2"
}
new_record() {
  [[ ! -e $1 && ! -L $1 ]] || fail
  set -o noclobber
  if { printf '%s\n' "$2" > "$1"; } 2> /dev/null; then set +o noclobber; else
    set +o noclobber
    fail
  fi
  expect_record "$1" "$2"
}
empty_private_directory() {
  local directory=$1 entry
  [[ -d $directory && ! -L $directory ]] || fail
  for entry in "$directory"/* "$directory"/.*; do
    [[ $entry != "$directory/." && $entry != "$directory/.." ]] || continue
    [[ ! -e $entry && ! -L $entry ]] || fail
  done
}
stage_pristine() {
  local entry name
  [[ -d $stage && ! -L $stage ]] || fail
  for name in table plan.json checks.sha256 receiver lock stage-kind.header stage-kubectl.header stage-node-oci.header; do
    [[ -f $stage/$name && ! -L $stage/$name ]] || fail
  done
  for entry in "$stage"/* "$stage"/.*; do
    [[ -e $entry || -L $entry ]] || continue
    case ${entry##*/} in
      . | .. | table | plan.json | checks.sha256 | receiver | lock | stage-kind.header | stage-kubectl.header | stage-node-oci.header) ;;
      *) fail ;;
    esac
  done
}
rootful_boot_guard() {
  local entry
  case $1 in
    prerequisite-v1) record_guard_fuel=10 ;;
    execution-v1) record_guard_fuel=5 ;;
    provider) [[ ${record_guard_fuel:-0} == 0 ]] || fail ;;
    *) fail ;;
  esac
  local trusted_prefix
  for trusted_prefix in / /var /var/lib /run /usr /usr/bin "$root" "$root/state" "$credits" "$captures" "$stage"; do
    [[ -d $trusted_prefix && ! -L $trusted_prefix && -O $trusted_prefix ]] || fail
  done
  [[ -f /usr/bin/cmp && ! -L /usr/bin/cmp && -x /usr/bin/cmp && -O /usr/bin/cmp ]] || fail
  case $1 in
    prerequisite-v1)
      [[ -d $root/state && ! -L $root/state ]] || fail
      for entry in "$root/state"/* "$root/state"/.*; do
        [[ $entry != "$root/state/." && $entry != "$root/state/.." && $entry != "$credits" ]] || continue
        [[ ! -e $entry && ! -L $entry ]] || fail
      done
      empty_private_directory "$credits"
      empty_private_directory "$captures"
      stage_pristine
      for entry in "$root/config" "$root/home" "$root/tmp" "$root/data" "$root/storage" /run/kubernetes-lens-rootful; do
        [[ ! -e $entry && ! -L $entry ]] || fail
      done
      # Claim and inflight publication precede the first utility/counter debit.
      claim prerequisite
      rootful_admitted=1
      new_record "$root/state/phase" "$owner $plan $boot prerequisite-inflight"
      ;;
    execution-v1)
      [[ ! -e $root/state/poison && ! -L $root/state/poison && ! -e $root/state/execution-claimed && ! -L $root/state/execution-claimed ]] || fail
      expect_record "$root/state/prerequisite-claimed" "$owner $plan $boot"
      expect_record "$root/state/phase" "$owner $plan $boot staged-required"
      expect_record "$root/state/mode" work
      expect_record "$stage/state" "v1 $owner $plan $profile $boot complete 3"
      closed_record "$root/state/deadlines"
      [[ $REPLY =~ ^[0-9]+\ [0-9]+$ ]] || fail
      ((record_guard_fuel == 0)) || fail
      claim execution
      rootful_admitted=1
      ;;
    provider) rootful_admitted=1 ;;
    *) fail ;;
  esac
}
rootful_stage_seed() {
  expect_record "$root/state/phase" "$owner $plan $boot prerequisite-inflight"
  expect_record "$root/state/prerequisite-claimed" "$owner $plan $boot"
  [[ -f /usr/bin/flock && ! -L /usr/bin/flock && -x /usr/bin/flock && -O /usr/bin/flock && -f $stage/lock && ! -L $stage/lock && -O $stage/lock ]] || fail
  exec 9<> "$stage/lock"
  # One nonblocking lock invocation, charged inside the original768 utilities.
  # Whole-image trust, the exact util-linux RPM predicate and existing stage
  # flock2.41.5 inventory remain its software authority; no new version query.
  u /usr/bin/flock -n 9 || fail
  stage_pristine
  new_record "$stage/state" "v1 $owner $plan $profile $boot ready 0"
}
rootful_publish_prerequisite() {
  [[ ! -e $root/state/poison && ! -L $root/state/poison ]] || fail
  expect_record "$root/state/phase" "$owner $plan $boot prerequisite-inflight"
  expect_record "$root/state/prerequisite-claimed" "$owner $plan $boot"
  expect_record "$root/state/mode" work
  expect_record "$stage/state" "v1 $owner $plan $profile $boot ready 0"
  closed_record "$root/state/deadlines"
  [[ $REPLY =~ ^[0-9]+\ [0-9]+$ ]] || fail
  # Publish success last, still holding the same stage lock. Lost ACKs do not
  # permit a second prerequisite or reset the existing ready0 cursor.
  printf '%s %s %s staged-required\n' "$owner" "$plan" "$boot" > "$root/state/phase"
  expect_record "$root/state/phase" "$owner $plan $boot staged-required"
  ((record_guard_fuel == 0)) || fail
}

# Entry: pure-control tests load only the definitions above; no guest program.
# Closed roles precede preflight; missing role never a fresh epoch.
rootful_intent=${1:-}
case $rootful_intent in
  prerequisite-v1 | execution-v1) [[ $# == 1 ]] || fail ;;
  provider) ;;
  *) fail ;;
esac
# Initial prerequisite selection.
if [[ $# == 1 && ${1:-} == prerequisite-v1 && ! -e $root/state/phase && ! -L $root/state/phase && ! -e $root/state/mode && ! -L $root/state/mode ]]; then
  prerequisite_mode=1
fi
[[ $EUID == 0 && $BASH_VERSION == 5.3.9* ]] || fail entry
read -r boot < /proc/sys/kernel/random/boot_id
[[ $boot =~ ^[0-9a-f-]{36}$ ]] || fail entry
# Trusted Ignition bindings precede first debit; checksummed spec follows.
read_file "$root/spec.json"
[[ $REPLY =~ \"owner\":\"([0-9a-f]{32})\" ]] || fail source
owner=${BASH_REMATCH[1]}
[[ $REPLY =~ \"plan_sha256\":\"([0-9a-f]{64})\" ]] || fail source
plan=${BASH_REMATCH[1]}
[[ $REPLY =~ \"profile\":\"([a-z0-9.-]+)\" ]] || fail source
profile=${BASH_REMATCH[1]}
[[ $profile == legacy-1.20.15 || $profile == modern-1.37.0 ]] || fail source
mode=work
rootful_boot_guard "$rootful_intent"
if [[ $rootful_intent != provider ]]; then shift; fi
if [[ -f $root/state/mode ]]; then
  read_file "$root/state/mode"
  mode=$REPLY
fi
[[ $mode == work || $mode == cleanup ]] || fail source
u /usr/bin/sha256sum --check --status "$root/checks.sha256" || fail source
values=$(u /usr/bin/jq -er 'select(.schema=="kubernetes-lens-owned-rootful-v13" and .resource_profile=="owned-vm-live-v1" and .resource_facts_sha256=="171aa78b13ac5e1a5b3863adab4f6b3dfd48a5877d2e06132bcb4a7a5c272106")|[.owner,.plan_sha256,.profile,.config_sha256,.manifest_sha256,.fixture_sha256,.kind_sha256,.kubectl_sha256,.archive_sha256,.server_patch,.kind_version,.expanded_image_bytes,.archive_bytes,.stage_payload_bytes]|.[]' "$root/spec.json") || fail
mapfile -t fields <<< "$values"
[[ ${#fields[@]} == 14 && ${fields[0]} == "$owner" && ${fields[1]} == "$plan" ]] || fail source
profile=${fields[2]}
image_id=${fields[3]}
manifest_sha=${fields[4]}
fixture_sha=${fields[5]}
kind_sha=${fields[6]}
kubectl_sha=${fields[7]}
archive_sha=${fields[8]}
patch=${fields[9]}
kind_version=${fields[10]}
expanded_image_bytes=${fields[11]}
archive_bytes=${fields[12]}
stage_payload_bytes=${fields[13]}
for value in "$expanded_image_bytes" "$archive_bytes" "$stage_payload_bytes"; do [[ $value =~ ^[1-9][0-9]{0,10}$ ]] || fail source; done
((expanded_image_bytes <= 4294967296 && archive_bytes <= 2147483648 && stage_payload_bytes <= 2415919104)) || fail source
[[ $profile == legacy-1.20.15 || $profile == modern-1.37.0 ]] || fail source
for value in "$image_id" "$manifest_sha" "$fixture_sha" "$kind_sha" "$kubectl_sha" "$archive_sha"; do [[ $value =~ ^[0-9a-f]{64}$ ]] || fail source; done
readonly owner plan boot profile image_id manifest_sha fixture_sha kind_sha kubectl_sha archive_sha patch kind_version expanded_image_bytes archive_bytes stage_payload_bytes
readonly cluster=kl-$owner node=kl-$owner-control-plane alias=localhost/kubernetes-lens-node:$owner
private_environment
if [[ ${1:-} == provider ]]; then
  prerequisite_mode=0
  shift
  provider "$@"
  exit $?
fi
[[ $# == 0 ]] || fail entry
for path in / /var /var/lib "$root" "$root/bin" "$root/state" "$credits" "$captures"; do
  [[ -d $path && ! -L $path ]] || fail paths
  value=$(u /usr/bin/stat -c '%u:%a' "$path") || fail
  [[ $value == 0:* ]] || fail paths
  value=${value#*:}
  (((8#$value & 8#022) == 0)) || fail paths
done
value=$(u /usr/bin/jq --version) || fail pkg-jq-ver
[[ $value == jq-1.8.1 ]] || fail pkg-jq-ver
value=''
packages=$(u /usr/bin/rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' bash jq coreutils systemd podman skopeo crun conmon netavark aardvark-dns util-linux libcap) || fail
[[ $packages == $'bash 5.3.9-3.fc44\njq 1.8.1-3.fc44\ncoreutils 9.10-5.fc44\nsystemd 259.9-1.fc44\npodman 5.8.7-1.fc44\nskopeo 1.22.3-1.fc44\ncrun 1.28-1.fc44\nconmon 2.2.1-2.fc44\nnetavark 1.17.2-1.fc44\naardvark-dns 1.17.1-1.fc44\nutil-linux 2.41.5-1.fc44\nlibcap 2.78-1.fc44' ]] || package_tuple_failure
# PDEATHSIG survives only ordinary credential-preserving execs. Bind the
# official-image executables before launch; absent getcap refuses, no installer.
for path in /usr/bin/setpriv /usr/bin/bash /usr/bin/podman; do
  [[ -f $path && ! -L $path && -x $path ]] || fail exec-closure
  value=$(u /usr/bin/stat -c '%u:%g:%a' "$path") || fail
  [[ $value == 0:0:* ]] || fail exec-closure
  value=${value##*:}
  [[ $value =~ ^[0-7]{3,4}$ ]] || fail exec-closure
  (((8#$value & 8#6022) == 0)) || fail exec-closure
done
[[ -x /usr/sbin/getcap && ! -L /usr/sbin/getcap ]] || fail exec-closure
value=$(u /usr/sbin/getcap -n /usr/bin/setpriv /usr/bin/bash /usr/bin/podman) || fail exec-closure
[[ -z $value ]] || fail exec-closure
value=$(SYSTEMD_COLORS=0 u /usr/lib/systemd/systemd --version) || fail "pkg-sd-q$?"
[[ $value == 'systemd 259 (259.9'* ]] || fail pkg-sd-ver
value=''
read -r kernel < /proc/sys/kernel/osrelease
[[ $kernel == 7.2.7-200.fc44.x86_64 ]] || fail pkg-kernel
if [[ $rootful_intent == prerequisite-v1 ]]; then
  prerequisite_eof
  [[ ! -e $root/storage && ! -e /run/kubernetes-lens-rootful ]] || fail fresh-state
  [[ ! -e $stage/state ]] || fail fresh-state
  u /usr/bin/mkdir -m 700 "$root/config" "$root/config/networks" "$root/home" "$root/tmp" "$root/data" /run/kubernetes-lens-rootful /run/kubernetes-lens-rootful/storage || fail
  printf '[storage]\ndriver="overlay"\ngraphroot="%s/storage"\nrunroot="/run/kubernetes-lens-rootful/storage"\n' "$root" > "$root/config/storage.conf"
  printf '[engine]\ncgroup_manager="cgroupfs"\nruntime="crun"\nhooks_dir=[]\n[network]\nnetwork_backend="netavark"\nnetwork_config_dir="%s/config/networks"\n' "$root" > "$root/config/containers.conf"
  printf 'unqualified-search-registries=[]\n' > "$root/config/registries.conf"
  printf '{"auths":{}}\n' > "$root/config/auth.json"
  printf '{"default":[{"type":"reject"}],"transports":{"oci-archive":{"%s/node.oci.tar":[{"type":"insecureAcceptAnything"}]}}}\n' "$stage" > "$root/config/policy.json"
  [[ ! -e /etc/cdi && ! -e /var/run/cdi ]] || fail fresh-state
  resource_check
  rootful_stage_seed
  uptime_now
  printf '%s %s\n' "$((UPTIME + 1680))" "$((UPTIME + 1800))" > "$root/state/deadlines"
  printf '%s\n' work > "$root/state/mode"
  mode=work
  printf '%s %s %s prerequisite-inflight\n' "$owner" "$plan" "$boot" > "$root/state/phase"
  native 16384 4096 /usr/bin/podman --remote=false info --format=json || fail podman-info
  info_check "$out"
  remember podman-info "$out"
  rootful_publish_prerequisite
  u /usr/bin/cat "$out" || fail
  exit 0
fi
prerequisite_mode=0
read_file "$root/state/phase"
[[ $REPLY == "$owner $plan $boot staged-required" ]] || fail
read_file "$stage/state"
[[ $REPLY == "v1 $owner $plan $profile $boot complete 3" ]] || fail
receive_packet
spec_sha=$(u /usr/bin/sha256sum "$root/spec.json") || fail
spec_sha=${spec_sha%% *}
[[ $packet =~ ^rootful-kind-v1\ $owner\ $plan\ $spec_sha\ ([1-9][0-9]{0,3})$ ]] || fail
seconds=${BASH_REMATCH[1]}
((seconds <= 1680)) || fail
uptime_now
read_file "$root/state/deadlines"
read -r previous_work previous_end <<< "$REPLY"
work=$((UPTIME + seconds))
end=$((work + 120))
((work <= previous_work && end <= previous_end)) || fail
printf '%s %s\n' "$work" "$end" > "$root/state/deadlines"
printf '%s %s %s execution-inflight\n' "$owner" "$plan" "$boot" > "$root/state/phase"
mode=work
created=0 create_status=-1 delete_status=-1 source_status=not-reached
# shellcheck disable=SC2329
finish() {
  local status=$? n=0 utilities=0 utility_ledger=0 output_count=0
  postlog_site=''
  trap - EXIT ERR HUP INT TERM
  pace_close
  [[ $status == 0 ]] || printf '%s\n' poisoned > "$root/state/poison"
  remember kind-create-failure || status=1
  if ((created)); then
    mode=cleanup
    printf '%s\n' cleanup > "$root/state/mode"
    if native 4096 4096 "$stage/kind" delete cluster --name "$cluster"; then delete_status=$tool_status; else
      delete_status=${tool_status:--1}
      status=1
    fi
    ((delete_status == 0)) || status=1
  fi
  emit_evidence
  emit_logs_evidence
  shopt -s nullglob
  local tokens=("$credits"/work.* "$credits"/cleanup.*)
  n=${#tokens[@]}
  tokens=("$credits"/utility-work.* "$credits"/utility-cleanup.*)
  utility_ledger=${#tokens[@]}
  utilities=$((utility_ledger + 24))
  tokens=("$credits"/output-work.* "$credits"/output-cleanup.*)
  output_count=$((${#tokens[@]} * 4096))
  tokens=("$credits"/sentinel.*)
  output_count=$((output_count + ${#tokens[@]}))
  local state=failed
  ((status == 0 && create_status == 0 && delete_status == 0)) && state='source-deployment-positive'
  local wire_json postlog_json=null
  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json '"%s"' "$postlog_failure" ;; esac
  printf -v wire_json '{"schema":"kubernetes-lens-owned-rootful-result-v13","resource_profile":"owned-vm-live-v1","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"
  ((${#wire_json} + 1 <= 262144)) || fail
  printf '%s\n' "$wire_json"
  exit "$status"
}
trap finish EXIT
trap 'exit 1' ERR HUP INT TERM
resource_check
for name in kind kubectl node.oci.tar; do [[ -f $stage/$name && ! -L $stage/$name ]] || fail; done
value=$(u /usr/bin/sha256sum "$stage/kind") || fail
[[ $value == "$kind_sha  $stage/kind" ]] || fail
value=''
value=$(u /usr/bin/sha256sum "$stage/kubectl") || fail
[[ $value == "$kubectl_sha  $stage/kubectl" ]] || fail
value=''
value=$(u /usr/bin/sha256sum "$stage/node.oci.tar") || fail
[[ $value == "$archive_sha  $stage/node.oci.tar" ]] || fail
value=''
native 4096 4096 "$stage/kind" version || fail
read_file "$out"
[[ $REPLY == "kind v$kind_version "* ]] || fail
native 4096 4096 "$stage/kubectl" version --client -o json || fail
# shellcheck disable=SC2016
u /usr/bin/jq -e --arg patch "v$patch" '.clientVersion.gitVersion==$patch' "$out" > /dev/null || fail
native 16384 4096 /usr/bin/skopeo --policy "$root/config/policy.json" copy --preserve-digests "oci-archive:$stage/node.oci.tar" "containers-storage:$alias" || fail
native 16384 4096 /usr/bin/skopeo inspect --raw "containers-storage:$alias" || fail
value=$(u /usr/bin/sha256sum "$out") || fail
[[ $value == "$manifest_sha  $out" ]] || fail
value=''
remember manifest "$out"
native 16384 4096 /usr/bin/skopeo inspect --raw --config "containers-storage:$alias" || fail
value=$(u /usr/bin/sha256sum "$out") || fail
[[ $value == "$image_id  $out" ]] || fail
value=''
remember config "$out"
native 16384 4096 /usr/bin/podman --remote=false inspect --type=image "$alias" || fail
# shellcheck disable=SC2016
u /usr/bin/jq -e --arg id "$image_id" 'length==1 and .[0].Id==$id' "$out" > /dev/null || fail
remember image-inspect "$out"
network_routes
native 4096 4096 /usr/bin/podman --remote=false network create -d=bridge --interface-name klbr0 --disable-dns --label "io.kubernetes-lens.issue2.owner=$owner" --subnet 172.30.0.0/16 --gateway 172.30.0.1 kind || fail
printf '%s\n' "$owner $plan $boot" > "$root/state/network-created"
native 4096 4096 /usr/bin/podman --remote=false network inspect kind || fail
network_check "$out"
remember network-inspect "$out"
printf '%s\n' '---' 'kind: Cluster' 'apiVersion: kind.x-k8s.io/v1alpha4' 'networking:' '  ipFamily: ipv4' '  apiServerAddress: 127.0.0.1' '  apiServerPort: 6443' '  podSubnet: 10.244.0.0/16' '  serviceSubnet: 10.96.0.0/16' 'nodes:' '- role: control-plane' > "$root/config/kind.yaml"
created=1
if native 16384 32768 "$stage/kind" create cluster --name "$cluster" --image "$alias" --config "$root/config/kind.yaml" --kubeconfig "$KUBECONFIG" --wait 0s; then create_status=$tool_status; else
  kind_failure_wrapper_status=$? create_status=${tool_status:--1} kind_failure_err=${err:-} kind_stdout_status=${stdout_status:--1} kind_stderr_status=${stderr_status:--1}
  fail
fi
logs_retirement
postlog_site=r
resource_check vm-live-v1
postlog_site=i
read_file "$root/state/node-id"
node_id=$REPLY
postlog_site=f
[[ $node_id =~ ^[0-9a-f]{64}$ ]] || fail
postlog_site=n
postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null
native 16384 4096 /usr/bin/podman --remote=false inspect --type=container --format '[{{json .}}]' "$node" || {
  postlog_rc=$?
  fail
}
postlog_site=j
# shellcheck disable=SC2016
u /usr/bin/jq -e --arg id "$node_id" --arg image "$image_id" --arg node "$node" 'length==1 and .[0].Id==$id and .[0].Image==$image and .[0].Name==$node and .[0].State.Running==true and .[0].State.Pid>0 and (.[0].Config.CreateCommand|map(select(.=="--pull=never"))|length)==1 and .[0].Config.CreateCommand[-1]==$image and (.[0].NetworkSettings.Networks|keys)==["kind"] and .[0].NetworkSettings.Ports["6443/tcp"]==[{"HostIp":"127.0.0.1","HostPort":"6443"}]' "$out" > /dev/null || fail
postlog_site=e
remember node-inspect "$out"
postlog_site=a
node_cgroup=/libpod_parent/libpod-$node_id
# shellcheck disable=SC2016
u /usr/bin/jq -e --arg path "$node_cgroup" '.[0].State.CgroupPath==$path' "$out" > /dev/null || fail
postlog_site=b
node_pid=$(u /usr/bin/jq -er '.[0].State.Pid' "$out") || fail
[[ $node_pid =~ ^[1-9][0-9]{0,4}$ ]] || fail
((node_pid < pid_max)) || fail
postlog_site=c
read_file "/proc/$node_pid/stat"
node_stat=$REPLY
postlog_site=d
[[ $node_stat == "$node_pid ("*') '* ]] || fail
tail=${node_stat##*) }
read -ra fields <<< "$tail"
expected_start=${fields[19]:-}
((${#fields[@]} >= 20)) && [[ $expected_start =~ ^[0-9]+$ ]] || fail
postlog_site=g
read_file "/proc/$node_pid/cgroup"
[[ $REPLY =~ ^0::"$node_cgroup"(/[^/[:cntrl:]]+)*$ && $REPLY != */. && $REPLY != */.. &&
  $REPLY != */./* && $REPLY != */../* ]] || fail
printf '%s\n%s\n' "$node_stat" "$REPLY" > "$root/state/actual-node-process"
postlog_site=h
read_file "/proc/$node_pid/stat"
[[ $REPLY == "$node_pid ("*') '* ]] || fail
tail=${REPLY##*) }
read -ra fields <<< "$tail"
[[ ${fields[19]:-} == "$expected_start" ]] || fail
postlog_site=k
k_site=a
native 65536 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" config view --raw -o json || {
  postlog_rc=$?
  fail
}
k_site=b
# shellcheck disable=SC2016
u /usr/bin/jq -e --arg name "kind-$cluster" '."current-context"==$name and (.clusters|length)==1 and (.contexts|length)==1 and (.users|length)==1 and .clusters[0].name==$name and .clusters[0].cluster.server=="https://127.0.0.1:6443" and (.clusters[0].cluster|keys)==["certificate-authority-data","server"] and (.users[0].user|keys)==["client-certificate-data","client-key-data"] and .contexts[0].context.cluster==$name and .contexts[0].context.user==$name' "$out" > /dev/null || fail
k_site=c
native 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" version -o json || {
  postlog_rc=$?
  fail
}
k_site=d
# shellcheck disable=SC2016
u /usr/bin/jq -e --arg patch "v$patch" '.serverVersion.gitVersion==$patch' "$out" > /dev/null || fail
ready=0
for _round in 1 2; do
  k_site=e
  native 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" get --raw=/readyz || {
    postlog_rc=$?
    continue
  }
  k_site=f
  read_file "$out"
  k_site=g
  [[ $REPLY == ok ]] || continue
  k_site=o
  native 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" wait --for=condition=Ready nodes --all --timeout=30s || {
    postlog_rc=$?
    fail
  }
  k_site=h
  native 16384 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" get nodes -o json || {
    postlog_rc=$?
    fail
  }
  k_site=i i_admitted=0 i_return=null i_round=$_round
  if
    # jq uses --arg.
    # shellcheck disable=SC2016
    u /usr/bin/jq -en --arg node "$node" --arg patch "v$patch" 'def classify: .items|if length!=1 then 64 else .[0]|if .metadata.name!=$node then 65 elif .status.nodeInfo.kubeletVersion!=$patch then 66 else .status.conditions|if any(.[]; .type=="Ready" and .status=="True") then 0 elif any(.[]; .type=="Ready" and (.message|strings|contains("NetworkPluginNotReady"))) then 69 elif any(.[]; .type=="Ready") then 67 else 68 end end end; (reduce inputs as $n (4; try ($n|classify) catch 5)) as $s|if $s==0 then true else ""|halt_error($s) end' "$out" > /dev/null
  then
    ready=1
    break
  else
    i_return=$?
    fail
  fi
done
((ready)) || fail
k_site=j
native 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" create namespace demo -o json || {
  postlog_rc=$?
  fail
}
k_site=k
value=$(u /usr/bin/sha256sum "$root/deployment.json") || fail
k_site=l
[[ $value == "$fixture_sha  $root/deployment.json" ]] || fail
value=''
k_site=m
native 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" create --dry-run=server -f "$root/deployment.json" '-o=jsonpath={@}' || {
  postlog_rc=$?
  fail
}
k_site=n
u /usr/bin/jq -e '.apiVersion=="apps/v1" and .kind=="Deployment" and .metadata.namespace=="demo" and .metadata.name=="demo"' "$out" > /dev/null || fail
source_status=server-dry-run-observed
exit 0
