"""Pure caller/receiver controls; no runtime, SSH, VM or Kubernetes tool executes."""
from contextlib import ExitStack
import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import owned_guest_rootful as rootful
import owned_guest_stage as stage
import owned_qemu as vm
from test_owned_guest_receiver import OwnedPipeChild

SCRIPT = Path(__file__).with_name('owned_guest_rootful.sh')
FINE_PACKAGE_CODES = ('pkg-jq-ver', 'pkg-sd-ver', 'pkg-sd-query', 'pkg-kernel', 'rpm-shape', 'rpm-bash', 'rpm-jq', 'rpm-coreutils', 'rpm-systemd', 'rpm-podman', 'rpm-skopeo', 'rpm-crun', 'rpm-conmon', 'rpm-netavark', 'rpm-aardvark', 'rpm-util-linux', 'rpm-libcap')

INVENTORY_CODES = ('inv-pid-range', 'inv-proc-task', 'inv-proc-read', 'inv-proc-pid', 'inv-proc-form', 'inv-task-empty', 'inv-tid-count', 'inv-task-read', 'inv-task-tid', 'inv-task-form', 'inv-nf-form', 'inv-nf-range', 'inv-fd-access', 'inv-fd-form', 'inv-fd-range', 'inv-snap-size', 'inv-empty', 'inv-drift')


# ADR0101 exact current -> frozen source339 DATA inverse.
LIVE_ENVELOPE_SOURCE = '145ea71ea21376b2f0385320a7799259ebd0c99168c9eec03d1c9144733872f1'
LIVE_ENVELOPE_SOURCE_BYTES = 65191
LIVE_ENVELOPE_PREDECESSOR = '0a512e1f5d2a9463e17fd5d10319b4a989129eb1149a5c4f4fbfc84b688424ad'
LIVE_ENVELOPE_PREDECESSOR_BYTES = 65397
LIVE_ENVELOPE_SOURCE_DELTA = [('}\n\ninfo_check() {\n  # jq variables use --arg, not shell expansion.\n  # shellcheck disable=SC2016\n  u /usr/bin/jq -e --arg root "$root" \'.host.security.rootless == false and .host.serviceIsRemote == false and .host.cgroupVersion == "v2" and .host.os == "linux" and .host.arch == "amd64" and .version.Version == "5.8.7" and .host.networkBackend == "netavark" and .host.cgroupManager == "cgroupfs" and .store.graphDriverName == "overlay" and .store.graphRoot == ($root+"/storage") and .store.runRoot == "/run/kubernetes-lens-rootful/storage" and .store.graphStatus["Backing Filesystem"] == "xfs"\' "$1" > /dev/null || fail podman-profile\n}\ninventory() {\n  local process pid tid task record tail hard _soft a b c rest fd count=0\n  SNAP=\'\'\n  declare -gA INVENTORY_START=()\n  shopt -s nullglob\n  for process in /proc/[0-9]*; do\n    pid=${process##*/}\n', '}\n\ninfo_check() {\n  # jq uses --arg.\n  # shellcheck disable=SC2016\n  u /usr/bin/jq -e --arg root "$root" \'.host.security.rootless == false and .host.serviceIsRemote == false and .host.cgroupVersion == "v2" and .host.os == "linux" and .host.arch == "amd64" and .version.Version == "5.8.7" and .host.networkBackend == "netavark" and .host.cgroupManager == "cgroupfs" and .store.graphDriverName == "overlay" and .store.graphRoot == ($root+"/storage") and .store.runRoot == "/run/kubernetes-lens-rootful/storage" and .store.graphStatus["Backing Filesystem"] == "xfs"\' "$1" > /dev/null || fail podman-profile\n}\ninventory() {\n  local process pid tid task record tail hard _soft a b c rest fd count=0\n  SNAP=\'\'\n  shopt -s nullglob\n  for process in /proc/[0-9]*; do\n    pid=${process##*/}\n'), ('      tail=${record##*) }\n      read -ra fields <<< "$tail"\n      ((${#fields[@]} >= 20)) && [[ ${fields[19]} =~ ^[0-9]+$ ]] || fail inv-task-form\n      INVENTORY_START[$tid]=${fields[19]}\n      SNAP+="$tid:${fields[19]}:"\n      hard=\'\'\n      while read -r a b c _soft rest; do\n', '      tail=${record##*) }\n      read -ra fields <<< "$tail"\n      ((${#fields[@]} >= 20)) && [[ ${fields[19]} =~ ^[0-9]+$ ]] || fail inv-task-form\n      SNAP+="$tid:${fields[19]}:"\n      hard=\'\'\n      while read -r a b c _soft rest; do\n'), ('}\n\nresource_check() {\n  [[ $# == 0 || $# == 1 && $1 == live ]] || fail\n  local value before namespace proc_ok=0 root_ok=0 total=0 swap=0 a b c d e rest entry\n  read -r value < /proc/sys/kernel/pid_max\n  [[ $value == 32768 ]] || fail pid-max\n', '}\n\nresource_check() {\n  [[ $# == 0 || $# == 1 && $1 == vm-live-v1 ]] || fail\n  local value before namespace proc_ok=0 root_ok=0 total=0 swap=0 a b c d e rest entry\n  read -r value < /proc/sys/kernel/pid_max\n  [[ $value == 32768 ]] || fail pid-max\n'), ('    ((available * block_size >= required)) || fail filesystem\n  fi\n  printf \'%s\\n\' "$fs_values" > "$root/state/actual-filesystem"\n  inventory\n  before=$SNAP\n  inventory\n  [[ ${1:-} == live || $SNAP == "$before" ]] || fail inv-drift\n}\nnetwork_routes() {\n  [[ ! -e /sys/class/net/klbr0 && ! -L /sys/class/net/klbr0 && -f /proc/net/route && -r /proc/net/route ]] || fail\n', '    ((available * block_size >= required)) || fail filesystem\n  fi\n  printf \'%s\\n\' "$fs_values" > "$root/state/actual-filesystem"\n  if (($# == 0)); then\n    inventory\n    before=$SNAP\n    inventory\n    [[ $SNAP == "$before" ]] || fail inv-drift\n  fi\n}\nnetwork_routes() {\n  [[ ! -e /sys/class/net/klbr0 && ! -L /sys/class/net/klbr0 && -f /proc/net/route && -r /proc/net/route ]] || fail\n'), ('    claim node\n    resource_check\n    native 16384 4096 /usr/bin/podman --remote=false inspect --type=image "$alias" || fail\n    # jq variables use --arg, not shell expansion.\n    # shellcheck disable=SC2016\n    u /usr/bin/jq -e --arg id "$image_id" \'length==1 and .[0].Id==$id\' "$out" > /dev/null || fail\n    remember image-inspect "$out"\n', '    claim node\n    resource_check\n    native 16384 4096 /usr/bin/podman --remote=false inspect --type=image "$alias" || fail\n    # jq uses --arg.\n    # shellcheck disable=SC2016\n    u /usr/bin/jq -e --arg id "$image_id" \'length==1 and .[0].Id==$id\' "$out" > /dev/null || fail\n    remember image-inspect "$out"\n'), ('}\nnetwork_check() {\n  local actual\n  # jq variables use --arg, not shell expansion.\n  # shellcheck disable=SC2016\n  u /usr/bin/jq -e --arg owner "$owner" \'length==1 and .[0].name=="kind" and (.[0].id|test("^[0-9a-f]{64}$")) and .[0].driver=="bridge" and .[0].network_interface=="klbr0" and .[0].ipv6_enabled==false and .[0].dns_enabled==false and .[0].subnets==[{"subnet":"172.30.0.0/16","gateway":"172.30.0.1"}] and .[0].labels["io.kubernetes-lens.issue2.owner"]==$owner\' "$1" > /dev/null || fail\n  actual=$(u /usr/bin/jq -er \'.[0].id\' "$1") || fail\n', '}\nnetwork_check() {\n  local actual\n  # jq uses --arg.\n  # shellcheck disable=SC2016\n  u /usr/bin/jq -e --arg owner "$owner" \'length==1 and .[0].name=="kind" and (.[0].id|test("^[0-9a-f]{64}$")) and .[0].driver=="bridge" and .[0].network_interface=="klbr0" and .[0].ipv6_enabled==false and .[0].dns_enabled==false and .[0].subnets==[{"subnet":"172.30.0.0/16","gateway":"172.30.0.1"}] and .[0].labels["io.kubernetes-lens.issue2.owner"]==$owner\' "$1" > /dev/null || fail\n  actual=$(u /usr/bin/jq -er \'.[0].id\' "$1") || fail\n'), ('}\n\n# Entry: pure-control tests load only the definitions above; no guest program.\n# Closed source-selected roles precede any guest preflight. Provider and logs\n# keep their existing internal routes; a missing role is never a fresh epoch.\nrootful_intent=${1:-}\ncase $rootful_intent in\n  prerequisite-v1 | execution-v1) [[ $# == 1 ]] || fail ;;\n  provider) ;;\n  *) fail ;;\nesac\n# Initial prerequisite diagnostic selection; admission checks remain unchanged.\nif [[ $# == 1 && ${1:-} == prerequisite-v1 && ! -e $root/state/phase && ! -L $root/state/phase && ! -e $root/state/mode && ! -L $root/state/mode ]]; then\n  prerequisite_mode=1\nfi\n[[ $EUID == 0 && $BASH_VERSION == 5.3.9* ]] || fail entry\nread -r boot < /proc/sys/kernel/random/boot_id\n[[ $boot =~ ^[0-9a-f-]{36}$ ]] || fail entry\n# Trusted, source-written Ignition inputs provide these initial bindings before\n# the first predebit; the full checksummed spec is authenticated immediately next.\nread_file "$root/spec.json"\n[[ $REPLY =~ \\"owner\\":\\"([0-9a-f]{32})\\" ]] || fail source\nowner=${BASH_REMATCH[1]}\n', '}\n\n# Entry: pure-control tests load only the definitions above; no guest program.\n# Closed roles precede preflight; missing role never a fresh epoch.\nrootful_intent=${1:-}\ncase $rootful_intent in\n  prerequisite-v1 | execution-v1) [[ $# == 1 ]] || fail ;;\n  provider) ;;\n  *) fail ;;\nesac\n# Initial prerequisite selection.\nif [[ $# == 1 && ${1:-} == prerequisite-v1 && ! -e $root/state/phase && ! -L $root/state/phase && ! -e $root/state/mode && ! -L $root/state/mode ]]; then\n  prerequisite_mode=1\nfi\n[[ $EUID == 0 && $BASH_VERSION == 5.3.9* ]] || fail entry\nread -r boot < /proc/sys/kernel/random/boot_id\n[[ $boot =~ ^[0-9a-f-]{36}$ ]] || fail entry\n# Trusted Ignition bindings precede first debit; checksummed spec follows.\nread_file "$root/spec.json"\n[[ $REPLY =~ \\"owner\\":\\"([0-9a-f]{32})\\" ]] || fail source\nowner=${BASH_REMATCH[1]}\n'), ('fi\n[[ $mode == work || $mode == cleanup ]] || fail source\nu /usr/bin/sha256sum --check --status "$root/checks.sha256" || fail source\nvalues=$(u /usr/bin/jq -er \'select(.schema=="kubernetes-lens-owned-rootful-v12")|[.owner,.plan_sha256,.profile,.config_sha256,.manifest_sha256,.fixture_sha256,.kind_sha256,.kubectl_sha256,.archive_sha256,.server_patch,.kind_version,.expanded_image_bytes,.archive_bytes,.stage_payload_bytes]|.[]\' "$root/spec.json") || fail\nmapfile -t fields <<< "$values"\n[[ ${#fields[@]} == 14 && ${fields[0]} == "$owner" && ${fields[1]} == "$plan" ]] || fail source\nprofile=${fields[2]}\n', 'fi\n[[ $mode == work || $mode == cleanup ]] || fail source\nu /usr/bin/sha256sum --check --status "$root/checks.sha256" || fail source\nvalues=$(u /usr/bin/jq -er \'select(.schema=="kubernetes-lens-owned-rootful-v13" and .resource_profile=="owned-vm-live-v1" and .resource_facts_sha256=="171aa78b13ac5e1a5b3863adab4f6b3dfd48a5877d2e06132bcb4a7a5c272106")|[.owner,.plan_sha256,.profile,.config_sha256,.manifest_sha256,.fixture_sha256,.kind_sha256,.kubectl_sha256,.archive_sha256,.server_patch,.kind_version,.expanded_image_bytes,.archive_bytes,.stage_payload_bytes]|.[]\' "$root/spec.json") || fail\nmapfile -t fields <<< "$values"\n[[ ${#fields[@]} == 14 && ${fields[0]} == "$owner" && ${fields[1]} == "$plan" ]] || fail source\nprofile=${fields[2]}\n'), ('  ((status == 0 && create_status == 0 && delete_status == 0)) && state=\'source-deployment-positive\'\n  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v12","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n  exit "$status"\n', '  ((status == 0 && create_status == 0 && delete_status == 0)) && state=\'source-deployment-positive\'\n  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v13","resource_profile":"owned-vm-live-v1","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n  exit "$status"\n'), ('fi\nlogs_retirement\npostlog_site=r\nresource_check live\npostlog_site=i\nread_file "$root/state/node-id"\nnode_id=$REPLY\n', 'fi\nlogs_retirement\npostlog_site=r\nresource_check vm-live-v1\npostlog_site=i\nread_file "$root/state/node-id"\nnode_id=$REPLY\n'), ('[[ $node_pid =~ ^[1-9][0-9]{0,4}$ ]] || fail\n((node_pid < pid_max)) || fail\npostlog_site=c\nexpected_start=${INVENTORY_START[$node_pid]:-}\n[[ $expected_start =~ ^[0-9]+$ ]] || fail\npostlog_site=d\nread_file "/proc/$node_pid/stat"\nnode_stat=$REPLY\n[[ ${node_stat%% *} == "$node_pid" ]] || fail\ntail=${node_stat##*) }\nread -ra fields <<< "$tail"\n[[ ${fields[19]:-} == "$expected_start" ]] || fail\npostlog_site=g\nread_file "/proc/$node_pid/cgroup"\n[[ $REPLY =~ ^0::"$node_cgroup"(/[^/[:cntrl:]]+)*$ && $REPLY != */. && $REPLY != */.. &&\n', '[[ $node_pid =~ ^[1-9][0-9]{0,4}$ ]] || fail\n((node_pid < pid_max)) || fail\npostlog_site=c\nread_file "/proc/$node_pid/stat"\nnode_stat=$REPLY\npostlog_site=d\n[[ $node_stat == "$node_pid ("*\') \'* ]] || fail\ntail=${node_stat##*) }\nread -ra fields <<< "$tail"\nexpected_start=${fields[19]:-}\n((${#fields[@]} >= 20)) && [[ $expected_start =~ ^[0-9]+$ ]] || fail\npostlog_site=g\nread_file "/proc/$node_pid/cgroup"\n[[ $REPLY =~ ^0::"$node_cgroup"(/[^/[:cntrl:]]+)*$ && $REPLY != */. && $REPLY != */.. &&\n'), ('printf \'%s\\n%s\\n\' "$node_stat" "$REPLY" > "$root/state/actual-node-process"\npostlog_site=h\nread_file "/proc/$node_pid/stat"\ntail=${REPLY##*) }\nread -ra fields <<< "$tail"\n[[ ${fields[19]:-} == "$expected_start" ]] || fail\n', 'printf \'%s\\n%s\\n\' "$node_stat" "$REPLY" > "$root/state/actual-node-process"\npostlog_site=h\nread_file "/proc/$node_pid/stat"\n[[ $REPLY == "$node_pid ("*\') \'* ]] || fail\ntail=${REPLY##*) }\nread -ra fields <<< "$tail"\n[[ ${fields[19]:-} == "$expected_start" ]] || fail\n'), ('  }\n  k_site=i i_admitted=0 i_return=null i_round=$_round\n  if\n    # jq variables use --arg, not shell expansion.\n    # shellcheck disable=SC2016\n    u /usr/bin/jq -en --arg node "$node" --arg patch "v$patch" \'def classify: .items|if length!=1 then 64 else .[0]|if .metadata.name!=$node then 65 elif .status.nodeInfo.kubeletVersion!=$patch then 66 else .status.conditions|if any(.[]; .type=="Ready" and .status=="True") then 0 elif any(.[]; .type=="Ready" and (.message|strings|contains("NetworkPluginNotReady"))) then 69 elif any(.[]; .type=="Ready") then 67 else 68 end end end; (reduce inputs as $n (4; try ($n|classify) catch 5)) as $s|if $s==0 then true else ""|halt_error($s) end\' "$out" > /dev/null\n  then\n', '  }\n  k_site=i i_admitted=0 i_return=null i_round=$_round\n  if\n    # jq uses --arg.\n    # shellcheck disable=SC2016\n    u /usr/bin/jq -en --arg node "$node" --arg patch "v$patch" \'def classify: .items|if length!=1 then 64 else .[0]|if .metadata.name!=$node then 65 elif .status.nodeInfo.kubeletVersion!=$patch then 66 else .status.conditions|if any(.[]; .type=="Ready" and .status=="True") then 0 elif any(.[]; .type=="Ready" and (.message|strings|contains("NetworkPluginNotReady"))) then 69 elif any(.[]; .type=="Ready") then 67 else 68 end end end; (reduce inputs as $n (4; try ($n|classify) catch 5)) as $s|if $s==0 then true else ""|halt_error($s) end\' "$out" > /dev/null\n  then\n')]


def receiver_before_live_envelope(source):
    """Restore exact old V12 census/cache/comments; never execute recovered DATA."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != LIVE_ENVELOPE_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != LIVE_ENVELOPE_SOURCE):
        raise AssertionError('live-envelope-current-source')
    for previous, current in reversed(LIVE_ENVELOPE_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('live-envelope-exact-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != LIVE_ENVELOPE_PREDECESSOR_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != LIVE_ENVELOPE_PREDECESSOR):
        raise AssertionError('live-envelope-predecessor')
    return source


# ADR0097 operational-current hash and distinct strict frozen ADR0094 owner.
STORAGE_CAPTURE_SOURCE = '0a512e1f5d2a9463e17fd5d10319b4a989129eb1149a5c4f4fbfc84b688424ad'
STORAGE_CAPTURE_SOURCE_BYTES = 65397
FROZEN_MODERN_LOGGING_SOURCE = '35035fe7b0e2d981fff0a0bd44a2de57b97cb11040bef4371297d338eb6516b6'
FROZEN_MODERN_LOGGING_SOURCE_BYTES = 65361
STORAGE_CAPTURE_RULE = '        [[ $profile != modern-1.37.0 ]] || maximum=8192\n'
STORAGE_CAPTURE_COMMENT_BEFORE = '# jq variables use --arg; keep shell expansion out.'
STORAGE_CAPTURE_COMMENT_CURRENT = '# jq variables use --arg, not shell expansion.'


def receiver_before_storage_capture(source):
    """Strict current storage-policy inverse to the one frozen logging source."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != STORAGE_CAPTURE_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != STORAGE_CAPTURE_SOURCE):
        raise AssertionError('storage-capture-current-source')
    if (source.count(STORAGE_CAPTURE_RULE) != 1
            or source.count(STORAGE_CAPTURE_COMMENT_CURRENT) != 4
            or STORAGE_CAPTURE_COMMENT_BEFORE in source):
        raise AssertionError('storage-capture-exact-rule-comments')
    source = source.replace(STORAGE_CAPTURE_RULE, '', 1)
    source = source.replace(STORAGE_CAPTURE_COMMENT_CURRENT, STORAGE_CAPTURE_COMMENT_BEFORE)
    if (len(source.encode()) != FROZEN_MODERN_LOGGING_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != FROZEN_MODERN_LOGGING_SOURCE):
        raise AssertionError('storage-capture-frozen-logging-source')
    return source


# Existing operational-current assertions advance; historical inverse domains do not.
MODERN_LOGGING_SOURCE = LIVE_ENVELOPE_SOURCE
MODERN_LOGGING_SOURCE_BYTES = LIVE_ENVELOPE_SOURCE_BYTES
FROZEN_COMPACT_ROOT_SOURCE = '491078357a3951a1c957f2bddec3453e0c65bd3bdf96d37c51110e5029ede576'
FROZEN_COMPACT_ROOT_SOURCE_BYTES = 65388
MODERN_LOGGING_GUARD = '  if [[ $profile == modern-1.37.0 && $action == init ]]; then\n    args[7]=--v=0\n  fi\n'
MODERN_LOGGING_COMMENT_BEFORE = '# jq variables are supplied by --arg; shell expansion would alter this program.'
MODERN_LOGGING_COMMENT_CURRENT = '# jq variables use --arg; keep shell expansion out.'


def receiver_before_modern_logging(source):
    """Strict new-current to frozen65388 inverse; never accept both source domains."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != FROZEN_MODERN_LOGGING_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != FROZEN_MODERN_LOGGING_SOURCE):
        raise AssertionError('modern-logging-current-source')
    if (source.count(MODERN_LOGGING_GUARD) != 1
            or source.count(MODERN_LOGGING_COMMENT_CURRENT) != 4
            or MODERN_LOGGING_COMMENT_BEFORE in source):
        raise AssertionError('modern-logging-exact-guard-comments')
    source = source.replace(MODERN_LOGGING_GUARD, '', 1)
    source = source.replace(MODERN_LOGGING_COMMENT_CURRENT, MODERN_LOGGING_COMMENT_BEFORE)
    if (len(source.encode()) != FROZEN_COMPACT_ROOT_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != FROZEN_COMPACT_ROOT_SOURCE):
        raise AssertionError('modern-logging-frozen65388-source')
    return source


# ADR0088 strict current V10-to-frozen V9 source domain.
I_ATOM_SOURCE = '9cd7ada881b04eef1283cd02dde3989a3a493dfb4a977d7c610d9316694d1d5b'
I_ATOM_SOURCE_BYTES = 65233
I_ATOM_SOURCE_DELTA = [("rootful_admitted=0\nrecord_guard_fuel=0\ndeclare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null postlog_reason=null k_site=''\nexec 3>&2 2> /dev/null\nfail() {\n", "rootful_admitted=0\nrecord_guard_fuel=0\ndeclare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null postlog_reason=null k_site='' i_admitted=0 i_return=null i_round=0\nexec 3>&2 2> /dev/null\nfail() {\n"), ('    if [[ $postlog_site == k ]]; then\n      case $k_site in [a-n]) printf -v postlog_reason \'"k1.%s"\' "$k_site" ;; esac\n    fi\n    if [[ $postlog_site == n || $postlog_site == k && $k_site == [acehjm] ]]; then\n', '    if [[ $postlog_site == k ]]; then\n      case $k_site in [a-n]) printf -v postlog_reason \'"k1.%s"\' "$k_site" ;; esac\n      if [[ $k_site == i && $i_round == [12] ]]; then\n        local +x atom=\'\'\n        case $i_admitted:$i_return in\n          0:null) atom=p ;;\n          1:64) atom=c ;;\n          1:65) atom=n ;;\n          1:66) atom=v ;;\n          1:67) atom=r ;;\n          1:*)\n            if [[ $i_return =~ ^[1-9][0-9]{0,2}$ ]] && ((i_return <= 255)); then atom=e.$i_return; fi\n            ;;\n        esac\n        [[ -z $atom ]] || printf -v postlog_reason \'"k2.i.%s.%s"\' "$i_round" "$atom"\n      fi\n    fi\n    if [[ $postlog_site == n || $postlog_site == k && $k_site == [acehjm] ]]; then\n'), ('    exec "$@"\n  fi\n  "$@"\n}\n', '    exec "$@"\n  fi\n  if [[ $BASH_SUBSHELL == 0 && ${rootful_admitted:-0} == 1 && ${rootful_intent:-} == execution-v1 && ${mode:-} == work && $postlog_site == k && $k_site == i && $1 == /usr/bin/jq ]]; then i_admitted=1; fi\n  "$@"\n}\n'), ('    logs_exec_failure "$?"\n  fi\n  # Failed exec must return even when this shell originally enabled errexit.\n  # Both returns below poison and exit; successful exec never returns.\n  set +e || logs_exec_failure\n  if exec /usr/bin/podman --remote=false logs -f "$node"; then\n', '    logs_exec_failure "$?"\n  fi\n  set +e || logs_exec_failure\n  if exec /usr/bin/podman --remote=false logs -f "$node"; then\n'), ('}\n\n# Persistent work/cleanup capture partitions leave4KiB for <=150 one-byte\n# sentinels, all inside the irreversibly reserved original1MiB allowance.\nnative() {\n  local maximum=$1 error_max=$2 domain=$mode max=70 action i slots rc helper_error=0 stdout_pid stderr_pid\n', '}\n\nnative() {\n  local maximum=$1 error_max=$2 domain=$mode max=70 action i slots rc helper_error=0 stdout_pid stderr_pid\n'), ('  exec {stderr_fd}> >(capture_stream "$error_max" "$err" "$stderr_dd" "$stderr_stat")\n  stderr_pid=$!\n  # Close inherited writers; collector waits require genuine source EOF.\n  if (\n    exec 1>&$stdout_fd 2>&$stderr_fd\n', '  exec {stderr_fd}> >(capture_stream "$error_max" "$err" "$stderr_dd" "$stderr_stat")\n  stderr_pid=$!\n  if (\n    exec 1>&$stdout_fd 2>&$stderr_fd\n'), ('  u /usr/bin/jq -e --arg root "$root" \'.host.security.rootless == false and .host.serviceIsRemote == false and .host.cgroupVersion == "v2" and .host.os == "linux" and .host.arch == "amd64" and .version.Version == "5.8.7" and .host.networkBackend == "netavark" and .host.cgroupManager == "cgroupfs" and .store.graphDriverName == "overlay" and .store.graphRoot == ($root+"/storage") and .store.runRoot == "/run/kubernetes-lens-rootful/storage" and .store.graphStatus["Backing Filesystem"] == "xfs"\' "$1" > /dev/null || fail podman-profile\n}\n# Builtin, fail-closed census.\ninventory() {\n  local process pid tid task record tail hard _soft a b c rest fd count=0\n', '  u /usr/bin/jq -e --arg root "$root" \'.host.security.rootless == false and .host.serviceIsRemote == false and .host.cgroupVersion == "v2" and .host.os == "linux" and .host.arch == "amd64" and .version.Version == "5.8.7" and .host.networkBackend == "netavark" and .host.cgroupManager == "cgroupfs" and .store.graphDriverName == "overlay" and .store.graphRoot == ($root+"/storage") and .store.runRoot == "/run/kubernetes-lens-rootful/storage" and .store.graphStatus["Backing Filesystem"] == "xfs"\' "$1" > /dev/null || fail podman-profile\n}\ninventory() {\n  local process pid tid task record tail hard _soft a b c rest fd count=0\n'), ("  ((count > 0)) || fail inv-empty\n}\n# Bounded raw input goes to one fixed exclusively created file. Bash's read\n# removes NUL; exact cmp against canonical bytes therefore remains mandatory.\nreceive_packet() {\n  [[ ! -e $root/state/request.in && ! -L $root/state/request.in && ! -e $root/state/request.extra && ! -L $root/state/request.extra ]] || fail\n", '  ((count > 0)) || fail inv-empty\n}\nreceive_packet() {\n  [[ ! -e $root/state/request.in && ! -L $root/state/request.in && ! -e $root/state/request.extra && ! -L $root/state/request.extra ]] || fail\n'), ('  done < /proc/self/status\n  ((proc_ok == 1)) || fail namespace\n  # Fresh official boot + authenticated constructor supply initial namespace\n  # authority; these live namespace/proc observations do not replace it.\n  proc_ok=0\n  while read -r a b c d e rest; do\n', '  done < /proc/self/status\n  ((proc_ok == 1)) || fail namespace\n  proc_ok=0\n  while read -r a b c d e rest; do\n'), ('}\nnetwork_routes() {\n  # Network-name ownership and routes do not prove the chosen Linux bridge is\n  # absent. Refuse a live or dangling link, even when it has no IPv4 route.\n  [[ ! -e /sys/class/net/klbr0 && ! -L /sys/class/net/klbr0 && -f /proc/net/route && -r /proc/net/route ]] || fail\n  local name destination _gateway _flags _ref _use _metric mask rest d m p pm\n', '}\nnetwork_routes() {\n  [[ ! -e /sys/class/net/klbr0 && ! -L /sys/class/net/klbr0 && -f /proc/net/route && -r /proc/net/route ]] || fail\n  local name destination _gateway _flags _ref _use _metric mask rest d m p pm\n'), ('  unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy CONTAINER_HOST CONTAINER_CONNECTION DOCKER_HOST SSH_AUTH_SOCK CONTAINERS_CONF_OVERRIDE STORAGE_DRIVER STORAGE_OPTS KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER KIND_EXPERIMENTAL_DOCKER_NETWORK\n}\n# Compare argv arrays, never their joined shell representation.\nexact() {\n  local i=0 part\n', '  unset HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy NO_PROXY no_proxy CONTAINER_HOST CONTAINER_CONNECTION DOCKER_HOST SSH_AUTH_SOCK CONTAINERS_CONF_OVERRIDE STORAGE_DRIVER STORAGE_OPTS KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER KIND_EXPERIMENTAL_DOCKER_NETWORK\n}\nexact() {\n  local i=0 part\n'), ('        ;;\n      image)\n        # jq variables are supplied by --arg; shell expansion would alter this program.\n        # shellcheck disable=SC2016\n        u /usr/bin/jq -e --arg id "$image_id" \'length==1 and .[0].Id==$id\' "$out" > /dev/null || fail\n', '        ;;\n      image)\n        # shellcheck disable=SC2016\n        u /usr/bin/jq -e --arg id "$image_id" \'length==1 and .[0].Id==$id\' "$out" > /dev/null || fail\n'), ('      ;;\n  esac\n  # Fixed private role; no caller path or application logs.\n  if [[ $# == 1 && $1 == node-init-stdout-prefix ]]; then\n    [[ ${prefix_claimed:-0} == 0 ]] || return 0\n', '      ;;\n  esac\n  if [[ $# == 1 && $1 == node-init-stdout-prefix ]]; then\n    [[ ${prefix_claimed:-0} == 0 ]] || return 0\n'), ('  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v9","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n', '  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v10","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n'), ('    continue\n  }\n  k_site=i\n  if\n    # jq variables are supplied by --arg; shell expansion would alter this program.\n    # shellcheck disable=SC2016\n    u /usr/bin/jq -e --arg node "$node" --arg patch "v$patch" \'.items|length==1 and .[0].metadata.name==$node and .[0].status.nodeInfo.kubeletVersion==$patch and any(.[0].status.conditions[]; .type=="Ready" and .status=="True")\' "$out" > /dev/null\n  then\n    ready=1\n    break\n  fi\ndone\n', '    continue\n  }\n  k_site=i i_admitted=0 i_return=null i_round=$_round\n  if\n    # jq variables are supplied by --arg; shell expansion would alter this program.\n    # shellcheck disable=SC2016\n    u /usr/bin/jq -en --arg node "$node" --arg patch "v$patch" \'def classify: .items|if length!=1 then 64 elif .[0].metadata.name!=$node then 65 elif .[0].status.nodeInfo.kubeletVersion!=$patch then 66 elif (any(.[0].status.conditions[]; .type=="Ready" and .status=="True")|not) then 67 else 0 end; (reduce inputs as $n (4; try ($n|classify) catch 5)) as $s|if $s==0 then true else ""|halt_error($s) end\' "$out" > /dev/null\n  then\n    ready=1\n    break\n  else\n    i_return=$?\n  fi\ndone\n')]

def receiver_before_i_atoms(source):
    """Strict V10-to-frozen V9 inverse; never normalize unknown source."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != I_ATOM_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != I_ATOM_SOURCE):
        raise AssertionError('i-atom-current-source')
    for previous, current in reversed(I_ATOM_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('i-atom-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != 65331 or hashlib.sha256(source.encode()).hexdigest() !=
            '7fb07aa0ffbf0f62968a6355ad02bccd6034e9496d424820806064329694c2d4'):
        raise AssertionError('i-atom-frozen-v9-source')
    return source
# ADR0088 seam end.

# ADR0090 strict current V11-to-frozen V10 source domain.
READY_REASON_SOURCE = 'b13c5b4b3f2782296c7764fb20475ac387bae803bde4075c7f3e1a137bec2283'
READY_REASON_SOURCE_BYTES = 65369
READY_REASON_SOURCE_DELTA = [('          1:67) atom=r ;;\n          1:*)\n            if [[ $i_return =~ ^[1-9][0-9]{0,2}$ ]] && ((i_return <= 255)); then atom=e.$i_return; fi\n            ;;\n        esac\n        [[ -z $atom ]] || printf -v postlog_reason \'"k2.i.%s.%s"\' "$i_round" "$atom"\n      fi\n    fi\n', '          1:67) atom=r ;;\n          1:*)\n            if [[ $i_return =~ ^[1-9][0-9]{0,2}$ ]] && ((i_return <= 255)); then atom=x.$i_return; fi\n            ;;\n        esac\n        [[ -z $atom ]] || printf -v postlog_reason \'"k3.i.%s.%s"\' "$i_round" "$atom"\n      fi\n    fi\n'), ('  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v10","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n', '  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v11","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n'), ('    # jq variables are supplied by --arg; shell expansion would alter this program.\n    # shellcheck disable=SC2016\n    u /usr/bin/jq -en --arg node "$node" --arg patch "v$patch" \'def classify: .items|if length!=1 then 64 elif .[0].metadata.name!=$node then 65 elif .[0].status.nodeInfo.kubeletVersion!=$patch then 66 elif (any(.[0].status.conditions[]; .type=="Ready" and .status=="True")|not) then 67 else 0 end; (reduce inputs as $n (4; try ($n|classify) catch 5)) as $s|if $s==0 then true else ""|halt_error($s) end\' "$out" > /dev/null\n  then\n    ready=1\n', '    # jq variables are supplied by --arg; shell expansion would alter this program.\n    # shellcheck disable=SC2016\n    u /usr/bin/jq -en --arg node "$node" --arg patch "v$patch" \'def classify: .items|if length!=1 then 64 else .[0]|if .metadata.name!=$node then 65 elif .status.nodeInfo.kubeletVersion!=$patch then 66 else .status.conditions|if any(.[]; .type=="Ready" and .status=="True") then 0 elif any(.[]; .type=="Ready" and (.message|strings|contains("NetworkPluginNotReady"))) then 69 elif any(.[]; .type=="Ready") then 67 else 68 end end end; (reduce inputs as $n (4; try ($n|classify) catch 5)) as $s|if $s==0 then true else ""|halt_error($s) end\' "$out" > /dev/null\n  then\n    ready=1\n')]

def receiver_before_ready_reason(source):
    """Strict V11-to-V10 inverse; reject unknown source rather than normalize it."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != READY_REASON_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != READY_REASON_SOURCE):
        raise AssertionError('ready-reason-current-source')
    for previous, current in reversed(READY_REASON_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('ready-reason-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != 65233 or hashlib.sha256(source.encode()).hexdigest() !=
            '9cd7ada881b04eef1283cd02dde3989a3a493dfb4a977d7c610d9316694d1d5b'):
        raise AssertionError('ready-reason-frozen-v10-source')
    return source
# ADR0090 seam end.

# ADR0091 exact current V12-to-frozen V11 source domain.
NODE_WAIT_SOURCE = 'e5d4870bc9d3994f9c73d54cbeeb5abe322c9511a973f3f1d8870dd05b16a0b5'
NODE_WAIT_SOURCE_BYTES = 65408
NODE_WAIT_SOURCE_DELTA = [("readonly credits=$root/state/credits captures=$root/captures\nreadonly fd_max=1073741816 pid_max=32768\nreadonly hard_nofile_max=9999999999\ninitial_prerequisite=0\nrootful_admitted=0\nrecord_guard_fuel=0\ndeclare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null postlog_reason=null k_site='' i_admitted=0 i_return=null i_round=0\n", "readonly credits=$root/state/credits captures=$root/captures\nreadonly fd_max=1073741816 pid_max=32768\nreadonly hard_nofile_max=9999999999\nprerequisite_mode=0\nrootful_admitted=0\nrecord_guard_fuel=0\ndeclare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null postlog_reason=null k_site='' i_admitted=0 i_return=null i_round=0\n"), ('      esac\n    fi\n    if [[ $postlog_site == k ]]; then\n      case $k_site in [a-n]) printf -v postlog_reason \'"k1.%s"\' "$k_site" ;; esac\n      if [[ $k_site == i && $i_round == [12] ]]; then\n        local +x atom=\'\'\n        case $i_admitted:$i_return in\n', '      esac\n    fi\n    if [[ $postlog_site == k ]]; then\n      case $k_site in [a-o]) printf -v postlog_reason \'"k4.%s"\' "$k_site" ;; esac\n      if [[ $k_site == i && $i_round == [12] ]]; then\n        local +x atom=\'\'\n        case $i_admitted:$i_return in\n'), ('            if [[ $i_return =~ ^[1-9][0-9]{0,2}$ ]] && ((i_return <= 255)); then atom=x.$i_return; fi\n            ;;\n        esac\n        [[ -z $atom ]] || printf -v postlog_reason \'"k3.i.%s.%s"\' "$i_round" "$atom"\n      fi\n    fi\n    if [[ $postlog_site == n || $postlog_site == k && $k_site == [acehjm] ]]; then\n      printf -v postlog_native \'{"return_status":%s,"command_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s}\' "$postlog_rc" "$postlog_tool" "$postlog_out" "$postlog_err"\n    fi\n  fi\n', '            if [[ $i_return =~ ^[1-9][0-9]{0,2}$ ]] && ((i_return <= 255)); then atom=x.$i_return; fi\n            ;;\n        esac\n        [[ -z $atom ]] || printf -v postlog_reason \'"k4.i.%s.%s"\' "$i_round" "$atom"\n      fi\n    fi\n    if [[ $postlog_site == n || $postlog_site == k && $k_site == [acehjmo] ]]; then\n      printf -v postlog_native \'{"return_status":%s,"command_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s}\' "$postlog_rc" "$postlog_tool" "$postlog_out" "$postlog_err"\n    fi\n  fi\n'), ('  esac\n  if [[ ${rootful_admitted:-0} == 1 && -d $root/state && ${mode:-work} != cleanup ]]; then printf \'%s\\n\' poisoned > "$root/state/poison" || true; fi\n  printf \'%s\\n\' rootful-receiver-refused >&3\n  if [[ ${initial_prerequisite:-0} == 1 && ${mode:-work} != cleanup && $# == 1 ]]; then\n    case $1 in\n      entry | source | paths | packages | exec-closure | eof | fresh-state | pid-limits | pid-max | nr-open-form | nr-open-range | namespace | mount | mount-both | mount-proc | mount-root | memory | block | mapper | filesystem | inventory | inv-pid-range | inv-proc-task | inv-proc-read | inv-proc-pid | inv-proc-form | inv-task-empty | inv-tid-count | inv-task-read | inv-task-tid | inv-task-form | inv-nf-form | inv-nf-range | inv-fd-access | inv-fd-form | inv-fd-range | inv-snap-size | inv-empty | inv-drift | podman-info | podman-profile | pkg-jq-ver | pkg-sd-ver | pkg-sd-query | pkg-kernel | rpm-shape | rpm-bash | rpm-jq | rpm-coreutils | rpm-systemd | rpm-podman | rpm-skopeo | rpm-crun | rpm-conmon | rpm-netavark | rpm-aardvark | rpm-util-linux | rpm-libcap | pkg-sd-q[123456789] | pkg-sd-q[123456789][0123456789] | pkg-sd-q1[0123456789][0123456789] | pkg-sd-q2[01234][0123456789] | pkg-sd-q25[012345])\n        printf \'rootful-prerequisite-code-v1:%s\\n\' "$1" >&3\n', '  esac\n  if [[ ${rootful_admitted:-0} == 1 && -d $root/state && ${mode:-work} != cleanup ]]; then printf \'%s\\n\' poisoned > "$root/state/poison" || true; fi\n  printf \'%s\\n\' rootful-receiver-refused >&3\n  if [[ ${prerequisite_mode:-0} == 1 && ${mode:-work} != cleanup && $# == 1 ]]; then\n    case $1 in\n      entry | source | paths | packages | exec-closure | eof | fresh-state | pid-limits | pid-max | nr-open-form | nr-open-range | namespace | mount | mount-both | mount-proc | mount-root | memory | block | mapper | filesystem | inventory | inv-pid-range | inv-proc-task | inv-proc-read | inv-proc-pid | inv-proc-form | inv-task-empty | inv-tid-count | inv-task-read | inv-task-tid | inv-task-form | inv-nf-form | inv-nf-range | inv-fd-access | inv-fd-form | inv-fd-range | inv-snap-size | inv-empty | inv-drift | podman-info | podman-profile | pkg-jq-ver | pkg-sd-ver | pkg-sd-query | pkg-kernel | rpm-shape | rpm-bash | rpm-jq | rpm-coreutils | rpm-systemd | rpm-podman | rpm-skopeo | rpm-crun | rpm-conmon | rpm-netavark | rpm-aardvark | rpm-util-linux | rpm-libcap | pkg-sd-q[123456789] | pkg-sd-q[123456789][0123456789] | pkg-sd-q1[0123456789][0123456789] | pkg-sd-q2[01234][0123456789] | pkg-sd-q25[012345])\n        printf \'rootful-prerequisite-code-v1:%s\\n\' "$1" >&3\n'), ('  exit 1\n}\npackage_tuple_failure() {\n  [[ ${initial_prerequisite:-0} == 1 && ${mode:-work} != cleanup ]] || fail packages\n  local remaining row i rows=0 first=13\n  ((${#packages} <= 4096)) || fail rpm-shape\n  remaining=$packages\n', '  exit 1\n}\npackage_tuple_failure() {\n  [[ ${prerequisite_mode:-0} == 1 && ${mode:-work} != cleanup ]] || fail packages\n  local remaining row i rows=0 first=13\n  ((${#packages} <= 4096)) || fail rpm-shape\n  remaining=$packages\n'), ('  take sentinel 150 || fail\n  take sentinel 150 || fail\n  out=$captures/$action.out err=$captures/$action.err\n  last_tool_status=-1 last_stdout_capture_status=-1 last_stderr_capture_status=-1\n  [[ ! -e $out && ! -L $out && ! -e $err && ! -L $err ]] || fail\n  grant_utility || fail\n  stdout_dd=$utility_ticket\n', '  take sentinel 150 || fail\n  take sentinel 150 || fail\n  out=$captures/$action.out err=$captures/$action.err\n  tool_status=-1 stdout_status=-1 stderr_status=-1\n  [[ ! -e $out && ! -L $out && ! -e $err && ! -L $err ]] || fail\n  grant_utility || fail\n  stdout_dd=$utility_ticket\n'), ('    exec {stdout_fd}>&- {stderr_fd}>&- 3>&-\n    "$@"\n  ); then rc=0; else rc=$?; fi\n  last_tool_status=$rc\n  [[ $postlog_site != [nk] ]] || postlog_tool=$last_tool_status\n  printf \'%s\\n\' "$rc" > "$captures/$action.status"\n  exec {stdout_fd}>&- {stderr_fd}>&-\n  if wait "$stdout_pid"; then last_stdout_capture_status=0; else\n    last_stdout_capture_status=$?\n    helper_error=1\n  fi\n  [[ $postlog_site != [nk] ]] || postlog_out=$last_stdout_capture_status\n  if wait "$stderr_pid"; then last_stderr_capture_status=0; else\n    last_stderr_capture_status=$?\n    helper_error=1\n  fi\n  [[ $postlog_site != [nk] ]] || postlog_err=$last_stderr_capture_status\n  if ((helper_error)); then\n    [[ $domain == cleanup ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n    return 125\n', '    exec {stdout_fd}>&- {stderr_fd}>&- 3>&-\n    "$@"\n  ); then rc=0; else rc=$?; fi\n  tool_status=$rc\n  [[ $postlog_site != [nk] ]] || postlog_tool=$tool_status\n  printf \'%s\\n\' "$rc" > "$captures/$action.status"\n  exec {stdout_fd}>&- {stderr_fd}>&-\n  if wait "$stdout_pid"; then stdout_status=0; else\n    stdout_status=$?\n    helper_error=1\n  fi\n  [[ $postlog_site != [nk] ]] || postlog_out=$stdout_status\n  if wait "$stderr_pid"; then stderr_status=0; else\n    stderr_status=$?\n    helper_error=1\n  fi\n  [[ $postlog_site != [nk] ]] || postlog_err=$stderr_status\n  if ((helper_error)); then\n    [[ $domain == cleanup ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n    return 125\n'), ('esac\n# Initial prerequisite diagnostic selection; admission checks remain unchanged.\nif [[ $# == 1 && ${1:-} == prerequisite-v1 && ! -e $root/state/phase && ! -L $root/state/phase && ! -e $root/state/mode && ! -L $root/state/mode ]]; then\n  initial_prerequisite=1\nfi\n[[ $EUID == 0 && $BASH_VERSION == 5.3.9* ]] || fail entry\nread -r boot < /proc/sys/kernel/random/boot_id\n', 'esac\n# Initial prerequisite diagnostic selection; admission checks remain unchanged.\nif [[ $# == 1 && ${1:-} == prerequisite-v1 && ! -e $root/state/phase && ! -L $root/state/phase && ! -e $root/state/mode && ! -L $root/state/mode ]]; then\n  prerequisite_mode=1\nfi\n[[ $EUID == 0 && $BASH_VERSION == 5.3.9* ]] || fail entry\nread -r boot < /proc/sys/kernel/random/boot_id\n'), ('fi\n[[ $mode == work || $mode == cleanup ]] || fail source\nu /usr/bin/sha256sum --check --status "$root/checks.sha256" || fail source\nvalues=$(u /usr/bin/jq -er \'[.owner,.plan_sha256,.profile,.config_sha256,.manifest_sha256,.fixture_sha256,.kind_sha256,.kubectl_sha256,.archive_sha256,.server_patch,.kind_version,.expanded_image_bytes,.archive_bytes,.stage_payload_bytes]|.[]\' "$root/spec.json") || fail\nmapfile -t fields <<< "$values"\n[[ ${#fields[@]} == 14 && ${fields[0]} == "$owner" && ${fields[1]} == "$plan" ]] || fail source\nprofile=${fields[2]}\n', 'fi\n[[ $mode == work || $mode == cleanup ]] || fail source\nu /usr/bin/sha256sum --check --status "$root/checks.sha256" || fail source\nvalues=$(u /usr/bin/jq -er \'select(.schema=="kubernetes-lens-owned-rootful-v12")|[.owner,.plan_sha256,.profile,.config_sha256,.manifest_sha256,.fixture_sha256,.kind_sha256,.kubectl_sha256,.archive_sha256,.server_patch,.kind_version,.expanded_image_bytes,.archive_bytes,.stage_payload_bytes]|.[]\' "$root/spec.json") || fail\nmapfile -t fields <<< "$values"\n[[ ${#fields[@]} == 14 && ${fields[0]} == "$owner" && ${fields[1]} == "$plan" ]] || fail source\nprofile=${fields[2]}\n'), ('readonly cluster=kl-$owner node=kl-$owner-control-plane alias=localhost/kubernetes-lens-node:$owner\nprivate_environment\nif [[ ${1:-} == provider ]]; then\n  initial_prerequisite=0\n  shift\n  provider "$@"\n  exit $?\n', 'readonly cluster=kl-$owner node=kl-$owner-control-plane alias=localhost/kubernetes-lens-node:$owner\nprivate_environment\nif [[ ${1:-} == provider ]]; then\n  prerequisite_mode=0\n  shift\n  provider "$@"\n  exit $?\n'), ('  u /usr/bin/cat "$out" || fail\n  exit 0\nfi\ninitial_prerequisite=0\nread_file "$root/state/phase"\n[[ $REPLY == "$owner $plan $boot staged-required" ]] || fail\nread_file "$stage/state"\n', '  u /usr/bin/cat "$out" || fail\n  exit 0\nfi\nprerequisite_mode=0\nread_file "$root/state/phase"\n[[ $REPLY == "$owner $plan $boot staged-required" ]] || fail\nread_file "$stage/state"\n'), ('  if ((created)); then\n    mode=cleanup\n    printf \'%s\\n\' cleanup > "$root/state/mode"\n    if native 4096 4096 "$stage/kind" delete cluster --name "$cluster"; then delete_status=$last_tool_status; else\n      delete_status=${last_tool_status:--1}\n      status=1\n    fi\n    ((delete_status == 0)) || status=1\n', '  if ((created)); then\n    mode=cleanup\n    printf \'%s\\n\' cleanup > "$root/state/mode"\n    if native 4096 4096 "$stage/kind" delete cluster --name "$cluster"; then delete_status=$tool_status; else\n      delete_status=${tool_status:--1}\n      status=1\n    fi\n    ((delete_status == 0)) || status=1\n'), ('  ((status == 0 && create_status == 0 && delete_status == 0)) && state=\'source-deployment-positive\'\n  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v11","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n  exit "$status"\n', '  ((status == 0 && create_status == 0 && delete_status == 0)) && state=\'source-deployment-positive\'\n  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v12","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n  exit "$status"\n'), ('remember network-inspect "$out"\nprintf \'%s\\n\' \'---\' \'kind: Cluster\' \'apiVersion: kind.x-k8s.io/v1alpha4\' \'networking:\' \'  ipFamily: ipv4\' \'  apiServerAddress: 127.0.0.1\' \'  apiServerPort: 6443\' \'  podSubnet: 10.244.0.0/16\' \'  serviceSubnet: 10.96.0.0/16\' \'nodes:\' \'- role: control-plane\' > "$root/config/kind.yaml"\ncreated=1\nif native 16384 32768 "$stage/kind" create cluster --name "$cluster" --image "$alias" --config "$root/config/kind.yaml" --kubeconfig "$KUBECONFIG" --wait 0s; then create_status=$last_tool_status; else\n  kind_failure_wrapper_status=$? create_status=${last_tool_status:--1} kind_failure_err=${err:-} kind_failure_stdout_status=${last_stdout_capture_status:--1} kind_failure_stderr_status=${last_stderr_capture_status:--1}\n  fail\nfi\nlogs_retirement\n', 'remember network-inspect "$out"\nprintf \'%s\\n\' \'---\' \'kind: Cluster\' \'apiVersion: kind.x-k8s.io/v1alpha4\' \'networking:\' \'  ipFamily: ipv4\' \'  apiServerAddress: 127.0.0.1\' \'  apiServerPort: 6443\' \'  podSubnet: 10.244.0.0/16\' \'  serviceSubnet: 10.96.0.0/16\' \'nodes:\' \'- role: control-plane\' > "$root/config/kind.yaml"\ncreated=1\nif native 16384 32768 "$stage/kind" create cluster --name "$cluster" --image "$alias" --config "$root/config/kind.yaml" --kubeconfig "$KUBECONFIG" --wait 0s; then create_status=$tool_status; else\n  kind_failure_wrapper_status=$? create_status=${tool_status:--1} kind_failure_err=${err:-} kind_failure_stdout_status=${stdout_status:--1} kind_failure_stderr_status=${stderr_status:--1}\n  fail\nfi\nlogs_retirement\n'), ('  read_file "$out"\n  k_site=g\n  [[ $REPLY == ok ]] || continue\n  k_site=h\n  native 16384 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" get nodes -o json || {\n    postlog_rc=$?\n    continue\n  }\n  k_site=i i_admitted=0 i_return=null i_round=$_round\n  if\n', '  read_file "$out"\n  k_site=g\n  [[ $REPLY == ok ]] || continue\n  k_site=o\n  native 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" wait --for=condition=Ready nodes --all --timeout=30s || {\n    postlog_rc=$?\n    fail\n  }\n  k_site=h\n  native 16384 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" get nodes -o json || {\n    postlog_rc=$?\n    fail\n  }\n  k_site=i i_admitted=0 i_return=null i_round=$_round\n  if\n'), ('    break\n  else\n    i_return=$?\n  fi\ndone\n((ready)) || fail\n', '    break\n  else\n    i_return=$?\n    fail\n  fi\ndone\n((ready)) || fail\n')]

def receiver_before_node_wait(source):
    """Recover exact V11 DATA before any historical inverse; never normalize."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != NODE_WAIT_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != NODE_WAIT_SOURCE):
        raise AssertionError('node-wait-current-source')
    for previous, current in reversed(NODE_WAIT_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('node-wait-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != READY_REASON_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != READY_REASON_SOURCE):
        raise AssertionError('node-wait-frozen-v11-source')
    return source
# ADR0091 seam end.

# ADR0093 source-only capture diagnostic -> exact accepted V12 source.
# Compatibility names below continue to mean operational current, not frozen history.
CAPTURE_SIZE_SOURCE = MODERN_LOGGING_SOURCE
CAPTURE_SIZE_SOURCE_BYTES = MODERN_LOGGING_SOURCE_BYTES
FROZEN_CAPTURE_SIZE_SOURCE = '5bc0d84d747686cb27e327589a49c120e2e9276528d77ebad05a9bc65c77256f'
FROZEN_CAPTURE_SIZE_SOURCE_BYTES = 65378
COMPACT_ROOT_PREVIOUS = 'create --dry-run=server -f "$root/deployment.json" -o json || {'
COMPACT_ROOT_CURRENT = 'create --dry-run=server -f "$root/deployment.json" \'-o=jsonpath={@}\' || {'


def receiver_before_compact_root(source):
    """Exact frozen65388-to65378 inverse; no projection of unknown source."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != FROZEN_COMPACT_ROOT_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != FROZEN_COMPACT_ROOT_SOURCE):
        raise AssertionError('compact-root-current-source')
    if source.count(COMPACT_ROOT_CURRENT) != 1 or COMPACT_ROOT_PREVIOUS in source:
        raise AssertionError('compact-root-exact-selector-delta')
    source = source.replace(COMPACT_ROOT_CURRENT, COMPACT_ROOT_PREVIOUS, 1)
    if (len(source.encode()) != FROZEN_CAPTURE_SIZE_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != FROZEN_CAPTURE_SIZE_SOURCE):
        raise AssertionError('compact-root-frozen-capture-size-source')
    return source

CAPTURE_SIZE_SOURCE_DELTA = [('  utility_launch "$dd_ticket" /usr/bin/dd bs=4096 count="$((maximum + 1))B" iflag=fullblock status=none > "$destination" || return 1\n  set +o noclobber\n  size=$(utility_launch "$stat_ticket" /usr/bin/stat -c %s "$destination") || return 1\n  [[ $size =~ ^[0-9]+$ ]] && ((size <= maximum))\n}\nprocess_identity() {\n  local pid=$1 record tail\n', '  utility_launch "$dd_ticket" /usr/bin/dd bs=4096 count="$((maximum + 1))B" iflag=fullblock status=none > "$destination" || return 1\n  set +o noclobber\n  size=$(utility_launch "$stat_ticket" /usr/bin/stat -c %s "$destination") || return 1\n  [[ $size =~ ^[0-9]+$ ]] || return 1\n  if ((size > maximum)); then\n    exit 23\n  fi\n  ((size <= maximum))\n}\nprocess_identity() {\n  local pid=$1 record tail\n'), ('preserve_kind_create_failure() {\n  [[ ${kind_failure_wrapper_status:--1} =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 0\n  ((kind_failure_wrapper_status > 0 && kind_failure_wrapper_status <= 255)) || return 0\n  [[ ${kind_failure_err+x} && ${kind_failure_stdout_status+x} && ${kind_failure_stderr_status+x} ]] || return 1\n  [[ $kind_failure_stdout_status =~ ^(-1|0|[1-9][0-9]{0,2})$ && $kind_failure_stderr_status =~ ^(-1|0|[1-9][0-9]{0,2})$ ]] || return 1\n  ((kind_failure_stdout_status <= 255 && kind_failure_stderr_status <= 255)) || return 1\n  [[ $mode == work && $source_status == not-reached && $kind_failure_err == "$captures"/work.*.err && -f $kind_failure_err && ! -L $kind_failure_err ]] || return 1\n  local size ticket i needed=3 prefix_bytes=0 eof=null truncated=false overflow=false\n  local destination=$root/state/kind-create-stderr-prefix attribution=$root/state/kind-create-attribution\n', 'preserve_kind_create_failure() {\n  [[ ${kind_failure_wrapper_status:--1} =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 0\n  ((kind_failure_wrapper_status > 0 && kind_failure_wrapper_status <= 255)) || return 0\n  [[ ${kind_failure_err+x} && ${kind_stdout_status+x} && ${kind_stderr_status+x} ]] || return 1\n  [[ $kind_stdout_status =~ ^(-1|0|[1-9][0-9]{0,2})$ && $kind_stderr_status =~ ^(-1|0|[1-9][0-9]{0,2})$ ]] || return 1\n  ((kind_stdout_status <= 255 && kind_stderr_status <= 255)) || return 1\n  [[ $mode == work && $source_status == not-reached && $kind_failure_err == "$captures"/work.*.err && -f $kind_failure_err && ! -L $kind_failure_err ]] || return 1\n  local size ticket i needed=3 prefix_bytes=0 eof=null truncated=false overflow=false\n  local destination=$root/state/kind-create-stderr-prefix attribution=$root/state/kind-create-attribution\n'), ('  done\n  ((size <= 4096)) || truncated=true\n  ((size != 32769)) || overflow=true\n  [[ $kind_failure_stderr_status != 0 ]] || eof=true\n  if ((size > 0)); then\n    ticket=${kind_failure_tickets[0]}\n    kind_failure_tickets=("${kind_failure_tickets[@]:1}")\n', '  done\n  ((size <= 4096)) || truncated=true\n  ((size != 32769)) || overflow=true\n  [[ $kind_stderr_status != 0 ]] || eof=true\n  if ((size > 0)); then\n    ticket=${kind_failure_tickets[0]}\n    kind_failure_tickets=("${kind_failure_tickets[@]:1}")\n'), ('  fi\n  (\n    set -o noclobber\n    printf \'{"schema":"kind-create-failure-attribution-v1","kind_child_wait_status":%s,"native_wrapper_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s,"stderr_captured_bytes":%s,"stderr_prefix_bytes":%s,"stderr_source_eof":%s,"stderr_overflow_sentinel":%s,"stderr_prefix_truncated":%s,"provider_child_wait_status":null,"provider_wrapper_status":null}\\n\' "$create_status" "$kind_failure_wrapper_status" "$kind_failure_stdout_status" "$kind_failure_stderr_status" "$size" "$prefix_bytes" "$eof" "$overflow" "$truncated" > "$attribution"\n  ) || return 1\n  ((size == 0)) || printf \'%s\\n\' "$destination" > "$root/state/evidence.kind-create-stderr-prefix"\n  printf \'%s\\n\' "$attribution" > "$root/state/evidence.kind-create-attribution"\n', '  fi\n  (\n    set -o noclobber\n    printf \'{"schema":"kind-create-failure-attribution-v1","kind_child_wait_status":%s,"native_wrapper_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s,"stderr_captured_bytes":%s,"stderr_prefix_bytes":%s,"stderr_source_eof":%s,"stderr_overflow_sentinel":%s,"stderr_prefix_truncated":%s,"provider_child_wait_status":null,"provider_wrapper_status":null}\\n\' "$create_status" "$kind_failure_wrapper_status" "$kind_stdout_status" "$kind_stderr_status" "$size" "$prefix_bytes" "$eof" "$overflow" "$truncated" > "$attribution"\n  ) || return 1\n  ((size == 0)) || printf \'%s\\n\' "$destination" > "$root/state/evidence.kind-create-stderr-prefix"\n  printf \'%s\\n\' "$attribution" > "$root/state/evidence.kind-create-attribution"\n'), ('printf \'%s\\n\' \'---\' \'kind: Cluster\' \'apiVersion: kind.x-k8s.io/v1alpha4\' \'networking:\' \'  ipFamily: ipv4\' \'  apiServerAddress: 127.0.0.1\' \'  apiServerPort: 6443\' \'  podSubnet: 10.244.0.0/16\' \'  serviceSubnet: 10.96.0.0/16\' \'nodes:\' \'- role: control-plane\' > "$root/config/kind.yaml"\ncreated=1\nif native 16384 32768 "$stage/kind" create cluster --name "$cluster" --image "$alias" --config "$root/config/kind.yaml" --kubeconfig "$KUBECONFIG" --wait 0s; then create_status=$tool_status; else\n  kind_failure_wrapper_status=$? create_status=${tool_status:--1} kind_failure_err=${err:-} kind_failure_stdout_status=${stdout_status:--1} kind_failure_stderr_status=${stderr_status:--1}\n  fail\nfi\nlogs_retirement\n', 'printf \'%s\\n\' \'---\' \'kind: Cluster\' \'apiVersion: kind.x-k8s.io/v1alpha4\' \'networking:\' \'  ipFamily: ipv4\' \'  apiServerAddress: 127.0.0.1\' \'  apiServerPort: 6443\' \'  podSubnet: 10.244.0.0/16\' \'  serviceSubnet: 10.96.0.0/16\' \'nodes:\' \'- role: control-plane\' > "$root/config/kind.yaml"\ncreated=1\nif native 16384 32768 "$stage/kind" create cluster --name "$cluster" --image "$alias" --config "$root/config/kind.yaml" --kubeconfig "$KUBECONFIG" --wait 0s; then create_status=$tool_status; else\n  kind_failure_wrapper_status=$? create_status=${tool_status:--1} kind_failure_err=${err:-} kind_stdout_status=${stdout_status:--1} kind_stderr_status=${stderr_status:--1}\n  fail\nfi\nlogs_retirement\n')]

def receiver_before_capture_size(source):
    """Recover exact accepted V12 source before unchanged historical inverses."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != CAPTURE_SIZE_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != CAPTURE_SIZE_SOURCE):
        raise AssertionError('capture-size-current-source')
    source = receiver_before_storage_capture(receiver_before_live_envelope(source))
    source = receiver_before_modern_logging(source)
    source = receiver_before_compact_root(source)
    for previous, current in reversed(CAPTURE_SIZE_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('capture-size-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != NODE_WAIT_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != NODE_WAIT_SOURCE):
        raise AssertionError('capture-size-frozen-v12-source')
    return source
# ADR0093 seam end.

class RootfulHostControls(unittest.TestCase):
    def budget(self, *, commands=128, output=vm.OUTPUT_MAX):
        return vm.Budget(time.monotonic() + 1800, 120, commands=commands, output=output)

    def test_one_actual_worker_budget_irrevocably_reserves75_and1mib(self):
        budget = self.budget()
        original = budget.end, budget.work_end
        self.assertEqual(rootful.reserve(budget), {'native': 75, 'output': 1048576, 'utilities': 768, 'utility_work': 680, 'utility_cleanup': 64, 'record_guards_prepaid': 24})
        self.assertEqual((budget.commands_left, budget.output_left), (53, 1048576))
        self.assertEqual((budget.end, budget.work_end), original)
        with self.assertRaisesRegex(vm.Refusal, 'rootful-original-budget-fit'):
            rootful.reserve(budget)
        self.assertEqual((budget.commands_left, budget.output_left), (53, 1048576))

    def test_cannot_start_reservation_without_fixed_eight_host_actions_or_output(self):
        for commands, output in [(82, vm.OUTPUT_MAX), (128, 1048575)]:
            budget = self.budget(commands=commands, output=output)
            with self.assertRaises(vm.Refusal):
                rootful.reserve(budget)
            self.assertEqual((budget.commands_left, budget.output_left), (commands, output))

    def test_real_bounded_stdin_pump_counts_short_writes_and_observes_eof(self):
        import os
        budget=self.budget(); account={'limit':4096,'written':0};original_write=os.write
        with tempfile.TemporaryDirectory(prefix='rootful-stdin-pure-') as directory:
            with patch.object(vm.os,'write',side_effect=lambda fd,data:original_write(fd,data[:2])):
                status,raw=vm.run(['/usr/bin/bash','-c','IFS= read -r line; printf "%s" "$line"'],
                    budget,directory,input_bytes=b'closed-packet\n',input_account=account)
        self.assertEqual(status,0);self.assertEqual(raw,b'closed-packet')
        self.assertEqual(account['written'],len(b'closed-packet\n'))
        self.assertEqual(budget.commands_left,127)

    def test_invalid_or_over4096_input_reservation_refuses_before_child(self):
        for packet,account in [(b'x',None),(b'x'*4097,{'limit':4096,'written':0}),
                               (b'x',{'limit':4096,'written':1})]:
            with patch.object(vm.subprocess,'Popen') as start:
                with self.assertRaises(vm.Refusal):
                    vm.run(['/usr/bin/false'],self.budget(),'/tmp',input_bytes=packet,input_account=account)
                start.assert_not_called()

    def test_resource_profile_has_no_adaptive_values(self):
        args = SimpleNamespace(**rootful.RESOURCE_VALUES)
        rootful.admit_resources(args)
        for key in rootful.RESOURCE_VALUES:
            altered = deepcopy(args)
            setattr(altered, key, getattr(altered, key) + 1)
            with self.assertRaises(vm.Refusal):
                rootful.admit_resources(altered)

    def test_execution_packet_binds_exact_spec_owner_plan_and_original_remaining(self):
        budget, spec = self.budget(), {'selected': 'fixed'}
        with patch.object(vm.time, 'monotonic', return_value=budget.work_end - 11.5):
            packet = rootful.request('a' * 32, 'b' * 64, budget, spec)
        self.assertEqual(packet, f'rootful-kind-v1 {"a"*32} {"b"*64} {vm.digest(vm.encode(spec))} 10\n'.encode())
        self.assertLessEqual(len(packet), 4096)
        with patch.object(vm.time, 'monotonic', return_value=budget.work_end - 1):
            with self.assertRaisesRegex(vm.Refusal, 'rootful-request-original-work-end'):
                rootful.request('a' * 32, 'b' * 64, budget, spec)

    def plan(self):
        raw = vm.encode({'schema': 'kubernetes-lens-owned-guest-stage-plan-v1', 'owner': 'a'*32,
                         'profile': 'legacy-1.20.15', 'files': {
            key: {'path': '/tmp/' + key, 'bytes': 3, 'sha256': 'b'*64} for key in stage.ROLES}})
        return stage.parse_plan(raw, vm.digest(raw))

    def test_guest_files_use_exact_original_source_deployment_and_checksum_every_source(self):
        evidence = {key: 'c'*64 for key in ('manifest_sha256', 'config_sha256', 'parent_sha256')}
        evidence.update(expanded_bytes_hashed=10,archive_bytes=3)
        evidence['catalogue'] = {'blobs/sha256/'+'c'*64: {'bytes': 100}}
        files, spec = rootful.guest_files(self.plan(), evidence, SCRIPT.read_bytes())
        fixture = files[rootful.ROOT + '/deployment.json'][0]
        original = json.loads((vm.ROOT / 'schemas/capabilities/kubernetes-native-scenarios.json').read_text())
        expected = next(s['positive_document'] for s in original['kind_scenarios'] if s['kind'] == 'Deployment')
        self.assertEqual(vm.strict_json(fixture), expected)
        self.assertEqual(spec['fixture_sha256'], vm.digest(fixture))
        self.assertEqual(spec['server_patch'], '1.20.15')
        checks = files[rootful.ROOT + '/checks.sha256'][0].decode()
        for name, (raw, mode) in files.items():
            if name.endswith('/checks.sha256'):
                continue
            self.assertIn(vm.digest(raw) + '  ' + name + '\n', checks)
            self.assertIn(mode, (0o400, 0o500))

    def config(self):
        return {'owner': 'a'*32, 'stage_plan_sha256': 'b'*64,
                'rootful_spec': {'profile': 'legacy-1.20.15', 'server_patch': '1.20.15'}}

    def result(self):
        return {'schema': 'kubernetes-lens-owned-rootful-result-v1', 'owner': 'a'*32,
            'plan_sha256': 'b'*64, 'profile': 'legacy-1.20.15', 'state': 'source-deployment-positive',
            'native_actions': 73, 'utility_actions': 500, 'utility_ledger_actions': 476,
            'record_guards': {'prepaid': 24, 'attempted': 24}, 'output_reserved': 980000,
            'kind_create_status': 0, 'kind_delete_status': 0,
            'source_deployment': 'server-dry-run-observed', 'server_patch': '1.20.15',
            'network_retirement': 'whole-vm-required', 'remaining_cases': 'pending-fresh-runs',
            'logs': {'state': 'direct-wait-zero',
                     'identities': {role: {'pid': i+2, 'start': 100+i}
                                    for i, role in enumerate(sorted(rootful.LOG_ROLES))},
                     'collectors': {role: {'dd_status': 0, 'tee_status': 0, 'bytes': 0,
                                           'source_eof': True} for role in ('out', 'err')},
                     'startup_marker': True, 'wrapper_observed_child_wait_status': 0, 'signal_cause': None}}

    def test_result_keeps_actual_delete_failure_and_never_promotes_it(self):
        value = self.result()
        self.assertEqual(rootful.result(vm.encode(value)+b'\n', self.config()), value)
        value.update(state='failed', kind_delete_status=19)
        with self.assertRaisesRegex(vm.Refusal, 'rootful-success-unproved'):
            rootful.result(vm.encode(value)+b'\n', self.config())
        self.assertEqual(rootful.result(vm.encode(value)+b'\n', self.config(), allow_failure=True)['kind_delete_status'], 19)

    def test_logs_exception_keeps_unobserved_wait_and_signal_null(self):
        value = self.result()
        value['logs'].update(state='retired-wait-and-signal-cause-unavailable', wrapper_observed_child_wait_status=None)
        checked = rootful.result(vm.encode(value)+b'\n', self.config())
        self.assertIsNone(checked['logs']['wrapper_observed_child_wait_status'])
        self.assertIsNone(checked['logs']['signal_cause'])
        for invented in (0, True, 'SIGKILL'):
            altered = deepcopy(value)
            altered['logs']['wrapper_observed_child_wait_status'] = invented
            with self.assertRaises(vm.Refusal):
                rootful.result(vm.encode(altered)+b'\n', self.config())

    def test_logs_failure_retains_partial_observations_without_claiming_retirement(self):
        value = self.result()
        value.update(state='failed', source_deployment='not-reached')
        value['logs'].update(state='not-established', startup_marker=False, wrapper_observed_child_wait_status=7)
        value['logs']['identities']['child'] = None
        value['logs']['collectors']['err'] = None
        checked = rootful.result(vm.encode(value)+b'\n', self.config(), allow_failure=True)
        self.assertEqual(checked['logs']['wrapper_observed_child_wait_status'], 7)
        self.assertIsNone(checked['logs']['identities']['child'])
        value.update(state='source-deployment-positive', source_deployment='server-dry-run-observed')
        with self.assertRaises(vm.Refusal):
            rootful.result(vm.encode(value)+b'\n', self.config())

    def test_logs_receipt_rejects_alias_missing_unknown_role_bool_and_false_eof(self):
        good = self.result()['logs']
        changes = [
            lambda v: v['identities'].__setitem__('child', deepcopy(v['identities']['wrapper'])),
            lambda v: v['identities'].pop('child'),
            lambda v: v['identities'].__setitem__('unexpected', {'pid': 20, 'start': 30}),
            lambda v: v['identities']['child'].__setitem__('pid', True),
            lambda v: v['identities']['child'].__setitem__('pid', 32768),
            lambda v: v['identities']['child'].__setitem__('start', 2**63),
            lambda v: v['collectors']['out'].__setitem__('source_eof', False),
            lambda v: v['collectors']['out'].__setitem__('bytes', 16385),
            lambda v: v['collectors']['err'].__setitem__('tee_status', 7),
            lambda v: v.__setitem__('startup_marker', False),
            lambda v: v.__setitem__('signal_cause', 'SIGKILL'),
            lambda v: v.__setitem__('raw_logs', 'private'),
        ]
        for change in changes:
            value = deepcopy(good)
            change(value)
            with self.subTest(value=value), self.assertRaises(vm.Refusal):
                rootful.logs_evidence(value, complete=True)

    def test_wrong_owner_plan_profile_counter_bool_and_trailing_result_refuse(self):
        for key, bad in [('owner', 'd'*32), ('plan_sha256', 'd'*64), ('profile', 'modern-1.37.0'),
                         ('native_actions', 76), ('native_actions', True), ('utility_actions', 769),
                         ('output_reserved', 1048577), ('network_retirement', 'removed')]:
            value = self.result(); value[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(vm.Refusal):
                rootful.result(vm.encode(value)+b'\n', self.config())
        with self.assertRaises(vm.Refusal):
            rootful.result(vm.encode(self.result())+b'\n\n', self.config())

    def test_fifth_producer_is_explicit_only_and_duplicate_pid_refuses(self):
        def identity(pid):
            return {'pid': pid, 'group': pid, 'session': pid, 'start': pid+1}
        records = [{'phase': p, 'process': identity(i+100)} for i,p in enumerate(rootful.PHASES[:-1])]
        event = {'stage': 'stage-producer-started', 'index': 4, 'phase': 'rootful-kind', 'ssh': identity(104)}
        with patch.object(vm, 'process_identity', return_value=identity(104)), patch.object(vm, 'process_cgroup', return_value='/owned'):
            with self.assertRaises(vm.Refusal):
                vm.admit_producer_event(event, deepcopy(records), identity(99), {'path':'/owned'})
            vm.admit_producer_event(event, records, identity(99), {'path':'/owned'}, rootful=True)
        self.assertEqual([r['phase'] for r in records], list(rootful.PHASES))
        event['index'] = 5
        with self.assertRaises(vm.Refusal):
            vm.admit_producer_event(event, records, identity(99), {'path':'/owned'}, rootful=True)


    def worker_case(self, *, bad_fifth_ack=False, delete_status=0, spec_schema=None):
        from test_owned_qemu import config, identity
        plan = self.plan()
        raw_plan = vm.encode({'schema':'kubernetes-lens-owned-guest-stage-plan-v1',
            'owner':plan.owner,'profile':plan.profile,'files':{f.role:{'path':f.path,'bytes':f.size,'sha256':f.sha256} for f in plan.files}})
        c = config()
        temporary=tempfile.TemporaryDirectory(prefix='rootful-worker-pure-'); self.addCleanup(temporary.cleanup)
        c['directory']=temporary.name
        c.update(phase='run-rootful-kind', start=time.monotonic()-1, end=time.monotonic()+60,
            cleanup_seconds=10, controller=identity(111), stage_plan_sha256=plan.sha256,
            stage_input_limit=sum(f.size+len(p)+1 for f,p in zip(plan.files,stage.PHASES)),
            rootful_reservation=rootful.reservation(),
            rootful_input_reserved=4096,rootful_spec={'profile':plan.profile,'server_patch':'1.20.15'})
        c['work_end']=c['end']-10
        if spec_schema is not None:
            c['rootful_spec']['schema']=spec_schema
        raw=vm.encode(c); target='/sys/fs/cgroup/'+c['unit']
        channel,qemu,selector=Mock(),Mock(),Mock()
        qemu.pid=444; qemu.poll.return_value=None
        selector.select.return_value=[(SimpleNamespace(fd=123,fileobj=qemu.stdout),None)]
        gate={'stage':'go','config_sha256':vm.digest(raw),'invocation':'b'*32,
              'cgroup':{'path':target},'host_view':{},'host_view_sha256':vm.digest(vm.encode({}))}
        pending,sends,budgets,sessions,calls=[],[],[],[],[]
        def sent(_channel,event,_budget,**_kwargs):
            sends.append(event)
            if event['stage']=='stage-producer-started':
                pending.append({**event,'stage':'stage-producer-admitted'})
        def received(*_args,**_kwargs):
            if not pending: return gate
            value=pending.pop(0)
            return {**value,'phase':'wrong'} if bad_fifth_ack and value['index']==4 else value
        def execute(argv,budget,_directory,**kwargs):
            budgets.append(budget); calls.append((argv,kwargs)); budget.commands_left-=1
            if argv[0]!=c['tools']['ssh']['path']:
                return (0,b'{"format":"qcow2","virtual-size":1024}') if argv[1]=='info' else (0,b'')
            if 'input_bytes' in kwargs:
                kwargs['on_start'](Mock(pid=559))
                kwargs['input_account']['written']=len(kwargs['input_bytes'])
                value=self.result(); value['plan_sha256']=plan.sha256
                if delete_status: value.update(state='failed',kind_delete_status=delete_status)
                return (1 if delete_status else 0),vm.encode(value)+b'\n'
            kwargs['on_start'](Mock(pid=555))
            return 0,vm.encode({'host':{'security':{'rootless':False},'serviceIsRemote':False,
                'cgroupVersion':'v2','os':'linux','arch':'amd64'},'version':{'Version':'5.8.7'}})
        def transfer(session,phase,_config,*,extra_streams,on_start,pre_child):
            sessions.append(session); pre_child(); session.budget.commands_left-=1
            on_start(Mock(pid=556+stage.PHASES.index(phase)))
            file=plan.files[session.next_phase]
            value=stage.reply(vm.encode({'schema':'kubernetes-lens-owned-guest-stage-reply-v1',
                'owner':plan.owner,'plan_sha256':plan.sha256,'phase':phase,'role':file.role,
                'bytes':file.size,'sha256':file.sha256,'state':'staged'})+b'\n',plan,phase,file)
            session.charge(file.size+len(phase)+1); session.next_phase+=1
            return value
        with ExitStack() as stack:
            overrides=[(vm,'read',{'side_effect':lambda path,*_:raw_plan if str(path).endswith('stage-plan.json') else raw}),
                (vm,'verify_source',{}),(vm,'worker_pre_child',{}),
                (vm.socket,'socket',{'return_value':channel}),(vm,'peer_identity',{'return_value':c['controller']}),
                (vm,'process_identity',{'side_effect':lambda pid:identity(pid)}),
                (vm,'process_cgroup',{'return_value':target}),(vm,'cgroup_snapshot',{'return_value':{'path':target}}),
                (vm,'send',{'side_effect':sent}),(vm,'receive',{'side_effect':received}),
                (vm,'run',{'side_effect':execute}),(vm.subprocess,'Popen',{'return_value':qemu}),
                (vm.selectors,'DefaultSelector',{'return_value':selector}),(vm.os,'set_blocking',{}),
                (vm.os,'read',{'return_value':b'Reached target Multi-User System\n'}),
                (vm,'reap',{'return_value':True}),(vm,'settle_guest_check',{}),
                (vm,'authenticated_module',{'side_effect':lambda name,*_:rootful if name=='owned_guest_rootful' else stage}),
                (stage,'transfer',{'side_effect':transfer}),
                (rootful,'wire_record',{'side_effect':lambda value,config,**kwargs:rootful.result(value,config,**kwargs)})]
            for obj,name,kwargs in overrides: stack.enter_context(patch.object(obj,name,**kwargs))
            stack.enter_context(patch.dict(vm.os.environ,{'INVOCATION_ID':'b'*32}))
            status=vm.worker('/private/config',vm.digest(raw))
        return status,sends[-1],budgets,sessions,calls,c

    def test_real_worker_path_calls_fifth_producer_same_budget_staging_and_original_ends(self):
        status,stopped,budgets,sessions,calls,c=self.worker_case()
        self.assertEqual(status,0)
        self.assertEqual([p['phase'] for p in stopped['producers']],list(rootful.PHASES))
        self.assertEqual(stopped['producers_reaped'],[True]*5)
        self.assertEqual(stopped['original_end'],c['end'])
        self.assertTrue(all(b is budgets[0] for b in budgets))
        self.assertTrue(all(s is sessions[0] and s.budget is budgets[0] for s in sessions))
        self.assertEqual(budgets[0].commands_left,45) #128-75-8, no refill
        self.assertEqual(budgets[0].output_left,1048576-len(b"Reached target Multi-User System\n"))
        argv,kw=calls[-1]
        self.assertEqual(argv[-1],rootful.EXECUTION_INTENT)
        self.assertNotIn('-n',argv)
        self.assertEqual(stopped['rootful_input_bytes'],len(kw['input_bytes']))
        self.assertEqual(stopped['rootful']['kind_delete_status'],0)

    def test_fifth_ack_failure_cannot_skip_producer_retirement(self):
        status,stopped,*_=self.worker_case(bad_fifth_ack=True)
        self.assertEqual(status,1)
        self.assertEqual(stopped['error'],'stage-producer-acknowledgment')
        self.assertEqual(len(stopped['producers']),5)
        self.assertEqual(stopped['producers_reaped'],[True]*5)
        self.assertIsNone(stopped['rootful'])
        self.assertEqual(stopped['rootful_input_bytes'],0)
        self.assertEqual(stopped['rootful_record_guards'],{'prepaid':24,
            'consumed_purposes':['guest-info','stage-kind','stage-kubectl','stage-node-oci','rootful-kind'],
            'comparisons_attempted':None})

    def test_actual_kind_delete_failure_survives_worker_and_vm_reap(self):
        status,stopped,*_=self.worker_case(delete_status=19)
        self.assertEqual(status,1)
        self.assertEqual(stopped['rootful']['kind_delete_status'],19)
        self.assertEqual(stopped['error'],'rootful-kind-phase-failed')
        self.assertTrue(stopped['qemu_reaped'])


class BashProtocolControls(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='rootful-pure-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root/'state/credits').mkdir(parents=True)
        (self.root/'captures').mkdir()
        self.definitions = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('# Entry: pure-control tests')[0]
        self.definitions = self.definitions.replace('readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={self.root} stage={self.root}/stage')

    def use_historical_v3_logs(self):
        """Only tests of the removed child/wait contract select frozen v3."""
        self.definitions = receiver_before_direct_exec(receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))))))))))).split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={self.root} stage={self.root}/stage')

    def child(self, body):
        definitions = self.definitions
        if 'remember() { :; }' in body:
            definitions = definitions.replace('\nremember() {', '\nproduct_remember() {', 1)
            body = body.replace('remember() { :; }', 'remember() { case $1 in kind-create-failure | kind-create-evidence) product_remember "$@" ;; *) : ;; esac; }')
        script = self.root / ('script' + str(len(list(self.root.glob('script*')))))
        script.write_text(definitions + '\nrootful_admitted=1\nowner=' + 'a'*32 + '\nplan='+'b'*64+'\nboot=own-test-boot\n' + body)
        return OwnedPipeChild(['/usr/bin/bash', str(script)], self.addCleanup)

    def run_body(self, body):
        child = self.child(body)
        result = child.finish()
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def classify(self, arguments, *, profile='legacy-1.20.15', volume='c'*64):
        # Encode literal shell array elements with single-quote escaping. No
        # input is eval'd and hostile argv remains inert comparison data.
        quote = lambda s: "'"+s.replace("'", "'\\''")+"'"
        body = 'profile='+quote(profile)+'\ncluster=own\nnode=own-control-plane\nalias=localhost/kubernetes-lens-node:owner\nvolume='+quote(volume)+'\nargs=('+ ' '.join(quote(a) for a in arguments)+')\n'
        body += 'if provider_classify; then printf "accepted:%s\\n" "$action"; else printf "refused\\n"; fi\n'
        return self.run_body(body).decode().strip()

    def test_exact_provider_identity_and_unknown_pull_create_cp_wait_refuse(self):
        self.assertEqual(self.classify(['--version']), 'accepted:version')
        self.assertEqual(self.classify(['inspect', '--type=image', 'localhost/kubernetes-lens-node:owner']), 'accepted:image')
        for argv in [['-v'], ['pull', 'anything'], ['network', 'create', 'kind'],
                     ['cp', '/tmp/a', 'own-control-plane:/a'], ['--version', 'extra'],
                     ['inspect', '--type=image', 'docker.io/library/sha256:fake']]:
            self.assertEqual(self.classify(argv), 'refused')

    def test_exec_payload_and_foreign_nodes_are_not_commands(self):
        prefix=['exec','--privileged','own-control-plane']
        self.assertEqual(self.classify(prefix+['cat','/kind/version']), 'accepted:node-version')
        for suffix in [['sh','-c','true'],['cat','/etc/shadow'],['cat /kind/version'],['cat','/kind/version; true']]:
            self.assertEqual(self.classify(prefix+suffix), 'refused')
        self.assertEqual(self.classify(['exec','--privileged','foreign','cat','/kind/version']), 'refused')

    def test_legacy_and_modern_bootstrap_are_separate(self):
        prefix=['exec','--privileged','own-control-plane','kubeadm','init']
        old=prefix+['--skip-phases=preflight','--config=/kind/kubeadm.conf','--skip-token-print','--v=6']
        modern=prefix+['--config=/kind/kubeadm.conf','--skip-token-print','--v=6']
        for version, good, bad in [('legacy-1.20.15', old, modern), ('modern-1.37.0',modern,old)]:
            self.assertEqual(self.classify(good,profile=version),'accepted:init')
            self.assertEqual(self.classify(bad,profile=version),'refused')

    def test_hard_native_utility_output_tokens_are_not_refunded(self):
        result=self.run_body('''
for ((i=0;i<70;i++)); do take work 70 || exit 2; done
if take work 70; then exit 3; fi
for ((i=0;i<5;i++)); do take cleanup 5 || exit 4; done
if take cleanup 5; then exit 5; fi
for ((i=0;i<768;i++)); do take utility 768 || exit 6; done
if take utility 768; then exit 7; fi
for ((i=0;i<256;i++)); do take output 256 || exit 8; done
if take output 256; then exit 9; fi
printf bounded
''')
        self.assertEqual(result,b'bounded')
        self.assertEqual(len(list((self.root/'state/credits').iterdir())),1099)
        self.assertEqual(self.run_body('if take work 70; then exit 1; fi; printf retained'),'retained'.encode())

    def test_utility_cleanup_partition_and_single_use_launch_are_persistent(self):
        result=self.run_body('''
mode=work
for ((i=0;i<680;i++)); do grant_utility || exit 2; done
if grant_utility; then exit 3; fi
mode=cleanup
for ((i=0;i<64;i++)); do grant_utility || exit 4; done
if grant_utility; then exit 5; fi
mode=work
if grant_utility; then exit 6; fi
printf retained-cleanup
''')
        self.assertEqual(result,b'retained-cleanup')
        self.assertEqual(len(list((self.root/'state/credits').glob('utility-work.*'))),680)
        self.assertEqual(len(list((self.root/'state/credits').glob('utility-cleanup.*'))),64)

    def test_concurrent_token_claims_have_one_winner_without_flock(self):
        one=self.child('if take cleanup 1; then printf won; else printf lost; fi\n')
        two=self.child('if take cleanup 1; then printf won; else printf lost; fi\n')
        a,b=one.finish(),two.finish()
        self.assertEqual(sorted([a.stdout,b.stdout]),[b'lost',b'won'])
        self.assertEqual(len(list((self.root/'state/credits').iterdir())),1)

    def test_execution_claim_is_single_use_and_failure_poison_is_persistent(self):
        self.assertEqual(self.run_body('claim execution; printf first'),b'first')
        child=self.child('claim execution; printf forbidden')
        result=child.finish()
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b'forbidden',result.stdout)
        self.assertTrue((self.root/'state/poison').is_file())

    def test_raw_packet_nul_missing_newline_extra_and_overlength_refuse(self):
        for payload in (b'good\0packet\n',b'good\n\0',b'good',b'x'*4097):
            # Each case owns a fresh fixed receiver state directory.
            with self.subTest(payload=payload[:20]):
                for name in ('request.in','request.extra','poison'):
                    (self.root/'state'/name).unlink(missing_ok=True)
                child=self.child('receive_packet; printf accepted')
                child.process.stdin.write(payload); child.process.stdin.flush()
                result=child.finish()
                self.assertNotEqual(result.returncode,0)
                self.assertNotIn(b'accepted',result.stdout)
        for name in ('request.in','request.extra','poison'):
            (self.root/'state'/name).unlink(missing_ok=True)
        child=self.child('receive_packet; printf "accepted:%s" "$packet"')
        child.process.stdin.write(b'canonical\n'); child.process.stdin.flush()
        self.assertEqual(child.finish().stdout,b'accepted:canonical')

    def test_prerequisite_eof_rejects_one_nul_byte(self):
        child=self.child('prerequisite_eof; printf forbidden')
        child.process.stdin.write(b'\0'); child.process.stdin.flush()
        result=child.finish()
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn(b'forbidden',result.stdout)

    def test_normal_io_helpers_capture_exact_bytes_and_reap_both(self):
        result=self.run_body('''
clock_check() { :; }
printf 'work\\n' > "$root/state/mode"
mode=work
native 4096 4096 /usr/bin/bash -c 'printf genuine; printf private-error >&2; exit 7' && exit 2
[[ $last_tool_status == 7 ]]
read_file "$out"; [[ $REPLY == genuine ]]
read_file "$err"; [[ $REPLY == private-error ]]
shopt -s nullglob
helpers=("$credits"/utility-work.* "$credits"/utility-cleanup.*)
((${#helpers[@]}==4))
printf checked
''')
        self.assertEqual(result,b'checked')

    def test_normal_io_overflow_refuses_without_truncation_success(self):
        result=self.run_body('''
clock_check() { :; }
printf 'work\\n' > "$root/state/mode"
mode=work
if native 4096 4096 /usr/bin/bash -c 'printf "%05000d" 0'; then exit 2; fi
[[ -f $root/state/poison ]]
[[ $last_tool_status == 0 || $last_tool_status == 141 ]]
[[ $(u /usr/bin/stat -c %s "$out") == 4097 ]]
printf overflow
''')
        self.assertEqual(result,b'overflow')

    def host_process_identities(self):
        # Pure tests use host-owned Bash/pipe children, not the guest PID bound.
        self.definitions = self.definitions.replace('pid_max=32768', 'pid_max=4194304')
        self.definitions = self.definitions.replace('[0-9]{0,4}', '[0-9]{0,9}')

    def collector_body(self):
        self.host_process_identities()
        return r'''
mode=work
grant_utility; d=$utility_ticket
grant_utility; s=$utility_ticket
grant_utility; t=$utility_ticket
logs_collector 4096 "$captures/stream" out "$d" "$s" "$t"
printf collector-closed
'''

    def test_streaming_short_marker_arrives_before_input_eof(self):
        body = self.collector_body()
        child = self.child(body)
        marker = b'Reached target Multi-User System.\n'
        child.process.stdin.write(marker)
        child.process.stdin.flush()
        observed = bytearray()
        # Original OwnedPipeChild deadline/ownership also governs this control.
        while marker not in observed:
            child.read_available()
            observed[:] = child.output["stdout"]
            self.assertTrue(child.running(), bytes(observed))
            self.assertGreater(child.remaining(), 0)
        self.assertNotIn(b'collector-closed', observed)
        child.close_input()
        result = child.finish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, marker + b'collector-closed')
        self.assertEqual((self.root/'captures/stream').read_bytes(), marker)
        self.assertEqual((self.root/'state/logs-out.closed').read_text(), f'0 0 {len(marker)} eof\n')
        for name in ('out', 'out-dd', 'out-tee'):
            self.assertRegex((self.root/f'state/logs-{name}.identity').read_text(), r'^\d+ \d+\n$')

    def test_streaming_overflow_is_sticky_and_not_successful_eof(self):
        child = self.child(self.collector_body())
        child.process.stdin.write(b'x'*4097)
        child.close_input()
        result = child.finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'collector-closed', result.stdout)
        self.assertEqual((self.root/'captures/stream').stat().st_size, 4097)
        self.assertTrue((self.root/'state/poison').is_file())
        self.assertIn('failed', (self.root/'state/logs-out.closed').read_text())

    def test_post_arm_gate_requires_actual_parent_and_start(self):
        self.use_historical_v3_logs()
        self.host_process_identities()
        # Project the guest's root credentials without changing host credentials.
        status = self.root/'projected-status'
        status.write_text('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n')
        self.definitions = self.definitions.replace('done < /proc/self/status', f'done < {status}')
        body = r'''
read -r boot < /proc/sys/kernel/random/boot_id
printf '%s %s %s\n' "$owner" "$plan" "$boot" > "$root/state/logs-binding"
record_identity "$root/state/logs-wrapper.identity"
(logs_gate; printf gate-verified) & child=$!
wait "$child"
'''
        self.assertEqual(self.run_body(body), b'gate-verified')
        self.assertTrue((self.root/'state/logs-child.identity').is_file())

    def test_post_arm_gate_refuses_parent_start_drift_before_exec(self):
        self.use_historical_v3_logs()
        self.host_process_identities()
        body = r'''
read -r boot < /proc/sys/kernel/random/boot_id
printf '%s %s %s\n' "$owner" "$plan" "$boot" > "$root/state/logs-binding"
process_identity "$BASHPID"
printf '%s %s\n' "$BASHPID" "$((PROC_START+1))" > "$root/state/logs-wrapper.identity"
if (logs_gate; printf forbidden); then exit 2; fi
[[ ! -e $root/state/logs-child.identity ]]
printf refused
'''
        self.assertEqual(self.run_body(body), b'refused')

    def test_post_arm_gate_refuses_early_reparented_identity(self):
        self.use_historical_v3_logs()
        self.host_process_identities()
        body = r'''
read -r boot < /proc/sys/kernel/random/boot_id
printf '%s %s %s\n' "$owner" "$plan" "$boot" > "$root/state/logs-binding"
printf '1 1\n' > "$root/state/logs-wrapper.identity"
if (logs_gate; printf forbidden); then exit 2; fi
[[ ! -e $root/state/logs-child.identity ]]
printf refused
'''
        self.assertEqual(self.run_body(body), b'refused')

    def retirement_body(self, *, legacy=False):
        self.host_process_identities()
        body = r'''
mode=work
clock_check() { UPTIME=1 work_limit=2; }
# Projected already-retired identities; source never signals these numbers.
for name in wrapper child out err out-dd out-tee err-dd err-tee; do
  printf '4194303 1\n' > "$root/state/logs-$name.identity"
done
printf '0 0 35 eof\n' > "$root/state/logs-out.closed"
printf '0 0 0 eof\n' > "$root/state/logs-err.closed"
printf '%s %s\n' "$captures/work.1.out" "$captures/work.1.err" > "$root/state/logs-captures"
printf 'Reached target Multi-User System.\n' > "$captures/work.1.out"
printf '' > "$captures/work.1.err"
'''
        return body if legacy else body.replace('wrapper child out err out-dd out-tee err-dd err-tee', 'native out err out-dd out-tee err-dd err-tee')

    def test_exception_retirement_preserves_unknown_wait_and_signal_cause(self):
        body = self.retirement_body() + r'''
logs_retirement
read_file "$root/state/logs-retirement"
printf '%s' "$REPLY"
'''
        self.assertEqual(self.run_body(body), b'retired-wait-and-signal-cause-unavailable')

    def test_normal_retirement_requires_genuine_zero_wait_status(self):
        self.use_historical_v3_logs()
        body = self.retirement_body(legacy=True) + r'''
printf '7\n' > "$root/state/logs-wrapper.status"
if (logs_retirement); then exit 2; fi
[[ ! -e $root/state/logs-retirement ]]
printf refused
'''
        self.assertEqual(self.run_body(body), b'refused')

    def test_retirement_refuses_missing_completion_marker_and_poison(self):
        for alteration in (
            'unset dummy; : > "$root/state/logs-out.closed"',
            'printf silent > "$captures/work.1.out"',
            'printf poisoned > "$root/state/poison"',
            'printf "0 0 4097 failed\\n" > "$root/state/logs-err.closed"',
            'printf "0 1 30 eof\\n" > "$root/state/logs-out.closed"',
        ):
            # Each subcase needs independent private identity/capture records.
            with tempfile.TemporaryDirectory(prefix='rootful-retirement-pure-') as directory:
                original_root = self.root
                original_definitions = self.definitions
                self.root = Path(directory)
                (self.root/'state/credits').mkdir(parents=True)
                (self.root/'captures').mkdir()
                self.definitions = original_definitions.replace(str(original_root), str(self.root))
                try:
                    body = self.retirement_body() + alteration + r'''
if (logs_retirement); then exit 2; fi
[[ ! -e $root/state/logs-retirement ]]
printf refused
'''
                    self.assertEqual(self.run_body(body), b'refused')
                finally:
                    self.root = original_root
                    self.definitions = original_definitions

    def test_late_original_descendant_refuses_without_numeric_signal(self):
        body = self.retirement_body() + r'''
process_identity "$BASHPID"
printf '%s %s\n' "$BASHPID" "$PROC_START" > "$root/state/logs-native.identity"
if (logs_retirement); then exit 2; fi
[[ ! -e $root/state/logs-retirement ]]
printf refused
'''
        self.assertEqual(self.run_body(body), b'refused')

    def test_identity_reuse_does_not_authorize_a_signal_or_false_live_claim(self):
        body = self.retirement_body() + r'''
process_identity "$BASHPID"
printf '%s %s\n' "$BASHPID" "$((PROC_START+1))" > "$root/state/logs-native.identity"
logs_retirement
printf retired-original-only
'''
        self.assertEqual(self.run_body(body), b'retired-original-only')

    def projected_logs_child(self, status):
        self.use_historical_v3_logs()
        self.host_process_identities()
        projected = self.root/'projected-status'
        projected.write_text('Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n')
        self.definitions = self.definitions.replace('done < /proc/self/status', f'done < {projected}')
        # Replace only the utility exec dispatch in this pure source projection.
        # No setpriv, Podman or other native client executes on the host.
        self.definitions = self.definitions.replace('    exec "$@"',
            '    if [[ $1 == /usr/bin/setpriv ]]; then logs_gate; '
            'printf "Reached target Multi-User System.\\n"; printf private-error >&2; '
            f'exit {status}; fi\n    exec "$@"', 1)
        return r'''
read -r boot < /proc/sys/kernel/random/boot_id
node=projected-owned-node
mode=work; printf 'work\n' > "$root/state/mode"
printf '999999999 999999999\n' > "$root/state/deadlines"
'''

    def test_streaming_normal_owner_really_waits_child_and_both_collectors(self):
        body = self.projected_logs_child(0) + r'''
stream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"
[[ $last_tool_status == 0 ]]
read_file "$root/state/logs-wrapper.status"; [[ $REPLY == 0 ]]
read_file "$out"; [[ $REPLY == 'Reached target Multi-User System.' ]]
read_file "$err"; [[ $REPLY == private-error ]]
shopt -s nullglob
tickets=("$credits"/utility-work.*); ((${#tickets[@]}==7))
printf waited
'''
        self.assertEqual(self.run_body(body), b'Reached target Multi-User System.\nwaited')
        self.assertTrue((self.root/'state/logs-out.closed').is_file())
        self.assertTrue((self.root/'state/logs-err.closed').is_file())

    def test_streaming_child_nonzero_preserves_actual_status_and_poison(self):
        body = self.projected_logs_child(7) + r'''
if stream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"; then exit 2; fi
[[ $last_tool_status == 7 ]]
read_file "$root/state/logs-wrapper.status"; [[ $REPLY == 7 ]]
[[ -e $root/state/poison ]]
printf actual-seven
'''
        self.assertEqual(self.run_body(body), b'Reached target Multi-User System.\nactual-seven')

    def test_post_arm_gate_refuses_credential_drift(self):
        body = self.projected_logs_child(0)
        (self.root/'projected-status').write_text('Uid:\t0\t0\t1000\t0\nGid:\t0\t0\t0\t0\n')
        body += r'''
if stream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"; then exit 2; fi
[[ ! -e $root/state/logs-child.identity && -e $root/state/poison ]]
printf credential-refused
'''
        self.assertEqual(self.run_body(body), b'credential-refused')

    def test_streaming_descendant_writer_requires_real_eof(self):
        self.host_process_identities()
        body = r'''
mode=work
grant_utility; d=$utility_ticket
grant_utility; s=$utility_ticket
grant_utility; t=$utility_ticket
exec 5<&0
exec {source_fd}< <(
  printf 'Reached target Multi-User System.\n'
  (IFS= read -r release <&5; [[ $release == release ]]; printf descendant-tail) & descendant=$!
  wait "$descendant"
)
source_pid=$!
logs_collector 4096 "$captures/stream" out "$d" "$s" "$t" <&$source_fd
exec {source_fd}<&-
wait "$source_pid"
printf collector-closed
'''
        child = self.child(body)
        marker = b'Reached target Multi-User System.\n'
        while marker not in child.output['stdout']:
            child.read_available()
            self.assertTrue(child.running())
            self.assertGreater(child.remaining(), 0)
        self.assertFalse((self.root/'state/logs-out.closed').exists())
        child.process.stdin.write(b'release\n')
        child.process.stdin.flush()
        child.close_input()
        result = child.finish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, marker+b'descendant-tailcollector-closed')

    def test_streaming_switch_never_replaces_an_unmatched_native_command(self):
        body = r'''
mode=work; node=owned-node
printf 'work\n' > "$root/state/mode"
printf '999999999 999999999\n' > "$root/state/deadlines"
if (stream_logs=1 native 16384 4096 /usr/bin/bash -c 'printf forbidden'); then exit 2; fi
[[ -e $root/state/poison && ! -e $root/state/logs-wrapper.identity ]]
printf unmatched-refused
'''
        self.assertEqual(self.run_body(body), b'unmatched-refused')

    def test_trusted_guest_logs_report_is_closed_and_excludes_raw_logs(self):
        body = self.retirement_body() + r'''
logs_retirement
emit_logs_evidence
printf '%s' "$logs_json"
'''
        # The projected retirement fixtures alias identities intentionally;
        # collector/report serialization must remain pure, parser rejects aliases.
        value = json.loads(self.run_body(body))
        self.assertEqual(set(value['identities']), rootful.LOG_ROLES_V4)
        self.assertEqual(set(value['collectors']), {'out', 'err'})
        self.assertIsNone(value['wrapper_observed_child_wait_status'])
        self.assertIsNone(value['signal_cause'])
        self.assertTrue(value['startup_marker'])
        self.assertNotIn('Multi-User System', json.dumps(value))
        self.assertNotIn(str(self.root), json.dumps(value))

    def test_early_failure_report_preserves_fixed_roles_as_null(self):
        value = json.loads(self.run_body('emit_logs_evidence; printf "%s" "$logs_json"'))
        self.assertEqual(value['state'], 'not-established')
        self.assertEqual(value['identities'], {name: None for name in rootful.LOG_ROLES_V4})
        self.assertEqual(value['collectors'], {'out': None, 'err': None})
        rootful.logs_evidence(value, complete=False, version=rootful.RESULT_V4)
        with self.assertRaises(vm.Refusal):
            rootful.logs_evidence(value, complete=True, version=rootful.RESULT_V4)

    def network_projection(self):
        bridge = self.root/'projected-sys/class/net/klbr0'
        bridge.parent.mkdir(parents=True)
        route = self.root/'projected-route'
        route.write_text('Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n')
        self.definitions = self.definitions.replace('/sys/class/net/klbr0', str(bridge))
        self.definitions = self.definitions.replace('/proc/net/route', str(route))
        return bridge, route

    def test_existing_bridge_without_ipv4_route_refuses_before_network_effect(self):
        bridge, _route = self.network_projection()
        bridge.mkdir()
        value = self.run_body(r'''
if (network_routes; printf network-effect > "$root/network-effect"); then exit 2; fi
[[ ! -e $root/network-effect && -e $root/state/poison ]]
printf bridge-refused
''')
        self.assertEqual(value, b'bridge-refused')

    def test_dangling_bridge_link_also_refuses(self):
        bridge, _route = self.network_projection()
        bridge.symlink_to(self.root/'missing-interface')
        value = self.run_body(r'''
if (network_routes; printf forbidden); then exit 2; fi
printf link-refused
''')
        self.assertEqual(value, b'link-refused')

    def test_absent_bridge_and_readable_nonconflicting_routes_admit_precondition(self):
        _bridge, route = self.network_projection()
        with route.open('a') as file:
            file.write('eth0 00000000 0100000A 0003 0 0 0 00000000 0 0 0\n')
        self.assertEqual(self.run_body('network_routes; printf precondition-only'), b'precondition-only')

    def test_missing_route_table_refuses_even_with_absent_bridge(self):
        _bridge, route = self.network_projection()
        # Project a path that exists but cannot be opened as a readable route file.
        route.unlink()
        self.assertEqual(self.run_body(r'''
if (network_routes; printf forbidden); then exit 2; fi
printf route-refused
'''), b'route-refused')

    def test_unreadable_existing_route_table_refuses(self):
        _bridge, route = self.network_projection()
        route.chmod(0)
        self.addCleanup(route.chmod, 0o600)
        # Independent actual I/O determines the expectation. UID/mode alone
        # cannot describe DAC overrides, capabilities or filesystem policy.
        try:
            route.read_bytes()
        except PermissionError:
            readable = False
        else:
            readable = True
        result = self.run_body(r'''
if (network_routes); then printf effectively-readable; else printf unreadable-route-refused; fi
''')
        self.assertEqual(result, b'effectively-readable' if readable else b'unreadable-route-refused')
        self.assertEqual((self.root/'state/poison').exists(), not readable)

    def test_nonregular_route_table_refuses_independently_of_credentials(self):
        _bridge, route = self.network_projection()
        route.unlink()
        route.mkdir()
        self.assertEqual(self.run_body(r'''
if (network_routes; printf forbidden); then exit 2; fi
[[ -e $root/state/poison ]]
printf nonregular-route-refused
'''), b'nonregular-route-refused')

    def test_malformed_clock_limits_refuse_before_following_effect(self):
        for value in ('not-a-number', '-1', '1.5', '1e2'):
            with self.subTest(value=value):
                (self.root/'state/deadlines').write_text(value+' 999999999\n')
                result = self.child('mode=work; clock_check; printf forbidden').finish()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b'forbidden', result.stdout)
                self.assertIn(b'rootful-receiver-refused', result.stderr)
                self.assertEqual(list((self.root/'state/credits').iterdir()), [])

    def test_route_ignored_fields_preserve_unrelated_destination_and_mask(self):
        _bridge, route = self.network_projection()
        with route.open('a') as file:
            file.write('eth0 0000320A 0100000A 0001 2 9 37 0000FFFF 0 0 0\n')
        self.assertEqual(self.run_body('network_routes; printf unrelated-only'), b'unrelated-only')

    def test_route_ignored_fields_still_refuse_each_owned_subnet(self):
        _bridge, route = self.network_projection()
        header = route.read_text()
        for destination in ('00001EAC', '0000F40A', '0000600A'):
            with self.subTest(destination=destination):
                route.write_text(header+'eth0 '+destination+' 0100000A 0001 2 9 37 0000FFFF 0 0 0\n')
                result = self.child('network_routes; printf forbidden').finish()
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b'forbidden', result.stdout)
                self.assertIn(b'rootful-receiver-refused', result.stderr)

    def test_actual_exit_trap_invokes_cleanup_and_both_closed_emitters(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        start = source.index('\nfinish() {\n')+1
        end = source.index('\ntrap finish EXIT\n', start)
        finish = source[start:end]
        handler = source[end+1:].splitlines()[0]
        for delete_status, expected_exit in ((0, 3), (7, 1)):
            with self.subTest(delete_status=delete_status):
                body = r'''
mode=work
profile=legacy-1.20.15 patch=1.20.15 cluster=owned-cluster
spec_sha=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
created=1 create_status=0 delete_status=-1 source_status=not-reached
native() {
  printf '%s\n' "$@" > "$root/state/cleanup-argv"
  last_tool_status=DELETE_STATUS
  return DELETE_STATUS
}
'''.replace('DELETE_STATUS', str(delete_status))+finish+'\n'+handler+'\nexit 3\n'
                result = self.child(body).finish()
                self.assertEqual(result.returncode, expected_exit, result.stderr)
                value = json.loads(result.stdout)
                self.assertEqual(value['state'], 'failed')
                self.assertEqual(value['kind_delete_status'], delete_status)
                self.assertEqual(value['evidence']['files'], {})
                self.assertEqual(set(value['logs']['identities']), rootful.LOG_ROLES_V4)
                self.assertEqual(value['logs']['state'], 'not-established')
                self.assertEqual((self.root/'state/mode').read_text(), 'cleanup\n')
                self.assertEqual((self.root/'state/cleanup-argv').read_text().splitlines(),
                    ['4096', '4096', str(self.root/'stage/kind'), 'delete', 'cluster', '--name', 'owned-cluster'])

    def test_expired_clock_refuses_before_native_debit(self):
        result=self.run_body('''
printf '0 0\\n' > "$root/state/deadlines"
mode=work
if (native 4096 4096 /usr/bin/true); then exit 1; fi
shopt -s nullglob
records=("$credits"/work.*)
((${#records[@]}==0))
printf refused
''')
        self.assertEqual(result,b'refused')



    def initial_selection(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        return 'if [[ $# == 0 ]]; then set -- prerequisite-v1; fi\n' + source.split('# Initial prerequisite diagnostic selection;', 1)[1].split(
            '[[ $EUID == 0 && $BASH_VERSION', 1)[0].split('\n', 1)[1]

    def refusal(self, body, expected):
        result = self.child(body).finish()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, expected)
        return result

    def test_default_refusal_remains_exact_and_poison_is_preserved(self):
        self.refusal('fail\n', b'rootful-receiver-refused\n')
        self.assertEqual((self.root / 'state/poison').read_bytes(), b'poisoned\n')

    def test_each_closed_initial_code_has_only_one_short_fixed_frame(self):
        codes = ('entry', 'source', 'paths', 'packages', 'exec-closure', 'eof', 'fresh-state',
                 'pid-limits', 'pid-max', 'nr-open-form', 'nr-open-range', 'mount-both', 'mount-proc', 'mount-root', 'namespace', 'mount', 'memory', 'block', 'mapper', 'filesystem',
                 'inventory', 'podman-info', 'podman-profile') + FINE_PACKAGE_CODES + INVENTORY_CODES
        for code in codes:
            with self.subTest(code=code):
                frame = ('rootful-prerequisite-code-v1:' + code + '\n').encode('ascii')
                self.assertLessEqual(len(frame), 44)
                self.refusal(self.initial_selection() + '\nfail ' + code + '\n',
                             b'rootful-receiver-refused\n' + frame)

    def test_unknown_unset_extra_and_hostile_code_arguments_never_echo(self):
        quote = lambda value: "'" + value.replace("'", "'\\''") + "'"
        for argument in ('', 'unknown', 'entry\nprivate-value', '$(printf private-value)',
                         "'; printf private-value; #", 'x' * 4096):
            with self.subTest(argument_size=len(argument)):
                self.refusal(self.initial_selection() + '\nfail ' + quote(argument) + '\n',
                             b'rootful-receiver-refused\n')
        self.refusal(self.initial_selection() + '\nfail\n', b'rootful-receiver-refused\n')
        self.refusal(self.initial_selection() + '\nfail entry source\n', b'rootful-receiver-refused\n')
        self.assertFalse((self.root / 'private-value').exists())

    def test_initial_selection_excludes_argument_and_existing_state_routes(self):
        for arguments in ('provider', 'logs-child', 'unknown', 'provider extra'):
            with self.subTest(arguments=arguments):
                self.refusal('set -- ' + arguments + '\n' + self.initial_selection() + '\nfail entry\n',
                             b'rootful-receiver-refused\n')
        for name, symbolic in (('phase', False), ('mode', False), ('phase', True), ('mode', True)):
            with self.subTest(state=name, symbolic=symbolic):
                path = self.root / 'state' / name
                if symbolic:
                    path.symlink_to(self.root / 'absent')
                else:
                    path.write_bytes(b'cleanup\n' if name == 'mode' else b'staged-required\n')
                try:
                    self.refusal(self.initial_selection() + '\nfail source\n', b'rootful-receiver-refused\n')
                finally:
                    path.unlink()

    def test_source_resets_ambient_selection_and_cleanup_stays_quiet(self):
        script = self.root / 'ambient-selection'
        script.write_text('export initial_prerequisite=1\n' + self.definitions + '\nrootful_admitted=1\nfail entry\n')
        result = OwnedPipeChild(['/usr/bin/bash', str(script)], self.addCleanup).finish()
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, b'', b'rootful-receiver-refused\n'))
        (self.root / 'state/poison').unlink()
        self.refusal(self.initial_selection() + '\nmode=cleanup\nfail entry\n', b'rootful-receiver-refused\n')
        self.assertFalse((self.root / 'state/poison').exists())

    def test_source_provider_and_later_resets_disable_already_selected_code(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        provider_reset = source.split('if [[ ${1:-} == provider ]]; then\n', 1)[1].split('  shift', 1)[0]
        self.assertEqual(provider_reset, '  initial_prerequisite=0\n')
        later_reset = source.split('\nread_file "$root/state/phase"\n', 1)[0].rsplit('\n', 1)[-1]
        self.assertEqual(later_reset, 'initial_prerequisite=0')
        for reset in (provider_reset, later_reset):
            self.refusal(self.initial_selection() + '\n' + reset + '\nfail pid-limits\n',
                         b'rootful-receiver-refused\n')

    def test_actual_pid_limit_guard_reports_only_closed_code_without_fixing_limit(self):
        guards = [line for line in receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).splitlines()
                  if line.strip().startswith('[[ $value == 32768 ]]')]
        self.assertEqual(guards, ['  [[ $value == 32768 ]] || fail pid-max'])
        self.refusal(self.initial_selection() + '\nvalue=not-the-required-limit\n' + guards[0] + '\nprintf forbidden\n',
                     b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pid-max\n')

    def test_source_codes_are_literals_or_one_immediate_status_expansion_and_helpers_keep_errexit(self):
        import re
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        codes = {'entry', 'source', 'paths', 'packages', 'exec-closure', 'eof', 'fresh-state',
                 'pid-limits', 'pid-max', 'nr-open-form', 'nr-open-range', 'mount-both', 'mount-proc', 'mount-root', 'namespace', 'mount', 'memory', 'block', 'mapper', 'filesystem',
                 'inventory', 'podman-info', 'podman-profile'} | set(FINE_PACKAGE_CODES) | set(INVENTORY_CODES)
        actual = re.findall(r'\bfail ([^;\n]+)', source)
        self.assertEqual(actual.count('"pkg-sd-q$?"'), 1)
        actual.remove('"pkg-sd-q$?"')
        # Post-create reasons have a separate closed vocabulary and one fixed
        # clock-helper forwarding site; neither expands prerequisite codes.
        self.assertEqual(actual.count('"${1:-}"'), 1)
        self.assertEqual(source.count('  ((UPTIME < limit)) || fail "${1:-}"\n'), 1)
        actual.remove('"${1:-}"')
        retirement = source.split('\nlogs_retirement() {\n', 1)[1].split('\n}\n', 1)[0]
        guard_codes = re.findall(r'\bfail ([^;\n]+)', retirement)
        self.assertEqual(guard_codes, list('abcdefghijklm')+['o'])
        self.assertEqual(source.count('      clock_check p\n'), 2)
        for code in guard_codes:
            actual.remove(code)
        codes.remove('pkg-sd-query')  # Retained legacy allowlist code, no longer the query branch.
        codes.remove('inventory')  # Historical coarse frame remains admitted.
        codes.remove('pid-limits')  # Retained historical coarse frame, no active resource guard.
        self.assertEqual(set(value.strip() for value in actual), codes)
        self.assertTrue(all(re.fullmatch(r'[a-z]+(?:-[a-z]+)*', value.strip()) for value in actual))
        self.assertIn('  prerequisite_eof\n', source)
        self.assertIn('  resource_check\n', source)
        self.assertIn('  info_check "$out"\n', source)
        self.assertNotRegex(source, r'(?:prerequisite_eof|resource_check|info_check "\$out")\s*\|\|')
        traps = [line.strip() for line in source.splitlines() if line.strip().startswith('trap ')]
        self.assertEqual(traps, ['trap - EXIT ERR HUP INT TERM', 'trap finish EXIT', "trap 'exit 1' ERR HUP INT TERM"])
        result = self.child(self.initial_selection() + '\nimplicit_failure() { false; printf forbidden; }\n'
                            'implicit_failure\nfail entry\n').finish()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b''))


class PidProfileGuardControls(unittest.TestCase):
    """Project only existing scalar values; production proc reads never run here."""
    CODES = ('pid-max', 'nr-open-form', 'nr-open-range')

    def guards(self):
        lines = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).splitlines()
        starts = ('[[ $value == 32768 ]]', '[[ $value =~ ^[0-9]{1,10}$ ]]',
                  '((value > 0 && value <= fd_max))')
        guards = [next(line for line in lines if line.strip().startswith(prefix)) for prefix in starts]
        self.assertEqual(guards, ['  [[ $value == 32768 ]] || fail pid-max',
            '  [[ $value =~ ^[0-9]{1,10}$ ]] || fail nr-open-form',
            '  ((value > 0 && value <= fd_max)) || fail nr-open-range'])
        return guards

    def quote(self, value):
        return "'" + value.replace("'", "'\\''") + "'"

    def test_actual_guards_keep_pid_and_nr_open_boundaries_without_queries_or_repairs(self):
        pid_guard, form_guard, range_guard = self.guards()
        cases = [('32768', '1', None), ('32768', '1073741816', None),
                 ('32767', '1', 'pid-max'), ('not-the-pid', '1', 'pid-max'),
                 ('32768', '', 'nr-open-form'), ('32768', 'private-value', 'nr-open-form'),
                 ('32768', '12345678901', 'nr-open-form'), ('32768', '-1', 'nr-open-form'),
                 ('32768', '0', 'nr-open-range'), ('32768', '1073741817', 'nr-open-range')]
        for pid, nr_open, code in cases:
            with self.subTest(pid=pid, nr_open=nr_open):
                fixture = BashProtocolControls(); fixture.setUp()
                try:
                    body = (fixture.initial_selection()+'\nvalue='+self.quote(pid)+'\n'+pid_guard
                        +'\nvalue='+self.quote(nr_open)+'\n'+form_guard+'\n'+range_guard+'\nprintf accepted\n')
                    result = fixture.child(body).finish()
                    if code is None:
                        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'accepted', b''))
                        self.assertFalse((fixture.root/'state/poison').exists())
                    else:
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                            (1, b'', b'rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code.encode()+b'\n'))
                        self.assertEqual((fixture.root/'state/poison').read_bytes(), b'poisoned\n')
                        self.assertNotIn(b'private-value', result.stderr)
                    self.assertEqual(list((fixture.root/'state/credits').iterdir()), [])
                finally:
                    fixture.doCleanups()

    def test_three_fixed_frames_are_initial_only_and_keep_poison_and_exit1(self):
        for code in self.CODES:
            for route in ('initial', 'unselected', 'provider', 'later', 'cleanup'):
                with self.subTest(code=code, route=route):
                    fixture = BashProtocolControls(); fixture.setUp()
                    try:
                        body = '' if route == 'unselected' else fixture.initial_selection()+'\n'
                        if route in ('provider', 'later'):
                            body += 'initial_prerequisite=0\n'
                        if route == 'cleanup':
                            body += 'mode=cleanup\n'
                        result = fixture.child(body+'fail '+code+'\n').finish()
                        expected = b'rootful-receiver-refused\n'
                        if route == 'initial':
                            expected += b'rootful-prerequisite-code-v1:'+code.encode()+b'\n'
                        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', expected))
                        self.assertEqual((fixture.root/'state/poison').exists(), route != 'cleanup')
                        self.assertEqual(list((fixture.root/'state/credits').iterdir()), [])
                    finally:
                        fixture.doCleanups()

    def test_malformed_or_extra_code_arguments_never_emit_values(self):
        for arguments in ("'nr-open-range private-value'", 'nr-open-form private-value',
                          "'pid-max\\nprivate-value'", 'nr-open-unknown'):
            with self.subTest(arguments=arguments):
                fixture = BashProtocolControls(); fixture.setUp()
                try:
                    fixture.refusal(fixture.initial_selection()+'\nfail '+arguments+'\n',
                        b'rootful-receiver-refused\n')
                    self.assertEqual((fixture.root/'state/poison').read_bytes(), b'poisoned\n')
                finally:
                    fixture.doCleanups()


class DurableEvidenceControls(unittest.TestCase):
    def bundle(self):
        import base64
        owner='a'*32
        configuration=vm.encode({'rootfs':{'type':'layers','diff_ids':[]}})
        image_id=vm.digest(configuration)
        manifest=vm.encode({'schemaVersion':2,'config':{'digest':'sha256:'+image_id},'layers':[]})
        config={'owner':owner,'stage_plan_sha256':'b'*64,'rootful_spec':{
            'profile':'legacy-1.20.15','server_patch':'1.20.15',
            'config_sha256':image_id,'manifest_sha256':vm.digest(manifest)}}
        network_id='d'*64; node_id='e'*64
        documents={
            'config':configuration,'manifest':manifest,
            'podman-info':vm.encode({'host':{'security':{'rootless':False},'serviceIsRemote':False,
                'cgroupVersion':'v2','os':'linux','arch':'amd64','networkBackend':'netavark','cgroupManager':'cgroupfs'},
                'version':{'Version':'5.8.7'},'store':{'graphDriverName':'overlay','graphRoot':rootful.ROOT+'/storage',
                'runRoot':'/run/kubernetes-lens-rootful/storage','graphStatus':{'Backing Filesystem':'xfs'}}}),
            'image-inspect':vm.encode([{'Id':image_id,'RepoDigests':['kindest/node@sha256:'+'f'*64]}]),
            'network-inspect':vm.encode([{'name':'kind','id':network_id,'driver':'bridge','network_interface':'klbr0',
                'ipv6_enabled':False,'dns_enabled':False,'subnets':[{'subnet':'172.30.0.0/16','gateway':'172.30.0.1'}],
                'labels':{'io.kubernetes-lens.issue2.owner':owner}}]),
            'node-inspect':vm.encode([{'Id':node_id,'Image':image_id,'Name':'kl-'+owner+'-control-plane',
                'State':{'Running':True,'Pid':7,'CgroupPath':'/libpod_parent/libpod-'+node_id},
                'NetworkSettings':{'Networks':{'kind':{'NetworkID':network_id}}},
                'Config':{'CreateCommand':['/usr/bin/podman','run','--pull=never',image_id]}}])}
        envelope=RootfulHostControls.result(self)
        envelope.update(owner=owner,plan_sha256=config['stage_plan_sha256'])
        envelope['evidence']={'schema':'kubernetes-lens-owned-rootful-evidence-v1','owner':owner,
            'plan_sha256':config['stage_plan_sha256'],'source_spec_sha256':vm.digest(vm.encode(config['rootful_spec'])),
            'files':{name:{'bytes':len(raw),'sha256':vm.digest(raw),'base64':base64.b64encode(raw).decode('ascii')}
                     for name,raw in documents.items()}}
        return config,envelope,documents

    def encode(self,value):
        return vm.encode(value)+b'\n'

    def test_exact_raw_bytes_and_genuine_repo_digests_are_retained(self):
        import base64
        config,value,documents=self.bundle()
        checked=rootful.wire_record(self.encode(value),config)
        self.assertEqual(checked['evidence']['raw_bytes'],sum(map(len,documents.values())))
        self.assertEqual(set(checked['evidence']['files']),rootful.EVIDENCE_NAMES)
        raw=base64.b64decode(value['evidence']['files']['image-inspect']['base64'])
        self.assertEqual(raw,documents['image-inspect'])
        self.assertIn(b'kindest/node@sha256:',raw)

    def test_kubeconfig_logs_secret_extra_and_bad_source_catalogues_refuse(self):
        for name in ('kubeconfig','Secret','stderr-log','application-output'):
            config,value,_=self.bundle()
            value['evidence']['files'][name]=value['evidence']['files']['config']
            with self.subTest(name=name),self.assertRaisesRegex(vm.Refusal,'rootful-evidence-catalogue'):
                rootful.wire_record(self.encode(value),config)
        config,value,_=self.bundle();value['evidence']['source_spec_sha256']='0'*64
        with self.assertRaises(vm.Refusal):rootful.wire_record(self.encode(value),config)

    def test_bad_base64_digest_length_bool_missing_and_modified_identities_refuse(self):
        import base64
        for field,bad in [('bytes',True),('bytes',99999),('sha256','0'*64),('base64','!')]:
            config,value,_=self.bundle();value['evidence']['files']['config'][field]=bad
            with self.subTest(field=field),self.assertRaises(vm.Refusal):
                rootful.wire_record(self.encode(value),config)
        for name,change in [('image-inspect',lambda row:row[0].update(Id='0'*64)),
                            ('node-inspect',lambda row:row[0]['Config'].update(CreateCommand=['podman','run','foreign'])),
                            ('network-inspect',lambda row:row[0].update(ipv6_enabled=True))]:
            config,value,docs=self.bundle();document=vm.strict_json(docs[name]);change(document);raw=vm.encode(document)
            value['evidence']['files'][name]={'bytes':len(raw),'sha256':vm.digest(raw),'base64':base64.b64encode(raw).decode()}
            with self.subTest(name=name),self.assertRaises(vm.Refusal):
                rootful.wire_record(self.encode(value),config)
        config,value,_=self.bundle();del value['evidence']['files']['manifest']
        with self.assertRaises(vm.Refusal):rootful.wire_record(self.encode(value),config)

    def test_full_wire_and_raw_aggregate_are_bounded_before_persistence(self):
        import base64
        config,value,_=self.bundle()
        with self.assertRaisesRegex(vm.Refusal,'rootful-wire-budget'):
            rootful.wire_record(b' '*262145,config)
        value['state']='failed'
        raw=b'x'*70000
        value['evidence']['files']={name:{'bytes':len(raw),'sha256':vm.digest(raw),'base64':base64.b64encode(raw).decode()}
            for name in ('podman-info','image-inspect')}
        with self.assertRaisesRegex(vm.Refusal,'rootful-evidence-aggregate'):
            rootful.wire_record(self.encode(value),config,allow_failure=True)

    def test_sidecar_is_fixed0600_exclusive_nofollow_and_failure_cannot_succeed(self):
        config,value,_=self.bundle();raw=self.encode(value)
        budget=vm.Budget(time.monotonic()+30,10)
        with tempfile.TemporaryDirectory(prefix='rootful-evidence-pure-') as directory:
            record=rootful.durable_wire(raw,config,Path(directory),budget)
            target=Path(directory)/record['name']
            self.assertEqual(target.read_bytes(),raw)
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertEqual(record['sha256'],vm.digest(raw))
            with self.assertRaisesRegex(vm.Refusal,'rootful-durable-evidence-write-failed'):rootful.durable_wire(raw,config,Path(directory),budget)
            target.unlink()
            other=Path(directory)/'preserved';other.write_bytes(b'unchanged')
            target.symlink_to(other)
            with self.assertRaises(vm.Refusal):rootful.durable_wire(raw,config,Path(directory),budget)
            self.assertEqual(other.read_bytes(),b'unchanged')
        with patch.object(vm,'write',side_effect=OSError('bounded simulated failure')):
            with tempfile.TemporaryDirectory(prefix='rootful-evidence-pure-') as directory:
                with self.assertRaisesRegex(vm.Refusal,'rootful-durable-evidence-write-failed'):rootful.durable_wire(raw,config,Path(directory),budget)


class AllTaskInventoryControls(unittest.TestCase):
    setUp=BashProtocolControls.setUp
    child=BashProtocolControls.child
    run_body=BashProtocolControls.run_body

    def fake_proc(self):
        proc=self.root/'proc'; process=proc/'7';(process/'task').mkdir(parents=True)
        def record(tid,start):return str(tid)+' (owned task) '+' '.join(['S']+['0']*18+[str(start)])+'\n'
        (process/'stat').write_text(record(7,42))
        for tid,start in [(7,42),(8,43)]:
            task=process/'task'/str(tid);task.mkdir();(task/'fd').mkdir()
            (task/'stat').write_text(record(tid,start))
            (task/'limits').write_text('Max open files 1024 2048 files\n')
            (task/'fd/3').write_text('only numeric index is inspected')
        self.definitions=self.definitions.replace('in /proc/[0-9]*;',f'in {proc}/[0-9]*;')
        return process

    def test_each_tid_has_own_start_limits_and_fd_table(self):
        self.fake_proc()
        result=self.run_body('inventory; [[ ${INVENTORY_START[7]} == 42 && ${INVENTORY_START[8]} == 43 ]]; printf "%s" "$SNAP"')
        self.assertIn(b'7:42:2048:3,',result)
        self.assertIn(b'8:43:2048:3,',result)

    def test_task_glob_preserves_quoted_prefix_and_lexical_order(self):
        process = self.fake_proc()
        source_task = process/'task/8'
        task = process/'task/10'
        (task/'fd').mkdir(parents=True)
        (task/'stat').write_text('10 (owned task) '+' '.join(['S']+['0']*18+['99'])+'\n')
        (task/'limits').write_bytes((source_task/'limits').read_bytes())
        (task/'fd/3').write_text('only numeric index is inspected')
        (process/'task/ignored').mkdir()
        proc = process.parent
        spaced = proc.with_name('proc with spaces')
        proc.rename(spaced)
        self.definitions = self.definitions.replace(f'in {proc}/[0-9]*;', f'in "{spaced}"/[0-9]*;')
        value = self.run_body('inventory; printf "%s" "$SNAP"')
        self.assertEqual(value, b'7:42:10:99:2048:3,;7:42:2048:3,;8:43:2048:3,;|')

    def test_empty_task_glob_refuses_before_any_effect(self):
        import shutil
        process = self.fake_proc()
        shutil.rmtree(process/'task/7')
        shutil.rmtree(process/'task/8')
        result = self.child('inventory; printf forbidden').finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'forbidden', result.stdout)

    def test_second_tid_unbounded_limit_or_existing_high_fd_refuses(self):
        process=self.fake_proc();second=process/'task/8'
        (second/'limits').write_text('Max open files 1024 unlimited files\n')
        result=self.child('inventory; printf forbidden').finish()
        self.assertNotEqual(result.returncode,0);self.assertNotIn(b'forbidden',result.stdout)
        (second/'limits').write_text('Max open files 1024 2048 files\n')
        (second/'fd/1073741816').write_text('existing high slot')
        result=self.child('inventory; printf forbidden').finish()
        self.assertNotEqual(result.returncode,0);self.assertNotIn(b'forbidden',result.stdout)

    def test_missing_tid_fd_directory_is_not_treated_as_empty_inventory(self):
        process=self.fake_proc();fd=process/'task/8/fd';(fd/'3').unlink();fd.rmdir()
        result=self.child('inventory; printf forbidden').finish()
        self.assertNotEqual(result.returncode,0);self.assertNotIn(b'forbidden',result.stdout)



class PackagePredicateControls(unittest.TestCase):
    ROWS = ('bash 5.3.9-3.fc44', 'jq 1.8.1-3.fc44', 'coreutils 9.10-5.fc44',
            'systemd 259.9-1.fc44', 'podman 5.8.7-1.fc44', 'skopeo 1.22.3-1.fc44',
            'crun 1.28-1.fc44', 'conmon 2.2.1-2.fc44', 'netavark 1.17.2-1.fc44',
            'aardvark-dns 1.17.1-1.fc44', 'util-linux 2.41.5-1.fc44', 'libcap 2.78-1.fc44')
    ROW_CODES = ('rpm-bash', 'rpm-jq', 'rpm-coreutils', 'rpm-systemd', 'rpm-podman',
                 'rpm-skopeo', 'rpm-crun', 'rpm-conmon', 'rpm-netavark', 'rpm-aardvark',
                 'rpm-util-linux', 'rpm-libcap')

    def setUp(self):
        self.fixture = BashProtocolControls()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))

    def line(self, prefix):
        return next(line for line in self.source.splitlines() if line.startswith(prefix))

    def quote(self, value):
        return "'" + value.replace("'", "'\\''") + "'"

    def guard(self, prefix):
        lines = self.source.splitlines()
        index = next(i for i, line in enumerate(lines) if line.startswith(prefix))
        return '\n'.join(lines[index:index+3]) if lines[index].startswith('value=$(') else lines[index]

    def refuse(self, body, code):
        frame = b'' if code is None else ('rootful-prerequisite-code-v1:' + code + '\n').encode('ascii')
        return self.fixture.refusal(self.fixture.initial_selection() + '\n' + body,
                                    b'rootful-receiver-refused\n' + frame)

    def tuple_guard(self, rows, *, initial=True):
        value = rows if isinstance(rows, str) else '\n'.join(rows)
        body = 'packages=' + self.quote(value) + '\n' + self.line('[[ $packages == ') + '\nprintf forbidden\n'
        if not initial:
            body = 'initial_prerequisite=0\n' + body
        return body

    def test_package_predicates_keep_literals_and_queries_with_explicit_status(self):
        self.assertEqual(self.guard('value=$(u /usr/bin/jq --version)'),
                         "value=$(u /usr/bin/jq --version) || fail pkg-jq-ver\n[[ $value == jq-1.8.1 ]] || fail pkg-jq-ver\nvalue=''" )
        self.assertEqual(self.guard('value=$(SYSTEMD_COLORS=0 u /usr/lib/systemd/systemd --version)'),
                         "value=$(SYSTEMD_COLORS=0 u /usr/lib/systemd/systemd --version) || fail \"pkg-sd-q$?\"\n[[ $value == 'systemd 259 (259.9'* ]] || fail pkg-sd-ver\nvalue=''" )
        self.assertEqual(self.line('[[ $kernel == '),
                         '[[ $kernel == 7.2.7-200.fc44.x86_64 ]] || fail pkg-kernel')
        self.assertEqual(self.line('packages=$(u '),
            "packages=$(u /usr/bin/rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\\n' bash jq coreutils systemd podman skopeo crun conmon netavark aardvark-dns util-linux libcap) || fail")
        expected = "[[ $packages == $'" + '\\n'.join(self.ROWS) + "' ]] || package_tuple_failure"
        self.assertEqual(self.line('[[ $packages == '), expected)

    def test_each_display_and_kernel_predicate_reports_only_its_fixed_code(self):
        for prefix, value, code in (('value=$(u /usr/bin/jq --version)', 'wrong-private-jq', 'pkg-jq-ver'),
                                    ('value=$(SYSTEMD_COLORS=0 u /usr/lib/systemd/systemd --version)', 'wrong-private-systemd', 'pkg-sd-ver'),
                                    ('[[ $kernel == ', 'wrong-private-kernel', 'pkg-kernel')):
            with self.subTest(code=code):
                body = 'u() { printf "%s" ' + self.quote(value) + '; }\nkernel=' + self.quote(value) + '\n'
                self.refuse(body + self.guard(prefix) + '\nprintf forbidden\n', code)

    def test_each_of_twelve_exact_rows_has_its_own_first_mismatch_code(self):
        for index, code in enumerate(self.ROW_CODES):
            with self.subTest(index=index, code=code):
                rows = list(self.ROWS)
                rows[index] += '-private-unknown'
                self.refuse(self.tuple_guard(rows), code)

    def test_shape_is_checked_before_mismatches_and_never_echoes_private_bytes(self):
        cases = ('', '\n', self.ROWS[:-1], self.ROWS + ('private-extra-row',),
                 'private-value' * 400, '\n'.join(self.ROWS) + '\n',
                 ('private-first',) + self.ROWS[1:] + ('private-extra-row',))
        for rows in cases:
            with self.subTest(size=len(rows)):
                result = self.refuse(self.tuple_guard(rows), 'rpm-shape')
                self.assertNotIn(b'private', result.stderr)
                self.assertEqual((self.fixture.root/'state/poison').read_bytes(), b'poisoned\n')
        rows = list(self.ROWS)
        overhead = len('\n'.join(rows)) - len(rows[0])
        rows[0] = 'x' * (4096-overhead)
        self.refuse(self.tuple_guard(rows), 'rpm-bash')
        rows[0] += 'x'
        self.refuse(self.tuple_guard(rows), 'rpm-shape')

    def test_reordered_duplicate_and_multiple_mismatches_choose_first_expected_row(self):
        rows = list(self.ROWS)
        rows[0], rows[1] = rows[1], rows[0]
        self.refuse(self.tuple_guard(rows), 'rpm-bash')
        rows = list(self.ROWS)
        rows[1] = rows[0]
        self.refuse(self.tuple_guard(rows), 'rpm-jq')
        rows = list(self.ROWS)
        rows[3], rows[10] = 'private-one', 'private-two'
        self.refuse(self.tuple_guard(rows), 'rpm-systemd')
        rows[0] = '$(printf private-value > unexpected-child)'
        self.refuse(self.tuple_guard(rows), 'rpm-bash')
        self.assertFalse((self.fixture.root/'unexpected-child').exists())

    def test_exact_tuple_passes_without_calling_failure_helper_or_emitting_frames(self):
        stub = 'u() { printf "%s\\n" ' + self.quote('\n'.join(self.ROWS)) + '; }\n'
        body = (stub + 'package_tuple_failure() { printf unexpected-helper; exit 99; }\n'
                + self.line('packages=$(u ') + '\n' + self.line('[[ $packages == ') + '\nprintf accepted\n')
        self.assertEqual(self.fixture.run_body(self.fixture.initial_selection()+'\n'+body), b'accepted')

    def test_failed_rpm_query_refuses_explicitly_without_inventing_a_package_code(self):
        body = ('u() { printf q >> "$root/query-calls"; return 17; }\n'
                + self.line('packages=$(u ') + '\n' + self.line('[[ $packages == ') + '\nprintf forbidden\n')
        result = self.fixture.child(self.fixture.initial_selection()+'\n'+body).finish()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b'rootful-receiver-refused\n'))
        self.assertEqual((self.fixture.root/'query-calls').read_bytes(), b'q')
        self.assertEqual((self.fixture.root/'state/poison').read_bytes(), b'poisoned\n')

    def test_outside_initial_or_cleanup_refuses_generically_before_scanning_unset_value(self):
        for before in ('initial_prerequisite=0', 'mode=cleanup'):
            with self.subTest(before=before):
                self.refuse(before+'\nunset packages\npackage_tuple_failure\nprintf forbidden\n', None)
        for code in FINE_PACKAGE_CODES:
            with self.subTest(code=code):
                self.refuse('initial_prerequisite=0\nfail '+code+'\n', None)

    def test_failure_helper_is_builtin_only_bounded_and_has_no_success_fallthrough(self):
        helper = self.source.split('package_tuple_failure() {\n', 1)[1].split('\n}\n', 1)[0]
        self.assertIn('for ((i = 0; i < 13; i++)); do', helper)
        self.assertIn('((${#packages} <= 4096)) || fail rpm-shape', helper)
        self.assertLess(helper.index('|| fail packages'), helper.index('${#packages}'))
        for prohibited in ('u /', '$(', '<<<', '<(', '>(', 'eval ', 'exec ', 'read ', 'mapfile ', 'printf ', 'echo '):
            # The one arithmetic expansion has no command substitution.
            checked = helper.replace('$((i + 1))', '')
            self.assertNotIn(prohibited, checked)
        self.assertTrue(helper.rstrip().endswith('esac'))
        self.refuse("packages=" + self.quote('\n'.join(self.ROWS)) + '\npackage_tuple_failure\nprintf forbidden\n', 'rpm-shape')

    def test_all_fine_codes_are_short_closed_and_bad_code_never_echoes(self):
        for code in FINE_PACKAGE_CODES:
            with self.subTest(code=code):
                self.assertLessEqual(len(('rootful-prerequisite-code-v1:'+code+'\n').encode('ascii')), 44)
                self.refuse('fail '+code+'\n', code)
        self.refuse("fail 'rpm-private-value'\n", None)
        self.refuse("fail rpm-bash extra-private-value\n", None)



class SystemdColorQueryControls(unittest.TestCase):
    """Project only the final utility exec; real source credit helpers stay active."""
    GOLDEN = 'systemd 259 (259.9-1.fc44)\n+PAM +AUDIT +SELINUX\n'

    def setUp(self):
        self.fixture = BashProtocolControls()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        projection = '  "$@"\n}\nu() {'
        self.assertEqual(self.fixture.definitions.count(projection), 1)
        self.fixture.definitions = self.fixture.definitions.replace(projection, '  projected_utility "$@"\n}\nu() {')
        lines = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).splitlines()
        index = next(i for i, line in enumerate(lines)
                     if line.startswith('value=$(SYSTEMD_COLORS=0 u /usr/lib/systemd/systemd --version)'))
        self.query = '\n'.join(lines[index:index+3])

    def quote(self, value):
        return "'" + value.replace("'", "'\\''") + "'"

    def exercise(self, inherited, *, display=GOLDEN, status=0, adjacent=False):
        environment = 'unset SYSTEMD_COLORS\n' if inherited is None else 'export SYSTEMD_COLORS='+self.quote(inherited)+'\n'
        body = (environment + 'export SYSTEMD_URLIFY=unchanged\nmode=work\n'
                + 'display='+self.quote(display)+'\nprojected_status='+str(status)+'\n'
                + '''projected_utility() {
  printf '%s|%s|%s|%s|%s\n' "${SYSTEMD_COLORS-unset}" "$#" "$1" "${2-}" "$SYSTEMD_URLIFY" >> "$root/calls"
  if [[ $1 == /usr/lib/systemd/systemd ]]; then
    [[ ${SYSTEMD_COLORS-unset} == 0 ]] || { printf forbidden-color-contract; return 99; }
    printf '%s' "$display"
    return "$projected_status"
  fi
  printf adjacent
}
''')
        if adjacent:
            body += 'u /usr/bin/jq --version > /dev/null\n'
        body += self.query+'\n'
        if adjacent:
            body += 'u /usr/bin/jq --version > /dev/null\n'
        body += '[[ ${SYSTEMD_COLORS-unset} == '+self.quote('unset' if inherited is None else inherited)+' ]]\nprintf accepted\n'
        result = self.fixture.child(self.fixture.initial_selection()+'\n'+body).finish()
        calls = (self.fixture.root/'calls').read_text().splitlines()
        credits = sorted(path.name for path in (self.fixture.root/'state/credits').iterdir())
        return result, calls, credits

    def test_inherited_absent_zero_one_and256_are_overridden_for_exact_single_query_and_charge(self):
        for inherited in (None, '0', '1', '256'):
            with self.subTest(inherited=inherited):
                # Each run owns a fresh ledger; no credit reset is part of production.
                fresh = SystemdColorQueryControls()
                fresh.setUp()
                try:
                    result, calls, credits = fresh.exercise(inherited)
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'accepted', b''))
                    self.assertEqual(calls, ['0|2|/usr/lib/systemd/systemd|--version|unchanged'])
                    self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])
                finally:
                    fresh.doCleanups()

    def test_scoped_override_does_not_leak_to_outer_or_adjacent_queries(self):
        result, calls, credits = self.exercise('256', adjacent=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'accepted', b''))
        self.assertEqual(calls, ['256|2|/usr/bin/jq|--version|unchanged',
                                '0|2|/usr/lib/systemd/systemd|--version|unchanged',
                                '256|2|/usr/bin/jq|--version|unchanged'])
        self.assertEqual(credits, ['used.utility-work.0', 'used.utility-work.1', 'used.utility-work.2',
                                   'utility-work.0', 'utility-work.1', 'utility-work.2'])

    def test_wrong_major_patch_prefix_empty_and_unexpected_ansi_still_refuse(self):
        displays = ('systemd 260 (260.1-1.fc44)', 'systemd 259 (259.8-1.fc44)',
                    'systemd 259 (v259.9-1.fc44)', 'prefix systemd 259 (259.9-1.fc44)',
                    '', '\x1b[1msystemd 259 (259.9-1.fc44)\x1b[0m')
        for display in displays:
            with self.subTest(display=display):
                fresh = SystemdColorQueryControls()
                fresh.setUp()
                try:
                    result, calls, credits = fresh.exercise('1', display=display)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                        (1, b'', b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-ver\n'))
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])
                    self.assertEqual((fresh.fixture.root/'state/poison').read_bytes(), b'poisoned\n')
                finally:
                    fresh.doCleanups()

    def test_nonzero_empty_query_still_refuses_with_same_accounting_and_no_continuation(self):
        result, calls, credits = self.exercise('256', display='', status=17)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, b'', b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-q17\n'))
        self.assertEqual(calls, ['0|2|/usr/lib/systemd/systemd|--version|unchanged'])
        self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])

    def test_nonzero_matching_query_refuses_before_continuation(self):
        result, calls, credits = self.exercise('1', status=17)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, b'', b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-q17\n'))
        self.assertEqual(calls, ['0|2|/usr/lib/systemd/systemd|--version|unchanged'])
        self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])

    def test_source_change_is_one_temporary_assignment_without_new_argv_or_global_environment(self):
        self.assertEqual(self.query,
            "value=$(SYSTEMD_COLORS=0 u /usr/lib/systemd/systemd --version) || fail \"pkg-sd-q$?\"\n[[ $value == 'systemd 259 (259.9'* ]] || fail pkg-sd-ver\nvalue=''")
        source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        source = receiver_before_node_monochrome(receiver_before_poll_diagnostic(source))
        self.assertEqual(source.count('SYSTEMD_COLORS'), 1)
        self.assertNotIn('SYSTEMD_URLIFY', source)
        self.assertNotIn('export SYSTEMD_COLORS', source)
        self.assertNotIn('/usr/bin/env SYSTEMD_COLORS', source)
        self.assertEqual(source.count('u /usr/lib/systemd/systemd --version'), 1)


    def test_canonical_query_failure_has_one_charge_and_no_alias_fallback(self):
        result, calls, credits = self.exercise('256', status=127)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
            (1, b'', b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-q127\n'))
        self.assertEqual(calls, ['0|2|/usr/lib/systemd/systemd|--version|unchanged'])
        self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        self.assertEqual(source.count('/usr/lib/systemd/systemd'), 3)
        self.assertNotIn('/usr/bin/systemd', source)
        self.assertEqual((self.fixture.root/'state/poison').read_bytes(), b'poisoned\n')

    def test_both_closed_utility_gates_refuse_aliases_before_any_launch_or_credit(self):
        for gate in ('u', 'utility_launch utility-work.0'):
            for path in ('/usr/bin/systemd', '/bin/systemd', '/lib/systemd/systemd',
                         '/usr/local/lib/systemd/systemd'):
                with self.subTest(gate=gate, path=path):
                    fresh = SystemdColorQueryControls()
                    fresh.setUp()
                    try:
                        body = (fresh.fixture.initial_selection()+'\n'
                            +'projected_utility() { printf forbidden-launch; }\n'
                            +gate+' '+path+' --version\nprintf forbidden\n')
                        fresh.fixture.refusal(body, b'rootful-receiver-refused\n')
                        self.assertEqual(list((fresh.fixture.root/'state/credits').iterdir()), [])
                        self.assertEqual((fresh.fixture.root/'state/poison').read_bytes(), b'poisoned\n')
                    finally:
                        fresh.doCleanups()



class UtilityStatusRefusalControls(unittest.TestCase):
    """Every projection keeps actual u/token logic and replaces only final exec."""
    def setUp(self):
        self.fixture = BashProtocolControls()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        original = '  "$@"\n}\nu() {'
        self.assertEqual(self.fixture.definitions.count(original), 1)
        self.fixture.definitions = self.fixture.definitions.replace(original, '  projected_utility "$@"\n}\nu() {')
        self.lines = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).splitlines()

    def quote(self, value):
        return "'" + value.replace("'", "'\\''") + "'"

    def selected(self, prefix, *, occurrence=0, inline=False):
        indices = [i for i, line in enumerate(self.lines) if line.strip().startswith(prefix)]
        index = indices[occurrence]
        return '\n'.join(line.strip() for line in self.lines[index:index+(3 if inline else 1)])

    def exercise(self, snippet, outputs, statuses, *, conditional=False):
        root = self.fixture.root
        body = ('mode=work\nnamespace=9:10\nentry='+self.quote(str(root/'entry'))+'\n'
                +'out='+self.quote(str(root/'captures/work.0.out'))+'\npay=(u)\n'
                +'path="$out"\nerr="$root/captures/work.0.err"\nkind_sha='+('a'*64)+'\nkubectl_sha='+('b'*64)+'\narchive_sha='+('c'*64)
                +'\nmanifest_sha='+('d'*64)+'\nimage_id='+('e'*64)+'\nfixture_sha='+('f'*64)+'\n'
                +'outputs=('+' '.join(self.quote(value) for value in outputs)+')\n'
                +'statuses=('+' '.join(str(value) for value in statuses)+')\n'
                +'''projected_utility() {
  local index=0
  if [[ -f $root/index ]]; then read -r index < "$root/index"; fi
  printf '%s\n' "$((index + 1))" > "$root/index"
  printf '%s\n' "$1" >> "$root/calls"
  printf '%s\\0' "$@" >> "$root/argv"
  printf '%s' "${outputs[$index]}"
  return "${statuses[$index]}"
}
selected_status_path() {
'''+snippet+'''
  printf effect > "$root/effect"
}
''')
        body += 'if selected_status_path "$out"; then printf accepted; fi\n' if conditional else 'selected_status_path "$out"\nprintf accepted\n'
        result = self.fixture.child(self.fixture.initial_selection()+'\n'+body).finish()
        calls = (root/'calls').read_text().splitlines()
        argv = (root/'argv').read_bytes().split(b'\0')[:-1]
        credits = sorted(path.name for path in (root/'state/credits').iterdir())
        return result, calls, argv, credits, (root/'effect').exists()

    def inline_specs(self):
        root = self.fixture.root
        stage_path = str(root/'stage')
        out = str(root/'captures/work.0.out')
        return (
            ('size=$(u /usr/bin/stat -c %s "$root/state/request.extra")', '0', None, 0),
            ('size=$(u /usr/bin/stat -c %s "$root/state/prerequisite.extra")', '0', 'eof', 0),
            ('value=$(u /usr/bin/stat -Lc', '9:10', 'namespace', 0),
            ('value=$(u /usr/bin/readlink -f', '/sys/devices/pci0000/virtio0/block/vda', 'block', 0),
            ('value=$(u /usr/bin/stat -c', '0:0:755', 'mapper', 0),
            ('value=$(u /usr/bin/stat -c', 'a:ec:0:0:600:1', 'mapper', 1),
            ('value=$(u /usr/bin/jq --version)', 'jq-1.8.1', 'pkg-jq-ver', 0),
            ('value=$(SYSTEMD_COLORS=0 u /usr/lib/systemd/systemd --version)', SystemdColorQueryControls.GOLDEN, 'pkg-sd-ver', 0),
            ('value=$(u /usr/bin/sha256sum "$stage/kind")', 'a'*64+'  '+stage_path+'/kind', None, 0),
            ('value=$(u /usr/bin/sha256sum "$stage/kubectl")', 'b'*64+'  '+stage_path+'/kubectl', None, 0),
            ('value=$(u /usr/bin/sha256sum "$stage/node.oci.tar")', 'c'*64+'  '+stage_path+'/node.oci.tar', None, 0),
            ('value=$(u /usr/bin/sha256sum "$out")', 'd'*64+'  '+out, None, 0),
            ('value=$(u /usr/bin/sha256sum "$out")', 'e'*64+'  '+out, None, 1),
            ('value=$(u /usr/bin/sha256sum "$root/deployment.json")', 'f'*64+'  '+str(root/'deployment.json'), None, 0),
        )

    def test_all14_former_inline_queries_require_status_and_unchanged_text_predicate(self):
        self.assertEqual(len(self.inline_specs()), 14)
        for site in range(14):
            for status, matching in ((0, True), (0, False), (17, True), (17, False)):
                with self.subTest(site=site, status=status, matching=matching):
                    fresh = UtilityStatusRefusalControls()
                    fresh.setUp()
                    try:
                        prefix, expected, code, occurrence = fresh.inline_specs()[site]
                        snippet = fresh.selected(prefix, occurrence=occurrence, inline=True)
                        result, calls, _argv, credits, effect = fresh.exercise(snippet,
                            [expected if matching else 'private-wrong-value'], [status], conditional=True)
                        success = status == 0 and matching
                        reported_code = 'pkg-sd-q'+str(status) if code == 'pkg-sd-ver' and status != 0 else code
                        frame = b'' if reported_code is None else ('rootful-prerequisite-code-v1:'+reported_code+'\n').encode('ascii')
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                            (0, b'accepted', b'') if success else (1, b'', b'rootful-receiver-refused\n'+frame))
                        self.assertEqual(effect, success)
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])
                        self.assertNotIn(b'private-wrong-value', result.stderr)
                    finally:
                        fresh.doCleanups()

    def captured_specs(self):
        return (
            'size=$(u /usr/bin/stat -c %s "$root/state/request.in")',
            'namespace=$(u /usr/bin/stat -Lc', 'fs_values=$(u /usr/bin/stat -f',
            'actual=$(u /usr/bin/jq -er', 'size=$("${pay[@]}" /usr/bin/stat -c %s "$path")',
            'sha=$("${pay[@]}" /usr/bin/sha256sum "$path")', 'encoded=$("${pay[@]}" /usr/bin/base64 -w0',
            'values=$(u /usr/bin/jq -er', 'value=$(u /usr/bin/stat -c', 'packages=$(u /usr/bin/rpm',
            'value=$(u /usr/bin/stat -c', 'spec_sha=$(u /usr/bin/sha256sum', 'node_pid=$(u /usr/bin/jq -er',
        )

    def test_all13_existing_assignments_fail_explicitly_before_later_effects_even_in_conditional_callers(self):
        self.assertEqual(len(self.captured_specs()), 13)
        for site, prefix in enumerate(self.captured_specs()):
            # First two value/stat occurrences are mapper queries; metadata sites are third/fourth.
            occurrence = 2 if site == 8 else 3 if site == 10 else 0
            for status, output in ((0, 'valid-value'), (0, 'private-invalid-value'), (17, 'valid-value'), (17, 'private-invalid-value')):
                with self.subTest(site=site, status=status, output=output):
                    fresh = UtilityStatusRefusalControls()
                    fresh.setUp()
                    try:
                        snippet = fresh.selected(prefix, occurrence=occurrence)
                        self.assertTrue(snippet.endswith(' || fail'))
                        result, calls, _argv, credits, effect = fresh.exercise(snippet, [output], [status], conditional=True)
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                            (0, b'accepted', b'') if status == 0 else (1, b'', b'rootful-receiver-refused\n'))
                        self.assertEqual(effect, status == 0)
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])
                    finally:
                        fresh.doCleanups()

    def test_four_standalone_calls_refuse_nonzero_before_following_effects(self):
        specs = (('u /usr/bin/cat "$out"', 0), ('u /usr/bin/cat "$err"', 0),
                 ('u /usr/bin/mkdir -m 700 "$root/config"', 0), ('u /usr/bin/cat "$out"', 1))
        for prefix, occurrence in specs:
            for status in (0, 17):
                with self.subTest(prefix=prefix, occurrence=occurrence, status=status):
                    fresh = UtilityStatusRefusalControls()
                    fresh.setUp()
                    try:
                        snippet = fresh.selected(prefix, occurrence=occurrence)
                        result, calls, _argv, credits, effect = fresh.exercise(snippet, [''], [status], conditional=True)
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                            (0, b'accepted', b'') if status == 0 else (1, b'', b'rootful-receiver-refused\n'))
                        self.assertEqual(effect, status == 0)
                        self.assertEqual(len(calls), 1)
                        self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])
                    finally:
                        fresh.doCleanups()

    def test_three_hash_queries_keep_lazy_order_and_stop_on_first_status_or_text_failure(self):
        for failure in (None, 0, 1, 2):
            for bad_status in (False, True):
                with self.subTest(failure=failure, bad_status=bad_status):
                    fresh = UtilityStatusRefusalControls()
                    fresh.setUp()
                    try:
                        specs = fresh.inline_specs()[8:11]
                        snippet = '\n'.join(fresh.selected(prefix, inline=True) for prefix, _value, _code, _occ in specs)
                        outputs = [row[1] for row in specs]
                        statuses = [0, 0, 0]
                        if failure is not None:
                            if bad_status:
                                statuses[failure] = 17
                            else:
                                outputs[failure] = 'private-wrong-hash'
                        result, calls, argv, credits, effect = fresh.exercise(snippet, outputs, statuses, conditional=True)
                        count = 3 if failure is None else failure+1
                        self.assertEqual(len(calls), count)
                        self.assertEqual(len(credits), count*2)
                        expected_argv = []
                        for name in ('kind', 'kubectl', 'node.oci.tar')[:count]:
                            expected_argv.extend([b'/usr/bin/sha256sum', str(fresh.fixture.root/'stage'/name).encode()])
                        self.assertEqual(argv, expected_argv)
                        self.assertEqual((result.returncode, result.stdout, result.stderr),
                            (0, b'accepted', b'') if failure is None else (1, b'', b'rootful-receiver-refused\n'))
                        self.assertEqual(effect, failure is None)
                    finally:
                        fresh.doCleanups()



class SystemdQueryDiagnosticControls(unittest.TestCase):
    def test_new_code_uses_existing_initial_gate_and_stays_quiet_for_other_routes(self):
        cases = ((None, None, True), ('provider', None, False), ('logs-child', None, False),
                 ('unknown', None, False), (None, 'initial_prerequisite=0', False),
                 (None, 'mode=cleanup', False))
        for route, reset, reports in cases:
            with self.subTest(route=route, reset=reset):
                fixture = BashProtocolControls()
                fixture.setUp()
                try:
                    body = ('set -- '+route+'\n' if route else '')+fixture.initial_selection()+'\n'
                    if reset:
                        body += reset+'\n'
                    result = fixture.child(body+'fail pkg-sd-query\n').finish()
                    expected = b'rootful-receiver-refused\n'
                    if reports:
                        expected += b'rootful-prerequisite-code-v1:pkg-sd-query\n'
                    self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', expected))
                finally:
                    fixture.doCleanups()
        fixture = BashProtocolControls()
        fixture.setUp()
        try:
            for arguments in ('pkg-sd-query-private', 'pkg-sd-query extra-private'):
                result = fixture.child(fixture.initial_selection()+'\nfail '+arguments+'\n').finish()
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (1, b'', b'rootful-receiver-refused\n'))
        finally:
            fixture.doCleanups()



class SystemdQueryStatusDiagnosticControls(unittest.TestCase):
    def test_all255_decimal_status_codes_have_exact_short_frames_poison_and_final1(self):
        fixture = BashProtocolControls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for status in range(1, 256):
            with self.subTest(status=status):
                code = 'pkg-sd-q'+str(status)
                frame = ('rootful-prerequisite-code-v1:'+code+'\n').encode('ascii')
                result = fixture.child(fixture.initial_selection()+'\nfail '+code+'\n').finish()
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (1, b'', b'rootful-receiver-refused\n'+frame))
                self.assertLessEqual(len(result.stderr), 66)
                self.assertEqual((fixture.root/'state/poison').read_bytes(), b'poisoned\n')

    def test_invalid_decimal_and_extra_arguments_never_echo_or_gain_a_frame(self):
        fixture = BashProtocolControls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        quote = lambda value: "'"+value.replace("'", "'\\''")+"'"
        invalid = ('0', '00', '01', '001', '0255', '-1', '+1', '256', '999', '1000', '',
                   ' 1', '1 ', '\t1', '1\n', '1\r', '١', '１', '1x', '1-private',
                   '1; printf private-value', '$(printf private-value)', '1/2')
        for value in invalid:
            with self.subTest(value=value):
                result = fixture.child(fixture.initial_selection()+'\nfail '+quote('pkg-sd-q'+value)+'\n').finish()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b'rootful-receiver-refused\n'))
        result = fixture.child(fixture.initial_selection()+'\nfail pkg-sd-q1 private-extra\n').finish()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b'rootful-receiver-refused\n'))

    def test_immediate_assignment_status_is_preserved_for_representative_values_without_more_queries(self):
        for status in (0, 1, 126, 127, 128, 255):
            for matching in (True, False):
                with self.subTest(status=status, matching=matching):
                    fixture = SystemdColorQueryControls()
                    fixture.setUp()
                    try:
                        result, calls, credits = fixture.exercise('256', status=status,
                            display=fixture.GOLDEN if matching else 'private-wrong-version')
                        if status:
                            expected = (1, b'', ('rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-q'+str(status)+'\n').encode('ascii'))
                        elif matching:
                            expected = (0, b'accepted', b'')
                        else:
                            expected = (1, b'', b'rootful-receiver-refused\nrootful-prerequisite-code-v1:pkg-sd-ver\n')
                        self.assertEqual((result.returncode, result.stdout, result.stderr), expected)
                        self.assertEqual(calls, ['0|2|/usr/lib/systemd/systemd|--version|unchanged'])
                        self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])
                    finally:
                        fixture.doCleanups()

    def test_numeric_frames_remain_initial_work_only_for_every_other_route(self):
        for status in (1, 255):
            for route in ('provider', 'logs-child', 'unknown', 'later', 'phase', 'cleanup'):
                with self.subTest(status=status, route=route):
                    fixture = BashProtocolControls()
                    fixture.setUp()
                    try:
                        body = ''
                        if route in ('provider', 'logs-child', 'unknown'):
                            body += 'set -- '+route+'\n'
                        if route == 'phase':
                            (fixture.root/'state/phase').write_bytes(b'existing-phase\n')
                        body += fixture.initial_selection()+'\n'
                        if route == 'later':
                            body += 'initial_prerequisite=0\n'
                        elif route == 'cleanup':
                            body += 'mode=cleanup\n'
                        result = fixture.child(body+'fail pkg-sd-q'+str(status)+'\n').finish()
                        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b'rootful-receiver-refused\n'))
                        self.assertEqual((fixture.root/'state/poison').exists(), route != 'cleanup')
                    finally:
                        fixture.doCleanups()

    def test_source_status_expansion_is_immediate_and_grammar_uses_only_literal_ascii_sets(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        query = 'value=$(SYSTEMD_COLORS=0 u /usr/lib/systemd/systemd --version) || fail "pkg-sd-q$?"'
        self.assertEqual(source.count(query), 1)
        self.assertEqual(source.count('"pkg-sd-q$?"'), 1)
        self.assertIn(query+"\n[[ $value == 'systemd 259 (259.9'* ]] || fail pkg-sd-ver\nvalue=''", source)
        grammar = 'pkg-sd-q[123456789] | pkg-sd-q[123456789][0123456789] | pkg-sd-q1[0123456789][0123456789] | pkg-sd-q2[01234][0123456789] | pkg-sd-q25[012345]'
        self.assertEqual(source.count(grammar), 1)
        self.assertNotIn('pkg-sd-q[1-9]', source)



class RootfulBootEpochControls(unittest.TestCase):
    """Owned scalar/file projections; no guest, SSH or runtime tool executes."""
    BOOT = '00000000-1111-2222-3333-444444444444'
    OTHER_BOOT = '99999999-1111-2222-3333-444444444444'

    def fixture(self):
        fixture = BashProtocolControls(); fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.definitions = fixture.definitions.replace('/run/kubernetes-lens-rootful', str(fixture.root/'runtime'))
        fixture.definitions = fixture.definitions.replace('in / /var /var/lib /run /usr /usr/bin', 'in \"$root\"')
        fixture.definitions = fixture.definitions.replace('-O /usr/bin/cmp', '-O \"$stage/lock\"')
        fixture.definitions = fixture.definitions.replace('-O /usr/bin/flock', '-O "$stage/lock"')
        stage_dir = fixture.root/'stage'; stage_dir.mkdir()
        for name in ('table', 'plan.json', 'checks.sha256', 'receiver', 'lock',
                     'stage-kind.header', 'stage-kubectl.header', 'stage-node-oci.header'):
            (stage_dir/name).write_bytes(b'private-source\n'); (stage_dir/name).chmod(0o600)
        return fixture

    def context(self, boot=None):
        return ('rootful_admitted=0\nmode=work\nprofile=legacy-1.20.15\nboot='
            +(boot or self.BOOT)+'\n')

    def snapshot(self, fixture):
        import os
        result = {}
        for scope in ('state', 'captures', 'stage'):
            for path in (fixture.root/scope).rglob('*'):
                key = str(path.relative_to(fixture.root))
                result[key] = ('link', os.readlink(path)) if path.is_symlink() else (
                    'directory' if path.is_dir() else path.read_bytes(), path.lstat().st_mode & 0o777)
        return result

    def record(self, fixture, name, raw):
        path = fixture.root/name; path.write_bytes(raw); path.chmod(0o600)

    def executed_state(self, fixture):
        prefix = 'a'*32+' '+'b'*64+' '+self.BOOT
        for name, value in [('state/prerequisite-claimed', prefix), ('state/phase', prefix+' staged-required'),
                            ('state/mode', 'work'), ('state/deadlines', '1000 1120'),
                            ('stage/state', 'v1 '+'a'*32+' '+'b'*64+' legacy-1.20.15 '+self.BOOT+' complete 3')]:
            self.record(fixture, name, (value+'\n').encode())

    def test_prerequisite_claim_inflight_ready0_then_success_are_one_time_and_one_charged_lock(self):
        fixture = self.fixture()
        body = self.context()+'''rootful_boot_guard prerequisite-v1
[[ $rootful_admitted == 1 && ! -e $stage/state ]]
rootful_stage_seed
[[ -f $stage/state ]]
printf 'work\n' > "$root/state/mode"
printf '1000 1120\n' > "$root/state/deadlines"
rootful_publish_prerequisite
[[ -f $root/state/phase && $record_guard_fuel == 0 ]]
printf admitted
'''
        self.assertEqual(fixture.run_body(body), b'admitted')
        credits = sorted(path.name for path in (fixture.root/'state/credits').iterdir())
        self.assertEqual(credits, ['used.utility-work.0', 'utility-work.0'])
        before = self.snapshot(fixture)
        result = fixture.child(self.context()+'rootful_boot_guard prerequisite-v1\nprintf forbidden\n').finish()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b'rootful-receiver-refused\n'))
        self.assertEqual(self.snapshot(fixture), before)  # Lost ACK cannot reinitialize or poison owner.

    def test_execution_missing_partial_foreign_oldboot_unknown_and_duplicate_refuse_without_effects(self):
        cases = [('missing', name) for name in ('state/prerequisite-claimed', 'state/phase', 'state/mode',
                                               'state/deadlines', 'stage/state')]
        cases += [('malformed', b''), ('malformed', b'partial'), ('malformed', b'work\n\n'),
                  ('malformed', b'work\x00\n'), ('malformed', b'x'*257), ('oldboot', None),
                  ('duplicate', None), ('unknown', None), ('all-missing', None)]
        for kind, value in cases:
            with self.subTest(kind=kind, value=value):
                fixture = self.fixture(); self.executed_state(fixture)
                intent, boot = 'execution-v1', self.BOOT
                if kind == 'missing': (fixture.root/value).unlink()
                elif kind == 'malformed': self.record(fixture, 'state/mode', value)
                elif kind == 'oldboot': boot = self.OTHER_BOOT
                elif kind == 'duplicate': self.record(fixture, 'state/execution-claimed', b'partial\n')
                elif kind == 'unknown': intent = 'unknown-role'
                elif kind == 'all-missing':
                    for path in (fixture.root/'state').iterdir():
                        if path.is_file(): path.unlink()
                    (fixture.root/'stage/state').unlink()
                before = self.snapshot(fixture)
                result = fixture.child(self.context(boot)+'rootful_boot_guard '+intent+'\nprintf forbidden-preflight\n').finish()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b'rootful-receiver-refused\n'))
                self.assertEqual(self.snapshot(fixture), before)

    def test_symlink_prefix_refuses_before_claim_or_credit(self):
        for name in ('state/credits', 'captures', 'stage', 'state'):
            with self.subTest(prefix=name):
                fixture=self.fixture(); path=fixture.root/name; moved=fixture.root/('saved-'+name.replace('/','-'))
                path.rename(moved); path.symlink_to(moved,target_is_directory=True)
                before=self.snapshot(fixture)
                result=fixture.child(self.context()+'rootful_boot_guard prerequisite-v1\nprintf forbidden\n').finish()
                self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
                self.assertEqual(self.snapshot(fixture),before)
                self.assertFalse((moved/'prerequisite-claimed').exists())

    def test_every_early_record_rejects_extra_line_trailing_bytes_nul_without_rewriting(self):
        for name in ('state/prerequisite-claimed', 'state/phase', 'state/mode', 'state/deadlines', 'stage/state'):
            for suffix in (b'\n', b'trailing', b'\x00', b'\x00\n', b'extra\n'):
                with self.subTest(record=name, suffix=suffix):
                    fixture = self.fixture(); self.executed_state(fixture)
                    original = (fixture.root/name).read_bytes()
                    self.record(fixture, name, original+suffix)
                    before = self.snapshot(fixture)
                    result = fixture.child(self.context()+'rootful_boot_guard execution-v1\nprintf forbidden\n').finish()
                    self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
                    self.assertEqual(self.snapshot(fixture),before)
                    self.assertEqual((fixture.root/name).read_bytes(),original+suffix)

    def test_valid_execution_reuses_old_records_and_guard_precedes_first_preflight(self):
        fixture = self.fixture(); self.executed_state(fixture); before = self.snapshot(fixture)
        self.assertEqual(fixture.run_body(self.context()+'rootful_boot_guard execution-v1\n[[ $rootful_admitted == 1 ]]\nprintf admitted\n'), b'admitted')
        after=self.snapshot(fixture)
        self.assertEqual(after.pop('state/execution-claimed'),(('a'*32+' '+'b'*64+' '+self.BOOT+'\n').encode(),0o600))
        self.assertEqual(after, before)
        entry = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('# Entry: pure-control tests', 1)[1]
        self.assertLess(entry.index('rootful_boot_guard "$rootful_intent"'), entry.index('u /usr/bin/sha256sum'))
        self.assertNotIn('new_record', entry.split('rootful_boot_guard "$rootful_intent"', 1)[0])

    def test_two_execution_contenders_keep_one_claim_and_loser_cannot_poison_or_debit(self):
        fixture=self.fixture(); self.executed_state(fixture);before=self.snapshot(fixture)
        first=fixture.child(self.context()+'rootful_boot_guard execution-v1\nprintf claimed\n')
        second=fixture.child(self.context()+'rootful_boot_guard execution-v1\nprintf claimed\n')
        results=(first.finish(),second.finish())
        self.assertEqual(sorted(result.returncode for result in results),[0,1])
        self.assertEqual(sorted(result.stdout for result in results),[b'',b'claimed'])
        self.assertEqual(sorted(result.stderr for result in results),[b'',b'rootful-receiver-refused\n'])
        after=self.snapshot(fixture);claim=after.pop('state/execution-claimed')
        self.assertEqual(claim,(('a'*32+' '+'b'*64+' '+self.BOOT+'\n').encode(),0o600))
        self.assertEqual(after,before)

    def test_partial_claim_cursor_payload_and_publication_cuts_never_become_pristine(self):
        for name in ('state/prerequisite-claimed', 'state/phase', 'state/mode', 'state/credits/work.0',
                     'captures/private-prefix', 'stage/state', 'stage/state.new', 'stage/header.in',
                     'stage/payload.in', 'stage/kind', 'stage/header.0', 'stage/extra.0'):
            with self.subTest(path=name):
                fixture = self.fixture(); self.record(fixture, name, b'partial')
                before = self.snapshot(fixture)
                result = fixture.child(self.context()+'rootful_boot_guard prerequisite-v1\nprintf forbidden\n').finish()
                self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b'rootful-receiver-refused\n'))
                self.assertEqual(self.snapshot(fixture), before)
        for cursor in (None, b'partial', b'v1 private\n'):
            fixture = self.fixture()
            fixture.run_body(self.context()+'rootful_boot_guard prerequisite-v1\nprintf claimed\n')
            if cursor is not None: self.record(fixture, 'stage/state', cursor)
            result = fixture.child(self.context()+'rootful_admitted=1\nrootful_publish_prerequisite\nprintf forbidden\n').finish()
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(b'staged-required', (fixture.root/'state/phase').read_bytes())

    def test_stage_lock_contention_is_nonblocking_charged_and_never_publishes_cursor(self):
        import fcntl
        fixture = self.fixture()
        with (fixture.root/'stage/lock').open('r+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = fixture.child(self.context()+'rootful_boot_guard prerequisite-v1\nrootful_stage_seed\nprintf forbidden\n').finish()
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, b'', b'rootful-receiver-refused\n'))
        self.assertFalse((fixture.root/'stage/state').exists())
        self.assertEqual(sorted(path.name for path in (fixture.root/'state/credits').iterdir()),
                         ['used.utility-work.0', 'utility-work.0'])
        self.assertIn(b'prerequisite-inflight\n', (fixture.root/'state/phase').read_bytes())
        self.assertEqual((fixture.root/'state/poison').read_bytes(), b'poisoned\n')


class MountPredicateControls(unittest.TestCase):
    def test_existing_scan_and_admission_distinguish_all_flags_without_raw_values(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        guard = source.split('  ((proc_ok == 1 && root_ok == 1)) || {', 1)[1].split('\n  }', 1)[0]
        guard = '((proc_ok == 1 && root_ok == 1)) || {'+guard+'\n}\n'
        for proc_ok, root_ok, code in ((1, 1, None), (0, 0, 'mount-both'),
                                       (0, 1, 'mount-proc'), (1, 0, 'mount-root'), (2, 0, 'mount')):
            with self.subTest(proc=proc_ok, root=root_ok):
                fixture = BashProtocolControls(); fixture.setUp()
                try:
                    result = fixture.child(fixture.initial_selection()+'\nproc_ok='+str(proc_ok)+'\nroot_ok='+str(root_ok)+'\n'+guard+'printf accepted\n').finish()
                    expected = b'' if code is None else b'rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code.encode()+b'\n'
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                        (0 if code is None else 1, b'accepted' if code is None else b'', expected))
                finally: fixture.doCleanups()


class ExactRecordFuelControls(unittest.TestCase):
    def fixture(self):
        controls=RootfulBootEpochControls(); fixture=controls.fixture();self.addCleanup(controls.doCleanups)
        return controls,fixture

    def test_independent_known_record_bytes_and_all_ten_prerequisite_comparisons(self):
        controls,fixture=self.fixture()
        result=fixture.run_body(controls.context()+'''rootful_boot_guard prerequisite-v1
printf '%s|' "$record_guard_fuel"
rootful_stage_seed
printf '%s|' "$record_guard_fuel"
printf 'work\n' > "$root/state/mode"
printf '1000 1120\n' > "$root/state/deadlines"
rootful_publish_prerequisite
printf '%s' "$record_guard_fuel"
''')
        self.assertEqual(result,b'9|6|0')
        prefix=('a'*32+' '+'b'*64+' '+controls.BOOT).encode()
        self.assertEqual((fixture.root/'state/phase').read_bytes(),prefix+b' staged-required\n')
        self.assertEqual((fixture.root/'stage/state').read_bytes(),b'v1 '+b'a'*32+b' '+b'b'*64+b' legacy-1.20.15 '+controls.BOOT.encode()+b' ready 0\n')
        self.assertEqual(len(list((fixture.root/'state/credits').glob('used.utility-work.*'))),1)

    def test_known_literal_refuses_no_lf_nul_extra_lf_suffix_and_257_bound(self):
        expected=b'literal-record\n'
        for raw in (expected[:-1],expected+b'\n',expected+b'\x00',expected+b'trailing',b'literal\x00-record\n',b'x'*257):
            controls,fixture=self.fixture();controls.record(fixture,'state/fixed',raw);before=controls.snapshot(fixture)
            result=fixture.child(controls.context()+'''record_guard_fuel=1
record_compare "$root/state/fixed" literal-record
printf forbidden
''').finish()
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
            self.assertEqual(controls.snapshot(fixture),before)
        controls,fixture=self.fixture();controls.record(fixture,'state/fixed',expected)
        self.assertEqual(fixture.run_body(controls.context()+'''record_guard_fuel=1
record_compare "$root/state/fixed" literal-record
printf '%s' "$record_guard_fuel"
'''),b'0')

    def test_matching_deadline_read_buffer_with_error_status_never_compares_or_claims(self):
        for status in (1,2):
            controls,fixture=self.fixture();controls.executed_state(fixture);before=controls.snapshot(fixture)
            fixture.definitions=fixture.definitions.replace('/usr/bin/cmp -s -- "$1" - <<< "$2"','projected_cmp -s -- "$1" - <<< "$2"')
            body=controls.context()+'''projected_cmp() { printf called > "$root/forbidden-cmp"; return 0; }
read() { value='1000 1120'; return STATUS; }
record_guard_fuel=5
closed_record "$root/state/deadlines"
printf forbidden
'''.replace('STATUS',str(status))
            result=fixture.child(body).finish()
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
            self.assertFalse((fixture.root/'forbidden-cmp').exists());self.assertEqual(controls.snapshot(fixture),before)

    def test_cmp_difference_io_signal_and_launch_failure_leave_early_state_unchanged(self):
        for status in (1,2,126,127,143):
            controls,fixture=self.fixture();controls.executed_state(fixture);before=controls.snapshot(fixture)
            fixture.definitions=fixture.definitions.replace('/usr/bin/cmp -s -- "$1" - <<< "$2"','projected_cmp -s -- "$1" - <<< "$2"')
            result=fixture.child(controls.context()+'projected_cmp() { return '+str(status)+'; }\nrootful_boot_guard execution-v1\nprintf forbidden\n').finish()
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
            self.assertEqual(controls.snapshot(fixture),before)
        controls,fixture=self.fixture();controls.executed_state(fixture);before=controls.snapshot(fixture)
        fixture.definitions=fixture.definitions.replace('/usr/bin/cmp -s -- "$1" - <<< "$2"','/usr/bin/cmp -s -- "$1" - 9< /definitely-absent-owned-record-test <<< "$2"')
        result=fixture.child(controls.context()+'rootful_boot_guard execution-v1\nprintf forbidden\n').finish()
        self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
        self.assertEqual(controls.snapshot(fixture),before)

    def test_zero_overrun_unknown_helper_and_purpose_fail_before_other_effects(self):
        for body in ('record_guard_fuel=0\nrecord_compare "$root/state/fixed" literal',
                     'record_guard_fuel=1\nrecord_compare "$root/state/fixed" literal\nrecord_compare "$root/state/fixed" literal',
                     'record_guard_fuel=1\nrecord_compare "$root/state/fixed" literal /usr/bin/true',
                     'rootful_boot_guard unknown'):
            controls,fixture=self.fixture();controls.record(fixture,'state/fixed',b'literal\n');before=controls.snapshot(fixture)
            result=fixture.child(controls.context()+body+'\nprintf forbidden\n').finish()
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
            self.assertEqual(controls.snapshot(fixture),before)

    def test_execution_all_five_records_then_one_claim_before_ordinary_debit(self):
        controls,fixture=self.fixture();controls.executed_state(fixture)
        fixture.definitions=fixture.definitions.replace('/usr/bin/cmp -s -- "$1" - <<< "$2"','projected_cmp -s -- "$1" - <<< "$2"')
        result=fixture.run_body(controls.context()+'''comparison_count=0
projected_cmp() {
  [[ ! -e $root/state/execution-claimed ]] || fail
  comparison_count=$((comparison_count + 1))
  /usr/bin/cmp "$@"
}
rootful_boot_guard execution-v1
[[ -f $root/state/execution-claimed && $rootful_admitted == 1 ]]
printf '%s|%s' "$comparison_count" "$record_guard_fuel"
''')
        self.assertEqual(result,b'5|0');self.assertEqual(list((fixture.root/'state/credits').iterdir()),[])

    def test_host_prepays_original24_and_consumes_each_purpose_once_before_failure(self):
        budget=vm.Budget(time.monotonic()+1800,120);original=budget.end,budget.work_end
        reservation=rootful.reserve(budget)
        self.assertEqual((reservation['utility_work'],reservation['record_guards_prepaid'],reservation['utility_cleanup']),(680,24,64))
        self.assertEqual(sum((680,24,64)),768)
        self.assertEqual((budget.commands_left,budget.output_left),(53,1048576))
        for phase,fuel in (('guest-info',10),('stage-kind',3),('stage-kubectl',3),('stage-node-oci',3),('rootful-kind',5)):
            self.assertEqual(rootful.consume_record_purpose(budget,phase),fuel)
            try: raise OSError('projected failed pre-child/spawn/ack')
            except OSError: pass
            with self.assertRaisesRegex(vm.Refusal,'rootful-record-purpose-replay'): rootful.consume_record_purpose(budget,phase)
            self.assertEqual(rootful.record_schedule(budget)['comparisons_attempted'],None)
            self.assertEqual(rootful.record_schedule(budget)['prepaid'],24)
        with self.assertRaises(vm.Refusal): rootful.consume_record_purpose(budget,'unknown')
        budget.commands_left=128
        with self.assertRaises(vm.Refusal): rootful.reserve(budget)
        self.assertEqual((budget.end,budget.work_end),original)
        returned=rootful.record_schedule(budget);returned['consumed_purposes'].clear()
        self.assertEqual(len(rootful.record_schedule(budget)['consumed_purposes']),5)

    def test_deadline_candidate_requires_complete_lf_and_exact_full_bytes(self):
        for raw in (b'1000 1120',b'1000 1120\x00\n',b'1000 1120\n\n',b'1000 1120\nextra',b'1'*257+b' 2\n'):
            controls,fixture=self.fixture();controls.executed_state(fixture)
            controls.record(fixture,'state/deadlines',raw);before=controls.snapshot(fixture)
            result=fixture.child(controls.context()+'rootful_boot_guard execution-v1\nprintf forbidden\n').finish()
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
            self.assertEqual(controls.snapshot(fixture),before)

    def test_result_separates24_actual_comparisons_after_admission_from_ordinary_ledger(self):
        fixture=RootfulHostControls();value=fixture.result()
        self.assertEqual(rootful.result(vm.encode(value)+b'\n',fixture.config())['utility_actions'],500)
        for changed in ({'record_guards':{'prepaid':24,'attempted':23}},
                        {'record_guards':{'prepaid':25,'attempted':24}},
                        {'utility_ledger_actions':500}, {'utility_actions':768,'utility_ledger_actions':745}):
            with self.assertRaises(vm.Refusal): rootful.result(vm.encode({**value,**changed})+b'\n',fixture.config())


class InventoryDestinationControls(unittest.TestCase):
    """Original inventory over private proc-shaped files; no host/guest proc reads."""
    SOURCE = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))

    def fixture(self):
        fixture=BashProtocolControls();fixture.setUp();self.addCleanup(fixture.doCleanups)
        proc=fixture.root/'private-proc';proc.mkdir()
        anchor='for process in /proc/[0-9]*; do'
        self.assertEqual(fixture.definitions.count(anchor),1)
        fixture.definitions=fixture.definitions.replace(anchor,'for process in "$inventory_proc"/[0-9]*; do')
        process=proc/'101';task=process/'task/101';(task/'fd').mkdir(parents=True)
        (process/'stat').write_text(self.stat(101));(task/'stat').write_text(self.stat(101))
        (task/'limits').write_text('Max open files 1024 1073741816 files\n')
        (task/'fd/3').touch()
        return SimpleNamespace(host=fixture,proc=proc,process=process,task=task)

    def stat(self,pid,*,short=False,start='1000'):
        fields=['S']+['0']*18+[start]
        if short:fields=fields[:-1]
        return str(pid)+' (protected comm /private/path) '+' '.join(fields)+'\n'

    def prefix(self,fixture):
        import shlex
        return fixture.host.initial_selection()+'\ninventory_proc='+shlex.quote(str(fixture.proc))+'\n'

    def refuse(self,fixture,body,code):
        result=fixture.host.child(self.prefix(fixture)+body+'\nprintf forbidden\n').finish()
        expected=b'rootful-receiver-refused\nrootful-prerequisite-code-v1:'+code.encode()+b'\n'
        self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',expected))
        self.assertLessEqual(len(expected),69)
        self.assertNotIn(b'protected',result.stderr);self.assertNotIn(str(fixture.proc).encode(),result.stderr)
        self.assertEqual((fixture.host.root/'state/poison').read_bytes(),b'poisoned\n')
        return result

    def guard(self,code):
        lines=[line.strip() for line in self.SOURCE.splitlines() if line.rstrip().endswith('|| fail '+code)]
        self.assertEqual(len(lines),1,code);return lines[0]+'\n'

    def test_every_explicit_inventory_destination_with_real_private_file_failures(self):
        import shutil
        cases=(
            ('inv-pid-range',lambda f:f.process.rename(f.proc/'0')),
            ('inv-pid-range',lambda f:f.process.rename(f.proc/'32768')),
            ('inv-proc-task',lambda f:shutil.rmtree(f.process/'task')),
            ('inv-proc-read',lambda f:(f.process/'stat').unlink()),
            ('inv-proc-read',lambda f:(f.process/'stat').write_text(self.stat(101).rstrip('\n'))),
            ('inv-proc-pid',lambda f:(f.process/'stat').write_text(self.stat(102))),
            ('inv-proc-form',lambda f:(f.process/'stat').write_text(self.stat(101,short=True))),
            ('inv-proc-form',lambda f:(f.process/'stat').write_text(self.stat(101,start='protected-start'))),
            ('inv-task-empty',lambda f:shutil.rmtree(f.task)),
            ('inv-tid-count',lambda f:f.task.rename(f.task.with_name('0'))),
            ('inv-tid-count',lambda f:f.task.rename(f.task.with_name('32768'))),
            ('inv-task-read',lambda f:(f.task/'stat').unlink()),
            ('inv-task-read',lambda f:(f.task/'stat').write_text(self.stat(101).rstrip('\n'))),
            ('inv-task-tid',lambda f:(f.task/'stat').write_text(self.stat(102))),
            ('inv-task-form',lambda f:(f.task/'stat').write_text(self.stat(101,short=True))),
            ('inv-task-form',lambda f:(f.task/'stat').write_text(self.stat(101,start='protected-start'))),
            ('inv-nf-form',lambda f:(f.task/'limits').write_text('')),
            ('inv-nf-form',lambda f:(f.task/'limits').write_text('Max open files 1024 unlimited files\n')),
            ('inv-nf-form',lambda f:(f.task/'limits').write_text('Max open files 1024 10000000000 files\n')),
            ('inv-fd-access',lambda f:shutil.rmtree(f.task/'fd')),
            ('inv-fd-form',lambda f:(f.task/'fd/7protected').touch()),
            ('inv-fd-form',lambda f:(f.task/'fd/10000000000').touch()),
            ('inv-fd-range',lambda f:(f.task/'fd/1073741816').touch()),
            ('inv-empty',lambda f:shutil.rmtree(f.process)),
        )
        observed=set()
        for code,mutate in cases:
            with self.subTest(code=code):
                fixture=self.fixture();mutate(fixture);self.refuse(fixture,'inventory\n',code);observed.add(code)
        # V2 H is the lexical maximum: no in-grammar hard limit reaches inv-nf-range.
        self.assertEqual(observed,set(INVENTORY_CODES)-{'inv-nf-range','inv-snap-size','inv-drift'})

    def test_both_directory_predicates_preserve_all_three_constituents(self):
        for code,subject in (('inv-proc-task','$process/task'),('inv-fd-access','$task/fd')):
            original=self.guard(code)
            projected=original
            for operator,name in (('-d','directory'),('-r','readable'),('-x','searchable')):
                atom=operator+' '+subject;self.assertEqual(projected.count(atom),1)
                projected=projected.replace(atom,'$'+name+' == 1')
            for values in ((0,1,1),(1,0,1),(1,1,0)):
                fixture=self.fixture();body='directory=%s\nreadable=%s\nsearchable=%s\n'%values+projected
                self.refuse(fixture,body,code)
            fixture=self.fixture()
            self.assertEqual(fixture.host.run_body(self.prefix(fixture)+'directory=1\nreadable=1\nsearchable=1\n'+projected+'printf accepted\n'),b'accepted')

    def test_tid_range_short_circuits_increment_and_strict_count_boundary(self):
        guard=self.guard('inv-tid-count')
        for tid,initial,final,passes in ((0,7,7,False),(32768,7,7,False),(1,32767,32768,False),
                                         (1,32766,32767,True),(32767,0,1,True)):
            fixture=self.fixture()
            body='tid='+str(tid)+'\ncount='+str(initial)+'\ntrap \'printf "%s" "$count" > "$root/count-at-exit"\' EXIT\n'+guard
            if passes:self.assertEqual(fixture.host.run_body(self.prefix(fixture)+body+'printf accepted\n'),b'accepted')
            else:self.refuse(fixture,body,'inv-tid-count')
            self.assertEqual((fixture.host.root/'count-at-exit').read_text(),str(final))

    def test_original_snapshot_size_accepts_exact_ceiling_and_refuses_next_byte(self):
        guard=self.guard('inv-snap-size')
        for size,passes in ((33554432,True),(33554433,False)):
            fixture=self.fixture();body="printf -v SNAP '%"+str(size)+"s' ''\n"+guard
            if passes:self.assertEqual(fixture.host.run_body(self.prefix(fixture)+body+'printf accepted\n'),b'accepted')
            else:self.refuse(fixture,body,'inv-snap-size')

    def snapshot_pair(self):
        start=self.SOURCE.index('  inventory\n  before=$SNAP\n  inventory\n')
        end=self.SOURCE.index('\n}',start)
        return self.SOURCE[start:end]+'\n'

    def test_healthy_identical_snapshots_and_maximum_admitted_fd_are_unchanged(self):
        fixture=self.fixture();(fixture.task/'fd/1073741815').touch()
        self.assertEqual(fixture.host.run_body(self.prefix(fixture)+self.snapshot_pair()+'[[ ${INVENTORY_START[101]} == 1000 ]]\nprintf healthy\n'),b'healthy')

    def test_two_healthy_snapshots_with_changed_private_fd_refuse_only_at_comparison(self):
        fixture=self.fixture();self.assertEqual(fixture.host.definitions.count('inventory() {'),1)
        fixture.host.definitions=fixture.host.definitions.replace('inventory() {','source_inventory() {',1)
        body='''invocations=0
inventory() {
 source_inventory
 invocations=$((invocations + 1))
 if ((invocations == 1)); then : > "$inventory_proc/101/task/101/fd/7"; fi
}
'''+self.snapshot_pair()
        self.refuse(fixture,body,'inv-drift')

    def test_all_new_labels_are_initial_only_and_execution_cannot_select_them(self):
        for code in INVENTORY_CODES:
            for intent in ('execution-v1','provider','logs-child','unknown'):
                fixture=self.fixture()
                result=fixture.host.child('set -- '+intent+'\n'+self.prefix(fixture)+'fail '+code+'\n').finish()
                self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
            fixture=self.fixture();result=fixture.host.child(self.prefix(fixture)+'mode=cleanup\nfail '+code+'\n').finish()
            self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
            self.assertFalse((fixture.host.root/'state/poison').exists())


CURRENT_KIND_FAILURE_SOURCE = '744d3673eb1a44419e91e9c34614b8225c71b05937c7b1476add1e2a4931444f'
PREVIOUS_KIND_FAILURE_SOURCE = '02f3c77abfc2aff302ad9e9946a7cd8538f7ae68f3165a6c761cac32208bd840'
KIND_FAILURE_SOURCE_DELTA = [('  take sentinel 150 || fail\n  take sentinel 150 || fail\n  out=$captures/$action.out err=$captures/$action.err\n  [[ ! -e $out && ! -L $out && ! -e $err && ! -L $err ]] || fail\n  grant_utility || fail\n  stdout_dd=$utility_ticket\n', '  take sentinel 150 || fail\n  take sentinel 150 || fail\n  out=$captures/$action.out err=$captures/$action.err\n  last_tool_status=-1 last_stdout_capture_status=-1 last_stderr_capture_status=-1\n  [[ ! -e $out && ! -L $out && ! -e $err && ! -L $err ]] || fail\n  grant_utility || fail\n  stdout_dd=$utility_ticket\n'), ('  last_tool_status=$rc\n  printf \'%s\\n\' "$rc" > "$captures/$action.status"\n  exec {stdout_fd}>&- {stderr_fd}>&-\n  wait "$stdout_pid" || helper_error=1\n  wait "$stderr_pid" || helper_error=1\n  if ((helper_error)); then\n    [[ $domain == cleanup ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n    return 125\n', '  last_tool_status=$rc\n  printf \'%s\\n\' "$rc" > "$captures/$action.status"\n  exec {stdout_fd}>&- {stderr_fd}>&-\n  if wait "$stdout_pid"; then last_stdout_capture_status=0; else\n    last_stdout_capture_status=$?\n    helper_error=1\n  fi\n  if wait "$stderr_pid"; then last_stderr_capture_status=0; else\n    last_stderr_capture_status=$?\n    helper_error=1\n  fi\n  if ((helper_error)); then\n    [[ $domain == cleanup ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n    return 125\n'), ('  [[ $actual == "$REPLY" ]] || fail\n}\n\nremember() {\n  # The fixed private diagnostic role is part of this directly used catalogue.\n  # It never accepts a caller path or general application log input.\n  if [[ $# == 1 && $1 == node-init-stdout-prefix ]]; then\n', '  [[ $actual == "$REPLY" ]] || fail\n}\n\npreserve_kind_create_failure() {\n  [[ ${kind_failure_wrapper_status:--1} =~ ^(0|[1-9][0-9]{0,2})$ ]] || return 0\n  ((kind_failure_wrapper_status > 0 && kind_failure_wrapper_status <= 255)) || return 0\n  [[ ${kind_failure_err+x} && ${kind_failure_stdout_status+x} && ${kind_failure_stderr_status+x} ]] || return 1\n  [[ $kind_failure_stdout_status =~ ^(-1|0|[1-9][0-9]{0,2})$ && $kind_failure_stderr_status =~ ^(-1|0|[1-9][0-9]{0,2})$ ]] || return 1\n  ((kind_failure_stdout_status <= 255 && kind_failure_stderr_status <= 255)) || return 1\n  [[ $mode == work && $source_status == not-reached && $kind_failure_err == "$captures"/work.*.err && -f $kind_failure_err && ! -L $kind_failure_err ]] || return 1\n  local size ticket i needed=3 prefix_bytes=0 eof=null truncated=false overflow=false\n  local destination=$root/state/kind-create-stderr-prefix attribution=$root/state/kind-create-attribution\n  [[ ! -e $destination && ! -L $destination && ! -e $attribution && ! -L $attribution ]] || return 1\n  grant_utility || return 1\n  ticket=$utility_ticket\n  size=$(utility_launch "$ticket" /usr/bin/stat -c %s "$kind_failure_err") || return 1\n  [[ $size =~ ^[0-9]{1,5}$ ]] && ((size <= 32769)) || return 1\n  if ((size > 0)); then\n    needed=7\n    prefix_bytes=$size\n    ((prefix_bytes <= 4096)) || prefix_bytes=4096\n  fi\n  kind_failure_tickets=()\n  for ((i = 0; i < needed; i++)); do\n    grant_utility || return 1\n    kind_failure_tickets+=("$utility_ticket")\n  done\n  ((size <= 4096)) || truncated=true\n  ((size != 32769)) || overflow=true\n  [[ $kind_failure_stderr_status != 0 ]] || eof=true\n  if ((size > 0)); then\n    ticket=${kind_failure_tickets[0]}\n    kind_failure_tickets=("${kind_failure_tickets[@]:1}")\n    (\n      set -o noclobber\n      utility_launch "$ticket" /usr/bin/dd if="$kind_failure_err" bs=1 count=4096 status=none > "$destination"\n    ) || return 1\n  fi\n  (\n    set -o noclobber\n    printf \'{"schema":"kind-create-failure-attribution-v1","kind_child_wait_status":%s,"native_wrapper_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s,"stderr_captured_bytes":%s,"stderr_prefix_bytes":%s,"stderr_source_eof":%s,"stderr_overflow_sentinel":%s,"stderr_prefix_truncated":%s,"provider_child_wait_status":null,"provider_wrapper_status":null}\\n\' "$create_status" "$kind_failure_wrapper_status" "$kind_failure_stdout_status" "$kind_failure_stderr_status" "$size" "$prefix_bytes" "$eof" "$overflow" "$truncated" > "$attribution"\n  ) || return 1\n  ((size == 0)) || printf \'%s\\n\' "$destination" > "$root/state/evidence.kind-create-stderr-prefix"\n  printf \'%s\\n\' "$attribution" > "$root/state/evidence.kind-create-attribution"\n}\n\nremember() {\n  case $1 in\n    kind-create-failure)\n      [[ $# == 1 ]] || fail\n      preserve_kind_create_failure\n      return $?\n      ;;\n    kind-create-evidence)\n      [[ $# == 1 ]] || fail\n      emit_kind_create_failure_evidence\n      return $?\n      ;;\n  esac\n  # The fixed private diagnostic role is part of this directly used catalogue.\n  # It never accepts a caller path or general application log input.\n  if [[ $# == 1 && $1 == node-init-stdout-prefix ]]; then\n'), ('  [[ $2 == "$captures"/work.*.out && -f $2 && ! -L $2 ]] || fail\n  printf \'%s\\n\' "$2" > "$root/state/evidence.$1"\n}\n# Called by finish from the fixed EXIT trap; not a standalone entrypoint.\n# shellcheck disable=SC2329\nemit_evidence() {\n', '  [[ $2 == "$captures"/work.*.out && -f $2 && ! -L $2 ]] || fail\n  printf \'%s\\n\' "$2" > "$root/state/evidence.$1"\n}\nemit_kind_create_failure_evidence() {\n  local name path size sha encoded index=0\n  for name in kind-create-stderr-prefix kind-create-attribution; do\n    [[ -e $root/state/evidence.$name ]] || continue\n    read_file "$root/state/evidence.$name"\n    path=$REPLY\n    [[ $path == "$root/state/$name" && -f $path && ! -L $path ]] || fail\n    ((index + 3 <= ${#kind_failure_tickets[@]})) || fail\n    size=$(utility_launch "${kind_failure_tickets[index]}" /usr/bin/stat -c %s "$path") || fail\n    index=$((index + 1))\n    [[ $size =~ ^[0-9]+$ ]] || fail\n    ((size > 0 && (total += size) <= 131072)) || fail\n    [[ $name != kind-create-stderr-prefix ]] || ((size <= 4096)) || fail\n    [[ $name != kind-create-attribution ]] || ((size <= 1024)) || fail\n    sha=$(utility_launch "${kind_failure_tickets[index]}" /usr/bin/sha256sum "$path") || fail\n    index=$((index + 1))\n    sha=${sha%% *}\n    encoded=$(utility_launch "${kind_failure_tickets[index]}" /usr/bin/base64 -w0 "$path") || fail\n    index=$((index + 1))\n    files+="$comma\\"$name\\":{\\"bytes\\":$size,\\"sha256\\":\\"$sha\\",\\"base64\\":\\"$encoded\\"}"\n    comma=,\n  done\n}\n\n# Called by finish from the fixed EXIT trap; not a standalone entrypoint.\n# shellcheck disable=SC2329\nemit_evidence() {\n'), ('    files+="$comma\\"$name\\":{\\"bytes\\":$size,\\"sha256\\":\\"$sha\\",\\"base64\\":\\"$encoded\\"}"\n    comma=,\n  done\n  printf -v evidence_json \'{"schema":"kubernetes-lens-owned-rootful-evidence-v1","owner":"%s","plan_sha256":"%s","source_spec_sha256":"%s","files":{%s}}\' "$owner" "$plan" "$spec_sha" "$files"\n  ((${#evidence_json} <= 262144)) || fail\n}\n', '    files+="$comma\\"$name\\":{\\"bytes\\":$size,\\"sha256\\":\\"$sha\\",\\"base64\\":\\"$encoded\\"}"\n    comma=,\n  done\n  remember kind-create-evidence\n  printf -v evidence_json \'{"schema":"kubernetes-lens-owned-rootful-evidence-v1","owner":"%s","plan_sha256":"%s","source_spec_sha256":"%s","files":{%s}}\' "$owner" "$plan" "$spec_sha" "$files"\n  ((${#evidence_json} <= 262144)) || fail\n}\n'), ('  local status=$? n=0 utilities=0 utility_ledger=0 output_count=0\n  trap - EXIT ERR HUP INT TERM\n  [[ $status == 0 ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n  if ((created)); then\n    mode=cleanup\n    printf \'%s\\n\' cleanup > "$root/state/mode"\n', '  local status=$? n=0 utilities=0 utility_ledger=0 output_count=0\n  trap - EXIT ERR HUP INT TERM\n  [[ $status == 0 ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n  remember kind-create-failure || status=1\n  if ((created)); then\n    mode=cleanup\n    printf \'%s\\n\' cleanup > "$root/state/mode"\n'), ('printf \'%s\\n\' \'---\' \'kind: Cluster\' \'apiVersion: kind.x-k8s.io/v1alpha4\' \'networking:\' \'  ipFamily: ipv4\' \'  apiServerAddress: 127.0.0.1\' \'  apiServerPort: 6443\' \'  podSubnet: 10.244.0.0/16\' \'  serviceSubnet: 10.96.0.0/16\' \'nodes:\' \'- role: control-plane\' > "$root/config/kind.yaml"\ncreated=1\nif native 16384 32768 "$stage/kind" create cluster --name "$cluster" --image "$alias" --config "$root/config/kind.yaml" --kubeconfig "$KUBECONFIG" --wait 0s; then create_status=$last_tool_status; else\n  create_status=${last_tool_status:--1}\n  fail\nfi\nlogs_retirement\n', 'printf \'%s\\n\' \'---\' \'kind: Cluster\' \'apiVersion: kind.x-k8s.io/v1alpha4\' \'networking:\' \'  ipFamily: ipv4\' \'  apiServerAddress: 127.0.0.1\' \'  apiServerPort: 6443\' \'  podSubnet: 10.244.0.0/16\' \'  serviceSubnet: 10.96.0.0/16\' \'nodes:\' \'- role: control-plane\' > "$root/config/kind.yaml"\ncreated=1\nif native 16384 32768 "$stage/kind" create cluster --name "$cluster" --image "$alias" --config "$root/config/kind.yaml" --kubeconfig "$KUBECONFIG" --wait 0s; then create_status=$last_tool_status; else\n  kind_failure_wrapper_status=$? create_status=${last_tool_status:--1} kind_failure_err=${err:-} kind_failure_stdout_status=${last_stdout_capture_status:--1} kind_failure_stderr_status=${last_stderr_capture_status:--1}\n  fail\nfi\nlogs_retirement\n')]


POSTCREATE_PREFIX_SOURCE = 'd7919e005b27bd77d504838b7129062f7aced7e0c475d8a86419dae6e9aad27c'
POSTCREATE_PREFIX_SOURCE_DELTA = [('    ((create_status > 0 && create_status <= 255)) || return 0', '    ((create_status >= 0 && create_status <= 255)) || return 0'), ('    set -o noclobber\n    u /usr/bin/dd if="$source" bs=1 count=16384 status=none > "$destination" || fail', '    [[ $mode == cleanup ]] || return 0\n    prefix_claimed=1 prefix_tickets=()\n    local i\n    for ((i = 0; i < 4; i++)); do\n      grant_utility || return 0\n      prefix_tickets+=("$utility_ticket")\n    done\n    set -o noclobber\n    utility_launch "${prefix_tickets[0]}" /usr/bin/dd if="$source" bs=1 count=16384 status=none > "$destination" || fail'), ("  local name path size sha encoded total=0 comma='' files=''\n  for name in", "  local name path size sha encoded total=0 comma='' files=''\n  local -a pay\n  for name in"), ('    path=$REPLY\n    if [[ $name == node-init-stdout-prefix ]]; then', '    path=$REPLY\n    pay=(u)\n    if [[ $name == node-init-stdout-prefix ]]; then\n      pay=(utility_launch "${prefix_tickets[1]}")'), ('    size=$(u /usr/bin/stat -c %s "$path") || fail', '    size=$("${pay[@]}" /usr/bin/stat -c %s "$path") || fail'), ('    sha=$(u /usr/bin/sha256sum "$path") || fail', '    [[ $name != node-init-stdout-prefix ]] || pay[1]=${prefix_tickets[2]}\n    sha=$("${pay[@]}" /usr/bin/sha256sum "$path") || fail'), ('    encoded=$(u /usr/bin/base64 -w0 "$path") || fail', '    [[ $name != node-init-stdout-prefix ]] || pay[1]=${prefix_tickets[3]}\n    encoded=$("${pay[@]}" /usr/bin/base64 -w0 "$path") || fail'), ('# Atomic O_EXCL token acquisition is the ledger. A token is never deleted or\n# refunded, even when execution, checksum, ACK, output or cleanup later fails.\n# Every attempt is finite. No flock/mv subprocess is needed to charge flock/mv.', '# Atomic O_EXCL tickets are permanent, including denied or unused prepayment.'), ('# A finite normal-I/O collector streams single bytes promptly, retains the exact\n# raw bytes privately and directly waits both its own actual utility children.\n# tee may ignore a cancelled reader; only dd EOF/size proves source closure.', '# Bounded private byte collector; only dd EOF/size proves source closure.'), ('# The fixed private diagnostic role is part of this directly used catalogue.\n  # It never accepts a caller path or general application log input.', '# Fixed private role; no caller path or application logs.'), ('# Close every extra copy of the write ends in both the tool and collectors.\n  # A successful collector wait then requires genuine source EOF, not just an\n  # exited top-level tool with a descendant still holding the pipe open.', '# Close inherited writers; collector waits require genuine source EOF.'), ('  if [[ $# == 1 && $1 == node-init-stdout-prefix ]]; then\n', '  if [[ $# == 1 && $1 == node-init-stdout-prefix ]]; then\n    [[ ${prefix_claimed:-0} == 0 ]] || return 0\n'), ('  for name in podman-info manifest config image-inspect network-inspect node-inspect node-init-stdout-prefix; do\n', '  for name in podman-info manifest config image-inspect network-inspect node-inspect node-init-stdout-prefix; do\n    [[ $name != node-init-stdout-prefix ]] || remember node-init-stdout-prefix\n'), ('  remember node-init-stdout-prefix\n  emit_evidence\n  emit_logs_evidence', '  emit_evidence\n  emit_logs_evidence')]

DIRECT_EXEC_SOURCE = 'c334f3714036ccb72ea72aef9f6e37e9ae0e92547b89297056c51f4278c05976'
DIRECT_EXEC_SOURCE_BYTES = 63399
DIRECT_EXEC_SOURCE_DELTA = [('  local -a parts\n  read -ra parts <<< "$tail"\n  ((${#parts[@]} >= 20)) && [[ ${parts[19]} =~ ^[0-9]+$ && ${parts[1]} =~ ^[0-9]+$ ]] || fail\n  PROC_START=${parts[19]} PROC_PARENT=${parts[1]}\n}\nrecord_identity() {\n  local path=$1 pid=$BASHPID\n', '  local -a parts\n  read -ra parts <<< "$tail"\n  ((${#parts[@]} >= 20)) && [[ ${parts[19]} =~ ^[0-9]+$ && ${parts[1]} =~ ^[0-9]+$ ]] || fail\n  PROC_START=${parts[19]}\n}\nrecord_identity() {\n  local path=$1 pid=$BASHPID\n'), ('    set +o noclobber\n    fail\n  fi\n}\n# Runs after setpriv has armed PDEATHSIG and before its same-PID ordinary exec.\n# All checks are shell builtins: no unprotected fork can escape this gate.\nlogs_gate() {\n  local wrapper wrapper_start expected_boot actual_boot parent line label a b c d rest\n  read_file "$root/state/logs-binding"\n  read -r owner plan expected_boot <<< "$REPLY"\n  [[ $owner =~ ^[0-9a-f]{32}$ && $plan =~ ^[0-9a-f]{64}$ && $expected_boot =~ ^[0-9a-f-]{36}$ ]] || fail\n  read -r actual_boot < /proc/sys/kernel/random/boot_id\n  [[ $actual_boot == "$expected_boot" ]] || fail\n  read_file "$root/state/logs-wrapper.identity"\n  read -r wrapper wrapper_start <<< "$REPLY"\n  [[ $wrapper_start =~ ^[0-9]+$ ]] || fail\n  process_identity "$BASHPID"\n  parent=$PROC_PARENT\n  [[ $parent == "$wrapper" ]] || fail\n  process_identity "$wrapper"\n  [[ $PROC_START == "$wrapper_start" ]] || fail\n  local uid_ok=0 gid_ok=0\n  while read -r label a b c d rest; do\n    case $label in\n      Uid:)\n        [[ $a == 0 && $b == 0 && $c == 0 && $d == 0 ]] || fail\n        uid_ok=1\n        ;;\n      Gid:)\n        [[ $a == 0 && $b == 0 && $c == 0 && $d == 0 ]] || fail\n        gid_ok=1\n        ;;\n    esac\n  done < /proc/self/status\n  ((uid_ok && gid_ok)) || fail\n  record_identity "$root/state/logs-child.identity"\n  # Recheck after writing the binding, immediately before the fixed exec.\n  process_identity "$BASHPID"\n  [[ $PROC_PARENT == "$wrapper" ]] || fail\n  process_identity "$wrapper"\n  [[ $PROC_START == "$wrapper_start" ]] || fail\n}\n# Bounded private byte collector; only dd EOF/size proves source closure.\nlogs_collector() {\n', '    set +o noclobber\n    fail\n  fi\n}\n# Bounded private byte collector; only dd EOF/size proves source closure.\nlogs_collector() {\n'), ('  fi\n  printf \'%s %s %s eof\\n\' "$dd_status" "$tee_status" "$size" > "$root/state/logs-$name.closed"\n}\nlogs_native() {\n  local stdout_tee stderr_tee setpriv_ticket child_pid rc=0 helper_error=0\n  grant_utility || fail\n  stdout_tee=$utility_ticket\n  grant_utility || fail\n  stderr_tee=$utility_ticket\n  grant_utility || fail\n  setpriv_ticket=$utility_ticket\n  claim logs\n  record_identity "$root/state/logs-wrapper.identity"\n  (\n    set -o noclobber\n    printf \'%s %s %s\\n\' "$owner" "$plan" "$boot" > "$root/state/logs-binding"\n  ) || fail\n  exec {stdout_fd}> >(logs_collector "$maximum" "$out" out "$stdout_dd" "$stdout_stat" "$stdout_tee")\n  stdout_pid=$!\n  exec {stderr_fd}> >(logs_collector "$error_max" "$err" err "$stderr_dd" "$stderr_stat" "$stderr_tee" >&3)\n  stderr_pid=$!\n  (\n    local utility_exec=1\n    exec 1>&$stdout_fd 2>&$stderr_fd {stdout_fd}>&- {stderr_fd}>&- 3>&-\n    utility_launch "$setpriv_ticket" /usr/bin/setpriv --pdeathsig KILL -- /usr/bin/bash "$root/receiver" logs-child\n  ) &\n  child_pid=$!\n  exec {stdout_fd}>&- {stderr_fd}>&-\n  wait "$child_pid" || rc=$?\n  last_tool_status=$rc\n  printf \'%s\\n\' "$rc" > "$captures/$action.status"\n  printf \'%s\\n\' "$rc" > "$root/state/logs-wrapper.status"\n  wait "$stdout_pid" || helper_error=1\n  wait "$stderr_pid" || helper_error=1\n  if ((rc != 0 || helper_error)); then\n    printf \'%s\\n\' poisoned > "$root/state/poison"\n    return 125\n  fi\n  clock_check\n}\npace_close() {\n  if [[ -n ${pace_fd:-} ]]; then\n', '  fi\n  printf \'%s %s %s eof\\n\' "$dd_status" "$tee_status" "$size" > "$root/state/logs-$name.closed"\n}\nlogs_exec_failure() {\n  local status=${1:-1}\n  [[ $status =~ ^[0-9]{1,3}$ ]] && ((status > 0 && status <= 255)) || status=1\n  printf \'%s\\n\' poisoned > "$root/state/poison" || true\n  exit "$status"\n}\nlogs_native() {\n  [[ $BASH_SUBSHELL == 0 ]] || logs_exec_failure\n  shopt -s execfail || logs_exec_failure\n  local stdout_tee stderr_tee\n  grant_utility || logs_exec_failure\n  stdout_tee=$utility_ticket\n  grant_utility || logs_exec_failure\n  stderr_tee=$utility_ticket\n  claim logs\n  record_identity "$root/state/logs-native.identity"\n  set -o noclobber\n  if printf \'%s %s %s\\n\' "$owner" "$plan" "$boot" > "$root/state/logs-binding"; then set +o noclobber; else\n    set +o noclobber\n    logs_exec_failure\n  fi\n  if exec {stdout_fd}> >(logs_collector "$maximum" "$out" out "$stdout_dd" "$stdout_stat" "$stdout_tee"); then :; else\n    logs_exec_failure "$?"\n  fi\n  if exec {stderr_fd}> >(logs_collector "$error_max" "$err" err "$stderr_dd" "$stderr_stat" "$stderr_tee" >&3); then :; else\n    logs_exec_failure "$?"\n  fi\n  if exec 1>&$stdout_fd 2>&$stderr_fd {stdout_fd}>&- {stderr_fd}>&- 3>&-; then :; else\n    logs_exec_failure "$?"\n  fi\n  # Failed exec must return even when this shell originally enabled errexit.\n  # Both returns below poison and exit; successful exec never returns.\n  set +e || logs_exec_failure\n  if exec /usr/bin/podman --remote=false logs -f "$node"; then\n    logs_exec_failure\n  else\n    logs_exec_failure "$?"\n  fi\n}\npace_close() {\n  if [[ -n ${pace_fd:-} ]]; then\n'), ('  [[ -p /proc/self/fd/0 ]] || fail\n  exec {pace_fd}<> /proc/self/fd/0 || fail\n  [[ /proc/self/fd/0 -ef /proc/self/fd/$pace_fd ]] || fail\n  for name in wrapper child out err out-dd out-tee err-dd err-tee; do\n    poll_state=u\n    read_file "$root/state/logs-$name.identity"\n    read -r pid start <<< "$REPLY"\n', '  [[ -p /proc/self/fd/0 ]] || fail\n  exec {pace_fd}<> /proc/self/fd/0 || fail\n  [[ /proc/self/fd/0 -ef /proc/self/fd/$pace_fd ]] || fail\n  for name in native out err out-dd out-tee err-dd err-tee; do\n    poll_state=u\n    read_file "$root/state/logs-$name.identity"\n    read -r pid start <<< "$REPLY"\n'), ('    done < "$name"\n  done\n  ((marker)) || fail m\n  if [[ -e $root/state/logs-wrapper.status ]]; then\n    read_file "$root/state/logs-wrapper.status"\n    [[ $REPLY == 0 ]] || fail n\n    state=direct-wait-zero\n  else\n    state=retired-wait-and-signal-cause-unavailable\n  fi\n  [[ ! -e $root/state/poison ]] || fail o\n  pace_close\n  poll_active=0\n', '    done < "$name"\n  done\n  ((marker)) || fail m\n  state=retired-wait-and-signal-cause-unavailable\n  [[ ! -e $root/state/poison ]] || fail o\n  pace_close\n  poll_active=0\n'), ("emit_logs_evidence() {\n  local name path pid start dd_status tee_status size closure item comma='' identities='' collectors=''\n  local state=${guard_reason:-not-established} marker=false wrapper_status=null eof maximum\n  for name in wrapper child out err out-dd out-tee err-dd err-tee; do\n    path=$root/state/logs-$name.identity\n    item=null\n    if [[ -e $path ]]; then\n", "emit_logs_evidence() {\n  local name path pid start dd_status tee_status size closure item comma='' identities='' collectors=''\n  local state=${guard_reason:-not-established} marker=false wrapper_status=null eof maximum\n  for name in native out err out-dd out-tee err-dd err-tee; do\n    path=$root/state/logs-$name.identity\n    item=null\n    if [[ -e $path ]]; then\n"), ('    state=$REPLY\n    [[ $state == direct-wait-zero || $state == retired-wait-and-signal-cause-unavailable ]] || fail\n    marker=true\n  fi\n  if [[ -e $root/state/logs-wrapper.status ]]; then\n    read_file "$root/state/logs-wrapper.status"\n    wrapper_status=$REPLY\n    [[ $wrapper_status =~ ^[0-9]{1,3}$ ]] || fail\n    ((wrapper_status <= 255)) || fail\n  fi\n  printf -v logs_json \'{"state":"%s","identities":{%s},"collectors":{%s},"startup_marker":%s,"wrapper_observed_child_wait_status":%s,"signal_cause":null}\' "$state" "$identities" "$collectors" "$marker" "$wrapper_status"\n  ((${#logs_json} <= 4096)) || fail\n', '    state=$REPLY\n    [[ $state == direct-wait-zero || $state == retired-wait-and-signal-cause-unavailable ]] || fail\n    marker=true\n  fi\n  printf -v logs_json \'{"state":"%s","identities":{%s},"collectors":{%s},"startup_marker":%s,"wrapper_observed_child_wait_status":%s,"signal_cause":null}\' "$state" "$identities" "$collectors" "$marker" "$wrapper_status"\n  ((${#logs_json} <= 4096)) || fail\n'), ('      $1 == /usr/bin/podman && $2 == --remote=false && $3 == logs && $4 == -f && $5 == "$node" ]] || fail\n    printf \'%s %s\\n\' "$out" "$err" > "$root/state/logs-captures"\n    logs_native\n    return $?\n  fi\n  exec {stdout_fd}> >(capture_stream "$maximum" "$out" "$stdout_dd" "$stdout_stat")\n  stdout_pid=$!\n', '      $1 == /usr/bin/podman && $2 == --remote=false && $3 == logs && $4 == -f && $5 == "$node" ]] || fail\n    printf \'%s %s\\n\' "$out" "$err" > "$root/state/logs-captures"\n    logs_native\n  fi\n  exec {stdout_fd}> >(capture_stream "$maximum" "$out" "$stdout_dd" "$stdout_stat")\n  stdout_pid=$!\n'), ('  fi\n  local rc=0\n  if [[ $action == logs ]]; then\n    stream_logs=1 native "$maximum" "$error_max" /usr/bin/podman --remote=false "${args[@]}" || rc=$?\n    return "$rc"\n  fi\n', '  fi\n  local rc=0\n  if [[ $action == logs ]]; then\n    [[ $BASH_SUBSHELL == 0 ]] || logs_exec_failure\n    stream_logs=1 native "$maximum" "$error_max" /usr/bin/podman --remote=false "${args[@]}" || rc=$?\n    return "$rc"\n  fi\n'), ('}\n\n# Entry: pure-control tests load only the definitions above; no guest program.\nif [[ ${1:-} == logs-child ]]; then\n  [[ $# == 1 && $EUID == 0 ]] || fail\n  rootful_admitted=1\n  logs_gate\n  exec 2>&3 3>&-\n  exec /usr/bin/podman --remote=false logs -f "kl-$owner-control-plane"\nfi\n# Closed source-selected roles precede any guest preflight. Provider and logs\n# keep their existing internal routes; a missing role is never a fresh epoch.\nrootful_intent=${1:-}\n', '}\n\n# Entry: pure-control tests load only the definitions above; no guest program.\n# Closed source-selected roles precede any guest preflight. Provider and logs\n# keep their existing internal routes; a missing role is never a fresh epoch.\nrootful_intent=${1:-}\n'), ('  local state=failed\n  ((status == 0 && create_status == 0 && delete_status == 0)) && state=\'source-deployment-positive\'\n  local wire_json\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v3","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n  exit "$status"\n', '  local state=failed\n  ((status == 0 && create_status == 0 && delete_status == 0)) && state=\'source-deployment-positive\'\n  local wire_json\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v4","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n  exit "$status"\n')]


# ADR0078 current-source seam.
POSTLOG_SOURCE = '19bd89c8172d06816d975b82e467cb05963596fb11ae88973169f634d69aef8f'
POSTLOG_SOURCE_BYTES = 63958
POSTLOG_SOURCE_DELTA = [("declare +x guard_reason='' poll_active=0\n", "declare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure=''\n"), ('', '  if [[ $BASH_SUBSHELL == 0 && ${rootful_admitted:-0} == 1 && ${rootful_intent:-} == execution-v1 && ${mode:-} == work && -z $postlog_failure ]]; then\n    case $postlog_site in r | i | f | n | j | e) postlog_failure=pl1.$postlog_site ;; esac\n  fi\n'), ('', "  postlog_site=''\n"), ('  local wire_json\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v4","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json"\n', '  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v5","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json"\n'), ('', 'postlog_site=r\n'), ('', 'postlog_site=i\n'), ('', 'postlog_site=f\n'), ('', 'postlog_site=n\n'), ('', 'postlog_site=j\n'), ('', 'postlog_site=e\n'), ('node_cgroup=/libpod_parent/libpod-$node_id\n', "postlog_site=''\nnode_cgroup=/libpod_parent/libpod-$node_id\n")]

# ADR0080 current-source seam.
NATIVE_STATUS_SOURCE = '0eeaf51d9394d3b91b830b5fab0fc8363e6164e5b864bbfdb34f8c17028cadcc'
NATIVE_STATUS_SOURCE_BYTES = 64608
NATIVE_STATUS_SOURCE_DELTA = [("declare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure=''\n", "declare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null\n"), ('', '    if [[ $postlog_site == n ]]; then\n      printf -v postlog_native \'{"return_status":%s,"command_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s}\' "$postlog_rc" "$postlog_tool" "$postlog_out" "$postlog_err"\n    fi\n'), ('', '  [[ $postlog_site != n ]] || postlog_tool=$last_tool_status\n'), ('', '  [[ $postlog_site != n ]] || postlog_out=$last_stdout_capture_status\n'), ('', '  [[ $postlog_site != n ]] || postlog_err=$last_stderr_capture_status\n'), ('  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v5","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json"\n', '  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v6","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native"\n'), ('native 16384 4096 /usr/bin/podman --remote=false inspect --type=container "$node" || fail\n', 'postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null\nnative 16384 4096 /usr/bin/podman --remote=false inspect --type=container "$node" || {\n  postlog_rc=$?\n  fail\n}\n')]

# ADR0081 current-source seam.
RESOURCE_REASON_SOURCE = 'b547819046445c72d48ccd96234f8387b72c7c8210ce80d8b0f96571cdaf359d'
RESOURCE_REASON_SOURCE_BYTES = 65246
RESOURCE_REASON_SOURCE_DELTA = [("declare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null\n", "declare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null postlog_reason=null\n"), ('', '    if [[ $postlog_site == r ]]; then\n      case ${1:-} in\n        block | filesystem | inv-drift | inv-empty | inv-fd-access | inv-fd-form | inv-fd-range | inv-nf-form | inv-nf-range | inv-pid-range | inv-proc-form | inv-proc-pid | inv-proc-read | inv-proc-task | inv-snap-size | inv-task-empty | inv-task-form | inv-task-read | inv-task-tid | inv-tid-count | mapper | memory | mount | mount-both | mount-proc | mount-root | namespace | nr-open-form | nr-open-range | pid-max) printf -v postlog_reason \'"%s"\' "$1" ;;\n        *) postlog_reason=\'"unlabelled"\' ;;\n      esac\n    fi\n'), ('  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v6","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native"\n', '  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v7","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n')]

# ADR0083 compact-source seam.
COMPACT_INSPECT_SOURCE = 'c6b771cfbe64491b5dc39bc597574b8b0134cce388c37fd3cb7c076f2f7a514d'
COMPACT_INSPECT_SOURCE_BYTES = 65270
COMPACT_INSPECT_SOURCE_DELTA = [('native 16384 4096 /usr/bin/podman --remote=false inspect --type=container "$node" || {\n', 'native 16384 4096 /usr/bin/podman --remote=false inspect --type=container --format \'[{{json .}}]\' "$node" || {\n')]

# ADR0084 current V8-to-frozen C6 V7 seam.
POSTNODE_SOURCE = 'd265f8834fdca00d79f9a4fdd487f3e5574813eeb5337cf10ece9dd5740adecb'
POSTNODE_SOURCE_BYTES = 65408
POSTNODE_SOURCE_DELTA = [('    case $postlog_site in r | i | f | n | j | e) postlog_failure=pl1.$postlog_site ;; esac\n', '    case $postlog_site in [rifnje]) postlog_failure=pl1.$postlog_site ;; [a-dghk]) postlog_failure=pl2.$postlog_site ;; esac\n'), ('  case $postlog_failure in pl1.[rifnje]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v7","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n', '  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v8","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n'), ("postlog_site=''\n", 'postlog_site=a\n'), ('', 'postlog_site=b\n'), ('', 'postlog_site=c\n'), ('', 'postlog_site=d\n'), ('', 'postlog_site=g\n'), ('', 'postlog_site=h\n'), ('', 'postlog_site=k\n')]

# ADR0085 current live-census source to frozen first-V8 source seam.
LIVE_CENSUS_SOURCE = '19c958a58fbfdd42085f6a2380807de5d23649d5aa7f1d9e9150ee5617a28983'
LIVE_CENSUS_SOURCE_BYTES = 65354
LIVE_CENSUS_SOURCE_DELTA = [('# No external programs, command substitutions, namespace changes or new tasks\n# run during a snapshot. Unreadable/disappeared entries refuse conservatively.\n', '# Builtin, fail-closed census.\n'), ('', '  [[ $# == 0 || $# == 1 && $1 == live ]] || fail\n'), ('  [[ $SNAP == "$before" ]] || fail inv-drift\n', '  [[ ${1:-} == live || $SNAP == "$before" ]] || fail inv-drift\n'), ('resource_check\n', 'resource_check live\n')]

# ADR0087 current V9-to-frozen owned-cgroup V8 seam.
K_STAGE_SOURCE = '7fb07aa0ffbf0f62968a6355ad02bccd6034e9496d424820806064329694c2d4'
K_STAGE_SOURCE_BYTES = 65331
K_STAGE_SOURCE_DELTA = [("rootful_admitted=0\nrecord_guard_fuel=0\ndeclare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null postlog_reason=null\nexec 3>&2 2> /dev/null\nfail() {\n", "rootful_admitted=0\nrecord_guard_fuel=0\ndeclare +x guard_reason='' poll_active=0 postlog_site='' postlog_failure='' postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null postlog_native=null postlog_reason=null k_site=''\nexec 3>&2 2> /dev/null\nfail() {\n"), ('      esac\n    fi\n    if [[ $postlog_site == n ]]; then\n      printf -v postlog_native \'{"return_status":%s,"command_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s}\' "$postlog_rc" "$postlog_tool" "$postlog_out" "$postlog_err"\n    fi\n', '      esac\n    fi\n    if [[ $postlog_site == k ]]; then\n      case $k_site in [a-n]) printf -v postlog_reason \'"k1.%s"\' "$k_site" ;; esac\n    fi\n    if [[ $postlog_site == n || $postlog_site == k && $k_site == [acehjm] ]]; then\n      printf -v postlog_native \'{"return_status":%s,"command_status":%s,"stdout_capture_status":%s,"stderr_capture_status":%s}\' "$postlog_rc" "$postlog_tool" "$postlog_out" "$postlog_err"\n    fi\n'), ('  exit 1\n}\n# Called only after the original exact RPM tuple predicate has failed. The\n# captured value stays private; one bounded builtin loop selects a fixed code.\npackage_tuple_failure() {\n  [[ ${initial_prerequisite:-0} == 1 && ${mode:-work} != cleanup ]] || fail packages\n', '  exit 1\n}\npackage_tuple_failure() {\n  [[ ${initial_prerequisite:-0} == 1 && ${mode:-work} != cleanup ]] || fail packages\n'), ('  fi\n}\n# Atomic O_EXCL tickets are permanent, including denied or unused prepayment.\ndeclare -A cursor=()\ntake() {\n', '  fi\n}\ndeclare -A cursor=()\ntake() {\n'), ('  ((UPTIME < limit)) || fail "${1:-}"\n}\n# Two fixed normal-I/O helpers, no polling service. The actual receiver owns\n# both process-substitution PIDs and waits for each. Each dd reads at most max+1\n# bytes: the extra byte is a pre-reserved overflow sentinel, never truncation proof.\ncapture_stream() {\n  local maximum=$1 destination=$2 dd_ticket=$3 stat_ticket=$4 size\n', '  ((UPTIME < limit)) || fail "${1:-}"\n}\ncapture_stream() {\n  local maximum=$1 destination=$2 dd_ticket=$3 stat_ticket=$4 size\n'), ('  [[ $size =~ ^[0-9]+$ ]] && ((size <= maximum))\n}\n# Kernel identities are never signal authority.\nprocess_identity() {\n  local pid=$1 record tail\n', '  [[ $size =~ ^[0-9]+$ ]] && ((size <= maximum))\n}\nprocess_identity() {\n  local pid=$1 record tail\n'), ('  fi\n}\n# Bounded private byte collector; only dd EOF/size proves source closure.\nlogs_collector() {\n  local maximum=$1 destination=$2 name=$3 dd_ticket=$4 stat_ticket=$5 tee_ticket=$6\n', '  fi\n}\nlogs_collector() {\n  local maximum=$1 destination=$2 name=$3 dd_ticket=$4 stat_ticket=$5 tee_ticket=$6\n'), ('  local stdout_fd stderr_fd stdout_dd stdout_stat stderr_dd stderr_stat\n  shift 2\n  [[ $domain == cleanup ]] && max=5\n  [[ $domain == work || $domain == cleanup ]] || fail\n', '  local stdout_fd stderr_fd stdout_dd stdout_stat stderr_dd stderr_stat\n  shift 2\n  [[ $postlog_site != k ]] || postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null\n  [[ $domain == cleanup ]] && max=5\n  [[ $domain == work || $domain == cleanup ]] || fail\n'), ('  ); then rc=0; else rc=$?; fi\n  last_tool_status=$rc\n  [[ $postlog_site != n ]] || postlog_tool=$last_tool_status\n  printf \'%s\\n\' "$rc" > "$captures/$action.status"\n  exec {stdout_fd}>&- {stderr_fd}>&-\n', '  ); then rc=0; else rc=$?; fi\n  last_tool_status=$rc\n  [[ $postlog_site != [nk] ]] || postlog_tool=$last_tool_status\n  printf \'%s\\n\' "$rc" > "$captures/$action.status"\n  exec {stdout_fd}>&- {stderr_fd}>&-\n'), ('    helper_error=1\n  fi\n  [[ $postlog_site != n ]] || postlog_out=$last_stdout_capture_status\n  if wait "$stderr_pid"; then last_stderr_capture_status=0; else\n    last_stderr_capture_status=$?\n    helper_error=1\n  fi\n  [[ $postlog_site != n ]] || postlog_err=$last_stderr_capture_status\n  if ((helper_error)); then\n    [[ $domain == cleanup ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n', '    helper_error=1\n  fi\n  [[ $postlog_site != [nk] ]] || postlog_out=$last_stdout_capture_status\n  if wait "$stderr_pid"; then last_stderr_capture_status=0; else\n    last_stderr_capture_status=$?\n    helper_error=1\n  fi\n  [[ $postlog_site != [nk] ]] || postlog_err=$last_stderr_capture_status\n  if ((helper_error)); then\n    [[ $domain == cleanup ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n'), ('  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v8","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n', '  local wire_json postlog_json=null\n  case $postlog_failure in pl1.[rifnje] | pl2.[a-dghk]) printf -v postlog_json \'"%s"\' "$postlog_failure" ;; esac\n  printf -v wire_json \'{"schema":"kubernetes-lens-owned-rootful-result-v9","owner":"%s","plan_sha256":"%s","profile":"%s","state":"%s","native_actions":%s,"utility_actions":%s,"utility_ledger_actions":%s,"record_guards":{"prepaid":24,"attempted":24},"output_reserved":%s,"kind_create_status":%s,"kind_delete_status":%s,"source_deployment":"%s","server_patch":"%s","network_retirement":"whole-vm-required","remaining_cases":"pending-fresh-runs","logs":%s,"evidence":%s,"postlog_failure":%s,"postlog_native":%s,"postlog_reason":%s}\' "$owner" "$plan" "$profile" "$state" "$n" "$utilities" "$utility_ledger" "$output_count" "$create_status" "$delete_status" "$source_status" "$patch" "$logs_json" "$evidence_json" "$postlog_json" "$postlog_native" "$postlog_reason"\n  ((${#wire_json} + 1 <= 262144)) || fail\n  printf \'%s\\n\' "$wire_json"\n'), ('[[ ${fields[19]:-} == "$expected_start" ]] || fail\npostlog_site=k\nnative 65536 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" config view --raw -o json || fail\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg name "kind-$cluster" \'."current-context"==$name and (.clusters|length)==1 and (.contexts|length)==1 and (.users|length)==1 and .clusters[0].name==$name and .clusters[0].cluster.server=="https://127.0.0.1:6443" and (.clusters[0].cluster|keys)==["certificate-authority-data","server"] and (.users[0].user|keys)==["client-certificate-data","client-key-data"] and .contexts[0].context.cluster==$name and .contexts[0].context.user==$name\' "$out" > /dev/null || fail\nnative 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" version -o json || fail\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg patch "v$patch" \'.serverVersion.gitVersion==$patch\' "$out" > /dev/null || fail\nready=0\nfor _round in 1 2; do\n  native 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" get --raw=/readyz || continue\n  read_file "$out"\n  [[ $REPLY == ok ]] || continue\n  native 16384 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" get nodes -o json || continue\n  if\n    # jq variables are supplied by --arg; shell expansion would alter this program.\n', '[[ ${fields[19]:-} == "$expected_start" ]] || fail\npostlog_site=k\nk_site=a\nnative 65536 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" config view --raw -o json || {\n  postlog_rc=$?\n  fail\n}\nk_site=b\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg name "kind-$cluster" \'."current-context"==$name and (.clusters|length)==1 and (.contexts|length)==1 and (.users|length)==1 and .clusters[0].name==$name and .clusters[0].cluster.server=="https://127.0.0.1:6443" and (.clusters[0].cluster|keys)==["certificate-authority-data","server"] and (.users[0].user|keys)==["client-certificate-data","client-key-data"] and .contexts[0].context.cluster==$name and .contexts[0].context.user==$name\' "$out" > /dev/null || fail\nk_site=c\nnative 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" version -o json || {\n  postlog_rc=$?\n  fail\n}\nk_site=d\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg patch "v$patch" \'.serverVersion.gitVersion==$patch\' "$out" > /dev/null || fail\nready=0\nfor _round in 1 2; do\n  k_site=e\n  native 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" get --raw=/readyz || {\n    postlog_rc=$?\n    continue\n  }\n  k_site=f\n  read_file "$out"\n  k_site=g\n  [[ $REPLY == ok ]] || continue\n  k_site=h\n  native 16384 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" get nodes -o json || {\n    postlog_rc=$?\n    continue\n  }\n  k_site=i\n  if\n    # jq variables are supplied by --arg; shell expansion would alter this program.\n'), ('done\n((ready)) || fail\nnative 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" create namespace demo -o json || fail\nvalue=$(u /usr/bin/sha256sum "$root/deployment.json") || fail\n[[ $value == "$fixture_sha  $root/deployment.json" ]] || fail\nvalue=\'\'\nnative 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" create --dry-run=server -f "$root/deployment.json" -o json || fail\nu /usr/bin/jq -e \'.apiVersion=="apps/v1" and .kind=="Deployment" and .metadata.namespace=="demo" and .metadata.name=="demo"\' "$out" > /dev/null || fail\nsource_status=server-dry-run-observed\n', 'done\n((ready)) || fail\nk_site=j\nnative 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" create namespace demo -o json || {\n  postlog_rc=$?\n  fail\n}\nk_site=k\nvalue=$(u /usr/bin/sha256sum "$root/deployment.json") || fail\nk_site=l\n[[ $value == "$fixture_sha  $root/deployment.json" ]] || fail\nvalue=\'\'\nk_site=m\nnative 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" create --dry-run=server -f "$root/deployment.json" -o json || {\n  postlog_rc=$?\n  fail\n}\nk_site=n\nu /usr/bin/jq -e \'.apiVersion=="apps/v1" and .kind=="Deployment" and .metadata.namespace=="demo" and .metadata.name=="demo"\' "$out" > /dev/null || fail\nsource_status=server-dry-run-observed\n')]

def receiver_before_k_stage(source):
    """Strict V9-to-frozen V8 inverse; no diagnostic inference or fallback."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != K_STAGE_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != K_STAGE_SOURCE):
        raise AssertionError('k-stage-current-source')
    for previous, current in reversed(K_STAGE_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('k-stage-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != OWNED_CGROUP_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != OWNED_CGROUP_SOURCE):
        raise AssertionError('k-stage-frozen-owned-cgroup-v8-source')
    return source
# ADR0087 seam end.

# ADR0086 owned-subtree source to frozen phase-specific V8 source seam.
OWNED_CGROUP_SOURCE = '237b5a10e1d767fa05588ff5dfc6d73cfa2959409bece5cc758b0f374d104829'
OWNED_CGROUP_SOURCE_BYTES = 65359
OWNED_CGROUP_SOURCE_DELTA = [('# Process identities come from the kernel, including in the post-arm gate.\n# No signal is ever sent to a recorded number or process group.\n', '# Kernel identities are never signal authority.\n'), ('[[ $REPLY == "0::$node_cgroup" ]] || fail\n', '[[ $REPLY =~ ^0::"$node_cgroup"(/[^/[:cntrl:]]+)*$ && $REPLY != */. && $REPLY != */.. &&\n  $REPLY != */./* && $REPLY != */../* ]] || fail\n')]

def receiver_before_owned_cgroup(source):
    """Strict source epoch inverse; no path normalization or historical fallback."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != OWNED_CGROUP_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != OWNED_CGROUP_SOURCE):
        raise AssertionError('owned-cgroup-current-source')
    for previous, current in reversed(OWNED_CGROUP_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('owned-cgroup-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != LIVE_CENSUS_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != LIVE_CENSUS_SOURCE):
        raise AssertionError('owned-cgroup-frozen-phase-source')
    return source
# ADR0086 seam end.

def receiver_before_live_census(source):
    """Exact current source to frozen V8 DATA; no normalization or fallback."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != LIVE_CENSUS_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != LIVE_CENSUS_SOURCE):
        raise AssertionError('live-census-current-source')
    for previous, current in reversed(LIVE_CENSUS_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('live-census-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != POSTNODE_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != POSTNODE_SOURCE):
        raise AssertionError('live-census-frozen-v8-source')
    return source
# ADR0085 seam end.

def receiver_before_postnode(source):
    """Exact V8 to frozen C6 V7 DATA; no normalization or source fallback."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != POSTNODE_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != POSTNODE_SOURCE):
        raise AssertionError('postnode-current-source')
    for previous, current in reversed(POSTNODE_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('postnode-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != COMPACT_INSPECT_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != COMPACT_INSPECT_SOURCE):
        raise AssertionError('postnode-frozen-c6-v7-source')
    return source
# ADR0084 seam end.

def receiver_before_compact_inspect(source):
    """Exact compact-current to frozen V7 presentation; wire semantics unchanged."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != COMPACT_INSPECT_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != COMPACT_INSPECT_SOURCE):
        raise AssertionError('compact-inspect-current-source')
    for previous, current in reversed(COMPACT_INSPECT_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('compact-inspect-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != RESOURCE_REASON_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != RESOURCE_REASON_SOURCE):
        raise AssertionError('compact-inspect-frozen-v7-source')
    return source
# ADR0083 seam end.

def receiver_before_resource_reason(source):
    """Exact V7-to-frozen64608-byte V6 DATA; never infer a resource predicate."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != RESOURCE_REASON_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != RESOURCE_REASON_SOURCE):
        raise AssertionError('resource-reason-current-source')
    for previous, current in reversed(RESOURCE_REASON_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('resource-reason-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != NATIVE_STATUS_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != NATIVE_STATUS_SOURCE):
        raise AssertionError('resource-reason-frozen-v6-source')
    return source
# ADR0081 seam end.

def receiver_before_native_status(source):
    """Exact v6-to-frozen v5 DATA; unavailable means no status observation."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != NATIVE_STATUS_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != NATIVE_STATUS_SOURCE):
        raise AssertionError('native-status-current-source')
    for previous, current in reversed(NATIVE_STATUS_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('native-status-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != POSTLOG_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != POSTLOG_SOURCE):
        raise AssertionError('native-status-frozen-v5-source')
    return source
# ADR0080 seam end.

def receiver_before_postlog(source):
    """Exact v5-to-frozen v4 DATA; no normalization or source fallback."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != POSTLOG_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != POSTLOG_SOURCE):
        raise AssertionError('postlog-current-source')
    for previous, current in reversed(POSTLOG_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('postlog-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != DIRECT_EXEC_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != DIRECT_EXEC_SOURCE):
        raise AssertionError('postlog-frozen-v4-source')
    return source
# ADR0078 seam end.

def receiver_before_direct_exec(source):
    """Exact v4-to-frozen65362-byte v3 DATA; no epoch or unknown-source fallback."""
    import hashlib
    if (type(source) is not str or len(source.encode()) != DIRECT_EXEC_SOURCE_BYTES
            or hashlib.sha256(source.encode()).hexdigest() != DIRECT_EXEC_SOURCE):
        raise AssertionError('direct-exec-current-source')
    for previous, current in reversed(DIRECT_EXEC_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('direct-exec-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != 65362 or hashlib.sha256(source.encode()).hexdigest() !=
            '1415b8c3f9e653e40547fb8e0b5d74e759edf825ea27e7332c472b510f84eb2a'):
        raise AssertionError('direct-exec-frozen-v3-source')
    return source

# ADR0076 is a separate, exactly sealed source domain before ADR0075 history.
POLL_PACING_SOURCE = '1415b8c3f9e653e40547fb8e0b5d74e759edf825ea27e7332c472b510f84eb2a'
POLL_PACING_SOURCE_DELTA = [('#!/usr/bin/bash\n# Original owned-guest receiver and closed provider; no caller text is executed.\nset -Eeuo pipefail\nexport LC_ALL=C\numask 077\n', '#!/usr/bin/bash\nset -Eeuo pipefail\nexport LC_ALL=C\numask 077\n'), ('  fi\n  clock_check\n}\n# Existing poll.\nlogs_retirement() {\n  local name pid start actual tail record i state marker=0 line a b size closure\n  local +x poll_active=1 poll_state=u\n  [[ ! -e $root/state/poison ]] || fail a\n  for name in wrapper child out err out-dd out-tee err-dd err-tee; do\n    poll_state=u\n    read_file "$root/state/logs-$name.identity"\n', '  fi\n  clock_check\n}\npace_close() {\n  if [[ -n ${pace_fd:-} ]]; then\n    exec {pace_fd}>&- || exit 1\n    unset pace_fd\n  fi\n}\nlogs_retirement() {\n  local name pid start actual tail record i state marker=0 line a b size closure\n  local +x poll_active=1 poll_state=u\n  [[ ! -e $root/state/poison ]] || fail a\n  [[ -p /proc/self/fd/0 ]] || fail\n  exec {pace_fd}<> /proc/self/fd/0 || fail\n  [[ /proc/self/fd/0 -ef /proc/self/fd/$pace_fd ]] || fail\n  for name in wrapper child out err out-dd out-tee err-dd err-tee; do\n    poll_state=u\n    read_file "$root/state/logs-$name.identity"\n'), ('    ((pid < pid_max)) || fail c\n    for ((i = 0; i < 4096; i++)); do\n      clock_check p\n      [[ -d /proc/$pid ]] || break\n      IFS= read -r record < "/proc/$pid/stat" || fail d\n      [[ ${record%% *} == "$pid" ]] || fail e\n', '    ((pid < pid_max)) || fail c\n    for ((i = 0; i < 4096; i++)); do\n      clock_check p\n      if ((i && work_limit - UPTIME > 1)); then\n        if IFS= read -rd \'\' -n 1 -t 0.01 -u "$pace_fd" line; then\n          fail\n        else\n          actual=$?\n        fi\n        ((actual == 142)) && [[ -z $line ]] || fail\n        clock_check p\n      fi\n      [[ -d /proc/$pid ]] || break\n      IFS= read -r record < "/proc/$pid/stat" || fail d\n      [[ ${record%% *} == "$pid" ]] || fail e\n'), ('    state=retired-wait-and-signal-cause-unavailable\n  fi\n  [[ ! -e $root/state/poison ]] || fail o\n  printf \'%s\\n\' "$state" > "$root/state/logs-retirement"\n}\n\n# Private logs from finish.\n# shellcheck disable=SC2329\nemit_logs_evidence() {\n  local name path pid start dd_status tee_status size closure item comma=\'\' identities=\'\' collectors=\'\'\n', '    state=retired-wait-and-signal-cause-unavailable\n  fi\n  [[ ! -e $root/state/poison ]] || fail o\n  pace_close\n  poll_active=0\n  clock_check p\n  printf \'%s\\n\' "$state" > "$root/state/logs-retirement"\n}\n\n# shellcheck disable=SC2329\nemit_logs_evidence() {\n  local name path pid start dd_status tee_status size closure item comma=\'\' identities=\'\' collectors=\'\'\n'), ('printf \'%s %s %s execution-inflight\\n\' "$owner" "$plan" "$boot" > "$root/state/phase"\nmode=work\ncreated=0 create_status=-1 delete_status=-1 source_status=not-reached\n# Fixed EXIT trap.\n# shellcheck disable=SC2329\nfinish() {\n  local status=$? n=0 utilities=0 utility_ledger=0 output_count=0\n  trap - EXIT ERR HUP INT TERM\n  [[ $status == 0 ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n  remember kind-create-failure || status=1\n  if ((created)); then\n', 'printf \'%s %s %s execution-inflight\\n\' "$owner" "$plan" "$boot" > "$root/state/phase"\nmode=work\ncreated=0 create_status=-1 delete_status=-1 source_status=not-reached\n# shellcheck disable=SC2329\nfinish() {\n  local status=$? n=0 utilities=0 utility_ledger=0 output_count=0\n  trap - EXIT ERR HUP INT TERM\n  pace_close\n  [[ $status == 0 ]] || printf \'%s\\n\' poisoned > "$root/state/poison"\n  remember kind-create-failure || status=1\n  if ((created)); then\n'), ('read_file "$out"\n[[ $REPLY == "kind v$kind_version "* ]] || fail\nnative 4096 4096 "$stage/kubectl" version --client -o json || fail\n# jq variables are supplied by --arg; shell expansion would alter this program.\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg patch "v$patch" \'.clientVersion.gitVersion==$patch\' "$out" > /dev/null || fail\nnative 16384 4096 /usr/bin/skopeo --policy "$root/config/policy.json" copy --preserve-digests "oci-archive:$stage/node.oci.tar" "containers-storage:$alias" || fail\n', 'read_file "$out"\n[[ $REPLY == "kind v$kind_version "* ]] || fail\nnative 4096 4096 "$stage/kubectl" version --client -o json || fail\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg patch "v$patch" \'.clientVersion.gitVersion==$patch\' "$out" > /dev/null || fail\nnative 16384 4096 /usr/bin/skopeo --policy "$root/config/policy.json" copy --preserve-digests "oci-archive:$stage/node.oci.tar" "containers-storage:$alias" || fail\n'), ('value=\'\'\nremember config "$out"\nnative 16384 4096 /usr/bin/podman --remote=false inspect --type=image "$alias" || fail\n# jq variables are supplied by --arg; shell expansion would alter this program.\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg id "$image_id" \'length==1 and .[0].Id==$id\' "$out" > /dev/null || fail\nremember image-inspect "$out"\n', 'value=\'\'\nremember config "$out"\nnative 16384 4096 /usr/bin/podman --remote=false inspect --type=image "$alias" || fail\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg id "$image_id" \'length==1 and .[0].Id==$id\' "$out" > /dev/null || fail\nremember image-inspect "$out"\n'), ('node_id=$REPLY\n[[ $node_id =~ ^[0-9a-f]{64}$ ]] || fail\nnative 16384 4096 /usr/bin/podman --remote=false inspect --type=container "$node" || fail\n# jq variables are supplied by --arg; shell expansion would alter this program.\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg id "$node_id" --arg image "$image_id" --arg node "$node" \'length==1 and .[0].Id==$id and .[0].Image==$image and .[0].Name==$node and .[0].State.Running==true and .[0].State.Pid>0 and (.[0].Config.CreateCommand|map(select(.=="--pull=never"))|length)==1 and .[0].Config.CreateCommand[-1]==$image and (.[0].NetworkSettings.Networks|keys)==["kind"] and .[0].NetworkSettings.Ports["6443/tcp"]==[{"HostIp":"127.0.0.1","HostPort":"6443"}]\' "$out" > /dev/null || fail\nremember node-inspect "$out"\nnode_cgroup=/libpod_parent/libpod-$node_id\n# jq variables are supplied by --arg; shell expansion would alter this program.\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg path "$node_cgroup" \'.[0].State.CgroupPath==$path\' "$out" > /dev/null || fail\nnode_pid=$(u /usr/bin/jq -er \'.[0].State.Pid\' "$out") || fail\n', 'node_id=$REPLY\n[[ $node_id =~ ^[0-9a-f]{64}$ ]] || fail\nnative 16384 4096 /usr/bin/podman --remote=false inspect --type=container "$node" || fail\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg id "$node_id" --arg image "$image_id" --arg node "$node" \'length==1 and .[0].Id==$id and .[0].Image==$image and .[0].Name==$node and .[0].State.Running==true and .[0].State.Pid>0 and (.[0].Config.CreateCommand|map(select(.=="--pull=never"))|length)==1 and .[0].Config.CreateCommand[-1]==$image and (.[0].NetworkSettings.Networks|keys)==["kind"] and .[0].NetworkSettings.Ports["6443/tcp"]==[{"HostIp":"127.0.0.1","HostPort":"6443"}]\' "$out" > /dev/null || fail\nremember node-inspect "$out"\nnode_cgroup=/libpod_parent/libpod-$node_id\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg path "$node_cgroup" \'.[0].State.CgroupPath==$path\' "$out" > /dev/null || fail\nnode_pid=$(u /usr/bin/jq -er \'.[0].State.Pid\' "$out") || fail\n'), ('read -ra fields <<< "$tail"\n[[ ${fields[19]:-} == "$expected_start" ]] || fail\nnative 65536 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" config view --raw -o json || fail\n# jq variables are supplied by --arg; shell expansion would alter this program.\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg name "kind-$cluster" \'."current-context"==$name and (.clusters|length)==1 and (.contexts|length)==1 and (.users|length)==1 and .clusters[0].name==$name and .clusters[0].cluster.server=="https://127.0.0.1:6443" and (.clusters[0].cluster|keys)==["certificate-authority-data","server"] and (.users[0].user|keys)==["client-certificate-data","client-key-data"] and .contexts[0].context.cluster==$name and .contexts[0].context.user==$name\' "$out" > /dev/null || fail\nnative 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" version -o json || fail\n# jq variables are supplied by --arg; shell expansion would alter this program.\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg patch "v$patch" \'.serverVersion.gitVersion==$patch\' "$out" > /dev/null || fail\nready=0\n', 'read -ra fields <<< "$tail"\n[[ ${fields[19]:-} == "$expected_start" ]] || fail\nnative 65536 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" config view --raw -o json || fail\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg name "kind-$cluster" \'."current-context"==$name and (.clusters|length)==1 and (.contexts|length)==1 and (.users|length)==1 and .clusters[0].name==$name and .clusters[0].cluster.server=="https://127.0.0.1:6443" and (.clusters[0].cluster|keys)==["certificate-authority-data","server"] and (.users[0].user|keys)==["client-certificate-data","client-key-data"] and .contexts[0].context.cluster==$name and .contexts[0].context.user==$name\' "$out" > /dev/null || fail\nnative 4096 4096 "$stage/kubectl" --kubeconfig "$KUBECONFIG" version -o json || fail\n# shellcheck disable=SC2016\nu /usr/bin/jq -e --arg patch "v$patch" \'.serverVersion.gitVersion==$patch\' "$out" > /dev/null || fail\nready=0\n')]
def receiver_before_poll_pacing(source):
    """Invert only adopted pacing/comment delta to immutable historical v3."""
    source = receiver_before_direct_exec(receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(source))))))))
    import hashlib
    if (type(source) is not str or len(source.encode()) != 65362
            or hashlib.sha256(source.encode()).hexdigest() != POLL_PACING_SOURCE):
        raise AssertionError('poll-pacing-current-source')
    for previous, current in reversed(POLL_PACING_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('poll-pacing-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != 65431 or hashlib.sha256(source.encode()).hexdigest() !=
            'e744849dab1741da10fdb70f4d420da2f94f33450dc4626a90a27dfc06da3b5b'):
        raise AssertionError('poll-pacing-independent-v3-source')
    return source

POLL_DIAGNOSTIC_SOURCE = 'e744849dab1741da10fdb70f4d420da2f94f33450dc4626a90a27dfc06da3b5b'
POLL_DIAGNOSTIC_SOURCE_DELTA = [("declare +x guard_reason=''\n", "declare +x guard_reason='' poll_active=0\n"),
 ('  case ${1:-} in [a-p]) guard_reason=${guard_reason:-pg1.$1} ;; esac\n',
  '  case ${1:-} in\n'
  '    [a-p])\n'
  '      if [[ -z $guard_reason && ${poll_active:-0} == 1 && $1 == [gp] ]]; then '
  'guard_reason=pg2.$1.$name.$poll_state.$i.$pid.$start; fi\n'
  '      guard_reason=${guard_reason:-pg1.$1}\n'
  '      ;;\n'
  '  esac\n'),
 ('# Existing retirement proof; no new observer or signals.\n', '# Existing poll.\n'),
 ('  local name pid start actual tail record i state marker=0 line a b size closure\n',
  '  local name pid start actual tail record i state marker=0 line a b size closure\n'
  '  local +x poll_active=1 poll_state=u\n'),
 ('  for name in wrapper child out err out-dd out-tee err-dd err-tee; do\n'
  '    read_file "$root/state/logs-$name.identity"\n',
  '  for name in wrapper child out err out-dd out-tee err-dd err-tee; do\n'
  '    poll_state=u\n'
  '    read_file "$root/state/logs-$name.identity"\n'),
 ('    # Original end; no helper or sleep.\n'
  '    for ((i = 0; i < 4096; i++)); do\n'
  '      clock_check p\n',
  '    for ((i = 0; i < 4096; i++)); do\n      clock_check p\n'),
 ('      [[ ${parts[19]} == "$start" ]] || break\n',
  '      [[ ${parts[19]} == "$start" ]] || break\n'
  '      case ${parts[0]} in\n'
  '        [RSDZTtXI]) poll_state=${parts[0]} ;;\n'
  '        *) poll_state=u ;;\n'
  '      esac\n'),
 ('# Closed guest report; missing failure records stay null.\n'
  '# Called by finish from the fixed EXIT trap; not a standalone entrypoint.\n',
  '# Private logs from finish.\n'),
 ('# Called only through the fixed EXIT trap below, after entry admission.\n',
  '# Fixed EXIT trap.\n'),
 ('"schema":"kubernetes-lens-owned-rootful-result-v2"',
  '"schema":"kubernetes-lens-owned-rootful-result-v3"')]


def receiver_before_poll_diagnostic(source):
    """Exact pacing inverse, then immutable ADR0075 v3 to frozen whole v2 DATA."""
    source = receiver_before_poll_pacing(source)
    import hashlib
    if (type(source) is not str or len(source.encode()) > 65536
            or hashlib.sha256(source.encode()).hexdigest() != POLL_DIAGNOSTIC_SOURCE):
        raise AssertionError('poll-diagnostic-current-source')
    for previous, current in reversed(POLL_DIAGNOSTIC_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('poll-diagnostic-exact-source-delta')
        source = source.replace(current, previous, 1)
    if (len(source.encode()) != 65336 or hashlib.sha256(source.encode()).hexdigest() !=
            '974a2090d47c12155dce3778d949492c37dc3578551c47deca1fa4b29363d6f7'):
        raise AssertionError('poll-diagnostic-independent-v2-source')
    return source


def poll_source_definitions(fixture, *, current):
    """Historical ADR0075 v3/v2 only; paced controls use actual current source."""
    source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
    if current:
        source = receiver_before_poll_pacing(source)
    else:
        source = receiver_before_poll_diagnostic(source)
    return source.split('# Entry: pure-control tests')[0].replace(
        'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
        f'readonly root={fixture.root} stage={fixture.root}/stage')


GUARD_REASON_SOURCE = '974a2090d47c12155dce3778d949492c37dc3578551c47deca1fa4b29363d6f7'
GUARD_REASON_SOURCE_DELTA = [('record_guard_fuel=0\nexec 3>&2', "record_guard_fuel=0\ndeclare +x guard_reason=''\nexec 3>&2"), ('fail() {\n', 'fail() {\n  case ${1:-} in [a-p]) guard_reason=${guard_reason:-pg1.$1} ;; esac\n'), ('  ((UPTIME < limit)) || fail\n', '  ((UPTIME < limit)) || fail "${1:-}"\n'), ('logs_retirement() {\n  local name pid start actual tail record i state marker=0 line a b size closure\n  [[ ! -e $root/state/poison ]] || fail\n  for name in wrapper child out err out-dd out-tee err-dd err-tee; do\n    read_file "$root/state/logs-$name.identity"\n    read -r pid start <<< "$REPLY"\n    [[ $pid =~ ^[1-9][0-9]{0,4}$ && $start =~ ^[0-9]+$ ]] || fail\n    ((pid < pid_max)) || fail\n    # No helper or sleep process; original work end still applies throughout.\n    for ((i = 0; i < 4096; i++)); do\n      clock_check\n      [[ -d /proc/$pid ]] || break\n      IFS= read -r record < "/proc/$pid/stat" || fail\n      [[ ${record%% *} == "$pid" ]] || fail\n      tail=${record##*) }\n      local -a parts\n      read -ra parts <<< "$tail"\n      ((${#parts[@]} >= 20)) && [[ ${parts[19]} =~ ^[0-9]+$ ]] || fail\n      [[ ${parts[19]} == "$start" ]] || break\n    done\n    ((i < 4096)) || fail\n  done\n  for name in out err; do\n    read_file "$root/state/logs-$name.closed"\n    read -r a b size closure <<< "$REPLY"\n    [[ $a == 0 && $b == 0 && $size =~ ^[0-9]+$ && $closure == eof ]] || fail\n    if [[ $name == out ]]; then ((size <= 16384)) || fail; else ((size <= 4096)) || fail; fi\n  done\n  read_file "$root/state/logs-captures"\n  read -r out err <<< "$REPLY"\n  [[ $out == "$captures"/work.*.out && $err == "$captures"/work.*.err ]] || fail\n  for name in "$out" "$err"; do\n    [[ -f $name && ! -L $name ]] || fail\n    while IFS= read -r line || [[ -n $line ]]; do\n      if [[ $line =~ Reached\\ target\\ .*Multi-User\\ System.*|detected\\ cgroup\\ v1 ]]; then marker=1; fi\n    done < "$name"\n  done\n  ((marker)) || fail\n  if [[ -e $root/state/logs-wrapper.status ]]; then\n    read_file "$root/state/logs-wrapper.status"\n    [[ $REPLY == 0 ]] || fail\n    state=direct-wait-zero\n  else\n    state=retired-wait-and-signal-cause-unavailable\n  fi\n  [[ ! -e $root/state/poison ]] || fail\n  printf \'%s\\n\' "$state" > "$root/state/logs-retirement"\n}\n', 'logs_retirement() {\n  local name pid start actual tail record i state marker=0 line a b size closure\n  [[ ! -e $root/state/poison ]] || fail a\n  for name in wrapper child out err out-dd out-tee err-dd err-tee; do\n    read_file "$root/state/logs-$name.identity"\n    read -r pid start <<< "$REPLY"\n    [[ $pid =~ ^[1-9][0-9]{0,4}$ && $start =~ ^[0-9]+$ ]] || fail b\n    ((pid < pid_max)) || fail c\n    # No helper or sleep process; original work end still applies throughout.\n    for ((i = 0; i < 4096; i++)); do\n      clock_check p\n      [[ -d /proc/$pid ]] || break\n      IFS= read -r record < "/proc/$pid/stat" || fail d\n      [[ ${record%% *} == "$pid" ]] || fail e\n      tail=${record##*) }\n      local -a parts\n      read -ra parts <<< "$tail"\n      ((${#parts[@]} >= 20)) && [[ ${parts[19]} =~ ^[0-9]+$ ]] || fail f\n      [[ ${parts[19]} == "$start" ]] || break\n    done\n    ((i < 4096)) || fail g\n  done\n  for name in out err; do\n    read_file "$root/state/logs-$name.closed"\n    read -r a b size closure <<< "$REPLY"\n    [[ $a == 0 && $b == 0 && $size =~ ^[0-9]+$ && $closure == eof ]] || fail h\n    if [[ $name == out ]]; then ((size <= 16384)) || fail i; else ((size <= 4096)) || fail j; fi\n  done\n  read_file "$root/state/logs-captures"\n  read -r out err <<< "$REPLY"\n  [[ $out == "$captures"/work.*.out && $err == "$captures"/work.*.err ]] || fail k\n  for name in "$out" "$err"; do\n    [[ -f $name && ! -L $name ]] || fail l\n    while IFS= read -r line || [[ -n $line ]]; do\n      if [[ $line =~ Reached\\ target\\ .*Multi-User\\ System.*|detected\\ cgroup\\ v1 ]]; then marker=1; fi\n    done < "$name"\n  done\n  ((marker)) || fail m\n  if [[ -e $root/state/logs-wrapper.status ]]; then\n    read_file "$root/state/logs-wrapper.status"\n    [[ $REPLY == 0 ]] || fail n\n    state=direct-wait-zero\n  else\n    state=retired-wait-and-signal-cause-unavailable\n  fi\n  [[ ! -e $root/state/poison ]] || fail o\n  printf \'%s\\n\' "$state" > "$root/state/logs-retirement"\n}\n'), ('local state=not-established marker=false', 'local state=${guard_reason:-not-established} marker=false'), ('kubernetes-lens-owned-rootful-result-v1', 'kubernetes-lens-owned-rootful-result-v2'), ('# Original phase receiver, never a new observer, verifies all exact identities\n# retired. Missing/unreadable records fail. A reused number is never signalled.', '# Existing retirement proof; no new observer or signals.'), ('    # No helper or sleep process; original work end still applies throughout.', '    # Original end; no helper or sleep.'), ('# Closed trusted-guest report only: no raw log data or guessed signal/status.\n# Missing records remain null on failure; positive retirement requires all roles.', '# Closed guest report; missing failure records stay null.')]

def receiver_before_guard_reason(source):
    """Invert only the exact ADR0073 seam before immutable earlier anchors."""
    import hashlib
    if hashlib.sha256(source.encode()).hexdigest() != GUARD_REASON_SOURCE:
        raise AssertionError('guard-reason-current-source')
    for previous, current in reversed(GUARD_REASON_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('guard-reason-exact-source-delta')
        source = source.replace(current, previous, 1)
    if hashlib.sha256(source.encode()).hexdigest() != POSTCREATE_PREFIX_SOURCE:
        raise AssertionError('guard-reason-previous-source')
    return source

def receiver_before_postcreate_prefix(source):
    """Invert only ADR0072; immutable earlier receiver anchors remain exact."""
    source = receiver_before_guard_reason(source)
    import hashlib
    if hashlib.sha256(source.encode()).hexdigest() != POSTCREATE_PREFIX_SOURCE:
        raise AssertionError('postcreate-prefix-current-source')
    for previous, current in reversed(POSTCREATE_PREFIX_SOURCE_DELTA):
        if source.count(current) != 1:
            raise AssertionError('postcreate-prefix-exact-source-delta')
        source = source.replace(current, previous, 1)
    if hashlib.sha256(source.encode()).hexdigest() != CURRENT_KIND_FAILURE_SOURCE:
        raise AssertionError('postcreate-prefix-previous-source')
    return source

def receiver_before_kind_create_failure(source):
    """Invert only the exact current diagnostic delta; preserve historical anchors."""
    source = receiver_before_postcreate_prefix(source)
    import hashlib
    if hashlib.sha256(source.encode()).hexdigest() != CURRENT_KIND_FAILURE_SOURCE:
        raise AssertionError('kind-failure-current-source')
    for previous, current in KIND_FAILURE_SOURCE_DELTA:
        if source.count(current) != 1:
            raise AssertionError('kind-failure-exact-source-delta')
        source = source.replace(current, previous, 1)
    if hashlib.sha256(source.encode()).hexdigest() != PREVIOUS_KIND_FAILURE_SOURCE:
        raise AssertionError('kind-failure-previous-source')
    return source


def receiver_before_node_monochrome(source):
    """Reverse only ADR0067's fixed node argv delta to immutable V22 bytes."""
    source = receiver_before_kind_create_failure(source)
    import hashlib
    current = '  executed_args=("${args[@]:0:${#args[@]}-1}" --pull=never -e SYSTEMD_COLORS=0 "$image_id")'
    previous = '  executed_args=("${args[@]:0:${#args[@]}-1}" --pull=never "$image_id")'
    if source.count(current) != 1:
        raise AssertionError('node-monochrome-exact-argv-anchor')
    normalized = source.replace(current, previous)
    if hashlib.sha256(normalized.encode()).hexdigest() != 'b323efa06dbafdd4958ac593c9fe7081e97535e87963f8508149b2ab2d8b9647':
        raise AssertionError('node-monochrome-reverse-v22-source')
    return normalized


def receiver_before_private_prefix(source):
    """Invert exact current presentation and ADR0065 deltas to original V18."""
    source = receiver_before_node_monochrome(source)
    import hashlib
    start = source.index('remember() {\n')
    end = source.index('# Called by finish from the fixed EXIT trap; not a standalone entrypoint.\n# shellcheck disable=SC2329\nemit_evidence() {', start)
    if hashlib.sha256(source[start:end].encode()).hexdigest() != 'b94fa423dcf97fca28439df1543baab250ff61e72d85481c38a9dcb169cca8a1':
        raise AssertionError('private-prefix-exact-proposal-fragment')
    original_remember = 'remember() {\n  case $1 in podman-info | manifest | config | image-inspect | network-inspect | node-inspect) ;; *) fail ;; esac\n  [[ $2 == "$captures"/work.*.out && -f $2 && ! -L $2 ]] || fail\n  printf \'%s\\n\' "$2" > "$root/state/evidence.$1"\n}\n'
    source = source[:start]+original_remember+source[end:]
    changes = [
        ('for name in podman-info manifest config image-inspect network-inspect node-inspect node-init-stdout-prefix; do',
         'for name in podman-info manifest config image-inspect network-inspect node-inspect; do'),
        ('''    if [[ $name == node-init-stdout-prefix ]]; then
      [[ $path == "$root/state/node-init-stdout-prefix" && -f $path && ! -L $path ]] || fail
    else
      [[ $path == "$captures"/work.*.out && -f $path && ! -L $path ]] || fail
    fi''', '    [[ $path == "$captures"/work.*.out && -f $path && ! -L $path ]] || fail'),
        ('    [[ $name != node-init-stdout-prefix ]] || ((size <= 16384)) || fail\n', ''),
        ('  remember node-init-stdout-prefix\n  emit_evidence', '  emit_evidence'),
        ("&& state='source-deployment-positive'", '&& state=source-deployment-positive')]
    for new, old in changes:
        if source.count(new) != 1:
            raise AssertionError('private-prefix-reverse-anchor')
        source = source.replace(new, old)
    if hashlib.sha256(source.encode()).hexdigest() != '9120732254d5e5f3ba41b342d7a785daef74f69d30a68efe6c726d03d4c33f04':
        raise AssertionError('private-prefix-reverse-v18-source')
    return source


class HardNofileV2Controls(unittest.TestCase):
    """Private proc-shaped v2 cases; no live proc, guest or native invocation."""
    SOURCE = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
    fixture = InventoryDestinationControls.fixture
    stat = InventoryDestinationControls.stat
    prefix = InventoryDestinationControls.prefix
    refuse = InventoryDestinationControls.refuse
    snapshot_pair = InventoryDestinationControls.snapshot_pair
    guard = InventoryDestinationControls.guard

    def pid1(self):
        fixture = self.fixture()
        fixture.process.rename(fixture.proc/'1')
        fixture.process = fixture.proc/'1'
        (fixture.process/'task/101').rename(fixture.process/'task/1')
        fixture.task = fixture.process/'task/1'
        (fixture.process/'stat').write_text(self.stat(1))
        (fixture.task/'stat').write_text(self.stat(1))
        return fixture

    def test_fixed_h_is_exact_ten_digit_envelope_and_future_slot_product(self):
        self.assertIn('readonly fd_max=1073741816 pid_max=32768\n', self.SOURCE)
        self.assertIn('readonly hard_nofile_max=9999999999\n', self.SOURCE)
        self.assertEqual(self.guard('inv-nf-form'), '[[ $hard =~ ^[0-9]{1,10}$ ]] || fail inv-nf-form\n')
        self.assertEqual(self.guard('inv-nf-range'), '((hard <= hard_nofile_max)) || fail inv-nf-range\n')
        self.assertEqual((10**10-1)*32767, 327669999967233)
        self.assertLess(327669999967233, 2**63)

    def test_original_and_new_hard_boundaries_admit_without_repair(self):
        for hard in (0, 1, 1073741815, 1073741816, 1073741817, 9999999998, 9999999999):
            with self.subTest(hard=hard):
                fixture = self.fixture()
                raw = 'Max open files 0 '+str(hard)+' files\n'
                (fixture.task/'limits').write_text(raw)
                result = fixture.host.run_body(self.prefix(fixture)+'inventory; printf "%s" "$SNAP"\n')
                self.assertIn((':1000:'+str(hard)+':3,;').encode(), result)
                self.assertEqual((fixture.task/'limits').read_text(), raw)

    def test_h_plus_one_and_nonfinite_or_nondecimal_metadata_refuse_form_privately(self):
        for hard in ('10000000000', 'unlimited', '-1', '1.0', 'private-hard-value', ''):
            with self.subTest(hard=hard):
                fixture = self.pid1()
                (fixture.task/'limits').write_text('Max open files 1024 '+hard+' files\n')
                result = self.refuse(fixture, 'inventory\n', 'inv-nf-form')
                if hard:
                    self.assertNotIn(hard.encode(), result.stderr)
                self.assertNotIn(b'1000', result.stderr)

    def test_pid1_is_covered_and_large_hard_does_not_relax_current_fd_envelope(self):
        for fd, code in ((1073741815, None), (1073741816, 'inv-fd-range')):
            with self.subTest(fd=fd):
                fixture = self.pid1()
                (fixture.task/'limits').write_text('Max open files 1024 9999999999 files\n')
                (fixture.task/'fd'/str(fd)).touch()
                if code:
                    self.refuse(fixture, 'inventory\n', code)
                else:
                    result = fixture.host.run_body(self.prefix(fixture)+'inventory; printf "%s" "$SNAP"\n')
                    self.assertIn(b'1:1000:1:1000:9999999999:', result)
                    self.assertIn(b'1073741815,', result)

    def test_large_hard_pid1_does_not_exempt_other_task_limits_or_fd_indices(self):
        for hard, fd, code in (('unlimited', '3', 'inv-nf-form'),
                               ('9999999999', '1073741816', 'inv-fd-range')):
            with self.subTest(hard=hard, fd=fd):
                fixture = self.pid1()
                (fixture.task/'limits').write_text('Max open files 1024 9999999999 files\n')
                task = fixture.process/'task/2'; (task/'fd').mkdir(parents=True)
                (task/'stat').write_text(self.stat(2))
                (task/'limits').write_text('Max open files 1024 '+hard+' files\n')
                (task/'fd'/fd).touch()
                self.refuse(fixture, 'inventory\n', code)

    def test_larger_inherited_hard_and_lower_nr_open_are_independent_checks(self):
        form = self.guard('nr-open-form'); limit = self.guard('nr-open-range')
        self.assertEqual(limit, '((value > 0 && value <= fd_max)) || fail nr-open-range\n')
        for nr_open, code in (('1', None), ('1073741816', None),
                              ('0', 'nr-open-range'), ('1073741817', 'nr-open-range')):
            with self.subTest(nr_open=nr_open):
                fixture = self.pid1()
                (fixture.task/'limits').write_text('Max open files 1024 9999999999 files\n')
                body = 'value='+nr_open+'\n'+form+limit+'inventory\n'
                if code:
                    self.refuse(fixture, body, code)
                else:
                    result = fixture.host.run_body(self.prefix(fixture)+body+'printf accepted\n')
                    self.assertEqual(result, b'accepted')

    def test_healthy_ten_character_hard_snapshots_admit_but_limit_drift_refuses(self):
        fixture = self.pid1()
        (fixture.task/'limits').write_text('Max open files 1024 9999999999 files\n')
        self.assertEqual(fixture.host.run_body(self.prefix(fixture)+self.snapshot_pair()+'printf accepted\n'), b'accepted')
        fixture = self.pid1()
        (fixture.task/'limits').write_text('Max open files 1024 1073741817 files\n')
        self.assertEqual(fixture.host.definitions.count('inventory() {'), 1)
        fixture.host.definitions = fixture.host.definitions.replace('inventory() {', 'source_inventory() {', 1)
        body = """invocations=0
inventory() {
 source_inventory
 invocations=$((invocations + 1))
 if ((invocations == 1)); then printf '%s\\n' 'Max open files 1024 9999999999 files' > "$inventory_proc/1/task/1/limits"; fi
}
"""+self.snapshot_pair()
        self.refuse(fixture, body, 'inv-drift')

    def test_reverse_normalization_preserves_entire_v16_receiver_and_exact_query_sites(self):
        import hashlib
        import re
        source = receiver_before_private_prefix(receiver_before_poll_diagnostic(receiver_before_k_stage(self.SOURCE)))
        self.assertEqual(source.count('readonly hard_nofile_max=9999999999\n'), 1)
        self.assertEqual(source.count('((hard <= hard_nofile_max)) || fail inv-nf-range'), 1)
        normalized = source.replace('readonly hard_nofile_max=9999999999\n', '').replace(
            '((hard <= hard_nofile_max)) || fail inv-nf-range', '((hard <= fd_max)) || fail inv-nf-range')
        self.assertEqual(hashlib.sha256(normalized.encode()).hexdigest(),
                         'd5d77a0298248e1de780e20f334fff42a4bf639358d605f61959bbf0f196a343')
        queries = [line for line in source.splitlines() if re.search(r'\bu /', line)]
        self.assertEqual(len(queries), 50)  # Original49 plus existing separately budgeted stage flock.
        self.assertEqual(len([line for line in queries if 'u /usr/bin/flock -n 9' not in line]), 49)
        self.assertEqual(hashlib.sha256(('\n'.join(queries)+'\n').encode()).hexdigest(),
                         '12cb936be87e4314af27bd97edb63ed168266cdb8653696071a2db3c3f08d48b')


class FailurePrefixControls(unittest.TestCase):
    def test_fixed_role_reuses_direct_catalogue_and_rejects_path_argument(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        self.assertNotIn('remember_node_init_failure() {', source)
        self.assertIn('remember manifest "$out"', source)
        self.assertIn('[[ $name != node-init-stdout-prefix ]] || remember node-init-stdout-prefix', source)
        fixture = self.shell_fixture(b'legacy-catalogue-raw')
        output = fixture.run_body(self.body()+'''create_status=-1
remember config "$captures/work.1.out"
emit_evidence
printf '%s\\n' "$evidence_json"
''')
        files = json.loads(output)['files']
        self.assertEqual(set(files), {'config'})
        self.assertEqual(base64.b64decode(files['config']['base64']), b'legacy-catalogue-raw')
        self.assertFalse((fixture.root/'state/node-init-stdout-prefix').exists())
        fixture = self.shell_fixture()
        result = fixture.child(self.body()+'remember node-init-stdout-prefix "$captures/work.1.out"; printf forbidden').finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'forbidden', result.stdout)
        self.assertFalse((fixture.root/'state/evidence.node-init-stdout-prefix').exists())

    def test_quoted_success_state_has_exact_original_truth_table(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        statement = next(line.strip() for line in source.splitlines()
                         if "&& state='source-deployment-positive'" in line)
        for status, create, delete in ((0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1), (0, -1, 0)):
            fixture = self.shell_fixture()
            output = fixture.run_body(f'status={status}\ncreate_status={create}\ndelete_status={delete}\nstate=failed\n'+statement+'\nprintf "%s" "$state"')
            expected = b'source-deployment-positive' if status == create == delete == 0 else b'failed'
            self.assertEqual(output, expected)

    def test_exact_delta_reverse_reconstructs_v18_and_rejects_unrelated_mutations(self):
        import hashlib
        source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        before = receiver_before_private_prefix(receiver_before_poll_diagnostic(source))
        self.assertEqual(hashlib.sha256(before.encode()).hexdigest(), '9120732254d5e5f3ba41b342d7a785daef74f69d30a68efe6c726d03d4c33f04')
        changes = [('count=16384 status=none', 'count=16385 status=none'),
                   ('u /usr/bin/rpm', 'u /usr/bin/stat'),
                   ('--wait 0s', '--wait 1s'),
                   ('record_guard_fuel=0', 'record_guard_fuel=1')]
        for old, new in changes:
            self.assertIn(old, source)
            with self.subTest(old=old), self.assertRaises(AssertionError):
                receiver_before_private_prefix(receiver_before_poll_diagnostic(source.replace(old, new, 1)))

    def bundle(self, raw=b'private-node-init-prefix\x00credential-shaped-text\xff', count=None):
        config, value, _ = DurableEvidenceControls.bundle(self)
        value.update(state='failed', kind_create_status=1, source_deployment='not-reached')
        value['logs'].update(state='not-established', startup_marker=False,
                             wrapper_observed_child_wait_status=None)
        value['logs']['collectors']['out'].update(bytes=len(raw) if count is None else count,
                                                 source_eof=False)
        value['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE] = {
            'bytes': len(raw), 'sha256': vm.digest(raw), 'base64': base64.b64encode(raw).decode()}
        return config, value, raw

    def encode(self, value):
        return vm.encode(value)+b'\n'

    def test_private_binary_prefix_persists_exclusively_and_public_summary_is_reference_only(self):
        config, value, prefix = self.bundle()
        raw = self.encode(value)
        with tempfile.TemporaryDirectory(prefix='prefix-private-') as directory:
            parent = Path(directory)
            record = rootful.durable_wire(raw, config, parent, vm.Budget(time.monotonic()+30, 10))
            artifact = parent/record['name']
            self.assertEqual(parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
            self.assertEqual(artifact.read_bytes(), raw)
            self.assertNotIn(prefix[:20], vm.encode(record))
            self.assertNotIn(base64.b64encode(prefix), vm.encode(record))
            self.assertEqual(record['catalogue']['protected_files'], [{
                'role': rootful.PRIVATE_FAILURE_ROLE, 'bytes': len(prefix), 'sha256': vm.digest(prefix),
                'protected': True, 'scope': 'pre-readiness-node-init-only',
                'completeness': 'diagnostic-prefix-only'}])
            with self.assertRaises(vm.Refusal):
                rootful.durable_wire(raw, config, parent, vm.Budget(time.monotonic()+30, 10))
        with self.assertRaisesRegex(vm.Refusal, 'rootful-success-unproved'):
            rootful.wire_record(raw, config)
        self.assertEqual(rootful.wire_record(raw, config, allow_failure=True)['kind_create_status'], 1)

    def test_sentinel_is_not_retained_and_does_not_establish_eof_or_success(self):
        config, value, _ = self.bundle(b'x'*16384, count=16385)
        checked = rootful.wire_record(self.encode(value), config, allow_failure=True)
        self.assertFalse(checked['logs']['collectors']['out']['source_eof'])
        self.assertFalse(checked['logs']['startup_marker'])
        self.assertIsNone(checked['logs']['wrapper_observed_child_wait_status'])
        self.assertEqual(checked['state'], 'failed')
        value['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE]['base64'] = base64.b64encode(b'x'*16385).decode()
        value['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE].update(bytes=16385, sha256=vm.digest(b'x'*16385))
        with self.assertRaisesRegex(vm.Refusal, 'rootful-private-prefix-capture'):
            rootful.wire_record(self.encode(value), config, allow_failure=True)

    def test_success_post_application_ready_and_missing_capture_refuse(self):
        changes = [lambda v: v.update(kind_create_status=-1),
                   lambda v: v.update(source_deployment='server-dry-run-observed'),
                   lambda v: v['logs'].update(state='direct-wait-zero', startup_marker=True,
                                               wrapper_observed_child_wait_status=0),
                   lambda v: v['logs']['collectors'].update(out=None),
                   lambda v: v['logs']['collectors']['out'].update(bytes=1)]
        for change in changes:
            config, value, _ = self.bundle()
            change(value)
            with self.subTest(change=change), self.assertRaises(vm.Refusal):
                rootful.wire_record(self.encode(value), config, allow_failure=True)
        config, value, _ = self.bundle()
        value.update(state='source-deployment-positive', kind_create_status=0,
                     source_deployment='server-dry-run-observed')
        value['logs'].update(state='direct-wait-zero', startup_marker=True,
                             wrapper_observed_child_wait_status=0)
        value['logs']['collectors']['out'].update(source_eof=True)
        with self.assertRaises(vm.Refusal):
            rootful.wire_record(self.encode(value), config)

    def test_foreign_source_role_extra_raw_public_field_and_bad_hash_refuse(self):
        changes = [lambda v: v['evidence'].update(owner='c'*32),
                   lambda v: v['evidence'].update(plan_sha256='c'*64),
                   lambda v: v['evidence'].update(source_spec_sha256='c'*64),
                   lambda v: v.update(raw_prefix='secret'),
                   lambda v: v['evidence']['files'].update({'application-stdout': {'bytes': 1}}),
                   lambda v: v['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE].update(sha256='0'*64)]
        for change in changes:
            config, value, _ = self.bundle()
            change(value)
            with self.subTest(change=change), self.assertRaises(vm.Refusal):
                rootful.wire_record(self.encode(value), config, allow_failure=True)

    def test_raw_and_wire_aggregate_caps_remain_unchanged(self):
        config, value, _ = self.bundle(b'x'*16384, count=16385)
        raw = b'y'*(rootful.RAW_MAX-16384+1)
        value['evidence']['files'] = {
            rootful.PRIVATE_FAILURE_ROLE: value['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE],
            'podman-info': {'bytes': len(raw), 'sha256': vm.digest(raw), 'base64': base64.b64encode(raw).decode()}}
        with self.assertRaisesRegex(vm.Refusal, 'rootful-evidence-aggregate'):
            rootful.wire_record(self.encode(value), config, allow_failure=True)
        with self.assertRaisesRegex(vm.Refusal, 'rootful-wire-budget'):
            rootful.wire_record(b'x'*(rootful.EVIDENCE_MAX+1), config, allow_failure=True)
        self.assertEqual((rootful.RAW_MAX, rootful.EVIDENCE_MAX), (131072, 262144))

    def shell_fixture(self, raw=b'private\x00binary\xff', size=None):
        fixture = BashProtocolControls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        capture = fixture.root/'captures/work.1.out'
        capture.write_bytes(raw)
        (fixture.root/'state/logs-captures').write_text(str(capture)+' '+str(fixture.root/'captures/work.1.err')+'\n')
        (fixture.root/'state/logs-out.closed').write_text('0 0 '+str(len(raw) if size is None else size)+' failed\n')
        return fixture

    def body(self):
        return 'mode=cleanup\nsource_status=not-reached\ncreate_status=1\nspec_sha='+('c'*64)+'\n'

    def test_guest_reuses_four_utility_credits_and_keeps_binary_first16384_only(self):
        raw = bytes(range(256))*64+b'!'
        fixture = self.shell_fixture(raw)
        output = fixture.run_body(self.body()+'''remember node-init-stdout-prefix
emit_evidence
shopt -s nullglob
tokens=("$credits"/utility-cleanup.*)
printf '%s\\n%s\\n' "$evidence_json" "${#tokens[@]}"
''')
        wire, credits = output.splitlines()
        value = json.loads(wire)
        record = value['files'][rootful.PRIVATE_FAILURE_ROLE]
        self.assertEqual(base64.b64decode(record['base64']), raw[:16384])
        self.assertEqual(record['bytes'], 16384)
        self.assertEqual(credits, b'4')
        artifact = fixture.root/'state/node-init-stdout-prefix'
        self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
        self.assertEqual(artifact.read_bytes(), raw[:16384])

    def test_guest_omits_empty_missing_post_application_ready_and_unattempted_create(self):
        for condition in ('source_status=server-dry-run-observed', 'create_status=-1', 'printf ready > "$root/state/logs-retirement"',
                          'unset source_status; source_status=not-reached; printf "0 0 0 failed\\n" > "$root/state/logs-out.closed"'):
            fixture = self.shell_fixture()
            output = fixture.run_body(self.body()+condition+'\nremember node-init-stdout-prefix\nemit_evidence\nprintf "%s\\n" "$evidence_json"')
            self.assertEqual(json.loads(output)['files'], {})
            self.assertFalse((fixture.root/'state/node-init-stdout-prefix').exists())
        fixture = self.shell_fixture()
        (fixture.root/'state/logs-captures').unlink()
        self.assertEqual(fixture.run_body(self.body()+'remember node-init-stdout-prefix; printf absent'), b'absent')

    def test_guest_rejects_unrestricted_paths_symlinks_bad_closure_oversize_and_overwrite(self):
        for change in ('foreign-path', 'nested-path', 'wrong-pair', 'bad-index', 'symlink', 'bad-closure', 'oversize', 'destination-exists'):
            fixture = self.shell_fixture()
            if change == 'foreign-path':
                (fixture.root/'state/logs-captures').write_text('/etc/passwd '+str(fixture.root/'captures/work.1.err')+'\n')
            elif change == 'nested-path':
                nested = fixture.root/'captures/work.1/nested.out'
                nested.parent.mkdir(); nested.write_bytes(b'private')
                (fixture.root/'state/logs-captures').write_text(str(nested)+' '+str(fixture.root/'captures/work.1.err')+'\n')
            elif change == 'wrong-pair':
                (fixture.root/'state/logs-captures').write_text(str(fixture.root/'captures/work.1.out')+' '+str(fixture.root/'captures/work.2.err')+'\n')
            elif change == 'bad-index':
                (fixture.root/'state/logs-captures').write_text(str(fixture.root/'captures/work.70.out')+' '+str(fixture.root/'captures/work.70.err')+'\n')
            elif change == 'symlink':
                capture = fixture.root/'captures/work.1.out'
                capture.unlink(); capture.symlink_to('/etc/passwd')
            elif change == 'bad-closure':
                (fixture.root/'state/logs-out.closed').write_text('0 0 4 invented\n')
            elif change == 'oversize':
                (fixture.root/'state/logs-out.closed').write_text('0 0 16386 failed\n')
            else:
                (fixture.root/'state/node-init-stdout-prefix').write_bytes(b'preserved')
            result = fixture.child(self.body()+'remember node-init-stdout-prefix; printf forbidden').finish()
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'forbidden', result.stdout)
            self.assertNotIn(b'private', result.stdout+result.stderr)
            self.assertFalse((fixture.root/'state/evidence.node-init-stdout-prefix').exists())

    def test_guest_exhausted_cleanup_partition_omits_optional_prefix(self):
        fixture = self.shell_fixture()
        output = fixture.child(self.body()+'''for ((i=0;i<64;i++)); do take utility-cleanup 64 || fail; done
remember node-init-stdout-prefix
printf forbidden
''').finish()
        self.assertEqual((output.returncode, output.stdout), (0, b'forbidden'))
        self.assertFalse((fixture.root/'state/node-init-stdout-prefix').exists())
        self.assertFalse((fixture.root/'state/evidence.node-init-stdout-prefix').exists())
        self.assertEqual(len(list((fixture.root/'state/credits').glob('utility-cleanup.*'))), 64)

    def test_no_additional_native_queries_or_changed_capture_caps(self):
        source = Path(rootful.__file__).with_suffix('.sh').read_text()
        function = source.split('remember() {', 1)[1].split('\n}\n', 1)[0]
        self.assertNotIn('native ', function)
        self.assertIn('count=16384', function)
        self.assertIn('size <= 16385', function)
        self.assertIn('dd bs=1 count="$((maximum + 1))"', source)




class NodeMonochromeControls(unittest.TestCase):
    """Fixed node-only presentation argv; no runtime or upstream source executes."""
    def fixture(self):
        fixture = BashProtocolControls('test_exact_provider_identity_and_unknown_pull_create_cp_wait_refuse')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def incoming(self, profile):
        args = ['run', '--name', 'own-control-plane', '--hostname', 'own-control-plane',
                '--label', 'io.x-k8s.kind.role=control-plane', '--privileged', '--tmpfs', '/tmp',
                '--tmpfs', '/run', '--volume', 'c'*64+':/var:suid,exec,dev', '--volume', '/lib/modules:/lib/modules:ro',
                '-e', 'KIND_EXPERIMENTAL_CONTAINERD_SNAPSHOTTER', '--detach', '--tty', '--net', 'kind',
                '--label', 'io.x-k8s.kind.cluster=own', '-e', 'container=podman']
        if profile == 'modern-1.37.0':
            args.append('--cgroupns=private')
        return args + ['--volume', '/dev/mapper:/dev/mapper', '--publish=127.0.0.1:6443:6443/tcp',
                       '-e', 'KUBECONFIG=/etc/kubernetes/admin.conf', 'localhost/kubernetes-lens-node:owner']

    def translate(self, args, *, profile='modern-1.37.0', image='d'*64, ambient='unexpected'):
        fixture = self.fixture()
        quote = lambda value: "'" + value.replace("'", "'\\''") + "'"
        body = 'profile='+quote(profile)+'\ncluster=own\nnode=own-control-plane\nalias=localhost/kubernetes-lens-node:owner\nvolume='+quote('c'*64)+'\nimage_id='+quote(image)+'\n'
        body += 'SYSTEMD_COLORS='+quote(ambient)+'\nexport SYSTEMD_COLORS\n'
        body += 'args=('+' '.join(quote(a)for a in args)+')\n'
        body += 'if translate_run; then printf "accepted\\0"; printf "%s\\0" "${executed_args[@]}"; else printf "refused\\0"; fi\n'
        body += 'printf "ambient:%s\\0" "$SYSTEMD_COLORS"\n'
        output = fixture.run_body(body).split(b'\0')[:-1]
        self.assertEqual(list((fixture.root/'state/credits').iterdir()), [])
        return output

    def test_exact_fixed_node_env_precedes_image_and_all_other_run_elements_remain(self):
        for profile in ['legacy-1.20.15', 'modern-1.37.0']:
            incoming = self.incoming(profile)
            output = self.translate(incoming, profile=profile)
            self.assertEqual(output[0], b'accepted')
            actual = [value.decode()for value in output[1:-1]]
            self.assertEqual(actual, incoming[:-1]+['--pull=never', '-e', 'SYSTEMD_COLORS=0', 'd'*64])
            self.assertEqual(actual[-3:], ['-e', 'SYSTEMD_COLORS=0', 'd'*64])
            self.assertEqual(actual.count('SYSTEMD_COLORS=0'), 1)
            self.assertEqual(output[-1], b'ambient:unexpected')

    def test_host_env_values_never_forward_or_change_the_fixed_node_value(self):
        for ambient in ['1', 'false', '$(touch forbidden)', 'SYSTEMD_LOG_LEVEL=quiet', '']:
            output = self.translate(self.incoming('modern-1.37.0'), ambient=ambient)
            self.assertEqual(output[-4:-1], [b'-e', b'SYSTEMD_COLORS=0', b'd'*64])
            self.assertEqual(output[-1], ('ambient:'+ambient).encode())

    def test_extra_env_alias_value_image_and_other_command_refuse_without_debit(self):
        original = self.incoming('modern-1.37.0')
        cases = [original[:-1]+['-e','SYSTEMD_COLORS=1',original[-1]],
                 original[:-1]+['-e','SYSTEMD_COLORS=0',original[-1]],
                 original[:-1]+['--env=SYSTEMD_COLORS=0',original[-1]],
                 original[:-1]+['-e','SYSTEMD_LOG_LEVEL=quiet',original[-1]],
                 original[:-1]+['docker.io/foreign:latest'], ['--version'],
                 ['logs','-f','own-control-plane']]
        for args in cases:
            self.assertEqual(self.translate(args)[0], b'refused')
        for image in ['D'*64, 'd'*63, 'd'*65, 'not-a-digest']:
            self.assertEqual(self.translate(original, image=image)[0], b'refused')

    def test_reverse_is_exact_and_neither_capture_poison_retirement_nor_query_changed(self):
        import hashlib
        source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        normalized = receiver_before_node_monochrome(receiver_before_poll_diagnostic(source))
        self.assertEqual(hashlib.sha256(normalized.encode()).hexdigest(), 'b323efa06dbafdd4958ac593c9fe7081e97535e87963f8508149b2ab2d8b9647')
        for before, after in [('count=16384 status=none','count=16385 status=none'),
                              ('size > maximum','size >= maximum'),
                              ('logs_retirement\npostlog_site=r\nresource_check','resource_check'),
                              ('u /usr/bin/rpm','u /usr/bin/stat')]:
            self.assertIn(before, source)
            with self.assertRaises(AssertionError):
                receiver_before_node_monochrome(receiver_before_poll_diagnostic(source.replace(before,after,1)))
        self.assertNotIn('export SYSTEMD_COLORS', source)
        self.assertNotIn('SYSTEMD_URLIFY', source)
        self.assertNotIn('SYSTEMD_LOG_LEVEL', source)
        self.assertEqual(source.count('SYSTEMD_COLORS'), 2)

    def test_facts_are_immutable_source_metadata_not_runtime_or_a_new_pin(self):
        facts = json.loads(SCRIPT.with_name('owned-node-monochrome-source-facts.json').read_bytes())
        self.assertEqual(facts['schema'], 'kubernetes-lens-owned-node-monochrome-source-facts-v1')
        self.assertEqual(facts['implemented_selection']['variable'], 'SYSTEMD_COLORS')
        self.assertEqual(facts['implemented_selection']['value'], '0')
        self.assertFalse(facts['operational_tool_pin'])
        self.assertNotIn('/tmp/', json.dumps(facts))
        self.assertFalse(facts['implemented_selection']['caller_selected_or_ambient_forwarding'])
        self.assertEqual(facts['systemd_tag']['commit'], '70bae7648f2c18010187c9cf20093155eaa26029')
        self.assertEqual(facts['preserved']['private_failure_prefix_bytes'], 16384)
        self.assertEqual(facts['preserved']['fixed_diagnostic_patterns'], 314)
        self.assertEqual(facts['renovate']['existing_exclusion'], '**/fixtures/**')
        for source in facts['systemd_sources']:
            self.assertEqual(source['commit'], facts['systemd_tag']['commit'])
            self.assertEqual(source['license_spdx'], 'LGPL-2.1-or-later')
            self.assertEqual(len(source['blob_sha1']), 40)
            self.assertEqual(len(source['sha256']), 64)
        self.assertTrue(any('tail' in limit for limit in facts['evidence_limits']))

    def test_no_python_command_contract_needs_widening_and_resources_are_exact(self):
        self.assertEqual(rootful.GUEST_OUTPUT, 1048576)
        self.assertEqual(vm.OUTPUT_MAX, 2097152)
        self.assertEqual(rootful.RESOURCE_VALUES, {'cpus':2,'memory_mib':8192,'guest_memory_mib':4096,
                         'pids':256,'disk_gib':24,'deadline_seconds':1800,'cleanup_seconds':120})
        self.assertEqual(rootful.PRIVATE_FAILURE_ROLE, 'node-init-stdout-prefix')
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        self.assertIn('dd bs=1 count="$((maximum + 1))"', source)
        self.assertIn('count=16384 status=none', source)
        self.assertIn('[[ $domain == work && $maximum == 16384 && $error_max == 4096 &&', source)

class PostCreatePrefixPrepaymentControls(unittest.TestCase):
    """Conditional diagnosis admission; no runtime or historical data acquisition."""

    shell_fixture = FailurePrefixControls.shell_fixture
    body = FailurePrefixControls.body

    def test_actual_create_zero_failed_gate_keeps_binary_and_actual_statuses(self):
        old = FailurePrefixControls()
        config, value, raw = old.bundle(b'fixed\x00post-create\xff')
        value.update(kind_create_status=0, kind_delete_status=0)
        checked = rootful.wire_record(old.encode(value), config, allow_failure=True)
        self.assertEqual((checked['state'], checked['kind_create_status'], checked['kind_delete_status']),
                         ('failed', 0, 0))
        self.assertEqual(checked['source_deployment'], 'not-reached')
        self.assertEqual(checked['logs']['state'], 'not-established')
        self.assertFalse(checked['logs']['startup_marker'])
        self.assertEqual(checked['evidence']['protected_files'][0]['role'], rootful.PRIVATE_FAILURE_ROLE)
        self.assertNotIn(raw, vm.encode(checked))
        self.assertNotIn(base64.b64encode(raw), vm.encode(checked))
        with self.assertRaisesRegex(vm.Refusal, 'rootful-success-unproved'):
            rootful.wire_record(old.encode(value), config)
        fixture = self.shell_fixture(raw)
        wire = fixture.run_body(self.body()+'create_status=0\nremember node-init-stdout-prefix\n'
                                'emit_evidence\nprintf "%s" "$evidence_json"')
        self.assertEqual(base64.b64decode(json.loads(wire)['files'][rootful.PRIVATE_FAILURE_ROLE]['base64']), raw)

    def test_zero_scope_refuses_boolean_and_invalid_status_values_on_real_host_paths(self):
        old = FailurePrefixControls()
        for status in (False, True, None, '0', -1, 256):
            with self.subTest(status=status):
                config, value, _ = old.bundle()
                value['kind_create_status'] = status
                with self.assertRaises(vm.Refusal):
                    rootful.wire_record(old.encode(value), config, allow_failure=True)
                with self.assertRaises(vm.Refusal):
                    rootful.evidence(value['evidence'], config, complete=False, failure=value)
        for status in (0, 1, 255):
            config, value, _ = old.bundle()
            value['kind_create_status'] = status
            checked = rootful.wire_record(old.encode(value), config, allow_failure=True)
            self.assertEqual(checked['kind_create_status'], status)

    def test_zero_through_three_credits_have_no_prefix_effect_four_exactly_pays_all(self):
        for available in range(5):
            with self.subTest(available=available):
                fixture = self.shell_fixture()
                output = fixture.run_body(self.body()+f'''create_status=0
for ((i=0;i<{64-available};i++)); do take utility-cleanup 64 || fail; done
remember node-init-stdout-prefix
emit_evidence
printf '%s\n%s\n' "$evidence_json" "$prefix_claimed"
''')
                wire, claimed = output.splitlines()
                self.assertEqual(claimed, b'1')
                self.assertEqual(bool(json.loads(wire)['files']), available == 4)
                destination = fixture.root/'state/node-init-stdout-prefix'
                self.assertEqual(destination.exists(), available == 4)
                self.assertEqual((fixture.root/'state/evidence.node-init-stdout-prefix').exists(), available == 4)
                credits = fixture.root/'state/credits'
                self.assertEqual(len(list(credits.glob('utility-cleanup.*'))), 64)
                self.assertEqual(len(list(credits.glob('used.utility-cleanup.*'))), 4 if available == 4 else 0)
                self.assertFalse(list(credits.glob('utility-work.*')))

    def test_denied_partial_reservation_is_sticky_and_spent_without_execution(self):
        for available in range(4):
            with self.subTest(available=available):
                fixture = self.shell_fixture()
                fixture.run_body(self.body()+f'''for ((i=0;i<{64-available};i++)); do take utility-cleanup 64 || fail; done
remember node-init-stdout-prefix
remember node-init-stdout-prefix
cursor[utility-cleanup]=0
remember node-init-stdout-prefix
[[ $prefix_claimed == 1 && ${{#prefix_tickets[@]}} == {available} ]] || fail
if grant_utility; then fail; fi
''')
                credits = fixture.root/'state/credits'
                self.assertEqual(len(list(credits.glob('utility-cleanup.*'))), 64)
                self.assertFalse(list(credits.glob('used.utility-cleanup.*')))
                self.assertFalse(list(credits.glob('utility-work.*')))
                self.assertFalse((fixture.root/'state/node-init-stdout-prefix').exists())

    def test_prepaid_copy_and_catalogue_cannot_reexecute_or_double_charge(self):
        fixture = self.shell_fixture()
        output = fixture.run_body(self.body()+'''remember node-init-stdout-prefix
remember node-init-stdout-prefix
emit_evidence
if (emit_evidence); then fail; fi
printf charged-once
''')
        self.assertEqual(output, b'charged-once')
        credits = fixture.root/'state/credits'
        self.assertEqual(len(list(credits.glob('utility-cleanup.*'))), 4)
        self.assertEqual(len(list(credits.glob('used.utility-cleanup.*'))), 4)
        self.assertFalse(list(credits.glob('utility-work.*')))

    def test_prefix_is_unavailable_in_work_mode_without_borrowing_its_unused_pool(self):
        fixture = self.shell_fixture()
        output = fixture.run_body(self.body()+'''mode=work
remember node-init-stdout-prefix
emit_evidence
printf '%s' "$evidence_json"
''')
        self.assertEqual(json.loads(output)['files'], {})
        self.assertFalse((fixture.root/'state/node-init-stdout-prefix').exists())
        self.assertFalse(list((fixture.root/'state/credits').glob('utility-*')))

    def test_copy_failure_keeps_all_four_reserved_and_reentry_cannot_refund_them(self):
        fixture = self.shell_fixture()
        fixture.definitions = fixture.definitions.replace('utility_launch() {', 'original_utility_launch() {', 1)
        wrapper = '''utility_launch() {
  if [[ $2 == /usr/bin/dd ]]; then
    original_utility_launch "$1" /usr/bin/dd if="$root/absent" status=none
  else original_utility_launch "$@"; fi
}
'''
        result = fixture.child(self.body()+wrapper+'remember node-init-stdout-prefix\nprintf forbidden').finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'forbidden', result.stdout)
        self.assertFalse((fixture.root/'state/evidence.node-init-stdout-prefix').exists())
        credits = fixture.root/'state/credits'
        self.assertEqual(len(list(credits.glob('utility-cleanup.*'))), 4)
        self.assertEqual(len(list(credits.glob('used.utility-cleanup.*'))), 1)
        repeat = fixture.child(self.body()+'remember node-init-stdout-prefix').finish()
        self.assertNotEqual(repeat.returncode, 0)
        self.assertEqual(len(list(credits.glob('utility-cleanup.*'))), 4)
        self.assertFalse(list(credits.glob('utility-work.*')))

    def test_catalogue_failure_leaves_unused_prepaid_ticket_spent_without_refund(self):
        fixture = self.shell_fixture()
        fixture.definitions = fixture.definitions.replace('utility_launch() {', 'original_utility_launch() {', 1)
        wrapper = '''utility_launch() {
  if [[ $2 == /usr/bin/sha256sum ]]; then
    original_utility_launch "$1" /usr/bin/sha256sum "$root/absent"
  else original_utility_launch "$@"; fi
}
'''
        result = fixture.child(self.body()+wrapper+'remember node-init-stdout-prefix\nemit_evidence\nprintf forbidden').finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'forbidden', result.stdout)
        self.assertNotIn(b'private', result.stdout+result.stderr)
        credits = fixture.root/'state/credits'
        self.assertEqual(len(list(credits.glob('utility-cleanup.*'))), 4)
        self.assertEqual(len(list(credits.glob('used.utility-cleanup.*'))), 3)
        self.assertTrue((fixture.root/'state/node-init-stdout-prefix').exists())
        self.assertFalse(list(credits.glob('utility-work.*')))

    def test_all_six_ordinary_roles_are_paid_and_emitted_before_optional_prefix_admission(self):
        roles = ('podman-info', 'manifest', 'config', 'image-inspect', 'network-inspect', 'node-inspect')
        for remaining in range(18, 23):
            with self.subTest(remaining=remaining):
                fixture = self.shell_fixture()
                body = self.body()+f'for ((i=0;i<{64-remaining};i++)); do take utility-cleanup 64 || fail; done\n'
                body += ''.join('remember '+role+' "$captures/work.1.out"\n' for role in roles)
                output = fixture.run_body(body+'emit_evidence\nprintf "%s" "$evidence_json"')
                files = json.loads(output)['files']
                self.assertEqual(set(files), set(roles) | ({rootful.PRIVATE_FAILURE_ROLE} if remaining == 22 else set()))
                self.assertEqual((fixture.root/'state/node-init-stdout-prefix').exists(), remaining == 22)
                credits = fixture.root/'state/credits'
                self.assertEqual(len(list(credits.glob('utility-cleanup.*'))), 64)
                self.assertEqual(len(list(credits.glob('used.utility-cleanup.*'))), 22 if remaining == 22 else 18)
                self.assertFalse(list(credits.glob('utility-work.*')))

    def test_original_failure_and_mandatory_cleanup_precede_every_optional_reservation(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        finish = 'finish() {'+source.split('finish() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
        self.assertLess(finish.index('native 4096 4096'), finish.index('emit_evidence'))
        self.assertNotIn('remember node-init-stdout-prefix', finish)
        self.assertIn('[[ $name != node-init-stdout-prefix ]] || remember node-init-stdout-prefix', source)
        for available in range(5):
            with self.subTest(available=available):
                fixture = self.shell_fixture()
                body = self.body()+f'''mode=work
for ((i=0;i<{60-available};i++)); do take utility-cleanup 64 || fail; done
created=1 create_status=0 delete_status=-1 profile=legacy-1.20.15 patch=1.20.15 cluster=own
native() {{
  [[ ! -e $root/state/node-init-stdout-prefix && ! ${{prefix_claimed+x}} ]] || fail
  for ((i=0;i<4;i++)); do grant_utility || fail; done
  printf cleanup > "$root/state/cleanup-ran"
  last_tool_status=0
}}
'''
                result = fixture.child(body+finish+'trap finish EXIT\nexit 3\n').finish()
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertTrue((fixture.root/'state/cleanup-ran').exists())
                self.assertTrue((fixture.root/'state/poison').exists())
                value = json.loads(result.stdout)
                self.assertEqual((value['state'], value['kind_create_status'], value['kind_delete_status']),
                                 ('failed', 0, 0))
                self.assertEqual(bool(value['evidence']['files']), available == 4)
                self.assertFalse(list((fixture.root/'state/credits').glob('utility-work.*')))

    def test_only_exact_source_delta_changes_with_original_caps_and_query_patterns(self):
        import hashlib
        source = receiver_before_guard_reason(receiver_before_poll_diagnostic(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))))
        previous = receiver_before_postcreate_prefix(receiver_before_poll_diagnostic(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))))
        self.assertEqual(hashlib.sha256(previous.encode()).hexdigest(), CURRENT_KIND_FAILURE_SOURCE)
        self.assertLessEqual(len(source.encode()), 65536)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        self.assertEqual(rootful.reserve(vm.Budget(time.monotonic()+1800, 120))['utility_cleanup'], 64)
        for text in ('maximum=64', 'maximum=680', 'record_guard_fuel=0', 'take "$domain" "$max"',
                     'output_max=10', 'take sentinel 150 || fail'):
            self.assertEqual(source.count(text), previous.count(text))
        for section, end in [('provider() {', 'network_check() {'), ('native() {', 'info_check() {'),
                             ('emit_logs_evidence() {', '# Persistent work/cleanup')]:
            current = source.split(section, 1)[1].split(end, 1)[0]
            original = previous.split(section, 1)[1].split(end, 1)[0]
            if section == 'native() {':
                # Only a comment is shortened in native; executable lines are exact.
                current = '\n'.join(l for l in current.splitlines() if not l.lstrip().startswith('#'))
                original = '\n'.join(l for l in original.splitlines() if not l.lstrip().startswith('#'))
            self.assertEqual(current, original)


class KindCreateFailureEvidenceControls(unittest.TestCase):
    """Existing-capture retention only; native calls stay mocked or absent."""
    def fixture(self, raw=b'private\x00binary\xff', *, capture=0, wrapper=1):
        fixture = BashProtocolControls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        (fixture.root/'captures/work.1.err').write_bytes(raw)
        body = ('mode=work\nsource_status=not-reached\ncreate_status=1\n'
                'kind_failure_wrapper_status='+str(wrapper)+'\nkind_failure_stdout_status=0\n'
                'kind_failure_stderr_status='+str(capture)+'\nkind_failure_err=$captures/work.1.err\n'
                'spec_sha='+('c'*64)+'\n')
        return fixture, body

    def catalogue(self, raw, *, capture=0, wrapper=1):
        fixture, body = self.fixture(raw, capture=capture, wrapper=wrapper)
        wire = fixture.run_body(body+'''preserve_kind_create_failure
mode=cleanup
emit_evidence
printf '%s\\n' "$evidence_json"
shopt -s nullglob
work=("$credits"/utility-work.*); cleanup=("$credits"/utility-cleanup.*)
printf '%s %s\\n' "${#work[@]}" "${#cleanup[@]}"
''')
        encoded, counts = wire.splitlines()
        value = json.loads(encoded)
        attribution = json.loads(base64.b64decode(value['files'][rootful.KIND_ATTRIBUTION_ROLE]['base64']))
        return fixture, value, attribution, counts

    def test_binary_prefix_boundaries_overflow_and_unknown_eof(self):
        for size in (0, 1, 4095, 4096, 4097, 32768, 32769):
            for complete in (False, True):
                if size == 32769 and complete:
                    continue
                with self.subTest(size=size, complete=complete):
                    raw = (bytes(range(256))*129)[:size]
                    fixture, value, attribution, counts = self.catalogue(
                        raw, capture=0 if complete else 1, wrapper=1 if complete else 125)
                    self.assertEqual(attribution['stderr_captured_bytes'], size)
                    self.assertEqual(attribution['stderr_prefix_bytes'], min(size, 4096))
                    self.assertEqual(attribution['stderr_prefix_truncated'], size > 4096)
                    self.assertEqual(attribution['stderr_overflow_sentinel'], size == 32769)
                    self.assertIs(attribution['stderr_source_eof'], True if complete else None)
                    self.assertIsNone(attribution['provider_child_wait_status'])
                    self.assertIsNone(attribution['provider_wrapper_status'])
                    self.assertEqual(counts, b'8 0' if size else b'4 0')
                    self.assertEqual(len(list((fixture.root/'state/credits').glob('used.utility-work.*'))), 8 if size else 4)
                    if size:
                        record = value['files'][rootful.KIND_STDERR_ROLE]
                        self.assertEqual(base64.b64decode(record['base64']), raw[:4096])
                    for name in value['files']:
                        self.assertEqual((fixture.root/'state'/name).stat().st_mode & 0o777, 0o600)
                    self.assertLessEqual(len(base64.b64decode(value['files'][rootful.KIND_ATTRIBUTION_ROLE]['base64'])), 1024)

    def bundle(self, raw=b'private-error\x00credential-shaped\xff', *, capture=0):
        config, value, _ = FailurePrefixControls.bundle(self)
        _, catalogue, attribution, _ = self.catalogue(raw, capture=capture, wrapper=1 if capture == 0 else 125)
        value['evidence']['files'].update(catalogue['files'])
        return config, value, attribution

    def test_durable_private_failure_is_content_free_in_public_summary(self):
        config, value, _ = self.bundle()
        raw = vm.encode(value)+b'\n'
        with tempfile.TemporaryDirectory(prefix='kind-private-') as directory:
            result = rootful.durable_wire(raw, config, Path(directory), vm.Budget(time.monotonic()+30, 10))
            self.assertEqual((Path(directory)/result['name']).stat().st_mode & 0o777, 0o600)
            self.assertEqual((Path(directory)/result['name']).read_bytes(), raw)
            public = vm.encode(result)
            for name in rootful.KIND_FAILURE_ROLES:
                protected = value['evidence']['files'][name]
                self.assertNotIn(protected['base64'].encode(), public)
                self.assertNotIn(base64.b64decode(protected['base64']), public)
            self.assertTrue(all(record['scope'] == 'kind-create-failure-only'
                                for record in result['catalogue']['protected_files']
                                if record['role'] in rootful.KIND_FAILURE_ROLES))
        with self.assertRaises(vm.Refusal):
            rootful.wire_record(raw, config)

    def test_private_attribution_refuses_mutation_missing_prefix_and_promoted_eof(self):
        config, value, attribution = self.bundle(capture=1)
        for change in (lambda v: v.update(kind_child_wait_status=2),
                       lambda v: v.update(native_wrapper_status=0),
                       lambda v: v.update(stderr_captured_bytes=32770),
                       lambda v: v.update(stderr_prefix_bytes=4097),
                       lambda v: v.update(stderr_source_eof=True),
                       lambda v: v.update(stderr_prefix_truncated=True),
                       lambda v: v.update(provider_wrapper_status=1),
                       lambda v: v.update(stdout_capture_status=True)):
            bad = deepcopy(value); modified = deepcopy(attribution); change(modified)
            raw = vm.encode(modified)+b'\n'
            bad['evidence']['files'][rootful.KIND_ATTRIBUTION_ROLE] = {
                'bytes': len(raw), 'sha256': vm.digest(raw), 'base64': base64.b64encode(raw).decode()}
            with self.assertRaises(vm.Refusal):
                rootful.wire_record(vm.encode(bad)+b'\n', config, allow_failure=True)
        for role in rootful.KIND_FAILURE_ROLES:
            bad = deepcopy(value); del bad['evidence']['files'][role]
            with self.assertRaises(vm.Refusal):
                rootful.wire_record(vm.encode(bad)+b'\n', config, allow_failure=True)

    def test_zero_and_partial_work_credit_refusal_preserve_cleanup_reserve(self):
        for initial in (680, 677):
            fixture, body = self.fixture(b'private')
            for index in range(initial):
                (fixture.root/'state/credits'/('utility-work.'+str(index))).write_text('a'*32+' '+'b'*64+' own-test-boot\n')
            wire = fixture.run_body(body+'''if preserve_kind_create_failure; then exit 99; fi
mode=cleanup
grant_utility
printf '%s %s\\n' "$create_status" "$utility_ticket"
''')
            self.assertEqual(wire, b'1 utility-cleanup.0\n')
            self.assertFalse((fixture.root/'state/evidence.kind-create-attribution').exists())
            self.assertFalse((fixture.root/'state/evidence.kind-create-stderr-prefix').exists())
            self.assertEqual(len(list((fixture.root/'state/credits').glob('utility-work.*'))), 680)

    def test_prepaid_emission_tickets_cannot_be_reused_or_debit_cleanup(self):
        fixture, body = self.fixture(b'private')
        result = fixture.child(body+"""preserve_kind_create_failure
mode=cleanup
emit_evidence
emit_evidence
printf forbidden
""").finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'forbidden', result.stdout)
        self.assertNotIn(b'private', result.stdout+result.stderr)
        credits = fixture.root/'state/credits'
        self.assertEqual(len(list(credits.glob('utility-work.*'))), 8)
        self.assertEqual(len(list(credits.glob('used.utility-work.*'))), 8)
        self.assertEqual(len(list(credits.glob('utility-cleanup.*'))), 0)

    def test_preservation_credit_failure_still_runs_original_cleanup_and_poison(self):
        fixture, body = self.fixture(b'private')
        for index in range(680):
            (fixture.root/'state/credits'/('utility-work.'+str(index))).write_text('a'*32+' '+'b'*64+' own-test-boot\n')
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        finish = 'finish() {'+source.split('finish() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
        mock = '''created=1 delete_status=-1 profile=legacy-1.20.15 patch=1.20.15
cluster=own
native() { printf cleanup > "$root/state/cleanup-ran"; out=overwritten err=overwritten last_tool_status=0; return 0; }
remember() { :; }
emit_evidence() { evidence_json='{}'; }
emit_logs_evidence() { logs_json='{}'; }
'''
        result = fixture.child(body+finish+mock+'set +e\nfalse\nfinish\n').finish()
        self.assertEqual(result.returncode, 1)
        self.assertTrue((fixture.root/'state/cleanup-ran').exists())
        self.assertTrue((fixture.root/'state/poison').exists())
        value = json.loads(result.stdout)
        self.assertEqual((value['kind_create_status'], value['kind_delete_status'], value['state']), (1, 0, 'failed'))

    def test_emission_failure_keeps_private_capture_and_original_failure_after_cleanup(self):
        fixture, body = self.fixture(b'private\x00binary\xff')
        fixture.definitions = fixture.definitions.replace('utility_launch() {', 'original_utility_launch() {', 1)
        wrapper = """utility_launch() {
  [[ $2 != /usr/bin/base64 ]] || return 17
  original_utility_launch "$@"
}
"""
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        finish = 'finish() {'+source.split('finish() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
        mock = """created=1 delete_status=-1 profile=legacy-1.20.15 patch=1.20.15
cluster=own
native() { printf cleanup > "$root/state/cleanup-ran"; out=overwritten err=overwritten last_tool_status=0; return 0; }
remember() { :; }
emit_logs_evidence() { logs_json='{}'; }
"""
        result = fixture.child(body+wrapper+finish+mock+'set +e\nfalse\nfinish\n').finish()
        self.assertEqual(result.returncode, 1)
        self.assertTrue((fixture.root/'state/cleanup-ran').exists())
        self.assertTrue((fixture.root/'state/poison').exists())
        prefix = fixture.root/'state/kind-create-stderr-prefix'
        self.assertEqual(prefix.read_bytes(), b'private\x00binary\xff')
        self.assertEqual(prefix.stat().st_mode & 0o777, 0o600)
        attribution = json.loads((fixture.root/'state/kind-create-attribution').read_bytes())
        self.assertEqual((attribution['kind_child_wait_status'], attribution['native_wrapper_status']), (1, 1))
        self.assertNotIn(b'private', result.stdout+result.stderr)
        self.assertNotIn(b'base64', result.stdout+result.stderr)

    def test_existing_metadata_cap_with_maximum_fixed_failure_fields(self):
        config, value, _ = self.bundle(bytes(range(256))*16, capture=1)
        value.update(kind_create_status=255, kind_delete_status=255, native_actions=75,
                     utility_actions=768, utility_ledger_actions=744, output_reserved=rootful.GUEST_OUTPUT)
        protected = value['evidence']['files'][rootful.KIND_ATTRIBUTION_ROLE]
        attribution = json.loads(base64.b64decode(protected['base64']))
        attribution.update(kind_child_wait_status=255)
        raw = vm.encode(attribution)+b'\n'
        value['evidence']['files'][rootful.KIND_ATTRIBUTION_ROLE] = {
            'bytes': len(raw), 'sha256': vm.digest(raw), 'base64': base64.b64encode(raw).decode()}
        for index, role in enumerate(value['logs']['identities']):
            value['logs']['identities'][role] = {'pid': 32767-index, 'start': 2**63-2-index}
        value['logs']['wrapper_observed_child_wait_status'] = 255
        summary = deepcopy({key: item for key, item in value.items() if key != 'evidence'})
        for role, maximum in (('out', 16385), ('err', 4097)):
            summary['logs']['collectors'][role] = {
                'dd_status': 255, 'tee_status': 255, 'bytes': maximum, 'source_eof': False}
        self.assertLess(len(vm.encode(summary)+b'\n'), vm.META_MAX)
        self.assertEqual(rootful.result(vm.encode(summary)+b'\n', config, allow_failure=True)['state'], 'failed')
        self.assertLess(len(vm.encode(value)+b'\n'), rootful.EVIDENCE_MAX)
        checked = rootful.wire_record(vm.encode(value)+b'\n', config, allow_failure=True)
        self.assertEqual(checked['state'], 'failed')
        self.assertEqual((vm.META_MAX, rootful.EVIDENCE_MAX, rootful.RAW_MAX), (65536, 262144, 131072))

    def test_no_new_producer_native_credit_cleanup_reservation_or_runtime_claim(self):
        source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        prior = receiver_before_kind_create_failure(receiver_before_poll_diagnostic(source))
        function = source.split('preserve_kind_create_failure() {', 1)[1].split('\n}\n', 1)[0]
        self.assertNotIn('native ', function)
        self.assertNotIn('utility-cleanup', function)
        self.assertIn('remember kind-create-failure || status=1\n  if ((created)); then', source)
        self.assertEqual(source.count('native 16384 32768 "$stage/kind" create cluster'), 1)
        self.assertEqual(source.count('native 4096 4096 "$stage/kind" delete cluster'), 1)
        for text in ('maximum=64', 'maximum=680', 'take "$domain" "$max"', 'take sentinel 150'):
            self.assertEqual(source.count(text), prior.count(text))


class KindCreateInterruptedBindingControls(unittest.TestCase):
    """Independent reproduction of the reviewed V24 cleanup regression."""
    def fixture(self):
        fixture = BashProtocolControls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        (fixture.root/'captures/work.1.err').write_bytes(b'private-error')
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        finish = 'finish() {'+source.split('finish() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
        body = '''mode=work
source_status=not-reached
create_status=1
created=1 delete_status=-1 profile=legacy-1.20.15 patch=1.20.15
cluster=own
native() { printf cleanup > "$root/state/cleanup-ran"; out=overwritten err=overwritten last_tool_status=0; return 0; }
remember() { :; }
emit_evidence() { evidence_json='{}'; }
emit_logs_evidence() { logs_json='{}'; }
'''
        return fixture, body+finish

    def assert_original_failure_and_cleanup(self, fixture, result):
        self.assertEqual(result.returncode, 1)
        self.assertTrue((fixture.root/'state/cleanup-ran').exists())
        self.assertTrue((fixture.root/'state/poison').exists())
        value = json.loads(result.stdout)
        self.assertEqual((value['kind_create_status'], value['kind_delete_status'], value['state']), (1, 0, 'failed'))
        self.assertNotIn(b'private-error', result.stdout+result.stderr)

    def test_each_partial_or_malformed_optional_binding_preserves_cleanup_and_poison(self):
        for bindings in (
                '',
                'kind_failure_err=$captures/work.1.err\n',
                'kind_failure_err=$captures/work.1.err\nkind_failure_stdout_status=0\n',
                'kind_failure_err=$captures/work.1.err\nkind_failure_stderr_status=0\n',
                'kind_failure_err=$captures/work.1.err\nkind_failure_stdout_status=bad\nkind_failure_stderr_status=0\n',
                'kind_failure_err=$captures/work.1.err\nkind_failure_stdout_status=0\nkind_failure_stderr_status=999\n',
                'kind_failure_err=$captures/work.1.err\nkind_failure_stdout_status=09\nkind_failure_stderr_status=0\n',
                'kind_failure_wrapper_status=09\n'):
            with self.subTest(bindings=bindings):
                fixture, body = self.fixture()
                result = fixture.child(body+'kind_failure_wrapper_status=1\n'+bindings+'set +e\nfalse\nfinish\n').finish()
                self.assert_original_failure_and_cleanup(fixture, result)
                self.assertFalse((fixture.root/'state/evidence.kind-create-attribution').exists())

    def test_self_signal_with_only_wrapper_or_completed_snapshot_preserves_cleanup(self):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        snapshot = next(line for line in source.splitlines()
                        if line.startswith('  kind_failure_wrapper_status=$? create_status='))
        self.assertIn('kind_failure_err=${err:-}', snapshot)
        for completed in (False, True):
            with self.subTest(completed=completed):
                fixture, body = self.fixture()
                bindings = 'kind_failure_wrapper_status=1\n'
                if completed:
                    bindings = ('last_tool_status=1\nerr=$captures/work.1.err\n'
                                'last_stdout_capture_status=0\nlast_stderr_capture_status=0\n'
                                'if false; then :; else\n'+snapshot+'\nfi\n')
                trap = "trap finish EXIT\ntrap 'exit 1' ERR HUP INT TERM\n"
                result = fixture.child(body+trap+bindings+'kill -TERM "$BASHPID"\nprintf forbidden\n').finish()
                self.assert_original_failure_and_cleanup(fixture, result)
                self.assertNotIn(b'forbidden', result.stdout)


class KindCreateFailureDispatchControls(unittest.TestCase):
    def test_fixed_dispatch_preserves_private_evidence_credits_and_refuses_extra_args(self):
        fixture, body = KindCreateFailureEvidenceControls.fixture(self, b'private\x00binary\xff')
        output = fixture.run_body(body+'''remember kind-create-failure
mode=cleanup
emit_evidence
printf '%s\\n' "$evidence_json"
shopt -s nullglob
work=("$credits"/utility-work.*); cleanup=("$credits"/utility-cleanup.*)
printf '%s %s\\n' "${#work[@]}" "${#cleanup[@]}"
''')
        wire, counts = output.splitlines()
        value = json.loads(wire)
        self.assertEqual(counts, b'8 0')
        self.assertEqual(set(value['files']), rootful.KIND_FAILURE_ROLES)
        prefix = value['files'][rootful.KIND_STDERR_ROLE]
        self.assertEqual(base64.b64decode(prefix['base64']), b'private\x00binary\xff')
        for role in ('kind-create-failure', 'kind-create-evidence'):
            fixture, body = KindCreateFailureEvidenceControls.fixture(self)
            result = fixture.child(body+'remember '+role+' /untrusted/path\nprintf forbidden\n').finish()
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(b'forbidden', result.stdout)
            self.assertFalse(list((fixture.root/'state/credits').glob('utility-work.*')))
            self.assertFalse(list((fixture.root/'state/credits').glob('utility-cleanup.*')))


class GuardReasonReceiverControls(unittest.TestCase):
    """Actual shell predicates over projected files only; no target/proc query."""

    def fixture(self, *, legacy=False, persistent=False):
        fixture = BashProtocolControls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        source = receiver_before_poll_diagnostic(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))))
        if legacy:
            source = receiver_before_guard_reason(source)
        fixture.definitions = source.split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={fixture.root} stage={fixture.root}/stage')
        proc = fixture.root/'projected-proc'
        proc.mkdir()
        (proc/'uptime').write_text('1.00 1.00\n')
        fixture.definitions = fixture.definitions.replace('/proc/', str(proc)+'/')
        fixture.definitions = fixture.definitions.replace('read_file() {', 'observed_read_file() {', 1)
        state = fixture.root/'state'
        (state/'mode').write_text('work\n')
        (state/'deadlines').write_text('100 110\n')
        for index, name in enumerate(('wrapper', 'child', 'out', 'err', 'out-dd', 'out-tee', 'err-dd', 'err-tee')):
            (state/f'logs-{name}.identity').write_text(f'{23+index} 1\n')
        raw = b'Reached target Multi-User System.\n'
        (fixture.root/'captures/work.1.out').write_bytes(raw)
        (fixture.root/'captures/work.1.err').write_bytes(b'')
        (state/'logs-out.closed').write_text(f'0 0 {len(raw)} eof\n')
        (state/'logs-err.closed').write_text('0 0 0 eof\n')
        (state/'logs-captures').write_text(str(fixture.root/'captures/work.1.out')+' '+str(fixture.root/'captures/work.1.err')+'\n')
        if persistent:
            (proc/'23').mkdir()
            (proc/'23/stat').write_text('23 (fixture) S '+'0 '*18+'1\n')
        hooks = '''mode=work
read() { printf 'read:%s\n' "$*" >> "$root/state/observations"; builtin read "$@"; }
read_file() {
  printf 'file:%s\n' "${1##*/}" >> "$root/state/observations"
  [[ ${interrupt_identity:-0} != 1 || $1 != "$root/state/logs-wrapper.identity" ]] || exit 9
  observed_read_file "$@"
  if [[ ${late_poison:-0} == 1 && $1 == "$root/state/logs-wrapper.status" ]]; then printf poisoned > "$root/state/poison"; fi
}
u() { printf unexpected-utility >> "$root/state/observations"; fail; }
native() { printf unexpected-native >> "$root/state/observations"; fail; }
'''
        return fixture, hooks

    def alter(self, fixture, code):
        state, proc = fixture.root/'state', fixture.root/'projected-proc'
        if code == 'a': (state/'poison').write_text('poisoned\n')
        elif code == 'b': (state/'logs-wrapper.identity').write_text('invalid 1\n')
        elif code == 'c': (state/'logs-wrapper.identity').write_text('32768 1\n')
        elif code in ('d', 'e', 'f'):
            (proc/'23').mkdir()
            if code != 'd':
                (proc/'23/stat').write_text('24 (fixture) S 0\n' if code == 'e' else '23 (fixture) S 0\n')
        elif code == 'h': (state/'logs-out.closed').write_text('0 1 1 eof\n')
        elif code == 'i': (state/'logs-out.closed').write_text('0 0 16385 eof\n')
        elif code == 'j': (state/'logs-err.closed').write_text('0 0 4097 eof\n')
        elif code == 'k': (state/'logs-captures').write_text(str(fixture.root/'foreign')+' '+str(fixture.root/'captures/work.1.err')+'\n')
        elif code == 'l': (fixture.root/'captures/work.1.out').unlink()
        elif code == 'm': (fixture.root/'captures/work.1.out').write_bytes(b'fixed synthetic nonmarker\x00\xff')
        elif code == 'n': (state/'logs-wrapper.status').write_text('7\n')
        elif code == 'o': (state/'logs-wrapper.status').write_text('0\n')
        elif code == 'p': (proc/'uptime').write_text('100.00 100.00\n')

    def run_reason(self, fixture, hooks, *, call='logs_retirement', before=''):
        trap = '''trap 'saved=$?; trap - EXIT; printf "%s\\n" "${guard_reason:-}" > "$root/state/test-reason"; exit "$saved"' EXIT
'''
        result = fixture.child(hooks+before+'\n'+trap+call+'\nprintf later-effect > "$root/state/later"\n').finish()
        reason = (fixture.root/'state/test-reason').read_text().strip()
        path = fixture.root/'state/observations'
        trace = path.read_text().splitlines() if path.exists() else []
        return result, reason, trace

    def test_all_sixteen_actual_false_branches_and_observation_order_match_v1(self):
        for code in 'abcdefghijklmnop':
            with self.subTest(code=code):
                runs = []
                for legacy in (True, False):
                    fixture, hooks = self.fixture(legacy=legacy, persistent=code == 'g')
                    self.alter(fixture, code)
                    result, reason, trace = self.run_reason(fixture, hooks,
                        before='late_poison=1' if code == 'o' else '')
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr, b'rootful-receiver-refused\n')
                    self.assertEqual(reason, '' if legacy else 'pg1.'+code)
                    self.assertFalse((fixture.root/'state/later').exists())
                    self.assertFalse((fixture.root/'state/logs-retirement').exists())
                    self.assertFalse(list((fixture.root/'state/credits').iterdir()))
                    self.assertNotIn('unexpected-', '\n'.join(trace))
                    if code == 'g':
                        self.assertEqual(trace.count('file:deadlines'), 4096)
                    runs.append(trace)
                self.assertEqual(runs[0], runs[1])

    def test_compound_identity_collector_and_path_guards_keep_first_false_code(self):
        cases = [('b', 'bad-start'), ('f', 'bad-stat-start'), ('h', 'bad-closure'), ('l', 'symlink')]
        for code, variant in cases:
            with self.subTest(variant=variant):
                fixture, hooks = self.fixture()
                state, proc = fixture.root/'state', fixture.root/'projected-proc'
                if variant == 'bad-start': (state/'logs-wrapper.identity').write_text('23 invalid\n')
                elif variant == 'bad-stat-start':
                    (proc/'23').mkdir(); (proc/'23/stat').write_text('23 (fixture) S '+'0 '*18+'invalid\n')
                elif variant == 'bad-closure': (state/'logs-out.closed').write_text('0 0 3 failed\n')
                else:
                    path = fixture.root/'captures/work.1.out'; path.unlink(); path.symlink_to(fixture.root/'absent')
                result, reason, _ = self.run_reason(fixture, hooks)
                self.assertEqual((result.returncode, reason), (1, 'pg1.'+code))

    def test_true_retired_and_pid_reuse_paths_keep_empty_reason_and_same_reads(self):
        for reused in (False, True):
            runs = []
            for legacy in (True, False):
                fixture, hooks = self.fixture(legacy=legacy, persistent=reused)
                if reused:
                    (fixture.root/'projected-proc/23/stat').write_text('23 (fixture) S '+'0 '*18+'2\n')
                result, reason, trace = self.run_reason(fixture, hooks)
                self.assertEqual((result.returncode, reason), (0, ''))
                self.assertTrue((fixture.root/'state/logs-retirement').exists())
                self.assertTrue((fixture.root/'state/later').exists())
                runs.append(trace)
            self.assertEqual(runs[0], runs[1])

    def test_skipped_interrupted_and_untagged_helper_failures_remain_unknown(self):
        for variant in ('skipped', 'interrupted', 'missing-identity', 'missing-deadlines', 'missing-uptime', 'bad-clock-read', 'bad-limit'):
            with self.subTest(variant=variant):
                fixture, hooks = self.fixture()
                state = fixture.root/'state'
                before, call = '', 'logs_retirement'
                if variant == 'skipped': call = 'exit 3'
                elif variant == 'interrupted': before = 'interrupt_identity=1'
                elif variant == 'missing-identity': (state/'logs-wrapper.identity').unlink()
                elif variant == 'missing-deadlines': (state/'deadlines').unlink()
                elif variant == 'missing-uptime': (fixture.root/'projected-proc/uptime').unlink()
                elif variant == 'bad-clock-read': (fixture.root/'projected-proc/uptime').write_text('invalid\n')
                else: (state/'deadlines').write_text('invalid 110\n')
                result, reason, _ = self.run_reason(fixture, hooks, call=call, before=before)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(reason, '')

    def test_clock_context_tags_only_existing_false_comparison_and_other_calls_stay_unknown(self):
        for context in ('', ' p'):
            fixture, hooks = self.fixture()
            (fixture.root/'projected-proc/uptime').write_text('100.00 100.00\n')
            result, reason, trace = self.run_reason(fixture, hooks, call='clock_check'+context)
            self.assertEqual((result.returncode, reason), (1, 'pg1.p' if context else ''))
            self.assertEqual(trace.count('file:deadlines'), 1)
            self.assertEqual(sum(line.startswith('read:-r UPTIME') for line in trace), 1)

    def test_private_reason_is_unexported_cleared_and_only_closed_tags_assign_it(self):
        import os
        fixture, hooks = self.fixture()
        with patch.dict(os.environ, {'guard_reason': 'pg1.p'}):
            result = fixture.child(hooks+'''[[ $(declare -p guard_reason) == 'declare -- guard_reason=""' ]] || fail
logs_retirement
[[ -z $guard_reason ]] || fail
''').finish()
        self.assertEqual(result.returncode, 0, result.stderr)
        for invalid in ('entry', 'pg1.a', 'q', 'A', ''):
            fixture, hooks = self.fixture()
            argument = "'"+invalid+"'"
            result, reason, _ = self.run_reason(fixture, hooks, call='fail '+argument)
            self.assertEqual((result.returncode, reason), (1, ''))

    def test_first_tag_survives_later_cleanup_failure_without_overwrite(self):
        fixture, hooks = self.fixture()
        result = fixture.child(hooks+'''exit() { printf '%s\n' "$guard_reason" >> "$root/state/test-reason"; builtin exit "$@"; }
trap 'mode=cleanup; fail b' EXIT
fail a
''').finish()
        self.assertEqual(result.returncode, 1)
        self.assertEqual((fixture.root/'state/test-reason').read_text().splitlines(), ['pg1.a', 'pg1.a'])
        self.assertTrue((fixture.root/'state/poison').exists())
        self.assertEqual(result.stderr, b'rootful-receiver-refused\nrootful-receiver-refused\n')

    def test_guard_schema_and_reason_survive_real_finish_with_exact_private_prefix(self):
        raw = b'fixed synthetic nonmarker\x00\xff'
        fixture = FailurePrefixControls.shell_fixture(self, raw)
        fixture.definitions = poll_source_definitions(fixture, current=False)
        fixture.definitions = fixture.definitions.replace('/proc/', str(fixture.root/'projected-proc')+'/')
        (fixture.root/'projected-proc').mkdir()
        (fixture.root/'projected-proc/uptime').write_text('1.00 1.00\n')
        state = fixture.root/'state'
        (state/'deadlines').write_text('100 110\n')
        for index, name in enumerate(('wrapper', 'child', 'out', 'err', 'out-dd', 'out-tee', 'err-dd', 'err-tee')):
            (state/f'logs-{name}.identity').write_text(f'{23+index} 1\n')
        (state/'logs-out.closed').write_text(f'0 0 {len(raw)} eof\n')
        (state/'logs-err.closed').write_text('0 0 0 eof\n')
        (fixture.root/'captures/work.1.err').write_bytes(b'')
        source = receiver_before_poll_diagnostic(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))))
        finish = 'finish() {'+source.split('finish() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
        body = '''mode=work
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=own spec_sha='''+('c'*64)+'''
native() { printf deleted > "$root/state/cleanup-ran"; last_tool_status=0; }
'''+finish+'trap finish EXIT\nlogs_retirement\nprintf forbidden\n'
        result = fixture.child(body).finish()
        self.assertEqual(result.returncode, 1)
        value = json.loads(result.stdout)
        self.assertEqual((value['schema'], value['state'], value['kind_create_status'], value['kind_delete_status']),
                         (rootful.RESULT_V2, 'failed', 0, 0))
        self.assertEqual(value['logs']['state'], 'pg1.m')
        self.assertFalse(value['logs']['startup_marker'])
        self.assertTrue((state/'cleanup-ran').exists())
        prefix = value['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE]
        self.assertEqual(base64.b64decode(prefix['base64']), raw)
        self.assertEqual(prefix['sha256'], vm.digest(raw))
        self.assertEqual(len(list((state/'credits').glob('utility-cleanup.*'))), 4)
        self.assertFalse(list((state/'credits').glob('utility-work.*')))
        self.assertNotIn(raw, result.stdout+result.stderr)


class GuardReasonDecoderControls(unittest.TestCase):
    def bundle(self, code='pg1.m', *, raw=b'fixed\x00private-prefix\xff'):
        config, value, _ = FailurePrefixControls.bundle(self, raw)
        value.update(schema=rootful.RESULT_V2, kind_create_status=0, kind_delete_status=0)
        value['logs']['state'] = code
        return config, value, raw

    def wire(self, value):
        return vm.encode(value)+b'\n'

    def test_v1_records_and_all_three_existing_states_keep_their_behavior(self):
        fixture = RootfulHostControls()
        for state in ('direct-wait-zero', 'retired-wait-and-signal-cause-unavailable', 'not-established'):
            for version in (rootful.RESULT_V1, rootful.RESULT_V2):
                value = fixture.result(); value['schema'] = version
                if state == 'retired-wait-and-signal-cause-unavailable':
                    value['logs'].update(state=state, wrapper_observed_child_wait_status=None)
                elif state == 'not-established':
                    value.update(state='failed', source_deployment='not-reached')
                    value['logs'].update(state=state, startup_marker=False)
                self.assertEqual(rootful.result(self.wire(value), fixture.config(), allow_failure=True), value)

    def test_v2_positive_wire_keeps_all_original_full_proof_requirements(self):
        config, value, _ = DurableEvidenceControls.bundle(self)
        value['schema'] = rootful.RESULT_V2
        checked = rootful.wire_record(self.wire(value), config)
        self.assertEqual((checked['schema'], checked['state']), (rootful.RESULT_V2, 'source-deployment-positive'))
        value['logs']['collectors']['out']['source_eof'] = False
        with self.assertRaises(vm.Refusal): rootful.wire_record(self.wire(value), config)

    def test_all_sixteen_v2_codes_accept_only_incomplete_failed_context_without_normalization(self):
        self.assertEqual(rootful.POSTCREATE_GUARD_STATES, frozenset('pg1.'+c for c in 'abcdefghijklmnop'))
        for code in sorted(rootful.POSTCREATE_GUARD_STATES):
            config, value, _ = self.bundle(code)
            value['logs']['identities']['child'] = None
            value['logs']['collectors']['err'] = None
            value['logs']['collectors']['out'].update(dd_status=7, tee_status=9, source_eof=False)
            checked = rootful.wire_record(self.wire(value), config, allow_failure=True)
            self.assertEqual((checked['schema'], checked['state'], checked['logs']['state']), (rootful.RESULT_V2, 'failed', code))
            self.assertIsNone(checked['logs']['identities']['child'])
            self.assertIsNone(checked['logs']['collectors']['err'])
            with self.assertRaises(vm.Refusal): rootful.wire_record(self.wire(value), config)
            self.assertEqual(rootful.logs_evidence(value['logs'], complete=False, version=rootful.RESULT_V2, failure=value), value['logs'])
            rootful.evidence(value['evidence'], config, complete=False, failure=value, version=rootful.RESULT_V2)

    def test_v1_codes_future_versions_unknown_codes_and_wrong_types_refuse(self):
        for code in ('pg1.q', 'pg2.a', 'pg1.aa', 'pg1.A', 'pg1.', '', None, False, 0, [], {}):
            config, value, _ = self.bundle(code)
            with self.subTest(code=code), self.assertRaises(vm.Refusal):
                rootful.wire_record(self.wire(value), config, allow_failure=True)
        for version in (rootful.RESULT_V1, 'kubernetes-lens-owned-rootful-result-v4', 'v2', None, False, 2, [], {}):
            config, value, _ = self.bundle(); value['schema'] = version
            with self.subTest(version=version), self.assertRaises(vm.Refusal):
                rootful.wire_record(self.wire(value), config, allow_failure=True)

    def test_codes_reject_create_not_zero_source_reached_success_and_marker_contradictions(self):
        changes = [lambda v: v.update(kind_create_status=1), lambda v: v.update(kind_create_status=-1),
            lambda v: v.update(kind_create_status=False), lambda v: v.update(kind_create_status=True),
            lambda v: v.update(source_deployment='server-dry-run-observed'),
            lambda v: v.update(state='source-deployment-positive', source_deployment='server-dry-run-observed'),
            lambda v: v['logs'].update(startup_marker=True)]
        for change in changes:
            config, value, _ = self.bundle(); change(value)
            with self.subTest(change=change), self.assertRaises(vm.Refusal):
                rootful.wire_record(self.wire(value), config, allow_failure=True)
            with self.assertRaises(vm.Refusal):
                rootful.logs_evidence(value['logs'], complete=False, version=rootful.RESULT_V2, failure=value)
            with self.assertRaises(vm.Refusal):
                rootful.evidence(value['evidence'], config, complete=False, failure=value, version=rootful.RESULT_V2)

    def test_standalone_calls_require_explicit_version_and_matching_failure_context(self):
        config, value, _ = self.bundle()
        with self.assertRaises(vm.Refusal): rootful.logs_evidence(value['logs'], complete=False)
        with self.assertRaises(vm.Refusal): rootful.logs_evidence(value['logs'], complete=False, version=rootful.RESULT_V2)
        with self.assertRaises(vm.Refusal): rootful.evidence(value['evidence'], config, complete=False, failure=value)
        with self.assertRaises(vm.Refusal): rootful.logs_evidence(value['logs'], complete=True, version=rootful.RESULT_V2, failure=value)
        for version in ('v3', None, False, [], {}):
            with self.assertRaises(vm.Refusal): rootful.logs_evidence(value['logs'], complete=False, version=version, failure=value)
            with self.assertRaises(vm.Refusal): rootful.evidence(value['evidence'], config, complete=False, failure=value, version=version)
        other = deepcopy(value); other['logs']['state'] = 'pg1.n'
        with self.assertRaises(vm.Refusal): rootful.logs_evidence(value['logs'], complete=False, version=rootful.RESULT_V2, failure=other)

    def test_overflow_sentinel_nulls_and_collector_failures_stay_incomplete_and_private(self):
        config, value, raw = self.bundle('pg1.i', raw=b'x'*16384)
        value['logs']['collectors']['out'].update(bytes=16385, dd_status=1, source_eof=False)
        value['logs']['collectors']['err'].update(bytes=4097, tee_status=2, source_eof=False)
        value['logs']['identities']['out-dd'] = None
        checked = rootful.wire_record(self.wire(value), config, allow_failure=True)
        self.assertEqual(checked['logs']['collectors']['out']['bytes'], 16385)
        self.assertEqual(checked['logs']['state'], 'pg1.i')
        with tempfile.TemporaryDirectory(prefix='guard-private-') as directory:
            parent = Path(directory)
            encoded = self.wire(value)
            descriptor = rootful.durable_wire(encoded, config, parent, vm.Budget(time.monotonic()+30, 10))
            path = parent/descriptor['name']
            self.assertEqual(path.read_bytes(), encoded)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(raw, vm.encode(descriptor))
            self.assertNotIn(base64.b64encode(raw), vm.encode(descriptor))
        value['logs']['collectors']['out'] = None
        value['evidence']['files'].pop(rootful.PRIVATE_FAILURE_ROLE)
        self.assertIsNone(rootful.wire_record(self.wire(value), config, allow_failure=True)['logs']['collectors']['out'])

    def test_code_never_relaxes_owner_plan_spec_raw_integrity_or_genuine_prefix_length(self):
        changes = [lambda v: v['evidence'].update(owner='f'*32),
            lambda v: v['evidence'].update(plan_sha256='f'*64),
            lambda v: v['evidence'].update(source_spec_sha256='f'*64),
            lambda v: v['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE].update(sha256='0'*64),
            lambda v: v['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE].update(base64='!'),
            lambda v: v['logs']['collectors']['out'].update(bytes=1),
            lambda v: v['logs'].update(signal_cause='SIGKILL')]
        for change in changes:
            config, value, _ = self.bundle(); change(value)
            with self.assertRaises(vm.Refusal): rootful.wire_record(self.wire(value), config, allow_failure=True)

    def test_actual_worker_failure_path_keeps_v2_code_without_positive_promotion(self):
        for delete_status in (0, 19):
            with self.subTest(actual_native_zero=delete_status == 0):
                host = RootfulHostControls()
                self.addCleanup(host.doCleanups)
                value = host.result()
                value.update(schema=rootful.RESULT_V2, state='failed', source_deployment='not-reached',
                             kind_delete_status=delete_status)
                value['logs'].update(state='pg1.m', startup_marker=False)
                with patch.object(host, 'result', return_value=value):
                    status, stopped, *_ = host.worker_case(delete_status=delete_status)
                self.assertEqual(status, 1)
                self.assertEqual(stopped['error'], 'rootful-kind-phase-failed' if delete_status else 'rootful-success-unproved')
                self.assertEqual((stopped['rootful']['schema'], stopped['rootful']['logs']['state']),
                                 (rootful.RESULT_V2, 'pg1.m'))
                self.assertTrue(stopped['qemu_reaped'])

    def test_exact_source_inverse_and_observation_budget_inventories_stay_sealed(self):
        import hashlib
        source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        historical_v3 = receiver_before_direct_exec(receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(source))))))))
        prior = receiver_before_guard_reason(receiver_before_poll_diagnostic(source))
        self.assertEqual(hashlib.sha256(prior.encode()).hexdigest(), POSTCREATE_PREFIX_SOURCE)
        self.assertLessEqual(len(source.encode()), 65536)
        for text in ('for ((i = 0; i < 4096; i++))', 'grant_utility', 'native ', 'u /usr/bin/',
                     'read_file ', 'read -r ', 'read -ra ', 'read -r line', 'maximum=680', 'maximum=64',
                     'prefix_claimed=1 prefix_tickets=()', 'count=16384', 'record_guard_fuel=0'):
            self.assertEqual(historical_v3.count(text), prior.count(text), text)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        altered = source.replace('((i < 4096))', '((i < 4095))', 1)
        with self.assertRaises(AssertionError): receiver_before_guard_reason(receiver_before_poll_diagnostic(altered))


class PollDiagnosticReceiverControls(unittest.TestCase):
    '''Historical ADR0075 v3/v2; separate pacing controls use current source.'''
    roles = ('wrapper', 'child', 'out', 'err', 'out-dd', 'out-tee', 'err-dd', 'err-tee')
    run_reason = GuardReasonReceiverControls.run_reason

    def fixture(self, *, current=True, role='wrapper', glyph='S', persistent=True):
        fixture, hooks = GuardReasonReceiverControls.fixture(self)
        fixture.definitions = poll_source_definitions(fixture, current=current).replace(
            '/proc/', str(fixture.root/'projected-proc')+'/').replace(
            'read_file() {', 'observed_read_file() {', 1)
        if persistent:
            pid = 23 + self.roles.index(role)
            directory = fixture.root/'projected-proc'/str(pid)
            directory.mkdir()
            (directory/'stat').write_text(f'{pid} (fixture) {glyph} '+'0 '*18+'1\n')
        return fixture, hooks

    def assert_failed(self, fixture, result, trace):
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, b'', b'rootful-receiver-refused\n'))
        self.assertFalse((fixture.root/'state/logs-retirement').exists())
        self.assertFalse((fixture.root/'state/later').exists())
        self.assertFalse(list((fixture.root/'state/credits').iterdir()))
        self.assertNotIn('unexpected-', '\n'.join(trace))

    def test_all_eight_original_exhaustions_and_zombie_keep_exact_v2_reads(self):
        for role, glyph in [(r, 'S') for r in self.roles] + [('wrapper', 'Z')]:
            with self.subTest(role=role, glyph=glyph):
                traces = []
                for current in (False, True):
                    fixture, hooks = self.fixture(current=current, role=role, glyph=glyph)
                    result, reason, trace = self.run_reason(fixture, hooks)
                    self.assert_failed(fixture, result, trace)
                    pid = 23 + self.roles.index(role)
                    expected = f'pg2.g.{role}.{glyph}.4096.{pid}.1' if current else 'pg1.g'
                    self.assertEqual(reason, expected)
                    self.assertEqual(trace.count('file:deadlines'), 4096+self.roles.index(role))
                    self.assertEqual(trace.count('read:-rrecord'), 4096)
                    traces.append(trace)
                self.assertEqual(*traces)

    def test_deadline_counts_zero_one_and4095_for_each_role_keep_v2_reads(self):
        for role in self.roles:
            for count in (0, 1, 4095):
                with self.subTest(role=role, count=count):
                    traces = []
                    for current in (False, True):
                        fixture, hooks = self.fixture(current=current, role=role)
                        hooks = hooks.replace('observed_read_file "$@"', 'observed_read_file "$@"\n'
                            f'  if [[ $1 == "$root/state/deadlines" && $name == {role} && $i == {count} ]]; then REPLY="1 110"; fi')
                        result, reason, trace = self.run_reason(fixture, hooks)
                        self.assert_failed(fixture, result, trace)
                        pid = 23 + self.roles.index(role)
                        expected = f'pg2.p.{role}.{"S" if count else "u"}.{count}.{pid}.1' if current else 'pg1.p'
                        self.assertEqual(reason, expected)
                        self.assertEqual(trace.count('read:-rrecord'), count)
                        self.assertEqual(trace.count('file:deadlines'), count+1+self.roles.index(role))
                        traces.append(trace)
                    self.assertEqual(*traces)

    def test_finite_cached_glyphs_and_unknown_state_at_short_deadline(self):
        for glyph in ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'I', 'u', 'W', 'x', 'unknown'):
            fixture, hooks = self.fixture(glyph=glyph)
            hooks = hooks.replace('observed_read_file "$@"', 'observed_read_file "$@"\n'
                '  if [[ $1 == "$root/state/deadlines" && $i == 1 ]]; then REPLY="1 110"; fi')
            result, reason, trace = self.run_reason(fixture, hooks)
            self.assert_failed(fixture, result, trace)
            expected = glyph if glyph in 'RSDZTtXI' else 'u'
            self.assertEqual(reason, f'pg2.p.wrapper.{expected}.1.23.1')

    def test_next_role_resets_cached_state_before_its_first_clock(self):
        for index, role in enumerate(self.roles[1:], 1):
            previous = self.roles[index-1]
            fixture, hooks = self.fixture(role=previous)
            hooks = hooks.replace('builtin read "$@";', 'builtin read "$@";\n'
                f'  if [[ $* == "-ra parts" && $name == {previous} && $i == 1 ]]; then parts[19]=2; fi;')
            hooks = hooks.replace('observed_read_file "$@"', 'observed_read_file "$@"\n'
                f'  if [[ $1 == "$root/state/deadlines" && $name == {role} ]]; then REPLY="1 110"; fi')
            result, reason, trace = self.run_reason(fixture, hooks)
            self.assert_failed(fixture, result, trace)
            self.assertEqual(reason, f'pg2.p.{role}.u.0.{23+index}.1')
            self.assertEqual(trace.count('read:-rrecord'), 2)

    def test_disappearance_reuse_and_all_other_false_branches_keep_v2_behavior(self):
        for variant in ('absent', 'reuse', *'abcdefhijklmno'):
            traces = []
            for current in (False, True):
                fixture, hooks = self.fixture(current=current, persistent=variant == 'reuse')
                if variant == 'reuse':
                    (fixture.root/'projected-proc/23/stat').write_text('23 (fixture) Z '+'0 '*18+'2\n')
                elif variant != 'absent':
                    GuardReasonReceiverControls.alter(self, fixture, variant)
                result, reason, trace = self.run_reason(fixture, hooks,
                    before='late_poison=1' if variant == 'o' else '')
                expected = '' if variant in ('absent', 'reuse') else 'pg1.'+variant
                self.assertEqual((result.returncode, reason), (0 if not expected else 1, expected))
                traces.append(trace)
            self.assertEqual(*traces)

    def test_untagged_helpers_and_direct_clock_do_not_invent_poll_details(self):
        for variant in ('missing-identity', 'missing-deadlines', 'missing-uptime', 'bad-clock', 'bad-limit', 'interrupted'):
            traces = []
            for current in (False, True):
                fixture, hooks = self.fixture(current=current)
                state = fixture.root/'state'
                before = ''
                if variant == 'missing-identity': (state/'logs-wrapper.identity').unlink()
                elif variant == 'missing-deadlines': (state/'deadlines').unlink()
                elif variant == 'missing-uptime': (fixture.root/'projected-proc/uptime').unlink()
                elif variant == 'bad-clock': (fixture.root/'projected-proc/uptime').write_text('invalid\n')
                elif variant == 'bad-limit': (state/'deadlines').write_text('invalid 110\n')
                else: before = 'interrupt_identity=1'
                result, reason, trace = self.run_reason(fixture, hooks, before=before)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(reason, '')
                traces.append(trace)
            self.assertEqual(*traces)
        fixture, hooks = self.fixture()
        (fixture.root/'projected-proc/uptime').write_text('100.00 100.00\n')
        result, reason, _ = self.run_reason(fixture, hooks, call='clock_check p')
        self.assertEqual((result.returncode, reason), (1, 'pg1.p'))

    def test_malformed_identity_stat_and_interrupted_sample_do_not_publish_cached_detail(self):
        for variant, expected in (('bad-identity-start', 'pg1.b'), ('bad-stat-start', 'pg1.f'),
                                  ('short-stat', 'pg1.f'), ('missing-stat', 'pg1.d'),
                                  ('late-bad-start', 'pg1.f'), ('late-helper', ''), ('interrupted', '')):
            traces = []
            for current in (False, True):
                fixture, hooks = self.fixture(current=current)
                if variant == 'bad-identity-start':
                    (fixture.root/'state/logs-wrapper.identity').write_text('23 invalid\n')
                elif variant in ('bad-stat-start', 'short-stat'):
                    (fixture.root/'projected-proc/23/stat').write_text(
                        '23 (fixture) S '+'0 '*18+'invalid\n' if variant == 'bad-stat-start' else '23 (fixture) S 0\n')
                elif variant == 'missing-stat': (fixture.root/'projected-proc/23/stat').unlink()
                elif variant == 'late-bad-start':
                    hooks = hooks.replace('builtin read "$@";', 'builtin read "$@";\n'
                        '  if [[ $* == "-ra parts" && $i == 1 ]]; then parts[19]=invalid; fi;')
                else:
                    action = 'REPLY="invalid 110"' if variant == 'late-helper' else 'exit 9'
                    hooks = hooks.replace('observed_read_file "$@"', 'observed_read_file "$@"\n'
                        '  if [[ $1 == "$root/state/deadlines" && $i == 1 ]]; then '+action+'; fi')
                result, reason, trace = self.run_reason(fixture, hooks)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(reason, expected)
                traces.append(trace)
            self.assertEqual(*traces)

    def test_inherited_exports_are_cleared_and_poll_locals_never_export(self):
        import os
        fixture, hooks = self.fixture(persistent=False)
        hooks = hooks.replace('observed_read_file "$@"', '''observed_read_file "$@"
  if [[ $1 == "$root/state/logs-wrapper.identity" ]]; then
    [[ $(declare -p poll_active) == 'declare -- poll_active="1"' ]] || fail
    [[ $(declare -p poll_state) == 'declare -- poll_state="u"' ]] || fail
  fi''')
        with patch.dict(os.environ, {'guard_reason': 'pg2.g.foreign.Z.4096.1.1',
                                    'poll_active': '1', 'poll_state': 'Z'}):
            result = fixture.child(hooks+'''[[ $(declare -p guard_reason) == 'declare -- guard_reason=""' ]] || fail
[[ $(declare -p poll_active) == 'declare -- poll_active="0"' ]] || fail
logs_retirement
[[ -z $guard_reason && $poll_active == 0 ]] || fail
''').finish()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_first_pg1_or_pg2_survives_cleanup_failure(self):
        for first in ('pg1.a', 'pg2.p.wrapper.u.0.23.1'):
            fixture, hooks = self.fixture()
            if first.startswith('pg2.'):
                (fixture.root/'projected-proc/uptime').write_text('100.00 100.00\n')
                call = 'logs_retirement'
            else: call = 'fail a'
            result = fixture.child(hooks+'''exit() { printf '%s\n' "$guard_reason" >> "$root/state/test-reason"; builtin exit "$@"; }
trap 'mode=cleanup; fail b' EXIT
'''+call).finish()
            self.assertEqual(result.returncode, 1)
            self.assertEqual((fixture.root/'state/test-reason').read_text().splitlines(), [first, first])

    def test_actual_v3_finish_preserves_private_wire_and_durable_data(self):
        raw = b'private-poll-prefix\x00\xff\nReached target Multi-User System.\n'
        fixture = FailurePrefixControls.shell_fixture(self, raw)
        fixture.use_historical_v3_logs()
        config, _, _ = DurableEvidenceControls.bundle(self)
        proc = fixture.root/'projected-proc'; proc.mkdir()
        (proc/'uptime').write_text('100.00 100.00\n')
        fixture.definitions = fixture.definitions.replace('/proc/', str(proc)+'/').replace(
            str(proc)+'/self/fd/', '/proc/self/fd/')
        state = fixture.root/'state'
        (state/'deadlines').write_text('100 110\n')
        for index, name in enumerate(self.roles):
            (state/f'logs-{name}.identity').write_text(f'{23+index} 1\n')
        (state/'logs-out.closed').write_text(f'0 0 {len(raw)} eof\n')
        (state/'logs-err.closed').write_text('0 0 0 eof\n')
        (fixture.root/'captures/work.1.err').write_bytes(b'')
        source = receiver_before_direct_exec(receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))))))))))
        finish = 'finish() {'+source.split('finish() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
        body = '''mode=work
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=own spec_sha='''+vm.digest(vm.encode(config['rootful_spec']))+'''
take work 70 || fail
take output-work 256 || fail
native() { take cleanup 5 || fail; printf deleted > "$root/state/cleanup-ran"; last_tool_status=0; }
'''+finish+'trap finish EXIT\nlogs_retirement\nprintf forbidden\n'
        result = fixture.child(body).finish()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'rootful-receiver-refused\n')
        value = json.loads(result.stdout)
        self.assertEqual(value['schema'], rootful.RESULT_V3)
        self.assertEqual(value['logs']['state'], 'pg2.p.wrapper.u.0.23.1')
        self.assertEqual(value['kind_delete_status'], 0)
        self.assertTrue((state/'cleanup-ran').exists())
        checked = rootful.wire_record(result.stdout, config, allow_failure=True)
        self.assertEqual(set(checked), set(value))
        detail = rootful.poll_failure(checked['logs'], version=checked['schema'], failure=checked)
        self.assertEqual((detail.reason, detail.last_observed_state, detail.last_sample_index),
                         ('work-deadline', None, None))
        prefix = value['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE]
        self.assertEqual(base64.b64decode(prefix['base64']), raw)
        with tempfile.TemporaryDirectory(prefix='poll-durable-') as directory:
            parent = Path(directory)
            descriptor = rootful.durable_wire(result.stdout, config, parent, vm.Budget(time.monotonic()+30, 10))
            self.assertEqual((parent/descriptor['name']).read_bytes(), result.stdout)
            self.assertEqual((parent/descriptor['name']).stat().st_mode & 0o777, 0o600)
            for private in (raw, base64.b64encode(raw), b'pg2.', b'iterations_completed'):
                self.assertNotIn(private, vm.encode(descriptor))
        self.assertEqual(len(list((state/'credits').glob('utility-cleanup.*'))), 4)
        self.assertFalse(list((state/'credits').glob('utility-work.*')))


class PollDiagnosticDecoderControls(unittest.TestCase):
    def bundle(self, *, cause='g', role='wrapper', glyph='S', count=4096):
        config, value, raw = GuardReasonDecoderControls.bundle(self)
        value['schema'] = rootful.RESULT_V3
        identity = value['logs']['identities'][role]
        value['logs']['state'] = f'pg2.{cause}.{role}.{glyph}.{count}.{identity["pid"]}.{identity["start"]}'
        return config, value, raw

    def check(self, config, value):
        return rootful.wire_record(vm.encode(value)+b'\n', config, allow_failure=True)

    def test_closed_roles_glyphs_counts_and_frozen_primitive_facts(self):
        from dataclasses import FrozenInstanceError, fields
        for role in sorted(rootful.LOG_ROLES):
            for glyph in 'RSDZTtXIu':
                for cause, count in (('g', 4096), ('p', 1), ('p', 4095)):
                    config, value, _ = self.bundle(role=role, glyph=glyph, cause=cause, count=count)
                    checked = self.check(config, value)
                    detail = rootful.poll_failure(checked['logs'], version=rootful.RESULT_V3, failure=checked)
                    self.assertEqual(detail, rootful.LogPollFailure(
                        'iteration-limit' if cause == 'g' else 'work-deadline', role,
                        value['logs']['identities'][role]['pid'], value['logs']['identities'][role]['start'],
                        None if glyph == 'u' else glyph, count, count-1,
                        'last-existing-comparison-passed-before-last-sample' if cause == 'g' else
                        'current-existing-work-comparison-failed-before-next-sample'))
                    self.assertTrue(all(type(getattr(detail, f.name)) in (str, int, type(None)) for f in fields(detail)))
                    with self.assertRaises(FrozenInstanceError): detail.pid = 1
                    self.assertNotIn('poll_failure', checked)
        config, value, _ = self.bundle(cause='p', glyph='u', count=0)
        self.check(config, value)
        detail = rootful.poll_failure(value['logs'], version=rootful.RESULT_V3, failure=value)
        self.assertEqual((detail.iterations_completed, detail.last_sample_index, detail.last_observed_state), (0, None, None))
        for pid, start in ((1, 1), (32767, 9223372036854775806)):
            config, value, _ = self.bundle(role='err-tee')
            value['logs']['identities']['err-tee'] = {'pid': pid, 'start': start}
            value['logs']['state'] = f'pg2.g.err-tee.I.4096.{pid}.{start}'
            self.assertLessEqual(len(value['logs']['state']), 46)
            self.check(config, value)

    def test_lexical_and_numeric_mutations_refuse_in_every_decoder(self):
        tokens = ['pg2.x.wrapper.S.4096.8.106', 'pg2.g.foreign.S.4096.8.106',
            'pg2.g.wrapper.s.4096.8.106', 'pg2.g.wrapper.unknown.4096.8.106',
            'pg2.g.wrapper.S.4095.8.106', 'pg2.p.wrapper.S.4096.8.106',
            'pg2.p.wrapper.S.0.8.106', 'pg2.g.wrapper.S.-1.8.106',
            'pg2.p.wrapper.u.00.8.106', 'pg2.g.wrapper.S.04096.8.106',
            'pg2.g.wrapper.S.4096.08.106', 'pg2.g.wrapper.S.4096.8.0106',
            'pg2.g.wrapper.S.4096.0.106', 'pg2.g.wrapper.S.4096.32768.106',
            'pg2.g.wrapper.S.4096.8.0', 'pg2.g.wrapper.S.4096.8.9223372036854775807',
            'pg2.g.wrapper.S.4096.8.'+'9'*100, 'pg2.g.wrapper.S.４０９６.8.106',
            'pg2.g.wrapper.S.4096.8.106\n', 'pg2.g.wrapper.S.4096.8.106.extra',
            'pg2.g.wrapper.S..8.106', 'pg2.g.wrapper.S.4096..106',
            'pg2.g.wrapper.S.4096.8', 'pg2.', '', None, True, 4096, [], {}]
        for token in tokens:
            with self.subTest(token=token):
                config, value, _ = self.bundle(); value['logs']['state'] = token
                with self.assertRaises(vm.Refusal): self.check(config, value)
                with self.assertRaises(vm.Refusal): rootful.poll_failure(value['logs'], version=rootful.RESULT_V3, failure=value)
                with self.assertRaises(vm.Refusal): rootful.evidence(value['evidence'], config, complete=False, failure=value, version=rootful.RESULT_V3)

    def test_explicit_version_failure_scope_and_selected_identity_are_mandatory(self):
        for version in (rootful.RESULT_V1, rootful.RESULT_V2, 'kubernetes-lens-owned-rootful-result-v4', None, True, [], {}):
            config, value, _ = self.bundle(); value['schema'] = version
            with self.assertRaises(vm.Refusal): self.check(config, value)
            with self.assertRaises(vm.Refusal): rootful.poll_failure(value['logs'], version=version, failure=value)
        changes = [lambda v: v.update(kind_create_status=1), lambda v: v.update(kind_create_status=-1),
            lambda v: v.update(kind_create_status=False), lambda v: v.update(kind_create_status=True),
            lambda v: v.update(state='source-deployment-positive'),
            lambda v: v.update(source_deployment='server-dry-run-observed'),
            lambda v: v['logs'].update(startup_marker=True),
            lambda v: v['logs']['identities'].update(wrapper=None),
            lambda v: v['logs']['identities']['wrapper'].update(pid=22),
            lambda v: v['logs']['identities']['wrapper'].update(start=999),
            lambda v: v['logs']['identities']['wrapper'].update(pid=True),
            lambda v: v['logs']['identities']['wrapper'].update(start=True),
            lambda v: v['logs']['identities'].update(child=v['logs']['identities']['wrapper']),
            lambda v: v['logs'].update(signal_cause='SIGKILL')]
        for change in changes:
            config, value, _ = self.bundle(); change(value)
            with self.assertRaises(vm.Refusal): self.check(config, value)
            with self.assertRaises(vm.Refusal): rootful.poll_failure(value['logs'], version=rootful.RESULT_V3, failure=value)
            with self.assertRaises(vm.Refusal): rootful.evidence(value['evidence'], config, complete=False, failure=value, version=rootful.RESULT_V3)
        config, value, _ = self.bundle()
        with self.assertRaises(vm.Refusal): rootful.logs_evidence(value['logs'], complete=False)
        with self.assertRaises(vm.Refusal): rootful.poll_failure(value['logs'], version=rootful.RESULT_V3, failure=None)
        with self.assertRaises(vm.Refusal): rootful.logs_evidence(value['logs'], complete=True, version=rootful.RESULT_V3, failure=value)
        other = deepcopy(value); other['logs']['state'] = 'pg1.g'
        with self.assertRaises(vm.Refusal): rootful.poll_failure(value['logs'], version=rootful.RESULT_V3, failure=other)
        with self.assertRaises(vm.Refusal): rootful.evidence(value['evidence'], config, complete=False, failure=value)

    def test_wrong_structured_inputs_refuse_safely_without_acquisition(self):
        config, value, _ = self.bundle()
        with patch.object(vm, 'read', side_effect=AssertionError('no acquisition')), \
             patch.object(vm.subprocess, 'Popen', side_effect=AssertionError('no native fallback')):
            for logs in (None, True, 0, '', [], {}, {'state': value['logs']['state']}):
                with self.assertRaises(vm.Refusal):
                    rootful.poll_failure(logs, version=rootful.RESULT_V3, failure=value)
            for failure in (None, True, 0, '', [], {}, {'state':'failed'},
                            {**value, 'logs':None}, {**value, 'logs':[]}, {**value, 'logs':{}}):
                with self.assertRaises(vm.Refusal):
                    rootful.poll_failure(value['logs'], version=rootful.RESULT_V3, failure=failure)
                with self.assertRaises(vm.Refusal):
                    rootful.evidence(value['evidence'], config, complete=False, failure=failure, version=rootful.RESULT_V3)

    def test_original_integrity_budgets_and_incomplete_sentinel_rules_remain(self):
        changes = [lambda v: v.update(owner='f'*32), lambda v: v.update(plan_sha256='f'*64),
            lambda v: v.update(native_actions=76), lambda v: v.update(utility_actions=769),
            lambda v: v['record_guards'].update(attempted=23),
            lambda v: v['evidence'].update(owner='f'*32),
            lambda v: v['evidence'].update(plan_sha256='f'*64),
            lambda v: v['evidence'].update(source_spec_sha256='f'*64),
            lambda v: v['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE].update(sha256='0'*64),
            lambda v: v['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE].update(base64='!'),
            lambda v: v['logs']['collectors']['out'].update(bytes=1)]
        for change in changes:
            config, value, _ = self.bundle(); change(value)
            with self.assertRaises(vm.Refusal): self.check(config, value)
        config, value, _ = self.bundle()
        raw = b'x'*16384
        value['logs']['collectors']['out'].update(bytes=16385, dd_status=9, source_eof=False)
        value['logs']['collectors']['err'].update(bytes=4097, tee_status=7, source_eof=False)
        value['logs']['identities']['child'] = None
        value['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE] = {'bytes': len(raw), 'sha256': vm.digest(raw),
                                                                  'base64': base64.b64encode(raw).decode()}
        checked = self.check(config, value)
        self.assertEqual(checked['logs']['collectors']['out']['bytes'], 16385)
        value['logs']['collectors']['out'] = None
        value['logs']['collectors']['err'] = None
        del value['evidence']['files'][rootful.PRIVATE_FAILURE_ROLE]
        self.assertIsNone(self.check(config, value)['logs']['collectors']['out'])

    def test_v3_success_still_requires_every_original_positive_proof(self):
        config, value, _ = DurableEvidenceControls.bundle(self)
        value['schema'] = rootful.RESULT_V3
        self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n', config)['schema'], rootful.RESULT_V3)
        changes = [lambda v: v.update(kind_create_status=1), lambda v: v.update(kind_delete_status=1),
            lambda v: v.update(source_deployment='not-reached'),
            lambda v: v['logs']['identities'].update(child=None),
            lambda v: v['logs']['collectors']['out'].update(source_eof=False),
            lambda v: v['logs'].update(startup_marker=False),
            lambda v: v['logs'].update(state='pg1.g'),
            lambda v: v['logs'].update(state='pg2.g.wrapper.Z.4096.8.106'),
            lambda v: v['evidence']['files'].pop('manifest')]
        for change in changes:
            altered = deepcopy(value); change(altered)
            with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(altered)+b'\n', config)

    def test_v12_and_all_legacy_plain_states_have_no_retrospective_detail(self):
        for version in (rootful.RESULT_V1, rootful.RESULT_V2, rootful.RESULT_V3):
            for state in ('not-established', 'direct-wait-zero', 'retired-wait-and-signal-cause-unavailable'):
                value = RootfulHostControls.result(self); value['schema'] = version
                value['logs']['state'] = state
                if state == 'not-established': value['logs']['startup_marker'] = False
                if state == 'retired-wait-and-signal-cause-unavailable': value['logs']['wrapper_observed_child_wait_status'] = None
                self.assertIsNone(rootful.poll_failure(value['logs'], version=version, failure=value))
        for version in (rootful.RESULT_V2, rootful.RESULT_V3):
            for code in sorted(rootful.POSTCREATE_GUARD_STATES):
                config, value, _ = GuardReasonDecoderControls.bundle(self, code)
                value['schema'] = version
                self.check(config, value)
                self.assertIsNone(rootful.poll_failure(value['logs'], version=version, failure=value))

    def test_new_inverse_seals_inside_and_outside_changes_without_rewriting_history(self):
        import hashlib
        source = receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))
        legacy_source = receiver_before_k_stage(receiver_before_i_atoms(source))
        historical_v3 = receiver_before_direct_exec(receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(legacy_source))))))))
        previous = receiver_before_poll_diagnostic(legacy_source)
        self.assertEqual((len(previous.encode()), hashlib.sha256(previous.encode()).hexdigest()),
                         (65336, GUARD_REASON_SOURCE))
        self.assertEqual(hashlib.sha256(SCRIPT.read_bytes()).hexdigest(), vm.PREREQUISITE_RECEIVER_SHA256)
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), I_ATOM_SOURCE)
        for old, new in [('poll_state=u', 'poll_state=S'), ('i < 4096', 'i < 4095'),
                         ('maximum=680', 'maximum=681')]:
            with self.assertRaises(AssertionError): receiver_before_poll_diagnostic(legacy_source.replace(old, new, 1))
        for text in ('read_file ', 'read -r ', 'read -ra ', 'grant_utility', 'native ', 'u /usr/bin/',
                     'for ((i = 0; i < 4096; i++))'):
            self.assertEqual(historical_v3.count(text), previous.count(text), text)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)


class PollPacingReceiverControls(unittest.TestCase):
    """Actual current poll/FD primitives with owned local Bash pipes and private proc projections."""
    roles = ('native', 'out', 'err', 'out-dd', 'out-tee', 'err-dd', 'err-tee')

    def fixture(self, *, role='native', glyph='S', persistent=True):
        fixture, _ = GuardReasonReceiverControls.fixture(self)
        proc = fixture.root/'projected-proc'
        for index, name in enumerate(self.roles):
            (fixture.root/'state'/f'logs-{name}.identity').write_text(f'{23+index} 1\n')
        # Keep the real inherited pipe descriptors; project only proc samples/clock.
        # Only V10-to-V9 epoch inversion; do not remove the V9 pacing here.
        fixture.definitions = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={fixture.root} stage={fixture.root}/stage').replace(
                '/proc/', str(proc)+'/').replace(str(proc)+'/self/fd/', '/proc/self/fd/').replace(
                    'read_file() {', 'observed_read_file() {', 1)
        if persistent:
            pid = 23 + self.roles.index(role)
            (proc/str(pid)).mkdir()
            (proc/str(pid)/'stat').write_text(f'{pid} (fixture) {glyph} '+'0 '*18+'1\n')
        hooks = r'''
mode=work
pace_behavior=stub pace_status=142 pace_bytes='' pace_reads=0 clock_reads=0
before_fds=(/proc/self/fd/[0-9]*)
read() {
  if [[ ${1:-} == -rd ]]; then
    pace_reads=$((pace_reads+1))
    saved_pace_fd=$pace_fd
    [[ -p /proc/self/fd/$pace_fd && /proc/self/fd/0 -ef /proc/self/fd/$pace_fd ]] || exit 90
    during_fds=(/proc/self/fd/[0-9]*)
    ((${#during_fds[@]} == ${#before_fds[@]}+1)) || exit 91
    printf 'pace:%s:%s:%s\n' "$name" "$i" "$poll_state" >> "$root/state/observations"
    case $pace_behavior in
      actual)
        if builtin read "$@"; then pace_actual=0; else pace_actual=$?; fi
        printf '%s:%s\n' "$pace_actual" "${#line}" >> "$root/state/wakes"
        return "$pace_actual"
        ;;
      signal-policy)
        trap 'printf signaled > "$root/state/signal"' ALRM
        kill -ALRM "$BASHPID"
        ;;
    esac
    line=$pace_bytes
    return "$pace_status"
  fi
  if [[ ${1:-} == -r && ${2:-} == record ]]; then
    printf 'sample:%s:%s\n' "$name" "$i" >> "$root/state/observations"
  fi
  if [[ ${1:-} == -ra && ${2:-} == parts ]]; then
    builtin read "$@" || return $?
    # SAMPLE PROJECTION
    return 0
  fi
  builtin read "$@"
}
read_file() {
  if [[ $1 == "$root/state/deadlines" ]]; then
    clock_reads=$((clock_reads+1))
    printf 'clock:%s:%s\n' "${name:-none}" "${i:-none}" >> "$root/state/observations"
  fi
  observed_read_file "$@"
  if [[ $1 == "$root/state/deadlines" ]]; then
    :
    # CLOCK PROJECTION
  fi
}
u() { printf unexpected-utility > "$root/state/unexpected"; fail; }
native() { printf unexpected-native > "$root/state/unexpected"; fail; }
'''
        return fixture, hooks

    def run_poll(self, fixture, hooks, *, before='', call='logs_retirement', after=''):
        body = hooks+before+r'''
trap 'saved=$?; trap - EXIT; printf "%s\n" "${guard_reason:-}" > "$root/state/test-reason"; exit "$saved"' EXIT
'''+call+'\n'+after+'\nprintf later > "$root/state/later"\n'
        result = fixture.child(body).finish()
        state = fixture.root/'state'
        reason = (state/'test-reason').read_text().strip()
        trace = (state/'observations').read_text().splitlines() if (state/'observations').exists() else []
        self.assertFalse((state/'unexpected').exists())
        return result, reason, trace

    def assert_refused(self, fixture, result, reason, *, expected=''):
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1, b'', b'rootful-receiver-refused\n'))
        self.assertEqual(reason, expected)
        self.assertFalse((fixture.root/'state/logs-retirement').exists())
        self.assertFalse((fixture.root/'state/later').exists())
        self.assertFalse(list((fixture.root/'state/credits').iterdir()))

    def reuse_after_first_sample(self, hooks):
        return hooks.replace('# SAMPLE PROJECTION', 'if ((i == 1)); then parts[19]=2; fi')

    def test_actual_empty_closed_producer_pipe_wakes_and_closes_exactly_one_added_fd(self):
        fixture, hooks = self.fixture()
        hooks = self.reuse_after_first_sample(hooks)
        result, reason, trace = self.run_poll(fixture, hooks, before='pace_behavior=actual\nif IFS= builtin read -r -n 1 eof_probe; then exit 89; fi\n', after=r'''
[[ ! ${pace_fd+x} && ! -e /proc/self/fd/$saved_pace_fd ]] || exit 92
after_fds=(/proc/self/fd/[0-9]*)
[[ ${before_fds[*]} == "${after_fds[*]}" ]] || exit 93
native() {
  [[ ! ${pace_fd+x} && ! -e /proc/self/fd/$saved_pace_fd ]] || exit 94
  printf next > "$root/state/next-native"
}
native
''')
        self.assertEqual((result.returncode, result.stdout, result.stderr, reason), (0, b'', b'', ''))
        self.assertEqual((fixture.root/'state/wakes').read_text(), '142:0\n')
        self.assertEqual((fixture.root/'state/next-native').read_text(), 'next')
        self.assertEqual(trace[:6], ['clock:native:0', 'sample:native:0',
                                     'clock:native:1', 'pace:native:1:S',
                                     'clock:native:1', 'sample:native:1'])
        # The open read/write pipe endpoint prevents a closed producer becoming EOF.
        self.assertEqual((fixture.root/'state/logs-retirement').read_text(),
                         'retired-wait-and-signal-cause-unavailable\n')

    def test_actual_data_including_nul_is_refused_before_second_sample(self):
        for raw in (b'A', b'\x00', b'\n', b'\xff', b'\x00suffix', b'A\x00'):
            with self.subTest(raw=raw):
                fixture, hooks = self.fixture()
                child = fixture.child(hooks+'pace_behavior=actual\nlogs_retirement\n'
                                      'printf forbidden > "$root/state/later"\n')
                child.process.stdin.write(raw)
                child.process.stdin.flush()
                result = child.finish()
                self.assert_refused(fixture, result, '')
                self.assertEqual((fixture.root/'state/observations').read_text().splitlines(),
                                 ['clock:native:0', 'sample:native:0',
                                  'clock:native:1', 'pace:native:1:S'])
                wake = (fixture.root/'state/wakes').read_text()
                self.assertEqual(wake, '0:0\n' if raw.startswith(b'\x00') else '0:1\n')

    def test_only_exact142_with_empty_buffer_is_an_accepted_policy_event(self):
        for status, text in ((0, ''), (0, 'x'), (1, ''), (2, ''), (127, ''),
                             (128, ''), (129, ''), (130, ''), (141, ''),
                             (142, 'x'), (143, ''), (255, '')):
            with self.subTest(status=status, text=text):
                fixture, hooks = self.fixture()
                result, reason, trace = self.run_poll(fixture, hooks,
                    before=f"pace_status={status} pace_bytes='{text}'\n")
                self.assert_refused(fixture, result, reason)
                self.assertEqual(trace.count('sample:native:0'), 1)
                self.assertNotIn('sample:native:1', trace)
        for behavior in ('stub', 'signal-policy'):
            fixture, hooks = self.fixture()
            result, reason, _ = self.run_poll(fixture, self.reuse_after_first_sample(hooks),
                                              before=f'pace_behavior={behavior}\n')
            self.assertEqual((result.returncode, reason), (0, ''))
            if behavior == 'signal-policy':
                self.assertEqual((fixture.root/'state/signal').read_text(), 'signaled')
            # Neither accepted event supplies a wait-zero or retirement proof.
            self.assertEqual((fixture.root/'state/logs-retirement').read_text(),
                             'retired-wait-and-signal-cause-unavailable\n')

    def test_nonpipe_regular_directory_character_and_closed_stdin_refuse(self):
        for kind in ('regular', 'directory', 'character', 'closed'):
            with self.subTest(kind=kind):
                fixture, hooks = self.fixture(persistent=False)
                path = fixture.root/'state/input'
                path.write_bytes(b'')
                redirection = {'regular': '< "$root/state/input"',
                               'directory': '< "$root/state"',
                               'character': '< /dev/null', 'closed': '0<&-'}[kind]
                result, reason, trace = self.run_poll(fixture, hooks,
                                                     call='logs_retirement '+redirection)
                self.assert_refused(fixture, result, reason)
                self.assertEqual(trace, [])

    def test_descriptor_exhaustion_refuses_open_before_any_clock_or_sample(self):
        fixture, hooks = self.fixture()
        # Bash allocates brace descriptors at ten or above. No helper/filler loop.
        result = fixture.child(hooks+'ulimit -n 10\nlogs_retirement\n'
                               'printf forbidden > \"$root/state/later\"\n').finish()
        self.assertEqual((result.returncode, result.stdout), (1, b''))
        # Descriptor exhaustion may also prevent the failure-frame redirection.
        # Require refusal and no sample/publication, never an invented frame.
        self.assertFalse((fixture.root/'state/observations').exists())
        self.assertFalse((fixture.root/'state/logs-retirement').exists())
        self.assertFalse((fixture.root/'state/later').exists())

    def test_open_and_same_inode_failures_refuse_without_sampling(self):
        for failure in ('open', 'inode'):
            with self.subTest(failure=failure):
                fixture, hooks = self.fixture()
                if failure == 'open':
                    old = 'exec {pace_fd}<> /proc/self/fd/0 || fail'
                    new = 'exec {pace_fd}<> /proc/self/fd/no-such-descriptor || fail'
                else:
                    old = '[[ /proc/self/fd/0 -ef /proc/self/fd/$pace_fd ]] || fail'
                    new = '[[ /proc/self/fd/0 -ef /proc/self/fd/2 ]] || fail'
                self.assertEqual(fixture.definitions.count(old), 1)
                fixture.definitions = fixture.definitions.replace(old, new, 1)
                result, reason, trace = self.run_poll(fixture, hooks)
                self.assertEqual((result.returncode, reason, trace), (1, '', []))
                self.assertIn(b'rootful-receiver-refused\n', result.stderr)
                self.assertFalse((fixture.root/'state/logs-retirement').exists())

    def test_no_wait_before_first_sample_or_with_one_second_remaining(self):
        for remaining in (1, 2):
            fixture, hooks = self.fixture()
            # Keep a real original clock check; project its existing deadline input.
            (fixture.root/'state/deadlines').write_text(f'{1+remaining} 110\n')
            result, reason, trace = self.run_poll(fixture, self.reuse_after_first_sample(hooks))
            self.assertEqual((result.returncode, reason), (0, ''))
            self.assertEqual(trace[:2], ['clock:native:0', 'sample:native:0'])
            self.assertEqual(sum(line.startswith('pace:') for line in trace), remaining-1)

    def test_postwake_clock_expiry_uses_cached_q_without_another_sample(self):
        fixture, hooks = self.fixture(glyph='Z')
        hooks = hooks.replace('# CLOCK PROJECTION',
            'if [[ ${name:-} == native && ${i:-0} == 1 && $pace_reads == 1 ]]; then REPLY="1 110"; fi')
        result, reason, trace = self.run_poll(fixture, hooks)
        self.assert_refused(fixture, result, reason, expected='pg2.p.native.Z.1.23.1')
        self.assertEqual(trace, ['clock:native:0', 'sample:native:0', 'clock:native:1',
                                 'pace:native:1:Z', 'clock:native:1'])

    def test_pre_wait_clock_expiry_does_not_wait_and_keeps_sample_count(self):
        for count in (0, 1):
            fixture, hooks = self.fixture()
            hooks = hooks.replace('# CLOCK PROJECTION',
                f'if [[ $name == native && $i == {count} ]]; then REPLY="1 110"; fi')
            result, reason, trace = self.run_poll(fixture, hooks)
            self.assert_refused(fixture, result, reason,
                expected=f'pg2.p.native.{"S" if count else "u"}.{count}.23.1')
            self.assertFalse(any(line.startswith('pace:') for line in trace))
            self.assertEqual(sum(line.startswith('sample:') for line in trace), count)

    def test_postwake_malformed_clock_and_interruption_stay_untagged(self):
        for action in ('REPLY="invalid 110"', 'exit 9'):
            fixture, hooks = self.fixture()
            hooks = hooks.replace('# CLOCK PROJECTION',
                'if [[ ${name:-} == native && ${i:-0} == 1 && $pace_reads == 1 ]]; then '+action+'; fi')
            result, reason, trace = self.run_poll(fixture, hooks)
            self.assertEqual((result.returncode, reason), (9 if action == 'exit 9' else 1, ''))
            self.assertNotIn('sample:native:1', trace)
            self.assertFalse((fixture.root/'state/logs-retirement').exists())

    def test_every_role_keeps4096_samples_and4095_bounded_wakes_even_for_zombie(self):
        for role, glyph in [(name, 'S') for name in self.roles]+[('native', 'Z')]:
            with self.subTest(role=role, glyph=glyph):
                fixture, hooks = self.fixture(role=role, glyph=glyph)
                # Bound-count control, separate from actual clock controls above.
                before = 'clock_check() { UPTIME=1 work_limit=100; }\n'
                result, reason, trace = self.run_poll(fixture, hooks, before=before)
                pid = 23+self.roles.index(role)
                self.assert_refused(fixture, result, reason,
                                     expected=f'pg2.g.{role}.{glyph}.4096.{pid}.1')
                self.assertEqual(sum(line.startswith('sample:') for line in trace), 4096)
                self.assertEqual(sum(line.startswith('pace:') for line in trace), 4095)
                self.assertIn(f'pace:{role}:4095:{glyph}', trace)
                self.assertNotIn(f'sample:{role}:4096', trace)

    def test_cached_finite_states_unknown_and_next_role_reset_remain_observations(self):
        for glyph in ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'I', 'W', 'unknown'):
            fixture, hooks = self.fixture(glyph=glyph)
            hooks = hooks.replace('# CLOCK PROJECTION',
                'if [[ ${name:-} == native && ${i:-0} == 1 && $pace_reads == 1 ]]; then REPLY="1 110"; fi')
            result, reason, _ = self.run_poll(fixture, hooks)
            cached = glyph if glyph in ('R', 'S', 'D', 'Z', 'T', 't', 'X', 'I') else 'u'
            self.assert_refused(fixture, result, reason, expected=f'pg2.p.native.{cached}.1.23.1')
        fixture, hooks = self.fixture(glyph='Z')
        hooks = self.reuse_after_first_sample(hooks).replace('# CLOCK PROJECTION',
            'if [[ ${name:-} == out ]]; then REPLY="1 110"; fi')
        result, reason, _ = self.run_poll(fixture, hooks)
        self.assert_refused(fixture, result, reason, expected='pg2.p.out.u.0.24.1')

    def test_postclose_deadline_refuses_publication_without_stale_poll_attribution(self):
        fixture, hooks = self.fixture(persistent=False)
        hooks = hooks.replace('# CLOCK PROJECTION',
            'if [[ ${poll_active:-0} == 0 ]]; then REPLY="1 110"; fi')
        result, reason, _ = self.run_poll(fixture, hooks,
            after='printf forbidden > "$root/state/after"')
        self.assert_refused(fixture, result, reason, expected='pg1.p')
        self.assertFalse((fixture.root/'state/after').exists())

    def test_wake_never_relaxes_collector_eof_status_marker_or_poison(self):
        for code in ('h', 'i', 'j', 'k', 'l', 'm', 'o'):
            with self.subTest(code=code):
                fixture, hooks = self.fixture()
                GuardReasonReceiverControls.alter(self, fixture, code)
                if code == 'o':
                    hooks = hooks.replace('# CLOCK PROJECTION', '')
                    hooks = hooks.replace('observed_read_file "$@"',
                        'observed_read_file "$@"\n'
                        '  if [[ $1 == "$root/state/logs-captures" ]]; then printf poisoned > "$root/state/poison"; fi')
                result, reason, trace = self.run_poll(fixture, self.reuse_after_first_sample(hooks))
                self.assert_refused(fixture, result, reason, expected='pg1.'+code)
                self.assertIn('pace:native:1:S', trace)

    def test_actual_finish_closes_pacing_fd_before_diagnosis_and_cleanup_native(self):
        for failure in ('read', 'postwake-clock', 'preexisting-poison'):
            with self.subTest(failure=failure):
                fixture, hooks = self.fixture()
                source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
                finish = 'finish() {'+source.split('finish() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
                if failure == 'postwake-clock':
                    hooks = hooks.replace('# CLOCK PROJECTION',
                        'if [[ ${i:-0} == 1 && $pace_reads == 1 ]]; then REPLY="1 110"; fi')
                before = 'pace_status=1\n' if failure == 'read' else ''
                if failure == 'preexisting-poison': before += 'printf poisoned > "$root/state/poison"\n'
                body = hooks+before+r'''
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=own spec_sha=fixed-private
remember() {
  [[ ! ${pace_fd+x} ]] || exit 95
  [[ ! ${saved_pace_fd+x} || ! -e /proc/self/fd/$saved_pace_fd ]] || exit 96
  printf diagnosis >> "$root/state/finish-order"
}
native() {
  [[ ! ${pace_fd+x} ]] || exit 97
  [[ ! ${saved_pace_fd+x} || ! -e /proc/self/fd/$saved_pace_fd ]] || exit 98
  printf cleanup >> "$root/state/finish-order"
  last_tool_status=0
}
emit_evidence() { evidence_json='{}'; printf evidence >> "$root/state/finish-order"; }
emit_logs_evidence() { logs_json='{}'; printf logs >> "$root/state/finish-order"; }
'''+finish+'trap finish EXIT\nlogs_retirement\nprintf forbidden > "$root/state/later"\n'
                result = fixture.child(body).finish()
                self.assertEqual(result.returncode, 1)
                self.assertIn(b'rootful-receiver-refused\n', result.stderr)
                value = json.loads(result.stdout)
                self.assertEqual((value['state'], value['kind_create_status'], value['kind_delete_status']),
                                 ('failed', 0, 0))
                self.assertEqual((fixture.root/'state/finish-order').read_text(),
                                 'diagnosiscleanupevidencelogs')
                self.assertTrue((fixture.root/'state/poison').exists())
                self.assertFalse((fixture.root/'state/later').exists())
                self.assertFalse((fixture.root/'state/logs-retirement').exists())

    def test_close_failure_stops_finish_before_any_diagnosis_or_native_child(self):
        fixture, hooks = self.fixture(persistent=False)
        # Force only the close operation to fail. Bash versions may legally
        # accept an already-closed fd or resolve a plain identifier arithmetically;
        # neither is a portable close-error injection. Keep the real exit branch.
        close_operation = 'exec {pace_fd}>&-'
        self.assertEqual(fixture.definitions.count(close_operation), 1)
        fixture.definitions = fixture.definitions.replace(close_operation, 'false', 1)
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        finish = 'finish() {'+source.split('finish() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
        result = fixture.child(hooks+r'''
remember() { printf forbidden > "$root/state/diagnosis"; }
native() { printf forbidden > "$root/state/native"; }
exec {pace_fd}<> /proc/self/fd/0
[[ /proc/self/fd/0 -ef /proc/self/fd/$pace_fd ]] || exit 88
'''+finish+'trap finish EXIT\nexit 7\n').finish()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'')
        self.assertFalse((fixture.root/'state/diagnosis').exists())
        self.assertFalse((fixture.root/'state/native').exists())

    def test_named_fifo_stdin_uses_same_fixed_read_and_releases_its_receiver_fd(self):
        import os
        fixture, hooks = self.fixture()
        os.mkfifo(fixture.root/'state/input-fifo', 0o600)
        result, reason, _ = self.run_poll(fixture, self.reuse_after_first_sample(hooks),
            before='pace_behavior=actual\nexec 0<> "$root/state/input-fifo"\n',
            after='[[ ! ${pace_fd+x} && ! -e /proc/self/fd/$saved_pace_fd ]] || exit 92')
        self.assertEqual((result.returncode, reason), (0, ''))
        self.assertEqual((fixture.root/'state/wakes').read_text(), '142:0\n')

    def test_actual_eof_after_injected_writer_hold_loss_is_refused(self):
        fixture, hooks = self.fixture()
        # Failure injection only: drop the product's writer hold, then duplicate
        # the original read-only fd0. OwnedPipeChild closes its producer before wait.
        hooks = hooks.replace('if builtin read "$@"; then pace_actual=0;',
            'exec {pace_fd}>&-\n        exec {pace_fd}<&0\n'
            '        if builtin read "$@"; then pace_actual=0;')
        result, reason, trace = self.run_poll(fixture, hooks,
            before='pace_behavior=actual\nif IFS= builtin read -r -n 1 eof_probe; then exit 89; fi\n')
        self.assert_refused(fixture, result, reason)
        self.assertEqual((fixture.root/'state/wakes').read_text(), '1:0\n')
        self.assertNotIn('sample:native:1', trace)

    def test_postwake4095_boundary_in_every_role_keeps_actual_clock_and_cached_q(self):
        for role in self.roles:
            with self.subTest(role=role):
                fixture, hooks = self.fixture(role=role)
                fixture.definitions = fixture.definitions.replace(
                    'clock_check() {', 'original_clock_check() {', 1)
                (fixture.root/'state/deadlines').write_text('1 110\n')
                # Accelerate earlier clocks, then exercise the actual clock helper
                # on the post-wake boundary, with the original expired input record.
                before = '''clock_check() {
  UPTIME=1 work_limit=100
  if [[ ${name:-} == '''+role+''' && ${i:-0} == 4095 && $pace_reads == 4095 ]]; then
    original_clock_check "$@"
  fi
}
'''
                result, reason, trace = self.run_poll(fixture, hooks, before=before)
                pid = 23+self.roles.index(role)
                self.assert_refused(fixture, result, reason,
                                     expected=f'pg2.p.{role}.S.4095.{pid}.1')
                self.assertEqual(sum(line.startswith('sample:') for line in trace), 4095)
                self.assertEqual(sum(line.startswith('pace:') for line in trace), 4095)
                self.assertNotIn(f'sample:{role}:4095', trace)

    def test_af_unix_socket_stdin_refuses_before_any_clock_or_sample(self):
        import fcntl
        import os
        import socket
        import subprocess
        fixture, hooks = self.fixture(persistent=False)
        selected, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with selected, peer, ExitStack() as descriptors:
            # Source initialization owns fd3; inherit a distinct test-only fd.
            receiver_fd = fcntl.fcntl(selected.fileno(), fcntl.F_DUPFD_CLOEXEC, 10)
            descriptors.callback(os.close, receiver_fd)
            popen = subprocess.Popen
            def inherited_input(*arguments, **keywords):
                self.assertNotIn('pass_fds', keywords)
                return popen(*arguments, pass_fds=(receiver_fd,), **keywords)
            with patch('test_owned_guest_receiver.subprocess.Popen', side_effect=inherited_input):
                result, reason, trace = self.run_poll(fixture, hooks,
                    before=f'exec 0<&{receiver_fd}\nexec {receiver_fd}<&-\n'
                           '[[ -S /proc/self/fd/0 ]] || exit 88\n')
            self.assert_refused(fixture, result, reason)
            self.assertEqual(trace, [])

    def test_pty_stdin_refuses_before_any_clock_or_sample(self):
        import fcntl
        import os
        import subprocess
        fixture, hooks = self.fixture(persistent=False)
        master, slave = os.openpty()
        with ExitStack() as descriptors:
            descriptors.callback(os.close, master)
            descriptors.callback(os.close, slave)
            receiver_fd = fcntl.fcntl(slave, fcntl.F_DUPFD_CLOEXEC, 10)
            descriptors.callback(os.close, receiver_fd)
            popen = subprocess.Popen
            def inherited_input(*arguments, **keywords):
                self.assertNotIn('pass_fds', keywords)
                return popen(*arguments, pass_fds=(receiver_fd,), **keywords)
            with patch('test_owned_guest_receiver.subprocess.Popen', side_effect=inherited_input):
                result, reason, trace = self.run_poll(fixture, hooks,
                    before=f'exec 0<&{receiver_fd}\nexec {receiver_fd}<&-\n'
                           '[[ -c /proc/self/fd/0 && -t 0 ]] || exit 88\n')
            self.assert_refused(fixture, result, reason)
            self.assertEqual(trace, [])

    def test_exact_inverse_preserves_v3_v2_v1_and_rejects_inside_or_outside_mutation(self):
        import hashlib
        source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        historical_v3 = receiver_before_poll_pacing(source)
        self.assertEqual((len(source.encode()), hashlib.sha256(source.encode()).hexdigest()),
                         (OWNED_CGROUP_SOURCE_BYTES, OWNED_CGROUP_SOURCE))
        self.assertEqual(hashlib.sha256(historical_v3.encode()).hexdigest(), POLL_DIAGNOSTIC_SOURCE)
        historical_v2 = receiver_before_poll_diagnostic(source)
        historical_v1 = receiver_before_guard_reason(historical_v2)
        self.assertEqual(hashlib.sha256(historical_v2.encode()).hexdigest(), GUARD_REASON_SOURCE)
        self.assertEqual(hashlib.sha256(historical_v1.encode()).hexdigest(), POSTCREATE_PREFIX_SOURCE)
        for old, new in (('-t 0.01', '-t 0.02'), ('actual == 142', 'actual > 128'),
                         ('work_limit - UPTIME > 1', 'work_limit - UPTIME >= 1'),
                         ('i < 4096', 'i < 4095'), ('maximum=680', 'maximum=681')):
            with self.subTest(old=old), self.assertRaises(AssertionError):
                receiver_before_poll_pacing(source.replace(old, new, 1))
        with self.assertRaises(AssertionError):
            receiver_before_poll_pacing(historical_v3)
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256, CAPTURE_SIZE_SOURCE)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)


class DirectExecReceiverControls(unittest.TestCase):
    """Current v4 ordinary exec and owned local pipes only; no native client runs."""
    def fixture(self, *, missing_exec=False, setup_failure=False):
        fixture = BashProtocolControls(); fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.host_process_identities()
        payload = fixture.root/'native-payload'
        payload.write_text(r'''#!/usr/bin/bash
set -Eeuo pipefail
IFS= read -r record < "/proc/$BASHPID/stat"
tail=${record##*) }; read -ra fields <<< "$tail"
printf '%s %s\n' "$BASHPID" "${fields[19]}" > "STATE/exec-identity"
printf 'Reached target Multi-User System.\n'
printf 'fixed-private-error' >&2
exec 1>&- 2>&-
IFS= read -r release || true
'''.replace('STATE', str(fixture.root/'state')))
        final_exec = 'exec /usr/bin/podman --remote=false logs -f "$node"'
        self.assertEqual(fixture.definitions.count(final_exec), 1)
        replacement = 'exec /no-such-owned-test-executable' if missing_exec else 'exec /usr/bin/bash "$root/native-payload"'
        fixture.definitions = fixture.definitions.replace(final_exec, replacement, 1)
        if setup_failure:
            line = 'if exec 1>&$stdout_fd 2>&$stderr_fd {stdout_fd}>&- {stderr_fd}>&- 3>&-;'
            self.assertEqual(fixture.definitions.count(line), 1)
            fixture.definitions = fixture.definitions.replace(line,
                'exec 3>&-\n  if exec 1>&999999 2>&$stderr_fd {stdout_fd}>&- {stderr_fd}>&- 3>&-;', 1)
        body = r'''mode=work
node=owned-local-fixture cluster=owned-local-fixture alias=localhost/owned-local-fixture
printf 'work\n' > "$root/state/mode"
printf '999999999 999999999\n' > "$root/state/deadlines"
'''
        return fixture, body

    def await_collectors(self, fixture, child):
        while not all((fixture.root/'state'/f'logs-{role}.closed').exists() for role in ('out', 'err')):
            child.remaining(); child.read_available()
            time.sleep(min(0.005, child.remaining()))
        for role, size in (('out', 34), ('err', 19)):
            values = (fixture.root/'state'/f'logs-{role}.closed').read_text().split()
            self.assertEqual(values, ['0', '0', str(size), 'eof'])

    def test_identity_start_and_parent_shape_remain_without_unused_parent_cache(self):
        fields = ['S', '1']+['0']*17+['7']
        records = [(f'23 (fixture) {" ".join(fields)}\n', True)]
        for index in (1, 19):
            bad = fields.copy(); bad[index] = 'invalid'
            records.append((f'23 (fixture) {" ".join(bad)}\n', False))
        records += [('23 (fixture) S 1 7\n', False),
                    (f'24 (fixture) {" ".join(fields)}\n', False), (None, False)]
        for record, accepted in records:
            with self.subTest(record=record):
                fixture = BashProtocolControls(); fixture.setUp()
                self.addCleanup(fixture.doCleanups)
                read = '  IFS= read -r record < "/proc/$pid/stat" || fail\n'
                self.assertEqual(fixture.definitions.count(read), 1)
                fixture.definitions = fixture.definitions.replace(read,
                    '  IFS= read -r record < "$root/state/projected-stat" || fail\n', 1)
                if record is not None:
                    (fixture.root/'state/projected-stat').write_text(record)
                result = fixture.child('process_identity 23\n'
                    '[[ $PROC_START == 7 && ! ${PROC_PARENT+x} ]] || exit 88\n'
                    'printf shape-checked\n').finish()
                if accepted:
                    self.assertEqual((result.returncode, result.stdout), (0, b'shape-checked'))
                else:
                    self.assertEqual(result.returncode, 1)
                    self.assertNotIn(b'shape-checked', result.stdout)

    def test_same_owned_pid_start_executes_payload_and_collectors_really_wait_dd_tee(self):
        fixture, body = self.fixture()
        child = fixture.child(body+'stream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"\nprintf forbidden\n')
        self.await_collectors(fixture, child)
        before = (fixture.root/'state/logs-native.identity').read_text().split()
        after = (fixture.root/'state/exec-identity').read_text().split()
        self.assertEqual(before, after)
        self.assertEqual(int(before[0]), child.process.pid)
        self.assertTrue(child.running())  # EOF is not native-identity retirement.
        self.assertFalse((fixture.root/'state/logs-wrapper.identity').exists())
        self.assertFalse((fixture.root/'state/logs-child.identity').exists())
        self.assertFalse((fixture.root/'state/logs-wrapper.status').exists())
        self.assertEqual(len(list((fixture.root/'state/credits').glob('utility-work.*'))), 6)
        result = child.finish()
        self.assertEqual((result.returncode, result.stdout), (0, b'Reached target Multi-User System.\n'))
        self.assertEqual((fixture.root/'captures/work.0.out').read_bytes(), result.stdout)
        self.assertEqual((fixture.root/'captures/work.0.err').read_bytes(), b'fixed-private-error')

    def test_cancellation_targets_the_exact_unreaped_exec_pid_without_group_signal(self):
        import os, signal
        fixture, body = self.fixture()
        child = fixture.child(body+'stream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"\n')
        self.await_collectors(fixture, child)
        self.assertIsNone(child.process.returncode)
        self.assertEqual(int((fixture.root/'state/exec-identity').read_text().split()[0]), child.process.pid)
        os.kill(child.process.pid, signal.SIGKILL)  # Actual owned unreaped test child only.
        result = child.finish()
        self.assertEqual(result.returncode, -signal.SIGKILL)
        self.assertFalse((fixture.root/'state/logs-wrapper.status').exists())

    def test_exec_failure_after_fd3_close_poison_and_nonzero_without_following_effect(self):
        fixture, body = self.fixture(missing_exec=True)
        result = fixture.child(body+'stream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"\nprintf forbidden > "$root/state/later"\n').finish()
        self.assertEqual(result.returncode, 127)
        self.assertEqual((fixture.root/'state/poison').read_text(), 'poisoned\n')
        self.assertFalse((fixture.root/'state/later').exists())
        self.assertFalse((fixture.root/'state/logs-wrapper.status').exists())

    def test_failed_descriptor_setup_after_fd3_close_poison_and_nonzero(self):
        fixture, body = self.fixture(setup_failure=True)
        result = fixture.child(body+'stream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"\nprintf forbidden > "$root/state/later"\n').finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((fixture.root/'state/poison').read_text(), 'poisoned\n')
        self.assertFalse((fixture.root/'state/later').exists())
        self.assertFalse((fixture.root/'state/exec-identity').exists())

    def test_execfail_setup_failure_remains_nonzero_before_logs_claim_or_collectors(self):
        fixture, body = self.fixture()
        result = fixture.child(body+'shopt() { return 37; }\nstream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"\n').finish()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((fixture.root/'state/poison').exists())
        self.assertFalse((fixture.root/'state/logs-claimed').exists())
        self.assertFalse((fixture.root/'state/logs-native.identity').exists())

    def test_poison_write_failure_still_exits_nonzero_after_failed_exec(self):
        fixture, body = self.fixture(missing_exec=True)
        (fixture.root/'state/poison-denied').mkdir()
        poison_write = "  printf '%s\\n' poisoned > \"$root/state/poison\" || true\n"
        self.assertEqual(fixture.definitions.count(poison_write), 1)
        fixture.definitions = fixture.definitions.replace(poison_write, poison_write.replace('/poison', '/poison-denied'), 1)
        result = fixture.child(body+'stream_logs=1 native 16384 4096 /usr/bin/podman --remote=false logs -f "$node"\nprintf forbidden > "$root/state/later"\n').finish()
        self.assertEqual(result.returncode, 127)
        self.assertFalse((fixture.root/'state/later').exists())

    def test_nonzero_subshell_refuses_before_any_claim_credit_or_collector_effect(self):
        for call in ('logs_native', 'provider logs -f "$node"'):
            fixture, body = self.fixture()
            result = fixture.child(body+'('+call+')\nprintf forbidden\n').finish()
            self.assertEqual(result.returncode, 1)
            self.assertTrue((fixture.root/'state/poison').exists())
            self.assertFalse((fixture.root/'state/logs-claimed').exists())
            self.assertFalse(list((fixture.root/'state/credits').iterdir()))
            self.assertFalse((fixture.root/'state/logs-native.identity').exists())
            self.assertFalse(list((fixture.root/'captures').iterdir()))

    def test_current_source_has_single_exec_chain_and_separate_frozen_v3_inverse(self):
        import hashlib
        source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        old = receiver_before_direct_exec(receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(source))))))))
        self.assertEqual((len(old.encode()), hashlib.sha256(old.encode()).hexdigest()),
                         (65362, '1415b8c3f9e653e40547fb8e0b5d74e759edf825ea27e7332c472b510f84eb2a'))
        self.assertNotIn('logs_gate() {', source)
        self.assertNotIn('if [[ ${1:-} == logs-child ]]', source)
        self.assertNotIn('--pdeathsig', source)
        current = source.split('logs_native() {', 1)[1].split('\n}\n', 1)[0]
        self.assertLess(current.index('[[ $BASH_SUBSHELL == 0 ]]'), current.index('claim logs'))
        self.assertLess(current.index('shopt -s execfail'), current.index('exec 1>&$stdout_fd'))
        self.assertNotIn('wait ', current)
        for a, b in [('shopt -s execfail', ':'), ('BASH_SUBSHELL == 0', 'BASH_SUBSHELL == 1'),
                     ('exec /usr/bin/podman', '/usr/bin/podman')]:
            with self.assertRaises(AssertionError): receiver_before_direct_exec(receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(source.replace(a, b, 1)))))))))


class DirectExecDecoderControls(unittest.TestCase):
    def bundle(self, *, complete=False, state='pg2.g.native.S.4096.23.1'):
        if complete:
            config, value, raw = DurableEvidenceControls.bundle(self)
        else:
            config, value, raw = GuardReasonDecoderControls.bundle(self)
        value['schema'] = rootful.RESULT_V4
        value['logs']['identities'] = {role: {'pid': 23+i, 'start': 1}
            for i, role in enumerate(('native', 'out', 'err', 'out-dd', 'out-tee', 'err-dd', 'err-tee'))}
        value['logs']['wrapper_observed_child_wait_status'] = None
        value['logs']['state'] = 'retired-wait-and-signal-cause-unavailable' if complete else state
        return config, value, raw

    def test_v4_positive_requires_original_proof_and_has_no_log_wait_status(self):
        config, value, _ = self.bundle(complete=True)
        checked = rootful.wire_record(vm.encode(value)+b'\n', config)
        self.assertEqual(checked['schema'], rootful.RESULT_V4)
        self.assertEqual(set(checked['logs']['identities']), rootful.LOG_ROLES_V4)
        for field, altered in [('wrapper_observed_child_wait_status', 0),
                               ('wrapper_observed_child_wait_status', False),
                               ('state', 'direct-wait-zero')]:
            bad = deepcopy(value); bad['logs'][field] = altered
            with self.subTest(field=field, value=altered), self.assertRaises(vm.Refusal):
                rootful.wire_record(vm.encode(bad)+b'\n', config)
        bad = deepcopy(value); bad['kind_delete_status'] = 7
        with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(bad)+b'\n', config)

    def test_v4_seven_roles_cached_states_counts_and_private_durable_failure(self):
        for role in sorted(rootful.LOG_ROLES_V4):
            for cause, count, glyph in [('g', 4096, 'Z'), ('p', 0, 'u'), ('p', 4095, 'S')]:
                config, value, _ = self.bundle()
                identity = value['logs']['identities'][role]
                state = f'pg2.{cause}.{role}.{glyph}.{count}.{identity["pid"]}.1'
                value['logs']['state'] = state
                checked = rootful.wire_record(vm.encode(value)+b'\n', config, allow_failure=True)
                detail = rootful.poll_failure(checked['logs'], version=rootful.RESULT_V4, failure=checked)
                self.assertEqual((detail.role, detail.iterations_completed), (role, count))
                self.assertLessEqual(len(state), 46)
        config, value, raw = self.bundle()
        wire = vm.encode(value)+b'\n'
        with tempfile.TemporaryDirectory(prefix='v4-private-') as directory:
            parent = Path(directory)
            descriptor = rootful.durable_wire(wire, config, parent, vm.Budget(time.monotonic()+30, 10))
            self.assertEqual((parent/descriptor['name']).read_bytes(), wire)
            self.assertNotIn(raw, vm.encode(descriptor))
            self.assertNotIn(b'pg2.', vm.encode(descriptor))

    def test_v4_missing_extra_alias_retirement_and_observation_mutations_refuse(self):
        config, value, _ = self.bundle(complete=True)
        mutations = []
        for role in sorted(rootful.LOG_ROLES_V4):
            bad = deepcopy(value); bad['logs']['identities'][role] = None; mutations.append(bad)
        bad = deepcopy(value); bad['logs']['identities']['child'] = {'pid': 200, 'start': 1}; mutations.append(bad)
        bad = deepcopy(value); bad['logs']['identities']['out'] = bad['logs']['identities']['native']; mutations.append(bad)
        for field, altered in [('source_eof', False), ('dd_status', 1), ('tee_status', 1), ('bytes', 16385)]:
            bad = deepcopy(value); bad['logs']['collectors']['out'][field] = altered; mutations.append(bad)
        bad = deepcopy(value); bad['logs']['startup_marker'] = False; mutations.append(bad)
        for bad in mutations:
            with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(bad)+b'\n', config)

    def test_v4_rejects_legacy_roles_wait_guard_and_cross_version_relabelling(self):
        for state in ['pg1.n', 'pg2.g.wrapper.S.4096.23.1', 'pg2.g.child.S.4096.23.1']:
            config, value, _ = self.bundle(state=state)
            with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(value)+b'\n', config, allow_failure=True)
        config, value, _ = self.bundle()
        for version in (rootful.RESULT_V1, rootful.RESULT_V2, rootful.RESULT_V3,
                        'kubernetes-lens-owned-rootful-result-v5'):
            bad = deepcopy(value); bad['schema'] = version
            with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(bad)+b'\n', config, allow_failure=True)
        for version in (rootful.RESULT_V2, rootful.RESULT_V3):
            config, historical, _ = GuardReasonDecoderControls.bundle(self, code='pg1.n')
            historical['schema'] = version
            self.assertEqual(rootful.wire_record(vm.encode(historical)+b'\n', config, allow_failure=True)['logs']['state'], 'pg1.n')


class PostlogReceiverControls(unittest.TestCase):
    """Original statements on fixed local DATA; no target observation."""
    def fixture(self):
        fixture = BashProtocolControls(); fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def segment(self, source=None):
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))) if source is None else source
        return source.split('\nlogs_retirement\n', 1)[1].split('\nnode_cgroup=', 1)[0]

    def setup_actions(self, failed=''):
        return r'''rootful_intent=execution-v1 mode=work
node=owned-node image_id=owned-image out=$captures/work.1.out
resource_check() { printf 'resource\n' >> "$root/trace"; [[ $failed != r ]] || fail; }
read_file() { printf 'read:%s\n' "${1##*/}" >> "$root/trace"; REPLY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; [[ $failed != i ]] || fail; [[ $failed == f ]] || REPLY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; }
native() { printf 'native:%s\n' "$*" >> "$root/trace"; [[ $failed != n ]]; }
u() { printf 'jq:%s\n' "$*" >> "$root/trace"; [[ $failed != j ]]; }
remember() { printf 'remember:%s\n' "$*" >> "$root/trace"; [[ $failed != e ]] || fail; }
''' + 'failed=' + failed + '\n'

    def test_six_original_fail_sites_and_success_keep_old_action_order(self):
        historical_current = receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))))))
        old = receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))))))))))
        for code in ('', 'r', 'i', 'f', 'n', 'j', 'e'):
            traces = []
            for source in (old, historical_current):
                fixture = self.fixture()
                body = self.setup_actions(code) + "trap 'printf \"%s\" \"$postlog_failure\" > \"$root/reason\"' EXIT\n" + self.segment(source)
                result = fixture.child(body).finish()
                self.assertEqual(result.returncode, 1 if code else 0)
                expected = 'pl1.'+code if code and source != old else ''
                self.assertEqual((fixture.root/'reason').read_text(), expected)
                traces.append((fixture.root/'trace').read_text().replace(str(fixture.root),'ROOT'))
                if code: self.assertTrue((fixture.root/'state/poison').exists())
            self.assertEqual(traces[0], traces[1])

    def test_original_nested_helpers_and_resource_guard(self):
        for code, action in [('i', 'read_file "$root/missing"'),
                             ('e', 'remember node-inspect "$root/not-a-capture"')]:
            fixture = self.fixture()
            body = f'''rootful_intent=execution-v1 mode=work postlog_site={code}
trap 'printf "%s" "$postlog_failure" > "$root/reason"' EXIT
{action}
'''
            self.assertEqual(fixture.child(body).finish().returncode, 1)
            self.assertEqual((fixture.root/'reason').read_text(), 'pl1.'+code)
        fixture = self.fixture()
        source = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('resource_check() {\n',1)[1].split('\n}',1)[0]
        guard = source.split('  read -r value < /proc/sys/fs/nr_open',1)[0]
        guard = guard.replace('read -r value < /proc/sys/kernel/pid_max', 'read -r value <<< 1')
        result = fixture.child('rootful_intent=execution-v1 mode=work postlog_site=r\n'
            'trap \'printf "%s" "$postlog_failure" > "$root/reason"\' EXIT\n'
            'resource_check() {\n'+guard+'\n}\nresource_check\n').finish()
        self.assertEqual(result.returncode, 1)
        self.assertEqual((fixture.root/'reason').read_text(), 'pl1.r')

    def test_scope_skips_err_signals_subshell_and_first_assignment(self):
        cases = [('', 'fail', ''), ('postlog_site=r', ':', ''),
                 ('postlog_site=r', 'false', ''),
                 ('postlog_site=r', 'printf x > "$root/missing/file"', ''),
                 ('postlog_site=r', 'kill -TERM "$BASHPID"', ''),
                 ('postlog_site=r', '(fail) || :', ''),
                 ('postlog_site=r mode=cleanup', 'fail', ''),
                 ('postlog_site=r rootful_intent=prerequisite-v1', 'fail', ''),
                 ('postlog_site=r rootful_admitted=0', 'fail', ''),
                 ('postlog_site=unknown', 'fail', ''),
                 ('postlog_site=r postlog_failure=pl1.i', 'fail', 'pl1.i'),
                 ("postlog_site=''", 'fail', '')]
        for setup, action, expected in cases:
            fixture = self.fixture()
            body = '''rootful_intent=execution-v1 mode=work
trap 'exit 1' ERR HUP INT TERM
trap 'printf "%s" "$postlog_failure" > "$root/reason"' EXIT
'''+setup+'\n'+action+'\n'
            fixture.child(body).finish()
            self.assertEqual((fixture.root/'reason').read_text(), expected, (setup,action))

    def test_inherited_variables_reset_and_unexported(self):
        fixture = self.fixture()
        fixture.definitions = "export postlog_site=r postlog_failure=pl1.r\n"+fixture.definitions
        result = fixture.run_body('[[ -z $postlog_site && -z $postlog_failure ]]\ndeclare -p postlog_site postlog_failure\n')
        self.assertNotIn(b'declare -x', result)

    def test_real_finish_preserves_exit_err_and_clear_before_cleanup(self):
        original = receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('\nfinish() {\n',1)[1].split('\ntrap finish EXIT',1)[0]
        finish = 'finish() {\n'+original+'\n'
        setup = '''rootful_intent=execution-v1 mode=work postlog_site=r
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=owned
pace_close() { [[ -z $postlog_site ]]; printf 'pace\n' >> "$root/order"; }
remember() { [[ -z $postlog_site ]]; printf 'diagnose\n' >> "$root/order"; }
native() { [[ -z $postlog_site ]]; printf 'native\n' >> "$root/order"; last_tool_status=0; }
emit_evidence() { [[ -z $postlog_site ]]; printf 'evidence\n' >> "$root/order"; evidence_json='{}'; }
emit_logs_evidence() { [[ -z $postlog_site ]]; logs_json='{}'; }
'''
        for code in ('', 'pl1.i'):
            for action, status in [('exit 7',7), ('false',1), ('kill -TERM "$BASHPID"',1)]:
                fixture = self.fixture()
                body = setup+f'postlog_failure={code}\n'+finish+"trap finish EXIT\ntrap 'exit 1' ERR HUP INT TERM\n"+action+'\n'
                result = fixture.child(body).finish()
                self.assertEqual(result.returncode,status,result.stderr)
                self.assertEqual(json.loads(result.stdout)['postlog_failure'],code or None)
                self.assertEqual((fixture.root/'order').read_text().splitlines(),['pace','diagnose','native','evidence'])
        for code in ('', 'pl1.i'):
            fixture = self.fixture()
            fixture.definitions = fixture.definitions.replace('  case ${1:-} in\n    [a-p])',
                '  printf "%s" "$postlog_failure" > "$root/at-fail"\n  case ${1:-} in\n    [a-p])',1)
            body = setup+f'postlog_failure={code}\n'+finish+'''remember() { fail; }
trap finish EXIT
exit 7
'''
            self.assertEqual(fixture.child(body).finish().returncode,1)
            self.assertEqual((fixture.root/'at-fail').read_text(),code)

    def test_exact_v5_inverse_preserves_all_historical_seals(self):
        import hashlib
        source = receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))); old = receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(source)))))))
        self.assertEqual(hashlib.sha256(old.encode()).hexdigest(), DIRECT_EXEC_SOURCE)
        self.assertEqual(len(old.encode()),DIRECT_EXEC_SOURCE_BYTES)
        self.assertLessEqual(len(source.encode()),65536)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)
        for a,b in [('postlog_site=r','postlog_site=i'),('local status=$?','local status=0'),
                    ('postlog_failure=pl1.$postlog_site','postlog_failure=pl1.r'),('maximum=680','maximum=681')]:
            with self.assertRaises(AssertionError): receiver_before_postlog(receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(source.replace(a,b,1))))))))
        with self.assertRaises(AssertionError): receiver_before_postlog(old)
        with self.assertRaises(AssertionError): receiver_before_direct_exec(source)


class PostlogDecoderControls(unittest.TestCase):
    def bundle(self, code='pl1.r'):
        config,value,raw = DirectExecDecoderControls.bundle(self,complete=True)
        value.update(schema=rootful.RESULT_V5,postlog_failure=code,state='failed',source_deployment='not-reached')
        value['evidence']['files'].pop('node-inspect')
        return config,value,raw

    def test_all_six_codes_preserve_positive_logs_and_delete_failure(self):
        for code in sorted(rootful.POSTLOG_FAILURES):
            config,value,_ = self.bundle(code)
            for delete in (0,19):
                value['kind_delete_status']=delete
                checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
                self.assertEqual(checked['postlog_failure'],code)
                self.assertEqual(checked['logs'],value['logs'])
                self.assertEqual(checked['kind_delete_status'],delete)
                self.assertIsNone(rootful.poll_failure(checked['logs'],version=rootful.RESULT_V5,failure=checked))
                with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(value)+b'\n',config)

    def test_v5_success_null_and_old_versions_never_gain_field(self):
        config,value,_ = DirectExecDecoderControls.bundle(self,complete=True)
        value.update(schema=rootful.RESULT_V5,postlog_failure=None)
        self.assertIsNone(rootful.wire_record(vm.encode(value)+b'\n',config)['postlog_failure'])
        value['postlog_failure']='pl1.r'
        with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(value)+b'\n',config)
        for version in (rootful.RESULT_V1,rootful.RESULT_V2,rootful.RESULT_V3,rootful.RESULT_V4):
            config,value,_ = (DirectExecDecoderControls.bundle(self,complete=True) if version==rootful.RESULT_V4
                              else DurableEvidenceControls.bundle(self))
            value['schema']=version
            self.assertNotIn('postlog_failure',rootful.wire_record(vm.encode(value)+b'\n',config))
            value['postlog_failure']=None
            with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(value)+b'\n',config)

    def test_types_scopes_logs_catalogue_and_true_future_refuse(self):
        config,value,_=self.bundle()
        changes=[('postlog_failure',x) for x in ('pl1.x','pl1.rr','pl1.R','pl1.r\n','',0,False,[],{})]
        changes += [('schema','kubernetes-lens-owned-rootful-result-v6'),('state','source-deployment-positive'),
                    ('kind_create_status',False),('kind_create_status',1),('source_deployment','server-dry-run-observed')]
        for key,altered in changes:
            bad=deepcopy(value); bad[key]=altered
            with self.subTest(key=key,value=altered),self.assertRaises(vm.Refusal):
                rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        bad=deepcopy(value);del bad['postlog_failure']
        with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for key,altered in [('state','direct-wait-zero'),('state','pg1.n'),('startup_marker',False),
                            ('wrapper_observed_child_wait_status',0),('signal_cause','SIGKILL')]:
            bad=deepcopy(value);bad['logs'][key]=altered
            with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for key,altered in [('source_eof',False),('dd_status',1),('tee_status',1),('bytes',16385)]:
            bad=deepcopy(value);bad['logs']['collectors']['out'][key]=altered
            with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for role in rootful.LOG_ROLES_V4:
            bad=deepcopy(value);bad['logs']['identities'][role]=None
            with self.assertRaises(vm.Refusal): rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        _,positive,_=DirectExecDecoderControls.bundle(self,complete=True)
        value['evidence']['files']['node-inspect']=positive['evidence']['files']['node-inspect']
        with self.assertRaisesRegex(vm.Refusal,'rootful-postlog-node-evidence'):
            rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)

    def test_null_and_coded_failure_wire_stays_private(self):
        # Real v5 failures before the new segment still use unchanged v4 log facts.
        for state in ('not-established','pg1.a','pg2.g.native.S.4096.23.1'):
            config,value,_=DirectExecDecoderControls.bundle(self,state=state)
            value.update(schema=rootful.RESULT_V5,postlog_failure=None)
            checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
            self.assertIsNone(checked['postlog_failure'])
            self.assertEqual(checked['logs'],value['logs'])
        for code in (None,'pl1.e'):
            config,value,_=self.bundle(code)
            wire=vm.encode(value)+b'\n'
            with tempfile.TemporaryDirectory(prefix='postlog-private-') as directory:
                parent=Path(directory)
                descriptor=rootful.durable_wire(wire,config,parent,vm.Budget(time.monotonic()+30,10))
                self.assertEqual((parent/descriptor['name']).read_bytes(),wire)
                self.assertNotIn(b'pl1.',vm.encode(descriptor))
                self.assertNotIn(b'postlog_failure',vm.encode(descriptor))


class NativeStatusReceiverControls(unittest.TestCase):
    """Original native/clock/parent-wait source on fixed local DATA only."""
    def fixture(self, *, historical=False):
        fixture=BashProtocolControls(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        source=receiver_before_native_status(receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))))))))) if historical else receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        if getattr(self,"current_v9",False): source=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        fixture.definitions=source.split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={fixture.root} stage={fixture.root}/stage')
        # Preserve original uptime predicate; replace only its input with fixed DATA.
        fixture.definitions=fixture.definitions.replace('read -r UPTIME rest < /proc/uptime',
                                                      'read -r UPTIME rest <<< "$uptime_value"',1)
        fixture.definitions=fixture.definitions.replace('clock_check() {\n', '''clock_check() {
  clock_calls=$((clock_calls+1))
  printf 'clock:%s\\n' "$clock_calls" >> "$root/trace"
  if [[ $clock_calls == 2 ]]; then
    case $scenario in
      after-uptime) uptime_value=bad ;;
      after-deadline) uptime_value=200 ;;
      after-form) printf 'bad 300\\n' > "$root/state/deadlines" ;;
      after-read) clock_path=$root/state/absent ;;
    esac
  fi
''',1)
        a=fixture.definitions.index('clock_check() {');b=fixture.definitions.index('\n}\n',a)
        part=fixture.definitions[a:b].replace('"$root/state/deadlines"','"$clock_path"')
        fixture.definitions=fixture.definitions[:a]+part+fixture.definitions[b:]
        (fixture.root/'state/mode').write_text('work\n')
        (fixture.root/'state/deadlines').write_text('200 300\n')
        segment=source.split('\npostlog_site=n\n',1)[1].split('\npostlog_site=j\n',1)[0]
        segment='postlog_site=n\n'+segment
        command='/usr/bin/podman --remote=false inspect --type=container '
        if not historical: command+="--format '[{{json .}}]' "
        command+='"$node"'
        self.assertEqual(segment.count(command),1)
        segment=segment.replace(command,'fixed_command'+command[len('/usr/bin/podman'):],1)
        self.assertNotIn('/usr/bin/podman',segment)
        return fixture,segment

    def run_case(self, scenario='', *, command=0, stdout=0, stderr=0, historical=False):
        fixture,segment=self.fixture(historical=historical)
        if scenario=='domain':
            fixture.definitions=fixture.definitions.replace('domain=$mode max=70','domain=invalid max=70',1)
        if scenario in ('state-missing','state-link'):
            (fixture.root/'state/mode').unlink()
            if scenario=='state-link': (fixture.root/'state/mode').symlink_to(fixture.root/'absent')
        if scenario in ('deadline-missing','deadline-link'):
            (fixture.root/'state/deadlines').unlink()
            if scenario=='deadline-link': (fixture.root/'state/deadlines').symlink_to(fixture.root/'absent')
        if scenario=='state-value': (fixture.root/'state/mode').write_text('cleanup\n')
        if scenario=='deadline-form': (fixture.root/'state/deadlines').write_text('bad 300\n')
        if scenario=='poison': (fixture.root/'state/poison').write_text('poisoned\n')
        if scenario.startswith('path-'):
            name=scenario[5:];suffix='err' if name.startswith('err') else 'out'
            path=fixture.root/f'captures/work.0.{suffix}'
            if name.endswith('link'): path.symlink_to(fixture.root/'absent')
            else: path.write_text('fixed\n')
        if scenario=='alignment-out': segment=segment.replace('native 16384 4096','native 16385 4096',1)
        if scenario=='alignment-err': segment=segment.replace('native 16384 4096','native 16384 4097',1)
        body=r'''rootful_intent=execution-v1 mode=work node=owned-node
clock_calls=0 clock_path=$root/state/deadlines uptime_value=100 take_calls=0 utility_calls=0
last_tool_status=19 last_stdout_capture_status=23 last_stderr_capture_status=29
postlog_rc=31 postlog_tool=37 postlog_out=41 postlog_err=43 postlog_native=null
trap 'printf "%s\n%s\n" "$postlog_failure" "$postlog_native" > "$root/result"' EXIT
trap 'exit 1' ERR HUP INT TERM
take() {
  printf 'take:%s:%s\n' "$1" "$2" >> "$root/trace"
  [[ $scenario != take-$take_calls ]] || return 1
  token=$take_calls
  take_calls=$((take_calls+1))
}
grant_utility() {
  utility_calls=$((utility_calls+1))
  printf 'grant:%s\n' "$utility_calls" >> "$root/trace"
  [[ $scenario != grant-$utility_calls ]] || return 1
  utility_ticket=utility-work.$utility_calls
}
capture_stream() {
  local line destination=$2
  [[ -z ${stdout_fd:-} ]] || exec {stdout_fd}>&-
  [[ -z ${stderr_fd:-} ]] || exec {stderr_fd}>&-
  exec 3>&-
  while IFS= read -r line; do :; done
  if [[ $destination == *.out ]]; then exit "$stdout_result"; else exit "$stderr_result"; fi
}
fixed_command() {
  printf 'command\n' >> "$root/trace"
  printf 'fixed-local-output\n'
  printf 'fixed-local-error\n' >&2
  return "$command_result"
}
'''+f'scenario={scenario} command_result={command} stdout_result={stdout} stderr_result={stderr}\n'
        if scenario=='uptime': body+='uptime_value=bad\n'
        if scenario=='deadline': body+='uptime_value=200\n'
        if scenario=='stream': body+='stream_logs=1\n'
        result=fixture.child(body+segment+'\n').finish()
        reason,snapshot=(fixture.root/'result').read_text().splitlines()
        trace=(fixture.root/'trace').read_text() if (fixture.root/'trace').exists() else ''
        return result,reason,json.loads(snapshot),trace,fixture

    def test_every_precommand_guard_has_fresh_unavailable_statuses(self):
        scenarios=['domain','uptime','deadline-missing','deadline-link','deadline-form','deadline',
                   'state-missing','state-link','state-value','poison','alignment-out','alignment-err',
                   'path-out','path-out-link','path-err','path-err-link','stream']
        scenarios += ['take-'+str(i) for i in range(8)] + ['grant-'+str(i) for i in range(1,5)]
        unavailable={key:None for key in NativeStatusDecoderControls.KEYS}
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                result,reason,record,trace,_fixture=self.run_case(scenario)
                self.assertEqual((result.returncode,reason,record),(1,'pl1.n',unavailable))
                self.assertNotIn('command\n',trace)

    def test_real_command_and_owned_capture_waits_preserve_old_traces_and_returns(self):
        for command in (0,7,125,255):
            for stdout,stderr in ((0,0),(1,0),(0,255),(1,255)):
                with self.subTest(command=command,stdout=stdout,stderr=stderr):
                    result,reason,record,trace,_fixture=self.run_case(command=command,stdout=stdout,stderr=stderr)
                    old,old_reason,old_record,old_trace,_old=self.run_case(command=command,stdout=stdout,stderr=stderr,historical=True)
                    self.assertEqual((result.returncode,reason,trace),(old.returncode,old_reason,old_trace))
                    self.assertIsNone(old_record)
                    if command==stdout==stderr==0:
                        self.assertEqual((result.returncode,reason,record),(0,'',None))
                    else:
                        returned=125 if stdout or stderr else command
                        self.assertEqual((result.returncode,reason),(1,'pl1.n'))
                        self.assertEqual(record,dict(zip(NativeStatusDecoderControls.KEYS,(returned,command,stdout,stderr))))
                        self.assertTrue((_fixture.root/'state/poison').exists())

    def test_each_final_clock_guard_keeps_obtained_statuses_without_return(self):
        for scenario in ('after-uptime','after-deadline','after-form','after-read'):
            for command in (0,19):
                result,reason,record,trace,_fixture=self.run_case(scenario,command=command)
                self.assertEqual((result.returncode,reason),(1,'pl1.n'))
                self.assertEqual(record,dict(zip(NativeStatusDecoderControls.KEYS,(None,command,0,0))))
                old,old_reason,_unused,old_trace,_old=self.run_case(scenario,command=command,historical=True)
                self.assertEqual((result.returncode,reason,trace),(old.returncode,old_reason,old_trace))

    def test_reset_unexport_partial_interruptions_other_sites_and_first_snapshot(self):
        fixture=BashProtocolControls();fixture.setUp();self.addCleanup(fixture.doCleanups)
        names=('postlog_rc','postlog_tool','postlog_out','postlog_err','postlog_native')
        fixture.definitions='export '+ ' '.join(name+'=99' for name in names)+'\n'+fixture.definitions
        result=fixture.run_body('[[ $postlog_rc == null && $postlog_tool == null && $postlog_out == null && $postlog_err == null && $postlog_native == null ]]\ndeclare -p '+' '.join(names)+'\n')
        self.assertNotIn(b'declare -x',result)
        for action in ('false','kill -TERM "$BASHPID"'):
            for prefix in ('postlog_tool=0','postlog_tool=0 postlog_out=0'):
                f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
                body='''rootful_intent=execution-v1 mode=work postlog_site=n
trap 'printf "%s\n%s\n" "$postlog_failure" "$postlog_native" > "$root/result"' EXIT
trap 'exit 1' ERR HUP INT TERM
'''+prefix+'\n'+action+'\n'
                self.assertEqual(f.child(body).finish().returncode,1)
                self.assertEqual((f.root/'result').read_text(),'\nnull\n')
        for site in ('','r','i','f','j','e'):
            f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
            body='rootful_intent=execution-v1 mode=work postlog_site='+site+'\n'+'postlog_rc=7 postlog_tool=7 postlog_out=0 postlog_err=0\ntrap \'printf "%s" "$postlog_native" > "$root/result"\' EXIT\nfail\n'
            self.assertEqual(f.child(body).finish().returncode,1)
            self.assertEqual((f.root/'result').read_text(),'null')
        f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
        f.definitions=f.definitions.replace('  exit 1\n}', '  return 1\n}',1)
        body='''rootful_intent=execution-v1 mode=work postlog_site=n
postlog_rc=7 postlog_tool=7 postlog_out=0 postlog_err=0
fail || :
first=$postlog_native
postlog_rc=125 postlog_tool=0 postlog_out=1 postlog_err=0
fail || :
[[ $postlog_native == "$first" && $postlog_failure == pl1.n ]]
'''
        f.run_body(body)

    def test_real_finish_cannot_replace_first_snapshot_or_fill_missing(self):
        finish='finish() {\n'+receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('\nfinish() {\n',1)[1].split('\ntrap finish EXIT',1)[0]+'\n'
        expected=dict(zip(NativeStatusDecoderControls.KEYS,(7,7,0,0)))
        for recorded in (False,True):
            f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
            body='''rootful_intent=execution-v1 mode=work postlog_site=n
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=owned
pace_close() { [[ -z $postlog_site ]]; }
remember() { [[ -z $postlog_site ]]; }
native() { [[ -z $postlog_site ]]; last_tool_status=0 last_stdout_capture_status=0 last_stderr_capture_status=0; }
emit_evidence() { evidence_json='{}'; }
emit_logs_evidence() { logs_json='{}'; }
'''
            if recorded: body+='postlog_rc=7 postlog_tool=7 postlog_out=0 postlog_err=0\n'
            action='fail' if recorded else 'exit 7'
            result=f.child(body+finish+"trap finish EXIT\ntrap 'exit 1' ERR HUP INT TERM\n"+action+'\n').finish()
            self.assertEqual(result.returncode,1 if recorded else 7)
            self.assertEqual(json.loads(result.stdout)['postlog_native'],expected if recorded else None)
            # Actual shared cleanup fail cannot fill null or replace the first object.
            f.definitions=f.definitions.replace('  exit 1\n}',
                '  printf "%s" "$postlog_native" > "$root/seen-snapshot"\n  exit 1\n}',1)
            failed=f.child(body+finish+'native() { [[ -z $postlog_site ]]; fail; }\n'+
                "trap finish EXIT\ntrap 'exit 1' ERR HUP INT TERM\n"+action+'\n').finish()
            self.assertEqual(failed.returncode,1)
            self.assertEqual(json.loads((f.root/'seen-snapshot').read_text()),expected if recorded else None)

    def test_exact_v6_inverse_preserves_frozen_v5_and_rejects_any_source_mutation(self):
        import hashlib
        current=receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))))))));old=receiver_before_native_status(current)
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),(POSTLOG_SOURCE_BYTES,POSTLOG_SOURCE))
        self.assertLessEqual(len(current.encode())-len(old.encode()),1200)
        self.assertLessEqual(len(current.encode()),65158)
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        for a,b in [('postlog_rc=null postlog_tool=null','postlog_rc=0 postlog_tool=null'),
                    ('postlog_tool=$last_tool_status','postlog_tool=0'),('maximum=680','maximum=681')]:
            with self.assertRaises(AssertionError):receiver_before_native_status(current.replace(a,b,1))
        with self.assertRaises(AssertionError):receiver_before_native_status(old)
        with self.assertRaises(AssertionError):receiver_before_postlog(current)


class NativeStatusDecoderControls(unittest.TestCase):
    KEYS=('return_status','command_status','stdout_capture_status','stderr_capture_status')

    def bundle(self, statuses=(None,None,None,None), *, code='pl1.n'):
        config,value,raw=PostlogDecoderControls.bundle(self,code)
        value.update(schema=rootful.RESULT_V6,postlog_native=dict(zip(NativeStatusDecoderControls.KEYS,statuses)) if code=='pl1.n' else None)
        return config,value,raw

    def test_all_available_forms_endpoints_and_private_retention(self):
        forms=[(None,None,None,None)]
        forms += [(None,command,0,0) for command in (0,1,125,255)]
        forms += [(command,command,0,0) for command in (1,125,255)]
        forms += [(125,command,stdout,stderr) for command in (0,1,125,255)
                  for stdout,stderr in ((1,0),(0,255),(1,255))]
        for form in forms:
            config,value,_raw=self.bundle(form)
            checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
            self.assertEqual(checked['postlog_native'],dict(zip(self.KEYS,form)))
            self.assertEqual(checked['logs'],value['logs'])
        config,value,_raw=self.bundle((125,0,1,0))
        wire=vm.encode(value)+b'\n'
        with tempfile.TemporaryDirectory(prefix='native-status-private-') as directory:
            parent=Path(directory)
            descriptor=rootful.durable_wire(wire,config,parent,vm.Budget(time.monotonic()+30,10))
            self.assertEqual((parent/descriptor['name']).read_bytes(),wire)
            for protected in (b'postlog_native',b'command_status',b'capture_status',b'pl1.n'):
                self.assertNotIn(protected,vm.encode(descriptor))

    def test_status_types_partial_triples_and_impossible_relations_refuse(self):
        config,value,_raw=self.bundle((7,7,0,0))
        mutations=[]
        for key in self.KEYS:
            for status in (False,True,-1,256,0.0,'0',[],{}):
                bad=deepcopy(value);bad['postlog_native'][key]=status;mutations.append(bad)
        for form in ((0,0,0,0),(7,None,None,None),(None,0,None,None),(None,None,0,0),
                     (None,0,1,0),(None,0,0,1),(7,0,0,0),(1,0,1,0),(125,0,0,0)):
            bad=deepcopy(value);bad['postlog_native']=dict(zip(self.KEYS,form));mutations.append(bad)
        for altered in (None,False,[],{},'unavailable'):
            bad=deepcopy(value);bad['postlog_native']=altered;mutations.append(bad)
        for key in self.KEYS:
            bad=deepcopy(value);del bad['postlog_native'][key];mutations.append(bad)
        bad=deepcopy(value);bad['postlog_native']['extra']=0;mutations.append(bad)
        bad=deepcopy(value);del bad['postlog_native'];mutations.append(bad)
        for bad in mutations:
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)

    def test_null_other_sites_scope_logs_catalogue_success_and_future_v7(self):
        for code in (None,'pl1.r','pl1.i','pl1.f','pl1.j','pl1.e'):
            config,value,_raw=self.bundle(code=code)
            self.assertIsNone(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)['postlog_native'])
            value['postlog_native']=dict(zip(self.KEYS,(None,None,None,None)))
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
        config,value,_raw=self.bundle()
        for field,altered in [('state','source-deployment-positive'),('kind_create_status',False),
                              ('kind_create_status',1),('source_deployment','server-dry-run-observed'),
                              ('schema','kubernetes-lens-owned-rootful-result-v7')]:
            bad=deepcopy(value);bad[field]=altered
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for field,altered in [('startup_marker',False),('wrapper_observed_child_wait_status',0),
                              ('state','direct-wait-zero'),('state','pg1.n')]:
            bad=deepcopy(value);bad['logs'][field]=altered
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        _,positive,_=DirectExecDecoderControls.bundle(self,complete=True)
        bad=deepcopy(value);bad['evidence']['files']['node-inspect']=positive['evidence']['files']['node-inspect']
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        positive.update(schema=rootful.RESULT_V6,postlog_failure=None,postlog_native=None)
        self.assertIsNone(rootful.wire_record(vm.encode(positive)+b'\n',config)['postlog_native'])
        positive['postlog_native']=dict(zip(self.KEYS,(None,None,None,None)))
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(positive)+b'\n',config)

    def test_v1_v5_schemas_never_gain_status_member(self):
        for version in (rootful.RESULT_V1,rootful.RESULT_V2,rootful.RESULT_V3,rootful.RESULT_V4,rootful.RESULT_V5):
            if version==rootful.RESULT_V5: config,value,_raw=PostlogDecoderControls.bundle(self)
            elif version==rootful.RESULT_V4: config,value,_raw=DirectExecDecoderControls.bundle(self,complete=True)
            else: config,value,_raw=DurableEvidenceControls.bundle(self);value['schema']=version
            checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
            self.assertNotIn('postlog_native',checked)
            value['postlog_native']=None
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)


class ResourceReasonReceiverControls(unittest.TestCase):
    REASONS=('block','filesystem','inv-drift','inv-empty','inv-fd-access','inv-fd-form','inv-fd-range',
             'inv-nf-form','inv-nf-range','inv-pid-range','inv-proc-form','inv-proc-pid','inv-proc-read',
             'inv-proc-task','inv-snap-size','inv-task-empty','inv-task-form','inv-task-read','inv-task-tid',
             'inv-tid-count','mapper','memory','mount','mount-both','mount-proc','mount-root','namespace',
             'nr-open-form','nr-open-range','pid-max')

    def fixture(self, *, historical=False):
        f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
        if historical:
            f.definitions=receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))))))).split('# Entry: pure-control tests')[0].replace(
                'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
                f'readonly root={f.root} stage={f.root}/stage')
        return f

    def prefix(self, site='r'):
        return '''rootful_intent=execution-v1 mode=work
postlog_reason=null
trap 'printf "%s\n%s\n" "$postlog_failure" "$postlog_reason" > "$root/reason"' EXIT
trap 'exit 1' ERR HUP INT TERM
'''+f'postlog_site={site}\n'

    def test_all_thirty_original_labels_preserve_old_failure_behavior(self):
        import re
        labels=[];source=receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))))))))
        for name in ('resource_check','inventory'):
            body=source.split(name+'() {\n',1)[1].split('\n}',1)[0]
            labels+=re.findall(r'\bfail[ \t]+([a-z][a-z0-9-]*)(?=[ \t;\n]|$)',body)
        self.assertEqual(set(labels),set(self.REASONS))
        self.assertEqual(rootful.POSTLOG_REASONS,set(self.REASONS)|{'unlabelled'})
        for reason in self.REASONS:
            results=[]
            for historical in (True,False):
                f=self.fixture(historical=historical)
                result=f.child(self.prefix()+'fail '+reason+'\n').finish()
                code,record=(f.root/'reason').read_text().splitlines()
                self.assertEqual((result.returncode,code),(1,'pl1.r'))
                self.assertEqual(json.loads(record),None if historical else reason)
                self.assertTrue((f.root/'state/poison').exists())
                results.append((result.returncode,result.stdout,result.stderr))
            self.assertEqual(results[0],results[1])

    def test_unlabelled_empty_unknown_and_arbitrary_args_never_escape(self):
        cases=['',"''", "'arbitrary-private-value'", "'inv-private-value'", "'pid-max-private-value'",
               "'pid-max\nprivate-value'", "'\"private-json\"'", "'memory' 'arbitrary-private-value'"]
        for arguments in cases:
            f=self.fixture();result=f.child(self.prefix()+'postlog_reason=\'"mapper"\'\nfail '+arguments+'\n').finish()
            code,record=(f.root/'reason').read_text().splitlines()
            self.assertEqual((result.returncode,code),(1,'pl1.r'))
            self.assertEqual(json.loads(record),'memory' if arguments.startswith("'memory'") else 'unlabelled')
            for protected in (b'arbitrary-private-value',b'inv-private-value',b'pid-max-private-value',b'private-json'):
                self.assertNotIn(protected,result.stdout+result.stderr+(f.root/'reason').read_bytes())

    def test_original_resource_predicates_and_parent_label_after_child_helper_failure(self):
        for pid,opened,expected in [('1','1','pid-max'),('32768','bad','nr-open-form'),
                                    ('32768','0','nr-open-range'),('32768','1',None)]:
            traces=[]
            for historical in (True,False):
                f=self.fixture(historical=historical)
                source=receiver_before_resource_reason(receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))))))) if historical else receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
                body=source.split('resource_check() {\n',1)[1].split('  namespace=$(u ',1)[0]
                body=body.replace('read -r value < /proc/sys/kernel/pid_max','printf "pid\\n" >> "$root/trace"\n  read -r value <<< "$pid_value"')
                body=body.replace('read -r value < /proc/sys/fs/nr_open','printf "open\\n" >> "$root/trace"\n  read -r value <<< "$open_value"')
                program=self.prefix()+f'pid_value={pid} open_value={opened}\nresource_check() {{\n'+body+'\n}\nresource_check\n'
                result=f.child(program).finish();code,record=(f.root/'reason').read_text().splitlines()
                self.assertEqual(result.returncode,1 if expected else 0)
                self.assertEqual(code,'pl1.r' if expected else '')
                self.assertEqual(json.loads(record),expected if not historical else None)
                traces.append((f.root/'trace').read_text())
            self.assertEqual(*traces)
        original=receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))).split('resource_check() {\n',1)[1]
        first=next(line.strip() for line in original.splitlines() if line.strip().startswith('namespace=$(u '))
        second=next(line.strip() for line in original.splitlines() if line.strip().startswith('value=$(u /usr/bin/stat -Lc'))
        for statement,reason in ((first,'unlabelled'),(second,'namespace')):
            for helper in ('u() { fail arbitrary-private-child; }','grant_utility() { return 1; }'):
                f=self.fixture()
                result=f.child(self.prefix()+helper+'\n'+statement+'\n').finish()
                code,record=(f.root/'reason').read_text().splitlines()
                self.assertEqual((result.returncode,code,json.loads(record)),(1,'pl1.r',reason))
                self.assertNotIn(b'arbitrary-private-child',result.stdout+result.stderr+(f.root/'reason').read_bytes())

    def test_scope_subshell_err_signal_reset_and_first_reason_immutability(self):
        f=self.fixture();f.definitions="export postlog_reason='arbitrary-private-value'\n"+f.definitions
        self.assertNotIn(b'declare -x',f.run_body('[[ $postlog_reason == null ]]\ndeclare -p postlog_reason\n'))
        for site in ('','i','f','n','j','e'):
            f=self.fixture();result=f.child(self.prefix(site)+'fail pid-max\n').finish()
            self.assertEqual(result.returncode,1)
            self.assertIsNone(json.loads((f.root/'reason').read_text().splitlines()[1]))
        for setup,action in [('', ':'),('', '(fail pid-max) || :'),('', 'false'),('', 'kill -TERM "$BASHPID"'),
                             ('mode=cleanup','fail pid-max'),('rootful_admitted=0','fail pid-max'),
                             ('rootful_intent=prerequisite-v1','fail pid-max')]:
            f=self.fixture();f.child(self.prefix()+setup+'\n'+action+'\n').finish()
            code,record=(f.root/'reason').read_text().splitlines()
            self.assertEqual((code,json.loads(record)),('',None),(setup,action))
        f=self.fixture();f.definitions=f.definitions.replace('  exit 1\n}','  return 1\n}',1)
        f.run_body(self.prefix()+'''fail memory || :
first=$postlog_reason
fail pid-max || :
[[ $postlog_failure == pl1.r && $postlog_reason == "$first" && $postlog_reason == '"memory"' ]]
''')

    def test_actual_finish_preserves_reason_and_unknown_status_before_cleanup_failure(self):
        finish='finish() {\n'+receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('\nfinish() {\n',1)[1].split('\ntrap finish EXIT',1)[0]+'\n'
        for recorded in (False,True):
            f=self.fixture()
            body='''rootful_intent=execution-v1 mode=work postlog_site=r
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=owned
pace_close() { [[ -z $postlog_site ]]; }
remember() { [[ -z $postlog_site ]]; }
native() { [[ -z $postlog_site ]]; last_tool_status=0; }
emit_evidence() { evidence_json='{}'; }
emit_logs_evidence() { logs_json='{}'; }
'''+finish+"trap finish EXIT\ntrap 'exit 1' ERR HUP INT TERM\n"
            action='fail memory' if recorded else 'exit 7'
            result=f.child(body+action+'\n').finish()
            self.assertEqual(result.returncode,1 if recorded else 7)
            wire=json.loads(result.stdout);self.assertEqual(wire['postlog_reason'],'memory' if recorded else None)
            self.assertIsNone(wire['postlog_native'])
            f.definitions=f.definitions.replace('  exit 1\n}',
                '  printf "%s" "$postlog_reason" > "$root/seen-reason"\n  exit 1\n}',1)
            failed=f.child(body+'native() { [[ -z $postlog_site ]]; fail pid-max; }\n'+action+'\n').finish()
            self.assertEqual(failed.returncode,1)
            self.assertEqual(json.loads((f.root/'seen-reason').read_text()),'memory' if recorded else None)

    def test_exact_v7_inverse_budget_and_unchanged_external_command_paths(self):
        import hashlib,re
        current=receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))))));old=receiver_before_resource_reason(current)
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),(NATIVE_STATUS_SOURCE_BYTES,NATIVE_STATUS_SOURCE))
        self.assertLessEqual(len(current.encode())-len(old.encode()),800);self.assertLessEqual(len(current.encode()),65408)
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        paths=lambda s:re.findall(r'/usr/[A-Za-z0-9_./-]+',s)
        self.assertEqual(paths(old),paths(current))
        for a,b in [('postlog_reason=null','postlog_reason=memory'),("postlog_reason='\"unlabelled\"'","postlog_reason='\"memory\"'"),
                    ('maximum=680','maximum=681')]:
            with self.assertRaises(AssertionError):receiver_before_resource_reason(current.replace(a,b,1))
        with self.assertRaises(AssertionError):receiver_before_resource_reason(old)
        with self.assertRaises(AssertionError):receiver_before_native_status(current)


class ResourceReasonDecoderControls(unittest.TestCase):
    def bundle(self, reason='pid-max', *, code='pl1.r'):
        config,value,raw=NativeStatusDecoderControls.bundle(self,code=code)
        value.update(schema=rootful.RESULT_V7,postlog_reason=reason if code=='pl1.r' else None)
        return config,value,raw

    def test_all_fixed_labels_unlabelled_and_delete_failure_stay_private_failed(self):
        for reason in (*ResourceReasonReceiverControls.REASONS,'unlabelled'):
            config,value,_=self.bundle(reason)
            for delete in (0,19):
                value['kind_delete_status']=delete
                checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
                self.assertEqual(checked['postlog_reason'],reason);self.assertIsNone(checked['postlog_native'])
                self.assertEqual(checked['logs'],value['logs']);self.assertEqual(checked['kind_delete_status'],delete)
                with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config)

    def test_malformed_types_scopes_logs_catalogue_and_future_v8_refuse(self):
        config,value,_=self.bundle()
        for reason in (None,False,True,0,0.0,[],{},'','private-value','inv-private','PID-MAX','pid-max\nprivate'):
            bad=deepcopy(value);bad['postlog_reason']=reason
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        bad=deepcopy(value);del bad['postlog_reason']
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        # Keep the registered predecessor ID; explicit V8 now makes V9 the future negative.
        for field,altered in [('state','source-deployment-positive'),('kind_create_status',False),('kind_create_status',1),
                              ('source_deployment','server-dry-run-observed'),('schema','kubernetes-lens-owned-rootful-result-v12')]:
            bad=deepcopy(value);bad[field]=altered
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for field,altered in [('startup_marker',False),('state','direct-wait-zero'),('state','pg1.n'),('wrapper_observed_child_wait_status',0)]:
            bad=deepcopy(value);bad['logs'][field]=altered
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        _,positive,_=DirectExecDecoderControls.bundle(self,complete=True)
        bad=deepcopy(value);bad['evidence']['files']['node-inspect']=positive['evidence']['files']['node-inspect']
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)

    def test_null_other_scopes_success_and_v6_native_status_meaning_unchanged(self):
        for code in (None,'pl1.i','pl1.f','pl1.n','pl1.j','pl1.e'):
            config,value,_=self.bundle(code=code)
            checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
            self.assertIsNone(checked['postlog_reason'])
            self.assertEqual(checked['postlog_native'],value['postlog_native'])
            value['postlog_reason']='pid-max'
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
        config,positive,_=DirectExecDecoderControls.bundle(self,complete=True)
        positive.update(schema=rootful.RESULT_V7,postlog_failure=None,postlog_native=None,postlog_reason=None)
        self.assertIsNone(rootful.wire_record(vm.encode(positive)+b'\n',config)['postlog_reason'])
        positive['postlog_reason']='memory'
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(positive)+b'\n',config)
        for form in ((None,None,None,None),(None,19,0,0),(7,7,0,0),(125,0,1,0)):
            config,value,_=NativeStatusDecoderControls.bundle(self,form)
            value.update(schema=rootful.RESULT_V7,postlog_reason=None)
            self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)['postlog_native'],value['postlog_native'])

    def test_v1_v6_schemas_and_durable_private_wire_without_public_reason(self):
        for version in (rootful.RESULT_V1,rootful.RESULT_V2,rootful.RESULT_V3,rootful.RESULT_V4,rootful.RESULT_V5,rootful.RESULT_V6):
            if version==rootful.RESULT_V6:config,value,_=NativeStatusDecoderControls.bundle(self)
            elif version==rootful.RESULT_V5:config,value,_=PostlogDecoderControls.bundle(self)
            elif version==rootful.RESULT_V4:config,value,_=DirectExecDecoderControls.bundle(self,complete=True)
            else:config,value,_=DurableEvidenceControls.bundle(self);value['schema']=version
            self.assertNotIn('postlog_reason',rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True))
            value['postlog_reason']=None
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
        for reason in ('pid-max','unlabelled','inv-task-empty'):
            config,value,_=self.bundle(reason);wire=vm.encode(value)+b'\n'
            with tempfile.TemporaryDirectory(prefix='resource-reason-private-') as directory:
                parent=Path(directory);descriptor=rootful.durable_wire(wire,config,parent,vm.Budget(time.monotonic()+30,10))
                self.assertEqual((parent/descriptor['name']).read_bytes(),wire)
                self.assertNotIn(b'postlog_reason',vm.encode(descriptor));self.assertNotIn(reason.encode(),vm.encode(descriptor))


class CompactInspectControls(unittest.TestCase):
    @staticmethod
    def replace_node(value,raw):
        value['evidence']['files']['node-inspect']={'bytes':len(raw),'sha256':vm.digest(raw),
            'base64':base64.b64encode(raw).decode('ascii')}

    def bundle(self, *, compact=True):
        config,value,_=DirectExecDecoderControls.bundle(self,complete=True)
        value.update(schema=rootful.RESULT_V7,postlog_failure=None,postlog_native=None,postlog_reason=None)
        row=vm.strict_json(base64.b64decode(value['evidence']['files']['node-inspect']['base64']))[0]
        row['NetworkSettings']['Ports']={'6443/tcp':[{'HostIp':'127.0.0.1','HostPort':'6443'}]}
        row['SyntheticProtectedExtension']={'Env':['SYNTHETIC_ONLY=private-placeholder'],
            'nested':{'null':None,'empty_list':[],'empty_map':{},'bool':True,'integer':2**63-1},
            'escapes':'quote" newline\n backslash\\ <html> & unicode:☃'}
        rows=[row]
        raw=(('['+json.dumps(row,ensure_ascii=False,separators=(',',':'))+']')if compact
             else json.dumps(rows,ensure_ascii=False,indent=5))+'\n'
        CompactInspectControls.replace_node(value,raw.encode())
        return config,value,rows

    def test_only_current_n_argument_changes_twentyfour_bytes_and_old_v7_stays_exact(self):
        import hashlib
        current=receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))))));old=receiver_before_compact_inspect(current)
        old_line='native 16384 4096 /usr/bin/podman --remote=false inspect --type=container "$node" || {'
        new_line='native 16384 4096 /usr/bin/podman --remote=false inspect --type=container --format \'[{{json .}}]\' "$node" || {'
        self.assertEqual(old.count(old_line),1);self.assertEqual(current,old.replace(old_line,new_line,1))
        self.assertEqual(len(current.encode())-len(old.encode()),24);self.assertLessEqual(len(current.encode()),65408)
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),(RESOURCE_REASON_SOURCE_BYTES,RESOURCE_REASON_SOURCE))
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        self.assertEqual(new_line.count('"$node"'),1)
        for flag in ('--all','--latest','--size'):self.assertNotIn(flag,new_line)
        for first,second in [("'[{{json .}}]'","'{{json .}}'"),("'[{{json .}}]'","'[{{json .Name}}]'"),
                             ('native 16384 4096','native 32768 4096'),('maximum=680','maximum=681')]:
            with self.assertRaises(AssertionError):receiver_before_compact_inspect(current.replace(first,second,1))
        with self.assertRaises(AssertionError):receiver_before_compact_inspect(old)
        with self.assertRaises(AssertionError):receiver_before_resource_reason(current)

    def test_synthetic_pretty_and_compact_preserve_all_values_arrays_and_escapes(self):
        # JSON-model evidence only; this does not execute or emulate Podman's Go code.
        config,compact,rows=self.bundle();_config,pretty,pretty_rows=self.bundle(compact=False)
        raw=base64.b64decode(compact['evidence']['files']['node-inspect']['base64'])
        default=base64.b64decode(pretty['evidence']['files']['node-inspect']['base64'])
        self.assertEqual(rows,pretty_rows);self.assertEqual(vm.strict_json(raw),vm.strict_json(default))
        self.assertEqual(len(vm.strict_json(raw)),1);self.assertEqual(vm.strict_json(raw),rows)
        self.assertLess(len(raw),len(default));self.assertIn(b'\\n',raw);self.assertIn(b'\\"',raw)
        self.assertIn('☃'.encode(),raw);self.assertIn(b'<html>',raw)
        self.assertEqual(vm.strict_json(raw)[0]['SyntheticProtectedExtension']['nested']['integer'],2**63-1)
        self.assertTrue(raw.startswith(b'[{')and raw.endswith(b'}]\n'))
        # Both byte presentations enter the unchanged real host semantic decoder.
        for value in (pretty,compact):
            checked=rootful.wire_record(vm.encode(value)+b'\n',config)
            self.assertEqual(checked['schema'],rootful.RESULT_V7)
            self.assertEqual(checked['state'],'source-deployment-positive')
            self.assertIsNone(checked['postlog_native']);self.assertIsNone(checked['postlog_reason'])

    def test_empty_encoding_object_multiple_roots_malformed_and_wrong_semantics_refuse(self):
        config,value,rows=self.bundle();good=base64.b64decode(value['evidence']['files']['node-inspect']['base64'])
        variants=[b'[]\n',b'['+b''+b']\n',vm.encode(rows[0])+b'\n',good+good,vm.encode(rows+rows)+b'\n',b'[{bad}]\n']
        for raw in variants:
            bad=deepcopy(value);self.replace_node(bad,raw)
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config)
        for field,altered in [('Id','not-an-id'),('Image','f'*64),('Name','foreign-node')]:
            changed=deepcopy(rows);changed[0][field]=altered;bad=deepcopy(value);self.replace_node(bad,vm.encode(changed))
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config)
        for mutate in (lambda row:row['State'].update(Running=False),lambda row:row['State'].update(Pid=True),
                       lambda row:row['Config'].update(CreateCommand=['wrong-image']),
                       lambda row:row['NetworkSettings'].update(Networks={})):
            changed=deepcopy(rows);mutate(changed[0]);bad=deepcopy(value);self.replace_node(bad,vm.encode(changed))
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config)
        # The actual Bash jq/length1/identity/state/args/ports expression is byte-unchanged.
        old=receiver_before_compact_inspect(receiver_before_postnode(receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))))));current=receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))
        jq=lambda source:source.split('postlog_site=j\n',1)[1].split('remember node-inspect',1)[0]
        self.assertEqual(jq(current),jq(old))
        for required in ('length==1','.[0].Id==$id','.[0].Image==$image','.[0].Name==$node',
                         '.[0].State.Running==true','.[0].Config.CreateCommand','.[0].NetworkSettings.Ports'):
            self.assertIn(required,jq(current))

    def test_original_capture_bound_and_nonoverflow_failures_remain_refusals(self):
        # Original helper with only its existing utility launcher replaced by fixed DATA.
        cases=[(16384,'16384',0,0,0),(16385,'16385',0,0,1),(4,'4',1,0,1),
               (4,'4',0,1,1),(4,'not-a-size',0,0,1)]
        for produced,size_value,dd_rc,stat_rc,expected in cases:
            f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
            body='''utility_launch() {
  shift
  if [[ $1 == /usr/bin/dd ]]; then
    local fixed
    printf -v fixed '%*s' "$produced" ''
    printf '%s' "$fixed"
    return "$dd_rc"
  fi
  [[ $1 == /usr/bin/stat ]] || return 1
  printf '%s\n' "$size_value"
  return "$stat_rc"
}
'''+f"produced={produced} size_value='{size_value}' dd_rc={dd_rc} stat_rc={stat_rc}\n"+'''rc=0
capture_stream 16384 "$root/capture" fixed-dd fixed-stat || rc=$?
printf '%s\n' "$rc"
'''
            result=f.child(body).finish();self.assertEqual(result.returncode,0);self.assertEqual(int(result.stdout),expected)
            self.assertEqual((f.root/'capture').stat().st_size,produced)
        # Identical helper1 can result from small output, so it is never overflow proof.

    def test_current_and_historical_native_projections_cannot_invoke_real_podman(self):
        for historical in (False,True):
            fixture,segment=NativeStatusReceiverControls.fixture(self,historical=historical)
            self.assertNotIn('/usr/bin/podman',segment);self.assertIn('fixed_command --remote=false inspect',segment)
            self.assertEqual("--format '[{{json .}}]'"in segment,not historical)

    def test_compact_private_durability_preserves_actual_bytes_without_public_content(self):
        config,value,_=self.bundle();wire=vm.encode(value)+b'\n'
        with tempfile.TemporaryDirectory(prefix='compact-private-')as directory:
            parent=Path(directory);descriptor=rootful.durable_wire(wire,config,parent,vm.Budget(time.monotonic()+30,10))
            self.assertEqual((parent/descriptor['name']).read_bytes(),wire)
            self.assertIn('node-inspect',descriptor['catalogue']['files'])
            for protected in (b'SYNTHETIC_ONLY',b'private-placeholder',b'SyntheticProtectedExtension'):
                self.assertNotIn(protected,vm.encode(descriptor))



class PostnodeReceiverControls(unittest.TestCase):
    """Original post-node statements with only fixed builtin helper doubles."""
    def fixture(self):
        fixture=BashProtocolControls();fixture.setUp();self.addCleanup(fixture.doCleanups)
        return fixture

    def segment(self,source):
        anchor='remember node-inspect "$out"\n'
        self.assertEqual(source.count(anchor),1)
        segment=source.split(anchor,1)[1]
        self.assertTrue(segment.endswith('source_status=server-dry-run-observed\nexit 0\n'))
        self.assertNotIn('/usr/bin/podman',segment)
        self.assertNotIn('utility_launch',segment)
        self.assertEqual(segment.count('read_file '),4)
        self.assertEqual(segment.count('native '),6)
        return segment

    def setup_actions(self,bad=''):
        # Every apparent /proc read and runtime argv below is DATA to a fake.
        # All helpers are replaced before the original segment can run.
        return r"""rootful_intent=execution-v1 mode=work postlog_site=''
node_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
node=owned-node cluster=owned patch=1.20.15
KUBECONFIG=$root/kubeconfig fixture_sha=fixed-sha out=$captures/work.1.out
declare -A INVENTORY_START=([123]=456)
stat_reads=0
u() {
  printf 'u:%s\n' "$*" >> "$root/trace"
  case "$*" in
    *State.CgroupPath*)
      [[ $bad != a-helper ]] || fail
      [[ $bad != a-query ]]
      ;;
    *State.Pid*)
      [[ $bad != b-helper ]] || fail
      [[ $bad != b-query ]] || return 9
      case $bad in b-form) printf 0123 ;; b-range) printf 32768 ;; *) printf 123 ;; esac
      ;;
    *current-context*) [[ $bad != k-config ]] ;;
    *sha256sum*)
      [[ $bad != k-fixture-helper ]] || fail
      [[ $bad != k-fixture ]] || { printf wrong; return; }
      printf '%s  %s' "$fixture_sha" "$root/deployment.json"
      ;;
    *apiVersion*) [[ $bad != k-result ]] ;;
    *) return 0 ;;
  esac
}
read_file() {
  printf 'read:%s\n' "$1" >> "$root/trace"
  case $1 in
    /proc/123/stat)
      stat_reads=$((stat_reads + 1))
      if ((stat_reads == 1)); then
        [[ $bad != d-read ]] || fail
        local first=123 start=456
        [[ $bad != d-pid ]] || first=124
        [[ $bad != d-start ]] || start=457
      else
        [[ $bad != h-read ]] || fail
        local first=123 start=456
        [[ $bad != h-start ]] || start=457
      fi
      printf -v REPLY '%s (fixed DATA) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 %s' "$first" "$start"
      ;;
    /proc/123/cgroup)
      [[ $bad != g-read ]] || fail
      REPLY=0::$node_cgroup
      [[ $bad != g-match ]] || REPLY=wrong
      ;;
    "$out")
      [[ $bad != k-read ]] || fail
      REPLY=ok
      ;;
    *) exit 88 ;;
  esac
}
native() {
  printf 'native:%s\n' "$*" >> "$root/trace"
  case "$*" in
    *'config view'*) [[ $bad != k-native ]] ;;
    *--raw=/readyz*) [[ $bad != k-readiness ]] ;;
    *'create namespace'*) [[ $bad != k-namespace ]] ;;
    *--dry-run=server*) [[ $bad != k-dry-run ]] ;;
    *) return 0 ;;
  esac
}
""" + 'bad='+bad+'\n' + (
            'unset "INVENTORY_START[123]"\n' if bad=='c-missing' else
            'INVENTORY_START[123]=not-decimal\n' if bad=='c-form' else '')

    def test_seven_groups_keep_original_query_read_return_and_poison_traces(self):
        current=receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))));old=receiver_before_postnode(receiver_before_live_census(current))
        cases=[('',None),('a-query','a'),('a-helper','a'),('b-query','b'),('b-helper','b'),
               ('b-form','b'),('b-range','b'),('c-missing','c'),('c-form','c'),
               ('d-read','d'),('d-pid','d'),('d-start','d'),('g-read','g'),('g-match','g'),
               ('h-read','h'),('h-start','h'),('k-native','k'),('k-config','k'),
               ('k-readiness','k'),('k-read','k'),('k-namespace','k'),('k-fixture','k'),
               ('k-fixture-helper','k'),('k-dry-run','k'),('k-result','k')]
        for bad,site in cases:
            traces=[]
            for source in (old,current):
                with self.subTest(bad=bad,current=source==current):
                    f=self.fixture()
                    body=self.setup_actions(bad)+"trap 'printf \"%s\" \"$postlog_failure\" > \"$root/reason\"' EXIT\n"+self.segment(source)
                    result=f.child(body).finish()
                    self.assertEqual((result.returncode,result.stdout),(1 if site else 0,b''),result.stderr)
                    self.assertEqual((f.root/'reason').read_text(),'pl2.'+site if site and source==current else '')
                    self.assertEqual((f.root/'state/poison').exists(),site is not None)
                    traces.append((f.root/'trace').read_text().replace(str(f.root),'ROOT'))
            self.assertEqual(traces[0],traces[1],bad)
        # Strip only the seven new assignments: no original action or guard moves.
        new=self.segment(current)
        for site in 'abcdghk':
            self.assertEqual(new.count('postlog_site='+site+'\n'),1)
            new=new.replace('postlog_site='+site+'\n',"postlog_site=''\n" if site=='a' else '',1)
        self.assertEqual(new,self.segment(old))

    def test_entry_child_implicit_err_signal_scope_and_first_parent_are_separate(self):
        for site in 'abcdghk':
            cases=[(':','', ''),('(fail) || :','', ''),('value=$(fail) || :','', ''),
                   ('false','', ''),('kill -TERM "$BASHPID"','', ''),
                   ('(fail) || fail','', 'pl2.'+site),('fail','mode=cleanup', ''),
                   ('fail','rootful_admitted=0', ''),('fail','rootful_intent=prerequisite-v1', ''),
                   ('fail','postlog_failure=pl1.i', 'pl1.i'),
                   ('fail','postlog_failure=pl2.a', 'pl2.a')]
            for action,setup,expected in cases:
                with self.subTest(site=site,action=action,setup=setup):
                    f=self.fixture()
                    body=f'rootful_intent=execution-v1 mode=work postlog_site={site}\n'+setup+'\n'+r"""trap 'exit 1' ERR HUP INT TERM
trap 'printf "%s" "$postlog_failure" > "$root/reason"' EXIT
"""+action+'\n'
                    f.child(body).finish()
                    self.assertEqual((f.root/'reason').read_text(),expected)

    def test_actual_bash_single_byte_recorder_and_emitter_sets_are_closed(self):
        source=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        recorder=next(line.strip() for line in source.splitlines() if 'case $postlog_site in' in line)
        emitter=next(line.strip() for line in source.splitlines() if 'case $postlog_failure in' in line)
        self.assertEqual(source.count(recorder),1);self.assertEqual(source.count(emitter),1)
        values=[(bytes([i]), 'pl1.'+chr(i) if chr(i) in 'rifnje' else
                 'pl2.'+chr(i) if chr(i) in 'abcdghk' else '') for i in range(1,256)]
        self.assertEqual(len({raw for raw,_ in values}),255)
        literal=lambda raw:"$'"+''.join('\\x%02x'%byte for byte in raw)+"'"
        commands=[]
        for raw,expected in values:
            commands.append('postlog_failure= postlog_site='+literal(raw)+'\n'+
                '[[ ${#postlog_site} == 1 ]] || exit 83\n'+
                "printf -v actual '%d' \"'$postlog_site\"\n"+
                '[[ $actual == '+str(raw[0])+' ]] || exit 84\n'+recorder+
                '\n[[ $postlog_failure == '+repr(expected)+' ]] || exit 81\n')
        codes=['pl1.'+c for c in 'rifnje']+['pl2.'+c for c in 'abcdghk']
        inputs=[prefix+raw for prefix in (b'pl1.',b'pl2.') for raw,_ in values]
        inputs += [code.encode()+suffix for code in codes for suffix in (b'x',b'\n')]
        inputs += [b'',b'pl1.',b'pl2.',b'pl2.aa',b'pl2.A',b'pl2.e',b'pl2.f',b'pl2.j']
        for raw in inputs:
            expected='"'+raw.decode('ascii')+'"' if raw in [c.encode() for c in codes] else 'null'
            commands.append('postlog_json=null postlog_failure='+literal(raw)+'\n'+emitter+
                '\n[[ $postlog_json == '+repr(expected)+' ]] || exit 82\n')
        f=self.fixture();self.assertEqual(f.run_body('LC_ALL=C\n'+''.join(commands)+"printf 'closed\\n'\n"),b'closed\n')

    def test_real_finish_keeps_status_and_clears_site_before_cleanup_without_new_code(self):
        original=receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))).split('\nfinish() {\n',1)[1].split('\ntrap finish EXIT',1)[0]
        self.assertTrue(original.startswith('  local status=$? '))
        self.assertLess(original.index("postlog_site=''"),original.index('trap - EXIT'))
        finish='finish() {\n'+original+'\n'
        setup=r"""rootful_intent=execution-v1 mode=work postlog_site=k
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=owned
pace_close() { [[ -z $postlog_site ]]; printf 'pace\n' >> "$root/order"; }
remember() { [[ -z $postlog_site ]]; printf 'diagnose\n' >> "$root/order"; }
native() { [[ -z $postlog_site ]]; printf 'native\n' >> "$root/order"; last_tool_status=0; }
emit_evidence() { [[ -z $postlog_site ]]; printf 'evidence\n' >> "$root/order"; evidence_json='{}'; }
emit_logs_evidence() { [[ -z $postlog_site ]]; logs_json='{}'; }
"""
        for code in ('',)+tuple(sorted(rootful.POSTNODE_FAILURES)):
            f=self.fixture()
            result=f.child(setup+'postlog_failure='+code+'\n'+finish+'trap finish EXIT\nexit 23\n').finish()
            self.assertEqual(result.returncode,23,result.stderr)
            wire=json.loads(result.stdout);self.assertEqual(wire['schema'],rootful.RESULT_V8)
            self.assertEqual(wire['postlog_failure'],code or None)
            self.assertIsNone(wire['postlog_native']);self.assertIsNone(wire['postlog_reason'])
            self.assertEqual((f.root/'order').read_text().splitlines(),['pace','diagnose','native','evidence'])
        for code in ('','pl2.a'):
            f=self.fixture();anchor='  case ${1:-} in\n    [a-p])'
            self.assertEqual(f.definitions.count(anchor),1)
            f.definitions=f.definitions.replace(anchor,'  printf "%s" "$postlog_failure" > "$root/cleanup-code"\n'+anchor,1)
            result=f.child(setup+'postlog_failure='+code+'\n'+finish+'remember() { [[ -z $postlog_site ]]; fail; }\ntrap finish EXIT\nexit 23\n').finish()
            self.assertEqual(result.returncode,1);self.assertEqual((f.root/'cleanup-code').read_text(),code)

    def test_exact_v8_inverse_enforced_budget_and_all_historical_seals_reject_tamper(self):
        import hashlib
        current=receiver_before_live_census(receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))));old=receiver_before_postnode(current)
        self.assertEqual((len(current.encode()),hashlib.sha256(current.encode()).hexdigest()),(65408,POSTNODE_SOURCE))
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),(65270,COMPACT_INSPECT_SOURCE))
        self.assertEqual(len(current.encode())-len(old.encode()),138);self.assertLessEqual(len(current.encode()),65536)
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)
        self.assertEqual(hashlib.sha256(receiver_before_poll_pacing(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))))).encode()).hexdigest(),POLL_DIAGNOSTIC_SOURCE)
        for first,second in [('postlog_site=a','postlog_site=b'),('pl2.[a-dghk]','pl2.[a-k]'),
                             ('[rifnje])','[rifnjex])'),('local status=$?','local status=0'),
                             ('maximum=680','maximum=681'),('node_pid < pid_max','node_pid <= pid_max')]:
            self.assertEqual(current.count(first),1)
            with self.assertRaises(AssertionError):receiver_before_postnode(current.replace(first,second,1))
        for other in (old,current+'\n',None,b'',False):
            with self.assertRaises(AssertionError):receiver_before_postnode(other)


class PostnodeDecoderControls(unittest.TestCase):
    def bundle(self,code='pl2.a'):
        config,value,rows=CompactInspectControls.bundle(self)
        value.update(schema=rootful.RESULT_V8,postlog_failure=code,state='failed',source_deployment='not-reached')
        return config,value,rows

    def test_each_code_requires_positive_seven_role_logs_and_preserves_delete_status(self):
        for code in sorted(rootful.POSTNODE_FAILURES):
            config,value,_=self.bundle(code)
            for delete in (0,19):
                value['kind_delete_status']=delete
                checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
                self.assertEqual(checked['schema'],rootful.RESULT_V8);self.assertEqual(checked['postlog_failure'],code)
                self.assertEqual(checked['kind_delete_status'],delete);self.assertEqual(checked['logs'],value['logs'])
                self.assertEqual(set(checked['logs']['identities']),rootful.LOG_ROLES_V4)
                self.assertIsNone(checked['postlog_native']);self.assertIsNone(checked['postlog_reason'])
                self.assertIsNone(rootful.poll_failure(checked['logs'],version=rootful.RESULT_V8,failure=checked))
                with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config)

    def test_v8_null_early_guard_and_poll_records_keep_original_v7_log_domains(self):
        for state in ('not-established','pg1.a','pg2.g.native.S.4096.23.1'):
            config,value,_=DirectExecDecoderControls.bundle(self,state=state)
            value.update(schema=rootful.RESULT_V8,postlog_failure=None,postlog_native=None,postlog_reason=None)
            checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
            self.assertEqual(checked['logs'],value['logs']);self.assertIsNone(checked['postlog_failure'])
            bad=deepcopy(value);bad['postlog_failure']='pl2.a'
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for state in ('pg1.n','pg2.g.wrapper.S.4096.23.1'):
            config,value,_=DirectExecDecoderControls.bundle(self,state=state)
            value.update(schema=rootful.RESULT_V8,postlog_failure=None,postlog_native=None,postlog_reason=None)
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)

    def test_unknown_type_scope_log_and_exact_key_failures_refuse(self):
        config,value,_=self.bundle()
        changes=[('postlog_failure',x) for x in ('','pl2.e','pl2.f','pl2.j','pl2.A','pl2.aa','pl2.a\n',False,0,[],{})]
        changes += [('schema','kubernetes-lens-owned-rootful-result-v12'),('kind_create_status',False),
                    ('kind_create_status',1),('state','source-deployment-positive'),
                    ('source_deployment','server-dry-run-observed'),('postlog_native',{}),('postlog_reason','pid-max')]
        for field,altered in changes:
            bad=deepcopy(value);bad[field]=altered
            with self.subTest(field=field,altered=altered),self.assertRaises(vm.Refusal):
                rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for field in ('postlog_failure','postlog_native','postlog_reason'):
            bad=deepcopy(value);del bad[field]
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        bad=deepcopy(value);bad['new_hint']=None
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for field,altered in [('state','not-established'),('state','pg1.a'),('startup_marker',False),
                              ('wrapper_observed_child_wait_status',0),('signal_cause','TERM')]:
            bad=deepcopy(value);bad['logs'][field]=altered
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for mutate in (lambda logs:logs['identities'].pop('native'),lambda logs:logs['identities'].update(native=None),
                       lambda logs:logs['identities']['native'].update(pid=True),
                       lambda logs:logs['collectors']['out'].update(source_eof=False),
                       lambda logs:logs['collectors']['err'].update(tee_status=1)):
            bad=deepcopy(value);mutate(bad['logs'])
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)

    def test_ordinary_node_role_raw_integrity_and_original_semantics_stay_mandatory(self):
        config,value,rows=self.bundle()
        bad=deepcopy(value);del bad['evidence']['files']['node-inspect']
        with self.assertRaisesRegex(vm.Refusal,'rootful-postnode-node-evidence'):
            rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for field,altered in [('bytes',True),('sha256','0'*64),('base64','!!!')]:
            bad=deepcopy(value);bad['evidence']['files']['node-inspect'][field]=altered
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for raw in (b'[]\n',vm.encode(rows[0]),vm.encode(rows+rows),b'[{bad}]\n'):
            bad=deepcopy(value);CompactInspectControls.replace_node(bad,raw)
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for mutate in (lambda row:row['State'].update(CgroupPath='wrong'),lambda row:row['State'].update(Pid=True),
                       lambda row:row['State'].update(Pid=32768),lambda row:row['State'].update(Running=False),
                       lambda row:row.update(Image='f'*64),lambda row:row['Config'].update(CreateCommand=[]),
                       lambda row:row['NetworkSettings'].update(Networks={})):
            changed=deepcopy(rows);mutate(changed[0]);bad=deepcopy(value)
            CompactInspectControls.replace_node(bad,vm.encode(changed))
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        bad=deepcopy(value);bad['evidence']['files']['foreign-node']=bad['evidence']['files'].pop('node-inspect')
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)

    def test_v8_null_success_and_old_pl1_native_reason_domains_are_unchanged(self):
        config,value,_=CompactInspectControls.bundle(self);value['schema']=rootful.RESULT_V8
        self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config)['state'],'source-deployment-positive')
        for code in sorted(rootful.POSTLOG_FAILURES):
            config,legacy,_=ResourceReasonDecoderControls.bundle(self,code=code)
            legacy['schema']=rootful.RESULT_V8
            checked=rootful.wire_record(vm.encode(legacy)+b'\n',config,allow_failure=True)
            self.assertEqual(checked['postlog_failure'],code)
            self.assertEqual(checked['postlog_native'],legacy['postlog_native'])
            self.assertEqual(checked['postlog_reason'],legacy['postlog_reason'])
            _,positive,_=CompactInspectControls.bundle(self)
            legacy['evidence']['files']['node-inspect']=positive['evidence']['files']['node-inspect']
            with self.assertRaisesRegex(vm.Refusal,'rootful-postlog-node-evidence'):
                rootful.wire_record(vm.encode(legacy)+b'\n',config,allow_failure=True)

    def test_v1_v7_schema_keys_and_code_domains_do_not_gain_pl2_or_defaults(self):
        for version in (rootful.RESULT_V1,rootful.RESULT_V2,rootful.RESULT_V3,rootful.RESULT_V4,
                        rootful.RESULT_V5,rootful.RESULT_V6,rootful.RESULT_V7):
            if version==rootful.RESULT_V7:config,value,_=ResourceReasonDecoderControls.bundle(self)
            elif version==rootful.RESULT_V6:config,value,_=NativeStatusDecoderControls.bundle(self)
            elif version==rootful.RESULT_V5:config,value,_=PostlogDecoderControls.bundle(self)
            elif version==rootful.RESULT_V4:config,value,_=DirectExecDecoderControls.bundle(self,complete=True)
            else:config,value,_=DurableEvidenceControls.bundle(self);value['schema']=version
            checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
            self.assertEqual(checked['schema'],version)
            self.assertEqual(set(checked),set(value))
            for code in sorted(rootful.POSTNODE_FAILURES):
                bad=deepcopy(value);bad['postlog_failure']=code
                with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)

    def test_v8_durable_wire_exact_summary_and_private_descriptor_redaction(self):
        config,value,_=self.bundle('pl2.k');raw=vm.encode(value)+b'\n'
        with tempfile.TemporaryDirectory(prefix='postnode-v8-private-') as directory:
            parent=Path(directory);descriptor=rootful.durable_wire(raw,config,parent,vm.Budget(time.monotonic()+30,10))
            self.assertEqual((parent/descriptor['name']).read_bytes(),raw)
            for protected in (b'pl2.k',b'postlog_failure',b'SYNTHETIC_ONLY'):
                self.assertNotIn(protected,vm.encode(descriptor))

class PhaseSpecificCensusControls(unittest.TestCase):
    """Two original censuses over prepared private trees; no real proc/runtime."""
    stat=InventoryDestinationControls.stat

    def trees(self):
        import shutil
        f=InventoryDestinationControls.fixture(self)
        second=f.proc.with_name('private-proc-second');shutil.copytree(f.proc,second)
        return f,second

    def pair(self,f,second,mode='live',*,corridor='',after='',argument=None):
        import shlex
        source=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        head=source.split('resource_check() {\n',1)[1].split('\n',1)[0]
        self.assertEqual(head,'  [[ $# == 0 || $# == 1 && $1 == live ]] || fail')
        anchor='  inventory\n  before=$SNAP\n  inventory\n'
        self.assertEqual(source.count(anchor),1)
        tail=anchor+source.split(anchor,1)[1].split('\n}',1)[0]+'\n'
        projected='resource_check() {\n'+head+'\n  local before\n'+tail+'}\n'
        self.assertNotIn('/proc/',projected);self.assertNotIn('/usr/bin/',projected)
        self.assertEqual(f.host.definitions.count('inventory() {\n'),1)
        f.host.definitions=f.host.definitions.replace('inventory() {\n','source_inventory() {\n',1)
        original=f.host.definitions.split('source_inventory() {\n',1)[1].split('\n}\n',1)[0]
        self.assertNotIn('/proc/',original)
        self.assertEqual(f.host.definitions.count('resource_check() {\n'),1)
        f.host.definitions=f.host.definitions.replace('resource_check() {\n','unprojected_resource_check() {\n',1)
        setup='inventory_proc='+shlex.quote(str(f.proc))+'\nnext_inventory_proc='+shlex.quote(str(second))+'\n'
        setup+='''rootful_intent=execution-v1 mode=work initial_prerequisite=0 postlog_site=r
scans=0
inventory() {
  source_inventory
  scans=$((scans + 1))
  printf '%s\n' "$scans" >> "$root/scan-trace"
  if ((scans == 1)); then inventory_proc=$next_inventory_proc; fi
}
trap 'printf "%s\n%s\n" "$postlog_failure" "$postlog_reason" > "$root/closed-code"' EXIT
'''
        call=('resource_check' if mode=='stable' else 'resource_check live') if argument is None else 'resource_check '+argument
        body=setup+projected+call+'\n'+corridor+after+'\nprintf healthy\n'
        result=f.host.child(body).finish()
        trace=(f.host.root/'scan-trace').read_text().splitlines() if (f.host.root/'scan-trace').exists() else []
        code=(f.host.root/'closed-code').read_text().splitlines()
        return result,trace,code

    def assert_healthy(self,result,trace,code):
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'healthy',b''))
        self.assertEqual(trace,['1','2']);self.assertEqual(code,['','null'])

    def assert_refusal(self,f,result,code,reason,*,site='pl1.r'):
        self.assertEqual((result.returncode,result.stdout,result.stderr),(1,b'',b'rootful-receiver-refused\n'))
        self.assertEqual(code,[site,json.dumps(reason) if reason is not None else 'null'])
        self.assertEqual((f.host.root/'state/poison').read_bytes(),b'poisoned\n')

    def test_benign_fd_open_close_and_valid_hard_limit_changes_are_live_only(self):
        for change in ('open','close','limit'):
            for mode in ('stable','live'):
                with self.subTest(change=change,mode=mode):
                    f,second=self.trees();task=second/'101/task/101'
                    if change=='open':(task/'fd/7').touch()
                    elif change=='close':(task/'fd/3').unlink()
                    else:(task/'limits').write_text('Max open files 1024 9999999999 files\n')
                    result,trace,code=self.pair(f,second,mode)
                    if mode=='live':self.assert_healthy(result,trace,code)
                    else:self.assertEqual(trace,['1','2']);self.assert_refusal(f,result,code,'inv-drift')

    def test_bounded_task_birth_and_exit_are_live_only_and_second_map_is_exact(self):
        import shutil
        for change in ('birth','exit'):
            for mode in ('stable','live'):
                with self.subTest(change=change,mode=mode):
                    f,second=self.trees()
                    # Exit remains a complete nonempty second census.
                    destination=(f.proc if change=='exit' else second)/'101/task/102'
                    shutil.copytree(f.task,destination);(destination/'stat').write_text(self.stat(102,start='2000'))
                    after='[[ ${INVENTORY_START[101]} == 1000 ]]\n'
                    after+='[[ ${INVENTORY_START[102]:-} == 2000 ]]\n' if change=='birth' else '[[ ! ${INVENTORY_START[102]+present} ]]\n'
                    result,trace,code=self.pair(f,second,mode,after=after)
                    if mode=='live':self.assert_healthy(result,trace,code)
                    else:self.assertEqual(trace,['1','2']);self.assert_refusal(f,result,code,'inv-drift')

    def test_healthy_identical_scans_pass_both_modes(self):
        for mode in ('stable','live'):
            f,second=self.trees();result,trace,code=self.pair(f,second,mode,after='[[ ${INVENTORY_START[101]} == 1000 ]]\n')
            self.assert_healthy(result,trace,code)

    def test_unknown_empty_extra_phase_arguments_fail_before_any_scan(self):
        for argument in ("''",'Live','unknown','live extra','stable'):
            f,second=self.trees();result,trace,code=self.pair(f,second,argument=argument)
            self.assertEqual(trace,[]);self.assert_refusal(f,result,code,'unlabelled')

    def test_live_keeps_every_original_malformed_range_and_incomplete_refusal_in_either_scan(self):
        import shutil
        changes=(
            ('process-pid','inv-proc-pid',lambda p,t:(p/'stat').write_text(self.stat(102))),
            ('task-pid','inv-task-tid',lambda p,t:(t/'stat').write_text(self.stat(102))),
            ('process-form','inv-proc-form',lambda p,t:(p/'stat').write_text(self.stat(101,short=True))),
            ('task-start','inv-task-form',lambda p,t:(t/'stat').write_text(self.stat(101,start='not-decimal'))),
            ('nofile-infinite','inv-nf-form',lambda p,t:(t/'limits').write_text('Max open files 1024 unlimited files\n')),
            ('nofile-eleven','inv-nf-form',lambda p,t:(t/'limits').write_text('Max open files 1024 10000000000 files\n')),
            ('nofile-missing','inv-nf-form',lambda p,t:(t/'limits').write_text('')),
            ('fd-malformed','inv-fd-form',lambda p,t:(t/'fd/7bad').touch()),
            ('fd-high','inv-fd-range',lambda p,t:(t/'fd/1073741816').touch()),
            ('fd-inaccessible','inv-fd-access',lambda p,t:shutil.rmtree(t/'fd')),
            ('process-unreadable','inv-proc-read',lambda p,t:(p/'stat').unlink()),
            ('task-unreadable','inv-task-read',lambda p,t:(t/'stat').unlink()),
            ('task-empty','inv-task-empty',lambda p,t:shutil.rmtree(t)),
            ('process-task-missing','inv-proc-task',lambda p,t:shutil.rmtree(p/'task')),
        )
        for name,reason,mutate in changes:
            for scan in (1,2):
                with self.subTest(name=name,scan=scan):
                    f,second=self.trees();process=(f.proc if scan==1 else second)/'101';mutate(process,process/'task/101')
                    result,trace,code=self.pair(f,second)
                    self.assertEqual(trace,[] if scan==1 else ['1']);self.assert_refusal(f,result,code,reason)
        for tid in ('0','32768'):
            for scan in (1,2):
                f,second=self.trees();process=(f.proc if scan==1 else second)/'101';(process/'task/101').rename(process/'task'/tid)
                result,trace,code=self.pair(f,second);self.assert_refusal(f,result,code,'inv-tid-count')
        for pid in ('0','32768'):
            f,second=self.trees();(second/'101').rename(second/pid)
            result,trace,code=self.pair(f,second);self.assertEqual(trace,['1']);self.assert_refusal(f,result,code,'inv-pid-range')

    def test_live_retains_strict_task_count_empty_and_snapshot_cap_failures(self):
        import shutil
        for initial,passes in ((32766,True),(32767,False)):
            f,second=self.trees();anchor='local process pid tid task record tail hard _soft a b c rest fd count=0'
            self.assertEqual(f.host.definitions.count(anchor),1)
            f.host.definitions=f.host.definitions.replace(anchor,anchor[:-1]+str(initial),1)
            result,trace,code=self.pair(f,second)
            if passes:self.assert_healthy(result,trace,code)
            else:self.assert_refusal(f,result,code,'inv-tid-count')
        f,second=self.trees();shutil.rmtree(second/'101')
        result,trace,code=self.pair(f,second);self.assert_refusal(f,result,code,'inv-empty')
        # Existing exact32MiB/+1 controls remain unchanged. This lowered private
        # projection checks that live cannot bypass the original size fail route.
        f,second=self.trees();guard='((${#SNAP} <= 33554432)) || fail inv-snap-size'
        self.assertEqual(f.host.definitions.count(guard),1)
        f.host.definitions=f.host.definitions.replace(guard,'((${#SNAP} <= 1)) || fail inv-snap-size',1)
        result,trace,code=self.pair(f,second);self.assert_refusal(f,result,code,'inv-snap-size')

    def node_corridor(self,*,first='2000',second='2000',pid='101',cgroup=True,stat_pid='101'):
        import shlex
        source=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))));start='postlog_site=a\n';end='postlog_site=k\n'
        self.assertEqual(source.count(start),1);self.assertEqual(source.count(end),1)
        corridor=start+source.split(start,1)[1].split(end,1)[0]
        self.assertEqual(corridor.count('read_file '),3);self.assertEqual(corridor.count('u /usr/bin/jq'),2)
        self.assertNotIn('native ',corridor);self.assertNotIn('/usr/bin/podman',corridor)
        setup='node_id='+'a'*64+'\nout=$captures/work.1.out\nnode_reads=0\n'
        setup+='selected_pid='+shlex.quote(pid)+'\nfirst_stat='+shlex.quote(self.stat(stat_pid,start=first))+'\nsecond_stat='+shlex.quote(self.stat('101',start=second))+'\n'
        setup+='''u() {
  case "$*" in *State.Pid*) printf '%s' "$selected_pid" ;; *) return 0 ;; esac
}
read_file() {
  case $1 in
    /proc/101/stat)
      node_reads=$((node_reads + 1))
      if ((node_reads == 1)); then REPLY=$first_stat; else REPLY=$second_stat; fi
      ;;
    /proc/101/cgroup) REPLY=0::$node_cgroup ;;
    *) exit 88 ;;
  esac
}
'''
        if not cgroup:setup=setup.replace('REPLY=0::$node_cgroup','REPLY=foreign-cgroup')
        return setup+corridor

    def test_selected_node_identity_uses_only_the_second_completed_scan(self):
        f,second=self.trees();process=second/'101';task=process/'task/101'
        (process/'stat').write_text(self.stat(101,start='2000'));(task/'stat').write_text(self.stat(101,start='2000'))
        result,trace,code=self.pair(f,second,corridor=self.node_corridor(),after='[[ ${INVENTORY_START[101]} == 2000 && $node_reads == 2 ]]\n')
        self.assert_healthy(result,trace,code)

    def test_missing_second_cache_and_later_selected_pid_start_cgroup_drift_refuse(self):
        import shutil
        f,second=self.trees();shutil.rmtree(second/'101')
        process=second/'202';shutil.copytree(f.process,process);(process/'stat').write_text(self.stat(202,start='2000'))
        (process/'task/101').rename(process/'task/202');(process/'task/202/stat').write_text(self.stat(202,start='2000'))
        result,trace,code=self.pair(f,second,corridor=self.node_corridor());self.assertEqual(trace,['1','2'])
        self.assert_refusal(f,result,code,None,site='pl2.c')
        for variant,site in [({'first':'1000'},'pl2.d'),({'stat_pid':'102'},'pl2.d'),
                             ({'second':'2001'},'pl2.h'),({'cgroup':False},'pl2.g'),({'pid':'032768'},'pl2.b')]:
            f,second=self.trees();process=second/'101';task=process/'task/101'
            (process/'stat').write_text(self.stat(101,start='2000'));(task/'stat').write_text(self.stat(101,start='2000'))
            result,trace,code=self.pair(f,second,corridor=self.node_corridor(**variant));self.assertEqual(trace,['1','2'])
            self.assert_refusal(f,result,code,None,site=site)

    def test_live_keeps_original_global_pid_nropen_and_helper_failures_before_inventory(self):
        import shlex
        source=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        self.assertEqual(source.count('resource_check() {\n'),1)
        prefix=source.split('resource_check() {\n',1)[1].split("  value=''\n",1)[0]+"  value=''\n"
        self.assertIn('[[ $# == 0 || $# == 1 && $1 == live ]] || fail',prefix)
        replacements=[('read -r value < /proc/sys/kernel/pid_max',
                       'printf "pid\\n" >> "$root/global-trace"\n  read -r value <<< "$pid_value"'),
                      ('read -r value < /proc/sys/fs/nr_open',
                       'printf "nr-open\\n" >> "$root/global-trace"\n  read -r value <<< "$open_value"')]
        for original,doubled in replacements:
            self.assertEqual(prefix.count(original),1)
            prefix=prefix.replace(original,doubled,1)
        self.assertNotIn('< /proc/',prefix);self.assertNotIn('/proc/sys/',prefix)
        self.assertEqual(prefix.count('/proc/'),2)  # Only argv DATA to doubled u.
        self.assertEqual(prefix.count('namespace=$(u /usr/bin/stat -Lc'),1)
        self.assertEqual(prefix.count('value=$(u /usr/bin/stat -Lc'),1)
        first=['u:first','grant:first','launch:first']
        second=['u:second','grant:second','launch:second']
        base=['pid','nr-open']
        cases=[('1','1','', 'pid-max',['pid']),
               ('32768','bad','', 'nr-open-form',base),
               ('32768','0','', 'nr-open-range',base),
               ('32768','1073741817','', 'nr-open-range',base),
               ('32768','1','', None,base+first+second+['inventory','native']),
               ('32768','1073741816','', None,base+first+second+['inventory','native']),
               ('32768','1','grant-first','unlabelled',base+first[:2]),
               ('32768','1','return-first','unlabelled',base+first),
               ('32768','1','fail-first','unlabelled',base+first),
               ('32768','1','grant-second','namespace',base+first+second[:2]),
               ('32768','1','return-second','namespace',base+first+second),
               ('32768','1','fail-second','namespace',base+first+second),
               ('32768','1','mismatch','namespace',base+first+second)]
        for pid,opened,problem,reason,expected_trace in cases:
            with self.subTest(pid=pid,nr_open=opened,problem=problem):
                f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
                self.assertEqual(f.definitions.count('\nu() {\n'),1)
                f.definitions=f.definitions.replace('\nu() {\n','\nsource_u() {\n',1)
                self.assertEqual(f.definitions.count('resource_check() {\n'),1)
                f.definitions=f.definitions.replace('resource_check() {\n','unused_resource_check() {\n',1)
                body=ResourceReasonReceiverControls.prefix(self)
                body+='pid_value='+shlex.quote(pid)+'\nopen_value='+shlex.quote(opened)+'\nproblem='+shlex.quote(problem)+'\n'
                body+='''u() {
  case ${*: -1} in
    /proc/1/ns/pid) which=first ;;
    /proc/self/ns/pid) which=second ;;
    *) exit 88 ;;
  esac
  printf 'u:%s\n' "$which" >> "$root/global-trace"
  source_u "$@"
}
grant_utility() {
  printf 'grant:%s\n' "$which" >> "$root/global-trace"
  [[ $problem != "grant-$which" ]] || return 1
  utility_ticket=utility-work.0
}
utility_launch() {
  printf 'launch:%s\n' "$which" >> "$root/global-trace"
  [[ $problem != "return-$which" ]] || return 9
  [[ $problem != "fail-$which" ]] || fail arbitrary-private-child
  if [[ $problem == mismatch && $which == second ]]; then printf '9:10'; else printf '9:9'; fi
}
inventory() { printf 'inventory\n' >> "$root/global-trace"; }
native() { printf 'native\n' >> "$root/global-trace"; }
'''
                body+='resource_check() {\n'+prefix+'}\nresource_check live\ninventory\nnative\nprintf healthy\n'
                result=f.child(body).finish()
                self.assertEqual((f.root/'global-trace').read_text().splitlines(),expected_trace)
                code,record=(f.root/'reason').read_text().splitlines()
                self.assertEqual((code,json.loads(record)),('pl1.r',reason) if reason else ('',None))
                if reason is None:
                    self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'healthy',b''))
                    self.assertFalse((f.root/'state/poison').exists())
                else:
                    self.assertEqual((result.returncode,result.stdout),(1,b''))
                    self.assertTrue(result.stderr.splitlines())
                    self.assertTrue(all(line==b'rootful-receiver-refused' for line in result.stderr.splitlines()))
                    self.assertNotIn('inventory',expected_trace);self.assertNotIn('native',expected_trace)
                    self.assertEqual((f.root/'state/poison').read_bytes(),b'poisoned\n')
                self.assertNotIn(b'arbitrary-private-child',result.stdout+result.stderr+(f.root/'reason').read_bytes())

    def test_exact_phase_topology_inverse_caps_and_unchanged_identity_corridor(self):
        import hashlib,re
        source=receiver_before_owned_cgroup(receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))));frozen=receiver_before_live_census(source)
        self.assertEqual((len(source.encode()),hashlib.sha256(source.encode()).hexdigest()),(LIVE_CENSUS_SOURCE_BYTES,LIVE_CENSUS_SOURCE))
        self.assertEqual((len(frozen.encode()),hashlib.sha256(frozen.encode()).hexdigest()),(POSTNODE_SOURCE_BYTES,POSTNODE_SOURCE))
        self.assertLessEqual(len(source.encode()),65408);self.assertLessEqual(len(source.encode()),65536)
        calls=re.findall(r'^([ \t]*)resource_check((?:[ \t].*)?)$',source,re.M)
        self.assertEqual(calls,[('    ',''),('  ',''),('',''),('',' live')])
        inventory=lambda text:text.split('inventory() {\n',1)[1].split('\n}\n',1)[0]
        self.assertEqual(inventory(source),inventory(frozen))
        corridor=lambda text:text.split('postlog_site=i\nread_file "$root/state/node-id"',1)[1]
        self.assertEqual(corridor(source),corridor(frozen))
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        for old,new in [('resource_check live','resource_check'),('${1:-} == live','${1:-} != live'),
                        ('fd < fd_max','fd <= fd_max'),('maximum=680','maximum=681')]:
            self.assertEqual(source.count(old),1)
            with self.assertRaises(AssertionError):receiver_before_live_census(source.replace(old,new,1))
        for invalid in (frozen,source+'\n',None,b'',False):
            with self.assertRaises(AssertionError):receiver_before_live_census(invalid)

class OwnedCgroupMembershipControls(unittest.TestCase):
    """Original selected-node corridor; fixed DATA and owned private files only."""
    stat=InventoryDestinationControls.stat
    trees=PhaseSpecificCensusControls.trees
    pair=PhaseSpecificCensusControls.pair
    assert_healthy=PhaseSpecificCensusControls.assert_healthy
    assert_refusal=PhaseSpecificCensusControls.assert_refusal
    ROOT='/libpod_parent/libpod-'+'a'*64

    def corridor(self,record,*,inspect_good=True,real_file=None,**identity):
        import shlex
        values={'first':'1000','second':'1000'};values.update(identity)
        body=PhaseSpecificCensusControls.node_corridor(self,**values)
        self.assertEqual(body.count('REPLY=0::$node_cgroup'),1)
        body=body.replace('REPLY=0::$node_cgroup','REPLY=$proc_record',1)
        if not inspect_good:
            self.assertEqual(body.count('*) return 0 ;;'),1)
            body=body.replace('*) return 0 ;;','*) return 9 ;;',1)
        self.assertEqual(body.count('u() {\n'),1);self.assertEqual(body.count('read_file() {\n'),1)
        body=body.replace('u() {\n','u() {\n  printf "u\\n" >> "$root/corridor-trace"\n',1)
        body=body.replace('read_file() {\n','read_file() {\n  printf "read:%s\\n" "$1" >> "$root/corridor-trace"\n',1)
        setup='proc_record='+shlex.quote(record)+'\n'
        if real_file is not None:
            self.assertEqual(body.count('/proc/101/cgroup) REPLY=$proc_record ;;'),1)
            body=body.replace('/proc/101/cgroup) REPLY=$proc_record ;;','/proc/101/cgroup) source_read_file "$private_cgroup" ;;',1)
            setup+='private_cgroup='+shlex.quote(str(real_file))+'\n'
        return setup+body

    def run_corridor(self,record,*,real_kind=None,missing_cache=False,**identity):
        import shutil
        f,second=self.trees();private=None
        if real_kind is not None:
            private=f.host.root/'private-cgroup'
            if real_kind=='directory':private.mkdir()
            elif real_kind=='symlink':
                target=f.host.root/'private-target';target.write_text(record+'\n');private.symlink_to(target)
            elif real_kind=='regular':private.write_text(record+'\n\n')
            else:self.assertEqual(real_kind,'missing')
            self.assertEqual(f.host.definitions.count('\nread_file() {\n'),1)
            f.host.definitions=f.host.definitions.replace('\nread_file() {\n','\nsource_read_file() {\n',1)
        if missing_cache:
            shutil.rmtree(second/'101');process=second/'202';shutil.copytree(f.process,process)
            (process/'stat').write_text(self.stat(202));(process/'task/101').rename(process/'task/202')
            (process/'task/202/stat').write_text(self.stat(202))
        body='native() { printf "native\\n" >> "$root/corridor-trace"; }\n'+self.corridor(record,real_file=private,**identity)
        result,trace,code=self.pair(f,second,corridor=body,after='native\n')
        calls=[x.replace('read:/proc/101/','read:') for x in (f.host.root/'corridor-trace').read_text().splitlines()]
        return f,result,trace,code,calls

    def test_root_canonical_descendants_and_dotted_names_keep_actual_private_reply(self):
        records=['0::'+self.ROOT+suffix for suffix in ('','/init.scope','/system.slice/example.service',
                 '/user.slice/user-0.slice/user@0.service/init.scope','/.hidden/a..b','/...','/space name')]
        for record in records:
            with self.subTest(record=record):
                f,result,trace,code,calls=self.run_corridor(record)
                self.assert_healthy(result,trace,code)
                self.assertEqual(calls,['u','u','read:stat','read:cgroup','read:stat','native'])
                actual=(f.host.root/'state/actual-node-process').read_bytes()
                self.assertTrue(actual.endswith(record.encode()+b'\n'))
                if record!='0::'+self.ROOT:self.assertFalse(actual.endswith(('0::'+self.ROOT+'\n').encode()))

    def test_noncanonical_foreign_headers_and_records_stop_before_write_and_native(self):
        r=self.ROOT
        bad=['','0::/','0::/init.scope','0::relative','0::/libpod_parent','0::'+r+'x/init.scope',
             '0::/libpod_parent/libpod-'+'b'*64+'/init.scope','0::/foreign'+r,'1::'+r,'0:cpu:'+r,
             '3:cpu,memory:'+r,'0:::'+r,' 0::'+r,'0::'+r+' ',
             *['0::'+r+s for s in ('/','//child','/child/','/child//grand','/.','/..','/./child',
                 '/../child','/a/./b','/a/../b','/a/.','/a/..','/a\r','/a\t','/a\x01','/a\x7f',
                 '/a\n0::'+r,'/a\r\n0::'+r)]]
        for record in bad:
            with self.subTest(record=record):
                f,result,trace,code,calls=self.run_corridor(record)
                self.assertEqual(trace,['1','2']);self.assert_refusal(f,result,code,None,site='pl2.g')
                self.assertEqual(calls,['u','u','read:stat','read:cgroup'])
                self.assertFalse((f.host.root/'state/actual-node-process').exists());self.assertNotIn('native',calls)

    def test_real_existing_read_helper_missing_directory_symlink_fail_and_lf_limit_is_honest(self):
        for kind in ('missing','directory','symlink'):
            f,result,trace,code,calls=self.run_corridor('0::'+self.ROOT+'/init.scope',real_kind=kind)
            self.assert_refusal(f,result,code,None,site='pl2.g')
            self.assertEqual(calls,['u','u','read:stat','read:cgroup'])
            self.assertFalse((f.host.root/'state/actual-node-process').exists())
        # Existing read_file strips trailing LF: this is consumed REPLY,
        # not a newly invented exact raw-file framing theorem.
        record='0::'+self.ROOT+'/init.scope'
        f,result,trace,code,calls=self.run_corridor(record,real_kind='regular')
        self.assert_healthy(result,trace,code)
        self.assertTrue((f.host.root/'state/actual-node-process').read_bytes().endswith(record.encode()+b'\n'))
        self.assertEqual(calls,['u','u','read:stat','read:cgroup','read:stat','native'])

    def test_descendant_acceptance_never_bypasses_inspected_root_cache_or_stat_identity(self):
        record='0::'+self.ROOT+'/init.scope'
        cases=[({'inspect_good':False},'pl2.a',False),({'missing_cache':True},'pl2.c',False),
               ({'stat_pid':'102'},'pl2.d',False),({'first':'1001'},'pl2.d',False),
               ({'second':'1001'},'pl2.h',True)]
        for options,site,written in cases:
            with self.subTest(options=options):
                f,result,trace,code,calls=self.run_corridor(record,**options)
                self.assert_refusal(f,result,code,None,site=site);self.assertNotIn('native',calls)
                self.assertEqual((f.host.root/'state/actual-node-process').exists(),written)
        # The unchanged host decoder still requires the inspect ROOT.
        config,value,rows=PostnodeDecoderControls.bundle(self)
        rows[0]['State']['CgroupPath']+='/init.scope'
        CompactInspectControls.replace_node(value,vm.encode(rows))
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)

    def test_real_finish_keeps_first_failure_and_actual_delete_failure_independent(self):
        original=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('\nfinish() {\n',1)[1].split('\ntrap finish EXIT',1)[0]
        for earlier in (False,True):
            for delete in (0,19):
                f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
                setup='''rootful_intent=execution-v1 mode=work postlog_site=r
declare -A INVENTORY_START=([101]=1000)
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=owned
pace_close() { [[ -z $postlog_site ]]; }
remember() { [[ -z $postlog_site ]]; }
emit_evidence() { [[ -z $postlog_site ]]; evidence_json='{}'; }
emit_logs_evidence() { [[ -z $postlog_site ]]; logs_json='{}'; }
native() {
  [[ -z $postlog_site && $mode == cleanup ]] || exit 88
  printf 'cleanup\\n' >> "$root/cleanup-trace"
  last_tool_status=$delete
  return "$delete"
}
'''
                body=setup+'delete='+str(delete)+'\nfinish() {\n'+original+'\ntrap finish EXIT\n'
                body+=self.corridor('0::/foreign',inspect_good=not earlier)
                body+='printf unexpected > "$root/work-reached"\n'
                result=f.child(body).finish();wire=json.loads(result.stdout)
                self.assertEqual(result.returncode,1)
                self.assertEqual((wire['state'],wire['kind_create_status'],wire['kind_delete_status']),('failed',0,delete))
                self.assertEqual(wire['postlog_failure'],'pl2.a' if earlier else 'pl2.g')
                self.assertIsNone(wire['postlog_reason']);self.assertIsNone(wire['postlog_native'])
                self.assertEqual((f.root/'cleanup-trace').read_text().splitlines(),['cleanup'])
                self.assertFalse((f.root/'work-reached').exists());self.assertFalse((f.root/'state/actual-node-process').exists())

    def test_exact_source_epoch_inverse_inspect_root_identity_reads_and_caps_remain(self):
        import hashlib
        source=receiver_before_k_stage(receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))));frozen=receiver_before_owned_cgroup(source)
        self.assertEqual((len(source.encode()),hashlib.sha256(source.encode()).hexdigest()),(65359,OWNED_CGROUP_SOURCE))
        self.assertEqual((len(frozen.encode()),hashlib.sha256(frozen.encode()).hexdigest()),(65354,LIVE_CENSUS_SOURCE))
        self.assertLessEqual(len(source.encode()),65408);self.assertLessEqual(len(source.encode()),65536)
        self.assertIn('^0::"$node_cgroup"(/[^/[:cntrl:]]+)*$',source)
        before=lambda text:text.split('postlog_site=i\n',1)[1].split('postlog_site=g\n',1)[0]
        self.assertEqual(before(source),before(frozen))
        self.assertEqual(source.split('postlog_site=h\n',1)[1],frozen.split('postlog_site=h\n',1)[1])
        g=lambda text:text.split('postlog_site=g\n',1)[1].split('postlog_site=h\n',1)[0]
        self.assertEqual(g(source).count('read_file '),1)
        self.assertIn('printf \'%s\\n%s\\n\' "$node_stat" "$REPLY" > "$root/state/actual-node-process"',g(source))
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)
        for old,new in [('^0::"$node_cgroup"','^0::.*'),('$REPLY != */..','true'),('maximum=680','maximum=681')]:
            self.assertGreater(source.count(old),0)
            with self.assertRaises(AssertionError):receiver_before_owned_cgroup(source.replace(old,new,1))
        for bad in (frozen,source+'\n',None,b'',False):
            with self.assertRaises(AssertionError):receiver_before_owned_cgroup(bad)



class KStageReceiverControls(unittest.TestCase):
    """Frozen V9 statements; every apparent runtime/read is mandatory fixed DATA."""
    STAGES = 'abcdefghijklmn'
    NATIVE = 'acehjm'

    def fixture(self):
        f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
        return f

    def segment(self,source=None):
        source=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))) if source is None else source
        return 'postlog_site=k\n'+source.split('postlog_site=k\n',1)[1]

    def setup(self,bad=''):
        import shlex
        return r'''rootful_intent=execution-v1 mode=work
node=owned-node cluster=owned patch=1.20.15 KUBECONFIG=$root/kubeconfig
fixture_sha=fixed-sha out=$captures/work.0.out round=0 native_count=0
last_tool_status=91 last_stdout_capture_status=92 last_stderr_capture_status=93
trap 'printf "%s\n%s\n%s\n%s\n" "$postlog_failure" "$postlog_reason" "$postlog_native" "${source_status:-not-reached}" > "$root/result"' EXIT
trap 'exit 1' ERR HUP INT TERM
native() {
  [[ $3 == "$stage/kubectl" ]] || exit 88
  printf 'native:%s\n' "$*" >> "$root/trace"
  native_count=$((native_count+1))
  postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null
  local role
  case "$*" in
    *'config view'*) role=a ;;
    *'version -o'*) role=c ;;
    *--raw=/readyz*) role=e; round=$((round+1)) ;;
    *'get nodes'*) role=h ;;
    *'create namespace'*) role=j ;;
    *--dry-run=server*) role=m ;;
    *) exit 88 ;;
  esac
  [[ $bad != "$role-helper" ]] || fail
  # A poisoned second entry refuses before any command-result observation.
  [[ $bad != poisoned-round || $round != 2 ]] || fail
  postlog_tool=0 postlog_out=0 postlog_err=0
  if [[ $bad == "$role-native" || $bad == first-then-success && $role == e && $round == 1 ]]; then
    postlog_tool=7
    return 7
  fi
  if [[ $bad == poisoned-round && $role == e ]]; then
    postlog_out=1
    printf 'poisoned\n' > "$root/state/poison"
    return 125
  fi
  return 0
}
u() {
  printf 'u:%s\n' "$*" >> "$root/trace"
  local role
  case "$*" in
    *current-context*) role=b ;;
    *serverVersion*) role=d ;;
    *nodeInfo*) role=i ;;
    *sha256sum*) role=k ;;
    *apiVersion*) role=n ;;
    *) exit 88 ;;
  esac
  [[ $bad != "$role-helper" ]] || fail
  if [[ $role == k ]]; then
    [[ $bad != l-query ]] || { printf wrong; return 0; }
    printf '%s  %s' "$fixture_sha" "$root/deployment.json"
  fi
  [[ $bad != "$role-query" && ! ( $bad == i-first-then-success && $role == i && $round == 1 ) ]]
}
read_file() {
  printf 'read:%s\n' "$1" >> "$root/trace"
  [[ $1 == "$out" ]] || exit 88
  [[ $bad != f-helper ]] || fail
  REPLY=ok
  [[ $bad != g-query && ! ( $bad == g-first-then-success && $round == 1 ) ]] || REPLY=not-ready
}
'''+ 'bad='+shlex.quote(bad)+'\n'

    def run_corridor(self,bad='',*,historical=False):
        f=self.fixture();source=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))))
        if historical:source=receiver_before_k_stage(source)
        result=f.child(self.setup(bad)+self.segment(source)).finish()
        code,reason,native,marker=(f.root/'result').read_text().splitlines()
        trace=(f.root/'trace').read_text().replace(str(f.root),'ROOT') if (f.root/'trace').exists() else ''
        return f,result,code,json.loads(reason),json.loads(native),marker,trace

    def test_all_fourteen_active_groups_and_helper_refusal_are_not_predicate_claims(self):
        cases=[('a-native','a'),('b-query','b'),('c-native','c'),('d-query','d'),
               ('e-native','e'),('f-helper','f'),('g-query','g'),('h-native','h'),
               ('i-query','i'),('j-native','j'),('k-helper','k'),('l-query','l'),
               ('m-native','m'),('n-query','n')]
        cases += [(c+'-helper',c) for c in 'abcdhijnm']
        for bad,stage in cases:
            with self.subTest(bad=bad):
                f,result,code,reason,native,marker,trace=self.run_corridor(bad)
                self.assertEqual((result.returncode,code,reason,marker),(1,'pl2.k','k1.'+stage,'not-reached'))
                self.assertTrue((f.root/'state/poison').exists())
                if stage not in self.NATIVE:self.assertIsNone(native)
                elif bad.endswith('-helper'):self.assertEqual(native,{k:None for k in NativeStatusDecoderControls.KEYS})
                else:self.assertEqual(native,dict(zip(NativeStatusDecoderControls.KEYS,(7,7,0,0))))
                self.assertNotIn('source-deployment-positive',trace)

    def test_original_commands_reads_counts_continuations_and_success_are_byte_exact(self):
        for bad in ('','a-native','b-query','c-native','d-query','e-native','f-helper','g-query',
                    'h-native','i-query','j-native','k-helper','l-query','m-native','n-query',
                    'first-then-success','g-first-then-success','i-first-then-success'):
            with self.subTest(bad=bad):
                f,new,code,reason,native,marker,trace=self.run_corridor(bad)
                _old,old,old_code,old_reason,old_native,old_marker,old_trace=self.run_corridor(bad,historical=True)
                self.assertEqual((new.returncode,new.stdout,marker,trace),(old.returncode,old.stdout,old_marker,old_trace))
                self.assertEqual(code,old_code)
                self.assertIsNone(old_reason);self.assertIsNone(old_native)
                if new.returncode==0:
                    self.assertEqual((code,reason,native,marker),('',None,None,'server-dry-run-observed'))
                    self.assertFalse((f.root/'state/poison').exists())
                if bad in ('e-native','g-query'):
                    self.assertEqual(trace.count('--raw=/readyz'),2)
                    self.assertNotIn('get nodes',trace)
                if bad in ('h-native','i-query'):
                    self.assertEqual(trace.count('--raw=/readyz'),2);self.assertEqual(trace.count('get nodes'),2)

    def test_last_rejected_round_and_poisoned_next_entry_preserve_availability(self):
        for bad,stage,command_count in [('e-native','e',2),('g-query','g',2),('h-native','h',2),('i-query','i',2),('poisoned-round','e',2)]:
            f,result,code,reason,native,marker,trace=self.run_corridor(bad)
            self.assertEqual((result.returncode,code,reason),(1,'pl2.k','k1.'+stage))
            self.assertEqual(trace.count('--raw=/readyz'),command_count)
            if bad=='poisoned-round':self.assertEqual(native,{k:None for k in NativeStatusDecoderControls.KEYS})
            self.assertEqual(marker,'not-reached')
        f,result,code,reason,native,marker,trace=self.run_corridor('i-helper')
        self.assertEqual((code,reason),('pl2.k','k1.i'));self.assertIsNone(native)
        self.assertEqual(trace.count('--raw=/readyz'),1)

    def test_actual_finite_recorder_scope_interruptions_reset_and_first_snapshot(self):
        keys=NativeStatusDecoderControls.KEYS
        for stage in self.STAGES:
            f=self.fixture()
            setup=f'rootful_intent=execution-v1 mode=work postlog_site=k k_site={stage}\n'
            setup+='postlog_rc=7 postlog_tool=7 postlog_out=0 postlog_err=0\n'
            setup+='trap \'printf "%s\\n%s\\n%s\\n" "$postlog_failure" "$postlog_reason" "$postlog_native" > "$root/result"\' EXIT\n'
            self.assertEqual(f.child(setup+'fail\n').finish().returncode,1)
            code,reason,record=(f.root/'result').read_text().splitlines()
            self.assertEqual((code,json.loads(reason)),('pl2.k','k1.'+stage))
            self.assertEqual(json.loads(record),dict(zip(keys,(7,7,0,0))) if stage in self.NATIVE else None)
        for stage in ('','A','aa','a\n','o','0','unlabelled'):
            import shlex
            f=self.fixture();result=f.child('rootful_intent=execution-v1 mode=work postlog_site=k k_site='+shlex.quote(stage)+
                '\ntrap \'printf "%s\\n%s\\n" "$postlog_failure" "$postlog_reason" > "$root/result"\' EXIT\nfail\n').finish()
            self.assertEqual(result.returncode,1);self.assertEqual((f.root/'result').read_text(),'pl2.k\nnull\n')
        cases=[('false',''),('kill -TERM "$BASHPID"',''),('(fail) || :',''),('value=$(fail) || :',''),
               ('fail','mode=cleanup'),('fail','rootful_admitted=0'),('fail','rootful_intent=prerequisite-v1')]
        for action,scope in cases:
            f=self.fixture();body='rootful_intent=execution-v1 mode=work postlog_site=k k_site=a\n'+scope+'\n'
            body+='trap \'printf "%s\\n%s\\n%s\\n" "$postlog_failure" "$postlog_reason" "$postlog_native" > "$root/result"\' EXIT\ntrap \'exit 1\' ERR HUP INT TERM\n'
            f.child(body+action+'\n').finish()
            self.assertEqual((f.root/'result').read_text(),'\nnull\nnull\n')
        f=self.fixture();f.definitions='export k_site=m\n'+f.definitions
        self.assertNotIn(b'declare -x',f.run_body('[[ -z $k_site ]]\ndeclare -p k_site\n'))
        f=self.fixture();f.definitions=f.definitions.replace('  exit 1\n}','  return 1\n}',1)
        body='''rootful_intent=execution-v1 mode=work postlog_site=k k_site=a
postlog_rc=7 postlog_tool=7 postlog_out=0 postlog_err=0
fail || :
first_reason=$postlog_reason first_native=$postlog_native
k_site=n postlog_rc=125 postlog_tool=0 postlog_out=1 postlog_err=0
fail || :
[[ $postlog_failure == pl2.k && $postlog_reason == "$first_reason" && $postlog_native == "$first_native" ]]
'''
        self.assertEqual(f.run_body(body),b'')

    def test_real_finish_preserves_first_k_snapshot_or_earlier_failure_and_delete_status(self):
        finish='finish() {\n'+receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())))).split('\nfinish() {\n',1)[1].split('\ntrap finish EXIT',1)[0]+'\n'
        for earlier in ('','pl1.r','pl2.a'):
            for delete in (0,19):
                f=self.fixture();body='''rootful_intent=execution-v1 mode=work postlog_site=k k_site=a
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=owned
postlog_rc=7 postlog_tool=7 postlog_out=0 postlog_err=0
pace_close() { [[ -z $postlog_site ]]; }
remember() { [[ -z $postlog_site ]]; }
emit_evidence() { [[ -z $postlog_site ]]; evidence_json='{}'; }
emit_logs_evidence() { [[ -z $postlog_site ]]; logs_json='{}'; }
native() { [[ -z $postlog_site && $mode == cleanup ]] || exit 88; k_site=m; postlog_rc=125 postlog_tool=0 postlog_out=1 postlog_err=0; last_tool_status=$delete; return "$delete"; }
'''+f'delete={delete} postlog_failure={earlier}\n'
                if earlier=='pl1.r':body+='postlog_reason=\'"memory"\'\n'
                result=f.child(body+finish+'trap finish EXIT\nfail\n').finish();wire=json.loads(result.stdout)
                self.assertEqual((result.returncode,wire['schema'],wire['kind_delete_status']),(1,rootful.RESULT_V9,delete))
                self.assertEqual(wire['postlog_failure'],earlier or 'pl2.k')
                self.assertEqual(wire['postlog_reason'],'memory' if earlier=='pl1.r' else None if earlier else 'k1.a')
                self.assertEqual(wire['postlog_native'],None if earlier else dict(zip(NativeStatusDecoderControls.KEYS,(7,7,0,0))))

    def test_exact_inverse_old_history_patterns_enrollment_and_no_action_delta(self):
        import hashlib
        source=receiver_before_i_atoms(receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))));frozen=receiver_before_k_stage(source)
        self.assertEqual((len(source.encode()),hashlib.sha256(source.encode()).hexdigest()),(K_STAGE_SOURCE_BYTES,K_STAGE_SOURCE))
        self.assertEqual((len(frozen.encode()),hashlib.sha256(frozen.encode()).hexdigest()),(65359,OWNED_CGROUP_SOURCE))
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        self.assertLessEqual(len(source.encode()),65408);self.assertLessEqual(len(source.encode()),65536)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)
        current=self.segment();old=self.segment(frozen)
        for stage in self.STAGES:
            import re
            current,count=re.subn(r'^[ \t]*k_site='+stage+r'\n','',current,flags=re.M)
            self.assertEqual(count,1)
        self.assertEqual(current.count(' || {\n  postlog_rc=$?\n  fail\n}'),4)
        self.assertEqual(current.count(' || {\n    postlog_rc=$?\n    continue\n  }'),2)
        current=current.replace(' || {\n  postlog_rc=$?\n  fail\n}',' || fail').replace(' || {\n    postlog_rc=$?\n    continue\n  }',' || continue')
        self.assertEqual(current,old)
        self.assertEqual(len(receiver_before_owned_cgroup(frozen).encode()),65354)
        for first,second in [('k_site=a','k_site=b'),('postlog_rc=null postlog_tool=null','postlog_rc=0 postlog_tool=null'),('maximum=680','maximum=681')]:
            with self.assertRaises(AssertionError):receiver_before_k_stage(source.replace(first,second,1))
        for bad in (frozen,source+'\n',None,b'',False):
            with self.assertRaises(AssertionError):receiver_before_k_stage(bad)


class KStageNativeControls(unittest.TestCase):
    """Original native command/capture waits with fixed DATA, no native tooling."""
    current_v9=True
    stage='a'
    round_case=''
    validation=''

    def fixture(self,*,historical=False):
        f,segment=NativeStatusReceiverControls.fixture(self,historical=historical)
        segment=segment.replace('postlog_site=n\n','postlog_site=k k_site='+self.stage+'\n',1)
        segment=segment.replace('postlog_rc=null postlog_tool=null postlog_out=null postlog_err=null\n','',1)
        segment=segment.rstrip('\n')+'\n'
        if self.round_case:
            call=segment.split('\n',1)[1]
            original_false='  postlog_rc=$?\n  fail\n}'
            self.assertEqual(call.count(original_false),1)
            call=call.replace(original_false,'  postlog_rc=$?\n  continue\n}',1)
            if self.round_case=='latest':prefix='command_result=$((round+6))\n'
            elif self.round_case=='success':prefix='command_result=$((round==1 ? 7 : 0))\n'
            else:prefix=''
            segment='postlog_site=k k_site=e\nfor round in 1 2; do\n'+prefix+call+'break\ndone\n'
            if self.round_case!='success':segment+='fail\n'
        segment='trap \'printf "%s\\n%s\\n" "$postlog_failure" "$postlog_native" > "$root/result"; printf "%s" "$postlog_reason" > "$root/k-reason"\' EXIT\n'+segment
        if self.validation: segment+='postlog_site=k k_site='+self.validation+'\nfail\n'
        return f,segment

    def run_case(self,*args,**kwargs):
        return NativeStatusReceiverControls.run_case(self,*args,**kwargs)

    def test_six_native_groups_obtain_only_real_command_and_collector_wait_statuses(self):
        keys=NativeStatusDecoderControls.KEYS
        for stage in 'acehjm':
            self.stage=stage
            for command,stdout,stderr in ((7,0,0),(255,0,0),(0,1,0),(0,0,255),(19,1,255)):
                result,code,record,trace,f=self.run_case(command=command,stdout=stdout,stderr=stderr)
                self.assertEqual((result.returncode,code),(1,'pl2.k'))
                self.assertEqual(json.loads((f.root/'k-reason').read_text()),'k1.'+stage)
                self.assertEqual(record,dict(zip(keys,(125 if stdout or stderr else command,command,stdout,stderr))))
                self.assertEqual(trace.count('command\n'),1)

    def test_early_guard_fresh_null_and_final_clock_known_triple_are_distinct(self):
        keys=NativeStatusDecoderControls.KEYS
        for stage in 'acehjm':
            self.stage=stage
            for scenario in ('domain','state-missing','poison','take-0','grant-1','uptime'):
                result,code,record,trace,f=self.run_case(scenario)
                self.assertEqual((result.returncode,code,record),(1,'pl2.k',{k:None for k in keys}))
                self.assertEqual(json.loads((f.root/'k-reason').read_text()),'k1.'+stage)
                self.assertNotIn('command\n',trace)
            for scenario in ('after-uptime','after-deadline','after-form','after-read'):
                result,code,record,trace,f=self.run_case(scenario,command=19)
                self.assertEqual((result.returncode,code),(1,'pl2.k'))
                self.assertEqual(record,dict(zip(keys,(None,19,0,0))))

    def test_successful_native_cannot_supply_validation_failure_status(self):
        for stage in 'bdfgikln':
            self.validation=stage
            result,code,record,trace,f=self.run_case()
            self.assertEqual((result.returncode,code,record),(1,'pl2.k',None))
            self.assertEqual(json.loads((f.root/'k-reason').read_text()),'k1.'+stage)
            self.assertEqual(trace.count('command\n'),1)

    def test_actual_next_round_freshness_success_and_poison_before_second_launch(self):
        self.stage='e'
        for case in ('latest','success','poison'):
            self.round_case=case
            result,code,record,trace,f=self.run_case(stdout=1 if case=='poison' else 0)
            self.assertEqual(trace.count('command\n'),1 if case=='poison' else 2)
            if case=='success':
                self.assertEqual((result.returncode,code,record),(0,'',None));self.assertEqual((f.root/'k-reason').read_text(),'null')
            else:
                self.assertEqual((result.returncode,code),(1,'pl2.k'))
                self.assertEqual(json.loads((f.root/'k-reason').read_text()),'k1.e')
                self.assertEqual(record,{k:None for k in NativeStatusDecoderControls.KEYS} if case=='poison' else dict(zip(NativeStatusDecoderControls.KEYS,(8,8,0,0))))


class KStageDecoderControls(unittest.TestCase):
    def expected_summary(self,value):
        expected=deepcopy(value)
        raw=expected.pop('evidence')
        encoded=vm.encode(raw)
        expected['evidence']={'sha256':vm.digest(encoded),'bytes':len(encoded),
                             'raw_bytes':sum(record['bytes'] for record in raw['files'].values()),
                             'files':sorted(raw['files'])}
        return expected

    def bundle(self,stage='a'):
        config,value,rows=PostnodeDecoderControls.bundle(self,'pl2.k')
        value.update(schema=rootful.RESULT_V9,postlog_reason='k1.'+stage,
                     postlog_native={k:None for k in NativeStatusDecoderControls.KEYS} if stage in 'acehjm' else None)
        return config,value,rows

    def test_fourteen_closed_groups_status_forms_and_independent_delete_failure(self):
        keys=NativeStatusDecoderControls.KEYS
        for stage in 'abcdefghijklmn':
            config,value,_=self.bundle(stage)
            forms=[None] if stage not in 'acehjm' else [dict(zip(keys,x)) for x in ((None,None,None,None),(None,0,0,0),(None,19,0,0),(7,7,0,0),(255,255,0,0),(125,0,1,0),(125,19,0,255),(125,0,255,255))]
            for record in forms:
                for delete in (0,19):
                    value.update(postlog_native=record,kind_delete_status=delete)
                    checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
                    self.assertEqual(checked,self.expected_summary(value))
                    self.assertRaises(vm.Refusal,rootful.wire_record,vm.encode(value)+b'\n',config)

    def test_wrong_reason_native_type_partial_range_relationship_and_scope_refuse(self):
        config,value,_=self.bundle();keys=NativeStatusDecoderControls.KEYS
        changes=[('postlog_reason',x) for x in (None,'','k1.o','k1.A','k1.aa','k1.a\n','memory',False,0,[],{})]
        changes += [('schema',rootful.RESULT_V8),('schema','kubernetes-lens-owned-rootful-result-v12'),
                    ('state','source-deployment-positive'),('kind_create_status',False),('kind_create_status',1),
                    ('source_deployment','server-dry-run-observed'),('postlog_failure',None),('postlog_failure','pl2.a')]
        for key,altered in changes:
            bad=deepcopy(value);bad[key]=altered
            with self.subTest(key=key,value=altered),self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for stage in 'abcdefghijklmn':
            config,value,_=self.bundle(stage)
            bad=deepcopy(value);bad['postlog_native']=None if stage in 'acehjm' else dict(zip(keys,(7,7,0,0)))
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        config,value,_=self.bundle()
        invalid=[False,0,[],{},dict(zip(keys[:3],(7,7,0))),dict(zip(keys,(7,7,0,0)),extra=0),dict(zip(keys,(0,0,0,0))),dict(zip(keys,(7,8,0,0))),dict(zip(keys,(7,7,1,0))),dict(zip(keys,(None,0,1,0)))]
        invalid += [dict(zip(keys,x)) for x in ((None,0,None,0),(7,None,None,None),(256,0,0,0),(7,-1,0,0),(True,1,0,0),(7,7,False,0))]
        for record in invalid:
            bad=deepcopy(value);bad['postlog_native']=record
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for key in ('postlog_failure','postlog_reason','postlog_native'):
            bad=deepcopy(value);bad.pop(key)
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        bad=deepcopy(value);bad['k_substage']='k1.a'
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        bad=deepcopy(value);bad['evidence']['files'].pop('node-inspect')
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for key,altered in (('startup_marker',False),('wrapper_observed_child_wait_status',0),('signal_cause','SIGKILL')):
            bad=deepcopy(value);bad['logs'][key]=altered
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)

    def test_v8_remains_null_and_v9_old_codes_and_positive_results_keep_meanings(self):
        for code in sorted(rootful.POSTNODE_FAILURES):
            config,old,_=PostnodeDecoderControls.bundle(self,code)
            self.assertEqual(rootful.wire_record(vm.encode(old)+b'\n',config,allow_failure=True),self.expected_summary(old))
            for key,value in (('postlog_reason','k1.a'),('postlog_native',{k:None for k in NativeStatusDecoderControls.KEYS})):
                bad=deepcopy(old);bad[key]=value
                with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
            if code!='pl2.k':
                old['schema']=rootful.RESULT_V9
                self.assertEqual(rootful.wire_record(vm.encode(old)+b'\n',config,allow_failure=True),self.expected_summary(old))
        config,positive,_=DirectExecDecoderControls.bundle(self,complete=True)
        positive.update(schema=rootful.RESULT_V9,postlog_failure=None,postlog_native=None,postlog_reason=None)
        self.assertEqual(rootful.wire_record(vm.encode(positive)+b'\n',config),self.expected_summary(positive))
        for code in sorted(rootful.POSTLOG_FAILURES):
            config,old,_=ResourceReasonDecoderControls.bundle(self,code=code) if code=='pl1.r' else NativeStatusDecoderControls.bundle(self,code=code)
            old['schema']=rootful.RESULT_V9
            if code=='pl1.r':old['postlog_reason']='memory'
            else:old['postlog_reason']=None
            self.assertEqual(rootful.wire_record(vm.encode(old)+b'\n',config,allow_failure=True),self.expected_summary(old))

    def test_exact_private_durability_and_public_descriptor_redaction(self):
        for stage in 'abcdefghijklmn':
            config,value,_=self.bundle(stage);wire=vm.encode(value)+b'\n'
            with tempfile.TemporaryDirectory(prefix='k-stage-private-') as directory:
                descriptor=rootful.durable_wire(wire,config,Path(directory),vm.Budget(time.monotonic()+30,10))
                self.assertEqual((Path(directory)/descriptor['name']).read_bytes(),wire)
                for protected in (b'postlog_reason',b'postlog_native',b'k1.',b'pl2.k',b'SYNTHETIC_ONLY'):
                    self.assertNotIn(protected,vm.encode(descriptor))



class ReadinessAtomReceiverControls(unittest.TestCase):
    """Actual V10 admission/caller/finish, all tool/input DATA is mandatory fixed."""
    def fixture(self):
        f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
        f.definitions=receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))).split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={f.root} stage={f.root}/stage')
        anchor='  "$@"\n}\nu() {'
        self.assertEqual(f.definitions.count(anchor),1)
        # Original dispatch-admission marker/guards remain before the fixed command.
        f.definitions=f.definitions.replace(anchor,'  fixed_jq "$@"\n}\nu() {',1)
        return f

    def loop(self):
        source=receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())));self.assertEqual(source.count('\nready=0\n'),1)
        loop='ready=0\n'+source.split('\nready=0\n',1)[1].split('k_site=j\n',1)[0]
        self.assertEqual(loop.count('native '),2)
        self.assertEqual(loop.count('u /usr/bin/jq '),1)
        return loop

    def setup(self,first=64,second=64,refusal=''):
        return r'''rootful_intent=execution-v1 mode=work postlog_site=k
node=owned-node patch=1.20.15 KUBECONFIG=$root/kubeconfig
trap 'printf "%s\n%s\n%s\n" "$postlog_failure" "$postlog_reason" "$postlog_native" > "$root/diagnostic"' EXIT
trap 'exit 1' ERR HUP INT TERM
native() {
  [[ $3 == "$stage/kubectl" ]] || exit 88
  case "$*" in
    *--raw=/readyz*) out=$root/ready; printf 'ok\n' > "$out"; printf 'ready:%s\n' "$_round" >> "$root/trace" ;;
    *'get nodes'*) out=$root/nodes; printf '{}\n' > "$out"; printf 'nodes:%s\n' "$_round" >> "$root/trace" ;;
    *) exit 88 ;;
  esac
}
fixed_jq() {
  [[ $# == 10 && $1 == /usr/bin/jq && $2 == -en && $3 == --arg && $4 == node && $5 == owned-node && $6 == --arg && $7 == patch && $8 == v1.20.15 && ${10} == "$out" ]] || exit 88
  printf 'jq:%s\n' "$_round" >> "$root/trace"
  if [[ $refusal == dispatch-interrupt ]]; then kill -TERM "$BASHPID"; fi
  if [[ $_round == 1 ]]; then return "$first"; else return "$second"; fi
}
'''+f'first={first} second={second} refusal={refusal}\n'

    def run_case(self,first=64,second=64,*,refusal='',prefix='',after=''):
        f=self.fixture();body=self.setup(first,second,refusal)
        if refusal=='grant':body+='grant_utility() { return 1; }\n'
        elif refusal=='ticket':body+='grant_utility() { utility_ticket=invalid; }\n'
        elif refusal=='binding':body+='grant_utility() { utility_ticket=utility-work.0; printf wrong > "$credits/$utility_ticket"; }\n'
        elif refusal=='missing':body+='grant_utility() { utility_ticket=utility-work.0; }\n'
        elif refusal=='directory':body+='grant_utility() { utility_ticket=utility-work.0; /usr/bin/mkdir "$credits/$utility_ticket"; }\n'
        elif refusal=='symlink':
            (f.root/'state/credits/utility-work.0').symlink_to(f.root/'owner')
            body+='grant_utility() { utility_ticket=utility-work.0; }\n'
        elif refusal=='used':body+='printf existing > "$credits/used.utility-work.0"\n'
        elif refusal=='second-grant':
            f.definitions=f.definitions.replace('grant_utility() {','source_grant_utility() {',1)
            body+='grant_utility() { [[ $_round != 2 ]] || return 1; source_grant_utility; }\n'
        result=f.child(body+prefix+self.loop()+after).finish()
        code,reason,native=(f.root/'diagnostic').read_text().splitlines()
        trace=(f.root/'trace').read_text().splitlines() if (f.root/'trace').exists() else []
        return f,result,code,json.loads(reason),json.loads(native),trace

    def test_each_atom_and_opaque_return_uses_decisive_round_without_extra_calls(self):
        for status,atom in [(64,'c'),(65,'n'),(66,'v'),(67,'r'),(1,'e.1'),(2,'e.2'),(3,'e.3'),(4,'e.4'),(5,'e.5'),(126,'e.126'),(127,'e.127'),(255,'e.255')]:
            with self.subTest(status=status):
                _f,result,code,reason,native,trace=self.run_case(status,status)
                self.assertEqual((result.returncode,code,reason,native),(1,'pl2.k','k2.i.2.'+atom,None))
                self.assertEqual(trace,['ready:1','nodes:1','jq:1','ready:2','nodes:2','jq:2'])

    def test_real_utility_refusals_precede_dispatch_and_round_reset_prevents_borrowing(self):
        for refusal in ('grant','ticket','missing','directory','symlink','binding','used'):
            f,result,code,reason,native,trace=self.run_case(refusal=refusal)
            self.assertEqual((result.returncode,code,reason,native),(1,'pl2.k','k2.i.1.p',None))
            self.assertEqual(trace,['ready:1','nodes:1'])
            self.assertTrue((f.root/'state/poison').exists())
        _f,result,code,reason,native,trace=self.run_case(67,64,refusal='second-grant')
        self.assertEqual((result.returncode,code,reason,native),(1,'pl2.k','k2.i.2.p',None))
        self.assertEqual(trace,['ready:1','nodes:1','jq:1','ready:2','nodes:2'])

    def test_first_round_false_then_success_has_no_committed_failure(self):
        for first in (0,64,65,66,67,5):
            f,result,code,reason,native,trace=self.run_case(first,0)
            self.assertEqual((result.returncode,code,reason,native),(0,'',None,None))
            self.assertEqual(len(trace),3 if first==0 else 6)
            self.assertFalse((f.root/'state/poison').exists())

    def test_prearmed_dispatched_and_postreturn_interruptions_never_invent_failure(self):
        for scope in ('rootful_admitted=0','rootful_intent=other','mode=cleanup',
                      'postlog_site=n','k_site=a'):
            f=self.fixture()
            body='rootful_intent=execution-v1 mode=work postlog_site=k k_site=i\n'+scope+'\n'
            body+='fixed_jq() { return 64; }\nif u /usr/bin/jq; then exit 88; fi\n[[ $i_admitted == 0 ]]\n'
            self.assertEqual(f.run_body(body),b'')
        f=self.fixture()
        body='rootful_intent=execution-v1 mode=work postlog_site=k k_site=i\n'
        body+='fixed_jq() { return 64; }\n(if u /usr/bin/jq; then exit 88; fi; [[ $i_admitted == 0 ]])\n'
        self.assertEqual(f.run_body(body),b'')
        f=self.fixture();body=self.setup()+'''k_site=i i_round=1 i_admitted=0 i_return=null
kill -TERM "$BASHPID"
'''
        self.assertEqual(f.child(body).finish().returncode,1)
        self.assertEqual((f.root/'diagnostic').read_text(),'\nnull\nnull\n')
        f,result,code,reason,native,trace=self.run_case(refusal='dispatch-interrupt')
        self.assertEqual((result.returncode,code,reason,native),(1,'',None,None))
        f=self.fixture();loop=self.loop().replace('done\n((ready)) || fail','done\nkill -TERM "$BASHPID"\n((ready)) || fail',1)
        self.assertEqual(f.child(self.setup()+loop).finish().returncode,1)
        self.assertEqual((f.root/'diagnostic').read_text(),'\nnull\nnull\n')

    def test_first_snapshot_and_unavailable_or_malformed_cache_do_not_promote(self):
        f=self.fixture();f.definitions=f.definitions.replace('  exit 1\n}','  return 1\n}',1)
        body='''rootful_intent=execution-v1 mode=work postlog_site=k k_site=i
i_round=1 i_admitted=0 i_return=null
fail || :
first=$postlog_reason
i_round=2 i_admitted=1 i_return=67
fail || :
[[ $postlog_reason == "$first" && $postlog_reason == '"k2.i.1.p"' ]]
'''
        self.assertEqual(f.run_body(body),b'')
        for state in ('i_round=0 i_admitted=0 i_return=null','i_round=1 i_admitted=1 i_return=null',
                      'i_round=1 i_admitted=0 i_return=64','i_round=1 i_admitted=1 i_return=0',
                      'i_round=1 i_admitted=1 i_return=064','i_round=1 i_admitted=1 i_return=256'):
            f=self.fixture();body=self.setup()+f'k_site=i {state}\nfail\n'
            self.assertEqual(f.child(body).finish().returncode,1)
            self.assertEqual((f.root/'diagnostic').read_text(),'pl2.k\n"k1.i"\nnull\n')
        f=self.fixture();f.definitions='export i_round=2 i_admitted=1 i_return=67\n'+f.definitions
        self.assertNotIn(b'declare -x',f.run_body('[[ $i_round == 0 && $i_admitted == 0 && $i_return == null ]]\ndeclare -p i_round i_admitted i_return\n'))

    def test_real_finish_preserves_atom_success_earlier_failure_and_delete_outcome(self):
        finish='finish() {\n'+receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()))).split('\nfinish() {\n',1)[1].split('\ntrap finish EXIT',1)[0]+'\n'
        for success,earlier in ((False,''),(True,''),(False,'pl1.r')):
            for delete in (0,19):
                f=self.fixture();body=self.setup(0 if success else 66,0 if success else 66)+f'''created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 cluster=owned delete={delete}
pace_close() {{ [[ -z $postlog_site ]]; }}
remember() {{ [[ -z $postlog_site ]]; }}
emit_evidence() {{ evidence_json='{{}}'; }}
emit_logs_evidence() {{ logs_json='{{}}'; }}
'''+finish+'trap finish EXIT\n'
                # Rename only the fixed native DATA function, retaining work dispatch.
                body=body.replace('native() {','work_native() {',1)
                body+='''native() {
  if [[ $mode == cleanup ]]; then
    [[ -z $postlog_site ]] || exit 88
    i_round=1 i_admitted=1 i_return=67
    last_tool_status=$delete
    return "$delete"
  fi
  work_native "$@"
}
'''
                if earlier:body+='postlog_failure=pl1.r postlog_reason=\'"memory"\'\n'
                result=f.child(body+self.loop()+('source_status=server-dry-run-observed\nexit 0\n' if success else '')).finish();wire=json.loads(result.stdout)
                self.assertEqual(wire['schema'],rootful.RESULT_V10)
                self.assertEqual(wire['kind_delete_status'],delete)
                self.assertEqual(wire['postlog_failure'],earlier or (None if success else 'pl2.k'))
                self.assertEqual(wire['postlog_reason'],'memory' if earlier else None if success else 'k2.i.2.v')
                self.assertIsNone(wire['postlog_native'])
                self.assertEqual(result.returncode,0 if success and delete==0 else 1)

    def test_strict_v10_inverse_reaches_frozen_v9_and_all_old_history_without_repinning(self):
        import hashlib
        source=receiver_before_ready_reason(receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())));old=receiver_before_i_atoms(source)
        self.assertEqual((len(source.encode()),hashlib.sha256(source.encode()).hexdigest()),(I_ATOM_SOURCE_BYTES,I_ATOM_SOURCE))
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),(65331,K_STAGE_SOURCE))
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        self.assertLessEqual(len(source.encode()),65408);self.assertLessEqual(len(source.encode()),65536)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)
        self.assertEqual(len(receiver_before_k_stage(old).encode()),65359)
        for first,second in [('i_admitted=0','i_admitted=1'),('catch 5','catch 64'),('i_return=$?','i_return=64'),('maximum=680','maximum=681')]:
            with self.assertRaises(AssertionError):receiver_before_i_atoms(source.replace(first,second,1))
        for bad in (old,source+'\n',None,b'',False):
            with self.assertRaises(AssertionError):receiver_before_i_atoms(bad)


class ReadinessAtomDecoderControls(unittest.TestCase):
    def bundle(self,reason='k2.i.2.c'):
        config,value,rows=KStageDecoderControls.bundle(self,'i')
        value.update(schema=rootful.RESULT_V10,postlog_reason=reason,postlog_native=None)
        return config,value,rows

    def test_all_finite_pre_atom_and_error_tokens_keep_full_expected_summary(self):
        self.assertEqual(len(rootful.I_ATOM_REASONS),512)
        for reason in sorted(rootful.I_ATOM_REASONS):
            config,value,_=self.bundle(reason)
            for delete in (0,19):
                value['kind_delete_status']=delete
                checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
                self.assertEqual(checked,KStageDecoderControls.expected_summary(self,value))
                with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config)

    def test_strict_range_scope_types_admission_tokens_and_old_schemas_refuse(self):
        config,value,_=self.bundle()
        invalid=(None,False,0,[],{},'', 'k2.i.0.p','k2.i.3.p','k2.i.1.P','k2.i.1.e.0',
                 'k2.i.1.e.256','k2.i.1.e.064','k2.i.1.e.64','k2.i.2.e.65','k2.i.2.e.66','k2.i.2.e.67','k2.i.1.c\n')
        for reason in invalid:
            bad=deepcopy(value);bad['postlog_reason']=reason
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for key,changed in [('schema',rootful.RESULT_V9),('schema','kubernetes-lens-owned-rootful-result-v12'),
                            ('postlog_failure','pl2.a'),('postlog_failure',None),('kind_create_status',False),
                            ('state','source-deployment-positive'),('source_deployment','server-dry-run-observed'),
                            ('postlog_native',{k:None for k in NativeStatusDecoderControls.KEYS})]:
            bad=deepcopy(value);bad[key]=changed
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        bad=deepcopy(value);bad['evidence']['files'].pop('node-inspect')
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        for key in ('postlog_failure','postlog_native','postlog_reason'):
            bad=deepcopy(value);bad.pop(key)
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)

    def test_v10_success_unknown_i_and_old_meanings_keep_original_domains(self):
        config,value,_=KStageDecoderControls.bundle(self,'i');value['schema']=rootful.RESULT_V10
        self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True),KStageDecoderControls.expected_summary(self,value))
        config,value,_=DirectExecDecoderControls.bundle(self,complete=True)
        value.update(schema=rootful.RESULT_V10,postlog_failure=None,postlog_native=None,postlog_reason=None)
        self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config),KStageDecoderControls.expected_summary(self,value))
        for code in sorted(rootful.POSTLOG_FAILURES):
            config,value,_=ResourceReasonDecoderControls.bundle(self,code=code)
            value['schema']=rootful.RESULT_V10
            self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True),KStageDecoderControls.expected_summary(self,value))

    def test_durable_bytes_and_public_descriptor_do_not_expose_atom_or_error(self):
        for reason in ('k2.i.1.p','k2.i.2.c','k2.i.2.n','k2.i.2.v','k2.i.2.r','k2.i.2.e.5'):
            config,value,_=self.bundle(reason);raw=vm.encode(value)+b'\n'
            with tempfile.TemporaryDirectory(prefix='readiness-atom-private-') as directory:
                parent=Path(directory);descriptor=rootful.durable_wire(raw,config,parent,vm.Budget(time.monotonic()+30,10))
                self.assertEqual((parent/descriptor['name']).read_bytes(),raw)
                for protected in (b'k2.i.',b'postlog_reason',b'postlog_native',b'PRIVATE_NODE_METADATA'):
                    self.assertNotIn(protected,vm.encode(descriptor))


class ReadyReasonReceiverControls(unittest.TestCase):
    """Actual V11 guarded dispatch/caller, fixed command DATA; never executes jq."""
    def fixture(self):
        f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
        f.definitions=receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text())).split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={f.root} stage={f.root}/stage')
        anchor='  "$@"\n}\nu() {'
        self.assertEqual(f.definitions.count(anchor),1)
        f.definitions=f.definitions.replace(anchor,'  fixed_jq "$@"\n}\nu() {',1)
        return f

    def loop(self):
        source=receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()));self.assertEqual(source.count('\nready=0\n'),1)
        return 'ready=0\n'+source.split('\nready=0\n',1)[1].split('k_site=j\n',1)[0]

    def run_case(self,*args,**kwargs):
        control=ReadinessAtomReceiverControls()
        control.fixture=self.fixture;control.loop=self.loop
        return control.run_case(*args,**kwargs)

    def test_new_obtained_exit_classes_and_opaque_returns_keep_exact_original_trace(self):
        for code,token in [(64,'c'),(65,'n'),(66,'v'),(67,'r'),(68,'x.68'),(69,'x.69'),
                           (1,'x.1'),(5,'x.5'),(70,'x.70'),(127,'x.127'),(255,'x.255')]:
            _f,result,failure,reason,native,trace=self.run_case(code,code)
            self.assertEqual((result.returncode,failure,reason,native),(1,'pl2.k','k3.i.2.'+token,None))
            self.assertEqual(trace,['ready:1','nodes:1','jq:1','ready:2','nodes:2','jq:2'])
        _f,result,failure,reason,native,trace=self.run_case(69,0)
        self.assertEqual((result.returncode,failure,reason,native),(0,'',None,None))
        self.assertEqual(trace,['ready:1','nodes:1','jq:1','ready:2','nodes:2','jq:2'])

    def test_fresh_refusal_and_interruptions_never_borrow_marker_or_atom(self):
        for refusal in ('grant','ticket','missing','directory','symlink','binding','used'):
            _f,result,failure,reason,native,trace=self.run_case(refusal=refusal)
            self.assertEqual((result.returncode,failure,reason,native),(1,'pl2.k','k3.i.1.p',None))
            self.assertEqual(trace,['ready:1','nodes:1'])
        _f,result,failure,reason,native,trace=self.run_case(69,68,refusal='second-grant')
        self.assertEqual((result.returncode,failure,reason,native),(1,'pl2.k','k3.i.2.p',None))
        self.assertEqual(trace,['ready:1','nodes:1','jq:1','ready:2','nodes:2'])
        _f,result,failure,reason,native,_trace=self.run_case(refusal='dispatch-interrupt')
        self.assertEqual((result.returncode,failure,reason,native),(1,'',None,None))

    def test_program_seal_source_inverse_and_original_budgets_are_independent(self):
        import hashlib,re
        source=receiver_before_node_wait(receiver_before_capture_size(SCRIPT.read_text()));old=receiver_before_ready_reason(source)
        self.assertEqual((len(source.encode()),hashlib.sha256(source.encode()).hexdigest()),
                         (READY_REASON_SOURCE_BYTES,READY_REASON_SOURCE))
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),
                         (65233,'9cd7ada881b04eef1283cd02dde3989a3a493dfb4a977d7c610d9316694d1d5b'))
        self.assertEqual(receiver_before_i_atoms(old).encode().__len__(),65331)
        program=re.search(r"u /usr/bin/jq -en --arg node .*? '(def classify:.*?)' \"\$out\"",source).group(1)
        self.assertEqual(hashlib.sha256(program.encode()).hexdigest(),'4e19d9041f8c1c9c0f38ad66d47b1bba0dfde1fc2b29c38f22290fc827ddf4a1')
        for literal in ('maximum=680','maximum=64','max=70','max=5','take sentinel 150','UPTIME + 1680','UPTIME + 1800','--wait 0s'):
            self.assertEqual(source.count(literal),old.count(literal))
        self.assertEqual(source.count('u /usr/bin/jq '),old.count('u /usr/bin/jq '))
        self.assertEqual(source.count('native '),old.count('native '))
        self.assertLessEqual(len(source.encode()),65408);self.assertLessEqual(len(source.encode()),65536)
        for changed in (source+'\n',source.replace('strings|contains','tostring|contains',1),source.replace('i_return=$?','i_return=68',1)):
            with self.assertRaises(AssertionError):receiver_before_ready_reason(changed)
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)

    def test_first_snapshot_preserves_new_class_across_later_return_and_cleanup_state(self):
        f=self.fixture();f.definitions=f.definitions.replace('  exit 1\n}','  return 1\n}',1)
        body='''rootful_intent=execution-v1 mode=work postlog_site=k k_site=i
i_round=1 i_admitted=1 i_return=68
fail || :
first=$postlog_reason
i_round=2 i_return=69
fail || :
[[ $postlog_reason == "$first" && $postlog_reason == '"k3.i.1.x.68"' ]]
mode=cleanup k_site=a i_return=5
fail || :
[[ $postlog_reason == "$first" ]]
'''
        self.assertEqual(f.run_body(body),b'')


class ReadyReasonDecoderControls(unittest.TestCase):
    def bundle(self,reason='k3.i.2.x.68'):
        config,value,rows=ReadinessAtomDecoderControls.bundle(self)
        value.update(schema=rootful.RESULT_V11,postlog_reason=reason,postlog_native=None)
        return config,value,rows

    def test_v11_fixed_classes_opaque_exits_and_delete_failure_are_private_exact(self):
        self.assertEqual(len(rootful.V11_I_REASONS),512)
        for reason in ('k3.i.1.p','k3.i.2.c','k3.i.2.n','k3.i.2.v','k3.i.2.r',
                       'k3.i.1.x.68','k3.i.2.x.69','k3.i.2.x.5','k3.i.2.x.70','k3.i.2.x.255'):
            config,value,_rows=self.bundle(reason)
            for delete in (0,19):
                value['kind_delete_status']=delete
                self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True),
                                 KStageDecoderControls.expected_summary(self,value))
                with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config)

    def test_old_v10_exit68_69_remain_old_opaque_and_cross_version_tokens_refuse(self):
        for code in (68,69):
            config,old,_rows=ReadinessAtomDecoderControls.bundle(self,'k2.i.2.e.'+str(code))
            checked=rootful.wire_record(vm.encode(old)+b'\n',config,allow_failure=True)
            self.assertEqual((checked['schema'],checked['postlog_reason']),
                             (rootful.RESULT_V10,'k2.i.2.e.'+str(code)))
            future=deepcopy(old);future['schema']=rootful.RESULT_V11
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(future)+b'\n',config,allow_failure=True)
            _config,new,_rows=self.bundle('k3.i.2.x.'+str(code))
            for schema in (rootful.RESULT_V9,rootful.RESULT_V10):
                new['schema']=schema
                with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(new)+b'\n',config,allow_failure=True)
        config,value,_rows=self.bundle()
        for bad in ('k3.i.0.x.68','k3.i.3.x.69','k3.i.1.e.68','k3.i.1.x.068',
                    'k3.i.1.x.0','k3.i.1.x.256','k3.i.1.x.64','k3.i.1.x.67',None,True,68):
            value['postlog_reason']=bad
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)

    def test_v11_success_keeps_null_diagnostic_and_complete_original_evidence(self):
        config,value,_rows=self.bundle()
        value.update(state='source-deployment-positive',source_deployment='server-dry-run-observed',
                     kind_delete_status=0,postlog_failure=None,postlog_reason=None,postlog_native=None)
        checked=rootful.wire_record(vm.encode(value)+b'\n',config)
        self.assertEqual((checked['schema'],checked['postlog_failure'],checked['postlog_reason'],checked['postlog_native']),
                         (rootful.RESULT_V11,None,None,None))

    def test_context_types_missing_proof_and_input_spec_contract_do_not_widen(self):
        config,value,_rows=self.bundle()
        for key,changed in [('postlog_failure','pl2.a'),('kind_create_status',False),
                            ('state','source-deployment-positive'),('postlog_native',{}),
                            ('source_deployment','server-dry-run-observed')]:
            bad=deepcopy(value);bad[key]=changed
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        bad=deepcopy(value);bad['evidence']['files'].pop('node-inspect')
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config,allow_failure=True)
        evidence={key:'c'*64 for key in ('manifest_sha256','config_sha256','parent_sha256')}
        evidence.update(expanded_bytes_hashed=10,archive_bytes=3,catalogue={'blobs/sha256/'+'c'*64:{'bytes':100}})
        _files,spec=rootful.guest_files(RootfulHostControls().plan(),evidence,SCRIPT.read_bytes())
        self.assertEqual((spec['schema'],spec['kind_version'],spec['server_patch']),
                         ('kubernetes-lens-owned-rootful-v13','0.14.0','1.20.15'))
        self.assertEqual((spec['native_work_max'],spec['native_cleanup_max'],spec['output_max']),(70,5,1048576))
        self.assertEqual(rootful.reservation(),{'native':75,'output':1048576,'utilities':768,
                                              'utility_work':680,'utility_cleanup':64,'record_guards_prepaid':24})





class NodeWaitReceiverControls(unittest.TestCase):
    """V12 CURRENT source, fixed injected command/classifier DATA only."""
    def fixture(self):
        f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
        f.definitions=receiver_before_capture_size(SCRIPT.read_text()).split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={f.root} stage={f.root}/stage')
        anchor='  "$@"\n}\nu() {'
        self.assertEqual(f.definitions.count(anchor),1)
        f.definitions=f.definitions.replace(anchor,'  fixed_jq "$@"\n}\nu() {',1)
        return f

    def loop(self):
        return 'ready=0\n'+receiver_before_capture_size(SCRIPT.read_text()).split('\nready=0\n',1)[1].split('k_site=j\n',1)[0]

    def run_case(self,*,pre='',wait_status=0,node_status=0,classifier=0,refuse=False):
        f=self.fixture()
        body=r'''rootful_intent=execution-v1 mode=work postlog_site=k
node=owned-node patch=1.20.15 KUBECONFIG=$root/kubeconfig
native_count=0 slots=0 sentinels=0 utilities=0
trap 'printf "%s\n%s\n%s\n" "$postlog_failure" "$postlog_reason" "$postlog_native" > "$root/diagnostic"; printf "%s %s %s %s\n" "$native_count" "$slots" "$sentinels" "$utilities" > "$root/charges"' EXIT
trap 'exit 1' ERR HUP INT TERM
native() {
  [[ $3 == "$stage/kubectl" && $4 == --kubeconfig && $5 == "$KUBECONFIG" && ! ${pace_fd+x} ]] || exit 88
  native_count=$((native_count+1)); slots=$((slots+($1+$2)/4096)); sentinels=$((sentinels+2)); utilities=$((utilities+4))
  postlog_rc=null postlog_tool=0 postlog_out=0 postlog_err=0
  local status=0
  case "$6:$7" in
    get:--raw=/readyz)
      [[ $# == 7 && $1 == 4096 && $2 == 4096 ]] || exit 88
      printf 'ready:%s\n' "$_round" >> "$root/trace"
      out=$root/ready; printf 'ok\n' > "$out"
      if [[ $pre == body && $_round == 1 || $pre == all-body ]]; then printf 'not-ok\n' > "$out"; fi
      if [[ $pre == native && $_round == 1 || $pre == all-native ]]; then status=7; fi
      ;;
    wait:--for=condition=Ready)
      [[ $# == 10 && $1 == 4096 && $2 == 4096 && $8 == nodes && $9 == --all && ${10} == --timeout=30s ]] || exit 88
      printf 'wait:%s\n' "$_round" >> "$root/trace"
      status=$wait_status
      ;;
    get:nodes)
      [[ $# == 9 && $1 == 16384 && $2 == 4096 && $8 == -o && $9 == json ]] || exit 88
      printf 'nodes:%s\n' "$_round" >> "$root/trace"
      out=$root/nodes; printf '{}\n' > "$out"; status=$node_status
      ;;
    *) exit 88 ;;
  esac
  postlog_tool=$status
  return "$status"
}
fixed_jq() {
  [[ $# == 10 && $1 == /usr/bin/jq && $2 == -en && $3 == --arg && $4 == node && $5 == owned-node && $6 == --arg && $7 == patch && $8 == v1.20.15 && ${10} == "$out" ]] || exit 88
  printf 'jq:%s\n' "$_round" >> "$root/trace"
  utilities=$((utilities+1))
  return "$classifier"
}
'''+f'pre={pre!r} wait_status={wait_status} node_status={node_status} classifier={classifier}\n'
        if refuse:body+='grant_utility() { return 1; }\n'
        result=f.child(body+self.loop()).finish()
        code,reason,native=(f.root/'diagnostic').read_text().splitlines()
        trace=(f.root/'trace').read_text().splitlines()
        charges=tuple(map(int,(f.root/'charges').read_text().split()))
        return f,result,code,json.loads(reason),json.loads(native),trace,charges

    def test_success_and_only_prewait_transition_reaches_round2_with_independent_bound(self):
        for pre,round_no,expected in [('',1,(3,9,6,13)),('body',2,(4,11,8,17)),('native',2,(4,11,8,17))]:
            f,result,code,reason,native,trace,charges=self.run_case(pre=pre)
            self.assertEqual((result.returncode,code,reason,native),(0,'',None,None))
            prefix=['ready:1'] if round_no==1 else ['ready:1','ready:2']
            self.assertEqual(trace,prefix+[f'wait:{round_no}',f'nodes:{round_no}',f'jq:{round_no}'])
            self.assertEqual(charges,expected)
            self.assertFalse((f.root/'state/poison').exists())
        # Independent original maximum: two readyz+NodeList+classifier rounds.
        self.assertEqual((4,2*(2+5),8,2*(4+4+1)),(4,14,8,18))
        self.assertEqual((2+1+1,2*2+2+5,2*4,2*4+4+4+1),(4,11,8,17))

    def test_wait_nonzero_is_hard_refusal_and_never_reaches_nodelist(self):
        for pre in ('','body'):
            for status in (1,28,124,125,127,255):
                _f,result,code,reason,native,trace,_charges=self.run_case(pre=pre,wait_status=status)
                self.assertEqual((result.returncode,code,reason),(1,'pl2.k','k4.o'))
                self.assertEqual(native,dict(return_status=status,command_status=status,stdout_capture_status=0,stderr_capture_status=0))
                self.assertEqual(trace.count('wait:1')+trace.count('wait:2'),1)
                self.assertFalse(any(item.startswith(('nodes:','jq:')) for item in trace))

    def test_wait_success_never_accepts_rejected_classifier_or_starts_another_round(self):
        for pre in ('','body'):
            r=2 if pre else 1
            for status,atom in [(64,'c'),(65,'n'),(66,'v'),(67,'r'),(68,'x.68'),(69,'x.69'),(4,'x.4'),(5,'x.5'),(255,'x.255')]:
                _f,result,code,reason,native,trace,_charges=self.run_case(pre=pre,classifier=status)
                self.assertEqual((result.returncode,code,reason,native),(1,'pl2.k',f'k4.i.{r}.{atom}',None))
                self.assertEqual(trace[-3:],[f'wait:{r}',f'nodes:{r}',f'jq:{r}'])
                self.assertEqual(sum(item.startswith('wait:') for item in trace),1)
                self.assertEqual(sum(item.startswith('nodes:') for item in trace),1)
            _f,result,code,reason,native,trace,_charges=self.run_case(pre=pre,node_status=7)
            self.assertEqual((result.returncode,code,reason),(1,'pl2.k','k4.h'))
            self.assertEqual(native['return_status'],7);self.assertFalse(any(item.startswith('jq:') for item in trace))

    def test_unready_api_never_waits_and_classifier_utility_refusal_is_fresh(self):
        for pre,site in [('all-native','e'),('all-body','g')]:
            _f,result,code,reason,_native,trace,_charges=self.run_case(pre=pre)
            self.assertEqual((result.returncode,code,reason),(1,'pl2.k','k4.'+site))
            self.assertEqual(trace,['ready:1','ready:2'])
        _f,result,code,reason,native,trace,_charges=self.run_case(refuse=True)
        self.assertEqual((result.returncode,code,reason,native),(1,'pl2.k','k4.i.1.p',None))
        self.assertEqual(trace,['ready:1','wait:1','nodes:1'])

    def test_exact_classifier_tail_history_and_space_recovery_preserve_all_guards(self):
        import hashlib,re
        source=receiver_before_capture_size(SCRIPT.read_text());old=receiver_before_node_wait(source)
        self.assertEqual((len(source.encode()),hashlib.sha256(source.encode()).hexdigest()),(NODE_WAIT_SOURCE_BYTES,NODE_WAIT_SOURCE))
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),(65369,READY_REASON_SOURCE))
        self.assertLessEqual(len(source.encode()),65408);self.assertLessEqual(len(source.encode()),65536)
        pattern=r"u /usr/bin/jq -en --arg node .*? '(def classify:.*?)' \"\$out\""
        self.assertEqual(re.search(pattern,source).group(1),re.search(pattern,old).group(1))
        self.assertEqual(source.split('k_site=j\n',1)[1],old.split('k_site=j\n',1)[1])
        for literal in ('maximum=680','maximum=64','max=70','max=5','take sentinel 150','UPTIME + 1680','UPTIME + 1800','--wait 0s'):
            self.assertEqual(source.count(literal),old.count(literal))
        self.assertEqual([line for line in source.splitlines() if line.lstrip().startswith('#')],
                         [line for line in old.splitlines() if line.lstrip().startswith('#')])
        for changed in (source+'\n',source.replace('--timeout=30s','--timeout=31s',1),source.replace('    fail\n','    true\n',1)):
            with self.assertRaises(AssertionError):receiver_before_node_wait(changed)
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)


    def test_real_finish_preserves_first_v12_failure_and_independent_delete_status(self):
        for delete in (0,19):
            f=self.fixture()
            f.definitions=f.definitions.replace('  exit 1\n}','  return 1\n}',1)
            source=receiver_before_capture_size(SCRIPT.read_text())
            finish='finish() {\n'+source.split('\nfinish() {\n',1)[1].split('\ntrap finish EXIT',1)[0]+'\n'
            body=r'''rootful_intent=execution-v1 mode=work postlog_site=k
created=1 create_status=0 delete_status=-1 source_status=not-reached
profile=legacy-1.20.15 patch=1.20.15 spec_sha=fixed-private cluster=own
remember() { [[ ! ${pace_fd+x} ]] || exit 90; }
native() { [[ $mode == cleanup && ! ${pace_fd+x} ]] || exit 91; tool_status=$delete; return "$delete"; }
emit_evidence() { evidence_json='{}'; }
emit_logs_evidence() { logs_json='{}'; }
k_site=i i_round=1 i_admitted=1 i_return=69
fail || :
k_site=o postlog_rc=28 postlog_tool=28 postlog_out=0 postlog_err=0
fail || :
'''+f'delete={delete}\n'+finish+'if false; then :; else finish; fi\n'
            result=f.child(body).finish();value=json.loads(result.stdout)
            self.assertEqual((result.returncode,value['schema'],value['state']),(1,rootful.RESULT_V12,'failed'))
            self.assertEqual((value['postlog_reason'],value['postlog_native'],value['kind_delete_status']),('k4.i.1.x.69',None,delete))


class NodeWaitNativeControls(unittest.TestCase):
    """Actual V12 native budgets/clock/waits; fixed command and capture DATA."""
    run_case=NativeStatusReceiverControls.run_case

    def fixture(self,*,historical=False):
        f,_segment=NativeStatusReceiverControls.fixture(self,historical=historical)
        source=receiver_before_capture_size(SCRIPT.read_text())
        for name in ('fail','native'):
            def extract(text):
                start=text.index('\n'+name+'() {\n')+1
                return text[start:text.index('\n}\n',start)+3]
            old=extract(f.definitions);new=extract(source)
            f.definitions=f.definitions.replace(old,new,1)
        f.definitions=f.definitions.replace('  exit 1\n}', '  printf "%s\\n" "$postlog_reason" > "$root/reason"\n  exit 1\n}',1)
        segment=source.split('  k_site=o\n',1)[1].split('  k_site=h\n',1)[0]
        segment='KUBECONFIG=$root/kubeconfig\npostlog_site=k k_site=o\n'+segment.replace('"$stage/kubectl"','fixed_command',1)
        return f,segment

    def test_real_wait_failure_keeps_truthful_native_status_and_fresh_guard_refusal(self):
        for kwargs,expected in [({'command':28},(28,28,0,0)),({'stdout':1},(125,0,1,0)),({'stderr':2},(125,0,0,2)),({'scenario':'after-deadline'},(None,0,0,0))]:
            result,code,snapshot,_trace,f=self.run_case(**kwargs)
            self.assertEqual((result.returncode,code),(1,'pl2.k'))
            self.assertEqual(json.loads((f.root/'reason').read_text()),'k4.o')
            self.assertEqual(tuple(snapshot[k] for k in ('return_status','command_status','stdout_capture_status','stderr_capture_status')),expected)
        for scenario in ('deadline','poison','take-0','take-1','take-2','take-3','take-4','grant-1','grant-4'):
            result,code,snapshot,trace,f=self.run_case(scenario)
            self.assertEqual((result.returncode,code),(1,'pl2.k'))
            self.assertEqual(json.loads((f.root/'reason').read_text()),'k4.o')
            self.assertEqual(set(snapshot.values()),{None});self.assertNotIn('command\n',trace)

    def test_real_native_charges_unchanged_work_output_sentinel_and_four_helpers(self):
        result,code,snapshot,trace,_f=self.run_case()
        self.assertEqual((result.returncode,code,snapshot),(0,'',None))
        self.assertEqual([line for line in trace.splitlines() if line.startswith('take:')],
                         ['take:work:70','take:output-work:245','take:output-work:245','take:sentinel:150','take:sentinel:150'])
        self.assertEqual([line for line in trace.splitlines() if line.startswith('grant:')],['grant:1','grant:2','grant:3','grant:4'])


class NodeWaitDecoderControls(unittest.TestCase):
    def bundle(self,reason='k4.i.2.x.69'):
        config,value,rows=ReadyReasonDecoderControls.bundle(self)
        config['rootful_spec']['schema']='kubernetes-lens-owned-rootful-v12'
        value['evidence']['source_spec_sha256']=vm.digest(vm.encode(config['rootful_spec']))
        value.update(schema=rootful.RESULT_V12,postlog_reason=reason,
                     postlog_native={key:None for key in NativeStatusDecoderControls.KEYS} if reason in rootful.V12_K_NATIVE_SUBSTAGES else None)
        return config,value,rows

    def test_v12_only_finite_vocabulary_and_wait_status_rounds_are_private(self):
        for reason in sorted(rootful.V12_K_SUBSTAGES | rootful.V12_I_REASONS):
            config,value,_rows=self.bundle(reason)
            self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)['postlog_reason'],reason)
        for reason in ('k1.o','k1.h','k3.i.2.r','k4.i.0.r','k4.i.3.r','k4.i.2.x.0','k4.i.2.x.256','k4.p',False,None):
            config,value,_rows=self.bundle(reason)
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)
        config,value,_rows=self.bundle('k4.o')
        value['postlog_native']=dict(return_status=28,command_status=28,stdout_capture_status=0,stderr_capture_status=0)
        self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)['postlog_native'],value['postlog_native'])
        for schema in (rootful.RESULT_V10,rootful.RESULT_V11):
            value['schema']=schema
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)

    def test_success_requires_original_proofs_and_delete_failure_remains_independent(self):
        for delete in (0,19):
            config,value,_rows=self.bundle('k4.o');value['kind_delete_status']=delete
            wire=vm.encode(value)+b'\n'
            self.assertEqual(rootful.wire_record(wire,config,allow_failure=True)['kind_delete_status'],delete)
        value.update(state='source-deployment-positive',source_deployment='server-dry-run-observed',kind_delete_status=0,
                     postlog_failure=None,postlog_native=None,postlog_reason=None)
        self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config)['schema'],rootful.RESULT_V12)
        for key,changed in [('kind_create_status',True),('kind_delete_status',19),('source_deployment','not-reached'),('postlog_reason','k4.o')]:
            bad=deepcopy(value);bad[key]=changed
            with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config)
        bad=deepcopy(value);bad['evidence']['files'].pop('node-inspect')
        with self.assertRaises(vm.Refusal):rootful.wire_record(vm.encode(bad)+b'\n',config)

    def test_current_constructor_spec_binds_current_receiver_and_no_extra_resources(self):
        evidence={key:'c'*64 for key in ('manifest_sha256','config_sha256','parent_sha256')}
        evidence.update(expanded_bytes_hashed=10,archive_bytes=3,catalogue={'blobs/sha256/'+'c'*64:{'bytes':100}})
        files,spec=rootful.guest_files(RootfulHostControls().plan(),evidence,SCRIPT.read_bytes())
        self.assertEqual(spec['schema'],'kubernetes-lens-owned-rootful-v13')
        self.assertEqual(files[rootful.ROOT+'/receiver'][0],SCRIPT.read_bytes())
        self.assertEqual((spec['native_work_max'],spec['native_cleanup_max'],spec['output_max']),(70,5,1048576))
        self.assertEqual((spec['kind_version'],spec['server_patch']),('0.14.0','1.20.15'))

    def test_v12_result_cannot_use_an_old_spec_version(self):
        for schema in (None,'kubernetes-lens-owned-rootful-v1',False):
            config,value,_rows=self.bundle()
            config['rootful_spec']['schema']=schema
            value['evidence']['source_spec_sha256']=vm.digest(vm.encode(config['rootful_spec']))
            with self.assertRaisesRegex(vm.Refusal,'rootful-v12-spec'):
                rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)

    def test_private_durable_bytes_do_not_expose_v12_wait_or_condition_tokens(self):
        for reason in ('k4.o','k4.i.1.x.69'):
            config,value,_rows=self.bundle(reason);raw=vm.encode(value)+b'\n'
            with tempfile.TemporaryDirectory(prefix='node-wait-private-') as directory:
                parent=Path(directory)
                descriptor=rootful.durable_wire(raw,config,parent,vm.Budget(time.monotonic()+30,10))
                self.assertEqual((parent/descriptor['name']).read_bytes(),raw)
                for protected in (b'k4.',b'postlog_reason',b'postlog_native',b'NetworkPluginNotReady',b'PRIVATE_NODE_METADATA'):
                    self.assertNotIn(protected,vm.encode(descriptor))


class NodeWaitIntentBindingControls(unittest.TestCase):
    """Valid legacy shapes cannot impersonate current V12 execution intent."""
    def envelope(self, version, *, success, spec_schema):
        if version == rootful.RESULT_V10:
            config,value,_rows=ReadinessAtomDecoderControls.bundle(self,'k2.i.2.r')
        elif version == rootful.RESULT_V11:
            config,value,_rows=ReadyReasonDecoderControls.bundle(self,'k3.i.2.x.69')
        else:
            self.assertEqual(version,rootful.RESULT_V12)
            config,value,_rows=NodeWaitDecoderControls.bundle(self,'k4.i.2.x.69')
        config['rootful_spec']['schema']=spec_schema
        # Rebind complete evidence too: rejection must be the intent guard,
        # not an unrelated stale source-spec digest or failure vocabulary.
        value['evidence']['source_spec_sha256']=vm.digest(vm.encode(config['rootful_spec']))
        if success:
            value.update(state='source-deployment-positive',source_deployment='server-dry-run-observed',
                         kind_create_status=0,kind_delete_status=0,
                         postlog_failure=None,postlog_native=None,postlog_reason=None)
        return config,value

    def test_legacy_success_cannot_satisfy_current_intent_even_with_rebound_evidence(self):
        for version in (rootful.RESULT_V10,rootful.RESULT_V11):
            config,value=self.envelope(version,success=True,spec_schema='kubernetes-lens-owned-rootful-v12')
            self.assertIsNone(value['postlog_reason'])
            result_value=deepcopy(value);result_value.pop('evidence')
            for decode,body in ((rootful.result,result_value),(rootful.wire_record,value)):
                with self.assertRaisesRegex(vm.Refusal,'rootful-v12-spec'):
                    decode(vm.encode(body)+b'\n',config)

    def test_legacy_failure_cannot_bind_current_intent_even_with_valid_old_vocabulary(self):
        for version,prefix in ((rootful.RESULT_V10,'k2.i.'),(rootful.RESULT_V11,'k3.i.')):
            config,value=self.envelope(version,success=False,spec_schema='kubernetes-lens-owned-rootful-v12')
            self.assertTrue(value['postlog_reason'].startswith(prefix))
            result_value=deepcopy(value);result_value.pop('evidence')
            for decode,body in ((rootful.result,result_value),(rootful.wire_record,value)):
                with self.assertRaisesRegex(vm.Refusal,'rootful-v12-spec'):
                    decode(vm.encode(body)+b'\n',config,allow_failure=True)

    def test_authentic_legacy_pairs_and_current_pairs_keep_exact_success_and_failure(self):
        for version in (rootful.RESULT_V10,rootful.RESULT_V11,rootful.RESULT_V12):
            spec_schema='kubernetes-lens-owned-rootful-v12' if version==rootful.RESULT_V12 else 'kubernetes-lens-owned-rootful-v1'
            for success in (False,True):
                config,value=self.envelope(version,success=success,spec_schema=spec_schema)
                result_value=deepcopy(value);result_value.pop('evidence')
                self.assertEqual(rootful.result(vm.encode(result_value)+b'\n',config,allow_failure=not success),result_value)
                raw=vm.encode(value)+b'\n'
                self.assertEqual(rootful.wire_record(raw,config,allow_failure=not success),
                                 KStageDecoderControls.expected_summary(self,value))





class CaptureSizeBoundaryControls(unittest.TestCase):
    """Current capture helper; fixed utility DATA, no dd/stat or native tools."""
    def fixture(self,*,historical=False):
        f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
        source=SCRIPT.read_text()
        if historical:source=receiver_before_capture_size(source)
        f.definitions=source.split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={f.root} stage={f.root}/stage')
        return f

    def run_case(self,size,*,maximum=4096,dd=0,stat=0,refusal='',existing=False,historical=False):
        from shlex import quote
        f=self.fixture(historical=historical)
        if existing:(f.root/'capture').write_text('existing-private-data')
        body=r'''mode=work
utility_launch() {
  local ticket=$1
  shift
  case $1 in
    /usr/bin/dd)
      [[ $ticket == utility-work.0 && $# == 5 && $2 == bs=4096 && $3 == count="$((maximum+1))B" && $4 == iflag=fullblock && $5 == status=none ]] || exit 88
      printf 'dd\n' >> "$root/trace"
      [[ $refusal != dd ]] || fail
      printf 'fixed-private-data\n'
      return "$dd_status"
      ;;
    /usr/bin/stat)
      [[ $ticket == utility-work.1 && $# == 4 && $2 == -c && $3 == %s && $4 == "$root/capture" ]] || exit 88
      printf 'stat\n' >> "$root/trace"
      [[ $refusal != stat ]] || fail
      printf '%s\n' "$size_data"
      return "$stat_status"
      ;;
    *) exit 88 ;;
  esac
}
'''+f'maximum={maximum} size_data={quote(str(size))} dd_status={dd} stat_status={stat} refusal={quote(refusal)}\n'
        body+='if capture_stream "$maximum" "$root/capture" utility-work.0 utility-work.1; then exit 0; else exit "$?"; fi\n'
        result=f.child(body).finish()
        trace=(f.root/'trace').read_text().splitlines() if (f.root/'trace').exists() else []
        return result,trace

    def test_below_equal_and_over_selected_caps_have_exact_fixed_status_without_extra_reads(self):
        for cap in (4096,16384,65536):
            for size,expected in [(0,0),(cap-1,0),(cap,0),(cap+1,23),(cap+17,23)]:
                result,trace=self.run_case(size,maximum=cap)
                self.assertEqual(result.returncode,expected)
                self.assertEqual(trace,['dd','stat'])
                self.assertEqual(result.stdout,b'')

    def test_other_failures_and_malformed_stat_stay_generic_one(self):
        for kwargs,expected_trace in [({'dd':1},['dd']),({'dd':23},['dd']),({'stat':1},['dd','stat']),
                                      ({'stat':23},['dd','stat']),({'refusal':'dd'},['dd']),
                                      ({'refusal':'stat'},['dd','stat']),({'existing':True},[])]:
            result,trace=self.run_case('4097',**kwargs)
            self.assertEqual(result.returncode,1);self.assertEqual(trace,expected_trace)
        for value in ('','not-numeric','-1','4097x','0x1001','08','0008'):
            result,trace=self.run_case(value)
            self.assertEqual(result.returncode,1);self.assertEqual(trace,['dd','stat'])

    def test_original_zero_nonzero_and_arithmetic_error_behavior_stays_exact(self):
        for value in ('0','4095','4096','4097','8192','010','08','bad',''):
            new,new_trace=self.run_case(value);old,old_trace=self.run_case(value,historical=True)
            self.assertEqual(new.returncode==0,old.returncode==0)
            self.assertEqual(new_trace,old_trace)
            if new.returncode==23:self.assertEqual(old.returncode,1)
            else:self.assertEqual(new.returncode,old.returncode)


class CaptureSizeNativeControls(unittest.TestCase):
    """Inert extracted native() helper tests with fixed utility/capture DATA."""
    run_case=NativeStatusReceiverControls.run_case
    earlier=False

    def fixture(self,*,historical=False):
        f,_segment=NodeWaitNativeControls.fixture(self,historical=historical)
        source=SCRIPT.read_text()
        capture='capture_stream() {\n'+source.split('capture_stream() {\n',1)[1].split('\n}\n',1)[0]+'\n}\n'
        utilities=r'''utility_launch() {
  shift
  case $1 in
    /usr/bin/dd)
      local line
      while IFS= read -r line; do :; done
      return 0
      ;;
    /usr/bin/stat)
      if [[ $4 == *.out ]]; then printf '%s\n' "$stdout_result"; else printf '%s\n' "$stderr_result"; fi
      return 0
      ;;
    *) exit 88 ;;
  esac
}
'''
        command=source.split('\nk_site=m\n',1)[1].split('\nk_site=n\n',1)[0]
        command=command.replace('"$stage/kubectl"','fixed_command',1)
        prefix='KUBECONFIG=$root/kubeconfig\npostlog_site=k k_site=m\n'
        if self.earlier:prefix+='postlog_failure=pl1.r postlog_reason=\'"memory"\' postlog_native=null\n'
        return f,prefix+utilities+capture+command+'\n'

    def test_native_keeps_command_capture_and_wrapper_status_precedence(self):
        keys=('return_status','command_status','stdout_capture_status','stderr_capture_status')
        for command,out,err,expected in [(0,4097,0,(125,0,23,0)),(7,4097,0,(125,7,23,0)),
                                         (0,0,4097,(125,0,0,23)),(23,0,0,(23,23,0,0))]:
            result,code,snapshot,_trace,f=self.run_case(command=command,stdout=out,stderr=err)
            self.assertEqual((result.returncode,code),(1,'pl2.k'))
            self.assertEqual(json.loads((f.root/'reason').read_text()),'k4.m')
            self.assertEqual(tuple(snapshot[k] for k in keys),expected)
        result,code,snapshot,_trace,_f=self.run_case(command=0,stdout=4096,stderr=4096)
        self.assertEqual((result.returncode,code,snapshot),(0,'',None))

    def test_earlier_failure_survives_later_capture23(self):
        self.earlier=True
        result,code,snapshot,_trace,f=self.run_case(stdout=4097)
        self.assertEqual((result.returncode,code,snapshot),(1,'pl1.r',None))
        self.assertEqual(json.loads((f.root/'reason').read_text()),'memory')


class CaptureSizeContractControls(unittest.TestCase):
    def test_raw_posix_fields_wire_versions_and_private_descriptor_do_not_change(self):
        config,value,_rows=NodeWaitDecoderControls.bundle(self,'k4.m')
        for status in (1,23,37):
            value['postlog_native']=dict(return_status=125,command_status=0,stdout_capture_status=status,stderr_capture_status=0)
            raw=vm.encode(value)+b'\n'
            checked=rootful.wire_record(raw,config,allow_failure=True)
            self.assertEqual(checked,KStageDecoderControls.expected_summary(self,value))
            self.assertEqual(checked['postlog_native']['stdout_capture_status'],status)
            self.assertEqual(checked['schema'],rootful.RESULT_V12)
            with tempfile.TemporaryDirectory(prefix='capture-size-private-') as directory:
                parent=Path(directory);descriptor=rootful.durable_wire(raw,config,parent,vm.Budget(time.monotonic()+30,10))
                self.assertEqual((parent/descriptor['name']).read_bytes(),raw)
                for private in (b'postlog_native',b'k4.m',b'over-cap',b'PRIVATE_NODE_METADATA'):
                    self.assertNotIn(private,vm.encode(descriptor))

    def test_exact_source_epoch_history_comment_guard_budget_and_canonical_fit(self):
        import hashlib
        source=SCRIPT.read_text();old=receiver_before_capture_size(source)
        self.assertEqual((len(source.encode()),hashlib.sha256(source.encode()).hexdigest()),(CAPTURE_SIZE_SOURCE_BYTES,CAPTURE_SIZE_SOURCE))
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),(65408,NODE_WAIT_SOURCE))
        self.assertLessEqual(len(source.encode()),65408);self.assertLessEqual(len(source.encode()),65536)
        self.assertEqual(source.count('exit 23'),1);self.assertNotIn('exit 23',old)
        self.assertEqual([line for line in receiver_before_modern_logging(receiver_before_storage_capture(receiver_before_live_envelope(source))).splitlines() if line.lstrip().startswith('#')],
                         [line for line in old.splitlines() if line.lstrip().startswith('#')])
        for literal in ('maximum=680','maximum=64','max=70','max=5','output_max=245','output_max=10','take sentinel 150',
                        'UPTIME + 1680','UPTIME + 1800','--wait 0s','--timeout=30s'):
            self.assertEqual(source.count(literal),old.count(literal))
        for name in ('native','emit_evidence'):
            def part(text):
                start=text.index('\n'+name+'() {\n')+1
                return text[start:text.index('\n}\n',start)+3]
            self.assertEqual(part(source),part(old))
        calls=[line for line in source.splitlines() if 'capture_stream ' in line]
        self.assertEqual(calls,[line for line in old.splitlines() if 'capture_stream ' in line])
        self.assertEqual(len(calls),2)
        self.assertTrue(all('> >(capture_stream ' in line and line.endswith(')') for line in calls))
        self.assertEqual([line for line in source.splitlines() if line.startswith('trap ')],
                         [line for line in old.splitlines() if line.startswith('trap ')])
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,CAPTURE_SIZE_SOURCE)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS),314)
        for changed in (source+'\n',source.replace('exit 23','exit 24',1),source.replace('size > maximum','size >= maximum',1)):
            with self.assertRaises(AssertionError):receiver_before_capture_size(changed)


class CompactRootDryRunControls(unittest.TestCase):
    """Extracted mandatory tail, fixed fake tools/status DATA; no real CLI or jq."""

    def run_tail(self, *, profile='legacy-1.20.15', namespace=0, dry_run=0,
                 admission=0, digest=True):
        from shlex import quote
        f = CaptureSizeBoundaryControls.fixture(self)
        source = SCRIPT.read_text()
        tail = 'k_site=j\n' + source.split('\nk_site=j\n', 1)[1]
        admission_line = tail.split('\nk_site=n\n', 1)[1].splitlines()[0]
        predicate = admission_line.split("u /usr/bin/jq -e '", 1)[1].split("' \"$out\"", 1)[0]
        body = r'''mode=work rootful_intent=execution-v1 postlog_site=k source_status=not-reached
KUBECONFIG=$root/kubeconfig fixture_sha=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
trap 'printf "%s\n%s\n%s\n" "$source_status" "$postlog_reason" "$postlog_native" > "$root/summary"' EXIT
native() {
  [[ $1 == 4096 && $2 == 4096 && $3 == "$stage/kubectl" && $4 == --kubeconfig && $5 == "$KUBECONFIG" && $6 == create && $# == 10 ]] || exit 88
  postlog_tool=0 postlog_out=0 postlog_err=0
  case $7 in
    namespace)
      [[ $8 == demo && $9 == -o && ${10} == json ]] || exit 88
      printf 'namespace\n' >> "$root/trace"
      postlog_tool=$namespace_status
      return "$namespace_status"
      ;;
    --dry-run=server)
      [[ $8 == -f && $9 == "$root/deployment.json" && ${10} == '-o=jsonpath={@}' ]] || exit 88
      printf 'dry-run\n' >> "$root/trace"
      out=$root/dry-run-response
      postlog_tool=$dry_run_status
      if [[ $dry_run_status == 125 ]]; then postlog_tool=0 postlog_out=23; fi
      return "$dry_run_status"
      ;;
    *) exit 88 ;;
  esac
}
u() {
  case $1 in
    /usr/bin/sha256sum)
      [[ $# == 2 && $2 == "$root/deployment.json" ]] || exit 88
      printf 'digest\n' >> "$root/trace"
      if [[ $digest_ok == 1 ]]; then printf '%s  %s\n' "$fixture_sha" "$2"; else printf 'bad\n'; fi
      ;;
    /usr/bin/jq)
      [[ $# == 4 && $2 == -e && $3 == "$expected_predicate" && $4 == "$out" ]] || exit 88
      printf 'admission\n' >> "$root/trace"
      return "$admission_status"
      ;;
    *) exit 88 ;;
  esac
}
'''
        body += (f'profile={quote(profile)} namespace_status={namespace} dry_run_status={dry_run} '
                 f'admission_status={admission} digest_ok={int(digest)}\n'
                 f'expected_predicate={quote(predicate)}\n')
        result = f.child(body + tail).finish()
        trace = (f.root / 'trace').read_text().splitlines()
        status, reason, snapshot = (f.root / 'summary').read_text().splitlines()
        return result, trace, status, json.loads(reason), json.loads(snapshot)

    def test_both_frozen_profiles_keep_one_fixed_full_root_call_and_mandatory_admission(self):
        for profile in ('legacy-1.20.15', 'modern-1.37.0'):
            result, trace, status, reason, snapshot = self.run_tail(profile=profile)
            self.assertEqual((result.returncode, status, reason, snapshot),
                             (0, 'server-dry-run-observed', None, None))
            self.assertEqual(trace, ['namespace', 'digest', 'dry-run', 'admission'])

    def test_failed_native_capture_fixture_or_response_never_reaches_success(self):
        cases = [({'namespace': 7}, ['namespace'], 'k4.j'),
                 ({'digest': False}, ['namespace', 'digest'], 'k4.l'),
                 ({'dry_run': 7}, ['namespace', 'digest', 'dry-run'], 'k4.m'),
                 ({'dry_run': 125}, ['namespace', 'digest', 'dry-run'], 'k4.m')]
        for admission in (1, 4, 23):
            cases.append(({'admission': admission},
                          ['namespace', 'digest', 'dry-run', 'admission'], 'k4.n'))
        for kwargs, expected_trace, expected_reason in cases:
            result, trace, status, reason, snapshot = self.run_tail(**kwargs)
            self.assertEqual((result.returncode, status, reason),
                             (1, 'not-reached', expected_reason))
            self.assertEqual(trace, expected_trace)
            if kwargs.get('dry_run') == 125:
                self.assertEqual(snapshot, dict(return_status=125, command_status=0,
                                               stdout_capture_status=23, stderr_capture_status=0))

    def test_exact_inverse_preserves_every_other_byte_and_original_response_predicate(self):
        import hashlib
        source = receiver_before_modern_logging(receiver_before_storage_capture(receiver_before_live_envelope(SCRIPT.read_text())))
        frozen = receiver_before_compact_root(source)
        self.assertEqual((len(frozen.encode()), hashlib.sha256(frozen.encode()).hexdigest()),
                         (65378, FROZEN_CAPTURE_SIZE_SOURCE))
        self.assertEqual(source, frozen.replace(COMPACT_ROOT_PREVIOUS, COMPACT_ROOT_CURRENT, 1))
        self.assertEqual(len(source.encode()), 65388)
        self.assertLessEqual(len(source.encode()), 65408)
        self.assertLessEqual(len(source.encode()), 65536)
        self.assertEqual(source.split('\nk_site=n\n', 1)[1], frozen.split('\nk_site=n\n', 1)[1])
        self.assertEqual(source.count('-o=jsonpath={@}'), 1)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        for changed in (source + '\n', source.replace('-o=jsonpath={@}', '-o=jsonpath={.metadata}', 1),
                        source.replace('native 4096 4096', 'native 8192 4096', 1)):
            with self.assertRaises(AssertionError):
                receiver_before_compact_root(changed)

    def test_frozen_public_source_facts_keep_versions_full_map_caveat_and_existing_exclusion(self):
        root = SCRIPT.parents[2]
        path = root / 'docs/compatibility/kubectl-root-jsonpath-sources.json'
        facts = json.loads(path.read_text())
        revisions = {'v1.20.15': '8f1e5bf0b9729a899b8df86249b56e2c74aebc55',
                     'v1.37.0': 'f54c212e3a2f75d674b717a9b29052b20b60aefc'}
        self.assertEqual({p['version']: p['revision'] for p in facts['profiles']}, revisions)
        for profile in facts['profiles']:
            self.assertTrue(any(row['path'] == 'LICENSE' for row in profile['source_files']))
            for row in profile['source_files']:
                self.assertEqual(row['url'], 'https://raw.githubusercontent.com/kubernetes/kubernetes/'
                                 + profile['revision'] + '/' + row['path'])
                self.assertRegex(row['sha256'], r'^[0-9a-f]{64}$')
                self.assertGreater(row['bytes'], 0)
                self.assertEqual(row['license'], 'Apache-2.0')
        self.assertIn('managedFields', facts['contracts']['modern_difference'])
        self.assertIn('increase', facts['contracts']['modern_difference'])
        self.assertNotIn('/tmp/', path.read_text())
        self.assertIn('docs/compatibility/**', (root / '.github/renovate.json').read_text())


class ModernKubeadmLoggingControls(unittest.TestCase):
    """Frozen logging-policy controls; current storage policy has separate controls."""

    def invoke(self, arguments, *, profile='modern-1.37.0', mode='work',
               returned=0, command=0, stdout_capture=0, stderr_capture=0):
        from shlex import quote
        current = receiver_before_storage_capture(receiver_before_live_envelope(SCRIPT.read_text()))
        receiver_before_modern_logging(current)  # Authenticate frozen logging policy; new storage controls use current source.
        fixture = BashProtocolControls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.definitions = current.split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={fixture.root} stage={fixture.root}/stage')
        body = r'''trap - EXIT ERR HUP INT TERM
fail() {
  printf '%s\0' "${args[@]}" > "$root/refused.argv"
  exit 93
}
read_file() {
  [[ $# == 1 && $1 == "$root/state/mode" ]] || exit 88
  REPLY=$fixture_mode
}
native() {
  printf '%s\0' "$@" > "$root/native.argv"
  out=$root/provider.out err=$root/provider.err
  printf 'base stdout\n' > "$out"
  printf 'ungated warning/error\n' > "$err"
  last_tool_status=$fixture_command
  last_stdout_capture_status=$fixture_stdout
  last_stderr_capture_status=$fixture_stderr
  return "$fixture_returned"
}
u() {
  [[ $# == 2 && $1 == /usr/bin/cat && ( $2 == "$out" || $2 == "$err" ) ]] || exit 88
  local content=''
  IFS= read -r -d '' content < "$2" || :
  printf '%s' "$content"
}
printf 'first-failure\n' > "$root/state/failure"
'''
        body += (f'profile={quote(profile)} fixture_mode={quote(mode)}\n'
                 f'fixture_returned={returned} fixture_command={command} '
                 f'fixture_stdout={stdout_capture} fixture_stderr={stderr_capture}\n'
                 'cluster=own node=own-control-plane alias=localhost/kubernetes-lens-node:owner\n'
                 'incoming=(' + ' '.join(quote(a) for a in arguments) + ')\n')
        body += r'''if provider "${incoming[@]}"; then returned=0; else returned=$?; fi
printf '%s %s %s %s\n' "$returned" "$last_tool_status" "$last_stdout_capture_status" "$last_stderr_capture_status" > "$root/status"
'''
        result = fixture.child(body).finish()

        def argv(name):
            path = fixture.root / name
            return [a.decode() for a in path.read_bytes().split(b'\0')[:-1]] if path.exists() else None

        status = fixture.root / 'status'
        observed_status = tuple(map(int, status.read_text().split())) if status.exists() else None
        return (result, argv('native.argv'), argv('refused.argv'), observed_status,
                (fixture.root / 'state/failure').read_bytes())

    def modern(self):
        return ['exec', '--privileged', 'own-control-plane', 'kubeadm', 'init',
                '--config=/kind/kubeadm.conf', '--skip-token-print', '--v=6']

    def test_modern_requested6_executes_only_final0_with_original_init_captures(self):
        requested = self.modern()
        result, observed, refused, status, first = self.invoke(requested)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(observed, ['32768', '32768', '/usr/bin/podman', '--remote=false']
                         + requested[:-1] + ['--v=0'])
        self.assertIsNone(refused)
        self.assertEqual(status, (0, 0, 0, 0))
        self.assertEqual((result.stdout, result.stderr),
                         (b'base stdout\n', b'ungated warning/error\n'))
        self.assertEqual(first, b'first-failure\n')

    def test_legacy_requested6_skip_preflight_and_native_tokens_remain_exact(self):
        requested = self.modern()
        requested.insert(5, '--skip-phases=preflight')
        result, observed, refused, status, _first = self.invoke(requested, profile='legacy-1.20.15')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(observed, ['32768', '32768', '/usr/bin/podman', '--remote=false'] + requested)
        self.assertEqual(observed[-1], '--v=6')
        self.assertIsNone(refused)
        self.assertEqual(status, (0, 0, 0, 0))

    def test_classifier_still_refuses_other_verbosity_spelling_and_bootstrap_requests(self):
        base = self.modern()
        cases = [(base[:-1] + [value], 'modern-1.37.0') for value in ('--v=0', '--v=5', '--v=7')]
        cases += [(base[:-1] + ['--v', '6'], 'modern-1.37.0'),
                  (base + ['--v=6'], 'modern-1.37.0'),
                  (base + ['--ignore-preflight-errors=all'], 'modern-1.37.0'),
                  (base[:5] + ['--skip-phases=preflight'] + base[5:], 'modern-1.37.0'),
                  (base[:5] + base[6:], 'modern-1.37.0'),
                  (base[:6] + base[7:], 'modern-1.37.0'),
                  (base[:5] + [base[6], base[5], base[7]], 'modern-1.37.0'),
                  (base[:2] + ['foreign-node'] + base[3:], 'modern-1.37.0'),
                  (base, 'foreign-profile')]
        for requested, profile in cases:
            with self.subTest(arguments=requested, profile=profile):
                result, observed, refused, status, first = self.invoke(requested, profile=profile)
                self.assertEqual(result.returncode, 93)
                self.assertIsNone(observed)
                self.assertEqual(refused, requested)
                self.assertIsNone(status)
                self.assertEqual(first, b'first-failure\n')

    def test_cleanup_refuses_init_before_translation_or_native_call(self):
        requested = self.modern()
        result, observed, refused, status, first = self.invoke(requested, mode='cleanup')
        self.assertEqual(result.returncode, 93)
        self.assertIsNone(observed)
        self.assertEqual(refused, requested)
        self.assertEqual(refused[-1], '--v=6')
        self.assertIsNone(status)
        self.assertEqual(first, b'first-failure\n')

    def test_nonzero_capture_status_and_both_streams_pass_through_without_success_rewrite(self):
        for values in [(7, 7, 0, 0), (23, 23, 0, 0), (125, 0, 23, 0),
                       (125, 0, 0, 23), (125, 7, 23, 23)]:
            with self.subTest(raw_status=values):
                result, observed, refused, status, first = self.invoke(
                    self.modern(), returned=values[0], command=values[1],
                    stdout_capture=values[2], stderr_capture=values[3])
                self.assertEqual(result.returncode, 0)
                self.assertEqual(status, values)
                self.assertEqual(observed[:2], ['32768', '32768'])
                self.assertEqual(observed[-1], '--v=0')
                self.assertIsNone(refused)
                self.assertEqual((result.stdout, result.stderr),
                                 (b'base stdout\n', b'ungated warning/error\n'))
                self.assertEqual(first, b'first-failure\n')

    def test_other_admitted_actions_keep_original_argv_and_capture_limits(self):
        for requested in [['--version'], ['exec', '--privileged', 'own-control-plane',
                                          'cat', '/kind/version']]:
            with self.subTest(arguments=requested):
                result, observed, refused, status, _first = self.invoke(requested)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(observed, ['4096', '4096', '/usr/bin/podman', '--remote=false'] + requested)
                self.assertIsNone(refused)
                self.assertEqual(status, (0, 0, 0, 0))

    def test_current_source_is_strictly_bound_and_inverse_preserves_exact_history_and_caps(self):
        import hashlib
        source = SCRIPT.read_text()
        self.assertEqual((len(source.encode()), hashlib.sha256(source.encode()).hexdigest()),
                         (MODERN_LOGGING_SOURCE_BYTES, MODERN_LOGGING_SOURCE))
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256, MODERN_LOGGING_SOURCE)
        self.assertLessEqual(len(source.encode()), 65408)
        self.assertLessEqual(len(source.encode()), 65536)
        source = receiver_before_storage_capture(receiver_before_live_envelope(source))
        frozen = receiver_before_modern_logging(source)
        self.assertEqual((len(frozen.encode()), hashlib.sha256(frozen.encode()).hexdigest()),
                         (65388, FROZEN_COMPACT_ROOT_SOURCE))
        self.assertEqual(source, frozen.replace(MODERN_LOGGING_COMMENT_BEFORE,
                                               MODERN_LOGGING_COMMENT_CURRENT).replace(
            '  if [[ $action == volume ]]; then claim volume; fi\n',
            MODERN_LOGGING_GUARD + '  if [[ $action == volume ]]; then claim volume; fi\n', 1))
        provider = source.split('\nprovider() {\n', 1)[1].split('\n}\n', 1)[0]
        self.assertLess(provider.index('provider_classify || fail'), provider.index(MODERN_LOGGING_GUARD))
        self.assertLess(provider.index('case $action in delete | volume-list | volume-delete) fail'),
                        provider.index(MODERN_LOGGING_GUARD))
        for changed in (source + '\n', frozen, source.replace('args[7]=--v=0', 'args[6]=--v=0', 1),
                        source.replace(MODERN_LOGGING_COMMENT_CURRENT, MODERN_LOGGING_COMMENT_BEFORE, 1)):
            with self.assertRaises(AssertionError):
                receiver_before_modern_logging(changed)
        with self.assertRaises(AssertionError):
            receiver_before_compact_root(source)
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)

class ModernStorageCaptureControls(unittest.TestCase):
    """Current source, real reservation/capture flow, fixed fake tools and DATA only."""

    PAYLOAD = (b'---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n'
               b'  name: independent-transport-data\n  namespace: demo\ndata:\n  text: |\n'
               + b'    ' + b'x' * 4448 + b'\n')

    def fixture(self):
        fixture = BashProtocolControls()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        current = SCRIPT.read_text()
        receiver_before_storage_capture(receiver_before_live_envelope(current))
        fixture.definitions = current.split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={fixture.root} stage={fixture.root}/stage')
        return fixture

    def allowance(self, arguments, profile='modern-1.37.0'):
        from shlex import quote
        fixture = self.fixture()
        body = ('profile=' + quote(profile) + '\ncluster=own node=own-control-plane '
                "alias=localhost/kubernetes-lens-node:owner volume=''\nargs=("
                + ' '.join(quote(a) for a in arguments) + ')\n'
                'if provider_classify; then printf "%s %s %s\\n" "$action" "$maximum" "$error_max"; '
                'else printf "refused\\n"; fi\n')
        result = fixture.child(body).finish()
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().strip()

    def provider_case(self, payload, *, profile='modern-1.37.0', apply=False,
                      stdin=b'', cursors=None, scenario='', mode='work', fallback=False):
        from shlex import quote
        fixture = self.fixture()
        (fixture.root / 'producer-data').write_bytes(payload)
        original = 'native() {\n' + fixture.definitions.split('\nnative() {\n', 1)[1].split('\n}\n', 1)[0] + '\n}\n'
        self.assertEqual(original.count('    "$@"\n'), 1)
        fixture.definitions = fixture.definitions.replace(
            original, original.replace('    "$@"\n', '    fixture_command "$@"\n', 1), 1)
        body = r'''trap 'exit 1' ERR HUP INT TERM
clock_check() { [[ $scenario != deadline ]] || fail; }
copy_data() {
  local data=''
  IFS= read -r -d '' data < "$1" || :
  printf '%s' "$data"
}
utility_launch() {
  local ticket=$1 data='' count
  shift
  [[ $ticket =~ ^utility-(work|cleanup)\.[0-9]{1,3}$ && -f $credits/$ticket && ! -e $credits/used.$ticket ]] || exit 88
  printf '%s\n' "$owner $plan $boot" > "$credits/used.$ticket"
  case $1 in
    /usr/bin/dd)
      [[ $# == 5 && $2 == bs=4096 && $4 == iflag=fullblock && $5 == status=none ]] || exit 88
      printf 'dd\n' >> "$root/trace"
      [[ $scenario != dd-failure ]] || return 1
      count=${3#count=}; count=${count%B}
      [[ $count == 4097 || $count == 8193 ]] || exit 88
      IFS= read -r -N "$count" data || :
      printf '%s' "$data"
      ;;
    /usr/bin/stat)
      [[ $# == 4 && $2 == -c && $3 == %s ]] || exit 88
      [[ $scenario != stat-failure ]] || return 1
      IFS= read -r -d '' data < "$4" || :
      printf '%s\n' "${#data}"
      ;;
    /usr/bin/cat)
      [[ $# == 2 && ( $2 == "$out" || $2 == "$err" ) ]] || exit 88
      copy_data "$2"
      ;;
    *) exit 88 ;;
  esac
}
fixture_command() {
  [[ $1 == /usr/bin/podman && $2 == --remote=false && $3 == exec && $4 == --privileged ]] || exit 88
  if [[ $# == 7 && $5 == "$node" && $6 == cat && $7 == /kind/manifests/default-storage.yaml ]]; then
    printf 'exec:read\n' >> "$root/trace"
    copy_data "$root/producer-data"
    [[ $scenario != child-failure ]] || return 7
    [[ $scenario != child23 ]] || return 23
  elif [[ $# == 11 && $5 == -i && $6 == "$node" && $7 == kubectl && $8 == --kubeconfig=/etc/kubernetes/admin.conf && $9 == apply && ${10} == -f && ${11} == - ]]; then
    printf 'exec:apply\n' >> "$root/trace"
    local data=''
    IFS= read -r -d '' data || :
    printf '%s' "$data" > "$root/applied"
    printf 'applied\n'
  else
    exit 88
  fi
}
'''
        body += (f'profile={quote(profile)} mode={quote(mode)} rootful_intent=execution-v1 '
                 f'scenario={quote(scenario)}\ncluster=own node=own-control-plane '
                 'alias=localhost/kubernetes-lens-node:owner\n'
                 'printf "%s\\n" "$mode" > "$root/state/mode"\n')
        for domain, count in (cursors or {}).items():
            body += f'cursor[{quote(domain)}]={count}\n'
        request = (['exec', '--privileged', '-i', 'own-control-plane', 'kubectl',
                    '--kubeconfig=/etc/kubernetes/admin.conf', 'apply', '-f', '-'] if apply else
                   ['exec', '--privileged', 'own-control-plane', 'cat', '/kind/manifests/default-storage.yaml'])
        body += 'if provider ' + ' '.join(quote(a) for a in request) + '; then rc=0; else rc=$?; fi\n'
        body += 'printf "%s %s %s %s\\n" "$rc" "$tool_status" "$stdout_status" "$stderr_status" > "$root/status"\n'
        if fallback:
            body += ('provider exec --privileged -i "$node" kubectl '
                     '--kubeconfig=/etc/kubernetes/admin.conf apply -f -\n')
        child = fixture.child(body)
        if stdin:
            child.process.stdin.write(stdin)
            child.process.stdin.flush()
        result = child.finish()
        status = fixture.root / 'status'
        trace = fixture.root / 'trace'
        applied = fixture.root / 'applied'
        return (result, tuple(map(int, status.read_text().split())) if status.exists() else None,
                trace.read_text().splitlines() if trace.exists() else [],
                applied.read_bytes() if applied.exists() else None,
                (fixture.root / 'state/poison').exists(), fixture)

    def test_only_exact_modern_storage_gets8192_and_other_roles_keep_independent_limits(self):
        storage = ['exec', '--privileged', 'own-control-plane', 'cat', '/kind/manifests/default-storage.yaml']
        self.assertEqual(self.allowance(storage), 'storage 8192 4096')
        self.assertEqual(self.allowance(storage, 'legacy-1.20.15'), 'storage 4096 4096')
        for arguments, expected in [
                (['exec', '--privileged', 'own-control-plane', 'cat', '/kind/manifests/default-cni.yaml'], 'cni 4096 4096'),
                (['exec', '--privileged', 'own-control-plane', 'cat', '/etc/kubernetes/admin.conf'], 'kubeconfig 65536 4096'),
                (['exec', '--privileged', '-i', 'own-control-plane', 'kubectl', '--kubeconfig=/etc/kubernetes/admin.conf', 'apply', '-f', '-'], 'storage-install 4096 4096'),
                (['exec', '--privileged', 'own-control-plane', 'kubeadm', 'init', '--config=/kind/kubeadm.conf', '--skip-token-print', '--v=6'], 'init 32768 32768')]:
            self.assertEqual(self.allowance(arguments), expected)
        for arguments in [storage + ['extra'], storage[:-1] + ['/kind/manifests/other.yaml'],
                          ['exec', '--privileged', '-i'] + storage[2:],
                          ['exec', '--privileged', 'foreign-node'] + storage[3:]]:
            self.assertEqual(self.allowance(arguments), 'refused')

    def check_full_transport(self, payload):
        import hashlib
        read, status, trace, applied, poison, fixture = self.provider_case(payload)
        self.assertEqual((read.returncode, status, poison), (0, (0, 0, 0, 0), False))
        self.assertEqual(read.stdout, payload)
        self.assertEqual(trace.count('exec:read'), 1)
        self.assertEqual(len(list((fixture.root / 'state/credits').glob('output-work.*'))), 3)
        self.assertEqual(len(list((fixture.root / 'state/credits').glob('sentinel.*'))), 2)
        self.assertEqual(len(list((fixture.root / 'state/credits').glob('utility-work.*'))), 6)
        # Independent buffer/Reader handoff DATA; the real pinned kind is never executed.
        reader_bytes = bytes(read.stdout)
        result, status, trace, applied, poison, fixture = self.provider_case(
            b'', apply=True, stdin=reader_bytes)
        self.assertEqual((result.returncode, status, poison), (0, (0, 0, 0, 0), False))
        self.assertEqual(applied, payload)
        self.assertEqual(hashlib.sha256(applied).digest(), hashlib.sha256(payload).digest())
        self.assertEqual(trace.count('exec:apply'), 1)
        self.assertEqual(len(list((fixture.root / 'state/credits').glob('output-work.*'))), 2)

    def test_complete_independent4567_payload_reaches_apply_fd0_once_with_final_newline(self):
        import hashlib
        self.assertEqual(len(self.PAYLOAD), 4567)
        self.assertEqual(hashlib.sha256(self.PAYLOAD).hexdigest(), '477591d525e2f170663374d21fb8ca295ed97cfdc8ac6a8daf657e65053e2757')
        self.assertTrue(self.PAYLOAD.endswith(b'\n'))
        self.check_full_transport(self.PAYLOAD)

    def test_exact_modern_and_legacy_boundaries_preserve_raw_capture23_wrapper125(self):
        for profile, count, expected in [('modern-1.37.0', 8192, (0, 0, 0, 0)),
                                         ('modern-1.37.0', 8193, (125, 0, 23, 0)),
                                         ('legacy-1.20.15', 4096, (0, 0, 0, 0)),
                                         ('legacy-1.20.15', 4097, (125, 0, 23, 0))]:
            result, status, trace, applied, poison, fixture = self.provider_case(b'x' * count, profile=profile)
            self.assertEqual((result.returncode, status), (0, expected))
            self.assertEqual(poison, expected[0] != 0)
            self.assertEqual(trace.count('exec:read'), 1)
            self.assertIsNone(applied)

    def test_third_output_slot_and_original_pools_deny_before_any_collector_or_exec(self):
        for cursors in [{'output-work': 243}, {'output-work': 245}, {'work': 70},
                        {'sentinel': 150}, {'utility-work': 680}]:
            result, status, trace, applied, poison, fixture = self.provider_case(b'x', cursors=cursors)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(trace, [])
            self.assertIsNone(status)
            self.assertIsNone(applied)
            self.assertTrue(poison)
        result, status, trace, applied, poison, fixture = self.provider_case(b'x', cursors={'output-work': 242})
        self.assertEqual((result.returncode, status), (0, (0, 0, 0, 0)))
        self.assertEqual(len(list((fixture.root / 'state/credits').glob('output-work.*'))), 3)

    def test_tool_failures_stay_opaque_and_deadline_cleanup_and_poison_refuse(self):
        for scenario, expected in [('child-failure', (7, 7, 0, 0)), ('child23', (23, 23, 0, 0))]:
            result, status, trace, applied, poison, fixture = self.provider_case(b'x', scenario=scenario)
            self.assertEqual(status, expected)
            self.assertFalse(poison)
        for scenario in ('dd-failure', 'stat-failure'):
            result, status, trace, applied, poison, fixture = self.provider_case(b'x', scenario=scenario)
            self.assertEqual(status[0], 125)
            self.assertIn(1, status[2:])
            self.assertNotIn(23, status[2:])
            self.assertTrue(poison)
        for kwargs in [{'scenario': 'deadline'}, {'mode': 'cleanup'}]:
            result, status, trace, applied, poison, fixture = self.provider_case(b'x', **kwargs)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(trace, [])
        result, status, trace, applied, poison, fixture = self.provider_case(b'x' * 8193, fallback=True)
        self.assertEqual(status, (125, 0, 23, 0))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(trace.count('exec:read'), 1)
        self.assertNotIn('exec:apply', trace)
        self.assertIsNone(applied)
        self.assertTrue(poison)

    def test_exact_source_and_history_leave_native_allocator_and_admission_bytes_unchanged(self):
        import hashlib
        current = SCRIPT.read_text()
        source = receiver_before_live_envelope(current)
        frozen = receiver_before_storage_capture(source)
        self.assertEqual((len(frozen.encode()), hashlib.sha256(frozen.encode()).hexdigest()),
                         (65361, FROZEN_MODERN_LOGGING_SOURCE))
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256, LIVE_ENVELOPE_SOURCE)
        self.assertLessEqual(len(source.encode()), 65408)
        self.assertLessEqual(len(source.encode()), 65536)
        for name in ('native', 'capture_stream', 'provider', 'finish'):
            start = '\n' + name + '() {\n'
            self.assertEqual(source.split(start, 1)[1].split('\n}\n', 1)[0].replace(
                STORAGE_CAPTURE_COMMENT_CURRENT, STORAGE_CAPTURE_COMMENT_BEFORE),
                frozen.split(start, 1)[1].split('\n}\n', 1)[0])
        self.assertEqual(source.split('# Entry: pure-control tests', 1)[1].replace(
            STORAGE_CAPTURE_COMMENT_CURRENT, STORAGE_CAPTURE_COMMENT_BEFORE),
            frozen.split('# Entry: pure-control tests', 1)[1])
        self.assertEqual(len(vm.PREREQUISITE_STDERR_PATTERNS), 314)
        for changed in (source + '\n', frozen, source.replace('maximum=8192', 'maximum=12288', 1)):
            with self.assertRaises(AssertionError):
                receiver_before_storage_capture(changed)




class LiveEnvelopeV13SourceControls(unittest.TestCase):
    """Current source bodies on private DATA; no kernel/native qualification."""
    stat = InventoryDestinationControls.stat
    def fixture(self):
        f=BashProtocolControls();f.setUp();self.addCleanup(f.doCleanups)
        s=SCRIPT.read_text();receiver_before_live_envelope(s)
        f.definitions=s.split('# Entry: pure-control tests')[0].replace(
            'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
            f'readonly root={f.root} stage={f.root}/stage')
        return f

    def test_current_stable_guards_and_scalar_prefix_preserved_without_obsolete_cache(self):
        s=SCRIPT.read_text();old=receiver_before_live_envelope(s)
        part=lambda text,name:text.split(name+'() {\n',1)[1].split('\n}\n',1)[0]
        inventory='\n'.join(line for line in part(old,'inventory').split('\n') if 'INVENTORY_START' not in line)
        self.assertEqual(part(s,'inventory'),inventory)
        self.assertNotIn('INVENTORY_START',s)
        old_prefix=part(old,'resource_check').split('  inventory\n',1)[0]
        prefix=part(s,'resource_check').split('  if (($# == 0)); then\n',1)[0]
        self.assertEqual(prefix,old_prefix.replace('$1 == live','$1 == vm-live-v1',1))
        import re
        self.assertEqual(re.findall(r'^([ \t]*)resource_check((?:[ \t].*)?)$',s,re.M),
                         [('    ',''),('  ',''),('',''),('',' vm-live-v1')])
        for name in ('native','capture_stream','process_identity','logs_retirement','emit_logs_evidence'):
            self.assertEqual(part(s,name),part(old,name))

    def selection(self,argument,second='one'):
        f=self.fixture();s=SCRIPT.read_text()
        resource=s.split('resource_check() {\n',1)[1].split('\n}\n',1)[0]
        f.definitions=f.definitions.replace('resource_check() {','unused_resource_check() {',1)
        tail='  if (($# == 0)); then\n'+resource.split('  if (($# == 0)); then\n',1)[1]
        body=r'''rootful_intent=execution-v1 mode=work postlog_site=r
scans=0
inventory() {
  scans=$((scans+1))
  printf '%s\n' "$scans" >> "$root/scans"
  if ((scans==1)); then SNAP=one; else SNAP=$second; fi
}
'''
        from shlex import quote
        body+='second='+quote(second)+'\nresource_check() {\n'+resource.splitlines()[0]+'\n  local before\n'+tail+'\n}\n'
        body+='resource_check'+(' '+argument if argument is not None else '')+'\nprintf healthy\n'
        result=f.child(body).finish()
        trace=(f.root/'scans').read_text().splitlines() if (f.root/'scans').exists() else []
        return f,result,trace

    def test_only_new_literal_skips_inventory_and_stable_still_requires_two_equal_scans(self):
        f,result,trace=self.selection('vm-live-v1',second='unobserved-high-PID/gone')
        self.assertEqual((result.returncode,result.stdout,trace),(0,b'healthy',[]))
        f,result,trace=self.selection(None)
        self.assertEqual((result.returncode,result.stdout,trace),(0,b'healthy',['1','2']))
        f,result,trace=self.selection(None,second='changed')
        self.assertEqual((result.returncode,trace),(1,['1','2']))
        self.assertEqual((f.root/'state/poison').read_bytes(),b'poisoned\n')
        for argument in ("''",'live','vm-live-v2','vm-live-v1 extra','stable'):
            f,result,trace=self.selection(argument)
            self.assertEqual((result.returncode,trace),(1,[]))
            self.assertNotIn(b'healthy',result.stdout)

    def test_current_scalar_pid_nropen_namespace_and_utility_failures_precede_progress(self):
        s=SCRIPT.read_text()
        prefix=s.split('resource_check() {\n',1)[1].split("  value=''\n",1)[0]+"  value=''\n"
        prefix=prefix.replace('read -r value < /proc/sys/kernel/pid_max','read -r value <<< "$selected_pid"',1)
        prefix=prefix.replace('read -r value < /proc/sys/fs/nr_open','read -r value <<< "$selected_open"',1)
        for pid,opened,utility,rc in [('32768','1073741816','ok',0),('1','1','ok',1),
             ('32768','bad','ok',1),('32768','0','ok',1),('32768','1073741817','ok',1),
             ('32768','1','first',1),('32768','1','second',1),('32768','1','drift',1)]:
            f=self.fixture();f.definitions=f.definitions.replace('resource_check() {','unused_resource_check() {',1)
            body=f'selected_pid={pid} selected_open={opened} utility={utility}\n'
            body+=r'''rootful_intent=execution-v1 mode=work postlog_site=r
u() {
  [[ $utility != first || $4 != /proc/1/ns/pid ]] || return 17
  [[ $utility != second || $4 != /proc/self/ns/pid ]] || return 19
  if [[ $utility == drift && $4 == /proc/self/ns/pid ]]; then printf '2:3'; else printf '1:2'; fi
}
'''
            body+='resource_check() {\n'+prefix+'\n}\nresource_check vm-live-v1\nprintf healthy\n'
            result=f.child(body).finish()
            self.assertEqual(result.returncode,rc)
            self.assertEqual(result.stdout,b'healthy' if rc==0 else b'')

    def corridor(self,*,pid='101',first=None,second=None,cgroup=None,inspect=True,missing=None):
        from shlex import quote
        f=self.fixture();cid='c'*64;owned='/libpod_parent/libpod-'+cid
        first=InventoryDestinationControls.stat(self,101,start='2000') if first is None else first
        second=first if second is None else second
        cgroup='0::'+owned+'/init.scope' if cgroup is None else cgroup
        (f.root/'selected').mkdir()
        for name,value in [('stat',first),('second',second),('cgroup',cgroup+'\n')]:
            (f.root/'selected'/name).write_text(value)
        if missing:(f.root/'selected'/missing).unlink()
        s=SCRIPT.read_text()
        corridor='postlog_site=a\n'+s.split('postlog_site=a\n',1)[1].split('postlog_site=k\n',1)[0]
        self.assertEqual(corridor.count('read_file '),3)
        corridor=corridor.replace('"/proc/$node_pid/stat"','"$root/selected/stat"').replace(
            '"/proc/$node_pid/cgroup"','"$root/selected/cgroup"')
        self.assertNotIn('/proc/',corridor)
        f.definitions=f.definitions.replace('\nread_file() {','\nsource_read_file() {',1)
        body=f'rootful_intent=execution-v1 mode=work node_id={cid} selected_pid={quote(pid)}\n'
        body+=f'out=$captures/inspect inspect_good={int(inspect)} stat_reads=0\n'
        body+=r'''trap 'printf "%s\n" "$postlog_failure" > "$root/failure"' EXIT
u() {
  if [[ $* == *State.Pid* ]]; then printf '%s' "$selected_pid"; else ((inspect_good)); fi
}
read_file() {
  printf '%s\n' "$1" >> "$root/reads"
  if [[ $1 == "$root/selected/stat" ]]; then
    stat_reads=$((stat_reads+1))
    if ((stat_reads==2)); then source_read_file "$root/selected/second"; return; fi
  fi
  source_read_file "$1"
}
'''
        result=f.child(body+corridor+'printf healthy\n').finish()
        reads=(f.root/'reads').read_text().splitlines() if (f.root/'reads').exists() else []
        failure=(f.root/'failure').read_text().strip()
        return f,result,reads,failure

    def test_direct_current_samples_accept_actual_root_and_canonical_descendants(self):
        root='/libpod_parent/libpod-'+'c'*64
        for suffix in ('','/init.scope','/system.slice/example.service','/.hidden/a..b'):
            f,result,reads,failure=self.corridor(cgroup='0::'+root+suffix)
            self.assertEqual((result.returncode,result.stdout,len(reads),failure),(0,b'healthy',3,''))
            self.assertTrue((f.root/'state/actual-node-process').read_text().endswith('0::'+root+suffix+'\n'))

    def test_direct_current_samples_refuse_missing_malformed_pid_reuse_and_owned_inspect_drift(self):
        stat=InventoryDestinationControls.stat
        cases=[({'pid':'32768'},'pl2.b'),({'pid':'0101'},'pl2.b'),
          ({'first':''},'pl2.d'),({'first':stat(self,102)},'pl2.d'),
          ({'first':stat(self,101,short=True)},'pl2.d'),
          ({'first':stat(self,101,start='PRIVATE-not-decimal')},'pl2.d'),
          ({'first':'101 '+('0 '*21)+'\n'},'pl2.d'),
          ({'second':stat(self,102,start='2000')},'pl2.h'),
          ({'second':stat(self,101,start='2001')},'pl2.h'),
          ({'missing':'stat'},'pl2.c'),({'missing':'second'},'pl2.h'),
          ({'missing':'cgroup'},'pl2.g'),({'inspect':False},'pl2.a')]
        for arguments,site in cases:
            f,result,reads,failure=self.corridor(**arguments)
            self.assertEqual((result.returncode,failure),(1,site))
            self.assertNotIn(b'healthy',result.stdout)
            self.assertEqual((f.root/'state/poison').read_bytes(),b'poisoned\n')
            self.assertNotIn(b'PRIVATE-not-decimal',result.stdout+result.stderr)

    def test_current_foreign_cgroup_prefix_traversal_and_multiple_records_refuse(self):
        root='/libpod_parent/libpod-'+'c'*64
        for value in ('','0::relative','0::/foreign','0::'+root+'x/init.scope',
          '0::'+root+'/..','0::'+root+'//x','0::'+root+'/./x','0::'+root+'/x/',
          '1::'+root,'0::'+root+'\n0::'+root):
            f,result,reads,failure=self.corridor(cgroup=value)
            self.assertEqual((result.returncode,len(reads),failure),(1,2,'pl2.g'))
            self.assertFalse((f.root/'state/actual-node-process').exists())

    def test_current_inverse_caps_and_all_predecessor_cache_bytes_remain_exact(self):
        import hashlib
        s=SCRIPT.read_text();old=receiver_before_live_envelope(s)
        self.assertEqual((len(old.encode()),hashlib.sha256(old.encode()).hexdigest()),
          (65397,'0a512e1f5d2a9463e17fd5d10319b4a989129eb1149a5c4f4fbfc84b688424ad'))
        self.assertIn('declare -gA INVENTORY_START=()',old)
        self.assertNotIn('INVENTORY_START',s)
        self.assertEqual(vm.PREREQUISITE_RECEIVER_SHA256,LIVE_ENVELOPE_SOURCE)
        self.assertLessEqual(len(s.encode()),65408);self.assertLessEqual(len(s.encode()),65536)
        for bad in (s+'\n',old,s.replace('maximum=680','maximum=681',1),
                    s.replace('vm-live-v1','vm-live-v2',1),s.replace('fd < fd_max','fd <= fd_max',1)):
            with self.assertRaises(AssertionError):receiver_before_live_envelope(bad)

    def test_current_finish_preserves_incoming_failure_and_independent_real_delete_status(self):
        s=SCRIPT.read_text()
        finish='finish() {\n'+s.split('\nfinish() {\n',1)[1].split('\n}\n',1)[0]+'\n}\n'
        for incoming,deleted in ((0,0),(7,0),(0,19),(7,19)):
            f=self.fixture()
            body=r'''pace_close() { :; }
remember() { return 0; }
emit_evidence() { evidence_json=null; }
emit_logs_evidence() { logs_json=null; }
native() {
  [[ $* == "4096 4096 $stage/kind delete cluster --name own" ]] || exit 88
  take cleanup 5 || fail
  tool_status=$delete_result
  return "$delete_result"
}
'''
            body+=finish+f'created=1 create_status=0 delete_status=-1 delete_result={deleted}\n'
            body+='profile=legacy-1.20.15 patch=1.20.15 cluster=own source_status=server-dry-run-observed\n'
            body+='rootful_intent=execution-v1 mode=work\ntake work 70 || fail\ntrap finish EXIT\n'
            result=f.child(body+f'exit {incoming}\n').finish();value=json.loads(result.stdout)
            self.assertEqual(result.returncode,1 if deleted else incoming)
            self.assertEqual((value['schema'],value['resource_profile'],value['kind_delete_status']),
                             (rootful.RESULT_V13,rootful.LIVE_RESOURCE_PROFILE,deleted))
            self.assertEqual(value['state'],'failed' if incoming or deleted else 'source-deployment-positive')
            self.assertEqual(value['network_retirement'],'whole-vm-required')


    def test_current_inventory_executes_prepared_positive_and_per_record_refusals(self):
        import shlex, shutil
        cases=[('positive',None),('missing-task',lambda f:shutil.rmtree(f.process/'task')),
               ('bad-task-start',lambda f:(f.task/'stat').write_text(InventoryDestinationControls.stat(self,101,start='bad'))),
               ('infinite-hard',lambda f:(f.task/'limits').write_text('Max open files 1024 unlimited files\n')),
               ('fd-ceiling',lambda f:(f.task/'fd/1073741816').touch()),
               ('empty',lambda f:shutil.rmtree(f.process))]
        for label,mutate in cases:
            f=InventoryDestinationControls.fixture(self)
            source=SCRIPT.read_text()
            f.host.definitions=source.split('# Entry: pure-control tests')[0].replace(
                'readonly root=/var/lib/kubernetes-lens-rootful stage=/var/lib/kubernetes-lens-stage',
                f'readonly root={f.host.root} stage={f.host.root}/stage')
            f.host.definitions=f.host.definitions.replace('for process in /proc/[0-9]*; do',
                'for process in "$inventory_proc"/[0-9]*; do',1)
            if mutate:mutate(f)
            body='inventory_proc='+shlex.quote(str(f.proc))+'\ninventory\nprintf "%s" "$SNAP"\n'
            result=f.host.child(body).finish()
            if label=='positive':
                self.assertEqual((result.returncode,result.stdout),
                                 (0,b'101:1000:101:1000:1073741816:3,;|'))
            else:
                self.assertEqual(result.returncode,1)
                self.assertEqual(result.stdout,b'')
                self.assertEqual((f.host.root/'state/poison').read_bytes(),b'poisoned\n')




class LiveEnvelopeV13FactsAndDecoderControls(unittest.TestCase):
    """Actual closed metadata/decoder functions with synthetic private wire DATA."""
    def facts(self):
        return json.loads(Path(rootful.__file__).with_name(rootful.LIVE_FACTS_NAME).read_bytes())

    def test_exact_schema_facts_arithmetic_scope_and_no_native_claim(self):
        import hashlib
        raw=Path(rootful.__file__).with_name(rootful.LIVE_FACTS_NAME).read_bytes()
        schema=Path(rootful.__file__).with_name(rootful.LIVE_SCHEMA_NAME).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),rootful.LIVE_FACTS_SHA256)
        self.assertEqual(hashlib.sha256(schema).hexdigest(),rootful.LIVE_SCHEMA_SHA256)
        self.assertEqual(json.loads(schema)['const'],self.facts())
        self.assertNotIn('/tmp/',raw.decode())
        self.assertEqual(self.facts()['theorem']['aggregate_upper'],(2**32//4096)*(2**28))
        self.assertLess(2**48,32767*9999999999)
        self.assertEqual(self.facts()['theorem']['one_page_uint_max_negative'],4503599626321920)
        self.assertGreater((2**20)*(2**32-1),32767*9999999999)
        self.assertNotEqual((2**20)*(2**32-1),(2**18)*(2**32-1))
        self.assertEqual(self.facts()['qualification']['native_qualification'],'not-claimed')
        self.assertIn('recursive-fault dead/leaked files pointers',self.facts()['scope']['excluded'])

    def config(self):
        return {'guest_memory_mib':4096,'tools':{'qemu':deepcopy(self.facts()['domain']['qemu'])}}

    def test_actual_metadata_admission_accepts_exact_and_refuses_memory_tool_and_canonical_image_drift(self):
        good=self.config()
        self.assertEqual(rootful.admit_live_resource_profile(good),
          {'resource_profile':rootful.LIVE_RESOURCE_PROFILE,'resource_facts_sha256':rootful.LIVE_FACTS_SHA256})
        for value in (4097,4096.0,None,False):
            bad=deepcopy(good);bad['guest_memory_mib']=value
            with self.assertRaises(vm.Refusal):rootful.admit_live_resource_profile(bad)
        for tools in (None,{},'unknown',{'qemu':None},{'qemu':'unknown'}):
            bad=deepcopy(good);bad['tools']=tools
            with self.assertRaises(vm.Refusal):rootful.admit_live_resource_profile(bad)
        for key in self.facts()['domain']['qemu']:
            bad=deepcopy(good);bad['tools']['qemu'].pop(key)
            with self.assertRaises(vm.Refusal):rootful.admit_live_resource_profile(bad)
        pin,pin_sha=vm.pin_document();pin=dict(pin);pin['release']='44.20260928.3.3'
        with patch.object(vm,'pin_document',return_value=(pin,pin_sha)):
            with self.assertRaisesRegex(vm.Refusal,'canonical-image'):rootful.admit_live_resource_profile(good)

    def test_missing_mutated_pending_unknown_and_extended_record_never_qualifies(self):
        path=Path(rootful.__file__).with_name(rootful.LIVE_FACTS_NAME);original=vm.read
        raws=[b'null\n',b'{}\n',b'']
        for key,value in (('schema','unknown'),('resource_profile','unknown'),('extra',True)):
            bad=self.facts();bad[key]=value;raws.append(vm.encode(bad))
        bad=self.facts();bad['qualification']['state']='pending';raws.append(vm.encode(bad))
        for raw in raws:
            with patch.object(vm,'read',side_effect=lambda p,*a:raw if Path(p)==path else original(p,*a)):
                with self.assertRaises(vm.Refusal):rootful.admit_live_resource_profile(self.config())
        with patch.object(vm,'read',side_effect=OSError('missing source facts')):
            with self.assertRaises(OSError):rootful.admit_live_resource_profile(self.config())

    def bundle(self,success=False):
        config,value,rows=NodeWaitDecoderControls.bundle(self,'k4.m')
        config['rootful_spec'].update(schema='kubernetes-lens-owned-rootful-v13',
            resource_profile=rootful.LIVE_RESOURCE_PROFILE,resource_facts_sha256=rootful.LIVE_FACTS_SHA256)
        value.update(schema=rootful.RESULT_V13,resource_profile=rootful.LIVE_RESOURCE_PROFILE)
        value['evidence']['source_spec_sha256']=vm.digest(vm.encode(config['rootful_spec']))
        if success:value.update(state='source-deployment-positive',source_deployment='server-dry-run-observed',
            kind_create_status=0,kind_delete_status=0,postlog_failure=None,postlog_native=None,postlog_reason=None)
        return config,value,rows

    def test_actual_v13_result_and_wire_keep_success_failure_and_delete_independent(self):
        for success in (False,True):
            config,value,_rows=self.bundle(success)
            checked=rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=not success)
            self.assertEqual((checked['schema'],checked['resource_profile']),(rootful.RESULT_V13,rootful.LIVE_RESOURCE_PROFILE))
        config,value,_rows=self.bundle();value['kind_delete_status']=19
        self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)['kind_delete_status'],19)

    def test_v13_refuses_v12_stale_profile_facts_and_old_live_inventory_meaning(self):
        for mutation in ('wire-v12','spec-v12','missing-profile','wrong-profile','stale-facts','old-inventory','extra-result-field'):
            config,value,_rows=self.bundle()
            if mutation=='wire-v12':value['schema']=rootful.RESULT_V12;value.pop('resource_profile')
            elif mutation=='spec-v12':config['rootful_spec']['schema']='kubernetes-lens-owned-rootful-v12'
            elif mutation=='missing-profile':value.pop('resource_profile')
            elif mutation=='wrong-profile':value['resource_profile']='unknown'
            elif mutation=='stale-facts':config['rootful_spec']['resource_facts_sha256']='f'*64
            elif mutation=='old-inventory':value.update(postlog_failure='pl1.r',postlog_reason='inv-proc-task',postlog_native=None)
            else:value['extra']=True
            summary=deepcopy(value);summary.pop('evidence')
            with self.assertRaises(vm.Refusal):rootful.result(vm.encode(summary)+b'\n',config,allow_failure=True)
        config,value,_rows=NodeWaitDecoderControls.bundle(self,'k4.m')
        self.assertEqual(rootful.wire_record(vm.encode(value)+b'\n',config,allow_failure=True)['schema'],rootful.RESULT_V12)



if __name__ == '__main__':
    unittest.main()
