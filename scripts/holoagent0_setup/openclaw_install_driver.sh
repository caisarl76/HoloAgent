#!/usr/bin/bash
set -euo pipefail
umask 077
unset BASH_ENV ENV CDPATH

driver_fd=${BASH_SOURCE[0]##*/}
readonly installer_fd=$1
shift
readonly expected_prefix=${OPENCLAW_PREFIX:?}
readonly expected_version=${HOLOAGENT0_EXPECTED_OPENCLAW_VERSION:?}
readonly expected_tarball=${HOLOAGENT0_EXPECTED_OPENCLAW_TARBALL:?}
readonly expected_installer_sha256="21b2b0fc74bd0876bfa6d4268cb28e2b11325204eebd529963d121a2a3126ca1"
[[ "$expected_version" == "2026.7.1-2" ]] || exit 64
[[ "$expected_tarball" == /* ]] || exit 64

[[ "$driver_fd" =~ ^[0-9]+$ ]] || exit 64
((driver_fd >= 3)) || exit 64
[[ "$installer_fd" =~ ^[0-9]+$ ]] || exit 64
((installer_fd >= 3)) || exit 64
[[ "$driver_fd" != "$installer_fd" ]] || exit 64
fd_to_close=$driver_fd
exec {fd_to_close}<&-
readonly installer_fd_path="/proc/self/fd/${installer_fd}"
/usr/bin/python3.10 -I -S -c '
import fcntl
import sys
required = 15
for value in sys.argv[1:]:
    observed = fcntl.fcntl(int(value), 1034)
    if observed & required != required:
        raise SystemExit(1)
' "$installer_fd" || exit 64
observed_installer_sha256=$(
  /usr/bin/sha256sum "$installer_fd_path"
)
observed_installer_sha256=${observed_installer_sha256%% *}
[[ "$observed_installer_sha256" == "$expected_installer_sha256" ]] || exit 64
export OPENCLAW_INSTALL_CLI_SH_NO_RUN=1
# The caller verifies the exact installer SHA-256 before this reviewed source step.
source "$installer_fd_path"
fd_to_close=$installer_fd
exec {fd_to_close}<&-

parse_args "$@"
[[ "$PREFIX" == "$expected_prefix" ]] || exit 64
[[ "$OPENCLAW_VERSION" == "file:${expected_tarball}" ]] || exit 64
[[ "$NODE_VERSION" == "24.15.0" ]] || exit 64
[[ "$INSTALL_METHOD" == "npm" ]] || exit 64
[[ "$RUN_ONBOARD" -eq 0 ]] || exit 64
[[ "$SET_NPM_PREFIX" -eq 0 ]] || exit 64
[[ "$JSON" -eq 1 ]] || exit 64

PATH="$(node_dir)/bin:${PREFIX}/bin:/usr/bin:/bin"
export PATH
[[ -x "$(node_bin)" ]] || exit 65
[[ -x "$(npm_bin)" ]] || exit 65

install_openclaw
emit_json "{\"event\":\"holoagent0-reviewed-subset\",\"ok\":true,\"version\":\"${expected_version}\"}"
