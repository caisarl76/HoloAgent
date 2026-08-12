#!/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH PYTHONPATH

script_source=${BASH_SOURCE[0]}
invocation_cwd=$(builtin pwd -P)
if [[ "$script_source" != /* ]]; then
  script_source=$invocation_cwd/$script_source
fi
path_component=$script_source
while [[ "$path_component" != / ]]; do
  if [[ -L "$path_component" ]]; then
    echo "WRAPPER_IDENTITY_MISMATCH" >&2
    exit 2
  fi
  path_component=${path_component%/*}
  [[ -n "$path_component" ]] || path_component=/
done
if [[ "${script_source##*/}" != "provision_openclaw.sh" ]]; then
  echo "WRAPPER_IDENTITY_MISMATCH" >&2
  exit 2
fi

readonly OPENCLAW_VERSION="2026.7.1-2"
readonly NODE_VERSION="24.15.0"
readonly INSTALLER_SHA256="21b2b0fc74bd0876bfa6d4268cb28e2b11325204eebd529963d121a2a3126ca1"
readonly REVIEWED_PYTHON="/usr/bin/python3.10"

dry_run=0
authorized_live_provisioning=0
output_dir=""
prefix=""
configuration_root=""
previous_record=""
while (($#)); do
  case "$1" in
    --dry-run)
      dry_run=1
      shift
      ;;
    --authorized-live-provisioning)
      authorized_live_provisioning=1
      shift
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || { echo "missing --output-dir value" >&2; exit 2; }
      output_dir=$2
      shift 2
      ;;
    --prefix)
      [[ $# -ge 2 ]] || { echo "missing --prefix value" >&2; exit 2; }
      prefix=$2
      shift 2
      ;;
    --configuration-root)
      [[ $# -ge 2 ]] || { echo "missing --configuration-root value" >&2; exit 2; }
      configuration_root=$2
      shift 2
      ;;
    --previous-record)
      [[ $# -ge 2 ]] || { echo "missing --previous-record value" >&2; exit 2; }
      previous_record=$2
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[[ -n "$output_dir" ]] || { echo "--output-dir is required" >&2; exit 2; }
[[ -x "$REVIEWED_PYTHON" ]] || { echo "reviewed Python is unavailable" >&2; exit 2; }
script_parent=${script_source%/*}
if [[ "$script_parent" == "$script_source" ]]; then
  script_parent=.
fi
CDPATH= builtin cd -- "$script_parent"
script_dir=$(builtin pwd -P)
canonical_wrapper=$script_dir/provision_openclaw.sh
if [[ ! -f "$canonical_wrapper" || -L "$canonical_wrapper" || ! "$script_source" -ef "$canonical_wrapper" || ! -f "$script_dir/holoagent0_setup/openclaw_gate.py" ]]; then
  echo "WRAPPER_IDENTITY_MISMATCH" >&2
  exit 2
fi

if ((dry_run)); then
  /usr/bin/env -i \
    PATH=/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    "$REVIEWED_PYTHON" -I -S -c 'import json; print(json.dumps({"package": "openclaw@2026.7.1-2", "node_version": "24.15.0", "installer_sha256": "21b2b0fc74bd0876bfa6d4268cb28e2b11325204eebd529963d121a2a3126ca1", "network_performed": False}, sort_keys=True))'
  exit 0
fi

if (( ! authorized_live_provisioning )); then
  echo "LIVE_PROVISIONING_NOT_AUTHORIZED" >&2
  exit 2
fi

command=(
  /usr/bin/env -i
  PATH=/usr/bin:/bin
  PYTHONDONTWRITEBYTECODE=1
  "$REVIEWED_PYTHON" -I -S -c
  'import runpy,sys; sys.path.insert(0, sys.argv[1]); sys.argv=sys.argv[2:]; runpy.run_module("holoagent0_setup.openclaw_gate", run_name="__main__", alter_sys=True)'
  "$script_dir"
  provision
  --output-dir "$output_dir"
)
if [[ -n "$prefix" ]]; then
  command+=(--prefix "$prefix")
fi
if [[ -n "$configuration_root" ]]; then
  command+=(--configuration-root "$configuration_root")
fi
if [[ -n "$previous_record" ]]; then
  command+=(--previous-record "$previous_record")
fi

exec "${command[@]}"
