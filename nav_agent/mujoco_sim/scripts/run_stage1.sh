#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
config_path="${1:-${repo_root}/nav_agent/mujoco_sim/config/stage1.yaml}"
python_bin="/home/jihun/work/GR00T-WholeBodyControl/.venv_sim/bin/python"
container_name="${HOLOAGENT_STAGE1_CONTAINER:-holoagent_running}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
evidence_root="${repo_root}/outputs/mujoco_holoagent"
run_dir="${evidence_root}/${run_id}"
preflight_log="${evidence_root}/${run_id}.preflight.log"
bridge_pid=""

export ROS_DOMAIN_ID=77
export ROS_LOCALHOST_ONLY=1
export ROS2CLI_DISABLE_DAEMON=1
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export MUJOCO_GL=egl
export PYTHONPATH="${repo_root}/nav_agent/mujoco_sim:/home/jihun/work/GR00T-WholeBodyControl/.venv_data_collection/lib/python3.10/site-packages:/opt/ros/humble/local/lib/python3.10/dist-packages:/opt/ros/humble/lib/python3.10/site-packages"

cleanup() {
  if [[ -n "${bridge_pid}" ]] && kill -0 "${bridge_pid}" 2>/dev/null; then
    kill -INT "${bridge_pid}" 2>/dev/null || true
    for _attempt in 1 2 3 4 5; do
      if ! kill -0 "${bridge_pid}" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    if kill -0 "${bridge_pid}" 2>/dev/null; then
      kill -TERM "${bridge_pid}" 2>/dev/null || true
    fi
    wait "${bridge_pid}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

mkdir -p "${evidence_root}"
set +e
"${python_bin}" -m holoagent_mujoco.preflight \
  --config "${config_path}" \
  --run-dir "${run_dir}" \
  --container "${container_name}" >"${preflight_log}" 2>&1
preflight_status=$?
set -e
if [[ -d "${run_dir}" ]]; then
  mv -- "${preflight_log}" "${run_dir}/preflight.log"
fi
if [[ ${preflight_status} -ne 0 ]]; then
  exit "${preflight_status}"
fi

cp -- "${config_path}" "${run_dir}/stage1.yaml"
"${python_bin}" -m holoagent_mujoco.bridge_node \
  --config "${config_path}" >"${run_dir}/bridge.log" 2>&1 &
bridge_pid=$!
printf '%s\n' "${bridge_pid}" >"${run_dir}/bridge.pid"

"${python_bin}" -m holoagent_mujoco.preflight \
  --config "${config_path}" \
  --run-dir "${run_dir}" \
  --container "${container_name}" \
  --graph-only >"${run_dir}/graph_preflight.log" 2>&1

set +e
"${python_bin}" -m holoagent_mujoco.stage1_eval \
  --config "${config_path}" \
  --output "${run_dir}/result.json" >"${run_dir}/evaluator.log" 2>&1
evaluation_status=$?
set -e

cleanup
bridge_pid=""
trap - EXIT
printf '%s\n' "${run_dir}"
exit "${evaluation_status}"
