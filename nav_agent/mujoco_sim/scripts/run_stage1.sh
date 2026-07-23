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
evaluator_pid=""
recorded_bridge_pid=""
recorded_evaluator_pid=""
cleanup_done=0
postflight_status=1
evaluation_status=125

set +u
source /opt/ros/humble/setup.bash
set -u
rmw_overlay="${HOLOAGENT_STAGE1_RMW_OVERLAY:-}"
if [[ -n "${rmw_overlay}" ]]; then
  rmw_prefix="${rmw_overlay%/}/opt/ros/humble"
  if [[ ! -f "${rmw_prefix}/lib/librmw_cyclonedds_cpp.so" ]]; then
    printf 'invalid CycloneDDS overlay: %s\n' "${rmw_prefix}" >&2
    exit 2
  fi
  export AMENT_PREFIX_PATH="${rmw_prefix}:${AMENT_PREFIX_PATH:-}"
  export LD_LIBRARY_PATH="${rmw_prefix}/lib:${rmw_prefix}/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
fi
export ROS_DOMAIN_ID=77
export ROS_LOCALHOST_ONLY=1
export ROS2CLI_DISABLE_DAEMON=1
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export MUJOCO_GL=egl
export ROS_LOG_DIR="${run_dir}/ros_logs"
export PYTHONPATH="${repo_root}/nav_agent/mujoco_sim:/home/jihun/work/GR00T-WholeBodyControl/.venv_data_collection/lib/python3.10/site-packages:/opt/ros/humble/local/lib/python3.10/dist-packages:/opt/ros/humble/lib/python3.10/site-packages"

stop_recorded_pid() {
  local pid="$1"
  if [[ -z "${pid}" ]]; then
    return
  fi
  if kill -0 "${pid}" 2>/dev/null; then
    kill -INT "${pid}" 2>/dev/null || true
    for _attempt in 1 2 3 4 5; do
      if ! kill -0 "${pid}" 2>/dev/null; then break; fi
      sleep 1
    done
  fi
  if kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
    for _attempt in 1 2 3 4 5; do
      if ! kill -0 "${pid}" 2>/dev/null; then break; fi
      sleep 1
    done
  fi
  if kill -0 "${pid}" 2>/dev/null; then
    kill -KILL "${pid}" 2>/dev/null || true
    for _attempt in 1 2 3 4 5; do
      if [[ ! -e "/proc/${pid}/stat" ]]; then break; fi
      read -r _pid _command process_state _rest <"/proc/${pid}/stat" || true
      if [[ "${process_state:-}" == "Z" ]]; then break; fi
      sleep 1
    done
  fi
  process_state=""
  if [[ -r "/proc/${pid}/stat" ]]; then
    read -r _pid _command process_state _rest <"/proc/${pid}/stat" || true
  fi
  if [[ ! -e "/proc/${pid}/stat" || "${process_state}" == "Z" ]]; then
    wait "${pid}" 2>/dev/null || true
  else
    return 1
  fi
}

cleanup() {
  if [[ ${cleanup_done} -eq 1 ]]; then return; fi
  cleanup_done=1
  stop_recorded_pid "${evaluator_pid}" || true
  stop_recorded_pid "${bridge_pid}" || true
  if [[ -d "${run_dir}" ]]; then
    set +e
    "${python_bin}" -m holoagent_mujoco.preflight \
      --config "${config_path}" \
      --run-dir "${run_dir}" \
      --postflight \
      --bridge-pid "${recorded_bridge_pid:-0}" \
      --evaluator-pid "${recorded_evaluator_pid:-0}" \
      --result-file "${run_dir}/result.pending.json" \
      --final-result-file "${run_dir}/result.json" \
      --evaluator-exit-status "${evaluation_status}" \
      >"${run_dir}/postflight.log" 2>&1
    postflight_status=$?
    set -e
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
recorded_bridge_pid="${bridge_pid}"
printf '%s\n' "${bridge_pid}" >"${run_dir}/bridge.pid"

ready_file="${run_dir}/motion_graph_ready.json"
approval_file="${run_dir}/motion_graph_approved.sha256"
"${python_bin}" -m holoagent_mujoco.stage1_eval \
  --config "${config_path}" \
  --output "${run_dir}/result.pending.json" \
  --ready-file "${ready_file}" \
  --approval-file "${approval_file}" >"${run_dir}/evaluator.log" 2>&1 &
evaluator_pid=$!
recorded_evaluator_pid="${evaluator_pid}"
printf '%s\n' "${evaluator_pid}" >"${run_dir}/evaluator.pid"

for _attempt in {1..120}; do
  if [[ -f "${ready_file}" ]]; then break; fi
  if ! kill -0 "${evaluator_pid}" 2>/dev/null; then break; fi
  sleep 1
done
if [[ ! -f "${ready_file}" ]]; then
  exit 1
fi

"${python_bin}" -m holoagent_mujoco.preflight \
  --config "${config_path}" \
  --run-dir "${run_dir}" \
  --container "${container_name}" \
  --graph-only \
  --expected-node /holoagent_mujoco_bridge \
  --expected-node /holoagent_stage1_eval \
  >"${run_dir}/graph_preflight.log" 2>&1

ready_digest="$(sha256sum "${ready_file}" | awk '{print $1}')"
printf '%s\n' "${ready_digest}" >"${approval_file}"

evaluation_status=124
for _attempt in {1..150}; do
  if ! kill -0 "${evaluator_pid}" 2>/dev/null; then
    set +e
    wait "${evaluator_pid}"
    evaluation_status=$?
    set -e
    evaluator_pid=""
    break
  fi
  sleep 1
done

cleanup
bridge_pid=""
evaluator_pid=""
trap - EXIT
if [[ ${postflight_status} -ne 0 ]]; then
  if [[ ${evaluation_status} -eq 0 ]]; then
    evaluation_status=${postflight_status}
  fi
fi
printf '%s\n' "${run_dir}"
exit "${evaluation_status}"
