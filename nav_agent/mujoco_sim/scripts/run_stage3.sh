#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
config_path="${1:-${repo_root}/nav_agent/mujoco_sim/config/stage2.yaml}"
python_bin="/home/jihun/work/GR00T-WholeBodyControl/.venv_sim/bin/python"
container_name="${HOLOAGENT_STAGE3_CONTAINER:-holoagent-stages234}"
container_root="/workspace/HoloAgent"
vikit_install="${HOLOAGENT_STAGE3_VIKIT_INSTALL:-/tmp/holoagent-stage3-build-20260724a/install}"
fastlivo_install="${HOLOAGENT_STAGE3_FASTLIVO_INSTALL:-/tmp/holoagent-stage3-build-20260724b/install}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${repo_root}/outputs/mujoco_holoagent/${run_id}"
container_run_dir="${container_root}/outputs/mujoco_holoagent/${run_id}"
converter_build="/tmp/holoagent-stage3-converter-${run_id}"
bridge_pid=""
converter_host_pid=""
fastlivo_host_pid=""
evaluator_host_pid=""
recorded_bridge_pid=""
recorded_converter_host_pid=""
recorded_fastlivo_host_pid=""
recorded_evaluator_host_pid=""
converter_container_pid=""
fastlivo_container_pid=""
evaluator_container_pid=""
evaluation_status=125
postflight_status=1
cleanup_done=0

set +u
source /opt/ros/humble/setup.bash
set -u
rmw_overlay="${HOLOAGENT_STAGE3_RMW_OVERLAY:-/tmp/holoagent_stage1_cyclonedds_overlay}"
rmw_prefix="${rmw_overlay%/}/opt/ros/humble"
if [[ ! -f "${rmw_prefix}/lib/librmw_cyclonedds_cpp.so" ]]; then
  printf 'invalid CycloneDDS overlay: %s\n' "${rmw_prefix}" >&2
  exit 2
fi
export AMENT_PREFIX_PATH="${rmw_prefix}:${AMENT_PREFIX_PATH:-}"
export LD_LIBRARY_PATH="${rmw_prefix}/lib:${rmw_prefix}/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
export ROS_DOMAIN_ID=77
export ROS_LOCALHOST_ONLY=1
export ROS2CLI_DISABLE_DAEMON=1
export RMW_IMPLEMENTATION=rmw_cyclonedds_cpp
export MUJOCO_GL=egl
export ROS_LOG_DIR="${run_dir}/ros_logs"
export PYTHONPATH="${repo_root}/nav_agent/mujoco_sim:/home/jihun/work/GR00T-WholeBodyControl/.venv_data_collection/lib/python3.10/site-packages:/opt/ros/humble/local/lib/python3.10/dist-packages:/opt/ros/humble/lib/python3.10/site-packages"

container_pid_alive() {
  docker exec "${container_name}" kill -0 "$1" >/dev/null 2>&1
}

stop_container_pid() {
  local pid="$1"
  if [[ -z "${pid}" ]]; then return; fi
  for signal in INT TERM KILL; do
    if ! container_pid_alive "${pid}"; then break; fi
    docker exec "${container_name}" kill -"${signal}" "${pid}" >/dev/null 2>&1 || true
    for _attempt in 1 2 3 4 5; do
      if ! container_pid_alive "${pid}"; then break; fi
      sleep 1
    done
  done
}

stop_host_pid() {
  local pid="$1"
  if [[ -z "${pid}" ]]; then return; fi
  for signal in INT TERM KILL; do
    if ! kill -0 "${pid}" 2>/dev/null; then break; fi
    kill -"${signal}" "${pid}" 2>/dev/null || true
    for _attempt in 1 2 3 4 5; do
      if ! kill -0 "${pid}" 2>/dev/null; then break; fi
      sleep 1
    done
  done
  wait "${pid}" 2>/dev/null || true
}

cleanup() {
  if [[ ${cleanup_done} -eq 1 ]]; then return; fi
  cleanup_done=1
  stop_container_pid "${evaluator_container_pid}" || true
  stop_container_pid "${fastlivo_container_pid}" || true
  stop_container_pid "${converter_container_pid}" || true
  stop_host_pid "${evaluator_host_pid}" || true
  stop_host_pid "${fastlivo_host_pid}" || true
  stop_host_pid "${converter_host_pid}" || true
  stop_host_pid "${bridge_pid}" || true
  if [[ -d "${run_dir}" && -f "${run_dir}/result.pending.json" ]]; then
    local args=(
      --config "${config_path}" --run-dir "${run_dir}"
      --container "${container_name}" --workspace-source "${repo_root}"
      --postflight --evaluator-exit-status "${evaluation_status}"
      --result-file "${run_dir}/result.pending.json"
      --final-result-file "${run_dir}/result.json"
    )
    for pid in "${recorded_bridge_pid}" "${recorded_converter_host_pid}" "${recorded_fastlivo_host_pid}" "${recorded_evaluator_host_pid}"; do
      if [[ -n "${pid}" ]]; then args+=(--host-pid "${pid}"); fi
    done
    for pid in "${converter_container_pid}" "${fastlivo_container_pid}" "${evaluator_container_pid}"; do
      if [[ -n "${pid}" ]]; then args+=(--container-pid "${pid}"); fi
    done
    set +e
    "${python_bin}" -m holoagent_mujoco.stage3_result "${args[@]}" >"${run_dir}/postflight.log" 2>&1
    postflight_status=$?
    set -e
  fi
}
trap cleanup EXIT

mkdir -p "${repo_root}/outputs/mujoco_holoagent"
"${python_bin}" -m holoagent_mujoco.stage2_result \
  --config "${config_path}" --run-dir "${run_dir}" \
  --container "${container_name}" --workspace-source "${repo_root}" \
  >"${run_id}.stage3-preflight.tmp"
mv -- "${run_id}.stage3-preflight.tmp" "${run_dir}/preflight.log"
cp -- "${config_path}" "${run_dir}/stage3.yaml"
"${python_bin}" -m holoagent_mujoco.calibration \
  --config "${config_path}" --output-dir "${run_dir}" \
  >"${run_dir}/calibration.log" 2>&1

docker exec "${container_name}" bash -lc "
  test -x ${fastlivo_install}/fast_livo/lib/fast_livo/fastlivo_mapping
  sha256sum ${fastlivo_install}/fast_livo/lib/fast_livo/fastlivo_mapping
  sha256sum ${container_root}/agentic_robot/core/src/fast_livo/CMakeLists.txt
  sha256sum ${container_root}/nav_agent/mujoco_sim/overlays/fast_livo_generated_interface.patch
" >"${run_dir}/fastlivo_artifacts.sha256"

docker exec "${container_name}" bash -lc "
  set -e
  set +u
  source /opt/ros/humble/setup.bash
  source /livox/livox_ws/install/setup.bash
  set -u
  cd ${container_root}/nav_agent/sem_nav_ctr/src/holoagent_livox_converter
  colcon --log-base ${converter_build}/log build --base-paths . \\
    --packages-select holoagent_livox_converter \\
    --build-base ${converter_build}/build --install-base ${converter_build}/install
" >"${run_dir}/converter_build.log" 2>&1

"${python_bin}" -m holoagent_mujoco.bridge_node --config "${config_path}" \
  >"${run_dir}/bridge.log" 2>&1 &
bridge_pid=$!
recorded_bridge_pid="${bridge_pid}"
printf '%s\n' "${bridge_pid}" >"${run_dir}/bridge.pid"

docker exec --env ROS_DOMAIN_ID=77 --env ROS_LOCALHOST_ONLY=1 \
  --env ROS2CLI_DISABLE_DAEMON=1 --env RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
  --env ROS_LOG_DIR="${container_run_dir}/ros_logs" \
  "${container_name}" bash -lc "
    set +u; source /opt/ros/humble/setup.bash; source /livox/livox_ws/install/setup.bash; set -u
    source ${converter_build}/install/setup.bash
    export PYTHONPATH=${container_root}/nav_agent/mujoco_sim:${container_root}/nav_agent/sem_nav_ctr/src/holoagent_livox_converter:\${PYTHONPATH:-}
    printf '%s\\n' \"\$\$\" >${container_run_dir}/converter.container.pid
    exec ${converter_build}/install/holoagent_livox_converter/lib/holoagent_livox_converter/livox_converter --ros-args \\
      -p use_sim_time:=true -p acquisition_mode:=snapshot \\
      -p scan_period_ns:=100000000 -p min_finite_points:=2500
  " >"${run_dir}/converter.log" 2>&1 &
converter_host_pid=$!
recorded_converter_host_pid="${converter_host_pid}"

docker exec --env ROS_DOMAIN_ID=77 --env ROS_LOCALHOST_ONLY=1 \
  --env ROS2CLI_DISABLE_DAEMON=1 --env RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
  --env ROS_LOG_DIR="${container_run_dir}/ros_logs" \
  "${container_name}" bash -lc "
    set +u; source /opt/ros/humble/setup.bash; source /livox/livox_ws/install/setup.bash; set -u
    source ${vikit_install}/vikit_common/share/vikit_common/local_setup.bash
    source ${vikit_install}/vikit_ros/share/vikit_ros/local_setup.bash
    source ${fastlivo_install}/fast_livo/share/fast_livo/local_setup.bash
    printf '%s\\n' \"\$\$\" >${container_run_dir}/fastlivo.container.pid
    exec ${fastlivo_install}/fast_livo/lib/fast_livo/fastlivo_mapping --ros-args \\
      --params-file ${container_run_dir}/fastlivo_sim.yaml \\
      -r /robot_odom:=/stage3/unused_robot_odom
  " >"${run_dir}/fastlivo.log" 2>&1 &
fastlivo_host_pid=$!
recorded_fastlivo_host_pid="${fastlivo_host_pid}"

docker exec --env ROS_DOMAIN_ID=77 --env ROS_LOCALHOST_ONLY=1 \
  --env ROS2CLI_DISABLE_DAEMON=1 --env RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
  --env ROS_LOG_DIR="${container_run_dir}/ros_logs" \
  "${container_name}" bash -lc "
    set +u; source /opt/ros/humble/setup.bash; source /livox/livox_ws/install/setup.bash; set -u
    source ${converter_build}/install/setup.bash
    export PYTHONPATH=${container_root}/nav_agent/mujoco_sim:${container_root}/nav_agent/sem_nav_ctr/src/holoagent_livox_converter:\${PYTHONPATH:-}
    printf '%s\\n' \"\$\$\" >${container_run_dir}/evaluator.container.pid
    exec ${converter_build}/install/holoagent_livox_converter/lib/holoagent_livox_converter/stage3_eval \\
      --config ${container_root}/nav_agent/mujoco_sim/config/stage2.yaml \\
      --calibration ${container_run_dir}/fastlivo_sim.yaml \\
      --calibration-metadata ${container_run_dir}/fastlivo_sim_calibration.json \\
      --output ${container_run_dir}/result.pending.json \\
      --ready-file ${container_run_dir}/stage3_graph_ready.json \\
      --approval-file ${container_run_dir}/stage3_graph_approved.sha256
  " >"${run_dir}/evaluator.log" 2>&1 &
evaluator_host_pid=$!
recorded_evaluator_host_pid="${evaluator_host_pid}"

for _attempt in {1..180}; do
  if [[ -f "${run_dir}/stage3_graph_ready.json" ]]; then break; fi
  if ! kill -0 "${evaluator_host_pid}" 2>/dev/null; then break; fi
  sleep 1
done
if [[ ! -f "${run_dir}/stage3_graph_ready.json" ]]; then exit 1; fi
converter_container_pid="$(<"${run_dir}/converter.container.pid")"
fastlivo_container_pid="$(<"${run_dir}/fastlivo.container.pid")"
evaluator_container_pid="$(<"${run_dir}/evaluator.container.pid")"

graph_command="printf '=== NODES ===\\n'; ros2 node list --no-daemon | sort; printf '=== TOPICS ===\\n'; ros2 topic list --no-daemon -t | sort; printf '=== SERVICES ===\\n'; ros2 service list --no-daemon -t | sort; printf '=== ACTIONS ===\\n'"
bash -lc "source /opt/ros/humble/setup.bash; ${graph_command}" >"${run_dir}/host_graph.txt"
docker exec --env ROS_DOMAIN_ID=77 --env ROS_LOCALHOST_ONLY=1 \
  --env ROS2CLI_DISABLE_DAEMON=1 --env RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
  "${container_name}" bash -lc "
    set +u; source /opt/ros/humble/setup.bash; source /livox/livox_ws/install/setup.bash
    source ${fastlivo_install}/fast_livo/share/fast_livo/local_setup.bash; set -u
    ${graph_command}
  " >"${run_dir}/container_graph.txt"

"${python_bin}" -m holoagent_mujoco.stage3_result \
  --config "${config_path}" --run-dir "${run_dir}" \
  --container "${container_name}" --workspace-source "${repo_root}" \
  --graph-host "${run_dir}/host_graph.txt" \
  --graph-container "${run_dir}/container_graph.txt" \
  >"${run_dir}/graph_preflight.log"
ready_digest="$(sha256sum "${run_dir}/stage3_graph_ready.json" | awk '{print $1}')"
printf '%s\n' "${ready_digest}" >"${run_dir}/stage3_graph_approved.sha256"

evaluation_status=124
for _attempt in {1..300}; do
  if ! kill -0 "${evaluator_host_pid}" 2>/dev/null; then
    set +e; wait "${evaluator_host_pid}"; evaluation_status=$?; set -e
    evaluator_host_pid=""
    break
  fi
  sleep 1
done

cleanup
bridge_pid=""; converter_host_pid=""; fastlivo_host_pid=""; evaluator_host_pid=""
trap - EXIT
if [[ ${postflight_status} -ne 0 && ${evaluation_status} -eq 0 ]]; then
  evaluation_status=${postflight_status}
fi
printf '%s\n' "${run_dir}"
exit "${evaluation_status}"
