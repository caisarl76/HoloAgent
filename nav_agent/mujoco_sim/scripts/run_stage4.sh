#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../../.." && pwd)"
config_path="${1:-${repo_root}/nav_agent/mujoco_sim/config/stage4.yaml}"
python_bin="/home/jihun/work/GR00T-WholeBodyControl/.venv_sim/bin/python"
container_name="${HOLOAGENT_STAGE4_CONTAINER:-holoagent-stages234}"
container_root="/workspace/HoloAgent"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="${repo_root}/outputs/mujoco_holoagent/${run_id}"
container_run_dir="${container_root}/outputs/mujoco_holoagent/${run_id}"
build_root="/tmp/holoagent-stage4-${run_id}"
versions_tmp="$(mktemp /tmp/holoagent-stage4-nav2-versions.XXXXXX)"

bridge_pid=""
fixture_host_pid=""
nav_host_pid=""
evaluator_host_pid=""
fixture_container_pid=""
nav_container_pid=""
evaluator_container_pid=""
recorded_bridge_pid=""
recorded_fixture_host_pid=""
recorded_nav_host_pid=""
recorded_evaluator_host_pid=""
evaluation_status=125
postflight_status=1
cleanup_done=0

set +u
source /opt/ros/humble/setup.bash
set -u
rmw_overlay="${HOLOAGENT_STAGE4_RMW_OVERLAY:-/tmp/holoagent_stage1_cyclonedds_overlay}"
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
export LC_ALL=C
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

capture_host_graph() {
  printf '=== NODES ===\n'
  ros2 node list --no-daemon | sort
  printf '=== TOPICS ===\n'
  ros2 topic list --no-daemon -t | sort
  printf '=== SERVICES ===\n'
  ros2 service list --no-daemon -t | sort
  printf '=== ACTIONS ===\n'
  ros2 action list -t | sort
}

capture_container_graph() {
  docker exec \
    --env ROS_DOMAIN_ID=77 \
    --env ROS_LOCALHOST_ONLY=1 \
    --env ROS2CLI_DISABLE_DAEMON=1 \
    --env RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
    --env LC_ALL=C \
    "${container_name}" bash -lc "
      set +u
      source /opt/ros/humble/setup.bash
      if [[ -f ${build_root}/install/setup.bash ]]; then source ${build_root}/install/setup.bash; fi
      set -u
      printf '=== NODES ===\\n'
      ros2 node list --no-daemon | sort
      printf '=== TOPICS ===\\n'
      ros2 topic list --no-daemon -t | sort
      printf '=== SERVICES ===\\n'
      ros2 service list --no-daemon -t | sort
      printf '=== ACTIONS ===\\n'
      ros2 action list -t | sort
    "
}

capture_postflight_graphs() {
  for _attempt in {1..30}; do
    if [[ -z "$(ros2 node list --no-daemon)" ]]; then break; fi
    sleep 1
  done
  capture_host_graph >"${run_dir}/postflight_host_graph.txt"
  capture_container_graph >"${run_dir}/postflight_container_graph.txt"
}

cleanup() {
  if [[ ${cleanup_done} -eq 1 ]]; then return; fi
  cleanup_done=1
  stop_container_pid "${evaluator_container_pid}" || true
  stop_container_pid "${nav_container_pid}" || true
  stop_container_pid "${fixture_container_pid}" || true
  stop_host_pid "${evaluator_host_pid}" || true
  stop_host_pid "${nav_host_pid}" || true
  stop_host_pid "${fixture_host_pid}" || true
  stop_host_pid "${bridge_pid}" || true
  if [[ -d "${run_dir}" ]]; then
    capture_postflight_graphs || true
  fi
  if [[ -d "${run_dir}" && -f "${run_dir}/result.pending.json" ]]; then
    local args=(
      --config "${config_path}" --run-dir "${run_dir}"
      --container "${container_name}" --workspace-source "${repo_root}"
      --postflight --evaluator-exit-status "${evaluation_status}"
      --result-file "${run_dir}/result.pending.json"
      --final-result-file "${run_dir}/result.json"
      --graph-host "${run_dir}/postflight_host_graph.txt"
      --graph-container "${run_dir}/postflight_container_graph.txt"
    )
    for pid in "${recorded_bridge_pid}" "${recorded_fixture_host_pid}" "${recorded_nav_host_pid}" "${recorded_evaluator_host_pid}"; do
      if [[ -n "${pid}" ]]; then args+=(--host-pid "${pid}"); fi
    done
    for pid in "${fixture_container_pid}" "${nav_container_pid}" "${evaluator_container_pid}"; do
      if [[ -n "${pid}" ]]; then args+=(--container-pid "${pid}"); fi
    done
    set +e
    "${python_bin}" -m holoagent_mujoco.stage4_result "${args[@]}" \
      >"${run_dir}/postflight.log" 2>&1
    postflight_status=$?
    set -e
  fi
  rm -f -- "${versions_tmp}"
}
trap cleanup EXIT

mkdir -p "${repo_root}/outputs/mujoco_holoagent"
docker exec "${container_name}" dpkg-query -W '-f=${Package}=${Version}\n' \
  ros-humble-navigation2 ros-humble-nav2-bringup ros-humble-nav2-controller \
  ros-humble-nav2-lifecycle-manager ros-humble-nav2-map-server \
  ros-humble-nav2-planner ros-humble-diagnostic-updater >"${versions_tmp}"

"${python_bin}" -m holoagent_mujoco.stage4_result \
  --config "${config_path}" --run-dir "${run_dir}" \
  --container "${container_name}" --workspace-source "${repo_root}" \
  --nav2-versions "${versions_tmp}" >"${run_id}.stage4-preflight.tmp"
mv -- "${run_id}.stage4-preflight.tmp" "${run_dir}/preflight.log"
cp -- "${config_path}" "${run_dir}/stage4.yaml"
cp -- "${versions_tmp}" "${run_dir}/nav2-package-versions.txt"

docker exec "${container_name}" bash -lc "
  set -e
  set +u
  source /opt/ros/humble/setup.bash
  set -u
  cd ${container_root}/nav_agent/mujoco_sim
  colcon --log-base ${build_root}/log build --base-paths . \\
    --packages-select holoagent_mujoco \\
    --build-base ${build_root}/build --install-base ${build_root}/install
" >"${run_dir}/colcon_build.log" 2>&1

"${python_bin}" -m holoagent_mujoco.stage4_prepare \
  --config "${config_path}" --output-dir "${run_dir}" \
  --runtime-output-dir "${container_run_dir}" \
  >"${run_dir}/stage4_prepare.log" 2>&1

"${python_bin}" -m holoagent_mujoco.bridge_node --config "${config_path}" \
  >"${run_dir}/bridge.log" 2>&1 &
bridge_pid=$!
recorded_bridge_pid="${bridge_pid}"
printf '%s\n' "${bridge_pid}" >"${run_dir}/bridge.pid"

docker exec \
  --env ROS_DOMAIN_ID=77 --env ROS_LOCALHOST_ONLY=1 \
  --env ROS2CLI_DISABLE_DAEMON=1 --env RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
  --env ROS_LOG_DIR="${container_run_dir}/ros_logs" --env LC_ALL=C \
  "${container_name}" bash -lc "
    set +u
    source /opt/ros/humble/setup.bash
    source ${build_root}/install/setup.bash
    set -u
    printf '%s\\n' \"\$\$\" >${container_run_dir}/fixture.container.pid
    exec ${build_root}/install/holoagent_mujoco/lib/holoagent_mujoco/stage4_fixture \\
      --config ${container_root}/nav_agent/mujoco_sim/config/stage4.yaml
  " >"${run_dir}/fixture.log" 2>&1 &
fixture_host_pid=$!
recorded_fixture_host_pid="${fixture_host_pid}"

docker exec \
  --env ROS_DOMAIN_ID=77 --env ROS_LOCALHOST_ONLY=1 \
  --env ROS2CLI_DISABLE_DAEMON=1 --env RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
  --env ROS_LOG_DIR="${container_run_dir}/ros_logs" --env LC_ALL=C \
  "${container_name}" bash -lc "
    set +u
    source /opt/ros/humble/setup.bash
    source ${build_root}/install/setup.bash
    set -u
    printf '%s\\n' \"\$\$\" >${container_run_dir}/nav.container.pid
    exec ros2 launch holoagent_mujoco stage4_nav2.launch.py \\
      params_file:=${container_root}/nav_agent/mujoco_sim/config/stage4_nav2.yaml \\
      map:=${container_run_dir}/sim_map.yaml use_sim_time:=true autostart:=true
  " >"${run_dir}/nav2.log" 2>&1 &
nav_host_pid=$!
recorded_nav_host_pid="${nav_host_pid}"

docker exec \
  --env ROS_DOMAIN_ID=77 --env ROS_LOCALHOST_ONLY=1 \
  --env ROS2CLI_DISABLE_DAEMON=1 --env RMW_IMPLEMENTATION=rmw_cyclonedds_cpp \
  --env ROS_LOG_DIR="${container_run_dir}/ros_logs" --env LC_ALL=C \
  "${container_name}" bash -lc "
    set +u
    source /opt/ros/humble/setup.bash
    source ${build_root}/install/setup.bash
    set -u
    printf '%s\\n' \"\$\$\" >${container_run_dir}/evaluator.container.pid
    exec ${build_root}/install/holoagent_mujoco/lib/holoagent_mujoco/stage4_eval \\
      --config ${container_root}/nav_agent/mujoco_sim/config/stage4.yaml \\
      --manifest ${container_run_dir}/stage4_manifest.json \\
      --output ${container_run_dir}/result.pending.json \\
      --ready-file ${container_run_dir}/stage4_graph_ready.json \\
      --approval-file ${container_run_dir}/stage4_graph_approved.sha256
  " >"${run_dir}/evaluator.log" 2>&1 &
evaluator_host_pid=$!
recorded_evaluator_host_pid="${evaluator_host_pid}"

for _attempt in {1..180}; do
  if [[ -f "${run_dir}/stage4_graph_ready.json" ]]; then break; fi
  if ! kill -0 "${evaluator_host_pid}" 2>/dev/null; then break; fi
  sleep 1
done

fixture_container_pid="$(<"${run_dir}/fixture.container.pid")"
nav_container_pid="$(<"${run_dir}/nav.container.pid")"
evaluator_container_pid="$(<"${run_dir}/evaluator.container.pid")"
if [[ ! -f "${run_dir}/stage4_graph_ready.json" ]]; then
  if ! kill -0 "${evaluator_host_pid}" 2>/dev/null; then
    set +e; wait "${evaluator_host_pid}"; evaluation_status=$?; set -e
    evaluator_host_pid=""
  fi
  exit 1
fi

capture_host_graph >"${run_dir}/host_graph.txt"
capture_container_graph >"${run_dir}/container_graph.txt"
"${python_bin}" -m holoagent_mujoco.stage4_result \
  --config "${config_path}" --run-dir "${run_dir}" \
  --container "${container_name}" --workspace-source "${repo_root}" \
  --graph-host "${run_dir}/host_graph.txt" \
  --graph-container "${run_dir}/container_graph.txt" \
  >"${run_dir}/graph_preflight.log"

ready_digest="$(sha256sum "${run_dir}/stage4_graph_ready.json" | awk '{print $1}')"
printf '%s\n' "${ready_digest}" >"${run_dir}/stage4_graph_approved.sha256"

evaluation_status=124
for _attempt in {1..420}; do
  if ! kill -0 "${evaluator_host_pid}" 2>/dev/null; then
    set +e; wait "${evaluator_host_pid}"; evaluation_status=$?; set -e
    evaluator_host_pid=""
    break
  fi
  sleep 1
done

cleanup
bridge_pid=""
fixture_host_pid=""
nav_host_pid=""
evaluator_host_pid=""
trap - EXIT
if [[ ${postflight_status} -ne 0 && ${evaluation_status} -eq 0 ]]; then
  evaluation_status=${postflight_status}
fi
printf '%s\n' "${run_dir}"
exit "${evaluation_status}"
