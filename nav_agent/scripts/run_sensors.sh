#!/usr/bin/env bash
set -euo pipefail

# run on hostmachine
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/nav_agent_env.sh"
load_nav_agent_env_file "${NAV_AGENT_ENV_FILE:-}"
SESSION_NAME="${SENSOR_TMUX_SESSION:-robot_sensors}"
SENSOR_PRE_CMD="${SENSOR_PRE_CMD:-}"
CAMERA_CMD="${CAMERA_CMD:-}"
IMU_WS="${IMU_WS:-$HOME/code_vln/ros2_ws}"
IMU_CMD="${IMU_CMD:-ros2 run imu_publisher imu_extractor}"
LIVOX_CMD="${LIVOX_CMD:-ros2 launch livox_ros_driver2 msg_MID360_launch.py}"

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    tmux kill-session -t "$SESSION_NAME"
    echo "Session '$SESSION_NAME' has been deleted."
fi

# 创建新的 tmux 会话，不附加 (-d)
tmux new-session -d -s "$SESSION_NAME" -n camera_tab

# # --- Window 1: Camera ---
if [[ -n "$SENSOR_PRE_CMD" ]]; then
    tmux send-keys -t "$SESSION_NAME:camera_tab" "$SENSOR_PRE_CMD" C-m
fi
if [[ -n "$CAMERA_CMD" ]]; then
    tmux send-keys -t "$SESSION_NAME:camera_tab" "$CAMERA_CMD" C-m
else
    tmux send-keys -t "$SESSION_NAME:camera_tab" "echo 'camera launch disabled; set CAMERA_CMD to enable RealSense.'" C-m
fi

# --- Window 2: IMU ---
tmux new-window -t "$SESSION_NAME" -n imu_tab
if [[ -n "$SENSOR_PRE_CMD" ]]; then
    tmux send-keys -t "$SESSION_NAME:imu_tab" "$SENSOR_PRE_CMD" C-m
fi
tmux send-keys -t "$SESSION_NAME:imu_tab" "cd \"$IMU_WS\"" C-m
tmux send-keys -t "$SESSION_NAME:imu_tab" "unset ASAN_OPTIONS" C-m
tmux send-keys -t "$SESSION_NAME:imu_tab" "source install/setup.bash" C-m
tmux send-keys -t "$SESSION_NAME:imu_tab" "$IMU_CMD" C-m

# --- Window 3: LiDAR ---
tmux new-window -t "$SESSION_NAME" -n lidar_tab
if [[ -n "$SENSOR_PRE_CMD" ]]; then
    tmux send-keys -t "$SESSION_NAME:lidar_tab" "$SENSOR_PRE_CMD" C-m
fi
tmux send-keys -t "$SESSION_NAME:lidar_tab" "unset ASAN_OPTIONS" C-m
tmux send-keys -t "$SESSION_NAME:lidar_tab" "$LIVOX_CMD" C-m

# 附加到 tmux 会话
tmux attach-session -t "$SESSION_NAME"
