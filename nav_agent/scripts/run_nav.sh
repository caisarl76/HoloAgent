#!/usr/bin/env bash
set -euo pipefail

# run inside docker
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/nav_agent_env.sh"
load_nav_agent_env_file "${NAV_AGENT_ENV_FILE:-}"
SESSION_NAME="${NAV_TMUX_SESSION:-robot_nav_ros2}"
NAV_SETUP="${NAV_SETUP:-/agentic_robot/G1_Nav_Bringup/install/setup.bash}"
FASTLIVO_SETUP="${FASTLIVO_SETUP:-/workspace/fastlivo_new_ws/install/setup.bash}"
FASTLIVO_RELOC_RVIZ="${FASTLIVO_RELOC_RVIZ:-True}"
NAV2_MAP="${NAV2_MAP:-/workspace/map/grid_map/grid_map.yaml}"
FASTLIVO_PRIOR_DIR="${FASTLIVO_PRIOR_DIR:-/workspace/hts_demo_maps/nianhui_map/map}"
FASTLIVO_CONFIG_PRIOR_DIR="${FASTLIVO_CONFIG_PRIOR_DIR:-/workspace/hts_demo_maps/nianhui_map/map}"
CHECK_NAV_ASSETS="${CHECK_NAV_ASSETS:-1}"
PRINT_NAV_COMMANDS="${PRINT_NAV_COMMANDS:-0}"
RMW_IMPLEMENTATION="${RMW_IMPLEMENTATION:-rmw_cyclonedds_cpp}"

fail() {
    echo "$1" >&2
    exit 1
}

trim_yaml_value() {
    local value="$1"
    value="${value%%#*}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"
    printf '%s\n' "$value"
}

check_nav_assets() {
    [[ -f "$NAV_SETUP" ]] || fail "NAV_SETUP not found inside container: $NAV_SETUP"
    [[ -f "$FASTLIVO_SETUP" ]] || fail "FASTLIVO_SETUP not found inside container: $FASTLIVO_SETUP"
    [[ -f "$NAV2_MAP" ]] || fail "NAV2_MAP yaml not found inside container: $NAV2_MAP"
    if [[ "$FASTLIVO_PRIOR_DIR" != "$FASTLIVO_CONFIG_PRIOR_DIR" ]]; then
        fail "FASTLIVO_PRIOR_DIR=$FASTLIVO_PRIOR_DIR does not match the installed FastLIVO config priorDir=$FASTLIVO_CONFIG_PRIOR_DIR. Mount the prior at FASTLIVO_CONFIG_PRIOR_DIR or patch the installed FastLIVO config."
    fi
    [[ -d "$FASTLIVO_PRIOR_DIR" ]] || fail "FASTLIVO_PRIOR_DIR not found inside container: $FASTLIVO_PRIOR_DIR"
    [[ -s "$FASTLIVO_PRIOR_DIR/keyframe_pose.txt" ]] || fail "FastLIVO prior missing or empty keyframe_pose.txt: $FASTLIVO_PRIOR_DIR"
    [[ -s "$FASTLIVO_PRIOR_DIR/cloudGlobal.pcd" ]] || fail "FastLIVO prior missing or empty cloudGlobal.pcd: $FASTLIVO_PRIOR_DIR"
    [[ -d "$FASTLIVO_PRIOR_DIR/keyframe_cloud" ]] || fail "FastLIVO prior missing keyframe_cloud directory: $FASTLIVO_PRIOR_DIR"
    if ! find "$FASTLIVO_PRIOR_DIR/keyframe_cloud" -maxdepth 1 -type f -name '*.pcd' -size +0c -print -quit 2>/dev/null | grep -q .; then
        fail "FastLIVO prior keyframe_cloud has no non-empty .pcd files: $FASTLIVO_PRIOR_DIR/keyframe_cloud"
    fi
    if ! find "$FASTLIVO_PRIOR_DIR" -mindepth 1 -maxdepth 2 -print -quit 2>/dev/null | grep -q .; then
        fail "FASTLIVO_PRIOR_DIR is empty inside container: $FASTLIVO_PRIOR_DIR"
    fi

    local map_image map_image_path
    map_image="$(awk -F: '/^[[:space:]]*image[[:space:]]*:/ {print $2; exit}' "$NAV2_MAP")"
    map_image="$(trim_yaml_value "$map_image")"
    [[ -n "$map_image" ]] || fail "NAV2_MAP yaml has no image field: $NAV2_MAP"
    if [[ "$map_image" = /* ]]; then
        map_image_path="$map_image"
    else
        map_image_path="$(cd "$(dirname "$NAV2_MAP")" && pwd)/$map_image"
    fi
    [[ -f "$map_image_path" ]] || fail "Nav2 map image referenced by NAV2_MAP not found: $map_image_path"

    command -v tmux >/dev/null 2>&1 || fail "tmux not found inside container"
}

print_nav_commands() {
    cat <<EOF
Navigation stack command preview:
  session: $SESSION_NAME
  NAV_SETUP: $NAV_SETUP
  FASTLIVO_SETUP: $FASTLIVO_SETUP
  FASTLIVO_PRIOR_DIR: $FASTLIVO_PRIOR_DIR
  FASTLIVO_CONFIG_PRIOR_DIR: $FASTLIVO_CONFIG_PRIOR_DIR
  NAV2_MAP: $NAV2_MAP
  RMW_IMPLEMENTATION: $RMW_IMPLEMENTATION

Pane 0:
  export RMW_IMPLEMENTATION="$RMW_IMPLEMENTATION"
  source "$NAV_SETUP"
  source "$FASTLIVO_SETUP"
  ros2 launch fast_livo online_reloc.launch.py use_rviz:=$FASTLIVO_RELOC_RVIZ

Pane 1:
  export RMW_IMPLEMENTATION="$RMW_IMPLEMENTATION"
  source "$NAV_SETUP"
  source "$FASTLIVO_SETUP"
  ros2 launch fast_livo online_livo.launch.py

Pane 2:
  export RMW_IMPLEMENTATION="$RMW_IMPLEMENTATION"
  source "$NAV_SETUP"
  ros2 launch g1_navigation2 navigation2.launch.py map:="$NAV2_MAP"

Pane 3:
  export RMW_IMPLEMENTATION="$RMW_IMPLEMENTATION"
  source "$NAV_SETUP"
  ros2 run pubpose pubpose
EOF
}

if [[ "$CHECK_NAV_ASSETS" == "1" ]]; then
    check_nav_assets
fi

if [[ "$PRINT_NAV_COMMANDS" == "1" ]]; then
    print_nav_commands
    exit 0
fi

# 删除旧 tmux 会话
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    tmux kill-session -t "$SESSION_NAME"
    echo "Session '$SESSION_NAME' has been deleted."
fi

# 创建 tmux 会话
tmux new-session -d -s "$SESSION_NAME" -n nav

# -------------------
# Pane 0: fast_livo online_reloc
# -------------------
tmux send-keys -t "$SESSION_NAME:0" "export RMW_IMPLEMENTATION=\"$RMW_IMPLEMENTATION\"" C-m
tmux send-keys -t "$SESSION_NAME:0" "source \"$NAV_SETUP\"" C-m
tmux send-keys -t "$SESSION_NAME:0" "source \"$FASTLIVO_SETUP\"" C-m
tmux send-keys -t "$SESSION_NAME:0" "ros2 launch fast_livo online_reloc.launch.py use_rviz:=$FASTLIVO_RELOC_RVIZ" C-m

# -------------------
# Pane 1: fast_livo online_livo
# -------------------
tmux split-window -h -t "$SESSION_NAME:0"
tmux send-keys -t "$SESSION_NAME:0.1" "export RMW_IMPLEMENTATION=\"$RMW_IMPLEMENTATION\"" C-m
tmux send-keys -t "$SESSION_NAME:0.1" "source \"$NAV_SETUP\"" C-m
tmux send-keys -t "$SESSION_NAME:0.1" "source \"$FASTLIVO_SETUP\"" C-m
tmux send-keys -t "$SESSION_NAME:0.1" "ros2 launch fast_livo online_livo.launch.py" C-m

# -------------------
# Pane 2: g1_navigation2
# -------------------
tmux split-window -v -t "$SESSION_NAME:0"
tmux send-keys -t "$SESSION_NAME:0.2" "export RMW_IMPLEMENTATION=\"$RMW_IMPLEMENTATION\"" C-m
tmux send-keys -t "$SESSION_NAME:0.2" "source \"$NAV_SETUP\"" C-m
tmux send-keys -t "$SESSION_NAME:0.2" "ros2 launch g1_navigation2 navigation2.launch.py map:=\"$NAV2_MAP\"" C-m

# -------------------
# Pane 3: pubpose
# -------------------
tmux split-window -v -t "$SESSION_NAME:0"
tmux send-keys -t "$SESSION_NAME:0.3" "export RMW_IMPLEMENTATION=\"$RMW_IMPLEMENTATION\"" C-m
tmux send-keys -t "$SESSION_NAME:0.3" "source \"$NAV_SETUP\"" C-m
tmux send-keys -t "$SESSION_NAME:0.3" "ros2 run pubpose pubpose" C-m

# 调整布局，让四个 pane 都可见
tmux select-layout -t "$SESSION_NAME:0" tiled

# 附加到 tmux 会话
tmux attach-session -t "$SESSION_NAME"
