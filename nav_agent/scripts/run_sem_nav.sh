#!/usr/bin/env bash
set -euo pipefail

SESSION_NAME="${SEM_NAV_TMUX_SESSION:-robot_nav}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAV_AGENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/nav_agent_env.sh"
load_nav_agent_env_file "${NAV_AGENT_ENV_FILE:-}"
SEM_NAV_SETUP="${SEM_NAV_SETUP:-$NAV_AGENT_DIR/sem_nav_ctr/install/setup.bash}"
SEM_NAV_PRE_CMD="${SEM_NAV_PRE_CMD:-}"
START_CHAT_LOC="${START_CHAT_LOC:-1}"
START_G1_PUBVEL="${START_G1_PUBVEL:-0}"
ALLOW_G1_MOTION="${ALLOW_G1_MOTION:-0}"
PRINT_SEM_NAV_COMMANDS="${PRINT_SEM_NAV_COMMANDS:-0}"
ATTACH_TMUX="${ATTACH_TMUX:-1}"
UNITREE_NET_IFACE="${UNITREE_NET_IFACE:-eth0}"
G1_DRY_RUN="${G1_DRY_RUN:-1}"
G1_MAX_LINEAR_X="${G1_MAX_LINEAR_X:-0.22}"
G1_MAX_LINEAR_Y="${G1_MAX_LINEAR_Y:-0.0}"
G1_MAX_YAW_RATE="${G1_MAX_YAW_RATE:-0.30}"
G1_MIN_ROTATING_YAW_RATE="${G1_MIN_ROTATING_YAW_RATE:-0.30}"
G1_MIN_MOVING_YAW_RATE="${G1_MIN_MOVING_YAW_RATE:-0.10}"
RMW_IMPLEMENTATION="${RMW_IMPLEMENTATION:-rmw_cyclonedds_cpp}"
NAV_AGENT_DATASET_PATH="${NAV_AGENT_DATASET_PATH:-}"
NAV_AGENT_GRAPH_PATH="${NAV_AGENT_GRAPH_PATH:-${HMSG_GRAPH_PATH:-}}"
NAV_AGENT_SAVE_PATH="${NAV_AGENT_SAVE_PATH:-}"
NAV_AGENT_CLIP_CHECKPOINT="${NAV_AGENT_CLIP_CHECKPOINT:-}"
FSRVLN_MEMORY_PATH="${FSRVLN_MEMORY_PATH:-$NAV_AGENT_DIR/../fsr_vln/memory}"
configure_fsrvln_pythonpath "$FSRVLN_MEMORY_PATH"
MPLCONFIGDIR="${MPLCONFIGDIR:-/tmp/matplotlib-cache}"
REQUIRE_G1_READINESS_CHECK="${REQUIRE_G1_READINESS_CHECK:-1}"
ALLOW_SKIP_G1_READINESS_CHECK="${ALLOW_SKIP_G1_READINESS_CHECK:-0}"
G1_READINESS_CHECK_SCRIPT="${G1_READINESS_CHECK_SCRIPT:-$SCRIPT_DIR/check_g1_deploy_readiness.sh}"

is_real_g1_motion() {
    [[ "$START_G1_PUBVEL" == "1" && "$G1_DRY_RUN" == "0" ]]
}

print_optional_export() {
    local name="$1"
    local value="$2"
    if [[ -n "$value" ]]; then
        printf '  export %s=%q\n' "$name" "$value"
    fi
}

print_common_commands() {
    if [[ -n "$SEM_NAV_PRE_CMD" ]]; then
        printf '  %s\n' "$SEM_NAV_PRE_CMD"
    fi
    print_optional_export "UNITREE_NET_IFACE" "$UNITREE_NET_IFACE"
    print_optional_export "G1_DRY_RUN" "$G1_DRY_RUN"
    print_optional_export "G1_MAX_LINEAR_X" "$G1_MAX_LINEAR_X"
    print_optional_export "G1_MAX_LINEAR_Y" "$G1_MAX_LINEAR_Y"
    print_optional_export "G1_MAX_YAW_RATE" "$G1_MAX_YAW_RATE"
    print_optional_export "G1_MIN_ROTATING_YAW_RATE" "$G1_MIN_ROTATING_YAW_RATE"
    print_optional_export "G1_MIN_MOVING_YAW_RATE" "$G1_MIN_MOVING_YAW_RATE"
    print_optional_export "RMW_IMPLEMENTATION" "$RMW_IMPLEMENTATION"
    print_optional_export "NAV_AGENT_DATASET_PATH" "$NAV_AGENT_DATASET_PATH"
    print_optional_export "NAV_AGENT_GRAPH_PATH" "$NAV_AGENT_GRAPH_PATH"
    print_optional_export "NAV_AGENT_SAVE_PATH" "$NAV_AGENT_SAVE_PATH"
    print_optional_export "NAV_AGENT_CLIP_CHECKPOINT" "$NAV_AGENT_CLIP_CHECKPOINT"
    print_optional_export "NAV_AGENT_SCENE" "${NAV_AGENT_SCENE:-}"
    print_optional_export "NAV_AGENT_ROOM_NAME_METHOD" "${NAV_AGENT_ROOM_NAME_METHOD:-}"
    print_optional_export "NAV_AGENT_ROOM_TYPES" "${NAV_AGENT_ROOM_TYPES:-}"
    print_optional_export "NAV_AGENT_QUERY_METHOD" "${NAV_AGENT_QUERY_METHOD:-}"
    print_optional_export "NAV_AGENT_USE_GPT" "${NAV_AGENT_USE_GPT:-}"
    print_optional_export "FSRVLN_MEMORY_PATH" "$FSRVLN_MEMORY_PATH"
    print_optional_export "FSRVLN_ROOT_PATH" "$FSRVLN_ROOT_PATH"
    print_optional_export "MPLCONFIGDIR" "$MPLCONFIGDIR"
    if [[ -n "$FSRVLN_PYTHONPATH" ]]; then
        printf '  export PYTHONPATH=%q:"${PYTHONPATH:-}"\n' "$FSRVLN_PYTHONPATH"
    fi
    printf '  source %q\n' "$SEM_NAV_SETUP"
    printf '  unset ASAN_OPTIONS\n'
}

print_sem_nav_commands() {
    cat <<EOF
Semantic navigation stack command preview:
  session: $SESSION_NAME
  SEM_NAV_SETUP: $SEM_NAV_SETUP
  START_CHAT_LOC: $START_CHAT_LOC
  START_G1_PUBVEL: $START_G1_PUBVEL
  G1_DRY_RUN: $G1_DRY_RUN
  ALLOW_G1_MOTION: $ALLOW_G1_MOTION
  REQUIRE_G1_READINESS_CHECK: $REQUIRE_G1_READINESS_CHECK
  RMW_IMPLEMENTATION: $RMW_IMPLEMENTATION
  UNITREE_NET_IFACE: $UNITREE_NET_IFACE
  velocity limits: x=$G1_MAX_LINEAR_X y=$G1_MAX_LINEAR_Y yaw=$G1_MAX_YAW_RATE

EOF

    if is_real_g1_motion; then
        if [[ "$REQUIRE_G1_READINESS_CHECK" == "1" ]]; then
            cat <<EOF
Before creating tmux panes, run_sem_nav.sh will run:
  CHECK_MODE=robot \\
  SEM_NAV_SETUP="$SEM_NAV_SETUP" \\
  START_G1_PUBVEL="$START_G1_PUBVEL" \\
  G1_DRY_RUN="$G1_DRY_RUN" \\
  ALLOW_G1_MOTION="$ALLOW_G1_MOTION" \\
  UNITREE_NET_IFACE="$UNITREE_NET_IFACE" \\
  bash "$G1_READINESS_CHECK_SCRIPT"

EOF
        else
            cat <<'EOF'
WARNING: strict G1 readiness check is disabled for this real-motion command.

EOF
        fi
    fi

    cat <<'EOF'
Pane 0: chat_loc_python
EOF
    print_common_commands
    if [[ "$START_CHAT_LOC" == "1" ]]; then
        printf '  ros2 run chat_loc_python topic_chat_loc_pub\n'
    else
        printf '  echo %q\n' "chat_loc_python disabled; publish text to /chat_loc_pub manually."
    fi

    cat <<'EOF'

Pane 1: semantic goal publisher
EOF
    print_common_commands
    printf '  ros2 run goal_publisher goal_pose_publisher\n'

    cat <<'EOF'

Pane 2: Nav2 /cmd_vel FIFO writer
  [ -p /tmp/vel_fifo ] && rm /tmp/vel_fifo; mkfifo /tmp/vel_fifo
EOF
    print_common_commands
    printf '  ros2 run g1_move g1_getvel_node\n'

    cat <<'EOF'

Pane 3: Unitree velocity publisher
EOF
    print_common_commands
    if [[ "$START_G1_PUBVEL" == "1" ]]; then
        printf '  ros2 run g1_move g1_pubvel_node\n'
    else
        printf '  echo %q\n' "g1_pubvel_node disabled. Set START_G1_PUBVEL=1 only after dry-run checks pass."
    fi
}

if is_real_g1_motion && [[ "$ALLOW_G1_MOTION" != "1" ]]; then
    cat >&2 <<'EOF'
Refusing to start real Unitree G1 motion.

This command would start g1_pubvel_node with G1_DRY_RUN=0, which allows
LocoClient.Move() calls. Re-run only after dry-run validation, with an
operator ready at the emergency stop, and add:

  ALLOW_G1_MOTION=1
EOF
    exit 2
fi

if [[ "$PRINT_SEM_NAV_COMMANDS" == "1" ]]; then
    if is_real_g1_motion && [[ "$REQUIRE_G1_READINESS_CHECK" != "1" && "$ALLOW_SKIP_G1_READINESS_CHECK" != "1" ]]; then
        cat >&2 <<'EOF'
Refusing to preview a real-motion command that would skip strict readiness.

Set REQUIRE_G1_READINESS_CHECK=1, or for controlled debugging only set both:

  REQUIRE_G1_READINESS_CHECK=0
  ALLOW_SKIP_G1_READINESS_CHECK=1
EOF
        exit 2
    fi
    print_sem_nav_commands
    exit 0
fi

if is_real_g1_motion; then
    if [[ "$REQUIRE_G1_READINESS_CHECK" == "1" ]]; then
        if [[ ! -f "$G1_READINESS_CHECK_SCRIPT" ]]; then
            echo "G1 readiness check script not found: $G1_READINESS_CHECK_SCRIPT" >&2
            exit 1
        fi
        echo "Running strict G1 readiness check before real motion..."
        CHECK_MODE=robot \
        SEM_NAV_SETUP="$SEM_NAV_SETUP" \
        START_G1_PUBVEL="$START_G1_PUBVEL" \
        G1_DRY_RUN="$G1_DRY_RUN" \
        ALLOW_G1_MOTION="$ALLOW_G1_MOTION" \
        UNITREE_NET_IFACE="$UNITREE_NET_IFACE" \
        G1_MAX_LINEAR_X="$G1_MAX_LINEAR_X" \
        G1_MAX_LINEAR_Y="$G1_MAX_LINEAR_Y" \
        G1_MAX_YAW_RATE="$G1_MAX_YAW_RATE" \
        NAV_AGENT_GRAPH_PATH="$NAV_AGENT_GRAPH_PATH" \
        NAV_AGENT_DATASET_PATH="$NAV_AGENT_DATASET_PATH" \
        NAV_AGENT_CLIP_CHECKPOINT="$NAV_AGENT_CLIP_CHECKPOINT" \
        FSRVLN_MEMORY_PATH="$FSRVLN_MEMORY_PATH" \
        FSRVLN_ROOT_PATH="$FSRVLN_ROOT_PATH" \
        MPLCONFIGDIR="$MPLCONFIGDIR" \
        bash "$G1_READINESS_CHECK_SCRIPT"
    elif [[ "$ALLOW_SKIP_G1_READINESS_CHECK" != "1" ]]; then
        cat >&2 <<'EOF'
Refusing to skip the strict G1 readiness check.

Real Unitree motion normally requires CHECK_MODE=robot readiness to pass before
run_sem_nav.sh starts g1_pubvel_node. For controlled debugging only, set both:

  REQUIRE_G1_READINESS_CHECK=0
  ALLOW_SKIP_G1_READINESS_CHECK=1
EOF
        exit 2
    else
        echo "WARNING: skipping strict G1 readiness check for real motion." >&2
    fi
fi

if [[ ! -f "$SEM_NAV_SETUP" ]]; then
    echo "SEM_NAV_SETUP not found: $SEM_NAV_SETUP" >&2
    exit 1
fi

if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux not found; install tmux before running semantic navigation." >&2
    exit 1
fi

send_optional_export() {
    local target="$1"
    local name="$2"
    local value="$3"
    if [[ -n "$value" ]]; then
        tmux send-keys -t "$target" "export $name=\"$value\"" C-m
    fi
}

send_common() {
    local target="$1"
    if [[ -n "$SEM_NAV_PRE_CMD" ]]; then
        tmux send-keys -t "$target" "$SEM_NAV_PRE_CMD" C-m
    fi
    tmux send-keys -t "$target" "export UNITREE_NET_IFACE=\"$UNITREE_NET_IFACE\"" C-m
    tmux send-keys -t "$target" "export G1_DRY_RUN=\"$G1_DRY_RUN\"" C-m
    tmux send-keys -t "$target" "export G1_MAX_LINEAR_X=\"$G1_MAX_LINEAR_X\"" C-m
    tmux send-keys -t "$target" "export G1_MAX_LINEAR_Y=\"$G1_MAX_LINEAR_Y\"" C-m
    tmux send-keys -t "$target" "export G1_MAX_YAW_RATE=\"$G1_MAX_YAW_RATE\"" C-m
    tmux send-keys -t "$target" "export G1_MIN_ROTATING_YAW_RATE=\"$G1_MIN_ROTATING_YAW_RATE\"" C-m
    tmux send-keys -t "$target" "export G1_MIN_MOVING_YAW_RATE=\"$G1_MIN_MOVING_YAW_RATE\"" C-m
    tmux send-keys -t "$target" "export RMW_IMPLEMENTATION=\"$RMW_IMPLEMENTATION\"" C-m
    send_optional_export "$target" "NAV_AGENT_DATASET_PATH" "$NAV_AGENT_DATASET_PATH"
    send_optional_export "$target" "NAV_AGENT_GRAPH_PATH" "$NAV_AGENT_GRAPH_PATH"
    send_optional_export "$target" "NAV_AGENT_SAVE_PATH" "$NAV_AGENT_SAVE_PATH"
    send_optional_export "$target" "NAV_AGENT_CLIP_CHECKPOINT" "$NAV_AGENT_CLIP_CHECKPOINT"
    send_optional_export "$target" "NAV_AGENT_SCENE" "${NAV_AGENT_SCENE:-}"
    send_optional_export "$target" "NAV_AGENT_ROOM_NAME_METHOD" "${NAV_AGENT_ROOM_NAME_METHOD:-}"
    send_optional_export "$target" "NAV_AGENT_ROOM_TYPES" "${NAV_AGENT_ROOM_TYPES:-}"
    send_optional_export "$target" "NAV_AGENT_QUERY_METHOD" "${NAV_AGENT_QUERY_METHOD:-}"
    send_optional_export "$target" "NAV_AGENT_USE_GPT" "${NAV_AGENT_USE_GPT:-}"
    send_optional_export "$target" "FSRVLN_MEMORY_PATH" "$FSRVLN_MEMORY_PATH"
    send_optional_export "$target" "FSRVLN_ROOT_PATH" "$FSRVLN_ROOT_PATH"
    tmux send-keys -t "$target" "export MPLCONFIGDIR=\"$MPLCONFIGDIR\"" C-m
    if [[ -d "$FSRVLN_MEMORY_PATH" && -d "$FSRVLN_ROOT_PATH" ]]; then
        tmux send-keys -t "$target" "export PYTHONPATH=\"$FSRVLN_PYTHONPATH:\${PYTHONPATH:-}\"" C-m
    else
        tmux send-keys -t "$target" "echo 'WARNING: FSR-VLN Python paths not found: $FSRVLN_PYTHONPATH'" C-m
    fi
    tmux send-keys -t "$target" "source \"$SEM_NAV_SETUP\"" C-m
    tmux send-keys -t "$target" "unset ASAN_OPTIONS" C-m
}

# run on hostmachine
# 删除旧 tmux 会话
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    tmux kill-session -t "$SESSION_NAME"
    echo "Session '$SESSION_NAME' has been deleted."
fi

# 创建新的 tmux 会话
tmux new-session -d -s "$SESSION_NAME" -n nav

# -------------------
# Pane 0: 语音交互
# -------------------
send_common "$SESSION_NAME:0"
if [[ "$START_CHAT_LOC" == "1" ]]; then
    tmux send-keys -t "$SESSION_NAME:0" "ros2 run chat_loc_python topic_chat_loc_pub" C-m
else
    tmux send-keys -t "$SESSION_NAME:0" "echo 'chat_loc_python disabled; publish text to /chat_loc_pub manually.'" C-m
fi

# -------------------
# Pane 1: 语义定位
# -------------------
tmux split-window -h -t "$SESSION_NAME:0"
send_common "$SESSION_NAME:0.1"
tmux send-keys -t "$SESSION_NAME:0.1" "ros2 run goal_publisher goal_pose_publisher" C-m

# -------------------
# Pane 2: 管道写入 (g1_getvel_node)，读取Navigation发布速度写入管道
# -------------------
tmux split-window -v -t "$SESSION_NAME:0"
tmux send-keys -t "$SESSION_NAME:0.2" "[ -p /tmp/vel_fifo ] && rm /tmp/vel_fifo; mkfifo /tmp/vel_fifo" C-m
send_common "$SESSION_NAME:0.2"
tmux send-keys -t "$SESSION_NAME:0.2" "ros2 run g1_move g1_getvel_node" C-m

# -------------------
# Pane 3: 管道读取 (g1_pubvel_node) 控制运动
# -------------------
tmux split-window -v -t "$SESSION_NAME:0"
send_common "$SESSION_NAME:0.3"
if [[ "$START_G1_PUBVEL" == "1" ]]; then
    tmux send-keys -t "$SESSION_NAME:0.3" "ros2 run g1_move g1_pubvel_node" C-m
else
    tmux send-keys -t "$SESSION_NAME:0.3" "echo 'g1_pubvel_node disabled. Set START_G1_PUBVEL=1 only after dry-run checks pass.'" C-m
fi

# 调整布局，让四个 pane 都可见
tmux select-layout -t "$SESSION_NAME:0" tiled

if [[ "$ATTACH_TMUX" == "1" ]]; then
    # 附加到 tmux 会话
    tmux attach-session -t "$SESSION_NAME"
else
    echo "Semantic navigation tmux session started: $SESSION_NAME"
    echo "Attach with: tmux attach-session -t $SESSION_NAME"
fi
