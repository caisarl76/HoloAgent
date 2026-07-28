#!/usr/bin/env bash

load_nav_agent_env_file() {
    local env_file="${1:-}"
    if [[ -z "$env_file" ]]; then
        return 0
    fi
    if [[ ! -f "$env_file" ]]; then
        printf 'NAV_AGENT_ENV_FILE not found: %s\n' "$env_file" >&2
        return 1
    fi
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
}

configure_fsrvln_pythonpath() {
    local memory_path="$1"
    local root_path="${FSRVLN_ROOT_PATH:-}"
    if [[ -z "$root_path" ]]; then
        if [[ -d "$memory_path/.." ]]; then
            root_path="$(cd -- "$memory_path/.." && pwd)"
        else
            root_path="$(dirname -- "$memory_path")"
        fi
    fi
    FSRVLN_MEMORY_PATH="$memory_path"
    FSRVLN_ROOT_PATH="$root_path"
    FSRVLN_PYTHONPATH="${FSRVLN_MEMORY_PATH}:${FSRVLN_ROOT_PATH}"
    export FSRVLN_MEMORY_PATH FSRVLN_ROOT_PATH FSRVLN_PYTHONPATH
}
