#!/bin/bash
set -euo pipefail
PATH='/usr/bin:/bin'
export PATH

SOURCE_URL="https://strace.io/files/6.6/strace-6.6.tar.xz"
SOURCE_SIZE="2420364"
SOURCE_SHA256="421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
TOP_DIRECTORY="strace-6.6"
SCRIPT_DIR="$(CDPATH= cd -- "$(/usr/bin/dirname -- "$0")" && pwd -P)"
POLICY_PATH="$SCRIPT_DIR/policies/holoagent0-trace-tool-v1.json"
USAGE="usage: $0 [--archive ARCHIVE] (--output-dir OUTPUT_DIR | --candidate-evidence FILE)"

archive=""
output_dir=""
candidate_evidence=""
while (($#)); do
    case "$1" in
        --archive|--output-dir|--candidate-evidence)
            (($# >= 2)) || { printf '%s\n' "$USAGE" >&2; exit 2; }
            case "$1" in
                --archive) archive="$2" ;;
                --output-dir) output_dir="$2" ;;
                --candidate-evidence) candidate_evidence="$2" ;;
            esac
            shift 2
            ;;
        *) printf '%s\n' "$USAGE" >&2; exit 2 ;;
    esac
done
if [[ ( -z "$output_dir" && -z "$candidate_evidence" ) || \
      ( -n "$output_dir" && -n "$candidate_evidence" ) ]]; then
    printf '%s\n' "$USAGE" >&2
    exit 2
fi

validate_destination() {
    /usr/bin/python3.10 - "$1" <<'PY'
from pathlib import Path
import sys

raw = sys.argv[1]
path = Path(raw)
if not path.is_absolute() or ".." in path.parts:
    raise SystemExit("destination must be an absolute canonical path without '..'")
resolved = path.resolve(strict=False)
if str(resolved) != raw or resolved == Path("/"):
    raise SystemExit("destination must be an absolute canonical path")
if resolved.exists() or resolved.is_symlink():
    raise SystemExit("destination already exists")
for original_parent, resolved_parent in zip(path.parents, resolved.parents):
    if original_parent.exists() and original_parent.resolve() != resolved_parent:
        raise SystemExit("destination must not traverse a symlink")
PY
}

destination="${output_dir:-$candidate_evidence}"
validate_destination "$destination"

readarray -t pins < <(/usr/bin/python3.10 - "$POLICY_PATH" <<'PY'
import json
from pathlib import Path
import sys

def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate policy key: {key}")
        result[key] = value
    return result

policy = json.loads(
    Path(sys.argv[1]).read_text(encoding="utf-8"),
    object_pairs_hook=closed_object,
    parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
)
row = policy["rows"][0]
print(row["build"]["review_state"])
print(row["build"]["recipe_sha256"] or "")
print(row["build"]["container_image_digest"] or "")
print(row["runtime"]["review_state"])
print(row["runtime"]["elf_size"] or "")
print(row["runtime"]["elf_sha256"] or "")
print(row["runtime"]["version_output_sha256"] or "")
PY
)

validate_build_pins() {
    if [[ "${pins[0]}" != "REVIEWED" || -z "${pins[1]}" || \
          ! "${pins[2]}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        printf 'error: PENDING_REPRODUCIBLE_BUILD: reviewed recipe and container pins are required\n' >&2
        return 3
    fi
    local measured_recipe
    measured_recipe="$(/usr/bin/sha256sum -- "$0" | /usr/bin/cut -d ' ' -f 1)"
    if [[ "$measured_recipe" != "${pins[1]}" ]]; then
        printf 'error: reviewed build recipe sha256 mismatch\n' >&2
        return 3
    fi
}

validate_runtime_pins() {
    if [[ "${pins[3]}" != "REVIEWED" || -z "${pins[4]}" || \
          -z "${pins[5]}" || -z "${pins[6]}" ]]; then
        printf 'error: runtime pins are required for reviewed install\n' >&2
        return 3
    fi
}

# A download is never attempted until the immutable build environment is reviewed.
if [[ -z "$archive" ]]; then
    validate_build_pins
fi

# BEGIN_OWNED_PROCESS_HELPERS
temp_dir="${temp_dir:-}"
install_staging_dir="${install_staging_dir:-}"
owned_candidate_staging_path="${owned_candidate_staging_path:-}"
owned_candidate_destination="${owned_candidate_destination:-}"
owned_candidate_device="${owned_candidate_device:-}"
owned_candidate_inode="${owned_candidate_inode:-}"
owned_install_destination="${owned_install_destination:-}"
owned_install_quarantine="${owned_install_quarantine:-}"
owned_install_device="${owned_install_device:-}"
owned_install_inode="${owned_install_inode:-}"
active_child_pid=""
active_child_pgid=""
active_child_starttime=""
active_docker_bin=""
active_container_name=""
active_container_nonce=""
container_launch_attempted=0
launching_child=0
first_signal_status=0
docker_cleanup_timeout=3
stopped_child_status=0

publication_helper_source="$(/bin/cat <<'PY'
# BEGIN_PUBLICATION_HELPER
from __future__ import annotations

import ctypes
import errno
import json
import os
from pathlib import Path
import stat
import sys


RENAME_NOREPLACE = 1
APPROVAL_MARKER = ".holoagent0-install-approved.json"
INSTALL_PRECOMMIT = "PRECOMMIT"
INSTALL_RENAMED_UNAPPROVED = "RENAMED_UNAPPROVED"
INSTALL_APPROVED = "APPROVED"
INSTALL_ROLLED_BACK = "ROLLED_BACK"
INSTALL_AMBIGUOUS = "AMBIGUOUS"


class PublicationError(RuntimeError):
    pass


def _paths(path_a: Path, path_b: Path, path_c: Path | None = None):
    paths = tuple(Path(path) for path in (path_a, path_b) if path is not None)
    if path_c is not None:
        paths += (Path(path_c),)
    if any(not path.is_absolute() or ".." in path.parts for path in paths):
        raise PublicationError("publication paths must be canonical and absolute")
    if any(path.parent != paths[0].parent for path in paths[1:]):
        raise PublicationError("publication paths must use the same parent")
    parent = paths[0].parent
    if parent.resolve(strict=True) != Path(os.path.abspath(parent)):
        raise PublicationError("publication parent must not traverse a symlink")
    return paths, parent


def _rename_no_replace(directory_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise PublicationError("renameat2 is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    if renameat2(
        directory_fd,
        os.fsencode(source),
        directory_fd,
        os.fsencode(destination),
        RENAME_NOREPLACE,
    ) == 0:
        return
    number = ctypes.get_errno()
    if number == errno.EEXIST:
        raise FileExistsError(number, os.strerror(number), destination)
    raise OSError(number, os.strerror(number), destination)


def _parent_fd(parent: Path) -> int:
    return os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))


def _same_identity(file_stat: os.stat_result, device: int, inode: int) -> bool:
    return (file_stat.st_dev, file_stat.st_ino) == (device, inode)


def publish_candidate_evidence(
    destination: Path,
    staging: Path,
    evidence: dict,
    expected_device: int | None = None,
    expected_inode: int | None = None,
) -> None:
    (destination, staging), parent = _paths(Path(destination), Path(staging))
    directory_fd = _parent_fd(parent)
    staging_fd = -1
    staging_identity = None
    published_identity = None
    linked = False
    payload = (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode()
    try:
        flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        if expected_device is None or expected_inode is None:
            flags |= os.O_CREAT | os.O_EXCL
        staging_fd = os.open(staging.name, flags, 0o600, dir_fd=directory_fd)
        os.fchmod(staging_fd, 0o600)
        staging_identity = os.fstat(staging_fd)
        if expected_device is not None and not _same_identity(
            staging_identity, expected_device, expected_inode
        ):
            raise PublicationError("candidate staging identity changed")
        os.ftruncate(staging_fd, 0)
        view = memoryview(payload)
        while view:
            written = os.write(staging_fd, view)
            if written <= 0:
                raise OSError("short candidate write")
            view = view[written:]
        os.fsync(staging_fd)
        os.link(
            staging.name,
            destination.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        linked = True
        published_identity = staging_identity
        os.unlink(staging.name, dir_fd=directory_fd)
        staging_identity = None
        os.fsync(directory_fd)
        linked = False
    except Exception as error:
        if linked:
            try:
                current = os.stat(
                    destination.name, dir_fd=directory_fd, follow_symlinks=False
                )
                if published_identity is None or not _same_identity(
                    current, published_identity.st_dev, published_identity.st_ino
                ):
                    raise PublicationError("AMBIGUOUS_CANDIDATE_IDENTITY")
                os.unlink(destination.name, dir_fd=directory_fd)
                os.fsync(directory_fd)
            except Exception as rollback_error:
                raise PublicationError("AMBIGUOUS_CANDIDATE_COMMIT") from rollback_error
            raise PublicationError("ROLLED_BACK_CANDIDATE_COMMIT") from error
        raise
    finally:
        if staging_fd >= 0:
            try:
                os.close(staging_fd)
            except OSError:
                pass
        if staging_identity is not None:
            try:
                current = os.stat(staging.name, dir_fd=directory_fd, follow_symlinks=False)
                if _same_identity(current, staging_identity.st_dev, staging_identity.st_ino):
                    os.unlink(staging.name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        try:
            os.close(directory_fd)
        except OSError:
            pass


def _fsync_install_parent(directory_fd: int) -> None:
    os.fsync(directory_fd)


def _validate_published_install(
    directory_fd: int, destination_name: str, retained_stat: os.stat_result
) -> int:
    installed_fd = os.open(
        destination_name,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    installed_stat = os.fstat(installed_fd)
    if not _same_identity(installed_stat, retained_stat.st_dev, retained_stat.st_ino):
        os.close(installed_fd)
        raise PublicationError("published install identity changed")
    return installed_fd


def _approval(installed_fd: int, retained_stat: os.stat_result) -> None:
    payload = (
        json.dumps(
            {
                "schema_version": "holoagent0.strace-install-approval.v1",
                "state": INSTALL_APPROVED,
                "install_device": retained_stat.st_dev,
                "install_inode": retained_stat.st_ino,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    marker_fd = os.open(
        APPROVAL_MARKER,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=installed_fd,
    )
    try:
        os.fchmod(marker_fd, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(marker_fd, view)
            if written <= 0:
                raise OSError("short approval-marker write")
            view = view[written:]
        os.fsync(marker_fd)
    finally:
        os.close(marker_fd)
    os.fsync(installed_fd)


def _rollback(
    directory_fd: int,
    destination_name: str,
    quarantine_name: str,
    device: int,
    inode: int,
) -> None:
    current = os.stat(destination_name, dir_fd=directory_fd, follow_symlinks=False)
    if not _same_identity(current, device, inode):
        raise PublicationError("AMBIGUOUS_INSTALL_IDENTITY")
    _rename_no_replace(directory_fd, destination_name, quarantine_name)
    os.fsync(directory_fd)


def publish_install_directory(staged: Path, destination: Path, quarantine: Path) -> None:
    (staged, destination, quarantine), parent = _paths(
        Path(staged), Path(destination), Path(quarantine)
    )
    directory_fd = _parent_fd(parent)
    retained_fd = -1
    installed_fd = -1
    committed = False
    retained_stat = None
    try:
        retained_fd = os.open(
            staged.name,
            os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        retained_stat = os.fstat(retained_fd)
        _rename_no_replace(directory_fd, staged.name, destination.name)
        committed = True
        _fsync_install_parent(directory_fd)
        installed_fd = _validate_published_install(
            directory_fd, destination.name, retained_stat
        )
        _approval(installed_fd, retained_stat)
    except Exception as error:
        if committed and retained_stat is not None:
            try:
                _rollback(
                    directory_fd,
                    destination.name,
                    quarantine.name,
                    retained_stat.st_dev,
                    retained_stat.st_ino,
                )
            except Exception as rollback_error:
                raise PublicationError("AMBIGUOUS_INSTALL_COMMIT") from rollback_error
            raise PublicationError("ROLLED_BACK_INSTALL_COMMIT") from error
        raise
    finally:
        if installed_fd >= 0:
            try:
                os.close(installed_fd)
            except OSError:
                pass
        if retained_fd >= 0:
            try:
                os.close(retained_fd)
            except OSError:
                pass
        try:
            os.close(directory_fd)
        except OSError:
            pass


def rollback_install_path(
    destination: Path, quarantine: Path, device: int, inode: int
) -> None:
    (destination, quarantine), parent = _paths(Path(destination), Path(quarantine))
    directory_fd = _parent_fd(parent)
    try:
        _rollback(directory_fd, destination.name, quarantine.name, device, inode)
    finally:
        os.close(directory_fd)


def verify_approved_install(destination: Path) -> None:
    destination = Path(destination)
    if not destination.is_absolute() or ".." in destination.parts:
        raise PublicationError("install path must be canonical and absolute")
    installed_fd = os.open(
        destination,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    marker_fd = -1
    try:
        installed_stat = os.fstat(installed_fd)
        marker_fd = os.open(
            APPROVAL_MARKER,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=installed_fd,
        )
        marker_stat = os.fstat(marker_fd)
        if not stat.S_ISREG(marker_stat.st_mode) or marker_stat.st_mode & 0o777 != 0o600:
            raise PublicationError("invalid install approval marker")
        payload = os.read(marker_fd, 4097)
        if len(payload) > 4096:
            raise PublicationError("install approval marker is oversized")
        def closed_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise PublicationError("duplicate install approval key")
                value[key] = item
            return value

        value = json.loads(
            payload,
            object_pairs_hook=closed_object,
            parse_constant=lambda token: (_ for _ in ()).throw(PublicationError(token)),
        )
        expected = {
            "schema_version": "holoagent0.strace-install-approval.v1",
            "state": INSTALL_APPROVED,
            "install_device": installed_stat.st_dev,
            "install_inode": installed_stat.st_ino,
        }
        if value != expected:
            raise PublicationError("install approval marker does not bind identity")
    finally:
        if marker_fd >= 0:
            os.close(marker_fd)
        os.close(installed_fd)


def main(argv: list[str]) -> int:
    command = argv[1]
    if command == "candidate":
        evidence = {
            "schema_version": "holoagent0.strace-candidate-evidence.v1",
            "measurement_kind": "CANDIDATE_MEASUREMENT",
            "recipe_sha256": argv[4],
            "container_image_digest": argv[5],
            "elf_size": int(argv[6]),
            "elf_sha256": argv[7],
            "version_output_sha256": argv[8],
        }
        publish_candidate_evidence(
            Path(argv[2]), Path(argv[3]), evidence, int(argv[9]), int(argv[10])
        )
    elif command == "install":
        publish_install_directory(Path(argv[2]), Path(argv[3]), Path(argv[4]))
    elif command == "rollback":
        rollback_install_path(Path(argv[2]), Path(argv[3]), int(argv[4]), int(argv[5]))
    elif command == "verify":
        verify_approved_install(Path(argv[2]))
    else:
        raise PublicationError("unknown publication command")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
# END_PUBLICATION_HELPER
PY
)"

cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    stop_owned_child
    local cleanup_failed=0
    remove_owned_container || cleanup_failed=1
    cleanup_owned_publications || cleanup_failed=1
    [[ -z "${install_staging_dir:-}" ]] || /usr/bin/rm -rf -- "$install_staging_dir" || cleanup_failed=1
    [[ -z "${temp_dir:-}" ]] || /usr/bin/rm -rf -- "$temp_dir" || cleanup_failed=1
    ((cleanup_failed == 0)) || status=3
    exit "$status"
}
terminate() {
    local status="$1"
    trap - EXIT HUP INT TERM
    stop_owned_child
    local cleanup_failed=0
    remove_owned_container || cleanup_failed=1
    cleanup_owned_publications || cleanup_failed=1
    [[ -z "${install_staging_dir:-}" ]] || /usr/bin/rm -rf -- "$install_staging_dir" || cleanup_failed=1
    [[ -z "${temp_dir:-}" ]] || /usr/bin/rm -rf -- "$temp_dir" || cleanup_failed=1
    ((cleanup_failed == 0)) || status=3
    exit "$status"
}

process_identity() {
    /usr/bin/python3.10 - "$1" <<'PY'
from pathlib import Path
import sys

text = Path(f"/proc/{int(sys.argv[1])}/stat").read_text(encoding="ascii")
closing = text.rfind(")")
if closing < 0:
    raise SystemExit(1)
fields = text[closing + 2 :].split()
if len(fields) < 20:
    raise SystemExit(1)
print(fields[2], fields[19])
PY
}

owned_child_matches() {
    [[ -n "${active_child_pid:-}" && -n "${active_child_pgid:-}" && \
       -n "${active_child_starttime:-}" ]] || return 1
    local identity current_pgid current_starttime
    identity="$(process_identity "$active_child_pid" 2>/dev/null)" || return 1
    read -r current_pgid current_starttime <<<"$identity"
    [[ "$current_pgid" == "$active_child_pgid" && \
       "$current_starttime" == "$active_child_starttime" ]]
}

clear_owned_child() {
    active_child_pid=""
    active_child_pgid=""
    active_child_starttime=""
}

stop_owned_child() {
    local count
    stopped_child_status=0
    if owned_child_matches; then
        kill -TERM -- "-$active_child_pgid" 2>/dev/null || :
        for ((count = 0; count < 100; count++)); do
            owned_child_matches || break
            /usr/bin/sleep 0.01
        done
        if owned_child_matches; then
            kill -KILL -- "-$active_child_pgid" 2>/dev/null || :
        fi
    elif [[ -n "${active_child_pid:-}" ]]; then
        kill -TERM -- "$active_child_pid" 2>/dev/null || :
        for ((count = 0; count < 100; count++)); do
            kill -0 "$active_child_pid" 2>/dev/null || break
            /usr/bin/sleep 0.01
        done
        kill -KILL -- "$active_child_pid" 2>/dev/null || :
    fi
    if [[ -n "${active_child_pid:-}" ]]; then
        wait "$active_child_pid" 2>/dev/null || stopped_child_status=$?
    fi
    clear_owned_child
}

remove_owned_container() {
    [[ -n "${active_docker_bin:-}" && -n "${active_container_name:-}" ]] || return 0
    if ((container_launch_attempted == 0)); then
        active_docker_bin=""
        active_container_name=""
        active_container_nonce=""
        return 0
    fi
    local observed inventory
    observed="$(/usr/bin/timeout "$docker_cleanup_timeout" "$active_docker_bin" \
        inspect --format '{{ index .Config.Labels "holoagent0.strace.owner" }}' \
        "$active_container_name" 2>/dev/null)" || observed=""
    if [[ -n "$observed" ]]; then
        [[ "$observed" == "$active_container_nonce" ]] || return 1
        /usr/bin/timeout "$docker_cleanup_timeout" "$active_docker_bin" \
            rm --force "$active_container_name" >/dev/null 2>&1 || return 1
    fi
    inventory="$(/usr/bin/timeout "$docker_cleanup_timeout" "$active_docker_bin" \
        container ls --all --no-trunc \
        --filter "name=^/${active_container_name}$" --format '{{.Names}}|{{.Labels}}')" \
        || return 1
    [[ -z "$inventory" ]] || return 1
    active_docker_bin=""
    active_container_name=""
    active_container_nonce=""
    container_launch_attempted=0
}

cleanup_owned_publications() {
    local identity=""
    if [[ -n "${owned_install_destination:-}" && -e "$owned_install_destination" ]]; then
        /usr/bin/timeout 3 /usr/bin/python3.10 -c "$publication_helper_source" \
            rollback "$owned_install_destination" "$owned_install_quarantine" \
            "$owned_install_device" "$owned_install_inode" || return 1
    fi
    if [[ -n "${owned_install_quarantine:-}" && -e "$owned_install_quarantine" ]]; then
        identity="$(/usr/bin/stat -c '%d:%i' -- "$owned_install_quarantine")" || return 1
        [[ "$identity" == "$owned_install_device:$owned_install_inode" ]] || return 1
        /usr/bin/rm -rf -- "$owned_install_quarantine" || return 1
    fi
    if [[ -n "${owned_candidate_destination:-}" && -e "$owned_candidate_destination" ]]; then
        [[ -f "$owned_candidate_destination" && ! -L "$owned_candidate_destination" ]] || return 1
        identity="$(/usr/bin/stat -c '%d:%i' -- "$owned_candidate_destination")" || return 1
        [[ "$identity" == "$owned_candidate_device:$owned_candidate_inode" ]] || return 1
        /usr/bin/rm -f -- "$owned_candidate_destination" || return 1
        /usr/bin/python3.10 -c \
            'import os,sys; fd=os.open(sys.argv[1], os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(fd); os.close(fd)' \
            "$(/usr/bin/dirname -- "$owned_candidate_destination")" || return 1
    fi
    if [[ -n "${owned_candidate_staging_path:-}" && -e "$owned_candidate_staging_path" ]]; then
        [[ -f "$owned_candidate_staging_path" && ! -L "$owned_candidate_staging_path" ]] || return 1
        identity="$(/usr/bin/stat -c '%d:%i' -- "$owned_candidate_staging_path")" || return 1
        [[ "$identity" == "$owned_candidate_device:$owned_candidate_inode" ]] || return 1
        /usr/bin/rm -f -- "$owned_candidate_staging_path" || return 1
    fi
    owned_candidate_staging_path=""
    owned_candidate_destination=""
    owned_candidate_device=""
    owned_candidate_inode=""
    owned_install_destination=""
    owned_install_quarantine=""
    owned_install_device=""
    owned_install_inode=""
}

signal_received() {
    local status="$1"
    if ((first_signal_status == 0)); then
        first_signal_status="$status"
    fi
    if ((launching_child == 0)); then
        terminate "$first_signal_status"
    fi
}

run_owned_process() {
    local identity status=0
    launching_child=1
    /usr/bin/setsid -- "$@" &
    active_child_pid=$!
    identity="$(process_identity "$active_child_pid")" || {
        launching_child=0
        stop_owned_child
        if ((first_signal_status != 0)); then
            terminate "$first_signal_status"
        fi
        if ((stopped_child_status == 0)); then
            return 0
        fi
        return 3
    }
    read -r active_child_pgid active_child_starttime <<<"$identity"
    if [[ "$active_child_pgid" != "$active_child_pid" ]]; then
        launching_child=0
        stop_owned_child
        if ((first_signal_status != 0)); then
            terminate "$first_signal_status"
        fi
        return 3
    fi
    launching_child=0
    if ((first_signal_status != 0)); then
        terminate "$first_signal_status"
    fi
    wait "$active_child_pid" || status=$?
    clear_owned_child
    return "$status"
}

run_owned_docker() {
    local docker_bin="$1"
    shift
    [[ "${1:-}" == "run" ]] || return 2
    shift
    local inventory status=0
    active_docker_bin="$docker_bin"
    active_container_nonce="$(/usr/bin/python3.10 -c 'import secrets; print(secrets.token_hex(16))')"
    active_container_name="holoagent0-strace-$active_container_nonce"
    inventory="$(/usr/bin/timeout "$docker_cleanup_timeout" "$docker_bin" \
        container ls --all --no-trunc \
        --filter "name=^/${active_container_name}$" --format '{{.Names}}|{{.Labels}}')" \
        || return 3
    [[ -z "$inventory" ]] || return 3
    container_launch_attempted=1
    run_owned_process "$docker_bin" run \
        --name "$active_container_name" \
        --label "holoagent0.strace.owner=$active_container_nonce" \
        "$@" || status=$?
    remove_owned_container || return 3
    return "$status"
}

run_owned_publication() {
    run_owned_process "$@"
}

install_provisioner_traps() {
    trap cleanup EXIT
    trap 'signal_received 129' HUP
    trap 'signal_received 130' INT
    trap 'signal_received 143' TERM
}

allocate_owned_directory() {
    local variable_name="$1" parent="$2" prefix="$3" nonce path
    nonce="$(/usr/bin/python3.10 -c 'import secrets; print(secrets.token_hex(16))')"
    path="$parent/$prefix-$nonce"
    printf -v "$variable_name" '%s' "$path"
    run_owned_process /usr/bin/mkdir --mode=0700 -- "$path"
    [[ -d "$path" && ! -L "$path" ]] || return 3
}

record_owned_install_publication() {
    install_staging_dir="$1"
    owned_install_destination="$2"
    owned_install_quarantine="$3"
    local identity
    identity="$(/usr/bin/stat -c '%d:%i' -- "$install_staging_dir")" || return 3
    IFS=: read -r owned_install_device owned_install_inode <<<"$identity"
}

prepare_owned_candidate_stage() {
    owned_candidate_staging_path="$1"
    local identity status=0
    run_owned_process /usr/bin/python3.10 -c \
        'import os,sys; fd=os.open(sys.argv[1], os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600); os.fchmod(fd, 0o600); os.close(fd)' \
        "$owned_candidate_staging_path" || status=$?
    ((status == 0)) || return "$status"
    identity="$(/usr/bin/stat -c '%d:%i' -- "$owned_candidate_staging_path")" || return 3
    IFS=: read -r owned_candidate_device owned_candidate_inode <<<"$identity"
}
# END_OWNED_PROCESS_HELPERS
install_provisioner_traps

# Traps and ownership variables precede every residue-capable allocation.
if [[ -n "$output_dir" ]]; then
    temp_parent="$(/usr/bin/dirname -- "$output_dir")"
    [[ -d "$temp_parent" && ! -L "$temp_parent" ]] || {
        printf 'error: output parent must be a real directory\n' >&2
        exit 2
    }
    allocate_owned_directory temp_dir "$temp_parent" .holoagent0-strace
    allocate_owned_directory install_staging_dir "$temp_parent" .holoagent0-strace-install
else
    temp_parent="${TMPDIR:-/tmp}"
    [[ -d "$temp_parent" && ! -L "$temp_parent" ]] || {
        printf 'error: temporary parent must be a real directory\n' >&2
        exit 2
    }
    allocate_owned_directory temp_dir "$temp_parent" holoagent0-strace
    install_staging_dir="$temp_dir/install"
fi
snapshot="$temp_dir/strace-6.6.tar.xz"

if [[ -n "$archive" ]]; then
    if [[ ! -f "$archive" || -L "$archive" ]]; then
        printf 'error: archive must be a regular non-symlink file\n' >&2
        exit 2
    fi
    /usr/bin/cp --reflink=never -- "$archive" "$snapshot"
else
    /usr/bin/curl --fail --location --proto '=https' --tlsv1.2 \
        --output "$snapshot" "$SOURCE_URL"
fi

actual_size="$(/usr/bin/stat -c '%s' -- "$snapshot")"
if [[ "$actual_size" != "$SOURCE_SIZE" ]]; then
    printf 'error: source archive size mismatch\n' >&2
    exit 2
fi
actual_sha256="$(/usr/bin/sha256sum -- "$snapshot" | /usr/bin/cut -d ' ' -f 1)"
if [[ "$actual_sha256" != "$SOURCE_SHA256" ]]; then
    printf 'error: source archive sha256 mismatch\n' >&2
    exit 2
fi

/usr/bin/python3.10 - "$snapshot" "$TOP_DIRECTORY" <<'PY'
# BEGIN_ARCHIVE_VALIDATOR
from pathlib import PurePosixPath
import sys
import tarfile

archive_path, expected_top = sys.argv[1:]
with tarfile.open(archive_path, mode="r:xz") as archive_file:
    members = archive_file.getmembers()
    if not members:
        raise SystemExit("error: empty archive")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or not path.parts or path.parts[0] != expected_top:
            raise SystemExit("error: archive member outside exact top directory")
        if any(part in {"", ".", ".."} for part in path.parts):
            raise SystemExit("error: unsafe archive member path")
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise SystemExit("error: unsupported archive member type")
        if member.issym() or member.islnk():
            target = PurePosixPath(member.linkname)
            if target.is_absolute():
                raise SystemExit("error: absolute archive link target")
            base = path.parent if member.issym() else PurePosixPath()
            parts = []
            for part in (base / target).parts:
                if part in {"", "."}:
                    continue
                if part == "..":
                    if not parts:
                        raise SystemExit("error: escaping archive link target")
                    parts.pop()
                else:
                    parts.append(part)
            if not parts or parts[0] != expected_top:
                raise SystemExit("error: escaping archive link target")
# END_ARCHIVE_VALIDATOR
PY

# Local archives are inspected before this gate; no build can cross it without pins.
validate_build_pins
if [[ -n "$output_dir" ]]; then
    validate_runtime_pins
fi

/usr/bin/mkdir "$temp_dir/source" "$temp_dir/build"
if [[ -z "$output_dir" ]]; then
    /usr/bin/mkdir "$install_staging_dir"
fi
/usr/bin/tar --extract --xz --file "$snapshot" --directory "$temp_dir/source" \
    --no-same-owner --no-same-permissions "$TOP_DIRECTORY"

umask 0022
run_owned_docker /usr/bin/docker run --pull=never --network=none \
    --user "$(/usr/bin/id -u):$(/usr/bin/id -g)" \
    --env LC_ALL=C --env LANG=C --env TZ=UTC --env SOURCE_DATE_EPOCH=0 \
    --volume "$temp_dir/source/$TOP_DIRECTORY:/src:ro" \
    --volume "$temp_dir/build:/build" \
    --volume "$install_staging_dir:/out" \
    "docker.io/library/gcc@${pins[2]}" \
    /bin/sh -eu -c 'cd /build && /src/configure --prefix=/out --disable-gcc-Werror && make -j1 && make install'

elf="$install_staging_dir/bin/strace"
[[ -f "$elf" && ! -L "$elf" ]] || { printf 'error: build did not produce strace ELF\n' >&2; exit 3; }
/usr/bin/python3.10 - "$elf" <<'PY'
from pathlib import Path
import struct
import sys

header = Path(sys.argv[1]).read_bytes()[:20]
EM_X86_64 = 62
if len(header) != 20 or header[:4] != b"\x7fELF":
    raise SystemExit("error: runtime is not an ELF file")
if header[4] != 2 or header[5] != 1:
    raise SystemExit("error: runtime is not ELF64 little-endian")
if struct.unpack("<H", header[18:20])[0] != EM_X86_64:
    raise SystemExit("error: runtime is not linux-x86_64")
PY
elf_size="$(/usr/bin/stat -c '%s' -- "$elf")"
elf_sha256="$(/usr/bin/sha256sum -- "$elf" | /usr/bin/cut -d ' ' -f 1)"
version_output="$(LC_ALL=C TZ=UTC "$elf" --version)"
case "$version_output" in
    "strace -- version 6.6"|"strace -- version 6.6"$'\n'*) ;;
    *) printf 'error: runtime version is not exactly strace 6.6\n' >&2; exit 3 ;;
esac
version_sha256="$(printf '%s\n' "$version_output" | /usr/bin/sha256sum | /usr/bin/cut -d ' ' -f 1)"

if [[ -n "$candidate_evidence" ]]; then
    # This path publishes only CANDIDATE_MEASUREMENT, never a reviewed install.
    candidate_parent="$(/usr/bin/dirname -- "$candidate_evidence")"
    candidate_nonce="$(/usr/bin/python3.10 -c 'import secrets; print(secrets.token_hex(16))')"
    owned_candidate_staging_path="$candidate_parent/.holoagent0-strace-candidate-$candidate_nonce"
    owned_candidate_destination="$candidate_evidence"
    prepare_owned_candidate_stage "$owned_candidate_staging_path"
    run_owned_publication /usr/bin/python3.10 -c "$publication_helper_source" \
        candidate "$candidate_evidence" "$owned_candidate_staging_path" \
        "${pins[1]}" "${pins[2]}" \
        "$elf_size" "$elf_sha256" "$version_sha256" \
        "$owned_candidate_device" "$owned_candidate_inode"
    owned_candidate_staging_path=""
    owned_candidate_destination=""
    owned_candidate_device=""
    owned_candidate_inode=""
    exit 0
fi

[[ "$elf_size" == "${pins[4]}" ]] || { printf 'error: ELF size mismatch\n' >&2; exit 3; }
[[ "$elf_sha256" == "${pins[5]}" ]] || { printf 'error: ELF sha256 mismatch\n' >&2; exit 3; }
[[ "$version_sha256" == "${pins[6]}" ]] || { printf 'error: version output sha256 mismatch\n' >&2; exit 3; }
install_nonce="$(/usr/bin/python3.10 -c 'import secrets; print(secrets.token_hex(16))')"
install_quarantine="$(/usr/bin/dirname -- "$output_dir")/.holoagent0-strace-quarantine-$install_nonce"
record_owned_install_publication \
    "$install_staging_dir" "$output_dir" "$install_quarantine"
run_owned_publication /usr/bin/python3.10 -c "$publication_helper_source" \
    install "$install_staging_dir" "$output_dir" "$install_quarantine"
run_owned_publication /usr/bin/python3.10 -c "$publication_helper_source" \
    verify "$output_dir"
owned_install_destination=""
owned_install_quarantine=""
owned_install_device=""
owned_install_inode=""
install_staging_dir=""
