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

temp_dir="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/holoagent0-strace.XXXXXXXX")"
cleanup() {
    local status=$?
    trap - EXIT
    /usr/bin/rm -rf -- "$temp_dir" || :
    exit "$status"
}
terminate() {
    local status="$1"
    trap - EXIT HUP INT TERM
    /usr/bin/rm -rf -- "$temp_dir" || :
    exit "$status"
}
trap cleanup EXIT
trap 'terminate 129' HUP
trap 'terminate 130' INT
trap 'terminate 143' TERM
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

/usr/bin/mkdir "$temp_dir/source" "$temp_dir/build" "$temp_dir/install"
/usr/bin/tar --extract --xz --file "$snapshot" --directory "$temp_dir/source" \
    --no-same-owner --no-same-permissions "$TOP_DIRECTORY"

umask 0022
/usr/bin/docker run --rm --pull=never --network=none \
    --user "$(/usr/bin/id -u):$(/usr/bin/id -g)" \
    --env LC_ALL=C --env LANG=C --env TZ=UTC --env SOURCE_DATE_EPOCH=0 \
    --volume "$temp_dir/source/$TOP_DIRECTORY:/src:ro" \
    --volume "$temp_dir/build:/build" \
    --volume "$temp_dir/install:/out" \
    "docker.io/library/gcc@${pins[2]}" \
    /bin/sh -eu -c 'cd /build && /src/configure --prefix=/out --disable-gcc-Werror && make -j1 && make install'

elf="$temp_dir/install/bin/strace"
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
    /usr/bin/python3.10 - "$candidate_evidence" "${pins[1]}" "${pins[2]}" \
        "$elf_size" "$elf_sha256" "$version_sha256" <<'PY'
import json
import os
from pathlib import Path
import sys
import tempfile

destination = Path(sys.argv[1])
evidence = {
    "schema_version": "holoagent0.strace-candidate-evidence.v1",
    "measurement_kind": "CANDIDATE_MEASUREMENT",
    "recipe_sha256": sys.argv[2],
    "container_image_digest": sys.argv[3],
    "elf_size": int(sys.argv[4]),
    "elf_sha256": sys.argv[5],
    "version_output_sha256": sys.argv[6],
}
payload = (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode()
with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
    temporary.write(payload)
    temporary.flush()
    os.fsync(temporary.fileno())
    temporary_path = temporary.name
os.replace(temporary_path, destination)
PY
    exit 0
fi

[[ "$elf_size" == "${pins[4]}" ]] || { printf 'error: ELF size mismatch\n' >&2; exit 3; }
[[ "$elf_sha256" == "${pins[5]}" ]] || { printf 'error: ELF sha256 mismatch\n' >&2; exit 3; }
[[ "$version_sha256" == "${pins[6]}" ]] || { printf 'error: version output sha256 mismatch\n' >&2; exit 3; }
/usr/bin/mv -- "$temp_dir/install" "$output_dir"
