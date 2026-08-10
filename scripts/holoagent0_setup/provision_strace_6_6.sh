#!/usr/bin/env bash
set -euo pipefail

SOURCE_URL="https://strace.io/files/6.6/strace-6.6.tar.xz"
SOURCE_SIZE="2420364"
SOURCE_SHA256="421b4186c06b705163e64dc85f271ebdcf67660af8667283147d5e859fc8a96c"
TOP_DIRECTORY="strace-6.6"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
REPOSITORY_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd -P)"
POLICY_PATH="$SCRIPT_DIR/policies/holoagent0-trace-tool-v1.json"
USAGE="usage: $0 [--archive ARCHIVE] --output-dir OUTPUT_DIR [--candidate-evidence FILE]"

archive=""
output_dir=""
candidate_evidence=""

while (($#)); do
    case "$1" in
        --archive)
            (($# >= 2)) || { printf '%s\n' "$USAGE" >&2; exit 2; }
            archive="$2"
            shift 2
            ;;
        --output-dir)
            (($# >= 2)) || { printf '%s\n' "$USAGE" >&2; exit 2; }
            output_dir="$2"
            shift 2
            ;;
        --candidate-evidence)
            (($# >= 2)) || { printf '%s\n' "$USAGE" >&2; exit 2; }
            candidate_evidence="$2"
            shift 2
            ;;
        *)
            printf '%s\n' "$USAGE" >&2
            exit 2
            ;;
    esac
done

if [[ -z "$output_dir" ]]; then
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
for parent in (resolved, *resolved.parents):
    if parent.exists() and parent.is_symlink():
        raise SystemExit("destination must not traverse a symlink")
PY
}

validate_destination "$output_dir"
if [[ -n "$candidate_evidence" ]]; then
    validate_destination "$candidate_evidence"
fi
if [[ -e "$output_dir" || -L "$output_dir" ]]; then
    printf 'error: output directory already exists\n' >&2
    exit 2
fi

temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/holoagent0-strace.XXXXXXXX")"
cleanup() {
    local status=$?
    trap - EXIT HUP INT TERM
    rm -rf -- "$temp_dir"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM
snapshot="$temp_dir/strace-6.6.tar.xz"

if [[ -n "$archive" ]]; then
    if [[ ! -f "$archive" || -L "$archive" ]]; then
        printf 'error: archive must be a regular non-symlink file\n' >&2
        exit 2
    fi
    cp --reflink=never -- "$archive" "$snapshot"
else
    /usr/bin/curl --fail --location --proto '=https' --tlsv1.2 \
        --output "$snapshot" "$SOURCE_URL"
fi

actual_size="$(stat -c '%s' -- "$snapshot")"
if [[ "$actual_size" != "$SOURCE_SIZE" ]]; then
    printf 'error: source archive size mismatch\n' >&2
    exit 2
fi
actual_sha256="$(sha256sum -- "$snapshot" | cut -d ' ' -f 1)"
if [[ "$actual_sha256" != "$SOURCE_SHA256" ]]; then
    printf 'error: source archive sha256 mismatch\n' >&2
    exit 2
fi

/usr/bin/python3.10 - "$snapshot" "$TOP_DIRECTORY" <<'PY'
from pathlib import PurePosixPath
import sys
import tarfile

archive_path, expected_top = sys.argv[1:]
with tarfile.open(archive_path, mode="r:xz") as archive:
    members = archive.getmembers()
    if not members:
        raise SystemExit("error: empty source archive")
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
PY

mkdir "$temp_dir/source"
tar --extract --xz --file "$snapshot" --directory "$temp_dir/source" \
    --no-same-owner --no-same-permissions "$TOP_DIRECTORY"

readarray -t pins < <(/usr/bin/python3.10 - "$POLICY_PATH" <<'PY'
import json
from pathlib import Path
import sys

policy = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
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

if [[ "${pins[0]}" != "REVIEWED" || -z "${pins[1]}" || -z "${pins[2]}" || \
      "${pins[3]}" != "REVIEWED" || -z "${pins[4]}" || -z "${pins[5]}" || \
      -z "${pins[6]}" ]]; then
    printf 'error: PENDING_REPRODUCIBLE_BUILD: explicit tracked build/runtime pins are required\n' >&2
    exit 3
fi

recipe_sha256="$(sha256sum -- "$0" | cut -d ' ' -f 1)"
if [[ "$recipe_sha256" != "${pins[1]}" ]]; then
    printf 'error: reviewed build recipe sha256 mismatch\n' >&2
    exit 3
fi
if [[ ! "${pins[2]}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf 'error: container image is not pinned by digest\n' >&2
    exit 3
fi

# This branch is unreachable until a human-reviewed policy commit supplies every
# literal build and runtime pin. The build has no network and no host-toolchain path.
umask 0022
docker run --rm --network=none \
    --env LC_ALL=C --env LANG=C --env TZ=UTC --env SOURCE_DATE_EPOCH=0 \
    --volume "$temp_dir/source/$TOP_DIRECTORY:/src:ro" \
    --volume "$temp_dir/install:/out" \
    "docker.io/library/debian@${pins[2]}" \
    /bin/sh -eu -c 'cd /src && ./configure --prefix=/out --disable-gcc-Werror && make -j1 && make install'

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
[[ "$(stat -c '%s' -- "$elf")" == "${pins[4]}" ]] || { printf 'error: ELF size mismatch\n' >&2; exit 3; }
[[ "$(sha256sum -- "$elf" | cut -d ' ' -f 1)" == "${pins[5]}" ]] || { printf 'error: ELF sha256 mismatch\n' >&2; exit 3; }
version_output="$(LC_ALL=C TZ=UTC "$elf" --version)"
case "$version_output" in
    "strace -- version 6.6"|"strace -- version 6.6"$'\n'*) ;;
    *) printf 'error: runtime version is not exactly strace 6.6\n' >&2; exit 3 ;;
esac
version_sha256="$(printf '%s\n' "$version_output" | sha256sum | cut -d ' ' -f 1)"
[[ "$version_sha256" == "${pins[6]}" ]] || { printf 'error: version output sha256 mismatch\n' >&2; exit 3; }

if [[ -n "$candidate_evidence" ]]; then
    printf 'error: candidate evidence is only produced by a separately reviewed measurement workflow\n' >&2
    exit 3
fi
mv -- "$temp_dir/install" "$output_dir"
