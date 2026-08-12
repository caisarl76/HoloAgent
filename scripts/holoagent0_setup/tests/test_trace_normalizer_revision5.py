from pathlib import Path

import pytest

from holoagent0_setup.trace_normalizer import (
    TraceDecodeError,
    TraceNormalizer,
    canonical_ndjson,
    normalize_bytes,
)


ROOT = Path(__file__).parents[1]
TEST_MANIFEST = ROOT / "test-manifest-v1.txt"


def _line(
    call: str,
    result: str = "0",
    *,
    pid: int = 84,
    timestamp: str = "1700000053.000001",
    duration: str = "0.000001",
) -> bytes:
    prefix = f"{pid:<5} {timestamp} "
    padding = " " * max(1, 40 - len(prefix) - len(call))
    return f"{prefix}{call}{padding}= {result} <{duration}>\n".encode()


@pytest.mark.parametrize(("phase", "prefix"), [("BEGIN", "H0B"), ("END", "H0E")])
def test_pinned_pr_set_name_marker_ellipsis_preserves_phase_and_token(phase, prefix):
    token = "0123456789ab"
    record = normalize_bytes(_line(f'prctl(PR_SET_NAME, "{prefix}{token}"...)'))[0]
    assert record["marker"] == {"phase": phase, "token": token}
    assert record["pid"] == 84
    assert record["entry_index"] == record["exit_index"] == 0
    assert record["result"] == {"value": 0}


def test_failed_pinned_marker_ellipsis_remains_visible_with_failure_result():
    record = normalize_bytes(
        _line(
            'prctl(PR_SET_NAME, "H0B0123456789ab"...)',
            "-1 EPERM (Operation not permitted)",
        )
    )[0]
    assert record["marker"] == {"phase": "BEGIN", "token": "0123456789ab"}
    assert record["result"]["errno"] == "EPERM"


def test_no_ellipsis_fifteen_byte_name_cannot_gain_pinned_marker_authority():
    record = normalize_bytes(_line('prctl(PR_SET_NAME, "H0B0123456789ab")'))[0]
    assert "marker" not in record


@pytest.mark.parametrize(
    ("prefix", "phase"),
    [("H0R", "READINESS_BEGIN"), ("H0F", "FUNCTIONAL_BEGIN")],
)
def test_handoff_marker_is_separate_payload_free_metadata(prefix, phase):
    token = "0123456789ab"
    record = normalize_bytes(_line(f'prctl(PR_SET_NAME, "{prefix}{token}"...)'))[0]

    assert record["handoff_marker"] == {"phase": phase, "token": token}
    assert "marker" not in record


@pytest.mark.parametrize(
    "call",
    [
        'prctl(PR_SET_NAME, "H0R0123456789a"...)',
        'prctl(PR_SET_NAME, "H0R0123456789ag"...)',
        'prctl(PR_SET_NAME, "H0X0123456789ab"...)',
        'prctl(PR_SET_NAME, "H0F0123456789ab")',
    ],
)
def test_handoff_marker_rejects_malformed_or_unreviewed_names(call):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(call))


@pytest.mark.parametrize(
    ("prefix", "phase"),
    [("H0R", "READINESS"), ("H0F", "FUNCTIONAL")],
)
def test_handoff_name_observation_is_separate_payload_free_metadata(prefix, phase):
    token = "0123456789ab"
    record = normalize_bytes(_line(f'prctl(PR_GET_NAME, "{prefix}{token}")'))[0]

    assert record["handoff_name_observation"] == {
        "phase": phase,
        "token": token,
    }
    assert "handoff_marker" not in record


@pytest.mark.parametrize(
    "call",
    [
        'prctl(PR_GET_NAME, "H0R0123456789a")',
        'prctl(PR_GET_NAME, "H0R0123456789ag")',
        'prctl(PR_GET_NAME, "H0F0123456789abc")',
    ],
)
def test_handoff_name_observation_rejects_malformed_reserved_name(call):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(call))


@pytest.mark.parametrize(
    "call",
    [
        'prctl(PR_SET_NAME, "H0X0123456789ab"...)',
        'prctl(PR_SET_NAME, "H0B0123456789AB"...)',
        'prctl(PR_SET_NAME, "H0B0123456789a"...)',
        'prctl(PR_SET_NAME, "H0B0123456789abc"...)',
        'prctl(PR_SET_NAME, "H0B0123456789abPAYLOAD_SENTINEL"...)',
        'prctl(PR_GET_NAME, "H0B0123456789ab"...)',
        'prctl(PR_SET_NAME, "ordinary"...)',
        'write(1, "PAYLOAD_SENTINEL"..., 16)',
    ],
)
def test_every_nonmarker_ellipsis_remains_rejected(call):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(call))


def test_marker_result_alignment_counts_the_displayed_ellipsis_columns():
    source = _line('prctl(PR_SET_NAME, "H0B0123456789ab"...)')
    assert b'"...) = 0' in source
    assert normalize_bytes(source)[0]["marker"]["phase"] == "BEGIN"
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source.replace(b'"...) =', b'"...)  ='))


def test_signal_unblock_preserves_the_exact_reviewed_mask_and_null_old_mask():
    record = normalize_bytes(
        _line("rt_sigprocmask(SIG_UNBLOCK, [HUP INT TERM], NULL, 8)")
    )[0]

    assert record["transition"] == {
        "operation": "rt_sigprocmask",
        "how": "SIG_UNBLOCK",
        "mask": ["HUP", "INT", "TERM"],
        "old_mask": None,
        "sigset_size": 8,
    }
    assert record["result"] == {"value": 0}


def test_signal_mask_observation_preserves_the_old_mask_without_payload_data():
    record = normalize_bytes(_line("rt_sigprocmask(SIG_BLOCK, [], [HUP INT TERM], 8)"))[
        0
    ]

    assert record["transition"] == {
        "operation": "rt_sigprocmask",
        "how": "SIG_BLOCK",
        "mask": [],
        "old_mask": ["HUP", "INT", "TERM"],
        "sigset_size": 8,
    }
    assert "PAYLOAD" not in canonical_ndjson([record])


def test_signal_action_preserves_handler_class_without_persisting_addresses():
    record = normalize_bytes(
        _line(
            "rt_sigaction(SIGHUP, "
            "{sa_handler=0x1234, sa_mask=[], "
            "sa_flags=SA_RESTORER|SA_ONSTACK, sa_restorer=0x5678}, "
            "{sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8)"
        )
    )[0]

    assert record["transition"] == {
        "operation": "rt_sigaction",
        "signal": "HUP",
        "action": {
            "handler": "CUSTOM",
            "mask": [],
            "flags": ["SA_RESTORER", "SA_ONSTACK"],
            "restorer": True,
        },
        "old_action": {
            "handler": "DEFAULT",
            "mask": [],
            "flags": [],
            "restorer": False,
        },
        "sigset_size": 8,
    }
    rendered = canonical_ndjson([record])
    assert "0x1234" not in rendered
    assert "0x5678" not in rendered


@pytest.mark.parametrize(
    "call",
    [
        "rt_sigprocmask(SIG_UNKNOWN, [HUP INT TERM], NULL, 8)",
        "rt_sigprocmask(SIG_UNBLOCK, [HUP HUP], NULL, 8)",
        "rt_sigprocmask(SIG_UNBLOCK, [HUP INT TERM], NULL, -1)",
        "rt_sigprocmask(SIG_UNBLOCK, [HUP INT TERM], PAYLOAD_SENTINEL, 8)",
    ],
)
def test_signal_mask_transition_rejects_undecodable_or_ambiguous_fields(call):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(call))


def test_interleaved_unfinished_vfork_with_whitespace_only_arguments_is_no_arg():
    source = (
        b"201   1700000054.000001 vfork( <unfinished ...>\n"
        b"202   1700000054.000002 getpid()        = 202 <0.000001>\n"
        b"201   1700000054.000003 <... vfork resumed>) = 202 <0.000010>\n"
    )

    records = normalize_bytes(source)

    assert records == [
        {
            "kind": "syscall",
            "pid": 202,
            "timestamp": "1700000054.000002",
            "duration": "0.000001",
            "entry_index": 1,
            "exit_index": 0,
            "syscall": "getpid",
            "result": {"value": 202},
            "record_index": 0,
        },
        {
            "kind": "syscall",
            "pid": 201,
            "timestamp": "1700000054.000001",
            "duration": "0.000010",
            "entry_index": 0,
            "exit_index": 1,
            "syscall": "vfork",
            "result": {"value": 202},
            "transition": {
                "operation": "vfork",
                "child_pid": 202,
                "fd_table": "copied",
            },
            "record_index": 1,
        },
    ]


@pytest.mark.parametrize(
    "call",
    [
        "read(3, , 1)",
        "vfork(,)",
        "vfork( , )",
    ],
)
def test_no_arg_vfork_support_does_not_accept_empty_comma_fields(call):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(call, "202"))


def _resumed_wait4(
    *,
    waited_pid=302,
    result_pid=302,
    status="WIFEXITED(s) && WEXITSTATUS(s) == 0",
    options="0",
    rusage="NULL",
):
    return (
        f"301   1700000054.000004 wait4({waited_pid},  <unfinished ...>\n"
        f"301   1700000054.000005 <... wait4 resumed>"
        f"[{{{status}}}], {options}, {rusage}) = {result_pid} <0.011225>\n"
    ).encode()


def test_resumed_wait4_exit_status_is_validated_but_not_authoritative():
    records = normalize_bytes(_resumed_wait4())

    assert records == [
        {
            "kind": "syscall",
            "pid": 301,
            "timestamp": "1700000054.000004",
            "duration": "0.011225",
            "entry_index": 0,
            "exit_index": 0,
            "syscall": "wait4",
            "result": {"value": 302},
            "record_index": 0,
        }
    ]
    assert "transition" not in records[0]


@pytest.mark.parametrize(
    "source",
    [
        _resumed_wait4(waited_pid=302, result_pid=303),
        _resumed_wait4(status="WIFCONTINUED(s)"),
        _resumed_wait4(status="WIFSIGNALED(s) && WTERMSIG(s) == SIGTERM"),
        _resumed_wait4(status="WIFSTOPPED(s) && WSTOPSIG(s) == SIGSTOP"),
        _resumed_wait4(status="WIFEXITED(s) && WEXITSTATUS(s) == 256"),
        _resumed_wait4(options="WNOHANG"),
        _resumed_wait4(rusage="0x1234"),
    ],
    ids=(
        "result-pid-mismatch",
        "unknown-status",
        "unreviewed-signaled-status",
        "unreviewed-stopped-status",
        "invalid-exit-status",
        "unreviewed-options",
        "decoded-rusage",
    ),
)
def test_resumed_wait4_rejects_unreviewed_or_inconsistent_annotations(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def _exit_group_pair(*, status=0, exited=0):
    return (
        f"301   1700000054.000006 exit_group({status}) = ?\n"
        f"301   1700000054.000007 +++ exited with {exited} +++\n"
    ).encode()


def test_exit_group_is_non_authoritative_until_matching_terminal_event():
    normalizer = TraceNormalizer()

    assert normalizer.feed(b"301   1700000054.000006 exit_group(7) = ?\n") == []
    assert normalizer.feed(
        b"302   1700000054.000006 getpid()        = 302 <0.000001>\n"
    ) == [
        {
            "kind": "syscall",
            "pid": 302,
            "timestamp": "1700000054.000006",
            "duration": "0.000001",
            "entry_index": 0,
            "exit_index": 0,
            "syscall": "getpid",
            "result": {"value": 302},
            "record_index": 0,
        }
    ]
    terminal = normalizer.feed(b"301   1700000054.000007 +++ exited with 7 +++\n")
    assert terminal == [
        {
            "kind": "exit",
            "pid": 301,
            "timestamp": "1700000054.000007",
            "exit_code": 7,
            "record_index": 1,
        }
    ]
    assert normalizer.finish() == []
    assert all(record.get("syscall") != "exit_group" for record in terminal)


@pytest.mark.parametrize(
    "source",
    [
        _exit_group_pair(status=7, exited=8),
        (
            b"301   1700000054.000006 exit_group(7) = ?\n"
            b"301   1700000054.000007 exit_group(7) = ?\n"
        ),
        (
            b"301   1700000054.000006 exit_group(7) = ?\n"
            b"301   1700000054.000007 getpid()        = 301 <0.000001>\n"
        ),
        (
            b"301   1700000054.000006 exit_group(7) = ?\n"
            b"301   1700000054.000007 --- SIGTERM {si_signo=SIGTERM} ---\n"
        ),
        (
            b"301   1700000054.000006 exit_group(7) = ?\n"
            b"301   1700000054.000007 +++ killed by SIGTERM +++\n"
        ),
        b"301   1700000054.000006 exit_group(-1) = ?\n",
        b"301   1700000054.000006 exit_group(256) = ?\n",
        b"301   1700000054.000006 exit_group(0 /* annotated */) = ?\n",
        b"301   1700000054.000006 exit_group(0) = ? <0.000001>\n",
    ],
    ids=(
        "mismatched-exit",
        "duplicate",
        "intervening-syscall",
        "intervening-signal",
        "killed-terminal",
        "negative-status",
        "out-of-range-status",
        "annotated-status",
        "duration-variant",
    ),
)
def test_exit_group_pair_rejects_unreviewed_or_inconsistent_sequences(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_exit_group_pair_rejects_eof_before_terminal_event():
    normalizer = TraceNormalizer()
    assert normalizer.feed(b"301   1700000054.000006 exit_group(7) = ?\n") == []
    with pytest.raises(TraceDecodeError):
        normalizer.finish()


def test_thread_exit_is_non_authoritative_until_matching_terminal_event():
    normalizer = TraceNormalizer()
    assert normalizer.feed(b"301   1700000054.000006 exit(0)       = ?\n") == []
    records = normalizer.feed(b"301   1700000054.000007 +++ exited with 0 +++\n")
    assert records == [
        {
            "kind": "exit",
            "pid": 301,
            "timestamp": "1700000054.000007",
            "exit_code": 0,
            "record_index": 0,
        }
    ]
    assert normalizer.finish() == []


@pytest.mark.parametrize(
    "source",
    [
        b"301   1700000054.000006 exit(7) = ?\n"
        b"301   1700000054.000007 +++ exited with 8 +++\n",
        b"301   1700000054.000006 exit(-1) = ?\n",
        b"301   1700000054.000006 exit(256) = ?\n",
        b"301   1700000054.000006 exit(0) = ? <0.000001>\n",
    ],
)
def test_thread_exit_pair_rejects_unreviewed_or_inconsistent_sequences(source):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_deleted_tmpfile_return_is_redacted_to_path_provenance():
    records = normalize_bytes(
        b'301   1700000054.000006 openat(AT_FDCWD</tmp>, "/tmp", '
        b"O_RDWR|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_TMPFILE, 0600) "
        b"= 6</tmp/#9351668>(deleted) <0.000016>\n"
    )
    assert records[0]["result"] == {
        "value": 6,
        "fd": {"fd": 6, "provenance": {"kind": "path"}},
    }


def test_deleted_tmpfile_annotation_is_valid_for_fd_arguments_and_alias_result():
    records = normalize_bytes(
        b"301   1700000054.000006 "
        b"dup2(6</tmp/#9351668>(deleted), 1<pipe:[42]>) "
        b"= 1</tmp/#9351668>(deleted) <0.000008>\n"
    )
    assert records[0]["transition"] == {
        "operation": "dup2",
        "source_fd": {"fd": 6, "provenance": {"kind": "path"}},
        "target_fd": {"fd": 1, "provenance": {"kind": "pipe", "inode": 42}},
        "created_fd": {"fd": 1, "provenance": {"kind": "path"}},
    }


@pytest.mark.parametrize(
    "result",
    [
        "6<pipe:[42]>(deleted)",
        "6</tmp/file>(DELETED)",
        "6</tmp/file>(deleted)junk",
        "-1</tmp/file>(deleted)",
    ],
)
def test_deleted_return_annotation_rejects_non_path_or_malformed_forms(result):
    source = (
        '301   1700000054.000006 openat(AT_FDCWD</tmp>, "/tmp", O_RDONLY) = '
        + result
        + " <0.000016>\n"
    ).encode()
    with pytest.raises(TraceDecodeError):
        normalize_bytes(source)


def test_pending_process_bound_counts_two_exit_group_pids_together():
    normalizer = TraceNormalizer(max_pending_processes=1)
    assert normalizer.feed(b"301   1700000054.000006 exit_group(0) = ?\n") == []
    with pytest.raises(TraceDecodeError, match="pending-process-bound"):
        normalizer.feed(b"302   1700000054.000007 exit_group(0) = ?\n")


def test_pending_process_bound_counts_unfinished_and_exit_group_together():
    normalizer = TraceNormalizer(max_pending_processes=1)
    assert (
        normalizer.feed(b"301   1700000054.000006 read(0x3, <unfinished ...>\n") == []
    )
    with pytest.raises(TraceDecodeError, match="pending-process-bound"):
        normalizer.feed(b"302   1700000054.000007 exit_group(0) = ?\n")


def test_same_pid_cannot_hold_unfinished_and_exit_group_pending_states():
    normalizer = TraceNormalizer(max_pending_processes=2)
    assert (
        normalizer.feed(b"301   1700000054.000006 read(0x3, <unfinished ...>\n") == []
    )
    with pytest.raises(TraceDecodeError, match="unreviewed-exit-group"):
        normalizer.feed(b"301   1700000054.000007 exit_group(0) = ?\n")


_PIPE_STAT = (
    "{st_dev=makedev(0, 0xe), st_ino=301, st_mode=S_IFIFO|0600, st_nlink=1, "
    "st_uid=1000, st_gid=1000, st_blksize=4096, st_blocks=0, st_size=0, "
    "st_atime=1, st_atime_nsec=2, st_mtime=1, st_mtime_nsec=2, "
    "st_ctime=1, st_ctime_nsec=2}"
)


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("fstat", f"3<pipe:[301]>, {_PIPE_STAT}"),
        (
            "newfstatat",
            f'3<pipe:[301]>, "", {_PIPE_STAT}, AT_EMPTY_PATH',
        ),
    ],
)
def test_broker_pipe_stat_preserves_only_alias_bound_validation(name, arguments):
    record = normalize_bytes(_line(f"{name}({arguments})"))[0]

    assert record["validation"] == {
        "operation": "fd_stat",
        "fd": {"fd": 3, "provenance": {"kind": "pipe", "inode": 301}},
        "file_type": "fifo",
        "mode": 0o600,
        "inode": 301,
    }
    rendered = canonical_ndjson([record])
    assert "st_uid" not in rendered
    assert "st_atime" not in rendered


def test_broker_pipe_readlink_preserves_no_arbitrary_path_or_target_text():
    record = normalize_bytes(
        _line(
            'readlink("/proc/self/fd/3", "pipe:[301]", 4096)',
            "10",
        )
    )[0]

    assert record["validation"] == {
        "operation": "fd_readlink",
        "fd": 3,
        "target_provenance": {"kind": "pipe", "inode": 301},
        "count": 4096,
    }
    rendered = canonical_ndjson([record])
    assert "/proc/self/fd" not in rendered


@pytest.mark.parametrize(
    "call",
    [
        f"fstat(3<pipe:[302]>, {_PIPE_STAT})",
        f"fstat(3<pipe:[301]>, {_PIPE_STAT.replace('S_IFIFO|0600', 'S_IFREG|0600')})",
        f"fstat(3<pipe:[301]>, {_PIPE_STAT.replace('S_IFIFO|0600', 'S_IFIFO|0666')})",
        f'newfstatat(3<pipe:[301]>, "other", {_PIPE_STAT}, AT_EMPTY_PATH)',
        f'newfstatat(3<pipe:[301]>, "", {_PIPE_STAT}, 0)',
        'readlink("/tmp/other", "pipe:[301]", 4096)',
        'readlink("/proc/self/fd/3", "/tmp/other", 4096)',
        'readlink("/proc/self/fd/3", "pipe:[301]", 1024)',
    ],
)
def test_broker_validation_metadata_rejects_unreviewed_shape(call):
    result = "10" if call.startswith("readlink") else "0"
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(call, result))


@pytest.mark.parametrize(
    ("direction", "arguments", "annotation"),
    [
        (
            "write",
            "4, NULL, [3<pipe:[301]>], NULL, {tv_sec=0, tv_nsec=974051000}, NULL",
            "1 (out [3], left {tv_sec=0, tv_nsec=974049637})",
        ),
        (
            "read",
            "4, [3<pipe:[302]>], NULL, NULL, {tv_sec=0, tv_nsec=998087000}, NULL",
            "1 (in [3], left {tv_sec=0, tv_nsec=998085776})",
        ),
    ],
)
def test_broker_pselect6_retains_only_bound_fd_direction_and_timeout_shape(
    direction, arguments, annotation
):
    record = normalize_bytes(_line(f"pselect6({arguments})", annotation))[0]

    assert record["wait"] == {
        "nfds": 4,
        "direction": direction,
        "fd": {
            "fd": 3,
            "provenance": {
                "kind": "pipe",
                "inode": 301 if direction == "write" else 302,
            },
        },
        "timeout": {
            "seconds": 0,
            "nanoseconds": 974051000 if direction == "write" else 998087000,
        },
    }
    assert record["result"] == {
        "value": 1,
        "ready": {"direction": direction, "fd": {"fd": 3}},
        "timeout_left": {
            "seconds": 0,
            "nanoseconds": 974049637 if direction == "write" else 998085776,
        },
    }


@pytest.mark.parametrize(
    ("arguments", "direction"),
    [
        (
            "4, [], [3<pipe:[301]>], [], {tv_sec=0, tv_nsec=974051000}, NULL",
            "write",
        ),
        (
            "4, [3<pipe:[302]>], [], [], {tv_sec=0, tv_nsec=998087000}, NULL",
            "read",
        ),
    ],
)
def test_broker_pselect6_accepts_python310_empty_fd_set_rendering(arguments, direction):
    ready = "out" if direction == "write" else "in"
    record = normalize_bytes(
        _line(
            f"pselect6({arguments})",
            f"1 ({ready} [3], left {{tv_sec=0, tv_nsec=1}})",
        )
    )[0]

    assert record["wait"]["direction"] == direction
    assert record["wait"]["fd"]["fd"] == 3


@pytest.mark.parametrize(
    "arguments",
    [
        "4, [3<pipe:[301]>], [], [4], {tv_sec=0, tv_nsec=1}, NULL",
        "4, [3<pipe:[301]>], [4<pipe:[302]>], [], {tv_sec=0, tv_nsec=1}, NULL",
        "4, [3<pipe:[301]>], [malformed], [], {tv_sec=0, tv_nsec=1}, NULL",
    ],
)
def test_broker_pselect6_rejects_nonempty_except_or_malformed_empty_sets(arguments):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            _line(
                f"pselect6({arguments})",
                "1 (in [3], left {tv_sec=0, tv_nsec=0})",
            )
        )


def test_broker_pselect6_timeout_is_closed_and_payload_free():
    record = normalize_bytes(
        _line(
            "pselect6(4, [3<pipe:[303]>], NULL, NULL, {tv_sec=0, tv_nsec=1}, NULL)",
            "0 (Timeout)",
        )
    )[0]

    assert record["result"] == {"value": 0, "timeout": True}
    assert record["wait"]["direction"] == "read"


@pytest.mark.parametrize(
    ("arguments", "result"),
    [
        (
            "4, [3<pipe:[303]>], NULL, NULL, {tv_sec=0, tv_nsec=1}, NULL",
            "2 (in [3], left {tv_sec=0, tv_nsec=0})",
        ),
        (
            "4, [3<pipe:[303]>], NULL, NULL, {tv_sec=0, tv_nsec=1}, NULL",
            "1 (out [3], left {tv_sec=0, tv_nsec=0})",
        ),
        (
            "4, [3<pipe:[303]>], [4<pipe:[304]>], NULL, {tv_sec=0, tv_nsec=1}, NULL",
            "1 (in [3], left {tv_sec=0, tv_nsec=0})",
        ),
        (
            "4, [3<pipe:[303]>], NULL, NULL, {tv_sec=0, tv_nsec=1000000000}, NULL",
            "1 (in [3], left {tv_sec=0, tv_nsec=0})",
        ),
        (
            "4, [3<pipe:[303]>], NULL, NULL, {tv_sec=0, tv_nsec=1}, NULL",
            "1 (in [3], unknown {tv_sec=0, tv_nsec=0})",
        ),
    ],
)
def test_broker_pselect6_rejects_unknown_or_inconsistent_shapes(arguments, result):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(f"pselect6({arguments})", result))


def test_packet_zero_halen_omits_address_and_accepts_numeric_or_named_ifindex():
    source = _line(
        "connect(-1, {sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), "
        "sll_ifindex=4207869677, sll_hatype=ARPHRD_ETHER, "
        "sll_pkttype=PACKET_HOST, sll_halen=0}, 20)",
        "-1 EBADF (Bad file descriptor)",
    ) + _line(
        "connect(-1, {sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), "
        'sll_ifindex=if_nametoindex("INTERFACE_PAYLOAD_SECRET"), '
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=0}, 20)",
        "-1 EBADF (Bad file descriptor)",
        timestamp="1700000053.000002",
    )
    records = normalize_bytes(source)
    assert records[0]["transition"]["address"] == {
        "family": "AF_PACKET",
        "protocol": "ETH_P_ALL",
        "ifindex": {"kind": "numeric", "value": 4207869677},
    }
    assert records[1]["transition"]["address"] == {
        "family": "AF_PACKET",
        "protocol": "ETH_P_ALL",
        "ifindex": {"kind": "name"},
    }
    assert "INTERFACE_PAYLOAD_SECRET" not in canonical_ndjson(records)


@pytest.mark.parametrize(
    "address",
    [
        "{sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), sll_ifindex=1, "
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=1}",
        "{sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), sll_ifindex=1, "
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=0, "
        "sll_addr=[]}",
        "{sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), sll_ifindex=-1, "
        "sll_hatype=ARPHRD_ETHER, sll_pkttype=PACKET_HOST, sll_halen=0}",
        "{sa_family=AF_PACKET, sll_protocol=htons(ETH_P_ALL), "
        'sll_ifindex=if_nametoindex("bad")|1, sll_hatype=ARPHRD_ETHER, '
        "sll_pkttype=PACKET_HOST, sll_halen=0}",
    ],
)
def test_packet_zero_halen_keeps_full_structural_validation(address):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(
            _line(
                f"connect(-1, {address}, 20)",
                "-1 EBADF (Bad file descriptor)",
            )
        )


def test_structurally_translated_socket_options_retain_identity_and_redact_values():
    source = (
        _line("getsockopt(6<TCP:[127.0.0.1:7400]>, SOL_TCP, TCP_MAXSEG, [536], [4])")
        + _line(
            "getsockopt(7<UNIX-STREAM:[707]>, SOL_SOCKET, SO_ACCEPTCONN, [1], [4])",
            timestamp="1700000053.000002",
        )
        + _line(
            "setsockopt(7<UNIX-STREAM:[707]>, SOL_SOCKET, SO_PASSCRED, "
            '"SOCKET_OPTION_PAYLOAD_SECRET", 4)',
            timestamp="1700000053.000003",
        )
        + _line(
            "setsockopt(8<PACKET:[808]>, SOL_XDP, XDP_UMEM_REG, "
            '"SOCKET_OPTION_PAYLOAD_SECRET", 16)',
            timestamp="1700000053.000004",
        )
    )
    records = normalize_bytes(source)
    assert [record["transition"]["option"] for record in records] == [
        "TCP_MAXSEG",
        "SO_ACCEPTCONN",
        "SO_PASSCRED",
        "XDP_UMEM_REG",
    ]
    assert records[0]["transition"]["fd"]["provenance"]["protocol"] == "TCP"
    assert records[3]["transition"]["level"] == "SOL_XDP"
    assert records[3]["transition"]["length"] == 16
    assert "SOCKET_OPTION_PAYLOAD_SECRET" not in canonical_ndjson(records)


@pytest.mark.parametrize(
    ("level", "option"),
    [
        ("SOL_tcp", "TCP_MAXSEG"),
        ("SOL_", "TCP_MAXSEG"),
        ("IPPROTO_TCP", "TCP_MAXSEG"),
        ("SOL_TCP|SOL_UDP", "TCP_MAXSEG"),
        ("SOL_TCP", "tcp_MAXSEG"),
        ("SOL_TCP", "TCP-MAXSEG"),
        ("SOL_TCP", "TCP__MAXSEG"),
        ("SOL_TCP", "42"),
    ],
)
def test_socket_option_tokens_reject_nontranslated_or_malformed_grammar(level, option):
    with pytest.raises(TraceDecodeError):
        normalize_bytes(_line(f"setsockopt(6<TCP:[606]>, {level}, {option}, [1], 4)"))


def test_pinned_test_manifest_includes_revision5_suite():
    paths = TEST_MANIFEST.read_text(encoding="utf-8").splitlines()
    assert "scripts/holoagent0_setup/tests/test_trace_normalizer_revision5.py" in paths
    assert len(paths) == len(set(paths))


def test_record_sink_mutation_cannot_change_returned_nested_evidence():
    sink_records = []

    def mutating_sink(record):
        sink_records.append(record)
        record["result"]["value"] = 999
        record["transition"]["created_fd"]["provenance"]["protocol"] = "MUTATED"
        record["sink_only"] = {"nested": ["mutation"]}

    normalizer = TraceNormalizer(record_sink=mutating_sink)
    records = normalizer.feed(
        _line("socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP)", "7<UDP:[7]>")
    )
    records.extend(normalizer.finish())

    assert len(sink_records) == 1
    assert records[0]["result"]["value"] == 7
    assert records[0]["transition"]["created_fd"]["provenance"]["protocol"] == "UDP"
    assert "sink_only" not in records[0]
