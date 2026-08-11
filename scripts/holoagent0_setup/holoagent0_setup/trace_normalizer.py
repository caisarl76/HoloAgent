"""Bounded, payload-free normalization for the reviewed strace 6.6 stream."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import errno as errno_module
import ipaddress
import json
import os
import re
from typing import Callable, Iterable


RAW_PAYLOAD_SYSCALL_ORDER = (
    "read",
    "readv",
    "pread64",
    "preadv",
    "preadv2",
    "write",
    "writev",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "sendfile",
    "splice",
    "vmsplice",
    "tee",
    "copy_file_range",
)
STRACE_ARGUMENT_TEMPLATE = (
    "--kill-on-exit",
    "-f",
    "-yy",
    "-ttt",
    "-T",
    "--no-abbrev",
    "--string-limit=1048576",
    "--quiet=none",
    "--trace=all",
    f"--raw={','.join(RAW_PAYLOAD_SYSCALL_ORDER)}",
    "--output=/proc/self/fd/{output_fd}",
)
# Compatibility name for consumers that inspect the reviewed template.
STRACE_ARGUMENTS = STRACE_ARGUMENT_TEMPLATE
STRACE_ENVIRONMENT = {"LC_ALL": "C", "TZ": "UTC"}
RAW_PAYLOAD_SYSCALLS = frozenset(RAW_PAYLOAD_SYSCALL_ORDER)
DECODED_ADDRESS_SYSCALLS = frozenset(
    {"sendto", "recvfrom", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg"}
)

_PREFIX = re.compile(r"^([1-9][0-9]*)( +)([0-9]+(?:\.[0-9]+)?) (.+)$")
_CALL = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)\)( +)= (.+) <([0-9]+(?:\.[0-9]+)?)>$"
)
_RESULT_TAIL = re.compile(r"^(.*\))( +)= (.+) <([0-9]+(?:\.[0-9]+)?)>$")
_UNFINISHED = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\((.*)<unfinished \.\.\.>$")
_RESUMED = re.compile(r"^<\.\.\. ([A-Za-z_][A-Za-z0-9_]*) resumed>(.*)$")
_SIGNAL = re.compile(r"^--- (SIG[A-Z0-9]+) \{.*\} ---$")
_EXITED = re.compile(r"^\+\+\+ exited with ([0-9]+) \+\+\+$")
_KILLED = re.compile(r"^\+\+\+ killed by (SIG[A-Z0-9]+)(?: \(core dumped\))? \+\+\+$")
_NUMBER_TEXT = r"(?:0|[1-9][0-9]*|0x[0-9a-f]+)"
_FD = re.compile(r"^(-?(?:0|[1-9][0-9]*))(?:<(.+)>)?$")
_INTEGER = re.compile(rf"^-?{_NUMBER_TEXT}$")
_RAW_INTEGER = re.compile(r"^(?:0|0x[0-9a-f]+)$")
_ERRNO = re.compile(r"^(-1) ([A-Z][A-Z0-9_]*) \(([^\r\n()]*)\)$")
_FLAGGED_RESULT = re.compile(
    rf"^({_NUMBER_TEXT}) \(flags ([A-Z][A-Z0-9_]*(?:\|[A-Z][A-Z0-9_]*)*)\)$"
)

_SOCKET_DOMAINS = frozenset(
    {
        "AF_ALG",
        "AF_APPLETALK",
        "AF_ASH",
        "AF_ATMPVC",
        "AF_ATMSVC",
        "AF_AX25",
        "AF_BLUETOOTH",
        "AF_BRIDGE",
        "AF_CAIF",
        "AF_CAN",
        "AF_DECnet",
        "AF_ECONET",
        "AF_IEEE802154",
        "AF_INET",
        "AF_INET6",
        "AF_IPX",
        "AF_IRDA",
        "AF_ISDN",
        "AF_IUCV",
        "AF_KCM",
        "AF_KEY",
        "AF_LLC",
        "AF_MCTP",
        "AF_MPLS",
        "AF_NETBEUI",
        "AF_NETLINK",
        "AF_NETROM",
        "AF_NFC",
        "AF_PACKET",
        "AF_PHONET",
        "AF_PPPOX",
        "AF_QIPCRTR",
        "AF_RDS",
        "AF_ROSE",
        "AF_RXRPC",
        "AF_SECURITY",
        "AF_SMC",
        "AF_SNA",
        "AF_TIPC",
        "AF_UNIX",
        "AF_UNSPEC",
        "AF_VSOCK",
        "AF_WANPIPE",
        "AF_X25",
        "AF_XDP",
    }
)
_SOCKET_BASE_TYPES = frozenset(
    {
        "SOCK_DCCP",
        "SOCK_DGRAM",
        "SOCK_PACKET",
        "SOCK_RAW",
        "SOCK_RDM",
        "SOCK_SEQPACKET",
        "SOCK_STREAM",
    }
)
_SOCKET_TYPE_FLAGS = frozenset({"SOCK_CLOEXEC", "SOCK_NONBLOCK"})
_INET_SOCKET_PROTOCOLS = frozenset(
    {
        "IPPROTO_AH",
        "IPPROTO_BEETPH",
        "IPPROTO_COMP",
        "IPPROTO_DCCP",
        "IPPROTO_DSTOPTS",
        "IPPROTO_EGP",
        "IPPROTO_ENCAP",
        "IPPROTO_ESP",
        "IPPROTO_ETHERNET",
        "IPPROTO_FRAGMENT",
        "IPPROTO_GRE",
        "IPPROTO_ICMP",
        "IPPROTO_ICMPV6",
        "IPPROTO_IDP",
        "IPPROTO_IGMP",
        "IPPROTO_IP",
        "IPPROTO_IPIP",
        "IPPROTO_IPV6",
        "IPPROTO_L2TP",
        "IPPROTO_MH",
        "IPPROTO_MPLS",
        "IPPROTO_MPTCP",
        "IPPROTO_MTP",
        "IPPROTO_NONE",
        "IPPROTO_PIM",
        "IPPROTO_PUP",
        "IPPROTO_RAW",
        "IPPROTO_ROUTING",
        "IPPROTO_RSVP",
        "IPPROTO_SCTP",
        "IPPROTO_TCP",
        "IPPROTO_TP",
        "IPPROTO_UDP",
        "IPPROTO_UDPLITE",
    }
)
_NETLINK_SOCKET_PROTOCOLS = frozenset(
    {
        "NETLINK_AUDIT",
        "NETLINK_CONNECTOR",
        "NETLINK_CRYPTO",
        "NETLINK_DNRTMSG",
        "NETLINK_ECRYPTFS",
        "NETLINK_FIB_LOOKUP",
        "NETLINK_FIREWALL",
        "NETLINK_GENERIC",
        "NETLINK_IP6_FW",
        "NETLINK_ISCSI",
        "NETLINK_KOBJECT_UEVENT",
        "NETLINK_NETFILTER",
        "NETLINK_NFLOG",
        "NETLINK_RDMA",
        "NETLINK_ROUTE",
        "NETLINK_SCSITRANSPORT",
        "NETLINK_SELINUX",
        "NETLINK_SMC",
        "NETLINK_SOCK_DIAG",
        "NETLINK_UNUSED",
        "NETLINK_USERSOCK",
        "NETLINK_XFRM",
    }
)
_FAMILY_SOCKET_PROTOCOLS = {
    "AF_BLUETOOTH": frozenset(
        {
            "BTPROTO_AVDTP",
            "BTPROTO_BNEP",
            "BTPROTO_CMTP",
            "BTPROTO_HCI",
            "BTPROTO_HIDP",
            "BTPROTO_L2CAP",
            "BTPROTO_RFCOMM",
            "BTPROTO_SCO",
        }
    ),
    "AF_CAN": frozenset(
        {
            "CAN_BCM",
            "CAN_ISOTP",
            "CAN_J1939",
            "CAN_MCNET",
            "CAN_RAW",
            "CAN_TP16",
            "CAN_TP20",
        }
    ),
    "AF_CAIF": frozenset(
        {
            "CAIFPROTO_AT",
            "CAIFPROTO_DATAGRAM",
            "CAIFPROTO_DATAGRAM_LOOP",
            "CAIFPROTO_DEBUG",
            "CAIFPROTO_RFM",
            "CAIFPROTO_UTIL",
        }
    ),
    "AF_IRDA": frozenset({"IRDAPROTO_ULTRA", "IRDAPROTO_UNITDATA"}),
    "AF_ISDN": frozenset(
        {
            "ISDN_P_BASE",
            "ISDN_P_B_HDLC",
            "ISDN_P_B_L2DSP",
            "ISDN_P_B_L2DSPHDLC",
            "ISDN_P_B_L2DTMF",
            "ISDN_P_B_RAW",
            "ISDN_P_B_X75SLP",
            "ISDN_P_LAPD_NT",
            "ISDN_P_LAPD_TE",
            "ISDN_P_NT_E1",
            "ISDN_P_NT_S0",
            "ISDN_P_TE_E1",
            "ISDN_P_TE_S0",
        }
    ),
    "AF_KCM": frozenset({"KCMPROTO_CONNECTED"}),
    "AF_NFC": frozenset({"NFC_SOCKPROTO_LLCP", "NFC_SOCKPROTO_RAW"}),
    "AF_PHONET": frozenset({"PN_PROTO_PHONET", "PN_PROTO_PIPE", "PN_PROTO_TRANSPORT"}),
    "AF_SMC": frozenset({"SMCPROTO_SMC", "SMCPROTO_SMC6"}),
}
_PACKET_PROTOCOLS = frozenset(
    {
        "ETH_P_8021Q",
        "ETH_P_ALL",
        "ETH_P_ARP",
        "ETH_P_IP",
        "ETH_P_IPV6",
        "ETH_P_LLDP",
        "ETH_P_LOOPBACK",
        "ETH_P_MPLS_MC",
        "ETH_P_MPLS_UC",
        "ETH_P_RARP",
    }
)
_INET_PROVENANCE_V4 = frozenset(
    {"DCCP", "L2TP/IP", "PING", "RAW", "SCTP", "TCP", "UDP", "UDPLITE"}
)
_INET_PROVENANCE_V6 = frozenset(
    {
        "DCCPv6",
        "L2TP/IPv6",
        "PINGv6",
        "RAWv6",
        "SCTPv6",
        "TCPv6",
        "UDPv6",
        "UDPLITEv6",
    }
)
_SOCKET_PROVENANCE_PROTOCOLS = (
    _INET_PROVENANCE_V4
    | _INET_PROVENANCE_V6
    | frozenset({"NETLINK", "PACKET", "UNIX", "UNIX-STREAM"})
)
_RESTART_TEXT = {
    "ERESTARTSYS": "To be restarted if SA_RESTART is set",
    "ERESTARTNOINTR": "To be restarted",
    "ERESTARTNOHAND": "To be restarted if no handler",
    "ERESTART_RESTARTBLOCK": "Interrupted by signal",
}
_SOCKET_OPTION_LEVEL = re.compile(r"SOL_[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*")
_SOCKET_OPTION_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_FCNTL_STATUS_FLAGS = frozenset(
    {
        "O_APPEND",
        "O_ASYNC",
        "O_DIRECT",
        "O_DSYNC",
        "O_LARGEFILE",
        "O_NOATIME",
        "O_NONBLOCK",
        "O_PATH",
        "O_RDONLY",
        "O_RDWR",
        "O_SYNC",
        "O_TMPFILE",
        "O_WRONLY",
    }
)


class TraceDecodeError(ValueError):
    """The stream is outside the single reviewed strace serialization."""


@dataclass(frozen=True)
class _Pending:
    syscall: str
    arguments_prefix: str
    timestamp: str
    entry_index: int


def strace_arguments_for_output_fd(output_fd: int) -> tuple[str, ...]:
    """Materialize the sole reviewed strace output path from a numeric FD."""

    if not isinstance(output_fd, int) or isinstance(output_fd, bool):
        raise TypeError("strace output FD must be an integer")
    if output_fd < 3 or output_fd > 2_147_483_647:
        raise ValueError("strace output FD is outside the reviewed numeric range")
    return (
        *STRACE_ARGUMENT_TEMPLATE[:-1],
        STRACE_ARGUMENT_TEMPLATE[-1].format(output_fd=output_fd),
    )


def _fail(code: str) -> TraceDecodeError:
    # Error text deliberately excludes source text, which may contain payload bytes.
    return TraceDecodeError(f"strace decode rejected: {code}")


def _split_arguments(value: str) -> list[str]:
    if not value:
        return []
    result: list[str] = []
    start = 0
    stack: list[str] = []
    quote = False
    escaped = False
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index, character in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quote = False
            continue
        if character == '"':
            quote = True
        elif character in pairs:
            stack.append(pairs[character])
        elif character in ")]}":
            if not stack or stack.pop() != character:
                raise _fail("unbalanced-arguments")
        elif character == "," and not stack:
            result.append(value[start:index].strip())
            start = index + 1
    if quote or escaped or stack:
        raise _fail("unbalanced-arguments")
    result.append(value[start:].strip())
    if any(not item for item in result):
        raise _fail("empty-argument")
    return result


def _integer(value: str, code: str) -> int:
    if not _INTEGER.fullmatch(value):
        raise _fail(code)
    try:
        return int(value, 0)
    except ValueError as error:  # pragma: no cover - guarded by the expression
        raise _fail(code) from error


def _raw_integer(value: str, code: str) -> int:
    if _RAW_INTEGER.fullmatch(value) is None:
        raise _fail(code)
    return int(value, 0)


def _provenance(value: str) -> dict[str, object]:
    inode = re.fullmatch(r"(socket|pipe):\[([0-9]+)\]", value)
    if inode is not None:
        return {"kind": inode.group(1), "inode": int(inode.group(2))}
    anon = re.fullmatch(r"anon_inode:\[([A-Za-z0-9_-]+)\]", value)
    if anon is not None:
        return {"kind": "anon_inode", "type": anon.group(1)}
    annotated_socket = re.fullmatch(r"([A-Za-z0-9/-]+):\[(.*)\]", value)
    if annotated_socket is not None:
        protocol, annotation = annotated_socket.groups()
        if protocol not in _SOCKET_PROVENANCE_PROTOCOLS:
            raise _fail("unsupported-fd-provenance")
        if protocol in _INET_PROVENANCE_V4:
            endpoint = r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]+"
            if not (
                re.fullmatch(r"[0-9]+", annotation)
                or re.fullmatch(rf"{endpoint}(?:->{endpoint})?", annotation)
            ):
                raise _fail("unsupported-fd-provenance")
            for address, port in re.findall(
                r"((?:[0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]+)", annotation
            ):
                try:
                    ipaddress.IPv4Address(address)
                except ipaddress.AddressValueError as error:
                    raise _fail("unsupported-fd-provenance") from error
                if int(port) > 65535:
                    raise _fail("unsupported-fd-provenance")
        elif protocol in _INET_PROVENANCE_V6:
            endpoint = r"\[([0-9A-Fa-f:.]+)\]:([0-9]+)"
            if re.fullmatch(r"[0-9]+", annotation):
                pass
            else:
                endpoints = re.fullmatch(rf"{endpoint}(?:->{endpoint})?", annotation)
                if endpoints is None:
                    raise _fail("unsupported-fd-provenance")
                values = endpoints.groups()
                for index in range(0, len(values), 2):
                    if values[index] is None:
                        continue
                    try:
                        ipaddress.IPv6Address(values[index])
                    except ipaddress.AddressValueError as error:
                        raise _fail("unsupported-fd-provenance") from error
                    if int(values[index + 1]) > 65535:
                        raise _fail("unsupported-fd-provenance")
        elif protocol in {"UNIX", "UNIX-STREAM"}:
            unix_name = r'@?"(?:[^"\\]|\\.)*"'
            if (
                re.fullmatch(r"[0-9]+", annotation) is None
                and re.fullmatch(rf"[0-9]+(?:->[0-9]+)?(?:,{unix_name})?", annotation)
                is None
            ):
                raise _fail("unsupported-fd-provenance")
        elif (
            protocol == "NETLINK"
            and re.fullmatch(r"(?:[0-9]+|[A-Z][A-Z0-9_]*:[0-9]+)", annotation) is None
        ):
            raise _fail("unsupported-fd-provenance")
        elif protocol == "PACKET" and re.fullmatch(r"[0-9]+", annotation) is None:
            raise _fail("unsupported-fd-provenance")
        return {"kind": "socket", "protocol": protocol}
    if value.startswith("/"):
        return {"kind": "path"}
    raise _fail("unsupported-fd-provenance")


def _fd(value: str, code: str) -> dict[str, object]:
    match = _FD.fullmatch(value)
    if match is None:
        raise _fail(code)
    record: dict[str, object] = {"fd": int(match.group(1), 0)}
    provenance = match.group(2)
    if provenance is not None:
        if record["fd"] < 0:
            raise _fail(code)
        if len(provenance) > 4096 or any(ord(char) < 32 for char in provenance):
            raise _fail("invalid-fd-provenance")
        record["provenance"] = _provenance(provenance)
    return record


def _result(value: str) -> dict[str, object]:
    restart = re.fullmatch(r"\? (ERESTART[A-Z_]*) \(([^\r\n()]*)\)", value)
    if restart is not None:
        name, text = restart.groups()
        if _RESTART_TEXT.get(name) != text:
            raise _fail("unsupported-restart-result")
        return {"interrupted": True, "restart": name}
    errno = _ERRNO.fullmatch(value)
    if errno is not None:
        errno_number = next(
            (
                number
                for number, name in errno_module.errorcode.items()
                if name == errno.group(2)
            ),
            None,
        )
        if errno_number is None or os.strerror(errno_number) != errno.group(3):
            raise _fail("noncanonical-errno")
        return {
            "value": -1,
            "errno": errno.group(2),
            "errno_text": errno.group(3),
        }
    descriptor = _FD.fullmatch(value)
    if descriptor is not None:
        fd = _fd(value, "invalid-return-fd")
        result: dict[str, object] = {"value": fd["fd"]}
        if descriptor.group(2) is not None:
            result["fd"] = fd
        return result
    if not _INTEGER.fullmatch(value):
        raise _fail("unsupported-return")
    return {"value": int(value, 0)}


def _raw_result(value: str) -> dict[str, object]:
    if _ERRNO.fullmatch(value) is not None or value.startswith("? ERESTART"):
        return _result(value)
    return {"value": _raw_integer(value, "invalid-raw-return")}


def _successful(result: dict[str, object]) -> bool:
    value = result.get("value")
    return isinstance(value, int) and value >= 0


def _flags(value: str) -> list[str]:
    if value in {"0", "NULL"}:
        return []
    flags = value.split("|")
    if not all(re.fullmatch(r"[A-Z][A-Z0-9_]*", flag) for flag in flags):
        raise _fail("invalid-flags")
    return flags


def _closed_flags(value: str, allowed: frozenset[str], code: str) -> list[str]:
    flags = _flags(value)
    if len(flags) != len(set(flags)) or any(flag not in allowed for flag in flags):
        raise _fail(code)
    return flags


def _socket_domain(value: str) -> str:
    if value not in _SOCKET_DOMAINS:
        raise _fail("unsupported-socket-domain")
    return value


def _socket_type(value: str) -> list[str]:
    values = value.split("|")
    if (
        not values
        or values[0] not in _SOCKET_BASE_TYPES
        or len(values) != len(set(values))
        or any(item not in _SOCKET_TYPE_FLAGS for item in values[1:])
    ):
        raise _fail("unsupported-socket-type")
    return values


def _socket_protocol(value: str, domain: str) -> int | str:
    if value == "0":
        return 0
    if domain in {"AF_INET", "AF_INET6"}:
        allowed = _INET_SOCKET_PROTOCOLS
    elif domain == "AF_NETLINK":
        allowed = _NETLINK_SOCKET_PROTOCOLS
    elif domain == "AF_PACKET":
        packet = re.fullmatch(r"htons\((ETH_P_[A-Z0-9_]+)\)", value)
        if packet is None or packet.group(1) not in _PACKET_PROTOCOLS:
            raise _fail("unsupported-packet-socket-protocol")
        return packet.group(1)
    else:
        allowed = _FAMILY_SOCKET_PROTOCOLS.get(domain, frozenset())
    if value not in allowed:
        raise _fail("unsupported-socket-protocol")
    return value


def _socket_parameters(arguments: list[str]) -> dict[str, object]:
    domain = _socket_domain(arguments[0])
    protocol = _socket_protocol(arguments[2], domain)
    if domain == "AF_UNIX" and protocol != 0:
        raise _fail("unsupported-unix-socket-protocol")
    if domain == "AF_NETLINK" and protocol not in _NETLINK_SOCKET_PROTOCOLS:
        raise _fail("unsupported-netlink-socket-protocol")
    if domain in {"AF_INET", "AF_INET6"} and isinstance(protocol, str):
        if protocol not in _INET_SOCKET_PROTOCOLS:
            raise _fail("unsupported-inet-socket-protocol")
    return {
        "domain": domain,
        "socket_type": _socket_type(arguments[1]),
        "protocol": protocol,
    }


def _fcntl_status_flags(value: str, code: str) -> list[str]:
    return _closed_flags(value, _FCNTL_STATUS_FLAGS, code)


def _fcntl_result(command: str, value: str) -> dict[str, object]:
    if _ERRNO.fullmatch(value) is not None:
        return _result(value)
    flagged = _FLAGGED_RESULT.fullmatch(value)
    if flagged is None:
        return _result(value)
    numeric = int(flagged.group(1), 0)
    flags = flagged.group(2).split("|")
    if command == "F_GETFD":
        if numeric != 1 or flags != ["FD_CLOEXEC"]:
            raise _fail("invalid-fcntl-getfd-result")
    elif command == "F_GETFL":
        _fcntl_status_flags(flagged.group(2), "invalid-fcntl-getfl-result")
    else:
        raise _fail("unexpected-fcntl-flagged-result")
    return {"value": numeric, "flags": flags}


def _fields(value: str, code: str) -> dict[str, str]:
    if not (value.startswith("{") and value.endswith("}")):
        raise _fail(code)
    inner = value[1:-1]
    result: dict[str, str] = {}
    for item in _split_arguments(inner):
        key, separator, field_value = item.partition("=")
        if (
            separator != "="
            or re.fullmatch(r"[a-z][a-z0-9_]*", key) is None
            or key in result
            or not field_value
        ):
            raise _fail(code)
        result[key] = field_value
    return result


def _vector(value: str, code: str) -> list[str]:
    if not (value.startswith("[") and value.endswith("]")):
        raise _fail(code)
    inner = value[1:-1]
    return [] if not inner else _split_arguments(inner)


def _output_pointer(value: str, code: str) -> None:
    if value != "NULL" and re.fullmatch(r"0x[0-9a-f]+", value) is None:
        raise _fail(code)


def _output_length(value: str, code: str) -> int | None:
    if value == "NULL" or re.fullmatch(r"0x[0-9a-f]+", value) is not None:
        return None
    length = re.fullmatch(r"\[([0-9]+)(?: => ([0-9]+))?\]", value)
    if length is None:
        raise _fail(code)
    return int(length.group(2) or length.group(1))


def _ipv4_inet_addr(value: str, code: str) -> str:
    match = re.fullmatch(r'inet_addr\("([^"\\]+)"\)', value)
    if match is None:
        raise _fail(code)
    try:
        return str(ipaddress.IPv4Address(match.group(1)))
    except ipaddress.AddressValueError as error:
        raise _fail(code) from error


def _ip_membership(value: str) -> dict[str, str]:
    fields = _fields(value, "ip-membership-grammar")
    if set(fields) != {"imr_multiaddr", "imr_interface"}:
        raise _fail("ip-membership-fields")
    return {
        "group": _ipv4_inet_addr(fields["imr_multiaddr"], "ip-membership-group"),
        "interface": _ipv4_inet_addr(
            fields["imr_interface"], "ip-membership-interface"
        ),
    }


def _ip_multicast_setup_value(option: str, value: str) -> str | int:
    if option == "IP_MULTICAST_IF":
        return _ipv4_inet_addr(value, "ip-multicast-interface")
    values = _vector(value, "ip-multicast-option-value")
    if len(values) != 1:
        raise _fail("ip-multicast-option-value")
    parsed = _integer(values[0], "ip-multicast-option-value")
    if not 0 <= parsed <= 255:
        raise _fail("ip-multicast-option-value")
    return parsed


def _address(value: str) -> dict[str, object] | None:
    if value == "NULL":
        return None
    if value.startswith("{sa_family=AF_INET6,"):
        match = re.fullmatch(
            r"\{sa_family=AF_INET6, sin6_port=htons\(([0-9]+)\), "
            r"sin6_flowinfo=htonl\(([0-9]+)\), inet_pton\(AF_INET6, "
            r'"([^"\\]+)", &sin6_addr\), sin6_scope_id=([0-9]+)\}',
            value,
        )
        if match is None:
            raise _fail("sockaddr-inet6-grammar")
        port_value = int(match.group(1))
        flowinfo = int(match.group(2))
        scope_id = int(match.group(4))
        if port_value > 65535 or flowinfo > 0xFFFFFFFF or scope_id > 0xFFFFFFFF:
            raise _fail("sockaddr-inet6-range")
        try:
            ip = str(ipaddress.IPv6Address(match.group(3)))
        except ipaddress.AddressValueError as error:
            raise _fail("sockaddr-inet6-address") from error
        return {
            "family": "AF_INET6",
            "port": port_value,
            "flowinfo": flowinfo,
            "ip": ip,
            "scope_id": scope_id,
        }
    fields = _fields(value, "sockaddr-grammar")
    family = fields.get("sa_family")
    if family not in {"AF_INET", "AF_NETLINK", "AF_PACKET", "AF_UNIX"}:
        raise _fail("unsupported-socket-family")
    result: dict[str, object] = {"family": family}
    if family == "AF_INET":
        if set(fields) != {"sa_family", "sin_port", "sin_addr"}:
            raise _fail("sockaddr-inet-fields")
        port = re.fullmatch(r"htons\(([0-9]+)\)", fields["sin_port"])
        address = re.fullmatch(r'inet_addr\("([^"\\]+)"\)', fields["sin_addr"])
        if port is None or address is None:
            raise _fail("sockaddr-inet-values")
        try:
            ip = str(ipaddress.IPv4Address(address.group(1)))
        except ipaddress.AddressValueError as error:
            raise _fail("sockaddr-inet-address") from error
    elif family == "AF_NETLINK":
        if set(fields) != {"sa_family", "nl_pid", "nl_groups"}:
            raise _fail("sockaddr-netlink-fields")
        pid = _integer(fields["nl_pid"], "sockaddr-netlink-pid")
        if (
            pid < 0
            or pid > 0xFFFFFFFF
            or re.fullmatch(r"[0-9a-f]{8}", fields["nl_groups"]) is None
        ):
            raise _fail("sockaddr-netlink-values")
        return {
            "family": family,
            "pid": pid,
            "groups": int(fields["nl_groups"], 16),
        }
    elif family == "AF_PACKET":
        base_fields = {
            "sa_family",
            "sll_protocol",
            "sll_ifindex",
            "sll_hatype",
            "sll_pkttype",
            "sll_halen",
        }
        if frozenset(fields) not in {
            frozenset(base_fields),
            frozenset(base_fields | {"sll_addr"}),
        }:
            raise _fail("sockaddr-packet-fields")
        protocol = re.fullmatch(r"htons\((ETH_P_[A-Z0-9_]+)\)", fields["sll_protocol"])
        if protocol is None or protocol.group(1) not in _PACKET_PROTOCOLS:
            raise _fail("sockaddr-packet-protocol")
        numeric_ifindex = re.fullmatch(r"[0-9]+", fields["sll_ifindex"])
        named_ifindex = re.fullmatch(
            r'if_nametoindex\("(?:[^"\\]|\\.)+"\)', fields["sll_ifindex"]
        )
        if numeric_ifindex is not None:
            ifindex_value = int(numeric_ifindex.group(0))
            if ifindex_value > 0xFFFFFFFF:
                raise _fail("sockaddr-packet-ifindex")
            ifindex: dict[str, object] = {
                "kind": "numeric",
                "value": ifindex_value,
            }
        elif named_ifindex is not None:
            ifindex = {"kind": "name"}
        else:
            raise _fail("sockaddr-packet-ifindex")
        if fields["sll_hatype"] not in {"ARPHRD_ETHER", "ARPHRD_LOOPBACK"}:
            raise _fail("sockaddr-packet-hatype")
        if fields["sll_pkttype"] not in {
            "PACKET_BROADCAST",
            "PACKET_FASTROUTE",
            "PACKET_HOST",
            "PACKET_KERNEL",
            "PACKET_LOOPBACK",
            "PACKET_MULTICAST",
            "PACKET_OTHERHOST",
            "PACKET_OUTGOING",
            "PACKET_USER",
        }:
            raise _fail("sockaddr-packet-type")
        address_length = _integer(fields["sll_halen"], "sockaddr-packet-length")
        if address_length == 0:
            if "sll_addr" in fields:
                raise _fail("sockaddr-packet-fields")
            return {
                "family": family,
                "protocol": protocol.group(1),
                "ifindex": ifindex,
            }
        if "sll_addr" not in fields:
            raise _fail("sockaddr-packet-fields")
        address_bytes = _vector(fields["sll_addr"], "sockaddr-packet-address")
        if (
            address_length < 0
            or address_length > 8
            or len(address_bytes) != address_length
            or any(
                re.fullmatch(r"0x[0-9a-f]{2}", byte) is None for byte in address_bytes
            )
        ):
            raise _fail("sockaddr-packet-address")
        return {"family": family, "protocol": protocol.group(1)}
    else:
        if set(fields) == {"sa_family"}:
            return result
        if set(fields) != {"sa_family", "sun_path"}:
            raise _fail("sockaddr-unix-fields")
        path = fields["sun_path"]
        if re.fullmatch(r'@?"(?:[^"\\]|\\.)*"', path) is None:
            raise _fail("sockaddr-unix-path")
        result["path"] = {"kind": "unix"}
        if path.startswith("@"):
            result["path"]["abstract"] = True
        return result
    port_value = int(port.group(1))
    if port_value > 65535:
        raise _fail("invalid-socket-port")
    result.update(port=port_value, ip=ip)
    return result


def _control(value: str) -> dict[str, object] | None:
    if value == "NULL":
        return None
    groups: list[list[dict[str, object]]] = []
    for item in _vector(value, "control-vector"):
        fields = _fields(item, "control-message")
        if fields.get("cmsg_type") != "SCM_RIGHTS":
            continue
        if fields.get("cmsg_level") != "SOL_SOCKET" or "cmsg_data" not in fields:
            raise _fail("scm-rights-fields")
        descriptors = [
            _fd(fd, "invalid-scm-rights-fd")
            for fd in _vector(fields["cmsg_data"], "scm-rights-vector")
        ]
        if not descriptors:
            raise _fail("empty-scm-rights")
        groups.append(descriptors)
    return None if not groups else {"scm_rights": groups}


def _message(value: str) -> dict[str, object]:
    fields = _fields(value, "message-header")
    required = {
        "msg_name",
        "msg_namelen",
        "msg_iov",
        "msg_iovlen",
        "msg_controllen",
        "msg_flags",
    }
    if frozenset(fields) not in {
        frozenset(required),
        frozenset(required | {"msg_control"}),
    }:
        raise _fail("message-header-fields")
    iov_count = _integer(fields["msg_iovlen"], "invalid-message-iov-count")
    if iov_count != len(_vector(fields["msg_iov"], "message-iov-vector")):
        raise _fail("message-iov-count-mismatch")
    control_length = _integer(
        fields["msg_controllen"], "invalid-message-control-length"
    )
    if "msg_control" not in fields and control_length != 0:
        raise _fail("missing-message-control")
    result: dict[str, object] = {"lengths": {"iov_count": iov_count}}
    address = _address(fields["msg_name"])
    if address is not None:
        result["address"] = address
    if "msg_control" in fields:
        control = _control(fields["msg_control"])
        if control is not None:
            result["control"] = control
    return result


_RAW_GRAMMAR = {
    "read": (3, (0,), 2, None, "count"),
    "readv": (3, (0,), 2, None, "iov_count"),
    "pread64": (4, (0,), 2, None, "count"),
    "preadv": (4, (0,), 2, None, "iov_count"),
    "preadv2": (6, (0,), 2, 5, "iov_count"),
    "write": (3, (0,), 2, None, "count"),
    "writev": (3, (0,), 2, None, "iov_count"),
    "pwrite64": (4, (0,), 2, None, "count"),
    "pwritev": (4, (0,), 2, None, "iov_count"),
    "pwritev2": (6, (0,), 2, 5, "iov_count"),
    "sendfile": (4, (0, 1), 3, None, "count"),
    "splice": (6, (0, 2), 4, 5, "count"),
    "vmsplice": (4, (0,), 2, 3, "iov_count"),
    "tee": (4, (0, 1), 2, 3, "count"),
    "copy_file_range": (6, (0, 2), 4, 5, "count"),
}


def _raw_metadata(name: str, arguments: list[str]) -> dict[str, object]:
    arity, fd_indexes, length_index, flag_index, length_key = _RAW_GRAMMAR[name]
    if len(arguments) != arity:
        raise _fail("raw-syscall-arity")
    for index, argument in enumerate(arguments):
        if index in fd_indexes:
            _raw_integer(argument, "invalid-raw-fd")
        else:
            _raw_integer(argument, "invalid-raw-number")
    metadata: dict[str, object] = {
        "fds": [
            {"fd": _raw_integer(arguments[index], "invalid-raw-fd")}
            for index in fd_indexes
        ],
        "lengths": {
            length_key: _raw_integer(arguments[length_index], "invalid-raw-length")
        },
    }
    if flag_index is not None:
        metadata["flags"] = _raw_integer(arguments[flag_index], "invalid-raw-flags")
    return metadata


def _message_vector(
    value: str, *, allow_incomplete: bool = False
) -> tuple[list[dict[str, object]], int]:
    messages: list[dict[str, object]] = []
    completed = 0
    incomplete_seen = False
    for item in _vector(value, "message-vector"):
        fields = _fields(item, "message-vector-entry")
        if set(fields) == {"msg_hdr", "msg_len"}:
            if incomplete_seen:
                raise _fail("message-vector-completion-order")
            _integer(fields["msg_len"], "invalid-message-length")
            completed += 1
        elif allow_incomplete and set(fields) == {"msg_hdr"}:
            incomplete_seen = True
        else:
            raise _fail("message-vector-entry-fields")
        messages.append(_message(fields["msg_hdr"]))
    return messages, completed


def _address_metadata(
    name: str, arguments: list[str], result: dict[str, object]
) -> dict[str, object]:
    arity = {
        "sendto": 6,
        "recvfrom": 6,
        "sendmsg": 3,
        "recvmsg": 3,
        "sendmmsg": 4,
        "recvmmsg": 5,
    }[name]
    if len(arguments) != arity:
        raise _fail("address-syscall-arity")
    metadata: dict[str, object] = {"fds": [_fd(arguments[0], "invalid-socket-fd")]}
    if name == "sendto":
        metadata["lengths"] = {"count": _integer(arguments[2], "invalid-count")}
        sockaddr_length = re.fullmatch(r"([0-9]+)", arguments[-1])
        if sockaddr_length is None:
            raise _fail("invalid-sockaddr-length")
        metadata["lengths"]["sockaddr"] = int(sockaddr_length.group(1))
        metadata["flags"] = _flags(arguments[3])
        address = _address(arguments[4])
        if address is not None:
            metadata["address"] = address
    elif name == "recvfrom":
        metadata["lengths"] = {"count": _integer(arguments[2], "invalid-count")}
        metadata["flags"] = _flags(arguments[3])
        if arguments[4].startswith("{"):
            address = _address(arguments[4])
            length = _output_length(arguments[5], "invalid-sockaddr-length")
            if length is None:
                raise _fail("invalid-sockaddr-length")
            metadata["lengths"]["sockaddr"] = length
            if address is not None:
                metadata["address"] = address
        else:
            _output_pointer(arguments[4], "invalid-recvfrom-address-pointer")
            sockaddr_length = _output_length(
                arguments[5], "invalid-recvfrom-length-pointer"
            )
            if sockaddr_length is not None:
                metadata["lengths"]["sockaddr"] = sockaddr_length
    elif name == "sendmsg":
        message = _message(arguments[1])
        metadata.update(message)
        metadata["flags"] = _flags(arguments[2])
    elif name == "recvmsg":
        metadata["flags"] = _flags(arguments[2])
        if arguments[1].startswith("{"):
            fields = _fields(arguments[1], "message-header")
            if set(fields) == {"msg_namelen"}:
                metadata["lengths"] = {
                    "name_length": _integer(
                        fields["msg_namelen"], "invalid-message-name-length"
                    )
                }
            else:
                metadata.update(_message(arguments[1]))
        else:
            _output_pointer(arguments[1], "invalid-recvmsg-output-pointer")
    elif name == "sendmmsg":
        messages, completed_count = _message_vector(arguments[1], allow_incomplete=True)
        requested_count = _integer(arguments[2], "invalid-message-count")
        if len(messages) != requested_count:
            raise _fail("message-vector-count-mismatch")
        if _successful(result):
            result_count = result.get("value")
            if not isinstance(result_count, int) or result_count > requested_count:
                raise _fail("sendmmsg-result-count")
        else:
            result_count = 0
        if completed_count != result_count:
            raise _fail("sendmmsg-completed-count")
        metadata["messages"] = messages
        if completed_count == requested_count:
            metadata["lengths"] = {"message_count": requested_count}
        else:
            metadata["lengths"] = {
                "message_count": completed_count,
                "requested_message_count": requested_count,
            }
        metadata["flags"] = _flags(arguments[3])
    else:
        requested_count = _integer(arguments[2], "invalid-message-count")
        metadata["flags"] = _flags(arguments[3])
        if _successful(result):
            successful_count = result["value"]
            if (
                not isinstance(successful_count, int)
                or successful_count > requested_count
            ):
                raise _fail("recvmmsg-result-count")
            messages, completed_count = _message_vector(arguments[1])
            if completed_count != successful_count:
                raise _fail("recvmmsg-completed-count")
            if len(messages) != successful_count:
                raise _fail("message-vector-count-mismatch")
        else:
            _output_pointer(arguments[1], "invalid-recvmmsg-output-pointer")
            successful_count = 0
            messages = []
        metadata["messages"] = messages
        metadata["lengths"] = {
            "message_count": successful_count,
            "requested_message_count": requested_count,
        }
    return metadata


_TRANSITION_SYSCALLS = frozenset(
    {
        "socket",
        "socketpair",
        "accept",
        "accept4",
        "bind",
        "connect",
        "getpeername",
        "getsockname",
        "getsockopt",
        "listen",
        "setsockopt",
        "shutdown",
        "dup",
        "dup2",
        "dup3",
        "fcntl",
        "fork",
        "vfork",
        "clone",
        "execve",
        "execveat",
        "close",
        "close_range",
        "unshare",
        "pidfd_getfd",
    }
)


def _arity(arguments: list[str], expected: int, code: str) -> None:
    if len(arguments) != expected:
        raise _fail(code)


def _returned_fd(result: dict[str, object], code: str) -> dict[str, object]:
    descriptor = result.get("fd")
    if not isinstance(descriptor, dict):
        raise _fail(code)
    return descriptor


def _named_arguments(arguments: list[str], code: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for argument in arguments:
        key, separator, value = argument.partition("=")
        if (
            separator != "="
            or re.fullmatch(r"[a-z][a-z0-9_]*", key) is None
            or key in result
            or not value
        ):
            raise _fail(code)
        result[key] = value
    return result


def _transition_metadata(
    name: str, arguments: list[str], result: dict[str, object]
) -> dict[str, object]:
    transition: dict[str, object] = {"operation": name}
    if name == "socket":
        _arity(arguments, 3, "socket-arity")
        transition.update(_socket_parameters(arguments))
        if _successful(result):
            transition["created_fd"] = _returned_fd(result, "socket-return-fd")
    elif name == "socketpair":
        _arity(arguments, 4, "socketpair-arity")
        transition.update(_socket_parameters(arguments))
        if _successful(result):
            descriptors = [
                _fd(value, "socketpair-fd")
                for value in _vector(arguments[3], "socketpair-vector")
            ]
            if len(descriptors) != 2:
                raise _fail("socketpair-count")
            transition["created_fds"] = descriptors
        else:
            _raw_integer(arguments[3], "socketpair-output-pointer")
    elif name in {"accept", "accept4"}:
        _arity(arguments, 3 if name == "accept" else 4, f"{name}-arity")
        transition["source_fd"] = _fd(arguments[0], f"{name}-source-fd")
        if arguments[1].startswith("{") or arguments[1] == "NULL":
            address = _address(arguments[1])
            if address is not None:
                transition["address"] = address
            if arguments[1] == "NULL":
                if arguments[2] != "NULL":
                    raise _fail(f"{name}-sockaddr-length")
            elif _output_length(arguments[2], f"{name}-sockaddr-length") is None:
                raise _fail(f"{name}-sockaddr-length")
        else:
            _output_pointer(arguments[1], f"{name}-address-pointer")
            _output_length(arguments[2], f"{name}-length-pointer")
        if name == "accept4":
            transition["flags"] = _closed_flags(
                arguments[3], _SOCKET_TYPE_FLAGS, "unsupported-accept4-flags"
            )
        if _successful(result):
            transition["created_fd"] = _returned_fd(result, f"{name}-return-fd")
    elif name in {"bind", "connect"}:
        _arity(arguments, 3, f"{name}-arity")
        transition.update(
            fd=_fd(arguments[0], f"{name}-fd"),
            address=_address(arguments[1]),
        )
    elif name in {"getpeername", "getsockname"}:
        _arity(arguments, 3, f"{name}-arity")
        transition["fd"] = _fd(arguments[0], f"{name}-fd")
        if arguments[1].startswith("{") or arguments[1] == "NULL":
            address = _address(arguments[1])
            if address is not None:
                transition["address"] = address
            if arguments[1] == "NULL":
                if arguments[2] != "NULL":
                    raise _fail(f"{name}-sockaddr-length")
            elif _output_length(arguments[2], f"{name}-sockaddr-length") is None:
                raise _fail(f"{name}-sockaddr-length")
        else:
            _output_pointer(arguments[1], f"{name}-address-pointer")
            _output_length(arguments[2], f"{name}-length-pointer")
    elif name in {"getsockopt", "setsockopt"}:
        _arity(arguments, 5, f"{name}-arity")
        level = arguments[1]
        option = arguments[2]
        if (
            _SOCKET_OPTION_LEVEL.fullmatch(level) is None
            or _SOCKET_OPTION_NAME.fullmatch(option) is None
        ):
            raise _fail(f"unsupported-{name}-option")
        transition.update(
            fd=_fd(arguments[0], f"{name}-fd"),
            level=level,
            option=option,
        )
        if name == "setsockopt":
            length = _integer(arguments[4], "setsockopt-length")
            if level == "SOL_IP" and option in {
                "IP_ADD_MEMBERSHIP",
                "IP_DROP_MEMBERSHIP",
            }:
                transition["membership"] = _ip_membership(arguments[3])
            elif level == "SOL_IP" and option in {
                "IP_MULTICAST_IF",
                "IP_MULTICAST_TTL",
                "IP_MULTICAST_LOOP",
            }:
                transition["value"] = _ip_multicast_setup_value(option, arguments[3])
        else:
            length = _output_length(arguments[4], "getsockopt-length")
        if length is not None and length < 0:
            raise _fail(f"{name}-length")
        if length is not None:
            transition["length"] = length
    elif name == "listen":
        _arity(arguments, 2, "listen-arity")
        transition.update(
            fd=_fd(arguments[0], "listen-fd"),
            backlog=_integer(arguments[1], "listen-backlog"),
        )
    elif name == "shutdown":
        _arity(arguments, 2, "shutdown-arity")
        if arguments[1] not in {"SHUT_RD", "SHUT_RDWR", "SHUT_WR"}:
            raise _fail("shutdown-how")
        transition.update(fd=_fd(arguments[0], "shutdown-fd"), how=arguments[1])
    elif name == "dup":
        _arity(arguments, 1, "dup-arity")
        transition["source_fd"] = _fd(arguments[0], "dup-source-fd")
        if _successful(result):
            transition["created_fd"] = _returned_fd(result, "dup-return-fd")
    elif name in {"dup2", "dup3"}:
        _arity(arguments, 2 if name == "dup2" else 3, f"{name}-arity")
        transition.update(
            source_fd=_fd(arguments[0], f"{name}-source-fd"),
            target_fd=_fd(arguments[1], f"{name}-target-fd"),
        )
        if name == "dup3":
            transition["flags"] = _closed_flags(
                arguments[2], frozenset({"O_CLOEXEC"}), "unsupported-dup3-flags"
            )
        if _successful(result):
            transition["created_fd"] = _returned_fd(result, f"{name}-return-fd")
    elif name == "fcntl":
        if len(arguments) not in {2, 3}:
            raise _fail("fcntl-arity")
        command = arguments[1]
        transition["source_fd"] = _fd(arguments[0], "fcntl-source-fd")
        if command in {"F_DUPFD", "F_DUPFD_CLOEXEC"}:
            _arity(arguments, 3, "fcntl-dup-arity")
            transition.update(
                operation="fcntl_dup",
                minimum_fd=_integer(arguments[2], "fcntl-minimum-fd"),
                cloexec=command == "F_DUPFD_CLOEXEC",
            )
            if _successful(result):
                transition["created_fd"] = _returned_fd(result, "fcntl-return-fd")
        elif command == "F_GETFD":
            _arity(arguments, 2, "fcntl-getfd-arity")
            transition["operation"] = "fcntl_getfd"
            if _successful(result):
                value = result.get("value")
                if value not in {0, 1}:
                    raise _fail("invalid-fcntl-getfd-result")
                transition["cloexec"] = value == 1
        elif command == "F_SETFD":
            _arity(arguments, 3, "fcntl-setfd-arity")
            if arguments[2] not in {"0", "FD_CLOEXEC"}:
                raise _fail("invalid-fcntl-setfd-flags")
            requested = arguments[2] == "FD_CLOEXEC"
            transition.update(operation="fcntl_setfd", requested_cloexec=requested)
            if _successful(result):
                transition["cloexec"] = requested
        elif command == "F_GETFL":
            _arity(arguments, 2, "fcntl-getfl-arity")
            transition["operation"] = "fcntl_getfl"
            if _successful(result):
                status_flags = result.get("flags")
                if not isinstance(status_flags, list):
                    raise _fail("invalid-fcntl-getfl-result")
                transition["status_flags"] = status_flags
        elif command == "F_SETFL":
            _arity(arguments, 3, "fcntl-setfl-arity")
            requested_flags = _fcntl_status_flags(
                arguments[2], "invalid-fcntl-setfl-flags"
            )
            transition.update(
                operation="fcntl_setfl", requested_status_flags=requested_flags
            )
            if _successful(result):
                transition["status_flags"] = requested_flags
        else:
            raise _fail("unreviewed-fcntl-command")
    elif name in {"fork", "vfork"}:
        _arity(arguments, 0, f"{name}-arity")
        if _successful(result):
            transition.update(
                child_pid=result["value"],
                fd_table="copied",
            )
    elif name == "clone":
        fields = _named_arguments(arguments, "clone-arguments")
        flags = fields.get("flags")
        if flags is None:
            raise _fail("clone-flags")
        flag_names = _flags(flags)
        transition["flags"] = flag_names
        if _successful(result):
            transition.update(
                child_pid=result["value"],
                fd_table="shared" if "CLONE_FILES" in flag_names else "copied",
            )
    elif name in {"execve", "execveat"}:
        transition["operation"] = "exec"
        if name == "execve":
            _arity(arguments, 3, "execve-arity")
        else:
            _arity(arguments, 5, "execveat-arity")
            if arguments[0] == "AT_FDCWD":
                transition["dirfd"] = {"kind": "cwd"}
            else:
                transition["dirfd"] = _fd(arguments[0], "execveat-dirfd")
            transition["flags"] = _closed_flags(
                arguments[4],
                frozenset({"AT_EMPTY_PATH", "AT_SYMLINK_NOFOLLOW"}),
                "unsupported-execveat-flags",
            )
        if _successful(result):
            if result.get("value") != 0:
                raise _fail("invalid-exec-result")
            transition["cloexec_fds"] = "closed"
    elif name == "close":
        _arity(arguments, 1, "close-arity")
        descriptor = _fd(arguments[0], "close-fd")
        if _successful(result):
            transition["closed_fd"] = descriptor
        else:
            transition["fd"] = descriptor
    elif name == "close_range":
        _arity(arguments, 3, "close-range-arity")
        transition.update(
            first_fd=_integer(arguments[0], "close-range-first"),
            last_fd=_integer(arguments[1], "close-range-last"),
            flags=_flags(arguments[2]),
        )
    elif name == "unshare":
        _arity(arguments, 1, "unshare-arity")
        flags = _flags(arguments[0])
        if "CLONE_FILES" not in flags:
            raise _fail("unreviewed-unshare")
        transition.update(operation="unshare_files", flags=flags)
    elif name == "pidfd_getfd":
        _arity(arguments, 3, "pidfd-getfd-arity")
        if _integer(arguments[2], "pidfd-getfd-flags") != 0:
            raise _fail("pidfd-getfd-nonzero-flags")
        transition.update(
            pidfd=_fd(arguments[0], "pidfd-getfd-pidfd"),
            target_fd=_integer(arguments[1], "pidfd-getfd-target"),
        )
        if _successful(result):
            transition["created_fd"] = _returned_fd(result, "pidfd-getfd-return-fd")
    return transition


def _marker_metadata(arguments: list[str]) -> dict[str, str] | None:
    if len(arguments) != 2 or arguments[0] != "PR_SET_NAME":
        return None
    marker = re.fullmatch(r'"H0([BE])([0-9a-f]{12})"\.\.\.', arguments[1])
    if marker is None:
        return None
    return {
        "phase": "BEGIN" if marker.group(1) == "B" else "END",
        "token": marker.group(2),
    }


class TraceNormalizer:
    """Incrementally normalize one canonical linux-x86_64 strace 6.6 stream."""

    def __init__(
        self,
        *,
        max_line_bytes: int = 2_097_152,
        max_records: int = 1_000_000,
        max_pending_processes: int = 4096,
        max_input_bytes: int = 67_108_864,
        record_sink: Callable[[dict[str, object]], object] | None = None,
    ) -> None:
        bounds = (max_line_bytes, max_records, max_pending_processes, max_input_bytes)
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in bounds
        ):
            raise ValueError("trace bounds must be positive integers")
        if record_sink is not None and not callable(record_sink):
            raise TypeError("record_sink must be callable")
        self.max_line_bytes = max_line_bytes
        self.max_records = max_records
        self.max_pending_processes = max_pending_processes
        self.max_input_bytes = max_input_bytes
        self._buffer = bytearray()
        self._input_bytes = 0
        self._pending: dict[int, _Pending] = {}
        self._records = 0
        self._entries = 0
        self._exits = 0
        self._finished = False
        self._record_sink = record_sink
        self._terminal_error: TraceDecodeError | None = None

    def _latch(self, error: TraceDecodeError) -> TraceDecodeError:
        if self._terminal_error is None:
            self._terminal_error = error
        return self._terminal_error

    def _raise_if_terminal(self) -> None:
        if self._terminal_error is not None:
            raise self._terminal_error

    def feed(self, chunk: bytes) -> list[dict[str, object]]:
        self._raise_if_terminal()
        if self._finished:
            raise TraceDecodeError("strace decode rejected: feed-after-finish")
        if not isinstance(chunk, bytes):
            raise TypeError("trace chunks must be bytes")
        try:
            self._input_bytes += len(chunk)
            if self._input_bytes > self.max_input_bytes:
                raise _fail("input-bound")
            self._buffer.extend(chunk)
            records: list[dict[str, object]] = []
            while True:
                newline = self._buffer.find(b"\n")
                if newline < 0:
                    if len(self._buffer) > self.max_line_bytes:
                        raise _fail("line-bound")
                    break
                if newline > self.max_line_bytes:
                    raise _fail("line-bound")
                line = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                records.extend(self._decode_line(line))
            return records
        except TraceDecodeError as error:
            raise self._latch(error)

    def finish(self) -> list[dict[str, object]]:
        self._raise_if_terminal()
        if self._finished:
            raise TraceDecodeError("strace decode rejected: duplicate-finish")
        self._finished = True
        try:
            if self._buffer:
                raise _fail("truncated-line")
            if self._pending:
                raise _fail("pending-syscall")
            return []
        except TraceDecodeError as error:
            raise self._latch(error)

    def _decode_line(self, encoded: bytes) -> list[dict[str, object]]:
        if not encoded or b"\r" in encoded or b"\x00" in encoded:
            raise _fail("noncanonical-line")
        try:
            line = encoded.decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise _fail("noncanonical-encoding") from error
        if any(ord(character) < 32 for character in line):
            raise _fail("control-character")
        prefix = _PREFIX.fullmatch(line)
        if prefix is None:
            raise _fail("line-grammar")
        pid_text, padding, timestamp, body = prefix.groups()
        if padding != " " * max(1, 6 - len(pid_text)):
            raise _fail("pid-prefix-framing")
        pid = int(pid_text)
        prefix_columns = len(line) - len(body)
        if "runs in " in body and " bit mode" in body:
            raise _fail("unsupported-personality")

        unfinished = _UNFINISHED.fullmatch(body)
        if unfinished is not None:
            if pid in self._pending:
                raise _fail("duplicate-unfinished")
            if len(self._pending) >= self.max_pending_processes:
                raise _fail("pending-process-bound")
            entry_index = self._entries
            self._entries += 1
            self._pending[pid] = _Pending(
                syscall=unfinished.group(1),
                arguments_prefix=unfinished.group(2),
                timestamp=timestamp,
                entry_index=entry_index,
            )
            return []

        resumed = _RESUMED.fullmatch(body)
        if resumed is not None:
            pending = self._pending.pop(pid, None)
            if pending is None:
                raise _fail("orphan-resumed")
            if pending.syscall != resumed.group(1):
                raise _fail("resumed-syscall-mismatch")
            exit_index = self._exits
            self._exits += 1
            result_tail = _RESULT_TAIL.fullmatch(body)
            if result_tail is None:
                raise _fail("resumed-result-grammar")
            combined = f"{pending.syscall}({pending.arguments_prefix}{resumed.group(2)}"
            return [
                self._decode_complete(
                    pid,
                    pending.timestamp,
                    combined,
                    pending.entry_index,
                    exit_index,
                    prefix_columns=prefix_columns,
                    alignment_close_column=prefix_columns + len(result_tail.group(1)),
                )
            ]

        signal = _SIGNAL.fullmatch(body)
        if signal is not None:
            return [
                self._emit(
                    {
                        "kind": "signal",
                        "pid": pid,
                        "timestamp": timestamp,
                        "signal": signal.group(1),
                    }
                )
            ]
        exited = _EXITED.fullmatch(body)
        if exited is not None:
            if pid in self._pending:
                raise _fail("exit-with-pending-syscall")
            return [
                self._emit(
                    {
                        "kind": "exit",
                        "pid": pid,
                        "timestamp": timestamp,
                        "exit_code": int(exited.group(1)),
                    }
                )
            ]
        killed = _KILLED.fullmatch(body)
        if killed is not None:
            if pid in self._pending:
                raise _fail("exit-with-pending-syscall")
            return [
                self._emit(
                    {
                        "kind": "exit",
                        "pid": pid,
                        "timestamp": timestamp,
                        "signal": killed.group(1),
                    }
                )
            ]

        entry_index = self._entries
        exit_index = self._exits
        self._entries += 1
        self._exits += 1
        return [
            self._decode_complete(
                pid,
                timestamp,
                body,
                entry_index,
                exit_index,
                prefix_columns=prefix_columns,
            )
        ]

    def _decode_complete(
        self,
        pid: int,
        timestamp: str,
        body: str,
        entry_index: int,
        exit_index: int,
        *,
        prefix_columns: int,
        alignment_close_column: int | None = None,
    ) -> dict[str, object]:
        call = _CALL.fullmatch(body)
        if call is None:
            raise _fail("syscall-grammar")
        name, arguments_text, result_padding, result_text, duration = call.groups()
        close_column = (
            prefix_columns + call.start(3)
            if alignment_close_column is None
            else alignment_close_column
        )
        if result_padding != " " * max(1, 40 - close_column):
            raise _fail("result-alignment")
        if re.fullmatch(r"syscall_0x[0-9a-f]+", name) is not None:
            raise _fail("unsupported-native-syscall")
        arguments = _split_arguments(arguments_text)
        marker = _marker_metadata(arguments) if name == "prctl" else None
        if "..." in body and (
            body.count("...") != 1 or arguments_text.count("...") != 1 or marker is None
        ):
            raise _fail("abbreviated-field")
        timeout_left: dict[str, int] | None = None
        left = re.fullmatch(
            r"(.+) \(left \{tv_sec=([0-9]+), tv_nsec=([0-9]+)\}\)", result_text
        )
        if left is not None:
            if name != "recvmmsg":
                raise _fail("unexpected-left-timeout")
            result_text = left.group(1)
            nanoseconds = int(left.group(3))
            if nanoseconds > 999_999_999:
                raise _fail("invalid-left-timeout")
            timeout_left = {
                "seconds": int(left.group(2)),
                "nanoseconds": nanoseconds,
            }
        record: dict[str, object] = {
            "kind": "syscall",
            "pid": pid,
            "timestamp": timestamp,
            "duration": duration,
            "entry_index": entry_index,
            "exit_index": exit_index,
            "syscall": name,
        }
        if marker is not None:
            record["marker"] = marker
        if name in RAW_PAYLOAD_SYSCALLS:
            result = _raw_result(result_text)
        elif name == "fcntl" and len(arguments) >= 2:
            result = _fcntl_result(arguments[1], result_text)
        else:
            result = _result(result_text)
        if timeout_left is not None:
            result["timeout_left"] = timeout_left
        if name in RAW_PAYLOAD_SYSCALLS:
            record.update(_raw_metadata(name, arguments))
        elif name in DECODED_ADDRESS_SYSCALLS:
            record.update(_address_metadata(name, arguments, result))
        # Generic syscalls retain no arguments: the reviewed safe structural subset
        # is identity, timing, and native return metadata only.
        record["result"] = result
        if name in _TRANSITION_SYSCALLS:
            record["transition"] = _transition_metadata(name, arguments, result)
        return self._emit(record)

    def _emit(self, record: dict[str, object]) -> dict[str, object]:
        if self._records >= self.max_records:
            raise _fail("record-bound")
        record["record_index"] = self._records
        self._records += 1
        if self._record_sink is not None:
            try:
                self._record_sink(copy.deepcopy(record))
            except Exception:
                raise _fail("record-sink") from None
        return record


def normalize_bytes(source: bytes, **bounds: int) -> list[dict[str, object]]:
    normalizer = TraceNormalizer(**bounds)
    records = normalizer.feed(source)
    records.extend(normalizer.finish())
    return records


def normalize_lines(lines: Iterable[bytes], **bounds: int) -> list[dict[str, object]]:
    normalizer = TraceNormalizer(**bounds)
    records: list[dict[str, object]] = []
    for line in lines:
        records.extend(normalizer.feed(line))
    records.extend(normalizer.finish())
    return records


def canonical_ndjson(records: Iterable[dict[str, object]]) -> str:
    return "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
        for record in records
    )
