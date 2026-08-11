"""Load and enforce the closed Cyclone DDS configuration set."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET


CONFIG_NAMES = tuple(f"cyclonedds-offline-p{index}.xml" for index in range(4))
CONFIG_ROLES = (
    "fixture",
    "query_publisher",
    "result_subscriber",
    "graph_inspector",
)
EXPECTED_CONFIG_SHA256 = {
    0: "103da44a684613ead128dd221cace5455ae8890322f8ef50607ea4aa53283ed1",
    1: "fed9c399b9cc2139440e359d89231d4c0dabe2ddaac99a256146f45faeb3c9fd",
    2: "badd1e0472ab796697c7aca008f392f76c30af55e25c4502d04116c34dad19e2",
    3: "1fc59441a89e0ac1632b84786f54ec9bfb40470d4498dbed4b18962cdab6993c",
}
CONFIG_SET_SHA256 = "2f4b15dfe1ee168425ad0552c45d5434d068e6ff6bab43c45f82d7869dcb5879"

_REPOSITORY_CONFIG_PREFIX = "scripts/holoagent0_setup/config"
_EXPECTED_INTERFACE = {
    "name": "lo",
    "autodetermine": False,
    "presence_required": True,
    "multicast": True,
}
_EXPECTED_PORTS = {
    "base": 7400,
    "domain_gain": 250,
    "participant_gain": 2,
    "multicast_meta_offset": 0,
    "multicast_data_offset": 1,
    "unicast_meta_offset": 10,
    "unicast_data_offset": 11,
}
_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")


class CycloneConfigError(ValueError):
    """The Cyclone configuration is absent, mutable, or outside policy."""


@dataclass(frozen=True)
class CycloneConfigDescriptor:
    """One measured configuration and its fixed participant role."""

    path: Path
    repository_relative_path: str
    role: str
    participant_index: int
    sha256: str

    @property
    def uri(self) -> str:
        """Return the only accepted ``CYCLONEDDS_URI`` for this descriptor."""

        return self.path.as_uri()


@dataclass(frozen=True)
class CycloneConfigSet:
    """Measured files plus their shared, closed DDS semantics."""

    configs: tuple[CycloneConfigDescriptor, ...]
    aggregate_sha256: str
    domain_id: int
    interface: dict[str, str | bool]
    transport: str
    allow_multicast: str
    multicast_loopback: bool
    multicast_ttl: int
    spdp_multicast_address: str
    default_multicast_address: str
    peers: tuple[str, ...]
    many_sockets_mode: bool
    monitor_port: int
    redundant_networking: bool
    ports: dict[str, int]
    spdp_port: int
    data_multicast_receive_port: int
    unicast_ports: dict[int, tuple[int, int]]


@dataclass(frozen=True)
class _ParsedConfig:
    domain_id: int
    participant_index: int
    interface_name: str
    interface_autodetermine: bool
    interface_presence_required: bool
    interface_multicast: bool
    transport: str
    allow_multicast: str
    multicast_loopback: bool
    multicast_ttl: int
    spdp_multicast_address: str
    default_multicast_address: str
    peers: tuple[str, ...]
    many_sockets_mode: bool
    monitor_port: int
    redundant_networking: bool
    ports: tuple[tuple[str, int], ...]


def load_pinned_cyclone_configs(
    config_dir: Path | str,
    *,
    repository_root: Path | str,
) -> CycloneConfigSet:
    """Measure and parse exactly the four reviewed Cyclone configuration files."""

    root = _resolve_config_directory(config_dir, repository_root)
    _require_closed_inventory(root)

    descriptors: list[CycloneConfigDescriptor] = []
    parsed_configs: list[_ParsedConfig] = []
    normalized_payloads: list[bytes] = []
    for participant_index, (name, role) in enumerate(zip(CONFIG_NAMES, CONFIG_ROLES)):
        path = root / name
        payload = _read_regular_file(path)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != EXPECTED_CONFIG_SHA256[participant_index]:
            raise CycloneConfigError(f"Cyclone configuration digest mismatch: {name}")

        parsed = _parse_config(payload, name)
        if parsed.participant_index != participant_index:
            raise CycloneConfigError(
                f"Cyclone participant index does not match its role: {name}"
            )
        _require_expected_semantics(parsed, name)
        parsed_configs.append(parsed)

        participant_element = (
            f"<ParticipantIndex>{participant_index}</ParticipantIndex>".encode()
        )
        if payload.count(participant_element) != 1:
            raise CycloneConfigError(
                f"Cyclone participant index is not uniquely serialized: {name}"
            )
        normalized_payloads.append(
            payload.replace(
                participant_element,
                b"<ParticipantIndex>INDEX</ParticipantIndex>",
            )
        )
        descriptors.append(
            CycloneConfigDescriptor(
                path=path.resolve(strict=True),
                repository_relative_path=(f"{_REPOSITORY_CONFIG_PREFIX}/{name}"),
                role=role,
                participant_index=participant_index,
                sha256=digest,
            )
        )

    if len(set(normalized_payloads)) != 1:
        raise CycloneConfigError(
            "Cyclone configurations differ by more than ParticipantIndex"
        )
    shared = parsed_configs[0]
    if any(
        _without_participant(parsed) != _without_participant(shared)
        for parsed in parsed_configs[1:]
    ):
        raise CycloneConfigError("Cyclone configurations do not share one policy")

    descriptor_tuple = tuple(descriptors)
    aggregate_sha256 = _aggregate_digest(descriptor_tuple)
    if aggregate_sha256 != CONFIG_SET_SHA256:
        raise CycloneConfigError("Cyclone configuration set digest mismatch")

    ports = dict(shared.ports)
    discovery_base = ports["base"] + ports["domain_gain"] * shared.domain_id
    return CycloneConfigSet(
        configs=descriptor_tuple,
        aggregate_sha256=aggregate_sha256,
        domain_id=shared.domain_id,
        interface={
            "name": shared.interface_name,
            "autodetermine": shared.interface_autodetermine,
            "presence_required": shared.interface_presence_required,
            "multicast": shared.interface_multicast,
        },
        transport=shared.transport,
        allow_multicast=shared.allow_multicast,
        multicast_loopback=shared.multicast_loopback,
        multicast_ttl=shared.multicast_ttl,
        spdp_multicast_address=shared.spdp_multicast_address,
        default_multicast_address=shared.default_multicast_address,
        peers=shared.peers,
        many_sockets_mode=shared.many_sockets_mode,
        monitor_port=shared.monitor_port,
        redundant_networking=shared.redundant_networking,
        ports=ports,
        spdp_port=discovery_base + ports["multicast_meta_offset"],
        data_multicast_receive_port=(discovery_base + ports["multicast_data_offset"]),
        unicast_ports={
            index: (
                discovery_base
                + ports["participant_gain"] * index
                + ports["unicast_meta_offset"],
                discovery_base
                + ports["participant_gain"] * index
                + ports["unicast_data_offset"],
            )
            for index in range(4)
        },
    )


def validate_cyclonedds_uri(
    uri: str,
    contract: CycloneConfigSet,
    *,
    participant_index: int,
) -> CycloneConfigDescriptor:
    """Validate and remeasure one role's absolute, canonical ``file:`` URI."""

    if not isinstance(uri, str) or not uri:
        raise CycloneConfigError("CYCLONEDDS_URI must be a non-empty string")
    if type(participant_index) is not int:
        raise CycloneConfigError("Cyclone participant index must be an integer")
    try:
        descriptor = next(
            config
            for config in contract.configs
            if config.participant_index == participant_index
        )
    except StopIteration as error:
        raise CycloneConfigError("unknown Cyclone participant role") from error

    try:
        parsed_uri = urlsplit(uri)
    except ValueError as error:
        raise CycloneConfigError("invalid CYCLONEDDS_URI") from error
    if (
        parsed_uri.scheme != "file"
        or parsed_uri.netloc
        or parsed_uri.query
        or parsed_uri.fragment
    ):
        raise CycloneConfigError("CYCLONEDDS_URI must be a local file URI")
    uri_path = Path(unquote(parsed_uri.path))
    if not uri_path.is_absolute() or uri != descriptor.uri:
        raise CycloneConfigError(
            "CYCLONEDDS_URI must be the canonical URI for its participant role"
        )

    payload = _read_regular_file(uri_path)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != descriptor.sha256:
        raise CycloneConfigError("Cyclone configuration changed after measurement")
    if uri_path.resolve(strict=True) != descriptor.path:
        raise CycloneConfigError("CYCLONEDDS_URI resolved to an alternate file")
    return descriptor


def _resolve_config_directory(
    config_dir: Path | str,
    repository_root: Path | str,
) -> Path:
    path = Path(config_dir)
    trusted_root = Path(repository_root)
    if path.is_symlink() or trusted_root.is_symlink():
        raise CycloneConfigError(
            "Cyclone configuration and repository roots cannot be symlinks"
        )
    try:
        resolved = path.resolve(strict=True)
        resolved_repository = trusted_root.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise CycloneConfigError(
            "Cyclone configuration or repository directory is unavailable"
        ) from error
    expected = resolved_repository / _REPOSITORY_CONFIG_PREFIX
    if not resolved_repository.is_dir() or not resolved.is_dir():
        raise CycloneConfigError(
            f"Cyclone configuration path is not a directory: {resolved}"
        )
    if resolved != expected:
        raise CycloneConfigError(
            "Cyclone configuration directory is outside the trusted repository"
        )
    return resolved


def _require_closed_inventory(root: Path) -> None:
    try:
        actual = {
            path.name for path in root.iterdir() if path.name.startswith("cyclonedds-")
        }
    except OSError as error:
        raise CycloneConfigError(
            "cannot list Cyclone configuration directory"
        ) from error
    expected = set(CONFIG_NAMES)
    if actual != expected:
        raise CycloneConfigError(
            "closed Cyclone configuration inventory mismatch; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )


def _read_regular_file(path: Path) -> bytes:
    if path.is_symlink():
        raise CycloneConfigError(f"Cyclone configuration cannot be a symlink: {path}")
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise CycloneConfigError(
                f"Cyclone configuration is not a regular file: {path}"
            )
        chunks = []
        size = 0
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            size += len(chunk)
            if size > 65_536:
                raise CycloneConfigError(
                    f"Cyclone configuration exceeds the reviewed bound: {path}"
                )
            chunks.append(chunk)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)
            or size != after.st_size
        ):
            raise CycloneConfigError(
                f"Cyclone configuration identity changed during read: {path}"
            )
        return b"".join(chunks)
    except CycloneConfigError:
        raise
    except OSError as error:
        raise CycloneConfigError(
            f"cannot read Cyclone configuration: {path}"
        ) from error
    finally:
        if fd >= 0:
            os.close(fd)


def _parse_config(payload: bytes, name: str) -> _ParsedConfig:
    if b"<!DOCTYPE" in payload.upper():
        raise CycloneConfigError(f"DOCTYPE is prohibited in Cyclone config: {name}")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as error:
        raise CycloneConfigError(f"invalid Cyclone XML: {name}") from error

    _require_element(root, "CycloneDDS", {})
    (domain,) = _require_children(root, ("Domain",), name)
    _require_element(domain, "Domain", {"Id": "77"})
    general, discovery, compatibility, internal = _require_children(
        domain,
        ("General", "Discovery", "Compatibility", "Internal"),
        name,
    )
    _require_element(general, "General", {})
    _require_element(discovery, "Discovery", {})
    _require_element(compatibility, "Compatibility", {})
    _require_element(internal, "Internal", {})

    (
        interfaces,
        transport,
        allow_multicast,
        multicast_loopback,
        multicast_ttl,
        redundant_networking,
    ) = _require_children(
        general,
        (
            "Interfaces",
            "Transport",
            "AllowMulticast",
            "EnableMulticastLoopback",
            "MulticastTimeToLive",
            "RedundantNetworking",
        ),
        name,
    )
    _require_element(interfaces, "Interfaces", {})
    (network_interface,) = _require_children(interfaces, ("NetworkInterface",), name)
    _require_element(
        network_interface,
        "NetworkInterface",
        {
            "name": "lo",
            "autodetermine": "false",
            "presence_required": "true",
            "multicast": "true",
        },
    )
    _require_children(network_interface, (), name)

    (
        participant_index,
        spdp_multicast_address,
        default_multicast_address,
        peers,
        port_elements,
    ) = _require_children(
        discovery,
        (
            "ParticipantIndex",
            "SPDPMulticastAddress",
            "DefaultMulticastAddress",
            "Peers",
            "Ports",
        ),
        name,
    )
    _require_element(peers, "Peers", {})
    peer_elements = _require_children(peers, (), name)
    _require_element(port_elements, "Ports", {})
    parsed_port_elements = _require_children(
        port_elements,
        (
            "Base",
            "DomainGain",
            "ParticipantGain",
            "MulticastMetaOffset",
            "MulticastDataOffset",
            "UnicastMetaOffset",
            "UnicastDataOffset",
        ),
        name,
    )
    port_names = tuple(_EXPECTED_PORTS)
    ports = tuple(
        (key, _integer_text(element, name))
        for key, element in zip(port_names, parsed_port_elements)
    )

    (many_sockets_mode,) = _require_children(compatibility, ("ManySocketsMode",), name)
    (monitor_port,) = _require_children(internal, ("MonitorPort",), name)
    return _ParsedConfig(
        domain_id=_integer_attribute(domain, "Id", name),
        participant_index=_integer_text(participant_index, name),
        interface_name=network_interface.attrib["name"],
        interface_autodetermine=_boolean_attribute(
            network_interface, "autodetermine", name
        ),
        interface_presence_required=_boolean_attribute(
            network_interface, "presence_required", name
        ),
        interface_multicast=_boolean_attribute(network_interface, "multicast", name),
        transport=_leaf_text(transport, name),
        allow_multicast=_leaf_text(allow_multicast, name),
        multicast_loopback=_boolean_text(multicast_loopback, name),
        multicast_ttl=_integer_text(multicast_ttl, name),
        spdp_multicast_address=_leaf_text(spdp_multicast_address, name),
        default_multicast_address=_leaf_text(default_multicast_address, name),
        peers=tuple(element.attrib.get("Address", "") for element in peer_elements),
        many_sockets_mode=_boolean_text(many_sockets_mode, name),
        monitor_port=_integer_text(monitor_port, name),
        redundant_networking=_boolean_text(redundant_networking, name),
        ports=ports,
    )


def _require_expected_semantics(parsed: _ParsedConfig, name: str) -> None:
    interface = {
        "name": parsed.interface_name,
        "autodetermine": parsed.interface_autodetermine,
        "presence_required": parsed.interface_presence_required,
        "multicast": parsed.interface_multicast,
    }
    expected_values = (
        parsed.domain_id == 77,
        interface == _EXPECTED_INTERFACE,
        parsed.transport == "udp",
        parsed.allow_multicast == "spdp",
        parsed.multicast_loopback is True,
        parsed.multicast_ttl == 1,
        parsed.spdp_multicast_address == "239.255.0.1",
        parsed.default_multicast_address == "239.255.0.1",
        parsed.peers == (),
        parsed.many_sockets_mode is False,
        parsed.monitor_port == -1,
        parsed.redundant_networking is False,
        dict(parsed.ports) == _EXPECTED_PORTS,
    )
    if not all(expected_values):
        raise CycloneConfigError(f"Cyclone semantics are outside policy: {name}")


def _without_participant(parsed: _ParsedConfig) -> tuple[object, ...]:
    return tuple(
        value
        for field_name, value in parsed.__dict__.items()
        if field_name != "participant_index"
    )


def _aggregate_digest(
    descriptors: tuple[CycloneConfigDescriptor, ...],
) -> str:
    records = [
        {
            "participant_index": descriptor.participant_index,
            "path": descriptor.repository_relative_path,
            "role": descriptor.role,
            "sha256": descriptor.sha256,
        }
        for descriptor in descriptors
    ]
    canonical_json = json.dumps(
        records,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical_json).hexdigest()


def _require_element(
    element: ET.Element,
    expected_tag: str,
    expected_attributes: dict[str, str],
) -> None:
    if element.tag != expected_tag or element.attrib != expected_attributes:
        raise CycloneConfigError(
            f"unexpected Cyclone element or attributes: {element.tag}"
        )


def _require_children(
    element: ET.Element,
    expected_tags: tuple[str, ...],
    name: str,
) -> tuple[ET.Element, ...]:
    children = tuple(element)
    if tuple(child.tag for child in children) != expected_tags:
        raise CycloneConfigError(
            f"unexpected Cyclone XML structure under {element.tag}: {name}"
        )
    return children


def _leaf_text(element: ET.Element, name: str) -> str:
    _require_element(element, element.tag, {})
    _require_children(element, (), name)
    if element.text is None or element.text != element.text.strip():
        raise CycloneConfigError(f"invalid Cyclone value for {element.tag}: {name}")
    return element.text


def _integer_attribute(element: ET.Element, key: str, name: str) -> int:
    value = element.attrib.get(key)
    if value is None or _INTEGER.fullmatch(value) is None:
        raise CycloneConfigError(f"invalid Cyclone integer attribute {key}: {name}")
    return int(value)


def _boolean_attribute(element: ET.Element, key: str, name: str) -> bool:
    value = element.attrib.get(key)
    if value not in {"false", "true"}:
        raise CycloneConfigError(f"invalid Cyclone boolean attribute {key}: {name}")
    return value == "true"


def _integer_text(element: ET.Element, name: str) -> int:
    value = _leaf_text(element, name)
    if _INTEGER.fullmatch(value) is None:
        raise CycloneConfigError(f"invalid Cyclone integer {element.tag}: {name}")
    return int(value)


def _boolean_text(element: ET.Element, name: str) -> bool:
    value = _leaf_text(element, name)
    if value not in {"false", "true"}:
        raise CycloneConfigError(f"invalid Cyclone boolean {element.tag}: {name}")
    return value == "true"
