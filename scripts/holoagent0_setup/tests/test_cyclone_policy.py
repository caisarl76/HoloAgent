from __future__ import annotations

import hashlib
from pathlib import Path
import shutil

import pytest

from holoagent0_setup.cyclone_policy import (
    CONFIG_SET_SHA256,
    EXPECTED_CONFIG_SHA256,
    CycloneConfigError,
    load_pinned_cyclone_configs,
    validate_cyclonedds_uri,
)


ROOT = Path(__file__).parents[1]
CONFIG_DIR = ROOT / "config"
REPOSITORY_ROOT = ROOT.parents[1]
CONFIG_NAMES = tuple(f"cyclonedds-offline-p{index}.xml" for index in range(4))


def _copy_configs(repository_root):
    destination = repository_root / "scripts/holoagent0_setup/config"
    destination.mkdir(parents=True)
    for name in CONFIG_NAMES:
        shutil.copyfile(CONFIG_DIR / name, destination / name)
    return destination


def test_four_configs_are_closed_byte_pinned_and_differ_only_by_index():
    contract = load_pinned_cyclone_configs(CONFIG_DIR, repository_root=REPOSITORY_ROOT)
    assert tuple(config.participant_index for config in contract.configs) == tuple(
        range(4)
    )
    assert tuple(config.path.name for config in contract.configs) == CONFIG_NAMES
    assert {
        path.name
        for path in CONFIG_DIR.iterdir()
        if path.name.startswith("cyclonedds-")
    } == set(CONFIG_NAMES)
    assert {
        config.participant_index: hashlib.sha256(config.path.read_bytes()).hexdigest()
        for config in contract.configs
    } == EXPECTED_CONFIG_SHA256
    assert contract.aggregate_sha256 == CONFIG_SET_SHA256
    normalized = [
        config.path.read_text(encoding="utf-8").replace(
            f"<ParticipantIndex>{config.participant_index}</ParticipantIndex>",
            "<ParticipantIndex>INDEX</ParticipantIndex>",
        )
        for config in contract.configs
    ]
    assert len(set(normalized)) == 1


def test_exact_cyclone_semantics_and_ports_are_pinned():
    contract = load_pinned_cyclone_configs(CONFIG_DIR, repository_root=REPOSITORY_ROOT)
    for config in contract.configs:
        assert config.path.read_bytes().count(b'allow_multicast="spdp"') == 1
    assert contract.domain_id == 77
    assert contract.interface == {
        "name": "lo",
        "autodetermine": False,
        "presence_required": True,
        "multicast": True,
        "allow_multicast": "spdp",
    }
    assert contract.transport == "udp"
    assert contract.allow_multicast == "spdp"
    assert contract.multicast_loopback is True
    assert contract.multicast_ttl == 1
    assert contract.spdp_multicast_address == "239.255.0.1"
    assert contract.default_multicast_address == "239.255.0.1"
    assert contract.add_localhost is False
    assert contract.peers == ()
    assert contract.many_sockets_mode is False
    assert contract.monitor_port == -1
    assert contract.redundant_networking is False
    assert contract.ports == {
        "base": 7400,
        "domain_gain": 250,
        "participant_gain": 2,
        "multicast_meta_offset": 0,
        "multicast_data_offset": 1,
        "unicast_meta_offset": 10,
        "unicast_data_offset": 11,
    }
    assert contract.spdp_port == 26650
    assert contract.prohibited_data_multicast_port == 26651
    assert contract.unicast_ports == {
        0: (26660, 26661),
        1: (26662, 26663),
        2: (26664, 26665),
        3: (26666, 26667),
    }


@pytest.mark.parametrize(
    "old,new",
    [
        (b">spdp<", b">false<"),
        (b">spdp<", b">true<"),
        (b">udp<", b">tcp<"),
        (b'name="lo"', b'name="eth0"'),
        (b'autodetermine="false"', b'autodetermine="true"'),
        (b'multicast="true"', b'multicast="false"'),
        (b">239.255.0.1<", b">239.255.0.2<"),
        (b">7400<", b">7401<"),
        (b">250<", b">251<"),
        (b">2<", b">3<"),
        (b">10<", b">12<"),
        (b">11<", b">13<"),
    ],
)
def test_any_semantic_or_digest_mutation_is_rejected(tmp_path, old, new):
    repository = tmp_path / "repository"
    copied = _copy_configs(repository)
    target = copied / CONFIG_NAMES[0]
    payload = target.read_bytes()
    assert old in payload
    target.write_bytes(payload.replace(old, new, 1))
    with pytest.raises(CycloneConfigError):
        load_pinned_cyclone_configs(copied, repository_root=repository)


def test_missing_extra_or_symlinked_config_is_rejected(tmp_path):
    repository = tmp_path / "repository"
    copied = _copy_configs(repository)
    (copied / CONFIG_NAMES[0]).unlink()
    with pytest.raises(CycloneConfigError):
        load_pinned_cyclone_configs(copied, repository_root=repository)

    shutil.rmtree(copied)
    copied = _copy_configs(repository)
    (copied / "cyclonedds-extra.xml").write_text("<CycloneDDS/>", encoding="utf-8")
    with pytest.raises(CycloneConfigError):
        load_pinned_cyclone_configs(copied, repository_root=repository)

    shutil.rmtree(copied)
    copied = _copy_configs(repository)
    target = copied / CONFIG_NAMES[0]
    real = copied / "real.xml"
    target.rename(real)
    target.symlink_to(real)
    with pytest.raises(CycloneConfigError):
        load_pinned_cyclone_configs(copied, repository_root=repository)


@pytest.mark.parametrize("participant_index", range(4))
def test_only_absolute_pinned_file_uri_for_matching_role_passes(participant_index):
    contract = load_pinned_cyclone_configs(CONFIG_DIR, repository_root=REPOSITORY_ROOT)
    path = (CONFIG_DIR / CONFIG_NAMES[participant_index]).resolve()
    descriptor = validate_cyclonedds_uri(
        path.as_uri(), contract, participant_index=participant_index
    )
    assert descriptor.participant_index == participant_index
    assert descriptor.path == path


def test_inline_relative_wrong_role_and_symlink_uri_are_rejected(tmp_path):
    contract = load_pinned_cyclone_configs(CONFIG_DIR, repository_root=REPOSITORY_ROOT)
    path = (CONFIG_DIR / CONFIG_NAMES[0]).resolve()
    for uri, index in (
        ("<CycloneDDS><Domain Id='77'/></CycloneDDS>", 0),
        ("file:relative.xml", 0),
        (path.as_uri(), 1),
        ("http://127.0.0.1/config.xml", 0),
        ("", 0),
    ):
        with pytest.raises(CycloneConfigError):
            validate_cyclonedds_uri(uri, contract, participant_index=index)

    link = tmp_path / "cyclone.xml"
    link.symlink_to(path)
    with pytest.raises(CycloneConfigError):
        validate_cyclonedds_uri(link.as_uri(), contract, participant_index=0)

    copied = tmp_path / "copied.xml"
    shutil.copyfile(path, copied)
    with pytest.raises(CycloneConfigError):
        validate_cyclonedds_uri(copied.as_uri(), contract, participant_index=0)


def test_config_loader_rejects_directory_outside_trusted_repository_root(tmp_path):
    copied = _copy_configs(tmp_path / "alternate")
    with pytest.raises(CycloneConfigError):
        load_pinned_cyclone_configs(copied, repository_root=REPOSITORY_ROOT)


def test_uri_is_remeasured_and_rejects_post_load_content_change(tmp_path):
    repository = tmp_path / "repository"
    copied = _copy_configs(repository)
    contract = load_pinned_cyclone_configs(copied, repository_root=repository)
    target = (copied / CONFIG_NAMES[0]).resolve()
    target.write_bytes(target.read_bytes().replace(b">spdp<", b">false<", 1))
    with pytest.raises(CycloneConfigError):
        validate_cyclonedds_uri(target.as_uri(), contract, participant_index=0)
