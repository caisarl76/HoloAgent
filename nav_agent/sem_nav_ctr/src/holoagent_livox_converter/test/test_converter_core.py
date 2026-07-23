from __future__ import annotations

from types import SimpleNamespace
import struct

import numpy as np
import pytest

from holoagent_livox_converter.converter_core import (
    ConversionError,
    ConversionOptions,
    decode_pointcloud,
)


def make_cloud(
    count: int = 2500,
    *,
    offsets: np.ndarray | None = None,
    nonfinite_index: int | None = None,
):
    if offsets is None:
        offsets = np.zeros(count, dtype=np.uint32)
    data = bytearray(count * 20)
    for index in range(count):
        x = float(index % 50 + 1)
        if index == nonfinite_index:
            x = float("nan")
        struct.pack_into(
            "<fffBBBxI",
            data,
            index * 20,
            x,
            float(index % 7),
            0.5,
            100,
            0,
            index % 6,
            int(offsets[index]),
        )
    fields = [
        SimpleNamespace(name="x", offset=0, datatype=7, count=1),
        SimpleNamespace(name="y", offset=4, datatype=7, count=1),
        SimpleNamespace(name="z", offset=8, datatype=7, count=1),
        SimpleNamespace(name="intensity", offset=12, datatype=2, count=1),
        SimpleNamespace(name="tag", offset=13, datatype=2, count=1),
        SimpleNamespace(name="line", offset=14, datatype=2, count=1),
        SimpleNamespace(name="offset_time", offset=16, datatype=6, count=1),
    ]
    return SimpleNamespace(
        header=SimpleNamespace(
            stamp=SimpleNamespace(sec=12, nanosec=345), frame_id="livox_frame"
        ),
        height=1,
        width=count,
        fields=fields,
        is_bigendian=False,
        point_step=20,
        row_step=count * 20,
        data=bytes(data),
        is_dense=True,
    )


def snapshot_options(**changes) -> ConversionOptions:
    values = {
        "acquisition_mode": "snapshot",
        "scan_period_ns": 100_000_000,
        "min_finite_points": 2500,
        "noise_std_m": 0.0,
        "dropout_probability": 0.0,
        "random_seed": 7,
        "reflectivity_override": None,
        "tag_override": None,
        "line_override": None,
    }
    values.update(changes)
    return ConversionOptions(**values)


def test_snapshot_cloud_decodes_exact_livox_contract():
    converted = decode_pointcloud(make_cloud(), snapshot_options())

    assert converted.timebase == 12_000_000_345
    assert converted.frame_id == "livox_frame"
    assert converted.point_num == 2500
    assert converted.xyz.shape == (2500, 3)
    assert converted.xyz.dtype == np.float32
    assert np.isfinite(converted.xyz).all()
    assert np.array_equal(converted.offset_time, np.zeros(2500, dtype=np.uint32))
    assert converted.reflectivity.min() == 100
    assert converted.lines.min() == 0 and converted.lines.max() == 5


def test_rolling_offsets_must_be_monotonic_and_bounded_by_scan_period():
    offsets = np.linspace(0, 99_000_000, 2500, dtype=np.uint32)
    converted = decode_pointcloud(
        make_cloud(offsets=offsets),
        snapshot_options(acquisition_mode="rolling"),
    )
    assert np.array_equal(converted.offset_time, offsets)

    offsets[100] = offsets[99] - 1
    with pytest.raises(ConversionError, match="monotonic"):
        decode_pointcloud(
            make_cloud(offsets=offsets),
            snapshot_options(acquisition_mode="rolling"),
        )

    too_late = np.linspace(0, 100_000_001, 2500, dtype=np.uint32)
    with pytest.raises(ConversionError, match="scan period"):
        decode_pointcloud(
            make_cloud(offsets=too_late),
            snapshot_options(acquisition_mode="rolling"),
        )


def test_snapshot_rejects_fabricated_nonzero_offsets():
    offsets = np.zeros(2500, dtype=np.uint32)
    offsets[-1] = 1

    with pytest.raises(ConversionError, match="snapshot offsets"):
        decode_pointcloud(make_cloud(offsets=offsets), snapshot_options())


def test_malformed_nonfinite_or_under_density_cloud_fails_closed():
    with pytest.raises(ConversionError, match="finite coordinates"):
        decode_pointcloud(make_cloud(nonfinite_index=10), snapshot_options())

    with pytest.raises(ConversionError, match="finite points"):
        decode_pointcloud(make_cloud(2499), snapshot_options())

    malformed = make_cloud()
    malformed.point_step = 24
    with pytest.raises(ConversionError, match="point_step"):
        decode_pointcloud(malformed, snapshot_options())

    wrong_field = make_cloud()
    wrong_field.fields[-1].offset = 15
    with pytest.raises(ConversionError, match="field layout"):
        decode_pointcloud(wrong_field, snapshot_options())


def test_configured_noise_dropout_and_metadata_overrides_are_deterministic():
    options = snapshot_options(
        min_finite_points=2500,
        noise_std_m=0.01,
        dropout_probability=0.05,
        reflectivity_override=42,
        tag_override=3,
        line_override=2,
    )
    source = make_cloud(3072)

    first = decode_pointcloud(source, options)
    second = decode_pointcloud(source, options)

    assert np.array_equal(first.xyz, second.xyz)
    assert np.array_equal(first.offset_time, second.offset_time)
    assert first.point_num >= 2500
    assert np.all(first.reflectivity == 42)
    assert np.all(first.tags == 3)
    assert np.all(first.lines == 2)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"acquisition_mode": "invented"}, "acquisition_mode"),
        ({"scan_period_ns": 0}, "scan_period_ns"),
        ({"min_finite_points": 0}, "min_finite_points"),
        ({"noise_std_m": -0.1}, "noise_std_m"),
        ({"dropout_probability": 1.0}, "dropout_probability"),
        ({"reflectivity_override": 256}, "reflectivity_override"),
        ({"tag_override": -1}, "tag_override"),
        ({"line_override": 256}, "line_override"),
    ],
)
def test_invalid_conversion_options_are_rejected(changes, message):
    with pytest.raises(ConversionError, match=message):
        decode_pointcloud(make_cloud(), snapshot_options(**changes))
