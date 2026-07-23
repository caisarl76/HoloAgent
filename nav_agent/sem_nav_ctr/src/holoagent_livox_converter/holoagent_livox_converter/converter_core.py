from __future__ import annotations

from dataclasses import dataclass
import math

import numpy as np


class ConversionError(RuntimeError):
    """Raised when a raw point cloud cannot satisfy the Livox contract."""


@dataclass(frozen=True)
class ConversionOptions:
    acquisition_mode: str
    scan_period_ns: int
    min_finite_points: int
    noise_std_m: float
    dropout_probability: float
    random_seed: int
    reflectivity_override: int | None
    tag_override: int | None
    line_override: int | None


@dataclass(frozen=True)
class ConvertedCloud:
    timebase: int
    frame_id: str
    xyz: np.ndarray
    reflectivity: np.ndarray
    tags: np.ndarray
    lines: np.ndarray
    offset_time: np.ndarray

    @property
    def point_num(self) -> int:
        return len(self.xyz)


_EXPECTED_FIELDS = {
    "x": (0, 7, 1),
    "y": (4, 7, 1),
    "z": (8, 7, 1),
    "intensity": (12, 2, 1),
    "tag": (13, 2, 1),
    "line": (14, 2, 1),
    "offset_time": (16, 6, 1),
}
_POINT_DTYPE = np.dtype(
    [
        ("x", "<f4"),
        ("y", "<f4"),
        ("z", "<f4"),
        ("intensity", "u1"),
        ("tag", "u1"),
        ("line", "u1"),
        ("padding", "u1"),
        ("offset_time", "<u4"),
    ]
)


def decode_pointcloud(message, options: ConversionOptions) -> ConvertedCloud:
    _validate_options(options)
    if bool(message.is_bigendian):
        raise ConversionError("big-endian PointCloud2 is not supported")
    if int(message.height) != 1:
        raise ConversionError("PointCloud2 height must be one")
    count = int(message.width)
    if int(message.point_step) != _POINT_DTYPE.itemsize:
        raise ConversionError("PointCloud2 point_step must be 20")
    if int(message.row_step) != count * _POINT_DTYPE.itemsize:
        raise ConversionError("PointCloud2 row_step is inconsistent")
    if len(message.data) != int(message.row_step):
        raise ConversionError("PointCloud2 data length is inconsistent")
    fields = {
        field.name: (int(field.offset), int(field.datatype), int(field.count))
        for field in message.fields
    }
    for name, expected in _EXPECTED_FIELDS.items():
        if fields.get(name) != expected:
            raise ConversionError(f"PointCloud2 field layout mismatch: {name}")

    packed = np.frombuffer(message.data, dtype=_POINT_DTYPE, count=count)
    xyz = np.column_stack((packed["x"], packed["y"], packed["z"])).astype(
        np.float32, copy=False
    )
    if not np.isfinite(xyz).all():
        raise ConversionError("PointCloud2 must contain only finite coordinates")
    offsets = packed["offset_time"].astype(np.uint32, copy=True)
    if options.acquisition_mode == "snapshot":
        if np.any(offsets != 0):
            raise ConversionError("snapshot offsets must all be zero")
    else:
        if np.any(np.diff(offsets.astype(np.int64)) < 0):
            raise ConversionError("rolling offsets must be monotonic")
        if len(offsets) and int(offsets[-1]) > options.scan_period_ns:
            raise ConversionError("rolling offsets exceed the scan period")

    generator = np.random.default_rng(options.random_seed)
    if options.noise_std_m > 0.0:
        ranges = np.linalg.norm(xyz, axis=1)
        if np.any(ranges <= 0.0):
            raise ConversionError("point ranges must be positive before adding noise")
        noisy_ranges = ranges + generator.normal(0.0, options.noise_std_m, count)
        if np.any(noisy_ranges <= 0.0) or not np.isfinite(noisy_ranges).all():
            raise ConversionError("configured noise produced invalid point ranges")
        xyz = (xyz / ranges[:, None] * noisy_ranges[:, None]).astype(np.float32)
    retained = generator.random(count) >= options.dropout_probability
    xyz = xyz[retained].copy()
    offsets = offsets[retained]
    reflectivity = packed["intensity"][retained].astype(np.uint8, copy=True)
    tags = packed["tag"][retained].astype(np.uint8, copy=True)
    lines = packed["line"][retained].astype(np.uint8, copy=True)
    if options.reflectivity_override is not None:
        reflectivity.fill(options.reflectivity_override)
    if options.tag_override is not None:
        tags.fill(options.tag_override)
    if options.line_override is not None:
        lines.fill(options.line_override)
    if len(xyz) < options.min_finite_points:
        raise ConversionError(
            "converted cloud contains too few finite points: "
            f"{len(xyz)} < {options.min_finite_points}"
        )

    stamp = message.header.stamp
    seconds = int(stamp.sec)
    nanoseconds = int(stamp.nanosec)
    if seconds < 0 or nanoseconds < 0 or nanoseconds >= 1_000_000_000:
        raise ConversionError("PointCloud2 stamp is invalid")
    timebase = seconds * 1_000_000_000 + nanoseconds
    for array in (xyz, offsets, reflectivity, tags, lines):
        array.setflags(write=False)
    return ConvertedCloud(
        timebase=timebase,
        frame_id=str(message.header.frame_id),
        xyz=xyz,
        reflectivity=reflectivity,
        tags=tags,
        lines=lines,
        offset_time=offsets,
    )


def _validate_options(options: ConversionOptions) -> None:
    if options.acquisition_mode not in {"snapshot", "rolling"}:
        raise ConversionError("acquisition_mode must be snapshot or rolling")
    if options.scan_period_ns <= 0 or options.scan_period_ns > np.iinfo(np.uint32).max:
        raise ConversionError("scan_period_ns must fit positive uint32 nanoseconds")
    if options.min_finite_points <= 0:
        raise ConversionError("min_finite_points must be positive")
    if not math.isfinite(options.noise_std_m) or options.noise_std_m < 0.0:
        raise ConversionError("noise_std_m must be finite and non-negative")
    if not math.isfinite(options.dropout_probability) or not (
        0.0 <= options.dropout_probability < 1.0
    ):
        raise ConversionError("dropout_probability must be in [0, 1)")
    for name, value in (
        ("reflectivity_override", options.reflectivity_override),
        ("tag_override", options.tag_override),
        ("line_override", options.line_override),
    ):
        if value is not None and not 0 <= value <= 255:
            raise ConversionError(f"{name} must be None or in [0, 255]")
