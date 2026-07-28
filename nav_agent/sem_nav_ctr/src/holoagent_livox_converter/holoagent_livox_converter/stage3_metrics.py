from __future__ import annotations

from dataclasses import dataclass
import math

import numpy as np


@dataclass(frozen=True)
class PoseSample:
    stamp_ns: int
    x: float
    y: float
    z: float
    yaw: float


@dataclass(frozen=True)
class Stage3Limits:
    duration_sec: float = 30.0
    min_estimate_hz: float = 5.0
    translation_rmse_m: float = 0.50
    translation_max_m: float = 1.50
    yaw_rmse_deg: float = 10.0
    min_excitation_m: float = 0.50
    min_excitation_yaw_deg: float = 20.0


def evaluate_stage3(
    ground_truth: tuple[PoseSample, ...],
    estimates: tuple[PoseSample, ...],
    *,
    limits: Stage3Limits,
    graph_approved: bool,
    use_sim_time: dict[str, bool],
    calibration_match: bool,
    perfect_odom_isolated: bool,
    sensor_contract: dict[str, object],
    message_errors: tuple[str, ...] = (),
) -> dict[str, object]:
    finite = _finite_monotonic(ground_truth) and _finite_monotonic(estimates)
    aligned, truth = _aligned_pairs(ground_truth, estimates) if finite else ([], [])
    translation_errors = [
        math.sqrt(
            (estimate.x - target.x) ** 2
            + (estimate.y - target.y) ** 2
            + (estimate.z - target.z) ** 2
        )
        for estimate, target in zip(aligned, truth)
    ]
    yaw_errors = [
        math.degrees(abs(_wrap(estimate.yaw - target.yaw)))
        for estimate, target in zip(aligned, truth)
    ]
    translation_rmse = _rmse(translation_errors)
    translation_max = max(translation_errors, default=math.inf)
    yaw_rmse = _rmse(yaw_errors)
    estimate_hz = len(estimates) / limits.duration_sec
    excitation_m, excitation_yaw_deg = _excitation(truth)
    sensor_gates = sensor_contract.get("gates")
    sensor_contract_pass = (
        sensor_contract.get("status") == "PASS"
        and sensor_contract.get("label") == "PASS_SYNTHETIC_LIVOX"
        and isinstance(sensor_gates, dict)
        and bool(sensor_gates)
        and all(bool(value) for value in sensor_gates.values())
    )

    gates = {
        "graph": bool(graph_approved),
        "use_sim_time": bool(use_sim_time) and all(use_sim_time.values()),
        "calibration": bool(calibration_match),
        "sensor_contract": sensor_contract_pass,
        "perfect_odom_isolated": bool(perfect_odom_isolated),
        "message_finite": finite and not message_errors,
        "estimate_stream": len(aligned) >= math.ceil(
            limits.duration_sec * limits.min_estimate_hz
        ),
        "excitation": excitation_m >= limits.min_excitation_m
        and excitation_yaw_deg >= limits.min_excitation_yaw_deg,
        "translation_rmse": translation_rmse <= limits.translation_rmse_m,
        "translation_max": translation_max <= limits.translation_max_m,
        "yaw_rmse": yaw_rmse <= limits.yaw_rmse_deg,
    }
    first_failure = next((name for name, passed in gates.items() if not passed), None)
    passed = first_failure is None
    return {
        "stage": 3,
        "status": "PASS" if passed else "FAIL",
        "label": "PASS_LIO_ONLY" if passed else "FAIL_ESTIMATOR",
        "qualified_pass": "PASS_LIO_ONLY" if passed else None,
        "first_failing_gate": first_failure,
        "motion_enabled": False,
        "simulated_motion": True,
        "physical_motion": False,
        "postflight_pass": False,
        "gates": gates,
        "metrics": {
            "duration_sec": limits.duration_sec,
            "ground_truth_samples": len(ground_truth),
            "estimate_samples": len(estimates),
            "paired_samples": len(aligned),
            "estimate_hz": estimate_hz,
            "translation_rmse_m": translation_rmse,
            "translation_max_m": translation_max,
            "yaw_rmse_deg": yaw_rmse,
            "excitation_m": excitation_m,
            "excitation_yaw_deg": excitation_yaw_deg,
            "message_contract_errors": list(message_errors),
            "use_sim_time": dict(use_sim_time),
            "sensor_contract": sensor_contract,
        },
    }


def _aligned_pairs(
    ground_truth: tuple[PoseSample, ...], estimates: tuple[PoseSample, ...]
) -> tuple[list[PoseSample], list[PoseSample]]:
    if not ground_truth or not estimates:
        return [], []
    pairs = []
    for estimate in estimates:
        target = _interpolate(ground_truth, estimate.stamp_ns)
        if target is not None:
            pairs.append((estimate, target))
    if not pairs:
        return [], []
    first_estimate, first_truth = pairs[0]
    rotation = first_truth.yaw - first_estimate.yaw
    cosine, sine = math.cos(rotation), math.sin(rotation)
    aligned = []
    truth = []
    for estimate, target in pairs:
        dx = estimate.x - first_estimate.x
        dy = estimate.y - first_estimate.y
        aligned.append(
            PoseSample(
                estimate.stamp_ns,
                first_truth.x + cosine * dx - sine * dy,
                first_truth.y + sine * dx + cosine * dy,
                first_truth.z + estimate.z - first_estimate.z,
                _wrap(estimate.yaw + rotation),
            )
        )
        truth.append(target)
    return aligned, truth


def _interpolate(samples: tuple[PoseSample, ...], stamp_ns: int) -> PoseSample | None:
    stamps = [sample.stamp_ns for sample in samples]
    index = int(np.searchsorted(stamps, stamp_ns, side="left"))
    if index < len(samples) and samples[index].stamp_ns == stamp_ns:
        return samples[index]
    if index == 0 or index == len(samples):
        return None
    before, after = samples[index - 1], samples[index]
    fraction = (stamp_ns - before.stamp_ns) / (after.stamp_ns - before.stamp_ns)
    return PoseSample(
        stamp_ns,
        before.x + fraction * (after.x - before.x),
        before.y + fraction * (after.y - before.y),
        before.z + fraction * (after.z - before.z),
        _wrap(before.yaw + fraction * _wrap(after.yaw - before.yaw)),
    )


def _finite_monotonic(samples: tuple[PoseSample, ...]) -> bool:
    return bool(samples) and all(
        current.stamp_ns > previous.stamp_ns
        and all(
            math.isfinite(value)
            for value in (current.x, current.y, current.z, current.yaw)
        )
        for previous, current in zip(samples, samples[1:])
    ) and all(
        math.isfinite(value)
        for value in (samples[0].x, samples[0].y, samples[0].z, samples[0].yaw)
    )


def _excitation(samples: list[PoseSample]) -> tuple[float, float]:
    if len(samples) < 2:
        return 0.0, 0.0
    first = samples[0]
    displacement = max(
        math.hypot(sample.x - first.x, sample.y - first.y) for sample in samples
    )
    yaw = max(math.degrees(abs(_wrap(sample.yaw - first.yaw))) for sample in samples)
    return displacement, yaw


def _rmse(values: list[float]) -> float:
    return math.sqrt(sum(value * value for value in values) / len(values)) if values else math.inf


def _wrap(angle: float) -> float:
    return math.atan2(math.sin(angle), math.cos(angle))
