from pathlib import Path

from holoagent_livox_converter.stage3_eval import stage3_command


def test_stage3_excitation_is_bounded_nonholonomic_and_ends_zero():
    samples = [stage3_command(value) for value in (0.0, 2.0, 10.0, 16.0, 24.0, 30.0)]
    assert samples == [
        (0.0, 0.0, 0.0),
        (0.10, 0.0, 0.0),
        (0.0, 0.0, 0.15),
        (0.10, 0.0, 0.0),
        (0.0, 0.0, -0.15),
        (0.0, 0.0, 0.0),
    ]
    assert all(y == 0.0 for _, y, _ in samples)
    assert max(abs(x) for x, _, _ in samples) <= 0.22
    assert max(abs(yaw) for _, _, yaw in samples) <= 0.30


def test_stage3_evaluator_measures_stage2_sensor_contract_in_the_same_run():
    source = (
        Path(__file__).resolve().parents[1]
        / "holoagent_livox_converter"
        / "stage3_eval.py"
    ).read_text(encoding="utf-8")

    assert "Stage2Collector" in source
    assert "evaluate_stage2" in source
    assert '"/camera/color/image_raw"' in source and "self._camera" in source
    assert '"/holoagent_sim/lidar_points"' in source and "self._raw_lidar" in source
    assert '"/livox/lidar"' in source and "self._custom_lidar" in source
    assert "sensor_contract=sensor_contract" in source
