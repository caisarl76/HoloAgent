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
