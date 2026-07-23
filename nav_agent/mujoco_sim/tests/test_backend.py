from __future__ import annotations

import collections
from pathlib import Path
import threading
import sys
from types import ModuleType

import numpy as np
import pytest
import torch
import yaml

from holoagent_mujoco.backend import (
    BackendError,
    MujocoBackend,
    load_runner_module,
    make_controller_class,
)
from holoagent_mujoco.command import VelocityCommand
from holoagent_mujoco.config import file_sha256, load_mapping
from test_config import valid_mapping


class FakeOpt:
    timestep = 0.005


class FakeModel:
    def __init__(self):
        self.opt = FakeOpt()
        self.nu = 3
        self.actuator_trnid = np.array([[1, 0], [2, 0], [3, 0]])
        self.jnt_actfrclimited = np.array([0, 1, 1, 1])
        self.jnt_actfrcrange = np.array(
            [[0.0, 0.0], [-10.0, 10.0], [-10.0, 10.0], [-5.0, 5.0]]
        )


class FakeData:
    def __init__(self):
        self.time = 0.0
        self.qpos = np.zeros(10)
        self.qpos[2] = 0.8
        self.qpos[3] = 1.0
        self.qpos[7:10] = [0.0, 0.0, 1.0]
        self.qvel = np.zeros(9)
        self.ctrl = np.zeros(3)
        self.sensordata = np.array([0.1, 0.2, 0.3, 0.0, 0.0, 9.81])
        self.ncon = 2
        identity = np.eye(3).reshape(9)
        yaw_90 = np.array(
            [[0.0, -1.0, 0.0], [1.0, 0.0, 0.0], [0.0, 0.0, 1.0]]
        )
        camera_axes = np.array(
            [[0.0, 0.0, -1.0], [-1.0, 0.0, 0.0], [0.0, 1.0, 0.0]]
        )
        self.xpos = np.array([[0.0, 0.0, 0.8]])
        self.xmat = np.array([identity])
        self.site_xpos = np.array([[0.1, 0.2, 1.1]])
        self.site_xmat = np.array([yaw_90.reshape(9)])
        self.cam_xpos = np.array([[0.4, -0.1, 1.3]])
        self.cam_xmat = np.array([camera_axes.reshape(9)])


class FakeMujoco:
    class mjtObj:
        mjOBJ_BODY = 1
        mjOBJ_SITE = 2
        mjOBJ_CAMERA = 3

    @staticmethod
    def mj_name2id(model, object_type, name):
        return {
            (1, "pelvis"): 0,
            (2, "imu_in_torso"): 0,
            (3, "head_camera"): 0,
        }.get((object_type, name), -1)

    @staticmethod
    def mj_step(model, data):
        data.time += model.opt.timestep


class FrozenTimeMujoco:
    mjtObj = FakeMujoco.mjtObj
    mj_name2id = FakeMujoco.mj_name2id

    @staticmethod
    def mj_step(model, data):
        pass


class FakeController:
    def __init__(self):
        self.model = FakeModel()
        self.data = FakeData()
        self.n_joints = 3
        self.base_index = 0
        self.config = {
            "num_actions": 2,
            "kps": np.array([100.0, 100.0]),
            "kds": np.array([0.0, 0.0]),
            "default_angles": np.array([1.0, -1.0]),
            "control_decimation": 2,
            "action_scale": 0.25,
        }
        self.control_dict = {"loco_cmd": np.zeros(3)}
        self.cmd_lock = threading.Lock()
        self.action = np.zeros(2, dtype=np.float32)
        self.target_dof_pos = self.config["default_angles"].copy()
        self.single_obs_dim = 4
        self.obs_history = collections.deque(
            [np.zeros(4), np.zeros(4)], maxlen=2
        )
        self.obs = np.zeros(8, dtype=np.float32)
        self.balance_calls = 0
        self.walk_calls = 0
        self.policy = self._balance
        self.walk_policy = self._walk

    @staticmethod
    def pd_control(target_q, q, kp, target_dq, dq, kd):
        return (target_q - q) * kp + (target_dq - dq) * kd

    def compute_observation(self, data, config, action, control_dict, n_joints):
        command = np.asarray(control_dict["loco_cmd"], dtype=np.float32)
        return np.array([*command, float(data.time)], dtype=np.float32), 4

    def _balance(self, observation):
        self.balance_calls += 1
        return torch.tensor([[0.2, -0.2]], dtype=torch.float32)

    def _walk(self, observation):
        self.walk_calls += 1
        return torch.tensor([[0.4, -0.4]], dtype=torch.float32)


def test_load_runner_module_uses_the_configured_file(tmp_path):
    runner = tmp_path / "runner.py"
    runner.write_text("class GearWbcController: pass\n", encoding="utf-8")

    module = load_runner_module(runner)

    assert module.GearWbcController.__module__ == module.__name__
    assert Path(module.__file__) == runner


def test_load_runner_module_rejects_forbidden_transport_import_delta(tmp_path):
    forbidden_name = "unitree" + "_sdk2py"
    sys.modules[forbidden_name] = ModuleType(forbidden_name)
    runner = tmp_path / "runner.py"
    runner.write_text(
        f"import {forbidden_name}\nclass GearWbcController: pass\n",
        encoding="utf-8",
    )
    try:
        with pytest.raises(BackendError, match="forbidden transport"):
            load_runner_module(runner)
    finally:
        sys.modules.pop(forbidden_name, None)


def test_controller_adapter_overrides_paths_keyboard_and_cpu_provider(tmp_path):
    raw = valid_mapping()
    config_file = tmp_path / "controller.yaml"
    config_file.write_text(
        yaml.safe_dump(
            {
                "policy_path": "missing-balance.onnx",
                "walk_policy_path": "missing-walk.onnx",
                "xml_path": "missing.xml",
                "kps": [1.0],
                "kds": [0.1],
                "default_angles": [0.0],
                "cmd_scale": [1.0, 1.0, 1.0],
                "cmd_init": [0.0, 0.0, 0.0],
            }
        ),
        encoding="utf-8",
    )
    raw["backend"]["config_yaml"] = str(config_file)
    raw["backend"]["expected_sha256"]["config_yaml"] = file_sha256(config_file)
    cfg = load_mapping(raw)
    generated_xml = tmp_path / "generated.xml"
    generated_xml.write_text("<mujoco/>", encoding="utf-8")

    class FakeSession:
        calls = []

        def __init__(self, path, providers):
            self.calls.append((str(path), tuple(providers)))

        def get_inputs(self):
            return [type("Input", (), {"name": "obs"})()]

        def run(self, outputs, inputs):
            return [np.array([[1.0]], dtype=np.float32)]

    class FakeOrt:
        InferenceSession = FakeSession

    class BaseController:
        def __init__(self, config_path):
            self.config = self.load_config("ignored")
            self.keyboard_started = False
            self.keyboard_listener({}, self.config)
            self.policy = self.load_onnx_policy(self.config["policy_path"])
            self.walk_policy = self.load_onnx_policy(self.config["walk_policy_path"])

        def keyboard_listener(self, control_dict, config):
            self.keyboard_started = True

    Adapter = make_controller_class(BaseController, cfg, generated_xml, FakeOrt)
    controller = Adapter(str(config_file.parent))

    assert controller.keyboard_started is False
    assert controller.config["xml_path"] == str(generated_xml)
    assert controller.config["policy_path"] == str(cfg.backend.balance_policy)
    assert controller.config["walk_policy_path"] == str(cfg.backend.walk_policy)
    assert all(isinstance(controller.config[key], np.ndarray) for key in (
        "kps", "kds", "default_angles", "cmd_scale", "cmd_init"
    ))
    assert FakeSession.calls == [
        (str(cfg.backend.balance_policy), ("CPUExecutionProvider",)),
        (str(cfg.backend.walk_policy), ("CPUExecutionProvider",)),
    ]
    output = controller.policy(torch.zeros((1, 1)))
    assert output.device.type == "cpu"


def test_step_clips_pd_torque_advances_time_and_returns_finite_snapshot():
    controller = FakeController()
    backend = MujocoBackend(controller, FakeMujoco)

    first = backend.step()

    assert first.sim_time == pytest.approx(0.005)
    assert controller.data.ctrl.tolist() == [10.0, -10.0, -5.0]
    assert np.isfinite(np.asarray(first.base_position)).all()
    assert np.isfinite(np.asarray(first.base_quaternion_wxyz)).all()
    assert first.imu_angular_velocity == (0.1, 0.2, 0.3)
    assert first.imu_linear_acceleration == (0.0, 0.0, 9.81)
    assert first.imu_position_in_base == pytest.approx((0.1, 0.2, 0.3))
    assert first.imu_quaternion_in_base_wxyz == pytest.approx(
        (2**-0.5, 0.0, 0.0, 2**-0.5)
    )
    assert first.camera_position_in_base == pytest.approx((0.4, -0.1, 0.5))
    assert first.contact_count == 2


def test_policy_decimation_selects_balance_then_walk():
    controller = FakeController()
    backend = MujocoBackend(controller, FakeMujoco)

    backend.step()
    backend.step()
    assert controller.balance_calls == 1
    assert controller.walk_calls == 0

    backend.set_command(VelocityCommand(0.10, 0.0, 0.0))
    backend.step()
    backend.step()
    assert controller.balance_calls == 1
    assert controller.walk_calls == 1


@pytest.mark.parametrize(
    "command",
    [
        VelocityCommand(float("nan"), 0.0, 0.0),
        VelocityCommand(0.0, float("inf"), 0.0),
        VelocityCommand(0.0, 0.0, float("-inf")),
    ],
)
def test_nonfinite_command_is_rejected_and_cleared(command):
    controller = FakeController()
    backend = MujocoBackend(controller, FakeMujoco)
    backend.set_command(VelocityCommand(0.1, 0.0, 0.0))

    with pytest.raises(BackendError, match="finite"):
        backend.set_command(command)

    assert controller.control_dict["loco_cmd"].tolist() == [0.0, 0.0, 0.0]


def test_nonmonotonic_mujoco_time_fails_closed():
    controller = FakeController()
    backend = MujocoBackend(controller, FrozenTimeMujoco)

    with pytest.raises(BackendError, match="advance"):
        backend.step()

    assert np.count_nonzero(controller.data.ctrl) == 0
    assert controller.control_dict["loco_cmd"].tolist() == [0.0, 0.0, 0.0]


def test_close_commands_zero_and_is_idempotent():
    controller = FakeController()
    backend = MujocoBackend(controller, FakeMujoco)
    backend.set_command(VelocityCommand(0.1, 0.0, 0.0))
    backend.step()

    backend.close()
    backend.close()

    assert np.count_nonzero(controller.data.ctrl) == 0
    assert controller.control_dict["loco_cmd"].tolist() == [0.0, 0.0, 0.0]
    with pytest.raises(BackendError, match="closed"):
        backend.step()
