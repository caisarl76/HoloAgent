from __future__ import annotations

import collections
from dataclasses import dataclass
import hashlib
import importlib
import importlib.util
import math
from pathlib import Path
import sys
from types import ModuleType
from typing import Any

import numpy as np
import torch
import yaml

from holoagent_mujoco.command import VelocityCommand
from holoagent_mujoco.config import Stage1Config


class BackendError(RuntimeError):
    """Raised when the controller or MuJoCo violates the Stage 1 contract."""


@dataclass(frozen=True)
class BackendSnapshot:
    sim_time: float
    base_position: tuple[float, float, float]
    base_quaternion_wxyz: tuple[float, float, float, float]
    base_linear_velocity: tuple[float, float, float]
    base_angular_velocity: tuple[float, float, float]
    imu_angular_velocity: tuple[float, float, float]
    imu_linear_acceleration: tuple[float, float, float]
    applied_command: VelocityCommand
    contact_count: int


def load_runner_module(path: Path) -> ModuleType:
    runner = Path(path).expanduser().resolve()
    if not runner.is_file():
        raise BackendError(f"runner does not exist: {runner}")
    suffix = hashlib.sha256(str(runner).encode("utf-8")).hexdigest()[:12]
    name = f"holoagent_direct_runner_{suffix}"
    spec = importlib.util.spec_from_file_location(name, runner)
    if spec is None or spec.loader is None:
        raise BackendError(f"cannot load runner module: {runner}")

    module = importlib.util.module_from_spec(spec)
    keyboard_module = ModuleType("pynput.keyboard")
    keyboard_module.Listener = _DisabledListener
    input_module = ModuleType("pynput")
    input_module.keyboard = keyboard_module
    saved_modules = {
        key: sys.modules.get(key) for key in ("pynput", "pynput.keyboard")
    }
    sys.modules["pynput"] = input_module
    sys.modules["pynput.keyboard"] = keyboard_module
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(name, None)
        raise BackendError(f"failed to import runner: {runner}") from exc
    finally:
        for key, previous in saved_modules.items():
            if previous is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = previous

    if not hasattr(module, "GearWbcController"):
        raise BackendError("runner has no GearWbcController")
    return module


def make_controller_class(
    base_class: type,
    config: Stage1Config,
    scene_xml: Path,
    ort_module: Any,
) -> type:
    scene_path = Path(scene_xml).expanduser().resolve()
    if not scene_path.is_file():
        raise BackendError(f"generated scene does not exist: {scene_path}")

    class DirectControllerAdapter(base_class):
        def keyboard_listener(self, control_dict, controller_config):
            return None

        def load_config(self, ignored_path):
            try:
                with config.backend.config_yaml.open("r", encoding="utf-8") as stream:
                    loaded = yaml.safe_load(stream)
            except (OSError, yaml.YAMLError) as exc:
                raise BackendError("failed to load controller YAML") from exc
            if not isinstance(loaded, dict):
                raise BackendError("controller YAML root must be a mapping")

            loaded["xml_path"] = str(scene_path)
            loaded["policy_path"] = str(config.backend.balance_policy)
            loaded["walk_policy_path"] = str(config.backend.walk_policy)
            for key in ("kps", "kds", "default_angles", "cmd_scale", "cmd_init"):
                if key not in loaded:
                    raise BackendError(f"controller YAML missing {key}")
                loaded[key] = np.asarray(loaded[key], dtype=np.float32)
            return loaded

        def load_onnx_policy(self, path):
            return _load_cpu_policy(
                Path(path), config.backend.onnx_providers, ort_module
            )

    DirectControllerAdapter.__name__ = "HoloAgentDirectController"
    return DirectControllerAdapter


def create_backend(config: Stage1Config, scene_xml: Path) -> MujocoBackend:
    runner_module = load_runner_module(config.backend.runner)
    ort_module = importlib.import_module("onnxruntime")
    mujoco_module = importlib.import_module("mujoco")
    adapter_class = make_controller_class(
        runner_module.GearWbcController, config, scene_xml, ort_module
    )
    try:
        controller = adapter_class(str(config.backend.config_yaml.parent))
    except Exception as exc:
        raise BackendError("failed to initialize the direct GR00T controller") from exc

    expected_timestep = 1.0 / config.rates.physics_hz
    actual_timestep = float(controller.model.opt.timestep)
    if not math.isclose(actual_timestep, expected_timestep, abs_tol=1e-12):
        raise BackendError(
            f"controller timestep {actual_timestep} does not match {expected_timestep}"
        )
    return MujocoBackend(controller, mujoco_module)


class MujocoBackend:
    """Deterministic single-step adapter around the direct GR00T controller."""

    def __init__(self, controller: Any, mujoco_module: Any) -> None:
        self.controller = controller
        self.model = controller.model
        self.data = controller.data
        self._mujoco = mujoco_module
        self._counter = 0
        self._closed = False
        self._renderer = None
        self._last_time = float(self.data.time)
        self._validate_dimensions()

    def set_command(self, command: VelocityCommand) -> None:
        if self._closed:
            raise BackendError("backend is closed")
        values = (command.x, command.y, command.yaw)
        if not all(math.isfinite(float(value)) for value in values):
            self._zero_outputs()
            raise BackendError("command values must be finite")
        self._write_command(command)

    def step(self) -> BackendSnapshot:
        if self._closed:
            raise BackendError("backend is closed")
        before = float(self.data.time)
        try:
            self._apply_pd_torques()
            self._mujoco.mj_step(self.model, self.data)
            after = float(self.data.time)
            if not math.isfinite(after) or after <= before or after <= self._last_time:
                raise BackendError("MuJoCo data.time did not advance monotonically")
            self._last_time = after
            self._counter += 1
            if self._counter % int(self.controller.config["control_decimation"]) == 0:
                self._update_policy()
            return self.snapshot()
        except Exception as exc:
            self._zero_outputs()
            if isinstance(exc, BackendError):
                raise
            raise BackendError("controller or physics step failed") from exc

    def snapshot(self) -> BackendSnapshot:
        try:
            snapshot = BackendSnapshot(
                sim_time=float(self.data.time),
                base_position=_finite_tuple(self.data.qpos[0:3], 3, "base position"),
                base_quaternion_wxyz=_finite_tuple(
                    self.data.qpos[3:7], 4, "base quaternion"
                ),
                base_linear_velocity=_finite_tuple(
                    self.data.qvel[0:3], 3, "base linear velocity"
                ),
                base_angular_velocity=_finite_tuple(
                    self.data.qvel[3:6], 3, "base angular velocity"
                ),
                imu_angular_velocity=_finite_tuple(
                    self.data.sensordata[0:3], 3, "IMU angular velocity"
                ),
                imu_linear_acceleration=_finite_tuple(
                    self.data.sensordata[3:6], 3, "IMU linear acceleration"
                ),
                applied_command=self._read_command(),
                contact_count=int(self.data.ncon),
            )
        except (IndexError, TypeError, ValueError) as exc:
            raise BackendError("invalid backend snapshot") from exc
        if not math.isfinite(snapshot.sim_time):
            raise BackendError("snapshot time must be finite")
        return snapshot

    def render_rgb(self, *, camera: str, width: int, height: int) -> np.ndarray:
        if self._closed:
            raise BackendError("backend is closed")
        try:
            if self._renderer is None:
                self._renderer = self._mujoco.Renderer(
                    self.model, height=height, width=width
                )
            self._renderer.update_scene(self.data, camera=camera)
            image = np.asarray(self._renderer.render()).copy()
        except Exception as exc:
            self._zero_outputs()
            raise BackendError("camera rendering failed") from exc
        if image.shape != (height, width, 3) or image.dtype != np.uint8:
            self._zero_outputs()
            raise BackendError("camera returned an invalid RGB image")
        return image

    def close(self) -> None:
        if self._closed:
            return
        self._zero_outputs()
        if self._renderer is not None:
            self._renderer.close()
            self._renderer = None
        self._closed = True

    def _validate_dimensions(self) -> None:
        required = ("num_actions", "control_decimation", "default_angles")
        for key in required:
            if key not in self.controller.config:
                raise BackendError(f"controller config missing {key}")
        actions = int(self.controller.config["num_actions"])
        if actions <= 0 or actions > int(self.controller.n_joints):
            raise BackendError("invalid num_actions")
        if int(self.controller.config["control_decimation"]) <= 0:
            raise BackendError("control_decimation must be positive")
        if int(self.model.nu) < int(self.controller.n_joints):
            raise BackendError("model has fewer actuators than joints")

    def _apply_pd_torques(self) -> None:
        actions = int(self.controller.config["num_actions"])
        joints = int(self.controller.n_joints)
        leg_tau = self.controller.pd_control(
            self.controller.target_dof_pos,
            self.data.qpos[7 : 7 + actions],
            self.controller.config["kps"],
            np.zeros(actions, dtype=np.float32),
            self.data.qvel[6 : 6 + actions],
            self.controller.config["kds"],
        )
        torque = np.zeros(joints, dtype=np.float64)
        torque[:actions] = np.asarray(leg_tau, dtype=np.float64)
        if joints > actions:
            arm_count = joints - actions
            arm_tau = self.controller.pd_control(
                np.zeros(arm_count, dtype=np.float32),
                self.data.qpos[7 + actions : 7 + joints],
                np.full(arm_count, 100.0),
                np.zeros(arm_count),
                self.data.qvel[6 + actions : 6 + joints],
                np.full(arm_count, 0.5),
            )
            torque[actions:] = np.asarray(arm_tau, dtype=np.float64)
        if not np.isfinite(torque).all():
            raise BackendError("PD controller produced non-finite torque")
        self.data.ctrl[:joints] = self._clip_torques(torque)

    def _clip_torques(self, torque: np.ndarray) -> np.ndarray:
        clipped = torque.copy()
        actuator_joints = np.asarray(self.model.actuator_trnid)[:, 0]
        for actuator, joint in enumerate(actuator_joints[: len(clipped)]):
            if joint < 0 or not self.model.jnt_actfrclimited[joint]:
                continue
            lower, upper = self.model.jnt_actfrcrange[joint]
            clipped[actuator] = np.clip(clipped[actuator], lower, upper)
        return clipped

    def _update_policy(self) -> None:
        with self.controller.cmd_lock:
            current = dict(self.controller.control_dict)
            current["loco_cmd"] = np.asarray(current["loco_cmd"]).copy()
        observation, dimension = self.controller.compute_observation(
            self.data,
            self.controller.config,
            self.controller.action,
            current,
            self.controller.n_joints,
        )
        if int(dimension) != int(self.controller.single_obs_dim):
            raise BackendError("controller observation dimension changed")
        observation = np.asarray(observation, dtype=np.float32)
        if observation.shape != (self.controller.single_obs_dim,):
            raise BackendError("controller observation has the wrong shape")
        if not np.isfinite(observation).all():
            raise BackendError("controller observation must be finite")
        self.controller.obs_history.append(observation)
        for index, history in enumerate(self.controller.obs_history):
            start = index * self.controller.single_obs_dim
            end = start + self.controller.single_obs_dim
            self.controller.obs[start:end] = history

        tensor = torch.from_numpy(self.controller.obs).unsqueeze(0)
        command_norm = float(np.linalg.norm(current["loco_cmd"]))
        policy = (
            self.controller.policy
            if command_norm <= 0.05
            else self.controller.walk_policy
        )
        action = policy(tensor)
        if isinstance(action, torch.Tensor):
            action = action.detach().cpu().numpy()
        action = np.asarray(action, dtype=np.float32).squeeze()
        actions = int(self.controller.config["num_actions"])
        if action.shape != (actions,) or not np.isfinite(action).all():
            raise BackendError("policy action must be a finite action vector")
        self.controller.action = action
        defaults = np.asarray(self.controller.config["default_angles"])
        if defaults.shape != (actions,):
            raise BackendError("default_angles must match num_actions")
        self.controller.target_dof_pos = (
            action * float(self.controller.config["action_scale"]) + defaults
        )

    def _write_command(self, command: VelocityCommand) -> None:
        values = np.array([command.x, command.y, command.yaw], dtype=np.float32)
        with self.controller.cmd_lock:
            target = self.controller.control_dict["loco_cmd"]
            if np.asarray(target).shape != (3,):
                raise BackendError("controller loco_cmd must have shape (3,)")
            target[:] = values

    def _read_command(self) -> VelocityCommand:
        with self.controller.cmd_lock:
            values = np.asarray(self.controller.control_dict["loco_cmd"]).copy()
        return VelocityCommand(float(values[0]), float(values[1]), float(values[2]))

    def _zero_outputs(self) -> None:
        try:
            with self.controller.cmd_lock:
                self.controller.control_dict["loco_cmd"][:] = 0.0
        finally:
            self.data.ctrl[:] = 0.0


def _load_cpu_policy(path: Path, providers: tuple[str, ...], ort_module: Any):
    session = ort_module.InferenceSession(str(path), providers=list(providers))
    inputs = session.get_inputs()
    if len(inputs) != 1:
        raise BackendError("ONNX policy must have exactly one input")
    input_name = inputs[0].name

    def infer(input_tensor: torch.Tensor) -> torch.Tensor:
        array = input_tensor.detach().cpu().numpy()
        outputs = session.run(None, {input_name: array})
        if len(outputs) != 1:
            raise BackendError("ONNX policy must have exactly one output")
        return torch.from_numpy(np.asarray(outputs[0], dtype=np.float32))

    return infer


def _finite_tuple(values: Any, length: int, label: str) -> tuple[float, ...]:
    array = np.asarray(values, dtype=np.float64)
    if array.shape != (length,) or not np.isfinite(array).all():
        raise BackendError(f"{label} must contain {length} finite values")
    return tuple(float(value) for value in array)


class _DisabledListener:
    def __init__(self, *args, **kwargs) -> None:
        pass

    def start(self) -> None:
        raise BackendError("keyboard listeners are disabled")
