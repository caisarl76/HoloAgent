from __future__ import annotations

import argparse
import json
from pathlib import Path
import time
from typing import Any, Mapping

from holoagent_mujoco.config import file_sha256
from holoagent_mujoco.stage4_config import load_stage4_config
from holoagent_mujoco.stage4_map import verify_loaded_map
from holoagent_mujoco.stage4_nav import validate_nav2_parameters


class Stage4ActivationError(RuntimeError):
    """Raised when Nav2 cannot be approved before lifecycle activation."""


MANAGED_PARAMETER_NODES = (
    "map_server",
    "planner_server",
    "controller_server",
    "bt_navigator",
    "global_costmap/global_costmap",
    "local_costmap/local_costmap",
    "lifecycle_manager_stage4",
)


def validate_pre_activation_contract(
    *,
    config_path: Path,
    manifest_path: Path,
    live_parameters: Mapping[str, Mapping[str, Any]],
) -> dict[str, object]:
    config = load_stage4_config(config_path, validate_bridge_artifacts=False)
    manifest_source = Path(manifest_path).expanduser().resolve()
    try:
        manifest = json.loads(manifest_source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Stage4ActivationError("cannot read Stage 4 manifest") from exc
    if manifest.get("config_sha256") != file_sha256(config.source_path):
        raise Stage4ActivationError("Stage 4 config digest changed before activation")
    if set(live_parameters) != set(MANAGED_PARAMETER_NODES):
        raise Stage4ActivationError("live Nav2 parameter-node set is incomplete")
    normalized = {
        name: dict(parameters) for name, parameters in live_parameters.items()
    }
    if not all(
        parameters.get("use_sim_time") is True for parameters in normalized.values()
    ):
        raise Stage4ActivationError("every live Nav2 node must use_sim_time=true")

    nav2 = manifest.get("nav2")
    map_evidence = manifest.get("map")
    if not isinstance(nav2, dict) or not isinstance(map_evidence, dict):
        raise Stage4ActivationError("Stage 4 manifest map/Nav2 evidence is missing")
    runtime_params = Path(str(nav2.get("runtime_params_path", ""))).resolve()
    if not runtime_params.is_file() or file_sha256(runtime_params) != nav2.get(
        "runtime_params_sha256"
    ):
        raise Stage4ActivationError("runtime Nav2 parameter digest mismatch")
    nav_contract = validate_nav2_parameters(
        runtime_params,
        bridge=config.bridge,
        inflation_radius_m=config.map.inflation_radius_m,
    )
    loaded_map = verify_loaded_map(
        Path(str(normalized["map_server"].get("yaml_filename", ""))),
        expected_yaml_path=Path(str(map_evidence.get("yaml_path", ""))),
        expected_yaml_sha256=str(map_evidence.get("yaml_sha256", "")),
        expected_pgm_sha256=str(map_evidence.get("pgm_sha256", "")),
        prohibited_real_map_paths=config.map.prohibited_real_map_paths,
    )
    return {
        "status": "PRE_ACTIVATION_APPROVED",
        "manifest_path": str(manifest_source),
        "manifest_sha256": file_sha256(manifest_source),
        "map": loaded_map,
        "nav2": nav_contract,
        "runtime_params_sha256": file_sha256(runtime_params),
        "live_parameters": normalized,
    }


def _write_json(path: Path, value: object) -> None:
    destination = Path(path).expanduser().resolve()
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(destination)


def activate_stage4(
    *, config_path: Path, manifest_path: Path, output_path: Path
) -> dict[str, object]:
    import rclpy
    from nav2_msgs.srv import ManageLifecycleNodes
    from rcl_interfaces.msg import ParameterType
    from rcl_interfaces.srv import GetParameters
    from rclpy.node import Node
    from rclpy.parameter import Parameter
    from std_srvs.srv import Trigger

    class ActivationNode(Node):
        def __init__(self) -> None:
            super().__init__(
                "holoagent_stage4_pre_activation",
                parameter_overrides=[
                    Parameter("use_sim_time", Parameter.Type.BOOL, True)
                ],
                automatically_declare_parameters_from_overrides=True,
            )
            self.parameter_clients = {
                name: self.create_client(GetParameters, f"/{name}/get_parameters")
                for name in MANAGED_PARAMETER_NODES
            }
            self.manage = self.create_client(
                ManageLifecycleNodes, "/lifecycle_manager_stage4/manage_nodes"
            )
            self.active = self.create_client(
                Trigger, "/lifecycle_manager_stage4/is_active"
            )
            self.deadline = time.monotonic() + 60.0

        def wait_future(self, future: Any, *, timeout_sec: float) -> Any:
            deadline = min(self.deadline, time.monotonic() + timeout_sec)
            while not future.done() and time.monotonic() < deadline:
                rclpy.spin_once(self, timeout_sec=0.05)
            if not future.done() or future.exception() is not None:
                raise Stage4ActivationError("pre-activation ROS request timed out")
            return future.result()

        def read_live_parameters(self) -> dict[str, dict[str, Any]]:
            values: dict[str, dict[str, Any]] = {}
            for name, client in self.parameter_clients.items():
                if not client.wait_for_service(timeout_sec=15.0):
                    raise Stage4ActivationError(
                        f"{name} parameter service unavailable before activation"
                    )
                names = ["use_sim_time"]
                if name == "map_server":
                    names.append("yaml_filename")
                response = self.wait_future(
                    client.call_async(GetParameters.Request(names=names)),
                    timeout_sec=5.0,
                )
                if response is None or len(response.values) != len(names):
                    raise Stage4ActivationError(f"{name} parameters unavailable")
                parameters: dict[str, Any] = {}
                for parameter, value in zip(names, response.values):
                    if value.type == ParameterType.PARAMETER_BOOL:
                        parameters[parameter] = bool(value.bool_value)
                    elif value.type == ParameterType.PARAMETER_STRING:
                        parameters[parameter] = str(value.string_value)
                    else:
                        raise Stage4ActivationError(
                            f"{name}.{parameter} has an unexpected type"
                        )
                values[name] = parameters
            return values

        def startup(self) -> None:
            if not self.manage.wait_for_service(timeout_sec=10.0):
                raise Stage4ActivationError("Nav2 lifecycle manager is unavailable")
            request = ManageLifecycleNodes.Request()
            request.command = ManageLifecycleNodes.Request.STARTUP
            response = self.wait_future(
                self.manage.call_async(request), timeout_sec=30.0
            )
            if response is None or not response.success:
                raise Stage4ActivationError("Nav2 lifecycle startup failed")
            if not self.active.wait_for_service(timeout_sec=5.0):
                raise Stage4ActivationError("Nav2 active-state service is unavailable")
            active = self.wait_future(
                self.active.call_async(Trigger.Request()), timeout_sec=5.0
            )
            if active is None or not active.success:
                raise Stage4ActivationError("Nav2 did not report active after startup")

    rclpy.init()
    node = ActivationNode()
    try:
        live = node.read_live_parameters()
        evidence = validate_pre_activation_contract(
            config_path=config_path,
            manifest_path=manifest_path,
            live_parameters=live,
        )
        node.startup()
        evidence["lifecycle_active"] = True
        _write_json(output_path, evidence)
        return evidence
    finally:
        node.destroy_node()
        if rclpy.ok():
            rclpy.shutdown()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate and activate the Stage 4 Nav2 lifecycle"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments, ros_arguments = parser.parse_known_args(argv)
    if ros_arguments:
        raise Stage4ActivationError("unexpected Stage 4 activation arguments")
    evidence = activate_stage4(
        config_path=arguments.config,
        manifest_path=arguments.manifest,
        output_path=arguments.output,
    )
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
