"""
LICENSE.

This project as a whole is licensed under the Apache License, Version 2.0.

THIRD-PARTY LICENSES

Third-party software already included in HoloAgent is governed by the separate
Open Source license terms under which the third-party software has been
distributed.

NOTICE ON LICENSE COMPATIBILITY FOR DISTRIBUTORS

Notably, this project depends on the third-party software FAST-LIVO2 and HOVSG.
Their default licenses restrict commercial use—separate permission from their
original authors is required for commercial integration/redistribution.

The third-party software FAST-LIVO2 dependency (licensed under GPL-2.0-only)
utilizes rpg_vikit-ros2 which contains components under the GPL-3.0. Please be
aware of license compatibility when distributing a combined work.

DISCLAIMER

Users are solely responsible for ensuring compliance with all applicable
license terms when using, modifying, or distributing the project. Project
maintainers accept no liability for any license violations arising from such
use.
"""
#!/usr/bin/env python3
import os
import rclpy
from rclpy.executors import ExternalShutdownException
from rclpy.node import Node
from geometry_msgs.msg import PoseStamped, Point, Quaternion
import math
from ament_index_python.packages import get_package_share_directory
from copy import deepcopy
import sys
from std_msgs.msg import String

from hmsg.graph.graph import Graph
import hydra
import open3d as o3d
from omegaconf import DictConfig
import time
import numpy as np

# pylint: disable=all

DEFAULT_ROOM_TYPES = [
    "Hallway",
    "Reception area",
    "Exhibition Hall",
    "Pantry",
    "Corner Hallway",
    "Elevator Lobby",
    "Lift",
    "Office",
    "Cafeteria",
]

ROOM_TYPE_PRESETS = {
    "icra_ic3f": [
        "Hallway",
        "Exhibition Hall",
        "none",
        "Elevator Lobby Reception Area",
    ],
    "icra_ic4f": [
        "Hallway",
        "Pantry",
        "Office",
    ],
    "icra_ic7f": [
        "Hallway",
        "Pantry",
        "Office",
        "Cafeteria",
    ],
    "icra_sh3f": [
        "Pantry",
        "Office",
        "Office-Pantry",
    ],
}

ROOM_METHOD_PRESETS = {
    "icra_ic3f": "view_embedding",
    "icra_ic4f": "label",
    "icra_ic7f": "obj_embedding",
    "icra_sh3f": "obj_embedding",
}

DESIGNATED_ROOM_NAME_PRESETS = {
    "digua": [
        "none",
        "none",
        "展厅",
        "none",
        "转角走廊",
        "走廊",
        "地瓜电梯间接待区",
    ],
    "ic7f_demo": [
        "none",
        "none",
        "办公区",
        "餐厅",
        "电梯间走廊",
        "茶水间",
        "办公休息区",
    ],
    "1014demo": [
        "转角走廊",
        "none",
        "长走廊",
        "地平线展厅",
        "none",
        "none",
        "长走廊",
        "接待区",
        "none",
        "地瓜办公区电梯间",
    ],
    "0918demo": [
        "接待区",
    ],
    "1028demo": [
        "none",
        "会议室",
        "实验室",
        "none",
        "none",
        "活动区",
    ],
    "1030demo": [
        "会议室",
        "户外",
        "活动区",
        "none",
        "none",
        "操作区",
        "会议室",
        "实验室",
        "活动区",
    ],
    "1127demo": [
        "none",
        "会议室",
        "电梯间",
        "活动区",
        "none",
        "活动区",
        "none",
    ],
}


def apply_env_overrides(params: DictConfig):
    env_overrides = [
        ("NAV_AGENT_DATASET_PATH", ("main", "dataset_path")),
        ("NAV_AGENT_GRAPH_PATH", ("main", "graph_path")),
        ("HMSG_GRAPH_PATH", ("main", "graph_path")),
        ("NAV_AGENT_SAVE_PATH", ("main", "save_path")),
        ("NAV_AGENT_CLIP_CHECKPOINT", ("models", "clip", "checkpoint")),
    ]

    for env_name, cfg_path in env_overrides:
        value = os.environ.get(env_name)
        if not value:
            continue

        cfg_node = params
        for key in cfg_path[:-1]:
            cfg_node = cfg_node[key]
        cfg_node[cfg_path[-1]] = value
        print(f"Using {env_name} override for {'.'.join(cfg_path)}: {value}")


def split_env_list(value: str):
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def env_bool(name: str, default: bool):
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def infer_scene_key(graph_path: str):
    graph_path = graph_path or ""
    for scene_key in ROOM_TYPE_PRESETS:
        if scene_key in graph_path:
            return scene_key
    return os.environ.get("NAV_AGENT_SCENE", "")


class GoalPosePublisher(Node):

    def __init__(self, cfg: DictConfig):
        super().__init__('goal_pose_publisher')

        # 创建发布者，消息类型为PoseStamped，话题名为/goal_pose，队列大小为10
        self.publisher_ = self.create_publisher(
            PoseStamped, '/object_pose', 10)
        self.waypoint_found_pub = self.create_publisher(
            String, 'waypoint_reached', 10)
        # 订阅String话题
        self.subscription = self.create_subscription(
            String,
            '/chat_loc_pub',
            self.hmsggetgoal_callback,
            10)
        # 设置定时器，每1秒发布一次目标位姿
        # timer_period = 1.0  # 秒
        # self.timer = self.create_timer(timer_period, self.timer_callback)
        self.count = 0
        self.params = cfg
        self.graph = Graph(cfg)
        self.T_switch_axis = np.array([[1, 0, 0, 0], [0, 0, 1, 0], [
                                      0, -1, 0, 0], [0, 0, 0, 1]], dtype=np.float64)  # g1_navi
        self.T_tomap = np.linalg.inv(self.T_switch_axis)
        self.scene_key = infer_scene_key(self.params.main.graph_path)
        self.query_method = os.environ.get(
            "NAV_AGENT_QUERY_METHOD",
            "icra" if self.scene_key.startswith("icra_") else "generic",
        ).strip().lower()
        self.hmsgcreate()
        # self.hmsggetgoal()

        # 初始化计数器

        self.get_logger().info('GoalPosePublisher 节点已启动，正在发布 /object_pose 话题...')
        # print(f"This node is running with Python at: {sys.executable}")

    def pubpose(self, x, y, z):
        # 创建PoseStamped消息
        msg = PoseStamped()

        # 设置消息头
        msg.header.stamp = self.get_clock().now().to_msg()
        msg.header.frame_id = 'map'  # 假设目标位姿在map坐标系中

        msg.pose.position.x = x
        msg.pose.position.y = y
        msg.pose.position.z = z
        msg.pose.orientation.x = 0.0
        msg.pose.orientation.y = 0.0
        msg.pose.orientation.z = 0.0
        msg.pose.orientation.w = 1.0
        # 设置目标朝向 - 这里使用简单的四元数表示
        # 让机器人始终朝向圆心
        # msg.pose.orientation = self.get_quaternion_from_euler(0, 0, angle + math.pi)

        # 发布消息
        self.publisher_.publish(msg)

        # 记录日志
        self.get_logger().info(
            f'发布第 {self.count} 个目标位姿: x={msg.pose.position.x:.2f}, y={msg.pose.position.y:.2f}, z={msg.pose.position.z:.2f}')

        # 增加计数器
        self.count += 1

    def hmsgcreate(self):
        # Load graph
        hmsg = self.graph
        hmsg.load_graph(self.params.main.graph_path)
        self.use_gpt = env_bool("NAV_AGENT_USE_GPT", bool(self.params.main.use_gpt))

        room_name_method = os.environ.get(
            "NAV_AGENT_ROOM_NAME_METHOD",
            ROOM_METHOD_PRESETS.get(self.scene_key, "view_embedding"),
        )
        room_types = split_env_list(os.environ.get("NAV_AGENT_ROOM_TYPES", ""))
        if not room_types:
            room_types = ROOM_TYPE_PRESETS.get(self.scene_key, DEFAULT_ROOM_TYPES)
        print(
            "Room naming config:",
            f"scene={self.scene_key or 'unknown'}",
            f"method={room_name_method}",
            f"types={room_types}",
            f"query_method={self.query_method}",
            f"use_gpt={self.use_gpt}",
        )

        hmsg.generate_room_names(
            generate_method=room_name_method,
            default_room_types=room_types,
        )

        designated_room_names = split_env_list(
            os.environ.get("NAV_AGENT_DESIGNATED_ROOM_NAMES", "")
        )
        room_profile = os.environ.get("NAV_AGENT_ROOM_PROFILE", "").strip()
        if room_profile:
            if room_profile not in DESIGNATED_ROOM_NAME_PRESETS:
                raise ValueError(
                    f"Unknown NAV_AGENT_ROOM_PROFILE={room_profile}. "
                    f"Available profiles: {sorted(DESIGNATED_ROOM_NAME_PRESETS)}"
                )
            designated_room_names = DESIGNATED_ROOM_NAME_PRESETS[room_profile]

        if designated_room_names:
            if len(designated_room_names) != len(hmsg.rooms):
                raise ValueError(
                    "Designated room names do not match graph room count: "
                    f"{len(designated_room_names)} names for {len(hmsg.rooms)} rooms. "
                    "Update NAV_AGENT_DESIGNATED_ROOM_NAMES/NAV_AGENT_ROOM_PROFILE "
                    "or unset them to use generated room names."
                )
            print(f"Using designated room names: {designated_room_names}")
            hmsg.set_room_names(room_names=designated_room_names)

    def hmsggetgoal_callback(self, msg):
        hmsg = self.graph
        query_instruction = '来自语音查找'
        ans = msg.data
        print(ans)
        start_time = time.time()
        if self.query_method == "icra":
            floor, room, obj, res_dict = hmsg.query_hierarchy_protected_icra(
                ans, top_k=1, use_gpt=self.use_gpt)
        else:
            floor, room, obj, res_dict = hmsg.query_hierarchy_protected(
                ans, top_k=1, use_gpt=self.use_gpt)
        end_time = time.time()
        print("obj: ", res_dict)
        object_scores = res_dict.get("object_scores", [])
        best_score = object_scores[0] if object_scores else None
        print("score: ", best_score)
        # print(type(res_dict))
        print(f"运行时间: {end_time - start_time:.4f} 秒")
        # save log for debug
        # 构建要写入 JSON 的数据
        # query_result = {
        #    "query": query_instruction,
        #    "room_query": res_dict["room_query"],
        #    "object_query": res_dict["object_query"],
        #    "time_seconds": query_time,
        #    "floor_id": floor.floor_id,
        #    "rooms": [{"room_id": r.room_id, "name": r.name} for r in room],
        #    "objects": [{"object_id": o.object_id} for o in obj],
        #    "objects_scores": res_dict["object_scores"]
        # }
        # print(query_result)
        if res_dict["object_query"] != 'unknown' and best_score is not None and best_score < 0.15:
            msg = String()
            msg.data = "not_found"
            self.waypoint_found_pub.publish(msg)
            print('not found')
            return
        elif (
            res_dict["room_query"] == 'unknown'
            and res_dict["object_query"] == 'unknown'
            and best_score is not None
            and best_score < 0.18
        ):
            return
        else:
            msg = String()
            msg.data = "found"
            self.waypoint_found_pub.publish(msg)
            print('found')

        # visualize the query
        print(floor.floor_id, [(r.room_id, r.name)
              for r in room], [o.object_id for o in obj])
        # use open3d to visualize room.pcd and color the points where obj.pcd
        # is
        print("len(obj): ", len(obj))
        for i in range(len(obj)):
            obj_pcd = obj[i].pcd.paint_uniform_color([1, 0, 0])  # rgb
            obj_pcd = deepcopy(obj[i].pcd)
            obj_center = obj_pcd.get_center()
            print("obj_center in scenegraph: ", obj_center)
            obj_center_h = np.hstack((obj_center, 1.0))  # 齐次坐标 (4,)
            obj_center_in_map = (self.T_tomap @ obj_center_h)[:3]
            print("obj_center in lidarmap: ", obj_center_in_map)
            self.pubpose(
                obj_center_in_map[0],
                obj_center_in_map[1],
                obj_center_in_map[2])


@hydra.main(version_base=None,
            config_path=get_package_share_directory('goal_publisher') + "/config",
            config_name="visualize_query_graph_demo")
def main(params: DictConfig, args=None):

    apply_env_overrides(params)

    # 初始化ROS2 Python客户端库
    rclpy.init(args=args)

    # 创建节点
    goal_pose_publisher = GoalPosePublisher(params)

    try:
        # 运行节点
        rclpy.spin(goal_pose_publisher)
    except (KeyboardInterrupt, ExternalShutdownException):
        # 处理Ctrl+C信号
        pass
    finally:
        # 销毁节点
        goal_pose_publisher.destroy_node()
        # 关闭ROS2 Python客户端库
        if rclpy.ok():
            rclpy.shutdown()


if __name__ == '__main__':
    main()
