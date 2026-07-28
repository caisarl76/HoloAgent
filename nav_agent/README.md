# NavAgent

本项目包含一个完整的 **具身智能导航系统**（NavAgent），包含定位、建图、导航、语义目标定位、语音交互、运控调用等模块，支持 Docker 与宿主机混合运行。

---

## 📁 项目结构
```text
nav_agent/
├── config/
│   └── g1_deploy.env.example         # G1 部署参数模板
├── humble_localization_nav2/        # Docker 内运行的本体定位 / 导航 & 避障模块
│   ├── g1_nav_bringup/              # 一键启动所有 launch 文件
│   ├── g1_navigation2/              # ROS 2 Navigation 参数接口
│   ├── lio_mapping_loc/             # FastLIVO2 + 重定位模块
│   ├── navigation2-humble/          # ROS 2 Navigation 2 核心功能包
│   ├── pubpose/                      # 接收 goal_publisher 目标位姿并转发给 Nav2 做全局导航与避障
│   └── rpg_vikit-ros2/              # FastLIVO2 第三方依赖
├── scripts/                         # 启动脚本（Docker / 宿主机）
│   ├── build_sem_nav.sh              # 构建宿主机语义导航 workspace，支持 dryrun/robot 两种模式
│   ├── build_navagent_image.sh        # 基于公开镜像构建带 NavAgent 依赖的派生 Docker 镜像
│   ├── create_navagent_env.sh         # 根据已生成 FSR-VLN 图自动生成部署 env
│   ├── discover_navagent_assets.sh    # 查找 Nav2 地图、FastLIVO prior 和网口候选
│   ├── apply_navagent_asset_overrides.sh # 将已确认的地图/prior/网口写入部署 env
│   ├── create_fastlivo_prior_mapping_config.sh # 生成 FastLIVO prior 建图配置
│   ├── finalize_fastlivo_prior.sh    # 将 mapping.txt 转为重定位所需 keyframe_pose.txt 并校验 prior
│   ├── prepare_fastlivo_prior_mapping.sh # 创建 prior 目录并把映射配置写入 env
│   ├── preflight_navagent_env.sh      # 宿主机检查部署 env 和挂载路径
│   ├── check_g1_deploy_readiness.sh  # Unitree G1 部署前检查
│   ├── setup_navagent_container.sh    # Docker 容器内安装依赖、dry-run 构建和检查
│   ├── smoke_navagent_container.sh    # Docker 容器内安全 smoke test，不启动机器人运动
│   ├── start_navagent_container.sh    # 宿主机创建/启动 Docker 容器
│   ├── run_navagent_container_checks.sh # 宿主机触发容器内 dry-run setup/checks
│   ├── run_nav.sh                    # Docker 内一键启动所有算法模块
│   ├── run_sem_nav.sh                # 宿主机一键启动语义导航模块
│   ├── run_sensors.sh                # 宿主机一键启动传感器
│   ├── validate_navagent_query_flow.sh # Docker/ROS 内验证 /chat_loc_pub -> /object_pose
│   ├── check_fastlivo_sim_topics.sh  # 校验仿真 FastLIVO 输入 topic 类型与频率
│   └── stop_navagent.sh              # 软件停止 NavAgent tmux 会话
└── sem_nav_ctr/                      # 宿主机运行的语音 / 运控 / 目标语义定位模块
    ├── chat_loc_python/             # 语音交互客户端
    ├── g1_move/                     # G1 运控接口
    └── goal_publisher/              # 目标实例 / 区域的语义定位, 内部调用fsr-vln模块的hmsg查询目标位姿
``` 

## 🚀 功能概述

- ✅ **导航和避障（Nav2）**  
  基于 ROS 2 Navigation2 框架，支持全局路径规划、局部避障。

- ✅ **FastLIVO2 里程计 + 重定位**  
  实时点云里程计，并支持地图重定位。

- ✅ **语音交互控制**  
  通过本地语音客户端配合远程服务端实现语音导航任务，当前代码仅包含客户端设备数据采集部分，建议自行实现语音交互模块, 或等下一步开源。

- ✅ **语义目标定位**  
  从目标名称（如"沙发"、"展厅"）解析为具体的三维空间目标位姿。

- ✅ **一键启动脚本**  
  提供 Docker / 宿主机 的一键启动方案。

---

## 🏃 启动方式

Unitree G1 真机部署前，请先阅读 [DEPLOY_UNITREE_G1.md](DEPLOY_UNITREE_G1.md)。
如果当前没有机器人硬件，按
[SIMULATION_FASTLIVO_NAVAGENT.md](SIMULATION_FASTLIVO_NAVAGENT.md)
把 Habitat 语义测试、MuJoCo/FastLIVO 传感器仿真、NavAgent dry-run 分开验证。
当前仓库的 MuJoCo-first Stage 1–4 实现、证据查看命令和 PC2 无运动交接步骤见
[mujoco_sim/README.md](mujoco_sim/README.md)。
以下命令从仓库根目录 `/home/jihun/work/HoloAgent` 执行。建议先走
Docker 内安全 dry-run，不在宿主机安装 NavAgent 依赖：

```bash
cd /home/jihun/work/HoloAgent
SCENE=icra_ic4f FORCE=1 bash nav_agent/scripts/create_navagent_env.sh

# 查找可填入 env 的 Nav2 map / FastLIVO prior / Unitree 网口候选
bash nav_agent/scripts/discover_navagent_assets.sh

# 示例：把已发现的 Nav2 map 写入 env；FastLIVO prior 和网口同理显式填写
NAV_AGENT_ENV_FILE=nav_agent/config/g1_deploy.env \
NAV2_MAP_YAML=/mnt/data/jihun/HoloAgent/maps/fastlio_map.yaml \
DRY_RUN=0 \
bash nav_agent/scripts/apply_navagent_asset_overrides.sh

$EDITOR nav_agent/config/g1_deploy.env

NAV_AGENT_ENV_FILE=nav_agent/config/g1_deploy.env \
CHECK_DOCKER_IMAGE=0 \
bash nav_agent/scripts/preflight_navagent_env.sh

NAV_AGENT_ENV_FILE=nav_agent/config/g1_deploy.env \
bash nav_agent/scripts/build_navagent_image.sh

# 可选：只打印 docker run 命令，不启动容器
NAV_AGENT_ENV_FILE=nav_agent/config/g1_deploy.env \
PRINT_DOCKER_COMMAND=1 \
bash nav_agent/scripts/start_navagent_container.sh

NAV_AGENT_ENV_FILE=nav_agent/config/g1_deploy.env \
bash nav_agent/scripts/start_navagent_container.sh
```

进入容器后再执行依赖检查、dry-run 构建和语义栈验证：

```bash
docker exec -it holoagent-navagent /bin/bash

cd /workspace/HoloAgent
export NAV_AGENT_ENV_FILE=/workspace/HoloAgent/nav_agent/config/g1_deploy.env

INSTALL_GOAL_PUBLISHER_DEPS=0 \
bash nav_agent/scripts/setup_navagent_container.sh

START_G1_PUBVEL=0 \
G1_DRY_RUN=1 \
ALLOW_G1_MOTION=0 \
bash nav_agent/scripts/run_sem_nav.sh
```

预览软件停止命令，不停止任何进程：

```bash
PRINT_STOP_COMMANDS=1 bash nav_agent/scripts/stop_navagent.sh
```

语义栈启动后，可先预览 dry-run 查询验证命令：

```bash
cd /workspace/HoloAgent
PRINT_TOPIC_TEST_COMMANDS=1 bash nav_agent/scripts/validate_navagent_query_flow.sh

bash nav_agent/scripts/validate_navagent_query_flow.sh
```

默认情况下 `run_sem_nav.sh` 不会启动真实 G1 运控桥接：
`START_G1_PUBVEL=0` 且 `G1_DRY_RUN=1`。
真实运动还需要额外设置 `ALLOW_G1_MOTION=1`，否则脚本会拒绝启动
`g1_pubvel_node` 的真实运动模式。真实运动路径还会先运行
`check_g1_deploy_readiness.sh` 的 `CHECK_MODE=robot` 严格检查；默认
`REQUIRE_G1_READINESS_CHECK=1`，不要在真机运动时关闭。

如果不构建派生镜像，需要在 `nav_agent/config/g1_deploy.env` 中设置：

```bash
HOLOAGENT_IMAGE=ghcr.io/zhaoyu199201/holoagent:latest
INSTALL_GOAL_PUBLISHER_DEPS=1
```

### Docker 构建与运行

确保已安装 Docker 与 NVIDIA Container Toolkit。

**基础镜像配置：**
- 自行构建 `ubuntu22.04 + ros2-humble` 基础镜像
- 在基础镜像中colcon build `humble_localization_nav2` 中的所有子模块

**使用预构建镜像：**
- 直接使用我们提供的镜像：ghcr.io/zhaoyu199201/holoagent:latest

### 启动命令

**Docker 内启动导航模块：**
```bash
cd /workspace/HoloAgent
PRINT_NAV_COMMANDS=1 bash nav_agent/scripts/run_nav.sh

bash nav_agent/scripts/run_nav.sh
```

**Docker 内启动语义导航 dry-run：**
```bash
cd /workspace/HoloAgent
PRINT_SEM_NAV_COMMANDS=1 START_G1_PUBVEL=0 G1_DRY_RUN=1 bash nav_agent/scripts/run_sem_nav.sh

START_G1_PUBVEL=0 G1_DRY_RUN=1 bash nav_agent/scripts/run_sem_nav.sh
```

**宿主机启动传感器：**
```bash
cd /home/jihun/work/HoloAgent
bash nav_agent/scripts/run_sensors.sh
```
