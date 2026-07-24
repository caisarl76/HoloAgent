# HoloAgent Stages 3–4 Implementation Plan

**Goal:** Evaluate repository FastLIVO against MuJoCo ground truth, then validate the complete simulation-only semantic fixture → Nav2 → bounded G1 loop in the `sim_map` frame.

**Safety boundary:** Every process uses domain 77 with localhost-only CycloneDDS. The dedicated `holoagent-stages234` container has host network/IPC, the continuation worktree as its only workspace bind, no host devices, and no privileged mode. No PC2 address, Unitree transport, physical motion executable, or `unitree_sdk2` import is allowed.

## Stage 3 — LIO-only estimator branch

1. Build `vikit_common`, `vikit_ros`, and `fast_livo` from the pinned continuation worktree into a unique `/tmp` overlay in the dedicated container. Record compiler/dependency versions and build logs. Do not edit restored FastLIVO source to make the build pass.
2. Extend the Stage 2 launcher components with a Stage 3 evaluator. It publishes a bounded excitation trajectory only after exact graph approval, subscribes to `/aft_mapped_to_init` and MuJoCo `/robot_odom`, and remaps FastLIVO's unused perfect-odometry subscriber to `/stage3/unused_robot_odom`.
3. Compare estimator and ground-truth motion after first-pose SE(2) alignment over 30 simulated seconds. Require translation RMSE ≤0.50 m, maximum translation error ≤1.50 m, yaw RMSE ≤10 degrees, finite monotonic samples, `use_sim_time=true`, `common.img_en=0`, and the Stage 2 sensor/rate contract.
4. Write `result.pending.json`; promote only after exact host/container PIDs are gone and no Stage 3 participant remains. Label a passing required gate `PASS_LIO_ONLY`; otherwise preserve `FAIL_ESTIMATOR` evidence and continue to Stage 4 as permitted by the approved design.

## Stage 4 — simulator-native semantic navigation

1. Install the version-matched Humble Nav2 packages only in the dedicated simulation container. Record package versions. Never install or start robot transport software.
2. Generate a deterministic 0.05 m/cell occupancy map directly from the known 8 m × 8 m MuJoCo room geometry. Use frame `sim_map`, hash the PGM/YAML, and reject any map path or digest matching the prohibited real-building map.
3. Add a simulation-only `sim_fixture` node that maps fixed phrases to prevalidated free-space poses. Validate world bounds, occupancy, and configured inflation clearance before Nav2 activation; publish `/object_pose` only in `sim_map`.
4. Add Nav2 parameters for a differential/non-holonomic controller (`min_vel_y=max_vel_y=0`, no lateral samples), simulator ground-truth localization (`sim_map→odom`), and `use_sim_time=true` on every node.
5. Add a Stage 4 evaluator/orchestrator. After exact graph and map-digest approval, submit one fixed phrase, confirm the fixture pose, Nav2 path, bounded `/cmd_vel`, collision-free MuJoCo motion, ≤0.35 m position error and ≤15° yaw error within 90 simulated seconds, then verify timeout/settled stop.
6. Atomically promote `PASS_SIM_SEMANTIC_PLUMBING` only after exact-PID cleanup, empty allowlisted motion graph, final zero command, and absence of all physical transport processes/imports.

## Verification and handoff

- Run pure unit tests first for alignment metrics, map generation, fixture clearance, non-holonomic parameter validation, result promotion, and launcher text/syntax.
- Run clean colcon builds in unique `/tmp` directories.
- Run the full Stage 1–4 Python/static regression suite and `git diff --check`.
- Preserve all failed and passing runtime directories; identify one authoritative result per stage.
- Document commands for viewing MuJoCo motion, sensor rates, estimator error, DDS graph, map, Nav2 path, and the final qualified labels.
