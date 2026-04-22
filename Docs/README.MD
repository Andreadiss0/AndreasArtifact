# F1TENTH Attack Runtime: Code Guide

This README is for a teammate who wants to understand how the code works, where to edit it, and how to run it safely.

## Project Purpose

This repo runs an executable attacker against an attack graph (`AttackGraph.dot`) and shows which predicate chain led to `systemCompromised(f1tenth)`.

Core idea:
- The graph defines logical attack possibilities.
- `attacker_agent_test.py` executes real runtime actions for selected predicates.
- State is persisted in `state.json`.
- Evidence is written into `logs/`.

## File Map

- `attacker_agent_test.py`
  - Main engine.
  - Parses graph, computes enabled actions, executes action implementations, derives consequences, prints explain chain.
- `AttackGraph.dot`
  - Attack graph exported from your modeling pipeline.
  - Contains predicate and rule nodes + edges.
- `state.json`
  - Runtime state store (`facts`, `predicates`, `smg`, `meta`).
- `logs/`
  - Per-action command outputs and diagnostics.
- `scan_wrapper_node.cpp`, `drive_wrapper_node.cpp`, `bridge_wrapper_node.cpp`, `map_wrapper_node.cpp`
  - Wrapper/monitor related runtime nodes (separate from attacker engine).
- `*_copilot/monitor.c`, `*_copilot/monitor.h`
  - Generated monitor rule logic.

## How `attacker_agent_test.py` Works

## 1) Parse Graph

It reads `AttackGraph.dot` and builds:
- predicate nodes
- rule nodes
- dependencies between predicates

Important detail:
- It preserves **OR semantics** across alternative rules (`dep_options`), so a predicate can be reached by one valid path instead of forcing all paths.

## 2) Load/Update Runtime State

State schema:
- `facts`: static or discovered facts
- `predicates`: achieved attack predicates
- `smg`: PRISM-style global variables mirror
- `meta`: explanations/why traces

Helper functions:
- `load_state()`, `save_state()`
- `mark_fact()`, `mark_pred()`
- `set_smg()`, `set_turn()`

## 3) Find Enabled Executable Actions

The engine computes currently enabled predicates and filters them to real attacker actions using:
- `EXECUTABLE_ATTACK_ACTIONS`

Action ordering is selected by policy:
- `ATTACKER_POLICY=random` (default in your runs)
- fallback behavior tries next enabled action if chosen one fails

## 4) Execute Action

Action dispatch map:
- `ACTION_IMPL = { "<predicate>": <python function> }`

Examples:
- `initialAccess(engineering_ws)` -> `act_initial_access_engineering_ws()`
- `topicWrite('/scan')` -> `act_topic_write_scan()`
- `serviceCall('/bridge/set_parameters',bridge)` -> `act_service_call_bridge_set_parameters()`
- `topicDelay('/scan')` -> `act_topic_delay_scan()`

## 5) Derive Consequences

After a successful action, the engine derives downstream predicates, updates SMG keys, and prints:
- `[EXPLAIN]` chain of newly derived predicates
- `[EXPLAIN_SUMMARY]` compact compromise path when goal is reached

Stop condition:
- `systemCompromised(f1tenth)` becomes true

## Action Types: What They Actually Change

These are the runtime effects your friend should know:

- `topicWrite('/scan')`, `maliciousTopicContent('/scan')`, `qosDegradation('/scan')`
  - Spawns temporary `ros2cli` publisher (`_ros2cli_*`) on `/scan`.
  - Does not edit simulator source.
- `topicRead('/scan')`
  - Spawns temporary `ros2cli` subscriber.
  - Reads data only.
- `serviceCall('/bridge/set_parameters',bridge)`
  - Calls parameter service on existing `/bridge`.
  - Changes runtime param state on bridge.
- `serviceCall('/map_server/change_state',map_server)`
  - Calls lifecycle service on existing `/map_server`.
  - Changes lifecycle state at runtime.
- `topicDelay('/scan')`, `topicDrop('/scan')`
  - Uses `tc netem` on Linux interface.
  - No ROS node source changes; this is kernel-level network shaping.

## Environment Variables (Most Used)

Execution and output:
- `ATTACKER_POLICY` (`random`, etc.)
- `ATTACKER_OUTPUT` (`summary` or `full`)
- `MAX_STEPS`
- `STATE_FILE`

## Run Commands

Simulator terminal:

```bash
source /opt/ros/foxy/setup.bash
source ~/sim_ws/install/setup.bash
export ROS_DOMAIN_ID=0
export ROS_LOCALHOST_ONLY=0
ros2 launch f1tenth_gym_ros gym_bridge_launch.py
```

Attacker terminal:

```bash
cd ~/finalVersion
echo '{}' > state.json
ATTACKER_OUTPUT=summary ATTACKER_POLICY=random ATTACK_NETEM_IFACE=enp0s1 ATTACK_TC_PREFIX="sudo -n tc" ATTACK_DELAY_SECS=8 ATTACK_DROP_SECS=8 ATTACK_ROBOT_HOST=127.0.0.1 ATTACK_DDS_SECURITY=off python3 attacker_agent_test.py AttackGraph.dot
```

## Where To Edit For New Attacks

When adding a new executable predicate:

1. Add Python implementation function in `attacker_agent_test.py`.
2. Register it in `ACTION_IMPL`.
3. Add predicate string to `EXECUTABLE_ATTACK_ACTIONS`.
4. Add PRISM label mapping in `ATTACK_LABEL_TO_PRED`.
5. Add SMG key mapping in `SMG_KEY_MAP` if needed.
6. Re-run and verify explain chain in `summary` mode.

## One-Line Mental Model

`AttackGraph.dot` says what is possible, `attacker_agent_test.py` chooses one valid enabled action path and proves compromise with runtime evidence + derivation chain.
