# System Monitor Explained (`system_monitor_node.cpp` + `Monitor.c`)

This is a first-time-reader guide for supervisors/reviewers.

The short version:
- `system_monitor_node.cpp` is the **observer**.
- `Monitor.c` is the **checker**.
- `attacker_agent_test.py` creates runtime attack behaviors.
- If behavior violates rules, monitor handlers publish alerts on `/monitor_alerts`.

## Mental Model

Think of this as a pipeline:

1. Observe runtime facts (`system_monitor_node.cpp`)
2. Evaluate rules (`Monitor.c`)
3. Emit alert (`handlerREQ_*` -> `/monitor_alerts`)

No attack logic is inside `Monitor.c`; it only checks whether observed values violate configured constraints.

## What Each File Does

## `system_monitor_node.cpp` (observer + adapter)

Responsibilities:
- Subscribes to ROS data/events:
  - `/scan`
  - `/parameter_events`
  - `/map_server/transition_event`
- Periodically snapshots graph metadata using CLI:
  - `ros2 topic info /scan -v`
  - `ros2 topic info /drive -v`
- Converts all observations into primitive monitor inputs:
  - counts, IDs, timestamps, booleans, reliability codes
- Calls `step()` every tick.
- Implements `handlerREQ_*` functions that publish alert strings.

Important: this file fills globals declared in `Monitor.h` (the generated monitor API boundary).

## `Monitor.c` (generated checker)

Responsibilities:
- Copies current inputs into local `_cpy` variables each `step()`.
- Evaluates requirement predicates (`s0_gen ... s11_gen`).
- Runs guard functions (`handlerREQ_*_guard`) that detect violations.
- Calls matching `handlerREQ_*` callback if violated.

Important: this file is generated from requirements. You usually edit requirements, then regenerate; you do not hand-maintain this file.

## End-to-End Sequence (one timer tick)

1. `system_monitor_node.cpp::tick()` runs.
2. It updates inputs, for example:
   - `scan_observed_reliability`
   - `scan_last_msg_time_sec`, `scan_prev_msg_time_sec`
   - `scan_pub_event`, `scan_pub_id`
   - `bridge_param_event`, `bridge_param_name_id`
3. It calls `step()` in `Monitor.c`.
4. `Monitor.c` evaluates all checks.
5. On violation, `Monitor.c` calls `handlerREQ_*`.
6. Handler publishes text alert on `/monitor_alerts`.
7. One-shot events are reset (`*_event = false`) by the node for next tick.

## How Attacker Actions Connect to Alerts

The attacker script (`attacker_agent_test.py`) performs runtime actions. The monitor sees side effects.

- `topicWrite('/scan')` / `maliciousTopicContent('/scan')`
  - likely alerts: `REQ_scan_content_attack`, possibly `REQ_scan_publisher_attack`
- `qosDegradation('/scan')`
  - likely alert: `REQ_scan_qos_attack`
- `topicDelay('/scan')`
  - likely alert: `REQ_scan_delay_attack`
- `topicDrop('/scan')`
  - likely alert: `REQ_scan_drop_attack`
- `topicRead('/scan')`
  - likely alert: `REQ_scan_reader_attack`
- `topicWrite('/drive')`
  - likely alert: `REQ_drive_publisher_attack`
- `topicFlood('/drive')`
  - likely alert: `REQ_drive_flood_attack`
- `serviceCall('/bridge/set_parameters',bridge)`
  - likely alert: `REQ_bridge_param_attack`
- `serviceCall('/map_server/change_state',map_server)`
  - likely alert: `REQ_map_lifecycle_attack`

## Current Checks Implemented in `Monitor.c`

- Scan content sanity:
  - invalid count limit
  - zero count limit
  - not all ranges identical
- Scan QoS matches expected reliability.
- Scan timing:
  - inter-arrival <= max
  - silence <= timeout
- Endpoint allowlists:
  - scan publisher ID
  - scan subscriber ID
  - drive publisher ID
- Drive anti-flood:
  - inter-arrival >= min
- Service abuse controls:
  - bridge parameter name allowlist
  - map transition allowlist

## Alert Names Published

- `REQ_scan_content_attack`
- `REQ_scan_qos_attack`
- `REQ_scan_delay_attack`
- `REQ_scan_drop_attack`
- `REQ_scan_publisher_attack`
- `REQ_scan_reader_attack`
- `REQ_drive_publisher_attack`
- `REQ_drive_flood_attack`
- `REQ_bridge_param_attack`
- `REQ_map_lifecycle_attack`

Note: three low-level scan checks map to one user-facing content alert:
- `REQ_scan_invalid_attack`
- `REQ_scan_zero_attack`
- `REQ_scan_uniform_attack`
-> all publish `REQ_scan_content_attack`

## How To Run a Demo

Terminal A (monitor):

```bash
source /opt/ros/foxy/setup.bash
source ~/sim_ws/install/setup.bash
ros2 run <your_package> system_monitor_node
```

Terminal B (alerts):

```bash
source /opt/ros/foxy/setup.bash
source ~/sim_ws/install/setup.bash
ros2 topic echo /monitor_alerts
```

Terminal C (attacker):

```bash
cd ~/finalVersion
echo '{}' > state.json
ATTACKER_OUTPUT=summary ATTACKER_POLICY=random ATTACK_NETEM_IFACE=enp0s1 ATTACK_TC_PREFIX="sudo -n tc" ATTACK_DELAY_SECS=8 ATTACK_DROP_SECS=8 ATTACK_ROBOT_HOST=127.0.0.1 ATTACK_DDS_SECURITY=off python3 attacker_agent_test.py AttackGraph.dot
```

## Reviewer Notes (What Can Be Confusing)

- `Monitor.c` names (`s0_gen`, `s1_gen`, etc.) are generated and not semantically friendly.
- Endpoint IDs are derived via `stable_id_for_name(...)` mapping; keep config IDs aligned with that table.
- Endpoint/QoS observation uses CLI snapshots, so very short-lived participants can be missed between ticks.

## Requirement Semantics (What Each Check Means)

Each requirement below is a **formal safety rule** enforced by `Monitor.c`.  
If the rule is violated, the corresponding `handlerREQ_*` publishes an alert.

---

### REQ_bridge_param_attack

- Requirement:
  - `((bridge_param_event = 1) -> (bridge_param_name_id = cfg_allowed_bridge_param_name_id))`

- Meaning:
  - Whenever a parameter change happens on `/bridge`, it must be the allowed parameter only.

- What it detects:
  - Unauthorized parameter modification on `/bridge`.

- Triggered by attacker:
  - `serviceCall('/bridge/set_parameters',bridge)`

---

### REQ_drive_flood_attack

- Requirement:
  - `(drive_last_msg_time_sec - drive_prev_msg_time_sec >= cfg_min_drive_interarrival_sec)`

- Meaning:
  - `/drive` messages must not arrive faster than the allowed rate.

- What it detects:
  - Message flooding on `/drive`.

- Triggered by attacker:
  - `topicFlood('/drive')`

---

### REQ_drive_publisher_attack

- Requirement:
  - `((drive_pub_event = 1) -> (drive_pub_id = cfg_allowed_drive_pub_id))`

- Meaning:
  - If a `/drive` publisher appears, it must be the expected one.

- What it detects:
  - Unauthorized publishing to `/drive`.

- Triggered by attacker:
  - `topicWrite('/drive')`

---

### REQ_map_lifecycle_attack

- Requirement:
  - `((map_lifecycle_event = 1) -> (map_transition_id = cfg_allowed_map_transition_id))`

- Meaning:
  - Lifecycle transitions of `/map_server` must be restricted to allowed ones.

- What it detects:
  - Unauthorized lifecycle manipulation.

- Triggered by attacker:
  - `serviceCall('/map_server/change_state',map_server)`

---

### REQ_scan_delay_attack

- Requirement:
  - `(scan_last_msg_time_sec - scan_prev_msg_time_sec <= cfg_max_scan_interarrival_sec)`

- Meaning:
  - `/scan` messages must not be delayed beyond the allowed interval.

- What it detects:
  - Artificial delay in sensor data.

- Triggered by attacker:
  - `topicDelay('/scan')`

---

### REQ_scan_drop_attack

- Requirement:
  - `(current_time_sec - scan_last_msg_time_sec <= cfg_scan_timeout_sec)`

- Meaning:
  - `/scan` must not stop publishing for too long.

- What it detects:
  - Dropping or blocking of sensor data.

- Triggered by attacker:
  - `topicDrop('/scan')`

---

### REQ_scan_invalid_attack

- Requirement:
  - `(scan_invalid_count <= cfg_max_scan_invalid_count)`

- Meaning:
  - The number of abnormal scan values must stay below a threshold.

- What it detects:
  - Corrupted or manipulated scan data.

- Triggered by attacker:
  - `maliciousTopicContent('/scan')`
  - sometimes `topicWrite('/scan')`

---

### REQ_scan_publisher_attack

- Requirement:
  - `((scan_pub_event = 1) -> (scan_pub_id = cfg_allowed_scan_pub_id))`

- Meaning:
  - `/scan` must only be published by the expected node.

- What it detects:
  - Spoofed sensor publisher.

- Triggered by attacker:
  - `topicWrite('/scan')`

---

### REQ_scan_qos_attack

- Requirement:
  - `(scan_observed_reliability = cfg_expected_scan_reliability)`

- Meaning:
  - `/scan` QoS reliability must match the expected configuration.

- What it detects:
  - QoS downgrade or manipulation.

- Triggered by attacker:
  - `qosDegradation('/scan')`

---

### REQ_scan_reader_attack

- Requirement:
  - `((scan_sub_event = 1) -> (scan_sub_id = cfg_allowed_scan_sub_id))`

- Meaning:
  - Only approved nodes may subscribe to `/scan`.

- What it detects:
  - Unauthorized data access.

- Triggered by attacker:
  - `topicRead('/scan')`

---

### REQ_scan_uniform_attack

- Requirement:
  - `(scan_all_same = 0)`

- Meaning:
  - Scan values must not all be identical.

- What it detects:
  - Fake or injected uniform sensor data.

- Triggered by attacker:
  - `maliciousTopicContent('/scan')`

---

### REQ_scan_zero_attack

- Requirement:
  - `(scan_zero_count <= cfg_max_scan_zero_count)`

- Meaning:
  - Too many zero values in scan data are not allowed.

- What it detects:
  - Blind-spot or zeroing attacks.

- Triggered by attacker:
  - `maliciousTopicContent('/scan')`

---
