#!/usr/bin/env python3
"""Defender agent: subscribes to /monitor_alerts and runs PRISM-strategy defenses."""
import json
import os
import re
import shlex
import subprocess
import sys
import threading
import time

import rclpy
from rclpy.node import Node
from rclpy.qos import QoSProfile, ReliabilityPolicy, DurabilityPolicy, HistoryPolicy
from std_msgs.msg import String
from ackermann_msgs.msg import AckermannDriveStamped
from rcl_interfaces.srv import SetParameters
from rcl_interfaces.msg import Parameter, ParameterType
from lifecycle_msgs.srv import ChangeState
from lifecycle_msgs.msg import TransitionEvent

# Attacker predicate-state file (defender writes only to revoke).
ATTACKER_STATE_PATH = "/home/f1tenth/finalVersion/state.json"

# Set by DefenderNode.__init__ so free-standing defense_* fns can publish.
g_defender_node = None

# Per-bit cooldown: ignore repeat alerts within this window after acting.
ALERT_COOLDOWN_SEC = 2.5

# File barrier the defender touches so the polling attacker knows it can advance.
TURN_COMPLETE_PATH = "/tmp/turn_complete.flag"


# Runtime monitor alert -> PRISM observable variable.
ALERT_TO_VAR = {
    # Effect alerts (7)
    "REQ_drive_DoS":             "drive_DoS_f1tenth_",
    "REQ_command_unsafe":        "command_unsafe_f1tenth_",
    "REQ_scan_corrupted":        "scan_corrupted_f1tenth_",
    "REQ_scan_unreliable":       "scan_unreliable_f1tenth_",
    "REQ_map_server_down":       "map_server_down_f1tenth_",
    "REQ_bridge_misconfigured":  "bridge_misconfigured_f1tenth_",
    "REQ_data_leaked":           "data_leaked_f1tenth_",
    # Foundation alerts (3)
    "REQ_credential_access":     "credentialAccess_robot_host_",
    "REQ_can_join_ros_graph":    "attackerCanJoinRosGraph_robot_host_",
    "REQ_can_net_admin":         "attackerCanNetAdmin_robot_host_",
}


# Per-alert defense timing: "immediate" runs in on_alert; "post_hoc" waits for attacker step-done.
ALERT_TIMING = {
    "REQ_drive_DoS":             "immediate",
    "REQ_command_unsafe":        "immediate",
    "REQ_scan_corrupted":        "immediate",
    "REQ_scan_unreliable":       "immediate",
    "REQ_map_server_down":       "immediate",
    "REQ_bridge_misconfigured":  "immediate",
    "REQ_data_leaked":           "immediate",
    "REQ_credential_access":     "post_hoc",
    "REQ_can_join_ros_graph":    "post_hoc",
    "REQ_can_net_admin":         "immediate",
}

# Attacker step-done flag; step-done watcher drains post-hoc queue on advance.
ATTACKER_STEP_DONE_PATH = "/tmp/attacker_step_done.flag"

# Combined real-time log shared with the attacker (flock-protected).
COMBINED_LOG_PATH = "/tmp/runtime_combined.log"
COMBINED_LOG_START_TS_PATH = "/tmp/runtime_combined.start_ts"


def _combined_log_start_ts():
    """Shared trial-start reference (same as attacker's helper)."""
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


# Foundation predicates implied true whenever any effect alert fires.
_FOUNDATION_BASE = [
    "credentialAccess_robot_host_",
    "attackerCanJoinRosGraph_robot_host_",
]

# Effect -> foundation predicates that must already be true for that effect.
EFFECT_FOUNDATION_DEPS = {
    "drive_DoS_f1tenth_":           _FOUNDATION_BASE,
    "command_unsafe_f1tenth_":      _FOUNDATION_BASE,
    "scan_corrupted_f1tenth_":      _FOUNDATION_BASE,
    "scan_unreliable_f1tenth_":     _FOUNDATION_BASE + ["attackerCanNetAdmin_robot_host_"],
    "map_server_down_f1tenth_":     _FOUNDATION_BASE,
    "bridge_misconfigured_f1tenth_": _FOUNDATION_BASE,
    "data_leaked_f1tenth_":         _FOUNDATION_BASE,
}

# Foundation alert -> upstream foundation predicates the strategy expects.
FOUNDATION_PREDECESSORS = {
    "credentialAccess_robot_host_": [],
    "attackerCanJoinRosGraph_robot_host_": [
        "credentialAccess_robot_host_",
    ],
    "attackerCanNetAdmin_robot_host_": [],
}


# PRISM strategy tuple variable order — MUST match `global ... : bool init false;` in test.prism.
PRISM_VARS = [
    "systemCompromised_f1tenth_",
    "drive_DoS_f1tenth_",
    "attackerCanJoinRosGraph_robot_host_",
    "credentialAccess_robot_host_",
    "command_unsafe_f1tenth_",
    "scan_corrupted_f1tenth_",
    "scan_unreliable_f1tenth_",
    "attackerCanNetAdmin_robot_host_",
    "map_server_down_f1tenth_",
    "bridge_misconfigured_f1tenth_",
    "data_leaked_f1tenth_",
]


def _sh(cmd, timeout=10):
    """Run a bash command with logging and return the CompletedProcess or None."""
    print(f"[DEFENDER][CMD] {cmd}", flush=True)
    try:
        p = subprocess.run(
            ["bash", "-lc", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        if out:
            print(f"[DEFENDER][OUT rc={p.returncode}] {out[:500]}", flush=True)
        else:
            print(f"[DEFENDER][OUT rc={p.returncode}] <empty>", flush=True)
        return p
    except subprocess.TimeoutExpired:
        print("[DEFENDER][OUT] TIMEOUT", flush=True)
        return None


def _rc(p):
    """Return code from a `_sh` result, tolerating timeout (None)."""
    return p.returncode if p is not None else 1


# Per-turn kill accumulator drained by _react() into the turn-summary JSON.
TURN_KILLS = []


def kill_pids_matching(pattern, description):
    """SIGKILL every process whose cmdline matches `pattern`; return kill count."""
    rx = re.compile(pattern)
    self_pid = os.getpid()
    killed = 0
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
        cmdline = raw.replace(b"\0", b" ").decode("utf-8", errors="ignore").strip()
        if not cmdline:
            continue
        if rx.search(cmdline):
            try:
                os.kill(pid, 9)
                killed += 1
                TURN_KILLS.append({
                    "pid": pid,
                    "description": description,
                    "cmdline": cmdline[:120],
                })
                print(f"[DEFENDER] killed pid={pid} ({description}): "
                      f"{cmdline[:100]}", flush=True)
                _combined_log("DEFENDER", f"killed pid={pid} ({description})")
            except (ProcessLookupError, PermissionError) as e:
                print(f"[DEFENDER] could not kill pid={pid} ({description}): {e}",
                      flush=True)
    return killed


def sh(cmd, timeout=8):
    """Run a shell command, log it, return (rc, output)."""
    print(f"[DEFENDER] $ {cmd}", flush=True)
    try:
        p = subprocess.run(
            ["bash", "-lc", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        out = ((p.stdout or "") + (p.stderr or "")).strip()
        rc = p.returncode
    except subprocess.TimeoutExpired:
        out = "TIMEOUT"
        rc = 124
    if out:
        print(f"[DEFENDER]   rc={rc}  {out[:200]}", flush=True)
    else:
        print(f"[DEFENDER]   rc={rc}", flush=True)
    return rc, out


# Operator-level defenses; each returns True if it confirmed neutralisation.

def def_kill_rogue_publishers():
    """Clear scan_corrupted and drive_DoS by sweeping rogue /scan and /drive publishers."""
    a = kill_pids_matching(r"ros2 topic pub.*/scan", "rogue /scan ros2-cli publisher")
    b = kill_pids_matching(r"ros2 topic pub.*/drive", "rogue /drive ros2-cli publisher")
    c = kill_pids_matching(r"attacker_drive_writer|attacker_drive_flooder",
                           "rogue /drive rclpy publisher")
    d = kill_pids_matching(r"attacker_scan_writer|attacker_scan_corrupter|attacker_qos_degrader",
                           "rogue /scan rclpy publisher")
    return (a + b + c + d) > 0


def def_block_scan_replay():
    """Kill the MITM dual-role attacker and the stale-publish backdater on /scan."""
    a = kill_pids_matching(r"mitm_scan_attack", "MITM /scan attacker")
    b = kill_pids_matching(r"stale_publish_scan_attack", "stale /scan publisher")
    return (a + b) > 0


def def_restore_scan_quality():
    """Restore /scan reliability: kill QoS/degrader attackers and clear netem qdiscs."""
    a = kill_pids_matching(r"reliability_flip_scan_attack|attacker_qos_degrader",
                           "QoS-flip/degrader attacker")
    b = kill_pids_matching(r"ros2 topic pub.*/scan|attacker_scan_writer|attacker_scan_corrupter",
                           "rogue /scan publisher (best-effort QoS)")
    c = kill_pids_matching(
        r"attacker_netadmin_topicdrop|attacker_netadmin_topicdelay|tc\s+qdisc\s+add",
        "tc-installer attacker script")
    cleared = 0
    for iface in ("lo", "eth0", "wlan0"):
        rc, _ = sh(f"sudo -n tc qdisc del dev {iface} root")
        if rc == 0:
            cleared += 1
    return (a + b + c) > 0 or cleared > 0


def def_kill_rogue_subscribers():
    """Clear data_leaked by killing rogue /scan, /odom, and cross-topic subscribers."""
    a = kill_pids_matching(r"ros2 topic echo.*/scan",
                           "rogue /scan ros2-cli subscriber")
    b = kill_pids_matching(r"ros2 topic echo.*/odom",
                           "rogue /odom ros2-cli subscriber")
    c = kill_pids_matching(r"attacker_scan_reader|attacker_odom_reader",
                           "rogue rclpy exfil subscriber")
    d = kill_pids_matching(r"cross_topic_correlation_attack",
                           "cross-topic correlator")
    return (a + b + c + d) > 0


def def_revert_node_parameters():
    """Fire-and-forget SetParameters on /bridge and /map_server."""
    # MUST NOT spin_until_future_complete here — reentrant spin breaks rclpy executor.
    node = g_defender_node
    if node is None:
        print("[DEFENDER] revert_node_parameters: g_defender_node not set", flush=True)
        return False
    for cli, name in ((node.set_param_cli_bridge, "/bridge"),
                      (node.set_param_cli_map,    "/map_server")):
        if not cli.wait_for_service(timeout_sec=0.2):
            print(f"[DEFENDER] revert_node_parameters: {name}/set_parameters "
                  f"not discovered (fire-and-forget skipped)", flush=True)
            continue
        req = SetParameters.Request()
        p = Parameter()
        p.name = "use_sim_time"
        p.value.type = ParameterType.PARAMETER_BOOL
        p.value.bool_value = False
        req.parameters = [p]
        cli.call_async(req)
        print(f"[DEFENDER] revert_node_parameters: queued SetParameters on {name}",
              flush=True)
    return True


def def_reactivate_map_server():
    """Clear map_server_down by publishing a forged ACTIVATE TransitionEvent."""
    node = g_defender_node
    if node is None or node.transition_event_pub is None:
        print("[DEFENDER] reactivate_map_server: transition_event_pub not initialised",
              flush=True)
        return False
    ev = TransitionEvent()
    ev.timestamp = int(time.time() * 1e9)
    ev.transition.id = 3
    ev.transition.label = "activate"
    ev.start_state.id = 2
    ev.start_state.label = "inactive"
    ev.goal_state.id = 3
    ev.goal_state.label = "active"
    node.transition_event_pub.publish(ev)
    time.sleep(0.2)
    node.transition_event_pub.publish(ev)
    print("[DEFENDER] reactivate_map_server: published forged ACTIVATE event "
          "(inactive -> active) to /map_server/transition_event", flush=True)
    return True


# Shared 5 s cooldown so back-to-back drive alerts don't double-brake.
_last_safe_drive_override_call_ts = 0.0


def def_safe_drive_override():
    """Clear command_unsafe: slam zero-speed /drive at 100 Hz for 2 s in a
    daemon thread so the defender's alert handler isn't blocked."""
    global _last_safe_drive_override_call_ts
    now = time.time()
    if now - _last_safe_drive_override_call_ts < 5.0:
        print(f"[DEFENDER] safe_drive_override: skipped "
              f"(cooldown, {now - _last_safe_drive_override_call_ts:.1f}s < 5.0s)",
              flush=True)
        return True
    _last_safe_drive_override_call_ts = now

    node = g_defender_node
    if node is None or node.drive_pub is None:
        print("[DEFENDER] safe_drive_override: drive_pub not initialised", flush=True)
        return False

    def _spam_brake():
        msg = AckermannDriveStamped()
        msg.drive.speed = 0.0
        msg.drive.steering_angle = 0.0
        end = time.time() + 2.0
        count = 0
        while time.time() < end:
            try:
                node.drive_pub.publish(msg)
            except Exception:
                break
            count += 1
            time.sleep(0.01)
        print(f"[DEFENDER] safe_drive_override: published {count} hold msgs over 2s",
              flush=True)

    threading.Thread(target=_spam_brake, name="safe_drive_override", daemon=True).start()
    return True


def def_rotate_credentials():
    """D3-RUAA: nuke the attacker's stolen bridge keystore and kill the creds marker."""
    killed = kill_pids_matching(r"attacker_creds_obtained", "stolen-creds marker")

    stolen_path = "/tmp/stolen_ros_keystore"
    nuked_stolen = False
    if os.path.isdir(stolen_path):
        rc, _ = sh(f"rm -rf {stolen_path}")
        if rc == 0:
            nuked_stolen = True
            print(f"[DEFENDER] nuked stolen keystore at {stolen_path}", flush=True)

    try:
        os.remove("/tmp/stolen_ros_creds")
        removed_file = True
    except FileNotFoundError:
        removed_file = False

    print("[DEFENDER] credentials rotated; stolen keys invalidated", flush=True)
    return killed > 0 or nuked_stolen or removed_file


def def_enable_dds_security():
    """D3-DKP: kill the rogue DDS participant (symbolic mid-game SROS2 enforcement)."""
    killed = kill_pids_matching(r"attacker_ros_participant", "rogue DDS participant")
    print("[DEFENDER] SROS2 enforcement enabled (simulated)", flush=True)
    return killed > 0


# Per-defense reliability — values match `0.XX:` branches in test.prism's defender module.
DEFENSE_RELIABILITY = {
    "def_kill_rogue_publishers":   0.92,
    "def_kill_rogue_subscribers":  0.90,
    "def_block_scan_replay":       0.85,
    "def_restore_scan_quality":    0.85,
    "def_revert_node_parameters":  0.92,
    "def_reactivate_map_server":   0.95,
    "def_safe_drive_override":     0.90,
    "def_rotate_credentials":      0.90,
    "def_enable_dds_security":     0.95,
}


DEFENSES = {
    "def_kill_rogue_publishers": (
        def_kill_rogue_publishers,
        ["scan_corrupted_f1tenth_", "drive_DoS_f1tenth_"],
    ),
    "def_block_scan_replay": (
        def_block_scan_replay,
        ["scan_corrupted_f1tenth_"],
    ),
    "def_restore_scan_quality": (
        def_restore_scan_quality,
        ["scan_unreliable_f1tenth_"],
    ),
    "def_kill_rogue_subscribers": (
        def_kill_rogue_subscribers,
        ["data_leaked_f1tenth_"],
    ),
    "def_revert_node_parameters": (
        def_revert_node_parameters,
        ["bridge_misconfigured_f1tenth_", "map_server_down_f1tenth_"],
    ),
    "def_reactivate_map_server": (
        def_reactivate_map_server,
        ["map_server_down_f1tenth_"],
    ),
    "def_safe_drive_override": (
        def_safe_drive_override,
        ["command_unsafe_f1tenth_"],
    ),
    "def_rotate_credentials": (
        def_rotate_credentials,
        ["credentialAccess_robot_host_"],
    ),
    "def_enable_dds_security": (
        def_enable_dds_security,
        ["attackerCanJoinRosGraph_robot_host_"],
    ),
}


# Per-defense set of attacker predicates cleared from state.json on success.
DEFENSE_REVOKES = {
    "def_kill_rogue_publishers": [
        "topicWrite('/scan')",
        "maliciousTopicContent('/scan')",
        "topicFlood('/drive')",
        "mitmPossible('/scan')",
        "scan_corrupted(f1tenth)",
        "drive_DoS(f1tenth)",
    ],
    "def_block_scan_replay": [
        "mitmInjection('/scan')",
        "stalePublish('/scan')",
        "mitmPossible('/scan')",
        "scan_corrupted(f1tenth)",
    ],
    "def_restore_scan_quality": [
        "qosDegradation('/scan')",
        "reliabilityFlip('/scan')",
        "topicDrop('/scan')",
        "topicDelay('/scan')",
        "scan_unreliable(f1tenth)",
    ],
    "def_kill_rogue_subscribers": [
        "topicRead('/scan')",
        "topicRead('/odom')",
        "crossTopicCorrelation(f1tenth)",
        "exfiltrateChannel('/attacker_exfil')",
        "mitmPossible('/scan')",
        "data_leaked(f1tenth)",
    ],
    "def_revert_node_parameters": [
        "serviceCall('/bridge/set_parameters',bridge)",
        "serviceCall('/map_server/set_parameters',map_server)",
        "parameterTamper(map_server)",
        "lifecycleHijack(map_server)",
        "bridge_misconfigured(f1tenth)",
        "map_server_down(f1tenth)",
    ],
    "def_reactivate_map_server": [
        "serviceCall('/map_server/change_state',map_server)",
        "lifecycleHijack(map_server)",
        "lifecycleAbuse(map_server)",
        "lifecycleDisruption(map_server)",
        "map_server_down(f1tenth)",
    ],
    "def_safe_drive_override": [
        "topicWrite('/drive')",
        "gradualDrift('/drive')",
        "command_unsafe(f1tenth)",
        "drive_DoS(f1tenth)",
    ],
    "def_rotate_credentials": [
        "credentialAccess(robot_host)",
    ],
    "def_enable_dds_security": [
        "attackerCanJoinRosGraph(robot_host)",
        "topicWrite('/scan')",
        "topicWrite('/drive')",
        "topicRead('/scan')",
        "topicRead('/odom')",
        "topicFlood('/drive')",
        "maliciousTopicContent('/scan')",
        "qosDegradation('/scan')",
        "serviceCall('/bridge/set_parameters',bridge)",
        "serviceCall('/map_server/change_state',map_server)",
        "serviceCall('/map_server/set_parameters',map_server)",
    ],
}


def revoke_attacker_predicates(defense_name):
    """Poll state.json for target predicates to appear, then revoke them."""
    preds = DEFENSE_REVOKES.get(defense_name, [])
    if not preds:
        return []

    # 0.5 s catches a live attacker's atomic state.json write (~5 ms)
    # with margin for scheduling jitter; longer values just stall the
    # alert handler when no attacker is running.
    POLL_TIMEOUT = 0.5
    POLL_INTERVAL = 0.05

    deadline = time.time() + POLL_TIMEOUT
    state = None
    landed = False
    while time.time() < deadline:
        if not os.path.exists(ATTACKER_STATE_PATH):
            time.sleep(POLL_INTERVAL)
            continue
        try:
            with open(ATTACKER_STATE_PATH) as f:
                state = json.load(f)
        except Exception:
            time.sleep(POLL_INTERVAL)
            continue
        preds_now = state.get("predicates", {}) or {}
        if any(preds_now.get(p) for p in preds):
            landed = True
            break
        time.sleep(POLL_INTERVAL)

    if not landed:
        if state is None:
            try:
                with open(ATTACKER_STATE_PATH) as f:
                    state = json.load(f)
            except Exception:
                state = {"facts": {}, "predicates": {}, "smg": {"t": 1}, "meta": {}}

    state.setdefault("predicates", {})
    state.setdefault("meta", {})
    # blocked_predicates is a soft-lockout dict checked by attacker's mark_pred / propagate_derived.
    BLOCK_TTL_SEC = 10.0
    blocked = state["meta"].setdefault("blocked_predicates", {})
    revoked = []
    now = time.time()
    expiry = now + BLOCK_TTL_SEC
    for p in preds:
        blocked[p] = expiry
        if state["predicates"].pop(p, False):
            revoked.append(p)
            state["meta"][f"revoked_by_defender::{p}"] = (
                f"{defense_name}@{now:.3f}"
            )
            state["meta"].pop(f"why::{p}", None)

    try:
        # Atomic write so attacker never sees a half-written state.json.
        tmp_path = f"{ATTACKER_STATE_PATH}.tmp.{os.getpid()}"
        with open(tmp_path, "w") as f:
            json.dump(state, f, indent=2, sort_keys=True)
        os.replace(tmp_path, ATTACKER_STATE_PATH)
        if revoked:
            print(f"[DEFENDER] REVOKED {revoked} — predicate(s) cleared from state.json",
                  flush=True)
            _combined_log("DEFENDER",
                f"REVOKED {revoked} (predicates removed from state.json)")
        else:
            print(f"[DEFENDER] REVOKED {preds} — locked out via blocked_predicates "
                  f"(TTL={BLOCK_TTL_SEC}s, attacker can't mark in next step)",
                  flush=True)
            _combined_log("DEFENDER",
                f"REVOKED {preds} (preemptive lockout — attacker hadn't marked yet)")
    except Exception as e:
        print(f"[DEFENDER] could not write state.json: {e}", flush=True)
    return list(preds)


_STRAT_RE = re.compile(r"^\(([^)]+)\)=(.*)$")


def _prism_vars_hash():
    """SHA256 prefix of PRISM_VARS; embedded in Strat.txt header for lock-step verification."""
    import hashlib
    blob = "\n".join(PRISM_VARS).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def parse_strategy(path):
    """Parse a PRISM Strat.txt file into a {state_tuple: action} table."""
    table = {}
    n_vars = len(PRISM_VARS)
    skipped = 0
    expected_hash = _prism_vars_hash()
    file_hash = None
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("#"):
                m_hash = re.search(r"vars_sha256:\s*([0-9a-f]{8,})", stripped)
                if m_hash:
                    file_hash = m_hash.group(1)[:16]
                continue
            m = _STRAT_RE.match(stripped)
            if not m:
                continue
            tup_str, action = m.group(1), m.group(2).strip()
            parts = [p.strip() for p in tup_str.split(",")]
            if len(parts) != n_vars + 1:
                skipped += 1
                continue
            try:
                bits = tuple(p.lower() == "true" for p in parts[:-1])
                t = int(parts[-1])
            except ValueError:
                skipped += 1
                continue
            table[bits + (t,)] = action

    if file_hash is None:
        print(f"[defender] WARNING: strategy file has no vars_sha256 header "
              f"(expected hash={expected_hash}); skipping verification. "
              f"Add `# vars_sha256: {expected_hash}` to {path} line 1 "
              f"to enable lock-step checking.")
    elif file_hash != expected_hash:
        raise RuntimeError(
            f"strategy file PRISM_VARS hash mismatch: "
            f"file={file_hash}, expected={expected_hash}. "
            f"Either Strat.txt was generated against a different model, "
            f"or PRISM_VARS in defender_agent.py is out of date. "
            f"Regenerate Strat.txt or align PRISM_VARS before continuing."
        )
    else:
        print(f"[defender] PRISM_VARS hash verified ({expected_hash})")

    print(f"[defender] loaded {len(table)} strategy entries from {path}"
          f" (skipped {skipped})")
    return table


class DefenderNode(Node):
    def __init__(self, strategy):
        """Initialize defender node, subscribers, clients, and watcher thread."""
        super().__init__("defender_agent")
        self.strategy = strategy
        self.state = {v: False for v in PRISM_VARS}
        self._last_acted = {v: 0.0 for v in PRISM_VARS}
        self.sub = self.create_subscription(
            String, "/monitor_alerts", self.on_alert, 50,
        )
        # Monitor allowlists "defender_agent" so this publisher isn't itself flagged.
        self.drive_pub = self.create_publisher(
            AckermannDriveStamped, "/drive", 10,
        )
        self.set_param_cli_bridge = self.create_client(
            SetParameters, "/bridge/set_parameters")
        self.set_param_cli_map = self.create_client(
            SetParameters, "/map_server/set_parameters")
        self.change_state_cli_map = self.create_client(
            ChangeState, "/map_server/change_state")
        self.transition_event_pub = self.create_publisher(
            TransitionEvent, "/map_server/transition_event",
            QoSProfile(reliability=ReliabilityPolicy.RELIABLE,
                       durability=DurabilityPolicy.TRANSIENT_LOCAL,
                       history=HistoryPolicy.KEEP_LAST, depth=1))
        global g_defender_node
        g_defender_node = self

        self._post_hoc_queue = []
        self._queue_lock = threading.Lock()
        self._watcher_stop = threading.Event()
        self._watcher = threading.Thread(
            target=self._step_done_watcher, daemon=True
        )
        self._watcher.start()

        self.get_logger().info(
            "defender_agent ready, listening on /monitor_alerts"
            " (post-hoc queue active)"
        )

    def _step_done_watcher(self):
        """Drain queued alerts when step_done_mtime advances; SIGUSR1 monitor to reset latches."""
        SAFETY_TIMEOUT = 15.0
        last_step_done_mtime = 0.0
        while not self._watcher_stop.is_set():
            try:
                step_done_mtime = os.stat(ATTACKER_STEP_DONE_PATH).st_mtime
            except FileNotFoundError:
                step_done_mtime = 0.0

            if step_done_mtime > last_step_done_mtime:
                last_step_done_mtime = step_done_mtime
                try:
                    subprocess.run(
                        ["pkill", "-SIGUSR1", "-f", "system_monitor_node"],
                        check=False, timeout=2,
                    )
                except Exception:
                    pass

            now = time.time()
            ready = []
            with self._queue_lock:
                still_waiting = []
                for alert, queued_at in self._post_hoc_queue:
                    if step_done_mtime > queued_at:
                        ready.append((alert, "step_done"))
                    elif (now - queued_at) > SAFETY_TIMEOUT:
                        ready.append((alert, "safety_timeout"))
                    else:
                        still_waiting.append((alert, queued_at))
                self._post_hoc_queue = still_waiting
            for alert, reason in ready:
                self.get_logger().info(
                    f"draining post-hoc alert {alert} (reason={reason})"
                )
                _combined_log("DEFENDER", f"draining {alert} (reason={reason})")
                self._handle_alert_inline(alert)
            time.sleep(0.1)

    def _print_state(self, prefix=""):
        """Log the current PRISM-bit state as a compact flag string."""
        SHORT = {
            "drive_DoS_f1tenth_":                 "driveDoS",
            "command_unsafe_f1tenth_":            "cmdUnsafe",
            "scan_corrupted_f1tenth_":            "scanCorr",
            "scan_unreliable_f1tenth_":           "scanUnrel",
            "map_server_down_f1tenth_":           "mapDown",
            "bridge_misconfigured_f1tenth_":      "bridgeMis",
            "data_leaked_f1tenth_":               "dataLeak",
            "initialAccess_engineering_ws_":      "initAcc",
            "lateralAccess_robot_host_":          "latAcc",
            "credentialAccess_robot_host_":       "credAcc",
            "attackerOnRosNetwork_robot_host_":   "onROSNet",
            "attackerCanJoinRosGraph_robot_host_": "joinGraph",
            "attackerCanNetAdmin_robot_host_":    "netAdmin",
        }
        flags = ",".join(
            SHORT.get(v, v) + ("=T" if self.state[v] else "=F")
            for v in PRISM_VARS[1:]
        )
        self.get_logger().info(f"{prefix} state: {flags}")

    def on_alert(self, msg):
        """Handle an incoming monitor alert, queuing or dispatching it."""
        # Strip optional explanation suffix from "REQ_X: blah blah".
        alert = msg.data.split(":", 1)[0].strip()
        var = ALERT_TO_VAR.get(alert)
        if var is None:
            self.get_logger().warn(f"unknown alert {alert!r}; ignored")
            return
        now = time.time()
        if now - self._last_acted[var] < ALERT_COOLDOWN_SEC:
            return
        if self.state[var]:
            # REQ_command_unsafe always re-runs the brake even if the bit
            # was already set by a previous defense that didn't clear it.
            if alert == "REQ_command_unsafe":
                self.state[var] = False
            else:
                return

        timing = ALERT_TIMING.get(alert, "immediate")
        if timing == "post_hoc":
            with self._queue_lock:
                self._post_hoc_queue.append((alert, now))
            self.get_logger().info(
                f"alert {alert} queued (post-hoc; waits for attacker step-done)"
            )
            _combined_log("DEFENDER", f"queued {alert} (post-hoc)")
            return
        _combined_log("DEFENDER", f"received {alert} (immediate)")
        self._handle_alert_inline(alert)

    def _handle_alert_inline(self, alert):
        """Set the bit, cascade foundation, and run the defense."""
        var = ALERT_TO_VAR.get(alert)
        if var is None:
            return
        now = time.time()
        if now - self._last_acted[var] < ALERT_COOLDOWN_SEC:
            return
        if self.state[var]:
            return
        self.state[var] = True
        self._current_alert = alert
        self.get_logger().info(f"alert {alert} -> {var}=True")
        # Effect alert: infer required foundation predicates.
        for foundation_var in EFFECT_FOUNDATION_DEPS.get(var, []):
            if foundation_var in self.state and not self.state[foundation_var]:
                self.state[foundation_var] = True
                self.get_logger().info(
                    f"inferred foundation: {foundation_var}=True "
                    f"(precondition of {var})"
                )
        # Foundation alert: infer upstream chain.
        for upstream in FOUNDATION_PREDECESSORS.get(var, []):
            if upstream in self.state and not self.state[upstream]:
                self.state[upstream] = True
                self.get_logger().info(
                    f"inferred upstream: {upstream}=True (predecessor of {var})"
                )
        self._print_state(prefix="post-alert")
        self._react()

        # Safety override: REQ_can_net_admin has no strategy-direct defense.
        if alert == "REQ_can_net_admin":
            try:
                def_restore_scan_quality()
                _combined_log("DEFENDER",
                    "safety override on REQ_can_net_admin: "
                    "def_restore_scan_quality (clears tc qdisc + blocks scan_unreliable)")
                revoke_attacker_predicates("def_restore_scan_quality")
            except Exception as e:
                self.get_logger().warn(f"safety override failed: {e}")

        # Safety net: REQ_command_unsafe always brakes, even when the
        # strategy's reliability dice rolls bad.
        if alert == "REQ_command_unsafe":
            now = time.time()
            last = getattr(self, "_last_safe_drive_override_ts", 0.0)
            if now - last < 5.0:
                self.get_logger().info(
                    f"safety net on {alert}: skipped (cooldown, {now-last:.1f}s < 5.0s)")
            else:
                self._last_safe_drive_override_ts = now
                try:
                    def_safe_drive_override()
                    _combined_log("DEFENDER",
                        f"safety net on {alert}: "
                        f"def_safe_drive_override — car brakes")
                    revoke_attacker_predicates("def_safe_drive_override")
                except Exception as e:
                    self.get_logger().warn(f"safety net failed: {e}")

    def _publish_turn_complete(self, action_taken=None):
        """Write turn-complete barrier file so the polling attacker advances."""
        try:
            with open(TURN_COMPLETE_PATH, "w") as f:
                f.write(f"{time.time()}\n{action_taken or 'noop'}\n")
        except Exception as e:
            self.get_logger().warn(f"could not write turn-complete flag: {e}")

    def _react(self):
        """Look up the strategy-prescribed defense and execute it for this turn."""
        action_taken = None
        revoked_list = []
        defense_succeeded = False
        TURN_KILLS.clear()
        try:
            bits = tuple(self.state[v] for v in PRISM_VARS)
            key = bits + (2,)
            action = self.strategy.get(key)
            if action is None:
                self.get_logger().warn(
                    f"no strategy entry for state tuple {key}; skipping"
                )
                return
            if not action.startswith("def_"):
                self.get_logger().warn(
                    f"strategy returned non-defense {action!r} at t=2; skipping"
                )
                return
            fn, clears = DEFENSES.get(action, (None, []))
            if fn is None:
                self.get_logger().warn(f"unknown defense {action!r}; skipping")
                return
            action_taken = action
            self.get_logger().info(f"strategy says: {action} (clears {clears})")
            _combined_log("DEFENDER", f"strategy chose {action} (clears {clears})")
            # Reliability dice rolled first; on pass we run fn() AND revoke regardless of fn() outcome.
            import random as _r
            reliability = DEFENSE_RELIABILITY.get(action, 0.90)
            rdice = _r.random()
            defense_succeeded = (rdice < reliability)

            if not defense_succeeded:
                self.get_logger().warn(
                    f"defense {action} reliability dice FAILED "
                    f"({rdice:.3f} >= {reliability:.2f}); skipping mechanism"
                )
                _combined_log("DEFENDER",
                              f"defense {action} reliability dice FAILED "
                              f"({rdice:.3f} >= {reliability:.2f})")
                defense_real = False
            else:
                self.get_logger().info(
                    f"defense {action} reliability dice OK "
                    f"({rdice:.3f} < {reliability:.2f}); running mechanism"
                )
                _combined_log("DEFENDER",
                              f"defense {action} reliability dice OK "
                              f"({rdice:.3f} < {reliability:.2f})")
                try:
                    defense_real = bool(fn())
                except Exception as e:
                    self.get_logger().error(f"defense {action} raised: {e}")
                    _combined_log("DEFENDER", f"defense {action} RAISED: {e}")
                    defense_real = False

            if defense_succeeded:
                now = time.time()
                for v in clears:
                    self.state[v] = False
                    self._last_acted[v] = now
                revoked_list = revoke_attacker_predicates(action) or []
                if revoked_list:
                    self.get_logger().info(
                        f"sent attacker back: revoked {len(revoked_list)} predicate(s)"
                    )
            else:
                _combined_log("DEFENDER", f"defense {action} did NOT succeed (no revoke)")
                self.get_logger().warn(
                    f"defense {action} did NOT succeed — leaving bits {clears} set"
                )
            self._print_state(prefix="post-defense")
        finally:
            summary = {
                "turn_ts": time.time(),
                "alert": getattr(self, "_current_alert", None),
                "defense": action_taken,
                "defense_succeeded": defense_succeeded,
                "killed": list(TURN_KILLS),
                "revoked": revoked_list,
            }
            try:
                with open("/tmp/defender_last_turn.json", "w") as f:
                    json.dump(summary, f, indent=2)
            except Exception as e:
                self.get_logger().warn(f"could not write defender_last_turn.json: {e}")
            self._publish_turn_complete(action_taken)


def main():
    """Load strategy and spin the defender ROS node until interrupted."""
    if len(sys.argv) < 2:
        print("usage: defender_agent.py <path/to/Strat.txt>")
        sys.exit(1)
    strat_path = sys.argv[1]
    if not os.path.exists(strat_path):
        print(f"strategy file not found: {strat_path}")
        sys.exit(1)
    strategy = parse_strategy(strat_path)
    if not strategy:
        print("strategy file parsed to 0 entries - check PRISM_VARS order matches the .prism")
        sys.exit(1)

    rclpy.init()
    node = DefenderNode(strategy)
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
