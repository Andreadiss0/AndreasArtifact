// ROS 2 wrapper around the generated PTLTL Monitor.c. Feeds extern
// variables and publishes REQ_* alerts on /monitor_alerts.

#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <sensor_msgs/msg/laser_scan.hpp>
#include <ackermann_msgs/msg/ackermann_drive_stamped.hpp>
#include <rcl_interfaces/msg/parameter_event.hpp>
#include <lifecycle_msgs/msg/transition_event.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "Monitor.h"
}

// Externs consumed by Monitor.c. C linkage so .c and .cpp share storage.
extern "C" {

int64_t drive_publisher_count = 0;
int64_t drive_msg_rate_hz = 0;
float   drive_speed_abs = 0.0f;
float   drive_steering_abs = 0.0f;

int64_t scan_invalid_count = 0;
int64_t scan_zero_count = 0;
float   scan_range_spread = 1.0f;
int64_t scan_publisher_count = 0;
float   scan_stamp_age_sec = 0.0f;
int64_t scan_msg_rate_hz = 0;
int64_t scan_observed_reliability = 1;

int64_t scan_subscriber_count = 0;
int64_t odom_subscriber_count = 0;

int64_t map_server_state = 3;
int64_t bridge_param_change_count = 0;

int64_t attacker_foothold_count = 0;
int64_t attacker_lateral_count = 0;
int64_t attacker_creds_count = 0;
int64_t attacker_on_ros_network_count = 0;
int64_t attacker_net_admin_count = 0;
int64_t unauth_node_count = 0;

int64_t cfg_expected_drive_publishers = 1;
int64_t cfg_max_drive_rate            = 200;
float   cfg_max_safe_speed            = 3.0f;
float   cfg_max_safe_steering         = 0.5f;
int64_t cfg_max_scan_invalid_count    = 20;
int64_t cfg_max_scan_zero_count       = 20;
float   cfg_min_scan_range_spread     = 0.01f;
int64_t cfg_expected_scan_publishers  = 1;
float   cfg_max_scan_stamp_age_sec    = 1.0f;
int64_t cfg_min_scan_rate             = 30;
int64_t cfg_expected_scan_reliability = 1;
int64_t cfg_active_state              = 3;
int64_t cfg_expected_scan_subscribers = 1;
int64_t cfg_expected_odom_subscribers = 1;

// SIGUSR1 reset request -- cleared at the start of each tick.
volatile sig_atomic_t g_reset_requested = 0;
}  // extern "C"

static void monitor_sigusr1_handler(int /*signum*/) { g_reset_requested = 1; }

extern "C" void reset_all_alert_latches(void);
extern "C" void reset_all_ptltl_state(void);

namespace {

// CredentialAccess detection: inotify IN_OPEN on the SROS2 keystore.
static std::atomic<int64_t> keystore_unauth_open_count{0};
// Sliding-window timestamps of post-grace keystore opens; tick() prunes
// entries older than kCredWindowSec and fires when the surviving count
// reaches kCredBurstThreshold.
static std::deque<std::chrono::steady_clock::time_point> keystore_open_window;
static std::mutex keystore_open_mtx;
static constexpr double kCredWindowSec = 2.0;
static constexpr size_t kCredBurstThreshold = 5;
static const char * kKeystoreRoot = "/home/f1tenth/sros2_keystore_f1tenth";

static std::chrono::steady_clock::time_point g_monitor_start;
static constexpr int kStartupGraceSec = 30;
static double seconds_since_start()
{
  return std::chrono::duration<double>(
    std::chrono::steady_clock::now() - g_monitor_start).count();
}

static void inotify_keystore_thread()
{
  int fd = inotify_init1(IN_NONBLOCK);
  if (fd < 0) {
    fprintf(stderr, "[monitor] inotify_init1 failed: %s\n", strerror(errno));
    return;
  }
  // inotify is non-recursive -- walk the keystore subtree manually.
  std::vector<std::string> dirs_to_watch = {kKeystoreRoot};
  if (DIR * d = opendir(kKeystoreRoot)) {
    while (struct dirent * de = readdir(d)) {
      if (de->d_name[0] == '.') continue;
      std::string sub = std::string(kKeystoreRoot) + "/" + de->d_name;
      struct stat st;
      if (stat(sub.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        dirs_to_watch.push_back(sub);
        if (DIR * d2 = opendir(sub.c_str())) {
          while (struct dirent * de2 = readdir(d2)) {
            if (de2->d_name[0] == '.') continue;
            std::string sub2 = sub + "/" + de2->d_name;
            struct stat st2;
            if (stat(sub2.c_str(), &st2) == 0 && S_ISDIR(st2.st_mode)) {
              dirs_to_watch.push_back(sub2);
            }
          }
          closedir(d2);
        }
      }
    }
    closedir(d);
  }
  for (const auto & p : dirs_to_watch) {
    int wd = inotify_add_watch(fd, p.c_str(), IN_OPEN);
    if (wd < 0) {
      fprintf(stderr, "[monitor] inotify_add_watch(%s) failed: %s\n",
              p.c_str(), strerror(errno));
    }
  }
  // Grace window: drop legit boot-time reads.
  auto end_grace = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  char buf[4096];
  while (true) {
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        continue;
      }
      break;
    }
    auto now_tp = std::chrono::steady_clock::now();
    bool grace = now_tp < end_grace;
    char * p = buf;
    while (p < buf + n) {
      inotify_event * ev = reinterpret_cast<inotify_event *>(p);
      if (!grace) {
        keystore_unauth_open_count.fetch_add(1);
        {
          std::lock_guard<std::mutex> lk(keystore_open_mtx);
          keystore_open_window.push_back(now_tp);
        }
      }
      p += sizeof(inotify_event) + ev->len;
    }
  }
  close(fd);
}

// Net-admin detection: snapshot `tc qdisc show` per iface at startup,
// flag any diff seen at runtime.
static std::map<std::string, std::string> tc_baseline;
static const std::vector<const char *> kTcIfaces = {"lo", "eth0", "wlan0"};

static std::string tc_qdisc_show(const char * iface)
{
  std::string cmd = std::string("tc qdisc show dev ") + iface + " 2>/dev/null";
  FILE * f = popen(cmd.c_str(), "r");
  if (!f) return "";
  char buf[1024];
  std::string out;
  while (fgets(buf, sizeof(buf), f)) out.append(buf);
  pclose(f);
  return out;
}

static void tc_baseline_snapshot()
{
  for (const char * iface : kTcIfaces) {
    tc_baseline[iface] = tc_qdisc_show(iface);
  }
}

static int64_t tc_unexpected_rule_count_now()
{
  int64_t c = 0;
  for (const char * iface : kTcIfaces) {
    auto it = tc_baseline.find(iface);
    if (it == tc_baseline.end()) continue;
    std::string current = tc_qdisc_show(iface);
    if (!current.empty() && current != it->second) {
      ++c;
    }
  }
  return c;
}

// Allowlist for ros2 node list; anything else counts as unauthorized.
const std::vector<std::regex> & node_allowlist()
{
  static const std::vector<std::regex> a = {
    std::regex(R"(/bridge)"),
    std::regex(R"(/ego_robot_state_publisher)"),
    std::regex(R"(/lifecycle_manager_localization.*)"),
    std::regex(R"(/map_server)"),
    std::regex(R"(/rviz)"),
    std::regex(R"(/transform_listener_impl.*)"),
    std::regex(R"(/system_monitor_node)"),
    std::regex(R"(/defender_agent.*)"),
    std::regex(R"(/launch_ros.*)"),
    std::regex(R"(/alerts_sniffer)"),
    std::regex(R"(/_ros2cli_\d+)"),
    std::regex(R"(/_ros2cli_daemon_\d+)"),
    std::regex(R"(/launch_ros_\d+)"),
    std::regex(R"(/_ros2_daemon)"),
  };
  return a;
}

bool node_allowed(const std::string & name)
{
  for (const auto & re : node_allowlist()) {
    if (std::regex_match(name, re)) return true;
  }
  return false;
}

// Counts subscribers on a topic; subtracts our own sub when applicable.
int64_t topic_subscriber_count(rclcpp::Node * node, const std::string & topic,
                               bool self_subscribes)
{
  int64_t n = static_cast<int64_t>(node->count_subscribers(topic));
  if (self_subscribes) n = std::max<int64_t>(0, n - 1);
  return n;
}

int64_t topic_publisher_count(rclcpp::Node * node, const std::string & topic)
{
  return static_cast<int64_t>(node->count_publishers(topic));
}

int64_t unauth_node_count_now(rclcpp::Node * node)
{
  auto names = node->get_node_names();
  int64_t n = 0;
  for (const auto & nm : names) {
    if (!node_allowed(nm)) {
      ++n;
      RCLCPP_INFO(node->get_logger(),
        "UNAUTH_NODE_DETECTED: %s", nm.c_str());
    }
  }
  return n;
}

// Sums per-topic endpoint counts contributed by non-allowlisted nodes.
struct AttackerEndpointCounts {
  int64_t scan_sub  = 0;
  int64_t odom_sub  = 0;
  int64_t scan_pub  = 0;
  int64_t drive_pub = 0;
};

// Returns "/ns/name" (or "/name") for a TopicEndpointInfo.
static std::string endpoint_node_full_name(
    const rclcpp::TopicEndpointInfo & ep)
{
  std::string ns = ep.node_namespace();
  std::string nm = ep.node_name();
  if (ns.empty() || ns == "/") return "/" + nm;
  if (ns.back() == '/') return ns + nm;
  return ns + "/" + nm;
}

AttackerEndpointCounts attacker_endpoint_counts(rclcpp::Node * node)
{
  AttackerEndpointCounts c;
  try {
    for (const auto & ep : node->get_subscriptions_info_by_topic("/scan")) {
      if (!node_allowed(endpoint_node_full_name(ep))) ++c.scan_sub;
    }
  } catch (...) {}
  try {
    for (const auto & ep : node->get_subscriptions_info_by_topic("/ego_racecar/odom")) {
      if (!node_allowed(endpoint_node_full_name(ep))) ++c.odom_sub;
    }
    for (const auto & ep : node->get_subscriptions_info_by_topic("/odom")) {
      if (!node_allowed(endpoint_node_full_name(ep))) ++c.odom_sub;
    }
  } catch (...) {}
  try {
    for (const auto & ep : node->get_publishers_info_by_topic("/scan")) {
      if (!node_allowed(endpoint_node_full_name(ep))) ++c.scan_pub;
    }
  } catch (...) {}
  try {
    for (const auto & ep : node->get_publishers_info_by_topic("/drive")) {
      if (!node_allowed(endpoint_node_full_name(ep))) ++c.drive_pub;
    }
  } catch (...) {}
  return c;
}

}  // namespace

class SystemMonitorNode final : public rclcpp::Node
{
public:
  SystemMonitorNode()
  : Node("system_monitor_node")
  {
    alerts_pub_ = this->create_publisher<std_msgs::msg::String>("/monitor_alerts", 50);

    scan_sub_ = this->create_subscription<sensor_msgs::msg::LaserScan>(
      "/scan",
      rclcpp::QoS(rclcpp::KeepLast(10)).reliable(),
      std::bind(&SystemMonitorNode::on_scan, this, std::placeholders::_1));

    drive_sub_ = this->create_subscription<ackermann_msgs::msg::AckermannDriveStamped>(
      "/drive", 10,
      std::bind(&SystemMonitorNode::on_drive, this, std::placeholders::_1));

    param_events_sub_ = this->create_subscription<rcl_interfaces::msg::ParameterEvent>(
      "/parameter_events", 10,
      std::bind(&SystemMonitorNode::on_parameter_event, this, std::placeholders::_1));

    // Track map_server lifecycle via transition events. TRANSIENT_LOCAL
    // so we still receive the latest event if pub/sub discovery races.
    rclcpp::QoS lifecycle_qos(rclcpp::KeepLast(1));
    lifecycle_qos.reliable();
    lifecycle_qos.transient_local();
    lifecycle_sub_ = this->create_subscription<lifecycle_msgs::msg::TransitionEvent>(
      "/map_server/transition_event", lifecycle_qos,
      std::bind(&SystemMonitorNode::on_lifecycle_event, this, std::placeholders::_1));

    tc_baseline_snapshot();

    std::thread(inotify_keystore_thread).detach();

    timer_ = this->create_wall_timer(
      std::chrono::milliseconds(1000),
      std::bind(&SystemMonitorNode::tick, this));

    RCLCPP_INFO(this->get_logger(), "system_monitor_node started");
  }

  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr get_alert_pub() const { return alerts_pub_; }

private:
  void on_scan(const sensor_msgs::msg::LaserScan::SharedPtr msg)
  {
    ++scan_msg_count_;
    scan_msg_received_ever_.store(true);

    int64_t invalid = 0;
    int64_t zeros = 0;
    float rmin = std::numeric_limits<float>::infinity();
    float rmax = -std::numeric_limits<float>::infinity();
    bool any_finite = false;

    for (float r : msg->ranges) {
      if (std::isnan(r) || std::isinf(r)) {
        ++invalid;
      } else {
        if (std::fabs(r) < 1e-6f) ++zeros;
        rmin = std::min(rmin, r);
        rmax = std::max(rmax, r);
        any_finite = true;
      }
    }

    scan_invalid_count = invalid;
    scan_zero_count = zeros;
    scan_range_spread = any_finite ? (rmax - rmin) : 1.0f;

    const double t_msg = static_cast<double>(msg->header.stamp.sec) +
                         static_cast<double>(msg->header.stamp.nanosec) * 1e-9;
    const double t_now = this->now().seconds();
    scan_stamp_age_sec = static_cast<float>(std::max(0.0, t_now - t_msg));
  }

  void on_drive(const ackermann_msgs::msg::AckermannDriveStamped::SharedPtr msg)
  {
    ++drive_msg_count_;
    drive_speed_abs = std::fabs(msg->drive.speed);
    drive_steering_abs = std::fabs(msg->drive.steering_angle);
  }

  void on_parameter_event(const rcl_interfaces::msg::ParameterEvent::SharedPtr msg)
  {
    if (msg->node != "/bridge" && msg->node != "bridge") return;
    bridge_param_change_count += static_cast<int64_t>(
      msg->changed_parameters.size() +
      msg->new_parameters.size() +
      msg->deleted_parameters.size());
  }

  void on_lifecycle_event(const lifecycle_msgs::msg::TransitionEvent::SharedPtr msg)
  {
    map_server_state = static_cast<int64_t>(msg->goal_state.id);
  }

  // 1 Hz tick: snapshot counters, poll DDS / host signals, step the monitor.
  void tick()
  {
    if (g_reset_requested) {
      reset_all_alert_latches();
      reset_all_ptltl_state();
      bridge_param_change_count = 0;
      keystore_unauth_open_count.store(0);
      // keystore_open_window intentionally NOT cleared -- it self-decays
      // via kCredWindowSec; clearing here would drop evidence of a burst
      // that straddles a SIGUSR1 boundary.
      g_reset_requested = 0;
      RCLCPP_INFO(this->get_logger(),
        "alert latches + PTLTL state + inotify counter reset");
    }

    // Startup-race guard: until the first /scan arrives, pin the rate to
    // a safe value so the first tick can't trip REQ_scan_unreliable.
    drive_msg_rate_hz = drive_msg_count_.exchange(0);
    int64_t scan_count_this_tick = scan_msg_count_.exchange(0);
    if (scan_msg_received_ever_.load()) {
      scan_msg_rate_hz = scan_count_this_tick;
    } else {
      scan_msg_rate_hz = std::max<int64_t>(cfg_min_scan_rate, 10);
    }

    drive_publisher_count = topic_publisher_count(this, "/drive");
    scan_publisher_count = topic_publisher_count(this, "/scan");
    scan_subscriber_count = topic_subscriber_count(this, "/scan", /*self*/ true);
    odom_subscriber_count = topic_subscriber_count(this, "/ego_racecar/odom", /*self*/ false);

    // Supplement count_*() with endpoint walks so SROS2 identity-conflict
    // refusals still register attacker pubs/subs.
    {
      auto extra = attacker_endpoint_counts(this);
      scan_subscriber_count += extra.scan_sub;
      odom_subscriber_count += extra.odom_sub;
      scan_publisher_count  += extra.scan_pub;
      drive_publisher_count += extra.drive_pub;
    }

    // Flag /scan as unreliable if any publisher uses BEST_EFFORT.
    {
      auto pubs = this->get_publishers_info_by_topic("/scan");
      bool any_best_effort = false;
      for (const auto & ep : pubs) {
        const auto r = ep.qos_profile().get_rmw_qos_profile().reliability;
        if (r == RMW_QOS_POLICY_RELIABILITY_BEST_EFFORT) any_best_effort = true;
      }
      scan_observed_reliability = any_best_effort ? 0 : 1;
    }

    // Treat stamp_age > 300 ms as unreliable to catch tc netem delay.
    if (scan_stamp_age_sec > 0.3f) {
      scan_observed_reliability = 0;
    }

    unauth_node_count = unauth_node_count_now(this);

    // Sliding-window credentialAccess detection.
    {
      const auto now_tp = std::chrono::steady_clock::now();
      const auto cutoff = now_tp - std::chrono::duration_cast<
        std::chrono::steady_clock::duration>(
          std::chrono::duration<double>(kCredWindowSec));
      size_t window_count = 0;
      {
        std::lock_guard<std::mutex> lk(keystore_open_mtx);
        while (!keystore_open_window.empty() &&
               keystore_open_window.front() < cutoff) {
          keystore_open_window.pop_front();
        }
        window_count = keystore_open_window.size();
      }
      attacker_creds_count = (window_count >= kCredBurstThreshold) ? 1 : 0;
    }

    // attackerCanNetAdmin: tc qdisc diff polled every 5th tick (popen is slow).
    static int tc_tick = 0;
    static int64_t tc_diff_cached = 0;
    if (++tc_tick >= 5) {
      tc_tick = 0;
      tc_diff_cached = tc_unexpected_rule_count_now();
    }
    attacker_net_admin_count = tc_diff_cached;

    // Host-event predicates are out of scope for this ROS-layer monitor.
    attacker_foothold_count        = 0;
    attacker_lateral_count         = 0;
    attacker_on_ros_network_count  = 0;

    RCLCPP_INFO(this->get_logger(),
      "tick: drive[pub=%ld rate=%ld speed=%.2f steer=%.2f] scan[pub=%ld sub=%ld rate=%ld inv=%ld zero=%ld spread=%.3f rel=%ld age=%.2f] map=%ld br_chg=%ld foot=%ld lat=%ld cred=%ld onrn=%ld na=%ld unauth=%ld",
      drive_publisher_count, drive_msg_rate_hz, drive_speed_abs, drive_steering_abs,
      scan_publisher_count, scan_subscriber_count, scan_msg_rate_hz, scan_invalid_count,
      scan_zero_count, scan_range_spread, scan_observed_reliability, scan_stamp_age_sec,
      map_server_state, bridge_param_change_count,
      attacker_foothold_count, attacker_lateral_count, attacker_creds_count,
      attacker_on_ros_network_count, attacker_net_admin_count, unauth_node_count);

    step();
  }

  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr alerts_pub_;
  rclcpp::Subscription<sensor_msgs::msg::LaserScan>::SharedPtr scan_sub_;
  rclcpp::Subscription<ackermann_msgs::msg::AckermannDriveStamped>::SharedPtr drive_sub_;
  rclcpp::Subscription<rcl_interfaces::msg::ParameterEvent>::SharedPtr param_events_sub_;
  rclcpp::Subscription<lifecycle_msgs::msg::TransitionEvent>::SharedPtr lifecycle_sub_;
  rclcpp::TimerBase::SharedPtr timer_;

  std::atomic<int64_t> drive_msg_count_{0};
  std::atomic<int64_t> scan_msg_count_{0};
  std::atomic<bool> scan_msg_received_ever_{false};
};

static std::shared_ptr<SystemMonitorNode> g_smnode;

// Monitor.c calls one handler per violated property. Each publishes its
// REQ_* alert once until reset_all_alert_latches() clears the latch.
extern "C" {

static void publish_alert_once(const char * text, bool & already_sent,
                               const char * cause = "")
{
  if (already_sent || !g_smnode) return;
  std_msgs::msg::String msg;
  if (cause && *cause) {
    msg.data = std::string(text) + ": " + cause;
  } else {
    msg.data = text;
  }
  g_smnode->get_alert_pub()->publish(msg);
  already_sent = true;
  RCLCPP_WARN(g_smnode->get_logger(),
              "[ALERT_CAUSE] %s -- %s", text, cause ? cause : "(no detail)");
}

static bool in_startup_grace()
{
  return seconds_since_start() < kStartupGraceSec;
}

static bool sent_drive_DoS = false;
static bool sent_command_unsafe = false;
static bool sent_scan_corrupted = false;
static bool sent_scan_unreliable = false;
static bool sent_map_server_down = false;
static bool sent_bridge_misconfigured = false;
static bool sent_data_leaked = false;
static bool sent_initial_access = false;
static bool sent_lateral_access = false;
static bool sent_credential_access = false;
static bool sent_on_ros_network = false;
static bool sent_can_join_ros_graph = false;
static bool sent_can_net_admin = false;

void reset_all_alert_latches(void)
{
  sent_drive_DoS = false;
  sent_command_unsafe = false;
  sent_scan_corrupted = false;
  sent_scan_unreliable = false;
  sent_map_server_down = false;
  sent_bridge_misconfigured = false;
  sent_data_leaked = false;
  sent_initial_access = false;
  sent_lateral_access = false;
  sent_credential_access = false;
  sent_on_ros_network = false;
  sent_can_join_ros_graph = false;
  sent_can_net_admin = false;
}

static char g_cause_buf[512];

void handlerREQ_drive_DoS(void) {
  if (in_startup_grace()) return;
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "/drive: %ld publishers (expected <=%ld), rate=%ld Hz (max %ld) "
    "-- attack is likely topicWrite('/drive') or topicFlood('/drive')",
    drive_publisher_count, cfg_expected_drive_publishers,
    drive_msg_rate_hz, cfg_max_drive_rate);
  publish_alert_once("REQ_drive_DoS", sent_drive_DoS, g_cause_buf);
}
void handlerREQ_command_unsafe(void) {
  if (in_startup_grace()) return;
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "/drive: speed=%.2f m/s (safe<=%.2f) steer=%.2f rad (safe<=%.2f) "
    "-- attack is likely topicWrite('/drive') or gradualDrift('/drive')",
    drive_speed_abs, cfg_max_safe_speed,
    drive_steering_abs, cfg_max_safe_steering);
  publish_alert_once("REQ_command_unsafe", sent_command_unsafe, g_cause_buf);
}
void handlerREQ_scan_corrupted(void) {
  if (in_startup_grace()) return;
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "/scan: invalid=%ld zero=%ld spread=%.3f stamp_age=%.2fs "
    "-- attack is likely topicWrite('/scan') or maliciousTopicContent('/scan') "
    "or stalePublish('/scan') or mitmInjection('/scan')",
    scan_invalid_count, scan_zero_count,
    scan_range_spread, scan_stamp_age_sec);
  publish_alert_once("REQ_scan_corrupted", sent_scan_corrupted, g_cause_buf);
}
void handlerREQ_scan_unreliable(void) {
  if (in_startup_grace()) return;
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "/scan: rate=%ld Hz (min %ld) reliability=%ld (expected %ld) "
    "publishers=%ld (expected %ld) "
    "-- attack is likely topicDrop('/scan') or topicDelay('/scan') "
    "or qosDegradation('/scan') or reliabilityFlip('/scan')",
    scan_msg_rate_hz, cfg_min_scan_rate,
    scan_observed_reliability, cfg_expected_scan_reliability,
    scan_publisher_count, cfg_expected_scan_publishers);
  publish_alert_once("REQ_scan_unreliable", sent_scan_unreliable, g_cause_buf);
}
void handlerREQ_map_server_down(void) {
  if (in_startup_grace()) return;
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "/map_server: state=%ld (expected ACTIVE=%ld) "
    "-- attack is likely serviceCall('/map_server/change_state',map_server) "
    "or lifecycleHijack(map_server)",
    map_server_state, cfg_active_state);
  publish_alert_once("REQ_map_server_down", sent_map_server_down, g_cause_buf);
}
void handlerREQ_bridge_misconfigured(void) {
  if (in_startup_grace()) return;
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "/bridge: param_change_count=%ld (expected 0) "
    "-- attack is likely serviceCall('/bridge/set_parameters',bridge)",
    bridge_param_change_count);
  publish_alert_once("REQ_bridge_misconfigured", sent_bridge_misconfigured, g_cause_buf);
}
void handlerREQ_data_leaked(void) {
  if (in_startup_grace()) return;
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "/scan subscribers=%ld (expected <=%ld), /ego_racecar/odom subscribers=%ld (expected <=%ld) "
    "-- attack is likely topicRead('/scan') or topicRead('/odom') "
    "or crossTopicCorrelation(f1tenth)",
    scan_subscriber_count, cfg_expected_scan_subscribers,
    odom_subscriber_count, cfg_expected_odom_subscribers);
  publish_alert_once("REQ_data_leaked", sent_data_leaked, g_cause_buf);
}
void handlerREQ_initial_access(void) {
  publish_alert_once("REQ_initial_access", sent_initial_access,
    "host-event predicate -- deferred to EDR/NIDS in deployment");
}
void handlerREQ_lateral_access(void) {
  publish_alert_once("REQ_lateral_access", sent_lateral_access,
    "host-event predicate -- deferred to EDR/NIDS in deployment");
}
void handlerREQ_credential_access(void) {
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "unauthorized SROS2 keystore opens=%ld (inotify after grace) "
    "-- attack is likely credentialAccess(robot_host)",
    attacker_creds_count);
  publish_alert_once("REQ_credential_access", sent_credential_access, g_cause_buf);
}
void handlerREQ_on_ros_network(void) {
  publish_alert_once("REQ_on_ros_network", sent_on_ros_network,
    "host-event predicate -- deferred to NIDS in deployment");
}
void handlerREQ_can_join_ros_graph(void) {
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "unauthorized ROS nodes on graph=%ld (rejecting allowlist) "
    "-- attack is likely attackerCanJoinRosGraph(robot_host)",
    unauth_node_count);
  publish_alert_once("REQ_can_join_ros_graph", sent_can_join_ros_graph, g_cause_buf);
}
void handlerREQ_can_net_admin(void) {
  snprintf(g_cause_buf, sizeof(g_cause_buf),
    "unexpected tc qdisc rules=%ld (vs startup baseline) "
    "-- attack is likely attackerCanNetAdmin(robot_host) "
    "or topicDrop('/scan') or topicDelay('/scan')",
    attacker_net_admin_count);
  publish_alert_once("REQ_can_net_admin", sent_can_net_admin, g_cause_buf);
}

}  // extern "C"

int main(int argc, char ** argv)
{
  std::signal(SIGUSR1, monitor_sigusr1_handler);
  g_monitor_start = std::chrono::steady_clock::now();

  rclcpp::init(argc, argv);
  g_smnode = std::make_shared<SystemMonitorNode>();
  rclcpp::spin(g_smnode);
  rclcpp::shutdown();
  g_smnode.reset();
  return 0;
}
