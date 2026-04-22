#include <rclcpp/rclcpp.hpp>
#include <std_msgs/msg/string.hpp>
#include <sensor_msgs/msg/laser_scan.hpp>
#include <ackermann_msgs/msg/ackermann_drive_stamped.hpp>
#include <rcl_interfaces/msg/parameter_event.hpp>
#include <lifecycle_msgs/msg/transition_event.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

extern "C" {
#include "Monitor.h"
}

// ==============================
// Monitor input globals expected by Monitor.c
// ==============================
extern "C" {

bool bridge_param_event = false;
int64_t bridge_param_name_id = -1;
int64_t cfg_allowed_bridge_param_name_id = 1;

int64_t cfg_allowed_drive_pub_id = -1;
int64_t cfg_allowed_map_transition_id = 3;
int64_t cfg_allowed_scan_pub_id = -1;
int64_t cfg_allowed_scan_sub_id = -1;
int64_t cfg_expected_scan_reliability = -1;   // learn baseline: 1=reliable, 0=best_effort

float cfg_max_scan_interarrival_sec = 0.30f;
int64_t cfg_max_scan_invalid_count = 10;      // relaxed enough to avoid clean-baseline false positives
int64_t cfg_max_scan_zero_count = 20;
float cfg_min_drive_interarrival_sec = 0.010f;
float cfg_scan_timeout_sec = 0.50f;

float current_time_sec = 0.0f;

float drive_last_msg_time_sec = 0.0f;
float drive_prev_msg_time_sec = 0.0f;
bool drive_pub_event = false;
int64_t drive_pub_id = -1;

bool map_lifecycle_event = false;
int64_t map_transition_id = -1;

bool scan_all_same = false;
int64_t scan_invalid_count = 0;
float scan_last_msg_time_sec = 0.0f;
int64_t scan_observed_reliability = -1;
float scan_prev_msg_time_sec = 0.0f;
bool scan_pub_event = false;
int64_t scan_pub_id = -1;
bool scan_sub_event = false;
int64_t scan_sub_id = -1;
int64_t scan_zero_count = 0;
}

// ==============================
// Helpers
// ==============================
namespace {

static std::string run_cmd(const std::string & cmd)
{
  std::array<char, 512> buffer{};
  std::string result;
  FILE * pipe = popen(cmd.c_str(), "r");
  if (!pipe) {
    return result;
  }
  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    result += buffer.data();
  }
  pclose(pipe);
  return result;
}

static inline float sec_now(const rclcpp::Node * node)
{
  return static_cast<float>(node->now().seconds());
}

static int64_t encode_reliability(const std::string & s)
{
  std::string x = s;
  std::transform(x.begin(), x.end(), x.begin(),
                 [](unsigned char c){ return static_cast<char>(std::tolower(c)); });

  if (x.find("reliable") != std::string::npos) {
    return 1;
  }
  if (x.find("best_effort") != std::string::npos || x.find("best effort") != std::string::npos) {
    return 0;
  }
  return -1;
}

static int64_t stable_id_for_name(const std::string & name)
{
  static const std::unordered_map<std::string, int64_t> table = {
    {"/bridge", 1},
    {"bridge", 1},
    {"/rviz", 2},
    {"rviz", 2},
    {"/map_server", 3},
    {"map_server", 3},
    {"/scan", 10},
    {"/drive", 11},
    {"scan_beams", 1},
    {"deactivate", 4},
    {"activate", 3},
    {"configure", 1},
    {"cleanup", 2}
  };

  auto it = table.find(name);
  if (it != table.end()) {
    return it->second;
  }

  std::hash<std::string> h;
  return static_cast<int64_t>((h(name) % 100000) + 1000);
}

static bool all_same_with_tol(const std::vector<float> & v, float tol = 1e-4f)
{
  if (v.empty()) {
    return false;
  }
  const float first = v.front();
  for (float x : v) {
    if (std::fabs(x - first) > tol) {
      return false;
    }
  }
  return true;
}

struct TopicEndpointSnapshot
{
  int64_t publisher_id = -1;
  int64_t subscriber_id = -1;
  int64_t reliability = -1;
};

static TopicEndpointSnapshot observe_topic(const std::string & topic_name)
{
  TopicEndpointSnapshot out{};

  const std::string cmd =
    "bash -lc '"
    "source /opt/ros/foxy/setup.bash >/dev/null 2>&1 && "
    "source /home/f1tenth/sim_ws/install/setup.bash >/dev/null 2>&1 && "
    "ros2 topic info " + topic_name + " -v 2>/dev/null"
    "'";

  const std::string text = run_cmd(cmd);
  if (text.empty()) {
    return out;
  }

  std::istringstream iss(text);
  std::string line;
  std::string endpoint_type;
  std::string node_name;

  while (std::getline(iss, line)) {
    if (line.find("Endpoint type:") != std::string::npos) {
      endpoint_type = line;
      continue;
    }

    if (line.find("Node name:") != std::string::npos) {
      auto pos = line.find(':');
      if (pos != std::string::npos) {
        node_name = line.substr(pos + 1);
        node_name.erase(0, node_name.find_first_not_of(" \t"));
        node_name.erase(node_name.find_last_not_of(" \t\r\n") + 1);
      }
      continue;
    }

    if (line.find("Reliability:") != std::string::npos) {
      auto pos = line.find(':');
      if (pos != std::string::npos) {
        std::string rel = line.substr(pos + 1);
        rel.erase(0, rel.find_first_not_of(" \t"));
        rel.erase(rel.find_last_not_of(" \t\r\n") + 1);
        out.reliability = encode_reliability(rel);
      }
      continue;
    }

    if (!node_name.empty() && !endpoint_type.empty()) {
      if (endpoint_type.find("PUBLISHER") != std::string::npos && out.publisher_id == -1) {
        out.publisher_id = stable_id_for_name(node_name);
      } else if (endpoint_type.find("SUBSCRIPTION") != std::string::npos && out.subscriber_id == -1) {
        out.subscriber_id = stable_id_for_name(node_name);
      }
    }
  }

  return out;
}

} // namespace

// ==============================
// Single monitor node
// ==============================
class SystemMonitorNode final : public rclcpp::Node
{
public:
  SystemMonitorNode()
  : Node("system_monitor_node")
  {
    this->declare_parameter<int64_t>("cfg_allowed_bridge_param_name_id", cfg_allowed_bridge_param_name_id);
    this->declare_parameter<int64_t>("cfg_allowed_drive_pub_id", cfg_allowed_drive_pub_id);
    this->declare_parameter<int64_t>("cfg_allowed_map_transition_id", cfg_allowed_map_transition_id);
    this->declare_parameter<int64_t>("cfg_allowed_scan_pub_id", cfg_allowed_scan_pub_id);
    this->declare_parameter<int64_t>("cfg_allowed_scan_sub_id", cfg_allowed_scan_sub_id);
    this->declare_parameter<int64_t>("cfg_expected_scan_reliability", cfg_expected_scan_reliability);
    this->declare_parameter<double>("cfg_max_scan_interarrival_sec", cfg_max_scan_interarrival_sec);
    this->declare_parameter<int64_t>("cfg_max_scan_invalid_count", cfg_max_scan_invalid_count);
    this->declare_parameter<int64_t>("cfg_max_scan_zero_count", cfg_max_scan_zero_count);
    this->declare_parameter<double>("cfg_min_drive_interarrival_sec", cfg_min_drive_interarrival_sec);
    this->declare_parameter<double>("cfg_scan_timeout_sec", cfg_scan_timeout_sec);

    refresh_config();

    alerts_pub_ = this->create_publisher<std_msgs::msg::String>("/monitor_alerts", 50);

    scan_sub_ = this->create_subscription<sensor_msgs::msg::LaserScan>(
      "/scan",
      rclcpp::SensorDataQoS(),
      std::bind(&SystemMonitorNode::on_scan, this, std::placeholders::_1));

    drive_sub_ = this->create_subscription<ackermann_msgs::msg::AckermannDriveStamped>(
      "/drive",
      10,
      std::bind(&SystemMonitorNode::on_drive, this, std::placeholders::_1));

    param_events_sub_ = this->create_subscription<rcl_interfaces::msg::ParameterEvent>(
      "/parameter_events",
      10,
      std::bind(&SystemMonitorNode::on_parameter_event, this, std::placeholders::_1));

    lifecycle_sub_ = this->create_subscription<lifecycle_msgs::msg::TransitionEvent>(
      "/map_server/transition_event",
      10,
      std::bind(&SystemMonitorNode::on_lifecycle_event, this, std::placeholders::_1));

    timer_ = this->create_wall_timer(
      std::chrono::milliseconds(200),
      std::bind(&SystemMonitorNode::tick, this));

    // Safe baseline before first real samples
    current_time_sec = sec_now(this);
    scan_prev_msg_time_sec = current_time_sec;
    scan_last_msg_time_sec = current_time_sec;
    drive_prev_msg_time_sec = current_time_sec;
    drive_last_msg_time_sec = current_time_sec + cfg_min_drive_interarrival_sec;

    RCLCPP_INFO(this->get_logger(), "system_monitor_node started");
  }

  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr get_alert_pub() const
  {
    return alerts_pub_;
  }

private:
  void refresh_config()
  {
    cfg_allowed_bridge_param_name_id =
      this->get_parameter("cfg_allowed_bridge_param_name_id").as_int();
    cfg_allowed_drive_pub_id =
      this->get_parameter("cfg_allowed_drive_pub_id").as_int();
    cfg_allowed_map_transition_id =
      this->get_parameter("cfg_allowed_map_transition_id").as_int();
    cfg_allowed_scan_pub_id =
      this->get_parameter("cfg_allowed_scan_pub_id").as_int();
    cfg_allowed_scan_sub_id =
      this->get_parameter("cfg_allowed_scan_sub_id").as_int();
    cfg_expected_scan_reliability =
      this->get_parameter("cfg_expected_scan_reliability").as_int();
    cfg_max_scan_interarrival_sec =
      static_cast<float>(this->get_parameter("cfg_max_scan_interarrival_sec").as_double());
    cfg_max_scan_invalid_count =
      this->get_parameter("cfg_max_scan_invalid_count").as_int();
    cfg_max_scan_zero_count =
      this->get_parameter("cfg_max_scan_zero_count").as_int();
    cfg_minDriveInterarrivalSecFromParam();
    cfg_scan_timeout_sec =
      static_cast<float>(this->get_parameter("cfg_scan_timeout_sec").as_double());
  }

  void cfg_minDriveInterarrivalSecFromParam()
  {
    cfg_min_drive_interarrival_sec =
      static_cast<float>(this->get_parameter("cfg_min_drive_interarrival_sec").as_double());
  }

  void on_scan(const sensor_msgs::msg::LaserScan::SharedPtr msg)
  {
    const float now_sec = sec_now(this);

    if (!scan_received_once_) {
      scan_prev_msg_time_sec = now_sec;
      scan_last_msg_time_sec = now_sec;
      scan_received_once_ = true;
    } else {
      scan_prev_msg_time_sec = scan_last_msg_time_sec;
      scan_last_msg_time_sec = now_sec;
    }

    int64_t invalid = 0;
    int64_t zeros = 0;
    std::vector<float> sample;
    sample.reserve(std::min<size_t>(msg->ranges.size(), 32));

    for (float r : msg->ranges) {
      // Treat NaN as invalid. Treat finite out-of-range as invalid.
      // Ignore +/-inf because clean laser scans often use inf for "no return / max range".
      if (std::isnan(r) || (std::isfinite(r) && (r < msg->range_min || r > msg->range_max))) {
        ++invalid;
      }
      if (std::fabs(r) < 1e-6f) {
        ++zeros;
      }
      if (sample.size() < 32 && std::isfinite(r)) {
        sample.push_back(r);
      }
    }

    scan_invalid_count = invalid;
    scan_zero_count = zeros;
    scan_all_same = all_same_with_tol(sample);

    current_time_sec = now_sec;
  }

  void on_drive(const ackermann_msgs::msg::AckermannDriveStamped::SharedPtr)
  {
    const float now_sec = sec_now(this);

    if (!drive_received_once_) {
      drive_prev_msg_time_sec = now_sec - cfg_min_drive_interarrival_sec;
      drive_last_msg_time_sec = now_sec;
      drive_received_once_ = true;
    } else {
      drive_prev_msg_time_sec = drive_last_msg_time_sec;
      drive_last_msg_time_sec = now_sec;
    }

    current_time_sec = now_sec;
  }

  void on_parameter_event(const rcl_interfaces::msg::ParameterEvent::SharedPtr msg)
  {
    if (msg->node != "/bridge" && msg->node != "bridge") {
      return;
    }

    if (!msg->changed_parameters.empty()) {
      bridge_param_event = true;
      bridge_param_name_id = stable_id_for_name(msg->changed_parameters.front().name);
    } else if (!msg->new_parameters.empty()) {
      bridge_param_event = true;
      bridge_param_name_id = stable_id_for_name(msg->new_parameters.front().name);
    } else if (!msg->deleted_parameters.empty()) {
      bridge_param_event = true;
      bridge_param_name_id = stable_id_for_name(msg->deleted_parameters.front().name);
    }
  }

  void on_lifecycle_event(const lifecycle_msgs::msg::TransitionEvent::SharedPtr msg)
  {
    map_lifecycle_event = true;
    map_transition_id = msg->transition.id;
  }

  void tick()
  {
    refresh_config();
    current_time_sec = sec_now(this);

    // Keep baseline safe before first messages
    if (!scan_received_once_) {
      scan_prev_msg_time_sec = current_time_sec;
      scan_last_msg_time_sec = current_time_sec;
      scan_invalid_count = 0;
      scan_zero_count = 0;
      scan_all_same = false;
    }

    if (!drive_received_once_) {
      drive_prev_msg_time_sec = current_time_sec;
      drive_last_msg_time_sec = current_time_sec + cfg_min_drive_interarrival_sec;
    } else if (drive_last_msg_time_sec <= drive_prev_msg_time_sec) {
      drive_last_msg_time_sec = drive_prev_msg_time_sec + cfg_min_drive_interarrival_sec;
    }

    // Observe endpoints/QoS from graph snapshot
    const auto scan_ep = observe_topic("/scan");
    const auto drive_ep = observe_topic("/drive");

    // Learn baseline scan publisher, then only pulse when it changes
    if (scan_ep.publisher_id != -1) {
      scan_pub_id = scan_ep.publisher_id;
      if (cfg_allowed_scan_pub_id == -1) {
        cfg_allowed_scan_pub_id = scan_ep.publisher_id;
        last_scan_pub_id_ = scan_ep.publisher_id;
      } else if (last_scan_pub_id_ == -1) {
        last_scan_pub_id_ = scan_ep.publisher_id;
      } else if (scan_ep.publisher_id != last_scan_pub_id_) {
        scan_pub_event = true;
        last_scan_pub_id_ = scan_ep.publisher_id;
      }
    }

    // Learn baseline scan subscriber, then only pulse when it changes
    if (scan_ep.subscriber_id != -1) {
      scan_sub_id = scan_ep.subscriber_id;
      if (cfg_allowed_scan_sub_id == -1) {
        cfg_allowed_scan_sub_id = scan_ep.subscriber_id;
        last_scan_sub_id_ = scan_ep.subscriber_id;
      } else if (last_scan_sub_id_ == -1) {
        last_scan_sub_id_ = scan_ep.subscriber_id;
      } else if (scan_ep.subscriber_id != last_scan_sub_id_) {
        scan_sub_event = true;
        last_scan_sub_id_ = scan_ep.subscriber_id;
      }
    }

    // Learn baseline QoS, then compare against it
    if (scan_ep.reliability != -1) {
      scan_observed_reliability = scan_ep.reliability;
      if (cfg_expected_scan_reliability == -1) {
        cfg_expected_scan_reliability = scan_ep.reliability;
      }
    } else if (cfg_expected_scan_reliability == -1) {
      // keep equality true before first observation
      scan_observed_reliability = -1;
    }

    // Learn baseline drive publisher, then only pulse when it changes
    if (drive_ep.publisher_id != -1) {
      drive_pub_id = drive_ep.publisher_id;
      if (cfg_allowed_drive_pub_id == -1) {
        cfg_allowed_drive_pub_id = drive_ep.publisher_id;
        last_drive_pub_id_ = drive_ep.publisher_id;
      } else if (last_drive_pub_id_ == -1) {
        last_drive_pub_id_ = drive_ep.publisher_id;
      } else if (drive_ep.publisher_id != last_drive_pub_id_) {
        drive_pub_event = true;
        last_drive_pub_id_ = drive_ep.publisher_id;
      }
    }

    RCLCPP_INFO(this->get_logger(),
      "MON inputs: scan_invalid_count=%ld scan_zero_count=%ld scan_all_same=%d "
      "scan_obs_rel=%ld cfg_exp_rel=%ld "
      "scan_pub_event=%d scan_pub_id=%ld cfg_allowed_scan_pub_id=%ld "
      "scan_sub_event=%d scan_sub_id=%ld cfg_allowed_scan_sub_id=%ld "
      "drive_prev=%.3f drive_last=%.3f cfg_min_drive_interarrival_sec=%.3f "
      "drive_pub_event=%d drive_pub_id=%ld cfg_allowed_drive_pub_id=%ld",
      (long)scan_invalid_count,
      (long)scan_zero_count,
      (int)scan_all_same,
      (long)scan_observed_reliability,
      (long)cfg_expected_scan_reliability,
      (int)scan_pub_event,
      (long)scan_pub_id,
      (long)cfg_allowed_scan_pub_id,
      (int)scan_sub_event,
      (long)scan_sub_id,
      (long)cfg_allowed_scan_sub_id,
      drive_prev_msg_time_sec,
      drive_last_msg_time_sec,
      cfg_min_drive_interarrival_sec,
      (int)drive_pub_event,
      (long)drive_pub_id,
      (long)cfg_allowed_drive_pub_id
    );

    step();

    // Clear one-shot event flags after each step
    bridge_param_event = false;
    map_lifecycle_event = false;
    scan_pub_event = false;
    scan_sub_event = false;
    drive_pub_event = false;
  }

private:
  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr alerts_pub_;
  rclcpp::Subscription<sensor_msgs::msg::LaserScan>::SharedPtr scan_sub_;
  rclcpp::Subscription<ackermann_msgs::msg::AckermannDriveStamped>::SharedPtr drive_sub_;
  rclcpp::Subscription<rcl_interfaces::msg::ParameterEvent>::SharedPtr param_events_sub_;
  rclcpp::Subscription<lifecycle_msgs::msg::TransitionEvent>::SharedPtr lifecycle_sub_;
  rclcpp::TimerBase::SharedPtr timer_;

  bool scan_received_once_{false};
  bool drive_received_once_{false};

  int64_t last_scan_pub_id_{-1};
  int64_t last_scan_sub_id_{-1};
  int64_t last_drive_pub_id_{-1};
};

// ==============================
// Global node ptr for handlers
// ==============================
static std::shared_ptr<SystemMonitorNode> g_node;

// ==============================
// Handlers called on violations
// Deduplicate to stop spam.
// ==============================
extern "C" {

static void publish_alert_once(const char * text, bool & already_sent)
{
  if (already_sent) {
    return;
  }
  already_sent = true;

  if (!g_node) {
    return;
  }

  std_msgs::msg::String msg;
  msg.data = text;
  g_node->get_alert_pub()->publish(msg);
}

void handlerREQ_scan_invalid_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_scan_content_attack", sent);
}

void handlerREQ_scan_zero_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_scan_content_attack", sent);
}

void handlerREQ_scan_uniform_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_scan_content_attack", sent);
}

void handlerREQ_scan_qos_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_scan_qos_attack", sent);
}

void handlerREQ_scan_delay_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_scan_delay_attack", sent);
}

void handlerREQ_scan_drop_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_scan_drop_attack", sent);
}

void handlerREQ_scan_publisher_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_scan_publisher_attack", sent);
}

void handlerREQ_scan_reader_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_scan_reader_attack", sent);
}

void handlerREQ_drive_publisher_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_drive_publisher_attack", sent);
}

void handlerREQ_drive_flood_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_drive_flood_attack", sent);
}

void handlerREQ_bridge_param_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_bridge_param_attack", sent);
}

void handlerREQ_map_lifecycle_attack(void)
{
  static bool sent = false;
  publish_alert_once("REQ_map_lifecycle_attack", sent);
}

} // extern "C"

// ==============================
// main
// ==============================
int main(int argc, char ** argv)
{
  rclcpp::init(argc, argv);
  g_node = std::make_shared<SystemMonitorNode>();
  rclcpp::spin(g_node);
  rclcpp::shutdown();
  return 0;
}
