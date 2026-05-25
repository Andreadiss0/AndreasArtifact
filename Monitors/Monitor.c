#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include "monitor_types.h"
#include "monitor.h"

// Called from the C++ wrapper on SIGUSR1 to restart the alwaysBeen() buffers.
void reset_all_ptltl_state(void);

static int64_t scan_msg_rate_hz_cpy;
static int64_t cfg_min_scan_rate_cpy;
static int64_t scan_observed_reliability_cpy;
static int64_t cfg_expected_scan_reliability_cpy;
static int64_t map_server_state_cpy;
static int64_t cfg_active_state_cpy;
static int64_t bridge_param_change_count_cpy;
static int64_t scan_subscriber_count_cpy;
static int64_t cfg_expected_scan_subscribers_cpy;
static int64_t odom_subscriber_count_cpy;
static int64_t cfg_expected_odom_subscribers_cpy;
static int64_t attacker_creds_count_cpy;
static int64_t unauth_node_count_cpy;
static int64_t attacker_net_admin_count_cpy;
static int64_t drive_publisher_count_cpy;
static int64_t cfg_expected_drive_publishers_cpy;
static int64_t drive_msg_rate_hz_cpy;
static int64_t cfg_max_drive_rate_cpy;
static float drive_speed_abs_cpy;
static float cfg_max_safe_speed_cpy;
static float drive_steering_abs_cpy;
static float cfg_max_safe_steering_cpy;
static int64_t scan_invalid_count_cpy;
static int64_t cfg_max_scan_invalid_count_cpy;
static int64_t scan_zero_count_cpy;
static int64_t cfg_max_scan_zero_count_cpy;
static float scan_range_spread_cpy;
static float cfg_min_scan_range_spread_cpy;
static int64_t scan_publisher_count_cpy;
static int64_t cfg_expected_scan_publishers_cpy;
static float scan_stamp_age_sec_cpy;
static float cfg_max_scan_stamp_age_sec_cpy;
static bool s0[(1)] = {(true)};
static bool s1[(1)] = {(true)};
static bool s2[(1)] = {(true)};
static bool s3[(1)] = {(true)};
static bool s4[(1)] = {(true)};
static bool s5[(1)] = {(true)};
static bool s6[(1)] = {(true)};
static bool s7[(1)] = {(true)};
static bool s8[(1)] = {(true)};
static bool s9[(1)] = {(true)};
static bool s10[(1)] = {(true)};
static bool s11[(1)] = {(true)};
static bool s12[(1)] = {(true)};
static bool s13[(1)] = {(true)};
static bool s14[(1)] = {(true)};
static bool s15[(1)] = {(true)};
static bool s16[(1)] = {(true)};
static bool s17[(1)] = {(true)};
static size_t s0_idx = (0);
static size_t s1_idx = (0);
static size_t s2_idx = (0);
static size_t s3_idx = (0);
static size_t s4_idx = (0);
static size_t s5_idx = (0);
static size_t s6_idx = (0);
static size_t s7_idx = (0);
static size_t s8_idx = (0);
static size_t s9_idx = (0);
static size_t s10_idx = (0);
static size_t s11_idx = (0);
static size_t s12_idx = (0);
static size_t s13_idx = (0);
static size_t s14_idx = (0);
static size_t s15_idx = (0);
static size_t s16_idx = (0);
static size_t s17_idx = (0);

static bool s0_get(size_t x) {
  return (s0)[((s0_idx) + (x)) % ((size_t)(1))];
}

static bool s1_get(size_t x) {
  return (s1)[((s1_idx) + (x)) % ((size_t)(1))];
}

static bool s2_get(size_t x) {
  return (s2)[((s2_idx) + (x)) % ((size_t)(1))];
}

static bool s3_get(size_t x) {
  return (s3)[((s3_idx) + (x)) % ((size_t)(1))];
}

static bool s4_get(size_t x) {
  return (s4)[((s4_idx) + (x)) % ((size_t)(1))];
}

static bool s5_get(size_t x) {
  return (s5)[((s5_idx) + (x)) % ((size_t)(1))];
}

static bool s6_get(size_t x) {
  return (s6)[((s6_idx) + (x)) % ((size_t)(1))];
}

static bool s7_get(size_t x) {
  return (s7)[((s7_idx) + (x)) % ((size_t)(1))];
}

static bool s8_get(size_t x) {
  return (s8)[((s8_idx) + (x)) % ((size_t)(1))];
}

static bool s9_get(size_t x) {
  return (s9)[((s9_idx) + (x)) % ((size_t)(1))];
}

static bool s10_get(size_t x) {
  return (s10)[((s10_idx) + (x)) % ((size_t)(1))];
}

static bool s11_get(size_t x) {
  return (s11)[((s11_idx) + (x)) % ((size_t)(1))];
}

static bool s12_get(size_t x) {
  return (s12)[((s12_idx) + (x)) % ((size_t)(1))];
}

static bool s13_get(size_t x) {
  return (s13)[((s13_idx) + (x)) % ((size_t)(1))];
}

static bool s14_get(size_t x) {
  return (s14)[((s14_idx) + (x)) % ((size_t)(1))];
}

static bool s15_get(size_t x) {
  return (s15)[((s15_idx) + (x)) % ((size_t)(1))];
}

static bool s16_get(size_t x) {
  return (s16)[((s16_idx) + (x)) % ((size_t)(1))];
}

static bool s17_get(size_t x) {
  return (s17)[((s17_idx) + (x)) % ((size_t)(1))];
}

static bool s0_gen(void) {
  return ((scan_msg_rate_hz_cpy) >= (cfg_min_scan_rate_cpy)) && ((s0_get)((0)));
}

static bool s1_gen(void) {
  return ((scan_observed_reliability_cpy) == (cfg_expected_scan_reliability_cpy)) && ((s1_get)((0)));
}

static bool s2_gen(void) {
  return ((map_server_state_cpy) == (cfg_active_state_cpy)) && ((s2_get)((0)));
}

static bool s3_gen(void) {
  return ((bridge_param_change_count_cpy) == ((int64_t)(0))) && ((s3_get)((0)));
}

static bool s4_gen(void) {
  return ((scan_subscriber_count_cpy) <= (cfg_expected_scan_subscribers_cpy)) && ((s4_get)((0)));
}

static bool s5_gen(void) {
  return ((odom_subscriber_count_cpy) <= (cfg_expected_odom_subscribers_cpy)) && ((s5_get)((0)));
}

static bool s6_gen(void) {
  return ((attacker_creds_count_cpy) == ((int64_t)(0))) && ((s6_get)((0)));
}

static bool s7_gen(void) {
  return ((unauth_node_count_cpy) == ((int64_t)(0))) && ((s7_get)((0)));
}

static bool s8_gen(void) {
  return ((attacker_net_admin_count_cpy) == ((int64_t)(0))) && ((s8_get)((0)));
}

static bool s9_gen(void) {
  return ((drive_publisher_count_cpy) <= (cfg_expected_drive_publishers_cpy)) && ((s9_get)((0)));
}

static bool s10_gen(void) {
  return ((drive_msg_rate_hz_cpy) <= (cfg_max_drive_rate_cpy)) && ((s10_get)((0)));
}

static bool s11_gen(void) {
  return ((drive_speed_abs_cpy) <= (cfg_max_safe_speed_cpy)) && ((s11_get)((0)));
}

static bool s12_gen(void) {
  return ((drive_steering_abs_cpy) <= (cfg_max_safe_steering_cpy)) && ((s12_get)((0)));
}

static bool s13_gen(void) {
  return ((scan_invalid_count_cpy) <= (cfg_max_scan_invalid_count_cpy)) && ((s13_get)((0)));
}

static bool s14_gen(void) {
  return ((scan_zero_count_cpy) <= (cfg_max_scan_zero_count_cpy)) && ((s14_get)((0)));
}

static bool s15_gen(void) {
  return ((scan_range_spread_cpy) >= (cfg_min_scan_range_spread_cpy)) && ((s15_get)((0)));
}

static bool s16_gen(void) {
  return ((scan_publisher_count_cpy) <= (cfg_expected_scan_publishers_cpy)) && ((s16_get)((0)));
}

static bool s17_gen(void) {
  return ((scan_stamp_age_sec_cpy) <= (cfg_max_scan_stamp_age_sec_cpy)) && ((s17_get)((0)));
}

static bool handlerREQ_scan_unreliable_0_guard(void) {
  return !((((scan_msg_rate_hz_cpy) >= (cfg_min_scan_rate_cpy)) && ((s0_get)((0)))) && (((scan_observed_reliability_cpy) == (cfg_expected_scan_reliability_cpy)) && ((s1_get)((0)))));
}

static bool handlerREQ_map_server_down_1_guard(void) {
  return !(((map_server_state_cpy) == (cfg_active_state_cpy)) && ((s2_get)((0))));
}

static bool handlerREQ_bridge_misconfigured_2_guard(void) {
  return !(((bridge_param_change_count_cpy) == ((int64_t)(0))) && ((s3_get)((0))));
}

static bool handlerREQ_data_leaked_3_guard(void) {
  return !((((scan_subscriber_count_cpy) <= (cfg_expected_scan_subscribers_cpy)) && ((s4_get)((0)))) && (((odom_subscriber_count_cpy) <= (cfg_expected_odom_subscribers_cpy)) && ((s5_get)((0)))));
}

static bool handlerREQ_credential_access_4_guard(void) {
  return !(((attacker_creds_count_cpy) == ((int64_t)(0))) && ((s6_get)((0))));
}

static bool handlerREQ_can_join_ros_graph_5_guard(void) {
  return !(((unauth_node_count_cpy) == ((int64_t)(0))) && ((s7_get)((0))));
}

static bool handlerREQ_can_net_admin_6_guard(void) {
  return !(((attacker_net_admin_count_cpy) == ((int64_t)(0))) && ((s8_get)((0))));
}

static bool handlerREQ_drive_DoS_7_guard(void) {
  return !((((drive_publisher_count_cpy) <= (cfg_expected_drive_publishers_cpy)) && ((s9_get)((0)))) && (((drive_msg_rate_hz_cpy) <= (cfg_max_drive_rate_cpy)) && ((s10_get)((0)))));
}

static bool handlerREQ_command_unsafe_8_guard(void) {
  return !((((drive_speed_abs_cpy) <= (cfg_max_safe_speed_cpy)) && ((s11_get)((0)))) && (((drive_steering_abs_cpy) <= (cfg_max_safe_steering_cpy)) && ((s12_get)((0)))));
}

static bool handlerREQ_scan_corrupted_9_guard(void) {
  return !(((((((scan_invalid_count_cpy) <= (cfg_max_scan_invalid_count_cpy)) && ((s13_get)((0)))) && (((scan_zero_count_cpy) <= (cfg_max_scan_zero_count_cpy)) && ((s14_get)((0))))) && (((scan_range_spread_cpy) >= (cfg_min_scan_range_spread_cpy)) && ((s15_get)((0))))) && (((scan_publisher_count_cpy) <= (cfg_expected_scan_publishers_cpy)) && ((s16_get)((0))))) && (((scan_stamp_age_sec_cpy) <= (cfg_max_scan_stamp_age_sec_cpy)) && ((s17_get)((0)))));
}

void step(void) {
  bool s0_tmp;
  bool s1_tmp;
  bool s2_tmp;
  bool s3_tmp;
  bool s4_tmp;
  bool s5_tmp;
  bool s6_tmp;
  bool s7_tmp;
  bool s8_tmp;
  bool s9_tmp;
  bool s10_tmp;
  bool s11_tmp;
  bool s12_tmp;
  bool s13_tmp;
  bool s14_tmp;
  bool s15_tmp;
  bool s16_tmp;
  bool s17_tmp;
  (scan_msg_rate_hz_cpy) = (scan_msg_rate_hz);
  (cfg_min_scan_rate_cpy) = (cfg_min_scan_rate);
  (scan_observed_reliability_cpy) = (scan_observed_reliability);
  (cfg_expected_scan_reliability_cpy) = (cfg_expected_scan_reliability);
  (map_server_state_cpy) = (map_server_state);
  (cfg_active_state_cpy) = (cfg_active_state);
  (bridge_param_change_count_cpy) = (bridge_param_change_count);
  (scan_subscriber_count_cpy) = (scan_subscriber_count);
  (cfg_expected_scan_subscribers_cpy) = (cfg_expected_scan_subscribers);
  (odom_subscriber_count_cpy) = (odom_subscriber_count);
  (cfg_expected_odom_subscribers_cpy) = (cfg_expected_odom_subscribers);
  (attacker_creds_count_cpy) = (attacker_creds_count);
  (unauth_node_count_cpy) = (unauth_node_count);
  (attacker_net_admin_count_cpy) = (attacker_net_admin_count);
  (drive_publisher_count_cpy) = (drive_publisher_count);
  (cfg_expected_drive_publishers_cpy) = (cfg_expected_drive_publishers);
  (drive_msg_rate_hz_cpy) = (drive_msg_rate_hz);
  (cfg_max_drive_rate_cpy) = (cfg_max_drive_rate);
  (drive_speed_abs_cpy) = (drive_speed_abs);
  (cfg_max_safe_speed_cpy) = (cfg_max_safe_speed);
  (drive_steering_abs_cpy) = (drive_steering_abs);
  (cfg_max_safe_steering_cpy) = (cfg_max_safe_steering);
  (scan_invalid_count_cpy) = (scan_invalid_count);
  (cfg_max_scan_invalid_count_cpy) = (cfg_max_scan_invalid_count);
  (scan_zero_count_cpy) = (scan_zero_count);
  (cfg_max_scan_zero_count_cpy) = (cfg_max_scan_zero_count);
  (scan_range_spread_cpy) = (scan_range_spread);
  (cfg_min_scan_range_spread_cpy) = (cfg_min_scan_range_spread);
  (scan_publisher_count_cpy) = (scan_publisher_count);
  (cfg_expected_scan_publishers_cpy) = (cfg_expected_scan_publishers);
  (scan_stamp_age_sec_cpy) = (scan_stamp_age_sec);
  (cfg_max_scan_stamp_age_sec_cpy) = (cfg_max_scan_stamp_age_sec);
  if ((handlerREQ_scan_unreliable_0_guard)()) {
    {(handlerREQ_scan_unreliable)();}
  };
  if ((handlerREQ_map_server_down_1_guard)()) {
    {(handlerREQ_map_server_down)();}
  };
  if ((handlerREQ_bridge_misconfigured_2_guard)()) {
    {(handlerREQ_bridge_misconfigured)();}
  };
  if ((handlerREQ_data_leaked_3_guard)()) {
    {(handlerREQ_data_leaked)();}
  };
  if ((handlerREQ_credential_access_4_guard)()) {
    {(handlerREQ_credential_access)();}
  };
  if ((handlerREQ_can_join_ros_graph_5_guard)()) {
    {(handlerREQ_can_join_ros_graph)();}
  };
  if ((handlerREQ_can_net_admin_6_guard)()) {
    {(handlerREQ_can_net_admin)();}
  };
  if ((handlerREQ_drive_DoS_7_guard)()) {
    {(handlerREQ_drive_DoS)();}
  };
  if ((handlerREQ_command_unsafe_8_guard)()) {
    {(handlerREQ_command_unsafe)();}
  };
  if ((handlerREQ_scan_corrupted_9_guard)()) {
    {(handlerREQ_scan_corrupted)();}
  };
  (s0_tmp) = ((s0_gen)());
  (s1_tmp) = ((s1_gen)());
  (s2_tmp) = ((s2_gen)());
  (s3_tmp) = ((s3_gen)());
  (s4_tmp) = ((s4_gen)());
  (s5_tmp) = ((s5_gen)());
  (s6_tmp) = ((s6_gen)());
  (s7_tmp) = ((s7_gen)());
  (s8_tmp) = ((s8_gen)());
  (s9_tmp) = ((s9_gen)());
  (s10_tmp) = ((s10_gen)());
  (s11_tmp) = ((s11_gen)());
  (s12_tmp) = ((s12_gen)());
  (s13_tmp) = ((s13_gen)());
  (s14_tmp) = ((s14_gen)());
  (s15_tmp) = ((s15_gen)());
  (s16_tmp) = ((s16_gen)());
  (s17_tmp) = ((s17_gen)());
  ((s0)[s0_idx]) = (s0_tmp);
  ((s1)[s1_idx]) = (s1_tmp);
  ((s2)[s2_idx]) = (s2_tmp);
  ((s3)[s3_idx]) = (s3_tmp);
  ((s4)[s4_idx]) = (s4_tmp);
  ((s5)[s5_idx]) = (s5_tmp);
  ((s6)[s6_idx]) = (s6_tmp);
  ((s7)[s7_idx]) = (s7_tmp);
  ((s8)[s8_idx]) = (s8_tmp);
  ((s9)[s9_idx]) = (s9_tmp);
  ((s10)[s10_idx]) = (s10_tmp);
  ((s11)[s11_idx]) = (s11_tmp);
  ((s12)[s12_idx]) = (s12_tmp);
  ((s13)[s13_idx]) = (s13_tmp);
  ((s14)[s14_idx]) = (s14_tmp);
  ((s15)[s15_idx]) = (s15_tmp);
  ((s16)[s16_idx]) = (s16_tmp);
  ((s17)[s17_idx]) = (s17_tmp);
  (s0_idx) = (((s0_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s1_idx) = (((s1_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s2_idx) = (((s2_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s3_idx) = (((s3_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s4_idx) = (((s4_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s5_idx) = (((s5_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s6_idx) = (((s6_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s7_idx) = (((s7_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s8_idx) = (((s8_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s9_idx) = (((s9_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s10_idx) = (((s10_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s11_idx) = (((s11_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s12_idx) = (((s12_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s13_idx) = (((s13_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s14_idx) = (((s14_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s15_idx) = (((s15_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s16_idx) = (((s16_idx) + ((size_t)(1))) % ((size_t)(1)));
  (s17_idx) = (((s17_idx) + ((size_t)(1))) % ((size_t)(1)));
}


// Reset all PTLTL alwaysBeen() rolling buffers to true.
void reset_all_ptltl_state(void)
{
  (s0)[0] = true;  (s0_idx) = 0;
  (s1)[0] = true;  (s1_idx) = 0;
  (s2)[0] = true;  (s2_idx) = 0;
  (s3)[0] = true;  (s3_idx) = 0;
  (s4)[0] = true;  (s4_idx) = 0;
  (s5)[0] = true;  (s5_idx) = 0;
  (s6)[0] = true;  (s6_idx) = 0;
  (s7)[0] = true;  (s7_idx) = 0;
  (s8)[0] = true;  (s8_idx) = 0;
  (s9)[0] = true;  (s9_idx) = 0;
  (s10)[0] = true; (s10_idx) = 0;
  (s11)[0] = true; (s11_idx) = 0;
  (s12)[0] = true; (s12_idx) = 0;
  (s13)[0] = true; (s13_idx) = 0;
  (s14)[0] = true; (s14_idx) = 0;
  (s15)[0] = true; (s15_idx) = 0;
  (s16)[0] = true; (s16_idx) = 0;
  (s17)[0] = true; (s17_idx) = 0;
}
