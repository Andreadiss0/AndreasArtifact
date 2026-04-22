#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

#include "monitor_types.h"
#include "monitor.h"

static int64_t scan_invalid_count_cpy;
static int64_t cfg_max_scan_invalid_count_cpy;
static int64_t scan_zero_count_cpy;
static int64_t cfg_max_scan_zero_count_cpy;
static bool scan_all_same_cpy;
static int64_t scan_observed_reliability_cpy;
static int64_t cfg_expected_scan_reliability_cpy;
static float scan_last_msg_time_sec_cpy;
static float scan_prev_msg_time_sec_cpy;
static float cfg_max_scan_interarrival_sec_cpy;
static float current_time_sec_cpy;
static float cfg_scan_timeout_sec_cpy;
static bool scan_pub_event_cpy;
static int64_t scan_pub_id_cpy;
static int64_t cfg_allowed_scan_pub_id_cpy;
static bool scan_sub_event_cpy;
static int64_t scan_sub_id_cpy;
static int64_t cfg_allowed_scan_sub_id_cpy;
static bool drive_pub_event_cpy;
static int64_t drive_pub_id_cpy;
static int64_t cfg_allowed_drive_pub_id_cpy;
static float drive_last_msg_time_sec_cpy;
static float drive_prev_msg_time_sec_cpy;
static float cfg_min_drive_interarrival_sec_cpy;
static bool bridge_param_event_cpy;
static int64_t bridge_param_name_id_cpy;
static int64_t cfg_allowed_bridge_param_name_id_cpy;
static bool map_lifecycle_event_cpy;
static int64_t map_transition_id_cpy;
static int64_t cfg_allowed_map_transition_id_cpy;
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

static bool s0_gen(void) {
  return ((scan_invalid_count_cpy) <= (cfg_max_scan_invalid_count_cpy)) && ((s0_get)((0)));
}

static bool s1_gen(void) {
  return ((scan_zero_count_cpy) <= (cfg_max_scan_zero_count_cpy)) && ((s1_get)((0)));
}

static bool s2_gen(void) {
  return (!(scan_all_same_cpy)) && ((s2_get)((0)));
}

static bool s3_gen(void) {
  return ((scan_observed_reliability_cpy) == (cfg_expected_scan_reliability_cpy)) && ((s3_get)((0)));
}

static bool s4_gen(void) {
  return (((scan_last_msg_time_sec_cpy) - (scan_prev_msg_time_sec_cpy)) <= (cfg_max_scan_interarrival_sec_cpy)) && ((s4_get)((0)));
}

static bool s5_gen(void) {
  return (((current_time_sec_cpy) - (scan_last_msg_time_sec_cpy)) <= (cfg_scan_timeout_sec_cpy)) && ((s5_get)((0)));
}

static bool s6_gen(void) {
  return ((!(scan_pub_event_cpy)) || ((scan_pub_id_cpy) == (cfg_allowed_scan_pub_id_cpy))) && ((s6_get)((0)));
}

static bool s7_gen(void) {
  return ((!(scan_sub_event_cpy)) || ((scan_sub_id_cpy) == (cfg_allowed_scan_sub_id_cpy))) && ((s7_get)((0)));
}

static bool s8_gen(void) {
  return ((!(drive_pub_event_cpy)) || ((drive_pub_id_cpy) == (cfg_allowed_drive_pub_id_cpy))) && ((s8_get)((0)));
}

static bool s9_gen(void) {
  return (((drive_last_msg_time_sec_cpy) - (drive_prev_msg_time_sec_cpy)) >= (cfg_min_drive_interarrival_sec_cpy)) && ((s9_get)((0)));
}

static bool s10_gen(void) {
  return ((!(bridge_param_event_cpy)) || ((bridge_param_name_id_cpy) == (cfg_allowed_bridge_param_name_id_cpy))) && ((s10_get)((0)));
}

static bool s11_gen(void) {
  return ((!(map_lifecycle_event_cpy)) || ((map_transition_id_cpy) == (cfg_allowed_map_transition_id_cpy))) && ((s11_get)((0)));
}

static bool handlerREQ_scan_invalid_attack_0_guard(void) {
  return !(((scan_invalid_count_cpy) <= (cfg_max_scan_invalid_count_cpy)) && ((s0_get)((0))));
}

static bool handlerREQ_scan_zero_attack_1_guard(void) {
  return !(((scan_zero_count_cpy) <= (cfg_max_scan_zero_count_cpy)) && ((s1_get)((0))));
}

static bool handlerREQ_scan_uniform_attack_2_guard(void) {
  return !((!(scan_all_same_cpy)) && ((s2_get)((0))));
}

static bool handlerREQ_scan_qos_attack_3_guard(void) {
  return !(((scan_observed_reliability_cpy) == (cfg_expected_scan_reliability_cpy)) && ((s3_get)((0))));
}

static bool handlerREQ_scan_delay_attack_4_guard(void) {
  return !((((scan_last_msg_time_sec_cpy) - (scan_prev_msg_time_sec_cpy)) <= (cfg_max_scan_interarrival_sec_cpy)) && ((s4_get)((0))));
}

static bool handlerREQ_scan_drop_attack_5_guard(void) {
  return !((((current_time_sec_cpy) - (scan_last_msg_time_sec_cpy)) <= (cfg_scan_timeout_sec_cpy)) && ((s5_get)((0))));
}

static bool handlerREQ_scan_publisher_attack_6_guard(void) {
  return !(((!(scan_pub_event_cpy)) || ((scan_pub_id_cpy) == (cfg_allowed_scan_pub_id_cpy))) && ((s6_get)((0))));
}

static bool handlerREQ_scan_reader_attack_7_guard(void) {
  return !(((!(scan_sub_event_cpy)) || ((scan_sub_id_cpy) == (cfg_allowed_scan_sub_id_cpy))) && ((s7_get)((0))));
}

static bool handlerREQ_drive_publisher_attack_8_guard(void) {
  return !(((!(drive_pub_event_cpy)) || ((drive_pub_id_cpy) == (cfg_allowed_drive_pub_id_cpy))) && ((s8_get)((0))));
}

static bool handlerREQ_drive_flood_attack_9_guard(void) {
  return !((((drive_last_msg_time_sec_cpy) - (drive_prev_msg_time_sec_cpy)) >= (cfg_min_drive_interarrival_sec_cpy)) && ((s9_get)((0))));
}

static bool handlerREQ_bridge_param_attack_10_guard(void) {
  return !(((!(bridge_param_event_cpy)) || ((bridge_param_name_id_cpy) == (cfg_allowed_bridge_param_name_id_cpy))) && ((s10_get)((0))));
}

static bool handlerREQ_map_lifecycle_attack_11_guard(void) {
  return !(((!(map_lifecycle_event_cpy)) || ((map_transition_id_cpy) == (cfg_allowed_map_transition_id_cpy))) && ((s11_get)((0))));
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
  (scan_invalid_count_cpy) = (scan_invalid_count);
  (cfg_max_scan_invalid_count_cpy) = (cfg_max_scan_invalid_count);
  (scan_zero_count_cpy) = (scan_zero_count);
  (cfg_max_scan_zero_count_cpy) = (cfg_max_scan_zero_count);
  (scan_all_same_cpy) = (scan_all_same);
  (scan_observed_reliability_cpy) = (scan_observed_reliability);
  (cfg_expected_scan_reliability_cpy) = (cfg_expected_scan_reliability);
  (scan_last_msg_time_sec_cpy) = (scan_last_msg_time_sec);
  (scan_prev_msg_time_sec_cpy) = (scan_prev_msg_time_sec);
  (cfg_max_scan_interarrival_sec_cpy) = (cfg_max_scan_interarrival_sec);
  (current_time_sec_cpy) = (current_time_sec);
  (cfg_scan_timeout_sec_cpy) = (cfg_scan_timeout_sec);
  (scan_pub_event_cpy) = (scan_pub_event);
  (scan_pub_id_cpy) = (scan_pub_id);
  (cfg_allowed_scan_pub_id_cpy) = (cfg_allowed_scan_pub_id);
  (scan_sub_event_cpy) = (scan_sub_event);
  (scan_sub_id_cpy) = (scan_sub_id);
  (cfg_allowed_scan_sub_id_cpy) = (cfg_allowed_scan_sub_id);
  (drive_pub_event_cpy) = (drive_pub_event);
  (drive_pub_id_cpy) = (drive_pub_id);
  (cfg_allowed_drive_pub_id_cpy) = (cfg_allowed_drive_pub_id);
  (drive_last_msg_time_sec_cpy) = (drive_last_msg_time_sec);
  (drive_prev_msg_time_sec_cpy) = (drive_prev_msg_time_sec);
  (cfg_min_drive_interarrival_sec_cpy) = (cfg_min_drive_interarrival_sec);
  (bridge_param_event_cpy) = (bridge_param_event);
  (bridge_param_name_id_cpy) = (bridge_param_name_id);
  (cfg_allowed_bridge_param_name_id_cpy) = (cfg_allowed_bridge_param_name_id);
  (map_lifecycle_event_cpy) = (map_lifecycle_event);
  (map_transition_id_cpy) = (map_transition_id);
  (cfg_allowed_map_transition_id_cpy) = (cfg_allowed_map_transition_id);
  if ((handlerREQ_scan_invalid_attack_0_guard)()) {
    {(handlerREQ_scan_invalid_attack)();}
  };
  if ((handlerREQ_scan_zero_attack_1_guard)()) {
    {(handlerREQ_scan_zero_attack)();}
  };
  if ((handlerREQ_scan_uniform_attack_2_guard)()) {
    {(handlerREQ_scan_uniform_attack)();}
  };
  if ((handlerREQ_scan_qos_attack_3_guard)()) {
    {(handlerREQ_scan_qos_attack)();}
  };
  if ((handlerREQ_scan_delay_attack_4_guard)()) {
    {(handlerREQ_scan_delay_attack)();}
  };
  if ((handlerREQ_scan_drop_attack_5_guard)()) {
    {(handlerREQ_scan_drop_attack)();}
  };
  if ((handlerREQ_scan_publisher_attack_6_guard)()) {
    {(handlerREQ_scan_publisher_attack)();}
  };
  if ((handlerREQ_scan_reader_attack_7_guard)()) {
    {(handlerREQ_scan_reader_attack)();}
  };
  if ((handlerREQ_drive_publisher_attack_8_guard)()) {
    {(handlerREQ_drive_publisher_attack)();}
  };
  if ((handlerREQ_drive_flood_attack_9_guard)()) {
    {(handlerREQ_drive_flood_attack)();}
  };
  if ((handlerREQ_bridge_param_attack_10_guard)()) {
    {(handlerREQ_bridge_param_attack)();}
  };
  if ((handlerREQ_map_lifecycle_attack_11_guard)()) {
    {(handlerREQ_map_lifecycle_attack)();}
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
}
