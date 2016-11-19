#ifndef _DNSFW_FLOW_FEATURES_H
#define _DNSFW_FLOW_FEATURES_H
#include <stdlib.h>

/*
Statistical parameters for packet flows;
Protocol agnostic, no DPI.
*/
typedef struct {
	int flow_mean_rtt_msec;			/*Avg. time between query and response arrival*/
	int flow_query_rate;				/*Scaled number of queries per second*/
	int flow_bytes_per_sec;			/*Avg number of bytes sent+received per second*/
	int flow_max_inter_query_time;		/*Max interval between last response and next query*/
	int flow_min_inter_query_time;		/*Min interval between last response and next query*/
	int flow_mean_inter_query_time;	/*Mean interval between last response and next query*/
	int flow_std_inter_query_time;		/*Std dev. interval resp-next_query*/
	int flow_uplink_to_downlink_ratio;	/*Ratio sent/received bytes*/
	int flow_max_inflight_pkts;		/*Max number of packets sent awaiting answer*/
	int flow_min_inflight_pkts;		/*Min number of packets sent awaiting answer*/
	int flow_mean_inflight_pkts;		/*Avg number of packets sent awaiting answer*/	
	int flow_std_inflight_pkts;		/*Std. dev number of packets sent awaiting answer*/
	int flow_max_inflight_bytes;		/*Max number of bytes sent awaiting answer*/
	int flow_min_inflight_bytes;		/*Min number of bytes sent awaiting answer*/
	int flow_mean_inflight_bytes;		/*avg number of bytes sent awaiting answer*/
	int flow_std_inflight_bytes;		/*Std. dev number of bytes sent awaiting answer*/
	int flow_max_forward_pkt_length;	/*Max packet length for "queries"*/
	int flow_min_forward_pkt_length;	/*Min packet length for "queries"*/
	int flow_mean_forward_pkt_length;	/*Avg packet length for "queries"*/
	int flow_std_forward_pkt_length;	/*Std. dev packet length for "queries"*/
	int flow_mean_src_port_reuse;		/*Avg. src port reuse*/
	int flow_std_src_port_reuse;		/*Std. dev src port reuse*/
	int flow_max_backward_pkt_length;	/*Max packet length for "responses"*/
	int flow_min_backward_pkt_length;	/*Min packet length for "responses"*/
	int flow_mean_backward_pkt_length;	/*Avg packet length for "responses"*/
	int flow_std_backward_pkt_length;	/*Std. dev packet length for "responses"*/
} flow_history;
#define FEATURE_SIZE sizeof(flow_history) / sizeof(uint32_t)

#ifdef __cplusplus
    extern "C" {
#endif
void model_downlink_flow_features(flow_history *flow_patt, 
		uint32_t src_ip, uint32_t dst_ip, 
		uint16_t src_port, uint16_t dst_port, size_t rlen);
void model_uplink_flow_features(flow_history *flow_patt, 
		uint32_t src_ip, uint32_t dst_ip, 
		uint16_t src_port, uint16_t dst_port, size_t rlen);
void flow_feature_to_point(const flow_history *fh, int* const arr, size_t arr_len);
#ifdef __cplusplus
    }
#endif
		
#endif
