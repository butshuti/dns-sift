#include <stdint.h>
#include <map>
#include <iostream>
#include "flow_features.h"
#include "flow_track.h"


static std::map<uint64_t, FlowTrack*> flows;

static FlowTrack* getFlow(uint32_t src_ip, uint32_t dst_ip){
	FlowTrack *ft = NULL;
	uint64_t key = src_ip;
	key = (key<<32) | dst_ip;
	if(flows.find(key) == flows.end()){
		ft = new FlowTrack;
		flows[key] = ft;
	}else{
		ft = flows.at(key);
	}
	return ft;
}

void update_flow_features(flow_history *flow_patt, FlowTrack *flow){
	flow_patt->flow_query_rate = flow->getQyeryRateMA()->getAverage();
	flow_patt->flow_uplink_to_downlink_ratio = flow->getU2DLinkRatioMA()->getAverage();
	flow_patt->flow_max_inflight_pkts = flow->getInflightPktsMA()->getMax();
	flow_patt->flow_min_inflight_pkts = flow->getInflightPktsMA()->getMin();
	flow_patt->flow_mean_inflight_pkts = flow->getInflightPktsMA()->getAverage();	
	flow_patt->flow_std_inflight_pkts = flow->getInflightPktsMA()->getStdDev();	
	flow_patt->flow_max_inflight_bytes = flow->getInflightBytesMA()->getMax();
	flow_patt->flow_min_inflight_bytes = flow->getInflightBytesMA()->getMin();
	flow_patt->flow_mean_inflight_bytes = flow->getInflightBytesMA()->getAverage();
	flow_patt->flow_std_inflight_bytes = flow->getInflightBytesMA()->getStdDev();
	flow_patt->flow_max_forward_pkt_length = flow->getFwdPktLengthMA()->getMax();
	flow_patt->flow_min_forward_pkt_length = flow->getFwdPktLengthMA()->getMin();
	flow_patt->flow_mean_forward_pkt_length = flow->getFwdPktLengthMA()->getAverage();
	flow_patt->flow_std_forward_pkt_length = flow->getFwdPktLengthMA()->getStdDev();
	flow_patt->flow_bytes_per_sec = flow->getFlowRateMA()->getAverage();
	flow_patt->flow_mean_src_port_reuse = flow->getPortReuseMA().getAverage();
	flow_patt->flow_std_src_port_reuse = flow->getPortReuseMA().getStdDev();
	flow_patt->flow_max_inter_query_time = flow->getInterQueryTimeMA()->getMax();
	flow_patt->flow_min_inter_query_time = flow->getInterQueryTimeMA()->getMin();
	flow_patt->flow_mean_inter_query_time = flow->getInterQueryTimeMA()->getAverage();
	flow_patt->flow_std_inter_query_time = flow->getInterQueryTimeMA()->getStdDev();
	flow_patt->flow_max_backward_pkt_length = flow->getBkwdPktLengthMA()->getMax();
	flow_patt->flow_min_backward_pkt_length = flow->getBkwdPktLengthMA()->getMin();
	flow_patt->flow_mean_backward_pkt_length = flow->getBkwdPktLengthMA()->getAverage();
	flow_patt->flow_std_backward_pkt_length = flow->getBkwdPktLengthMA()->getStdDev();
	flow_patt->flow_mean_rtt_msec = flow->getRTTMA()->getAverage();
}

void model_uplink_flow_features(flow_history *flow_patt, 
		uint32_t src_ip, uint32_t dst_ip, 
		uint16_t src_port, uint16_t dst_port, size_t rlen)
{
	FlowTrack *flow = getFlow(src_ip, dst_ip);
	flow->recordQuery(rlen);
	flow->recordPort(src_port);
	flow->updateInflightPkts(1, static_cast<int>(rlen));
	update_flow_features(flow_patt, flow);
}
void model_downlink_flow_features(flow_history *flow_patt, 
		uint32_t src_ip, uint32_t dst_ip, 
		uint16_t src_port, uint16_t dst_port, size_t rlen)
{
	FlowTrack *flow = getFlow(dst_ip, src_ip);
	flow->recordResponse(rlen);
	flow->updateInflightPkts(-1, -(static_cast<int>(rlen)));
	update_flow_features(flow_patt, flow);
}

void flow_feature_to_point(const flow_history *fh, int* const arr, size_t arr_len){
	int temp[FEATURE_SIZE];
	size_t i = 0;
	temp[i++] = fh->flow_mean_rtt_msec;
	temp[i++] = fh->flow_query_rate;				
	temp[i++] = fh->flow_bytes_per_sec;			
	temp[i++] = fh->flow_max_inter_query_time;		
	temp[i++] = fh->flow_min_inter_query_time;		
	temp[i++] = fh->flow_mean_inter_query_time;	
	temp[i++] = fh->flow_std_inter_query_time;	
	temp[i++] = fh->flow_uplink_to_downlink_ratio;		
	temp[i++] = fh->flow_max_inflight_pkts; 			
	temp[i++] = fh->flow_min_inflight_pkts;			
	temp[i++] = fh->flow_mean_inflight_pkts;				
	temp[i++] = fh->flow_std_inflight_pkts;		
	temp[i++] = fh->flow_max_inflight_bytes;			
	temp[i++] = fh->flow_min_inflight_bytes;			
	temp[i++] = fh->flow_mean_inflight_bytes;
	temp[i++] = fh->flow_std_inflight_bytes;	
	temp[i++] = fh->flow_max_forward_pkt_length;	
	temp[i++] = fh->flow_min_forward_pkt_length;	
	temp[i++] = fh->flow_mean_forward_pkt_length;
	temp[i++] = fh->flow_std_forward_pkt_length;	
	temp[i++] = fh->flow_mean_src_port_reuse;		
	temp[i++] = fh->flow_std_src_port_reuse;		
	temp[i++] = fh->flow_max_backward_pkt_length;	
	temp[i++] = fh->flow_min_backward_pkt_length;	
	temp[i++] = fh->flow_mean_backward_pkt_length;	
	temp[i++] = fh->flow_std_backward_pkt_length;
	arr_len = arr_len < i ? arr_len : i;
	for(size_t idx=0; idx<i; idx++){
		arr[idx] = temp[idx];
	}
}

