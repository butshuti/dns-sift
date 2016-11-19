#ifndef _DNSFW_FLOW_TRACK_H
#define _DNSFW_FLOW_TRACK_H

#include <map>
#include <time.h>
#include <stdint.h>

class MovingAverage{
	public:
		MovingAverage();
		MovingAverage(int windowSize);
		~MovingAverage();
		int pushValue(float value);
		int getAverage() const;
		int getStdDev() const;
		int getMin() const;
		int getMax() const;
	private:
		void init(int windowSize);
		int window_size, offset;
		float *window;
		float min, max, prev_mean, std_dev;
		float cur_sum;
};
class FlowTrack
{
	private:
		MovingAverage rtt;
		MovingAverage query_rate;
		MovingAverage bytes_rate;
		MovingAverage inflight_packets;
		MovingAverage inflight_bytes;
		MovingAverage fwd_pkt_length;
		MovingAverage bkwd_pkt_length;
		MovingAverage inter_query_time;
		MovingAverage uplink_to_downlink_ratio;
		std::map<int, int> used_ports;
		long long int bytes_sent, bytes_recvd, inflight_pkt_bytes;
		int inflight_pkt_num;
		time_t last_query_tm, last_response_tm;
		void updateInterQueryTime(float iqt);
		void updateQueryRate(float rate);
		void updateFlowRate(float rate);
		void updateU2DLinkRatio(float ratio);
		void updateRTT(float rtt_msec);	
		void updateFwdpktLen(int len);
		void updateBkwdpktLen(int len);
	public:
		FlowTrack();		
		~FlowTrack();
		void updateInflightPkts(int num, int bytes);
		void recordQuery(int len);
		void recordResponse(int len);
		void recordPort(int portNum);
		const MovingAverage* const getRTTMA();
		const MovingAverage* const getQyeryRateMA();
		const MovingAverage* const getInflightPktsMA();
		const MovingAverage* const getInflightBytesMA();
		const MovingAverage* const getFwdPktLengthMA();
		const MovingAverage* const getBkwdPktLengthMA();
		const MovingAverage* const getInterQueryTimeMA();
		const MovingAverage* const getU2DLinkRatioMA();
		const MovingAverage* const getFlowRateMA();
		MovingAverage getPortReuseMA();		
};

#endif
