#include <math.h>
#include <map>
#include <climits>
#include <iostream>
#include "flow_track.h"
static int DEFAULT_AVG_WIN_SIZE = 50;
static int INT_SCALE_MULTIPLE = 1;//00;

MovingAverage::MovingAverage()
{
	init(DEFAULT_AVG_WIN_SIZE);
	
}

MovingAverage::MovingAverage(int windowSize)
{
	init(windowSize);
}

MovingAverage::~MovingAverage()
{
	delete window;
}

void MovingAverage::init(int windowSize)
{
	window_size = windowSize;
	window = new float[window_size];
	for(int i=0; i<window_size; i++){
		window[i] = 0;
	}
	offset = 0;
	min = INT_MAX;
	max = INT_MIN;
	std_dev = 0;
	prev_mean = 0;
	cur_sum = 0;
}

int MovingAverage::pushValue(float value)
{
	cur_sum -= window[offset];
	window[offset] = value;
	cur_sum += window[offset];
	offset = (offset+1)%window_size;	
	prev_mean = cur_sum /window_size;
	if(value < min){
		min = value;
	}
	if(value > max){
		max = value;
	}
	return getAverage();
}
int MovingAverage::getAverage() const
{
	return static_cast<int>(INT_SCALE_MULTIPLE*prev_mean);
}
int MovingAverage::getStdDev() const
{
	float ret = 0;
	for(int i=0; i<window_size; i++){
		ret += (window[i] - prev_mean)*(window[i] - prev_mean);
	}
	return static_cast<int>(INT_SCALE_MULTIPLE*sqrt(ret/window_size));
}
int MovingAverage::getMin() const
{
	return min;
}
int MovingAverage::getMax() const
{
	return max;
}

FlowTrack::FlowTrack()
{
	time(&last_query_tm);
	time(&last_response_tm);	
	bytes_sent = 0;
	bytes_recvd = 0;
	inflight_pkt_num = 0;
	inflight_pkt_bytes = 0;
}
FlowTrack::~FlowTrack()
{

}
void FlowTrack::updateRTT(float rtt_msec)
{
	rtt.pushValue(rtt_msec);
}
void FlowTrack::updateQueryRate(float rate)
{
	query_rate.pushValue(rate);
}
void FlowTrack::updateFlowRate(float rate)
{
	bytes_rate.pushValue(rate);
}
void FlowTrack::updateInterQueryTime(float iqt)
{
	inter_query_time.pushValue(iqt);
}
void FlowTrack::updateU2DLinkRatio(float ratio)
{
	uplink_to_downlink_ratio.pushValue(ratio);
}
void FlowTrack::updateInflightPkts(int num, int bytes)
{
	inflight_pkt_bytes += bytes;
	inflight_pkt_num += num;
	inflight_packets.pushValue(inflight_pkt_num);
	inflight_bytes.pushValue(inflight_pkt_bytes);
	if(num == 1 && bytes>0){
		updateFwdpktLen(bytes);
	}else if(num == -1 && bytes<0){
		updateBkwdpktLen(-bytes);
	}
}
void FlowTrack::updateFwdpktLen(int len)
{
	fwd_pkt_length.pushValue(len);
}
void FlowTrack::updateBkwdpktLen(int len)
{
	bkwd_pkt_length.pushValue(len);
}
void FlowTrack::recordPort(int portNum)
{
	if(used_ports.find(portNum) == used_ports.end()){
		used_ports[portNum] = 1;
	}else{
		used_ports.at(portNum)  += 1;
	}
}

void FlowTrack::recordQuery(int len)
{
	bytes_sent += len;
	time_t cur_time;
	time(&cur_time);
	double time_since_last_response = difftime(cur_time, last_response_tm);
	double time_since_last_query = difftime(cur_time, last_query_tm);
	last_query_tm = cur_time;
	updateQueryRate((2.0/(1+time_since_last_query))); 
	updateFlowRate(1000.0*len/(1+time_since_last_query));
	updateInterQueryTime(static_cast<float>(time_since_last_response));	
	updateU2DLinkRatio((1.0+bytes_sent)/(1+bytes_recvd));
	std::cout<<"cur_time: "<<cur_time<<" ; last_resp_tm: "<<last_response_tm<<" ; tm_since_last_resp: "<<time_since_last_response<<" --OR-- "<<getInterQueryTimeMA()->getAverage()<<std::endl;
}

void FlowTrack::recordResponse(int len)
{
	bytes_recvd += len;
	time_t cur_time;
	time(&cur_time);
	double diff_t = difftime(cur_time, last_query_tm);
	updateRTT(static_cast<float>(diff_t));
	updateFlowRate(1000.0*len/(1+diff_t));
	last_response_tm = cur_time;	
}

const MovingAverage* const FlowTrack::getRTTMA(){return &rtt;}
const MovingAverage* const FlowTrack::getQyeryRateMA(){return &query_rate;}
const MovingAverage* const FlowTrack::getInflightPktsMA(){return &inflight_packets;}
const MovingAverage* const FlowTrack::getInflightBytesMA(){return &inflight_bytes;}
const MovingAverage* const FlowTrack::getFwdPktLengthMA(){return &fwd_pkt_length;}
const MovingAverage* const FlowTrack::getBkwdPktLengthMA(){return &bkwd_pkt_length;}
const MovingAverage* const FlowTrack::getInterQueryTimeMA(){return &inter_query_time;}
const MovingAverage* const FlowTrack::getU2DLinkRatioMA(){return &uplink_to_downlink_ratio;}
const MovingAverage* const FlowTrack::getFlowRateMA(){return &bytes_rate;}
MovingAverage FlowTrack::getPortReuseMA(){
	MovingAverage ret;
	for (std::map<int,int>::iterator it=used_ports.begin(); it!=used_ports.end(); ++it){
		ret.pushValue(it->second);
	}
	return ret;
}
		
