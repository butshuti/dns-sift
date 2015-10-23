#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <strings.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdio.h>
#include "../config.h"
#include "dns_parse.h"
#include "dns_features.h"


#ifdef MODEL_SYSTEM_FLOW_THRESHOLDS

/*Minimum normal TTL, in seconds*/
#define MIN_TTL_SECONDS 20
/*Maximum normal TTL, in seconds*/
#define MAX_TTL_SECONDS 40000

#define ALPHA 0.15
#define ABS(x)(x>0? x : -x)
#define MAX(X,Y)(X>Y?X:Y)
#define MIN(X,Y)(X<Y?X:Y)

void update_avg(uint32_t new_val, double *adaptive_avg, double *dynamic_avg, uint64_t *num_observations){
	num_observations++;
	*dynamic_avg = ( (*num_observations * (*dynamic_avg)) + new_val) / (*num_observations + 1);
	*adaptive_avg += ALPHA * ( (*dynamic_avg) - (*adaptive_avg));
}

void model_ttl_feature(uint32_t ttl, feature *ft){

	static double avg_flow_ttl = 60;
	static double avg_ttl = 60;
	static uint64_t num_observations = 40000;
	update_avg(ttl, &avg_flow_ttl, &avg_ttl, &num_observations);	 
	if(ttl < MIN(MIN_TTL_SECONDS, avg_ttl / 10)){
		ft->f_code = TTL_TOO_LOW;
		ft->f_range = 0x07 & (8 * ttl / MIN_TTL_SECONDS);
	}else if(ttl > MAX(MAX_TTL_SECONDS, avg_ttl * 10)){
		ft->f_code = TTL_TOO_HIGH;
		ft->f_range = 0x07 & (1<<(ttl / (8 * MAX_TTL_SECONDS)));
	}else{
		avg_ttl = (avg_ttl + ttl) / 2;
		ft->f_code = TTL_OK;
		ft->f_range = 0x07 & (1<<(int)(8 * ttl / avg_flow_ttl));
	}
	ft->uniqueness = (ABS(ttl - avg_flow_ttl) * ABS(ttl - avg_ttl)) / (1 + ft->f_range);
}

void model_packet_feature(const dns_packet *pkt, feature *ft){

}

void model_query_feature(const dns_packet *pkt, feature *ft){

}

void model_reply_feature(const dns_packet *pkt, feature *ft){

}

void model_src_feature(const dns_packet *pkt, feature *ft){

}

void model_dst_feature(const dns_packet *pkt, feature *ft){

}

void model_qname_feature(const char *qname, feature *ft){

}

PACKET_SCORE  classify_pattern(const pattern *pat){
	return SCORE_NORMAL;
}

#endif
