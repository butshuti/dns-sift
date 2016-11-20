#include <string.h>
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <strings.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdio.h>
#include "logger.h"
#include "dns_features.h"
#include "flow_features.h"
#include "dns_policies.h"
#include "dns_parse.h"
#include "dns_flow_model.h"
#include "domain_utils.h"
#include "routing.h"


#include <time.h>

#define UDP_HDR_SIZE 8
#define TCP_HDR_SIZE 20

#define MAX_CONNECTIONS_TABLE_SIZE 10
#define MAX_DOMAINS_TABLE_SIZE 10

#define LOG_LINE_SIZE 200

#define  UNUSED_PARAM(x) ((void)(x))

#define INVALID_DNS_QNAME_TAG ".dilavni"

void print_flow_feature_point(const pattern *pat, FILE *fp, char *tag){
	int arr[FEATURE_SIZE] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	flow_feature_to_point(&pat->flow_patt, arr, FEATURE_SIZE);
	fprintf(fp, "%d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %s\n", 
		arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9], arr[10], arr[11], arr[12], arr[13], arr[14], 
		arr[15], arr[16], arr[17], arr[18], arr[19], arr[20], arr[21], arr[22], arr[23], arr[24], arr[25], tag);
}

char *print_feature_start(int buflen){
	char *buf = calloc(1, buflen);
	return buf;
}

int print_feature(char *buf, int buflen, int cur_offs, const char *label, const feature ft){
	int num = snprintf(buf+cur_offs, buflen-cur_offs, "%s:%d|%d|%d, ", label, ft.f_code, ft.f_range, ft.uniqueness);
	return cur_offs+num;
}
void print_feature_end(char *buf, char *tag){
	if(buf != NULL){
		log_debug("<%s>   ---  %s\n", buf, tag);
		free(buf);
	}
}

/*void feature_to_point(const feature ft, uint64_t *arr, uint32_t idx){
	arr[0] |= ((((uint16_t)ft.f_code) << 5) | (((uint16_t)ft.f_range)<<3) | ft.uniqueness) << idx ;
	arr[1] |= arr[0] - ((1+ft.f_range) / (1+ft.uniqueness));
}*/

void feature_to_point(const feature ft, uint64_t *arr, uint32_t idx){
	arr[idx] |= ((((uint16_t)ft.f_code) << 5) | (((uint16_t)ft.f_range)<<3) | ft.uniqueness);
	//arr[1] |= arr[0] - ((1+ft.f_range) / (1+ft.uniqueness));
}

void pattern_to_point(const pattern *pat, uint64_t *arr){
	feature_to_point(pat->src_patt, arr, 0);
	feature_to_point(pat->dst_info, arr, 1);
	feature_to_point(pat->packet_patt, arr, 2);
	feature_to_point(pat->qname_patt, arr, 3);
	feature_to_point(pat->query_patt, arr, 4);
	feature_to_point(pat->reply_patt, arr, 5);
	feature_to_point(pat->ttl_patt, arr, 6);
}

void print_pattern_point(const pattern *pat, FILE *fp, char *tag){
	uint64_t arr[] = {0, 0, 0, 0, 0, 0, 0};
	pattern_to_point(pat, arr);
	fprintf(fp, "%ld, %ld, %ld, %ld, %ld, %ld, %ld, %s\n", arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], tag);
	print_pattern(pat, tag);
}

void print_pattern(const pattern *pat, char *tag){
	int buflen = LOG_LINE_SIZE,cur_offs = 0;
	char *buf = print_feature_start(buflen);
	if(buf == NULL){
		perror("print_feature_start");
	}
	cur_offs = print_feature(buf, buflen, cur_offs, "SRC", pat->src_patt);
	cur_offs = print_feature(buf, buflen, cur_offs, "DST", pat->dst_info);
	cur_offs = print_feature(buf, buflen, cur_offs, "PACKET", pat->packet_patt);
	cur_offs = print_feature(buf, buflen, cur_offs, "QUERY", pat->query_patt);
	cur_offs = print_feature(buf, buflen, cur_offs, "REPLY", pat->reply_patt);
	cur_offs = print_feature(buf, buflen, cur_offs, "TTL", pat->ttl_patt);
	cur_offs = print_feature(buf, buflen, cur_offs, "QNAME", pat->qname_patt);
	print_feature_end(buf, tag);
}

void adapt_feature(feature *ft, const feature *new_f){
	if(ft->f_code != new_f->f_code){
		if( (ft->f_range >> 2) > 0){
			ft->uniqueness--;
			ft->f_range--;
		}
	}else{
		ft->uniqueness = (ft->uniqueness  & 0x07) | (ft->uniqueness  + 1);
	}
}

void extract_features(const dns_packet *pkt, const unsigned int length, pattern *pat){
	model_packet_feature(pkt, &(pat->packet_patt));
	model_src_feature(pkt, &(pat->src_patt));
	model_dst_feature(pkt, &(pat->dst_info));
	if(pkt->answers != NULL){
		uint32_t ttl = pkt->answers->ttl;
		model_ttl_feature(ttl, pkt->questions->name, &(pat->ttl_patt));
		model_reply_feature(pkt, &(pat->reply_patt));
	}else{
		model_query_feature(pkt, length, &(pat->query_patt));
		if(pkt->questions){
		    model_qname_feature(pkt->questions->name, &(pat->qname_patt));
		}
	}
}

void dns_flow_inspect(uint8_t *payload, uint32_t payload_len, struct in_addr src_ip, 
		struct in_addr dst_ip, DIRECTION drctn, pattern* const patt)
{
	dns_parse_errors err_code = parse_msg_unknown;
	dns_packet *pkt = NULL;
	pattern new_patt;
	memset(&new_patt, 0, sizeof(pattern));
	err_code = dns_parse(payload, payload_len, &pkt);
	if(err_code != parse_ok){
		switch(err_code){
			case parse_malformed: case parse_incomplete: case parse_memory_error:
				{
					new_patt.packet_patt.f_code = DNS_PACKET_MALFORMED;
				}
				break;
			default:
				new_patt.packet_patt.f_code = DNS_NOT_DNS;
		}
		char domain[255];
		snprintf(domain, 255, "%d.%d.INVALID", src_ip.s_addr, dst_ip.s_addr);
		model_qname_feature(domain, &(new_patt.qname_patt));
    }else{
    	new_patt.packet_patt.f_code = DNS_OK;
    }
    if(new_patt.packet_patt.f_code == DNS_OK){
    	extract_features(pkt, payload_len, &(new_patt));
    }
    if((drctn == OUT) && !is_local_sa((struct sockaddr*)&src_ip)){
    	new_patt.src_patt.f_code = SOURCE_IP_SPOOFED;
    }else{
    	uint32_t upstream_addr;
    	if(drctn == OUT){
    		upstream_addr = dst_ip.s_addr;
    	}else{
    		upstream_addr = src_ip.s_addr;
    	}
    	new_patt.dst_info.f_range = upstream_score(dst_ip.s_addr);
    	if(is_black_upstream(upstream_addr)){
			new_patt.dst_info.f_code = SERVER_BLACK;
		}else if(is_configured_upstream(upstream_addr)){
    		new_patt.dst_info.f_code = SERVER_SYS_CONF;
		}else{
			new_patt.dst_info.f_code = SERVER_UNKNOWN;
		}
    }  
    if(new_patt.packet_patt.f_code == DNS_OK){
		//DNS packet successfully parsed
		adapt_feature(&(patt->src_patt), &(new_patt.src_patt));
		adapt_feature(&(patt->dst_info), &(new_patt.dst_info));
		adapt_feature(&(patt->query_patt), &(new_patt.query_patt));
		adapt_feature(&(patt->reply_patt), &(new_patt.reply_patt));
		adapt_feature(&(patt->qname_patt), &(new_patt.qname_patt));
		adapt_feature(&(patt->ttl_patt), &(new_patt.ttl_patt));
		adapt_feature(&(patt->packet_patt), &(new_patt.packet_patt));
	}
}

