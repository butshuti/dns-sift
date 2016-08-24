#include <stdint.h>
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
#include <ctype.h>
#include <time.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <search.h>
#include "../../config.h"
#include "dns_parse.h"
#include "logger.h"
#include "dns_features.h"


#ifdef MODEL_SYSTEM_FLOW_THRESHOLDS

/*Minimum normal TTL, in seconds*/
#define MIN_TTL_SECONDS 20
/*Maximum normal TTL, in seconds*/
#define MAX_TTL_SECONDS 40000

#define MAX_DOMAINS_TABLE_SIZE 1000
#define NUM_DOMAIN_KEY_LEVELS 2

#define ALPHA 0.15
#define ABS(x)(x>0? x : -x)
#define MAX(X,Y)(X>Y?X:Y)
#define MIN(X,Y)(X<Y?X:Y)

extern int classify(uint64_t arr[], int size, const char *tag);
extern void pattern_to_point(const pattern *pat, uint64_t *arr);

static struct hsearch_data *resolved_domains = NULL;

void model_domain_history(const char *qname, domain_history *history);

int get_domain_history(const char *qname, domain_history **history){
	if(resolved_domains == NULL){
		resolved_domains = malloc(sizeof(struct hsearch_data));
		memset(resolved_domains, 0, sizeof(struct hsearch_data));
		if(0 == hcreate_r(MAX_DOMAINS_TABLE_SIZE, resolved_domains)){
			log_critical("hcreate_r: %s\n", strerror(errno));
			perror("get_domain_history(): error initializing hash table");
			raise(SIGTERM);
		}
	}
	const char *name = qname;
	size_t len = strlen(qname);
	char temp[len];
	int level = 0;
	while( (name = strchr(name, '.')) != NULL){
		if(level >= NUM_DOMAIN_KEY_LEVELS)break;
		level++;
		name++;
	} 
	if(name == NULL){
		name = qname;
	}else{
		len -= strlen(name);
		strncpy(temp, qname, len);
		temp[len] = '\0';
		name = temp;
	}
	ENTRY e, *ep = NULL;
	e.key = (char*)name;
	if(0 != hsearch_r(e, FIND, &ep, resolved_domains)){
		*history = (domain_history*)ep->data;
	}else{
		*history = calloc(1, sizeof(domain_history));
	}
	if(*history != NULL){
		model_domain_history(qname, *history);
		e.data = *history;
		if(0 == hsearch_r(e, ENTER, &ep, resolved_domains)){
			perror("get_domain_history(): Failed updating domains table");
			raise(SIGTERM);
		}
	}
	return *history != NULL;
}

void update_avg(const char *domain, uint32_t new_val, double *adaptive_avg, 
		double *dynamic_avg, uint64_t *num_observations){
	num_observations++;
	*dynamic_avg = ( (*num_observations * (*dynamic_avg)) + new_val) / (*num_observations + 1);
	domain_history *h;
	if(!get_domain_history(domain, &h)){
		*adaptive_avg += ALPHA * ( (*dynamic_avg) - (*adaptive_avg));
	}else{
		*adaptive_avg += ALPHA * 0.1 * ( (*dynamic_avg) - (*adaptive_avg));
	}
}

void model_packet_feature(const dns_packet *pkt, feature *ft){

}

void model_reply_feature(const dns_packet *pkt, feature *ft){

}

void model_src_feature(const dns_packet *pkt, feature *ft){

}

void model_dst_feature(const dns_packet *pkt, feature *ft){

}

void model_ttl_feature(uint32_t ttl, char *domain, feature *ft){
	static double avg_flow_ttl = 60;
	static double avg_ttl = 60;
	static uint64_t num_observations = 40000;
	update_avg(domain, ttl, &avg_flow_ttl, &avg_ttl, &num_observations);	 
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

void model_query_feature(const dns_packet *pkt, const unsigned int length, feature *ft){
	static double avg_flow_qsize = 80;
	static double avg_qsize = 80;
	static uint64_t num_observations = 40000;
	if(!pkt->questions){
		ft->f_code = REQUEST_WITH_DATA;
		return;
	}
	update_avg(pkt->questions->name, length, &avg_flow_qsize, &avg_qsize, &num_observations);
	if(length > (avg_flow_qsize * 2)){
		ft->f_code = REQUEST_TOO_LARGE;
		ft->f_range = 0x07 & (((int)(length / avg_flow_qsize)));
	}else if( (pkt->answers != NULL) || (pkt->authority != NULL)
		|| (pkt->additional != NULL)){
		ft->f_code = REQUEST_WITH_DATA;
		ft->f_range = 0x07 & (((int)((length * 1.5)/ avg_flow_qsize)));
	}
}

void model_qname_feature(const char *qname, feature *ft){
	static double avg_flow_nonlc_rate = 0.3;
	static double avg_nonlc_rate = 0.3;
	static double avg_flow_len = 15;
	static double avg_len = 15;
	static double avg_flow_query_rate_per_domain = 5; //queries per minute?
	static double avg_query_rate_per_domain = 5;
	static uint64_t num_observations = 40000;
	domain_history *history;
	get_domain_history(qname, &history);
	if(history != NULL){
		if(history->len_avg > (avg_flow_len * 3)){
			ft->f_code = LABELS_TOO_LARGE;
			ft->f_range = 0x07 & (((int)((history->len_avg * 3)/ avg_flow_len))<<1);
		}else if((history->query_rate > (avg_flow_query_rate_per_domain * 2)) && (history->len_self_variation < 50)){
			ft->f_code = DOMAIN_HIGH_RATE;
			ft->f_range = 0x07 & (((int)((history->query_rate * 2)/ avg_flow_query_rate_per_domain))<<1);
		}else if((history->nonlc_avg_rate > (avg_flow_nonlc_rate * 1.5)) && (history->nonlc_rate_self_variation < 50)){
			ft->f_code = LABELS_STRANGE_ENCODING;
			ft->f_range = 0x07 & (((int)((history->nonlc_avg_rate * 3)/ avg_flow_nonlc_rate))<<1);
			printf("STRANGE_ENCODING: %s -- nonlc_avg_rate: %d/%d, history->nonlc_rate_self_variation : %d\n", qname, history->nonlc_avg_rate, history->nonlc_rate_self_variation);
		}else if((history->len_self_variation < 25 || history->nonlc_rate_self_variation < 50 )
			&& (history->query_rate_self_variation < 50) ){
			ft->f_code = LABELS_TOO_UNIFORM;
			ft->f_range = 0x07 & (history->query_rate_self_variation | history->nonlc_rate_self_variation | history->len_self_variation);
			printf("TOO_UNIFORM: %s -- rate_self_variation: %d, len_self_variation: %d, nlc: %d\n", qname, history->query_rate_self_variation, history->len_self_variation, history->nonlc_rate_self_variation);
		}else{
			ft->f_code = LABELS_OK;
		}
		update_avg(qname, history->query_avg_rate, &avg_flow_query_rate_per_domain, &avg_query_rate_per_domain, &num_observations);
		update_avg(qname, history->len_avg, &avg_flow_len, &avg_len, &num_observations);
		update_avg(qname, history->nonlc_avg_rate, &avg_flow_nonlc_rate, &avg_nonlc_rate, &num_observations);
	}else{
		perror("model_qname_feature(): error retrieving domain history");
		raise(SIGTERM);
	}
}

void model_domain_history(const char *qname, domain_history *history){
	size_t len = strlen(qname);
	int idx, nonlc = 1;
	for(idx=0; idx<len-1; idx++){
		if(!(islower(qname[idx]) || qname[idx] == '.')){
			nonlc++;
		}
	}
	if(difftime(history->refresh, time(0)) < 300){
		history->refresh = time(0);
		history->query_rate = 1;
		history->len_avg = len;
		history->query_avg_rate = 1;
		history->nonlc_avg_rate = nonlc / len;
		history->query_rate_self_variation = 100;
		history->len_self_variation = 100;
		history->nonlc_rate_self_variation = 100;
	}else{
		history->query_rate++;
	}
	/*Query rate stats*/
	history->query_avg_rate = (history->query_avg_rate + history->query_rate) / 2;
	history->query_rate_self_variation = (history->query_rate_self_variation + (1+ABS(history->query_avg_rate - history->query_rate)/(1+history->query_avg_rate)))/2;
	
	/*Len stats*/
	history->len_avg = (history->len_avg + len) / 2;
	history->len_self_variation = (history->len_self_variation + (1+ABS(history->len_avg - len)/(1+history->len_avg)))/2;
	
	/*Nonlc freq*/
	if(nonlc > 1){
		history->nonlc_avg_rate = (history->nonlc_avg_rate + (nonlc/len)) / 2;
		history->nonlc_rate_self_variation = (history->nonlc_avg_rate + (1+ABS(history->nonlc_avg_rate - (nonlc/len))/(1+history->nonlc_avg_rate)))/2;
	}
}

PACKET_SCORE  classify_pattern(const pattern *pat, const char *tag){
	uint64_t arr[7] = {0, 0, 0, 0, 0, 0, 0};
	pattern_to_point(pat, arr);
	int score = classify(arr, 7, tag);
	return score == 1 ? SCORE_NORMAL : SCORE_OUTSTANDING;
}

#endif
