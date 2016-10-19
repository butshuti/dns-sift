#include <string.h>
#include <errno.h>
#include <err.h>
#include <signal.h>
#include <strings.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#define _GNU_SOURCE
#define __USE_GNU
#include <search.h>
#include <stdio.h>
#include "logger.h"
#include "dns_features.h"
#include "dns_policies.h"
#include "dns_parse.h"
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

const feature NULL_FEATURE = {0, 0, 0};
static struct hsearch_data *connections_table = NULL;
static struct hsearch_data *high_level_domains_table = NULL;
int conn_misses = 0;

void dump(const unsigned char *data_buffer, const unsigned int length);
void dump_ascii(const unsigned char *data_buffer, const unsigned int length);
void print_pattern(const pattern*, char *tag);
void extract_features(const dns_packet *pkt, const unsigned int length, pattern *pat);
void print_pattern_point(const pattern *pat, FILE *fp, char *tag);
int print_feature(char *buf, int buflen, int cur_offs, const char *label, const feature ft);
void adapt_feature(const feature *prev, feature *cur);

extern void model_ttl_feature(uint32_t ttl, char *domain, feature *ft);
extern void model_packet_feature(const dns_packet *pkt, feature *ft);
extern void model_query_feature(const dns_packet *pkt, const unsigned int length, feature *ft);
extern void model_reply_feature(const dns_packet *pkt, feature *ft);
extern void model_src_feature(const dns_packet *pkt, feature *ft);
extern void model_dst_feature(const dns_packet *pkt, feature *ft);
extern void model_qname_feature(const char *qname, feature *ft);
extern PACKET_SCORE classify_pattern(const pattern *pat, const char *tag);

/*
Extracts details from IP packet (assumes Ethernet header stripped off)
*/
PACKET_SCORE classify_packet(const uint8_t *data, size_t rlen, dnsPacketInfo **pkt_info, DIRECTION drctn)
{
	static FILE *fp = NULL;
	if(connections_table == NULL || high_level_domains_table == NULL){
		connections_table = malloc(sizeof(struct hsearch_data));
		high_level_domains_table = malloc(sizeof(struct hsearch_data));
		memset(connections_table, 0, sizeof(struct hsearch_data));
		memset(high_level_domains_table, 0, sizeof(struct hsearch_data));
		if(0 == hcreate_r(MAX_CONNECTIONS_TABLE_SIZE, connections_table)){
			log_critical("hcreate: %s\n", strerror(errno));
			perror("classify_packet(): (1) error initializing hash table");
			raise(SIGTERM);
		}else if(0 == hcreate_r(MAX_DOMAINS_TABLE_SIZE, high_level_domains_table)){
			log_critical("hcreate: %s\n", strerror(errno));
			perror("classify_packet(): (2) error initializing hash table");
			raise(SIGTERM);
		}
	}
    if(rlen < sizeof(struct ip)){ //At least the ip header should be there!
        log_critical("Error extracting IP header: Packet too short.");
        return SCORE_FLAGGED;
    }
    struct ip *ip;
    dns_packet *pkt = NULL;
    struct	in_addr src_ip, dst_ip;
    uint16_t src_port, dst_port;
    char tag[255];
    ENTRY e, *ep;
    dnsTransaction *cur_t, *t = NULL;
    cur_t = (dnsTransaction *)malloc(sizeof(dnsTransaction));
    memset(cur_t, 0, sizeof(dnsTransaction));
    ip = (struct ip*)data;
    if(rlen < (ip->ip_hl << 2))
    {
        log_critical("Error parsing IP packet: Packet too short.");
        return SCORE_FLAGGED;
    }
    dns_parse_errors err_code = parse_msg_unknown;
    src_ip = ip->ip_src;
    dst_ip = ip->ip_dst;

    switch(ip->ip_p)
    {
        case IP_PROTO_UDP:
        {
            struct udphdr *udp;
            udp = (struct udphdr*) ((unsigned long)ip + (ip->ip_hl << 2));
            src_port = udp->source;
            dst_port = udp->dest;
            uint8_t *payload = (uint8_t*)udp + UDP_HDR_SIZE;
            err_code = dns_parse((uint8_t *)payload, ntohs(udp->len) - UDP_HDR_SIZE, &pkt);
            break;
        }
        case IP_PROTO_TCP:
        {
            struct tcphdr *tcp;
    	    tcp = (struct tcphdr*) ((unsigned long) ip + (ip->ip_hl << 2));
    	    src_port = tcp->source;
          dst_port = tcp->dest;
    	    uint8_t *payload = (uint8_t*)tcp + (tcp->doff << 2);
    	    if(ntohs(ip->ip_len) - ((ip->ip_hl << 2) + (tcp->doff << 2)) > 0){
    	        //Payload is not empty
    	        err_code = dns_parse((uint8_t *)payload+2, ntohs(ip->ip_len) - ((ip->ip_hl << 2) + (tcp->doff << 2)), &pkt);
    	        //printf("IP_LEN: %d, IPHDR_LEN: %d,  TCHHDR_LEN: %d, DNS_LEN: %d----------------\n", ntohs(ip->ip_len), (ip->ip_hl << 2), (tcp->doff << 2), ntohs(ip->ip_len) - ((ip->ip_hl << 2) + (tcp->doff << 2)));
    	    }else{
    	        //This packet may be part of the connection handshake or tear-down? Anyway not useful.
    	    }
            break;
        }
        default:
        {
            log_debug("Unsupported protocol for DNS: %d\n", ip->ip_p);
            return SCORE_FLAGGED;
        }
        
    }
    if(err_code != parse_ok){
        	switch(err_code){
        		case parse_malformed: case parse_incomplete: case parse_memory_error:
        			{
        				cur_t->patt.packet_patt.f_code = DNS_PACKET_MALFORMED;
        			}
        			break;
        		default:
        			cur_t->patt.packet_patt.f_code = DNS_NOT_DNS;
        	}
        	char domain[255];
			snprintf(domain, 255, "%d.%d.%d.INVALID", dst_ip.s_addr, dst_ip.s_addr, src_ip.s_addr);
			model_qname_feature(domain, &(cur_t->patt.qname_patt));
    }else{
    	cur_t->patt.packet_patt.f_code = DNS_OK;
    }
    if(!fp){
    	fp = fopen("/tmp/dnssift/datapoints.csv", "a+");
    }
    if(pkt == NULL){
    	cur_t->patt.packet_patt.f_code = DNS_NOT_DNS;
    	snprintf(tag, 255, "%u;%s", drctn == OUT ? dst_ip.s_addr : src_ip.s_addr, INVALID_DNS_QNAME_TAG);
    	PACKET_SCORE score = classify_pattern(&(cur_t->patt), tag);  	 
    	free(cur_t);
    	return score;
    }
    if(pkt->questions && pkt->questions->name){ 
    	snprintf(tag, 255, "%u;%s", drctn == OUT ? dst_ip.s_addr : src_ip.s_addr, pkt->questions->name);
    }else{
    	snprintf(tag, 255, "%u;%s", drctn == OUT ? dst_ip.s_addr : src_ip.s_addr, INVALID_DNS_QNAME_TAG);
    }
    if(cur_t->patt.packet_patt.f_code == DNS_OK){
    	extract_features(pkt, rlen, &(cur_t->patt));
    }
    if((drctn == OUT) && !is_local_sa((struct sockaddr*)&src_ip)){
    	cur_t->patt.src_patt.f_code = SOURCE_IP_SPOOFED;
    }else{
    	uint32_t upstream_addr;
    	if(drctn == OUT){
    		upstream_addr = dst_ip.s_addr;
    	}else{
    		upstream_addr = src_ip.s_addr;
    	}
    	cur_t->patt.dst_info.f_range = upstream_score(dst_ip.s_addr);
    	if(is_black_upstream(upstream_addr)){
			cur_t->patt.dst_info.f_code = SERVER_BLACK;
		}else if(is_configured_upstream(upstream_addr)){
    		cur_t->patt.dst_info.f_code = SERVER_SYS_CONF;
		}else{
			cur_t->patt.dst_info.f_code = SERVER_UNKNOWN;
		}
    }    
    char key[32];
    if(0 > snprintf(key, sizeof(key), "key%u", (drctn == IN ? src_ip.s_addr : dst_ip.s_addr))){//(src_ip.s_addr + dst_ip.s_addr) ^ (src_ip.s_addr | src_ip.s_addr))){
    	char errmsg[255];
    	snprintf(errmsg, sizeof(errmsg), "classify_packet(): Failed to create key for %d -> %d connection", src_ip.s_addr, dst_ip.s_addr);
    	perror(errmsg);
    	raise(SIGTERM);
    }
    e.key = key;
    e.data = NULL;
    cur_t->id = pkt->header->id;
    if(0 != hsearch_r(e, FIND, &ep, connections_table)){ //Entry found
    	t = (dnsTransaction*)(ep->data);
    	if(drctn == IN){
    		cur_t->transaction_count = t->transaction_count + 1;
    		cur_t->src_port_count = t->src_port_count;
    		cur_t->id_count = t->id_count;
    		cur_t->patt.query_patt = t->patt.query_patt;
    		cur_t->port = dst_port;
    		cur_t->patt.src_patt.f_code = t->patt.src_patt.f_code;
    	}else{
    		cur_t->patt.ttl_patt = t->patt.ttl_patt;
    		cur_t->patt.reply_patt = t->patt.reply_patt;
    		cur_t->transaction_count = t->transaction_count;
    		cur_t->port = src_port;
    		if(t->port == src_port){
    			cur_t->src_port_count = t->src_port_count + 1;
    		}else{
    			cur_t->src_port_count = t->src_port_count;
    			cur_t->patt.src_patt.f_range = 0;
    		}
    		if(t->id == pkt->header->id){
    			cur_t->id_count = t->id_count + 1;
    		}else{
    			cur_t->id = pkt->header->id;
    			cur_t->id_count = 0;
    			cur_t->patt.src_patt.f_range = 0;
    		}
    	}
    	if((cur_t->transaction_count > 1) && ((cur_t->src_port_count > 5) || (cur_t->id_count > 10)) && t->patt.src_patt.f_code == SOURCE_OK){
    		cur_t->patt.src_patt.f_code = SOURCE_PORT_BOUND;
    	}
    	cur_t->patt.packet_patt.f_range++;
    }else{
    	cur_t->transaction_count = 0;
    	cur_t->id_count = 1;
    	cur_t->src_port_count = 1;
    	conn_misses++;
    }
    e.data = cur_t;
	if(ep != NULL){
		ep->data = e.data;
	}else if(0 == hsearch_r(e, ENTER, &ep, connections_table)){
		log_debug("classify_packet(): Failed updating connections table -- SIZE = %d / %d ?", conn_misses, MAX_CONNECTIONS_TABLE_SIZE);
		perror("classify_packet(): Failed updating connections table");
		raise(SIGTERM);
	}    
	if(cur_t->patt.packet_patt.f_code == DNS_OK && t != NULL){
		adapt_feature(&(t->patt.src_patt), &(cur_t->patt.src_patt));
		adapt_feature(&(t->patt.dst_info), &(cur_t->patt.dst_info));
		adapt_feature(&(t->patt.query_patt), &(cur_t->patt.query_patt));
		adapt_feature(&(t->patt.reply_patt), &(cur_t->patt.reply_patt));
		adapt_feature(&(t->patt.qname_patt), &(cur_t->patt.qname_patt));
		adapt_feature(&(t->patt.ttl_patt), &(cur_t->patt.ttl_patt));
		adapt_feature(&(t->patt.packet_patt), &(cur_t->patt.packet_patt));
	} 
	UNUSED_PARAM(dst_port);
	PACKET_SCORE score = classify_pattern(&(cur_t->patt), tag);	 
	char *qname = strdup(pkt->questions ? pkt->questions->name : "NULL");
	reverse(qname);		
	char classif_log[255];
	snprintf(classif_log, sizeof(classif_log), "SCORE: %d -- %s / %s", score, pkt->answers == NULL ? "Query" : "Reply", qname);
	free(qname);
	print_pattern_point(&(cur_t->patt), fp, classif_log);
	//print_dns(pkt);
 	free(cur_t);
 	return score;
}

void adapt_feature(const feature *prev, feature *cur){
	if(prev->f_code != cur->f_code){
		if( (prev->f_range >> 2) > 0){
			cur->f_code = prev->f_code;
			cur->uniqueness = prev->uniqueness - 1;
			cur->f_range = prev->f_range - 1;
		}else{
			cur->f_range = 0;
		}
	}else{
		cur->f_range = prev->f_range;
		cur->uniqueness = (prev->uniqueness  & 0x07) | (prev->uniqueness  + 1);
	}
}

/*
Dumps raw memory in hex byte and printable split format
==Copy: Jon Erickson < Hacking --The art of exploitation-->
*/
void dump(const unsigned char *data_buffer, const unsigned int length){
	unsigned char byte;
	unsigned int i, j;
	for(i=0; i<length; i++){
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]); // Display byte in hex.
		if(((i%16)==15) || (i==length-1)){
			for(j=0; j < 15-(i%16); j++){
				printf("  ");
			}
			printf("| ");
			for(j=(i-(i%16)); j <= i; j++){ // Display printable bytes form line
				byte = data_buffer[j];
				if((byte > 31) && (byte < 127)){  // Printable char range
					printf("%c", byte);
				}else{
					printf(".");
				}
			}
			printf("\n");  // End of the dump line ( each line is 16 bytes)
		} // End if
	}  // End for
}

/*
Dumps raw memory in ascii
*/
void dump_ascii(const unsigned char *data_buffer, const unsigned int length){
	unsigned char byte;
	unsigned int i, j;
	for(i=0; i<length; i++){
		byte = data_buffer[i];
		if(((i%16)==15) || (i==length-1)){
			for(j=(i-(i%64)); j <= i; j++){ // Display printable bytes form line
				byte = data_buffer[j];
				if((byte > 31) && (byte < 127)){  // Printable char range
					printf("%c", byte);
				}else{
					printf(".");
				}
			}
			printf("\n");  // End of the dump line ( each line is 16 bytes)
		}
	}
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
