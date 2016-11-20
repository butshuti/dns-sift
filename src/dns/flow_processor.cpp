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
#include "domain_utils.h"


#include <time.h>

#define UDP_HDR_SIZE 8
#define TCP_HDR_SIZE 20

#define MAX_CONNECTIONS_TABLE_SIZE 10
#define MAX_DOMAINS_TABLE_SIZE 10

#define LOG_LINE_SIZE 200

#define  UNUSED_PARAM(x) ((void)(x))

#define INVALID_DNS_QNAME_TAG ".dilavni"
extern "C" {
	int classify_flow(int arr[], int size, const char *tag);
}
void pattern_to_point(const pattern *pat, uint64_t *arr);
void print_flow_feature_point(const pattern *pat, FILE *fp, char *tag);

PACKET_SCORE  classify_pattern(const pattern *pat, const char *tag){
	uint64_t arr[7] = {0, 0, 0, 0, 0, 0, 0};
	int flow_arr[26] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	pattern_to_point(pat, arr);
	flow_feature_to_point(&pat->flow_patt, flow_arr, 26);
	int score = classify_flow(flow_arr, 26, tag);
	return score == 1 ? SCORE_NORMAL : SCORE_OUTSTANDING;
}

/*
Extracts details from IP packet (assumes Ethernet header stripped off)
@param data: copied payload (first rlen bytes), may not be the entire packet
@param rlen: size of copied portion of the datagram, may be less than the actual datagram length, to reduce copy overhead
@param pkt_info
@param drctn {IN, OUT}
*/
PACKET_SCORE classify_packet(const uint8_t *data, size_t rlen, dnsPacketInfo **pkt_info, DIRECTION drctn)
{
	static FILE *fp = NULL;
    if(rlen < sizeof(struct ip)){ //At least the ip header should be there!
        log_critical("Error extracting IP header: Packet too short.");
        return SCORE_FLAGGED;
    }
    struct ip *ip;
    struct	in_addr src_ip, dst_ip;
    uint16_t src_port, dst_port, ip_datagram_len;
    pattern pkt_descr;
    ip = (struct ip*)data;
    if((int)rlen < (ip->ip_hl << 2))
    {
        log_critical("Error parsing IP packet: Packet too short.");
        return SCORE_FLAGGED;
    }
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
            UNUSED_PARAM(payload);
            ip_datagram_len = ntohs(udp->len);
            if(ip_datagram_len < rlen){
    	        //All payload copied: can run DPI
            	dns_flow_inspect(payload, ip_datagram_len, src_ip, dst_ip, drctn, &pkt_descr);
            }
            break;
        }
        case IP_PROTO_TCP:
        {
            struct tcphdr *tcp;
    	    tcp = (struct tcphdr*) ((unsigned long) ip + (ip->ip_hl << 2));
    	    src_port = tcp->source;
          	dst_port = tcp->dest;
    	    uint8_t *payload = (uint8_t*)tcp + (tcp->doff << 2);
    	    UNUSED_PARAM(payload);
    	    ip_datagram_len = ntohs(ip->ip_len);
    	    if(ntohs(ip->ip_len) - ((ip->ip_hl << 2) + (tcp->doff << 2)) > 0){
    	        //Payload is not empty
    	        uint16_t expected_size = ntohs(ip->ip_len) - ((ip->ip_hl << 2) + (tcp->doff << 2));
    	        if(expected_size < rlen){
    	        	//All payload copied: can run DPI
    	        	dns_flow_inspect(payload+2, expected_size, src_ip, dst_ip, drctn, &pkt_descr);
    	        }
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
    //Extract & model flow features
	if(drctn == OUT){
		model_uplink_flow_features(&(pkt_descr.flow_patt), src_ip.s_addr, dst_ip.s_addr, src_port, dst_port, ip_datagram_len);
	}else{
		model_downlink_flow_features(&(pkt_descr.flow_patt), src_ip.s_addr, dst_ip.s_addr, src_port, dst_port, ip_datagram_len);
	}
	//printf("rlen(%zu {%d}): %d -> %d\n", rlen, ip_datagram_len, src_port, dst_port);
    if(!fp){
    	fp = fopen("/tmp/dnssift/datapoints.csv", "a+");
    }
	PACKET_SCORE score = classify_pattern(&pkt_descr, "NO_TAG");	
	char classif_log[255];
	snprintf(classif_log, sizeof(classif_log), "SCORE: %d", score); 
	print_flow_feature_point(&pkt_descr, fp, classif_log);
 	return score;
}

