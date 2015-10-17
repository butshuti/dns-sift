#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdio.h>
#include "logger.h"
#include "dns_features.h"
#include "dns_parse.h"

#define UDP_HDR_SIZE 8
#define TCP_HDR_SIZE 20


void dump(const unsigned char *data_buffer, const unsigned int length);
void dump_ascii(const unsigned char *data_buffer, const unsigned int length);

/*
Extracts packet details
*/
void get_packet_info(const uint8_t *data, size_t rlen, dnsPacketInfo **pkt_info)
{
    if(rlen < sizeof(struct ip)){ /*At least the ip header should be there!*/
        log_critical("Error extracting IP header: Packet too short.");
        return;
    }
    struct ip *ip;
    dns_packet *pkt = NULL;
    ip = (struct ip*)data;
    if(rlen < (ip->ip_hl << 2))
    {
        log_critical("Error parsing IP packet: Packet too short.");
        return;
    }
    switch(ip->ip_p)
    {
        case IP_PROTO_UDP:
        {
            struct udphdr *udp;
            udp = (struct udphdr*) ((unsigned long)ip + (ip->ip_hl << 2));
            uint8_t *payload = (uint8_t*)udp + UDP_HDR_SIZE;
            dns_parse((uint8_t *)payload, ntohs(udp->len) - UDP_HDR_SIZE, &pkt);
            break;
        }
        case IP_PROTO_TCP:
        {
            struct tcphdr *tcp;
    	    tcp = (struct tcphdr*) ((unsigned long) ip + (ip->ip_hl << 2));
    	    uint8_t *payload = (uint8_t*)tcp + (tcp->doff << 2);
    	    if(ntohs(ip->ip_len) - ((ip->ip_hl << 2) + (tcp->doff << 2)) > 0){
    	        /*Payload is not empty*/
    	        dns_parse((uint8_t *)payload+2, ntohs(ip->ip_len) - ((ip->ip_hl << 2) + (tcp->doff << 2)), &pkt);
    	        printf("IP_LEN: %d, IPHDR_LEN: %d,  TCHHDR_LEN: %d, DNS_LEN: %d----------------\n", ntohs(ip->ip_len), (ip->ip_hl << 2), (tcp->doff << 2), ntohs(ip->ip_len) - ((ip->ip_hl << 2) + (tcp->doff << 2)));
    	    }else{
    	        /*This packet may be part of the connection handshake or tear-down? Anyway not useful.*/
    	    }
            break;
        }
        default:
        {
            log_debug("Unsupported protocol for DNS: %d\n", ip->ip_p);
            return;
        }
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
