#include <netinet/ip.h>
#include <linux/netfilter.h>  
#include "dns_features.h"         
#include "dns_verdict.h"

/*
Handle incoming packet and return verdict.
Use features in pkt and local policies to decide whether the packet passes or gets dropped.
TODO:Important targets: malformed packets, DNS tunnels, abnormal TTLs, abnormal sizes, IPs blocked by local firewalls.
*/
int handle_inpacket(dnsPacketInfo* pkt, PACKET_SCORE packet_score)
{
	return packet_score >= SCORE_OUTSTANDING ? NF_DROP : NF_ACCEPT;
}

/*
Handle outgoing packet and return verdict.
Use features in pkt and local policies to decide whether the packet passes or gets dropped.
TODO:Important target activities for filtering: DNS tunnels, random-looking subdomains, abnormal sizes, abnormal encodings, 
blacklisted addresses (IPs, domains)
*/
int handle_outpacket(dnsPacketInfo* pkt, PACKET_SCORE packet_score)
{
	return packet_score >= SCORE_OUTSTANDING ? NF_DROP : NF_ACCEPT;
}

int issue_verdict(dnsPacketInfo* pkt, PACKET_SCORE packet_score, DIRECTION drctn){
	return drctn == IN ? handle_inpacket(pkt, packet_score) : handle_outpacket(pkt, packet_score);
}

/*
Let packet through.
*/
int accept_packet(dnsPacketInfo* pkt, PACKET_SCORE packet_score, DIRECTION drctn){
	return NF_ACCEPT;
}
