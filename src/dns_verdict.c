#include <netinet/ip.h>
#include <linux/netfilter.h>  
#include "dns_features.h"         
#include "dns_verdict.h"

/*
Handle incoming packet and return verdict.
Use features in pkt and local policies to decide whether the packet passes or gets dropped.
TODO:Important targets: malformed packets, DNS tunnels, abnormal TTLs, abnormal sizes, IPs blocked by local firewalls.
*/
int handle_inpacket(dnsPacketInfo* pkt)
{
	
	return NF_ACCEPT;
}

/*
Handle outgoing packet and return verdict.
Use features in pkt and local policies to decide whether the packet passes or gets dropped.
TODO:Important target activities for filtering: DNS tunnels, random-looking subdomains, abnormal sizes, abnormal encodings, 
blacklisted addresses (IPs, domains)
*/
int handle_outpacket(dnsPacketInfo* pkt)
{
	
	return NF_ACCEPT;
}
