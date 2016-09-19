#ifndef __TCPTLS_ROUTE_H__
#define __TCPTLS_ROUTE_H__

int issue_verdict(dnsPacketInfo*, PACKET_SCORE, DIRECTION);
int accept_packet(dnsPacketInfo*, PACKET_SCORE, DIRECTION);

#endif
