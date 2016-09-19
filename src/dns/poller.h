#ifndef __TCPTLS_DIVERT_H__
#define __TCPTLS_DIVERT_H__

#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>           
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include "dns_features.h"

#define DF_IN	0x1

typedef int (*divert_cb)(void *data, int len, int flags);


/* Initialize netfilter library for packet handling 
*
*Return file descriptor for queue handler
*/
int start_divert(struct nfq_handle**, struct nfq_q_handle**, int, void*);
int init_divert(struct nfq_handle**, struct nfq_q_handle**, int);

/* Close and free resources */
int end_divert(struct nfq_handle**, struct nfq_q_handle**);

/* Divert next packet in queue*/
void process_next_packet(struct nfq_handle*, int);

/*
Callback function to register for packet processing in the handler in permissive mode
Returns 'ACCEPT' as the verdict on packet (see netfilter)
*/
int permissive_callback(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*);


int process_packet(struct nfq_q_handle*, struct nfgenmsg*, struct nfq_data*, void*, 
	 int (*verdict_function)(dnsPacketInfo*, PACKET_SCORE, DIRECTION));
	 
int start_forwarding(struct in_addr from, int dport, int sport, int QNum);
int stop_forwarding(struct in_addr from, int dport, int sport, int QNum);

#endif
