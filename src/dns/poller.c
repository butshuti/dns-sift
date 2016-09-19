#include <err.h>
#include "poller.h"
#include "logger.h"
#include "dns_features.h"
#include "dns_verdict.h"

#define BUFSIZE 1024

/*
Callback function to register for packet processing in the handler
Returns VERDICT on packet (see netfilter)
*/
static int verdict_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	return process_packet(qh, nfmsg, nfa, data, issue_verdict);
}

/*
Callback function to register for packet processing in the handler in permissive mode
Returns 'ACCEPT' as the verdict on packet (see netfilter)
*/
int permissive_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
	return process_packet(qh, nfmsg, nfa, data, accept_packet);
}


int process_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data, 
	 int (*verdict_function)(dnsPacketInfo*, PACKET_SCORE, DIRECTION)){
	int id, rlen, verdict, phys_in_dev;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *payload;
	rlen = nfq_get_payload(nfa, &payload);
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
	phys_in_dev=nfq_get_indev(nfa);
	if (ph){
		id = ntohl(ph->packet_id);
		/*
		Extract DNS features from packet
		*/
		dnsPacketInfo *info;
		/*
		Check if packet is incoming
		*/
		int packet_score;
		if(phys_in_dev){
			packet_score = classify_packet(payload, rlen, &info, IN);
			verdict = verdict_function(info, packet_score, IN);
		}else{
			packet_score = classify_packet(payload, rlen, &info, OUT);
			verdict = verdict_function(info, packet_score, IN);
		}
		return nfq_set_verdict(qh, id, verdict, rlen, payload);
	}else{
		err(1, "verdict_callback()");
		return -1;
	}	
}

/*
*Initialize the queue and handler; open a raw socket
*/
int start_divert(struct nfq_handle **h, struct nfq_q_handle **qh, int port, void *cb){
	int fd;
	*h = nfq_open();
	if (!(*h)) {
		err(1, "error during nfq_open()\n");
	}
	if(cb == NULL){
		log_info("unbinding existing nf_queue handler for AF_INET (if any)\n");
		if (nfq_unbind_pf(*h, AF_INET) < 0) {
			err(1, "error during nfq_unbind_pf()\n");
		}

		log_info("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
		if (nfq_bind_pf(*h, AF_INET) < 0) {
			err(1, "error during nfq_bind_pf()\n");
		}
	}
	log_info("binding this socket to queue '0'\n");
	if(cb){
		*qh = nfq_create_queue(*h,  port, cb, NULL);
	}else{
		*qh = nfq_create_queue(*h,  port, &verdict_callback, NULL);
	}
	if (!(*qh)) {
		err(1, "error during nfq_create_queue()\n");
	}
	log_info("setting copy_packet mode\n");
	if (nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		err(1, "can't set packet_copy mode\n");
	}
	fd = nfq_fd(*h);
	return fd; 
}

/*
*Free the queue and handler.
*/
int end_divert(struct nfq_handle **h, struct nfq_q_handle **queue){
	if(*queue){
		nfq_destroy_queue(*queue);
	}
	if(*h){
		return nfq_close(*h);
	}
	return -1;
}

/*
Fetch next packet in queue and process it
*/
void process_next_packet(struct nfq_handle *h, int fd){
	char buf[BUFSIZE];
	int rv;
	if((rv = recv(fd, buf, sizeof(buf), MSG_WAITALL)) && rv >= 0) {	
		nfq_handle_packet(h, buf, rv);
	}
	if (errno == ENOBUFS) {
		log_debug("Err: {ENOBUFS} ; Packet dropped.............\n");
		return;
	}
}
