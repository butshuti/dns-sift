#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <err.h>

#include "poller.h"
#include "qh_daemon.h"

extern int train();

struct nfq_handle *nfqhIN;
struct nfq_q_handle *inQ;

void sigHandle(int signum){
	fprintf(stderr, "Interrupted: <%d>:: ERROR (%d -- %s)\n", signum, errno, strerror(errno));
	end_divert(&nfqhIN, &inQ);
	//fprintf(stderr, "Freed %d children\n", free_children());
	exit(signum);
}

void pkt_divert_start(){
	int fd_in = start_divert(&nfqhIN, &inQ, 6000, NULL);
	fprintf(stderr, "INTITIATING QUEUE: %d\n", fd_in);
	signal(SIGSEGV, sigHandle);
	signal(SIGINT, sigHandle);
	if (getuid() == 0) {
		
	}
	/*int flags = fcntl(fd_in, F_GETFL);
	if (flags == -1){
		err(1, "fcntl()");
	}
	if (fcntl(fd_in, F_SETFL, flags | O_NONBLOCK) == -1){
		err(1, "fcntl()");
	}*/
	train();
	while(1){
		process_next_packet(nfqhIN, fd_in);
	}
	end_divert(&nfqhIN, &inQ);
}
