#include<stdio.h>
#include<stdlib.h>
#include<signal.h>
#include<assert.h>
#include<string.h>
#include <pcap/pcap.h>
#include "poller.h"
//#include "children.h"
//#include "hash.h"

struct nfq_handle *nfqhIN;
struct nfq_q_handle *inQ;

void sigHandle(int signum){
	fprintf(stderr, "Interrupted: <%d>:: ERROR (%d -- %s)\n", signum, errno, strerror(errno));
	end_divert(&nfqhIN, &inQ);
	//fprintf(stderr, "Freed %d children\n", free_children());
	exit(signum);
}

int main(){
	int fd_in = start_divert(&nfqhIN, &inQ, 6000, NULL);
	fprintf(stderr, "INTITIATING QUEUE: %d\n", fd_in);
	signal(SIGSEGV, sigHandle);
	signal(SIGINT, sigHandle);
	while(1){
		process_next_packet(nfqhIN, fd_in);
	}
	end_divert(&nfqhIN, &inQ);
	return 0;
}
