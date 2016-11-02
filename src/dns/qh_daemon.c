#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include "poller.h"
#include "logger.h"
#include <syslog.h>
#include "qh_daemon.h"

extern int train(void);

struct nfq_handle *nfqhIN;
struct nfq_q_handle *inQ;

#define  QUEUE_PORT_IN 6000
#define	 QUEUE_PORT_OUT 6000
#define  TCP_IN "iptables %s INPUT -i %s -p tcp --source-port 53 -j NFQUEUE --queue-num %d ;"
#define  UDP_IN "iptables %s INPUT -i %s -p udp --source-port 53 -j NFQUEUE --queue-num %d ;"
#define  TCP_OUT "iptables %s OUTPUT -o %s -p tcp --destination-port 53 -j NFQUEUE --queue-num %d ;"
#define  UDP_OUT "iptables %s OUTPUT -o %s -p udp --destination-port 53 -j NFQUEUE --queue-num %d ;"
static int pending_signal = 0;
static char *selected_iface = "";
int LOG_LEVEL = LOG_LEVELS_CRITICAL;

void iptables_divert_tpl(char *cmd, char *iface){
	if(!cmd){
		fprintf(stderr, "Invalid iptables option.\n");
		exit(-1);
	}else if(strncmp(cmd, "-I", 2) !=0 && strncmp(cmd, "-D", 2) != 0){
		fprintf(stderr, "Supported options are ['-I' and '-D'] only.\n");
		exit(-1);
	}
	char divIn[255], divOut[255];
	int offs = snprintf(divIn, sizeof(divIn), TCP_IN, cmd, iface, QUEUE_PORT_IN);
	if(offs < strlen(TCP_IN)){
		perror("iptables_divert_tpl() - snprintf");
		exit(-1);
	}
	snprintf(divIn + offs, sizeof(divIn) - offs, UDP_IN, cmd, iface, QUEUE_PORT_IN);
	offs = snprintf(divOut, sizeof(divOut), TCP_OUT, cmd, iface, QUEUE_PORT_OUT);
	if(offs < strlen(TCP_IN)){
		perror("iptables_divert_tpl() - snprintf");
		exit(-1);
	}
	snprintf(divOut + offs, sizeof(divOut) - offs, UDP_OUT, cmd, iface, QUEUE_PORT_OUT);
	printf("\n\nRefreshing iptables rules for DNS traffic...\n%s\n%s\n\n", divIn, divOut);
	if(system(divIn) == -1 || system(divOut) == -1){
		perror("iptables_divert_tpl() -- system()");
		exit(-1);
	}
}

void iptables_start_divert(char *iface){
	iptables_divert_tpl("-I", iface);
}

void iptables_end_divert(char *iface){
	iptables_divert_tpl("-D", iface);
}

void qh_daemon_signal(int signum){
	fprintf(stderr, "Signalled <%d> to disable QUEUE?\n", signum);
	pending_signal = signum;
	iptables_end_divert(selected_iface);
	exit(pending_signal);
}

void set_log_level(int level){
	LOG_LEVEL = level;
}

void sigHandle(int signum){
	fprintf(stderr, "Received signal %d.\n", signum);
	if(signum != SIGINT && signum != SIGUSR1){
		fprintf(stderr, "Error (%d): %s\n", errno, strerror(errno));
	}
	qh_daemon_signal(signum);
}

void pkt_divert_start(ENFORCEMENT_MODE mode, char *iface, void (*thread_switch_wrapper)(void (*)(void))){
	signal(SIGSEGV, sigHandle);
 	signal(SIGINT, sigHandle);
 	signal(SIGTERM, sigHandle);
 	signal(SIGHUP, sigHandle);
 	signal(SIGUSR1, sigHandle);
	int fd_in;
	if(mode == STRICT){
		fprintf(stderr, "STARTING ENGINE IN STRICT MODE\n");
		fd_in = start_divert(&nfqhIN, &inQ, 6000, NULL);
	}else{
		fprintf(stderr, "STARTING ENGINE IN %s MODE\n", mode==LEARNING ? "LEARNING" : "PERMISSIVE");
		fd_in = start_divert(&nfqhIN, &inQ, 6000, &permissive_callback);
	}
	fprintf(stderr, "INTITIATING QUEUE: %d\n", fd_in);
	if (getuid() == 0) {
		
	}
	/*int flags = fcntl(fd_in, F_GETFL);
	if (flags == -1){
		err(1, "fcntl()");
	}
	if (fcntl(fd_in, F_SETFL, flags | O_NONBLOCK) == -1){
		err(1, "fcntl()");
	}*/
	if(!train()){
		fprintf(stderr, "Error training DNS classifier.\nExiting.\n\n");
		exit(-1);
	}
	openlog("DNSSIFT", LOG_PERROR, LOG_USER);
	iptables_start_divert(iface);
	selected_iface = strdup(iface);
	while(!pending_signal){
		if(thread_switch_wrapper){
			void f(void){process_next_packet(nfqhIN, fd_in);}
			thread_switch_wrapper(&f);
		}else{
			process_next_packet(nfqhIN, fd_in);
		}
	}
	iptables_end_divert(iface);
	end_divert(&nfqhIN, &inQ);
	exit(pending_signal);
}
