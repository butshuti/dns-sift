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
#define  TCP_IN "iptables %s INPUT -i %s -p tcp -m multiport --sports %s -j NFQUEUE --queue-num %d ;"
#define  UDP_IN "iptables %s INPUT -i %s -p udp -m multiport --sports %s -j NFQUEUE --queue-num %d ;"
#define  TCP_OUT "iptables %s OUTPUT -o %s -p tcp -m multiport --dports %s -j NFQUEUE --queue-num %d ;"
#define  UDP_OUT "iptables %s OUTPUT -o %s -p udp -m multiport --dports %s -j NFQUEUE --queue-num %d ;"
static int pending_signal = 0;
static char *selected_iface = "";
static char *selected_srvc_ports = "";
int LOG_LEVEL = LOG_LEVELS_CRITICAL;

int verify_service_ports_arg(char *args){
	if(!args){
		return 0;
	}
	char *token, *saveptr;
	int num_tokens = 0;
	token = strtok_r(args, ",", &saveptr);
	while(token){
		if(atoi(token) <= 0){
			return 0;
		}
		num_tokens++;
		token = strtok_r(NULL, ",", &saveptr);
	}
	return num_tokens > 0;
}

void iptables_divert_tpl(char *cmd, char *iface, char *srvc_ports){
	if(!cmd){
		fprintf(stderr, "Invalid iptables option.\n");
		exit(-1);
	}else if(!verify_service_ports_arg(srvc_ports)){
		fprintf(stderr, "Invalid service port(s) specification.\n");
		exit(-1);
	}else if(strncmp(cmd, "-I", 2) !=0 && strncmp(cmd, "-D", 2) != 0){
		fprintf(stderr, "Supported options are ['-I' and '-D'] only.\n");
		exit(-1);
	}
	char divIn[255], divOut[255];
	int offs = snprintf(divIn, sizeof(divIn), TCP_IN, cmd, iface, srvc_ports, QUEUE_PORT_IN);
	if(offs < strlen(TCP_IN)){
		perror("iptables_divert_tpl() - snprintf");
		exit(-1);
	}
	snprintf(divIn + offs, sizeof(divIn) - offs, UDP_IN, cmd, iface, srvc_ports, QUEUE_PORT_IN);
	offs = snprintf(divOut, sizeof(divOut), TCP_OUT, cmd, iface, srvc_ports, QUEUE_PORT_OUT);
	if(offs < strlen(TCP_IN)){
		perror("iptables_divert_tpl() - snprintf");
		exit(-1);
	}
	snprintf(divOut + offs, sizeof(divOut) - offs, UDP_OUT, cmd, iface, srvc_ports, QUEUE_PORT_OUT);
	printf("\n\nRefreshing iptables rules for DNS traffic...\n%s\n%s\n\n", divIn, divOut);
	if(system(divIn) == -1 || system(divOut) == -1){
		perror("iptables_divert_tpl() -- system()");
		exit(-1);
	}
}

void iptables_start_divert(char *iface, char *srvc_ports){
	iptables_divert_tpl("-I", iface, srvc_ports);
}

void iptables_end_divert(char *iface, char *srvc_ports){
	iptables_divert_tpl("-D", iface, srvc_ports);
}

void qh_daemon_signal(int signum){
	fprintf(stderr, "Signalled <%d> to disable QUEUE?\n", signum);
	pending_signal = signum;
	iptables_end_divert(selected_iface, selected_srvc_ports);
	free(selected_iface);
	free(selected_srvc_ports);
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

void pkt_divert_start(ENFORCEMENT_MODE mode, char *iface, char *srvc_ports, void (*thread_switch_wrapper)(void (*)(void))){
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
	iptables_start_divert(iface, srvc_ports);
	selected_iface = strdup(iface);
	selected_srvc_ports = strdup(srvc_ports);
	while(!pending_signal){
		if(thread_switch_wrapper){
			void f(void){process_next_packet(nfqhIN, fd_in);}
			thread_switch_wrapper(&f);
		}else{
			process_next_packet(nfqhIN, fd_in);
		}
	}
	iptables_end_divert(iface, srvc_ports);
	end_divert(&nfqhIN, &inQ);
	exit(pending_signal);
}
