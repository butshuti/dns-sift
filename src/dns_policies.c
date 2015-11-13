#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "dns_policies.h"

#define RESOLV_CONF "/etc/resolv.conf"

struct upstream *parse_upstreams(char *config_path){
	struct upstream *ret = NULL;
	struct upstream *prev = NULL;
	struct sockaddr_in temp;
	if(inet_aton("8.8.8.8", &temp.sin_addr)){
		struct upstream *r = malloc(sizeof(struct upstream));
		if(r != NULL){
			r->address = temp.sin_addr.s_addr;
			r->next = NULL;
			if(prev != NULL){
				prev->next = r;
			}else{
				ret = r;
			}
			prev = r;
		}
	}
	if(inet_aton("60.31.127.118", &temp.sin_addr)){
		struct upstream *r = malloc(sizeof(struct upstream));
		if(r != NULL){
			r->address = temp.sin_addr.s_addr;
			r->next = NULL;
			if(prev != NULL){
				prev->next = r;
			}else{
				ret = r;
			}
			prev = r;
		}
	}
	return ret;
}

int is_configured_upstream(uint32_t address){
	static upstreams_list *upstreams = NULL;
	if(upstreams == NULL){
		upstreams = malloc(sizeof(upstreams_list));
		if(upstreams != NULL){
			upstreams->list = parse_upstreams(RESOLV_CONF);
		}
		
	}
	struct upstream *r = upstreams->list;
	while(r != NULL){
			if(address == r->address){
				return 1;
			}
			r = r->next;
	}
	return 0;
}

int is_black_upstream(uint32_t address){
	return 0;
}

int upstream_score(uint32_t address){
	return 0;
}
