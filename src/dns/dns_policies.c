#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "dns_policies.h"
#include "config_parser.h"

#define RESOLV_CONF "/etc/resolv.conf"

struct upstream *parse_upstreams(char *config_path){
	struct upstream *ret = NULL;
	struct upstream *prev = NULL;
	struct sockaddr_in temp;
	struct string_ll *nameservers = NULL;
	parse_nameservers(RESOLV_CONF, &nameservers);
	struct string_ll *ns_entry = NULL;
	for(ns_entry = nameservers; ns_entry != NULL; ns_entry = ns_entry->next){
		if(inet_aton(ns_entry->val, &temp.sin_addr)){
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
		printf("NS: %s\n", ns_entry->val);
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
