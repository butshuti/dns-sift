#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "routing.h"
#include "logger.h"

int is_local_sa(struct sockaddr *sa){
	int ret = 0, family;
	struct ifaddrs *ifaddr, *ifa;
	/*
	*Get all locally-configured interface addresses.
	*/
	if(getifaddrs(&ifaddr) == -1)
	{
	   log_critical("is_local_ip<getifaddrs>");
	   return 0;
	}
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
		   continue;
		family = ifa->ifa_addr->sa_family;
		if(family == AF_INET)
		{
			if(((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr == 
				((struct sockaddr_in*)ifa->ifa_addr)->sin_addr.s_addr){
				ret = 1;
				break;
			}
		}else if(family == AF_INET6){
			if(memcmp(&(((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr), 
				&(((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr), sizeof(struct in6_addr)) == 0){
				ret = 1;
				break;
			}
		}
	}
	freeifaddrs(ifaddr);
	return ret;
}

/*Not thread-safe*/
int is_local_ip4(uint32_t ip){
	static struct sockaddr_in ip4addr;
	ip4addr.sin_addr.s_addr = ip;
	return is_local_sa((struct sockaddr*) (&ip4addr));
}


/*Not thread-safe*/
int is_local_ip6(uint8_t ip[16]){
	static struct sockaddr_in6 ip6addr;
	memcpy(ip6addr.sin6_addr.s6_addr, ip, 16);
	return is_local_sa((struct sockaddr*) (&ip6addr));
}
