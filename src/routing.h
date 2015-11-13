#include <stdint.h>
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
#ifndef _DNSFW_ROUTING_H
#define _DNSFW_ROUTING_H
int is_local_sa(struct sockaddr *sa);
#endif
