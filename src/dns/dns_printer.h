#include <stdint.h>
#include "dns_parse.h"

#ifndef _DNSFW_PRINTER_H
#define _DNSFW_PRINTER_H

void print_rrset(const dns_rr* rr_list, char *label);

char *opcode_str(uint32_t opcode);

char *rcode_str(uint16_t rcode, uint8_t tsig);

void print_header(const dns_hdr *h, uint32_t opt_flags);

void print_dns(const dns_packet *pkt);

char *rclass_str(uint16_t rclass);

char *rtype_str(uint16_t rtype);

char *rdata_str(char *rdata, uint16_t rtype);

char *rrsig_str(char *rdata, uint16_t rtype);

#endif
