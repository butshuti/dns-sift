#ifndef _DNSFW_DNS_FLOW_MODEL_H
#define _DNSFW_DNS_FLOW_MODEL_H

#include "dns_features.h"

#ifdef __cplusplus
    extern "C" {
#endif

void model_domain_history(const char *qname, domain_history *history);
void model_packet_feature(const dns_packet *pkt, feature *ft);
void model_reply_feature(const dns_packet *pkt, feature *ft);
void model_src_feature(const dns_packet *pkt, feature *ft);
void model_dst_feature(const dns_packet *pkt, feature *ft);
void model_ttl_feature(uint32_t ttl, char *domain, feature *ft);
void model_query_feature(const dns_packet *pkt, const unsigned int length, feature *ft);
void model_qname_feature(const char *qname, feature *ft);

#ifdef __cplusplus
    }
#endif //__CPLUSPLUS

#endif //_DNSFW_DNS_FLOW_MODEL_H
