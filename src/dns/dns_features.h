#ifndef _DNSFW_FEATURES_H
#define _DNSFW_FEATURES_H
#include <stdio.h>
#include "flow_features.h"
/*
Protocol numbers for TCP and UDP.
See http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
*/
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

typedef enum {
    ADDRESS, /*A or AAAA*/
    DELEGATION, /*NS, DS,...?*/
    REDIRECTION, /*CNAME, DNAME*/
    EXCHANGE, /*TXT, DNSKEY, RRSIG,...*/
    OTHER /*MX,...*/
} QTYPE;

typedef enum {
    SCORE_NORMAL = -3,
    SCORE_OUTSTANDING = 1,
    SCORE_FLAGGED = 3
} PACKET_SCORE;

typedef enum {IN, OUT} DIRECTION;

typedef enum {
	SOURCE_OK = 0,			/*Nothing abnormal*/
	SOURCE_PORT_BOUND,		/*All queries originating from the same port*/
	SOURCE_IP_SPOOFED		/*Sending query with a fake srcIP*/
} SRC_PATTERN;

typedef enum {
	SERVER_SYS_CONF = 0,	/*Server configured locally (e.g. resolv.conf)*/
	SERVER_BLACK,			/*Query sent to blacklisted IP address*/
	SERVER_UNKNOWN			/*Nameserver not in configuration, but nothing else known*/
} DST_PATTERN;

typedef enum {
	W,
	E
} DOMAIN_LABELS_PATTERN;

typedef enum {
	TTL_OK = 0,				/*Reasonable TTL in responses*/
	TTL_TOO_LOW,			/*Abnormally low TTL in responses*/
	TTL_TOO_HIGH			/*Abnormally high TTL in responses*/
} TTL_PATTERN;

typedef enum {
	REQUEST_OK = 0,			/*Nothing abnormal*/
	REQUEST_TOO_LARGE,		/*Query larger than general*/
	REQUEST_WITH_DATA		/*Data in non-Question sections of the query*/
} QUERY_PATTERN;

typedef enum {
	ANSWER_OK = 0,			/*No particularity*/
	ANSWER_TOO_LARGE,		/*Answer larger than generally observed*/
	ANSWER_TOO_UNIFORM		/*Answers consistently uniform ([mal]format, size, errors, rtt)*/
} REPLY_PATTERN;

typedef enum {
	DNS_OK = 0,				/*Packet successfully parsed as DNS*/
	DNS_PACKET_MALFORMED,	/*Malformed packet (incomplete packet, unknown RRtype/class, incompatible flags, unknown opcode)*/
	DNS_NOT_DNS				/*Maybe just raw IP data sent to the DNS port (like raw UDP...)*/
} PACKET_PATTERN;

typedef enum {
	LABELS_OK = 0,			/*Normal-looking*/
	LABELS_TOO_LARGE,		/*Too long label*/
	DOMAIN_HIGH_RATE,
	LABELS_STRANGE_ENCODING,
	LABELS_TOO_UNIFORM		/*Labels too uniform (length, pre/suffixes, number, readability)*/
} QNAME_PATTERN;

typedef struct {
	time_t refresh;
	uint8_t query_avg_rate;		/*num queries per minute*/
	uint8_t query_rate;
	uint8_t len_avg;				/*qname length*/
	uint8_t nonlc_avg_rate; /*Digits and uppercase chars*/
	uint8_t query_rate_self_variation;
	uint8_t len_self_variation;
	uint8_t nonlc_rate_self_variation;
	uint8_t query_rate_global_variation;
	uint8_t len_global_variation;
	uint8_t nonlc_rate_global_variation;
} domain_history;

#pragma pack(push)
#pragma pack(1) 
/*Feature byte*/
typedef struct {
	unsigned int f_code : 3; 	/*feature code*/
	unsigned int f_range : 3;	/*feature range: capturing continuity in a discrete variable*/
	unsigned int uniqueness : 2; /* overflowing <<2 of how many different connections exhibited the same pattern*/
} feature;
#pragma pack(pop)

/*DNS stream feature vector*/
typedef struct {
	feature src_patt;
	feature dst_info;
	feature packet_patt;
	feature query_patt;
	feature reply_patt;
	feature ttl_patt;
	feature qname_patt;
	flow_history flow_patt;
} pattern;

/*
Packet info: srcIP and dstIP used for a connection key;
pattern used to classify packets observed in the transaction/connection
*/
typedef struct {
    struct in_addr source, dest;
    pattern *patt;
} dnsPacketInfo;

/*Connection entry*/
typedef struct {
	uint16_t id;	/*Current transaction id*/
	uint16_t port;	/*Current src port*/
	uint16_t id_count; /*Number of transactions with same id*/
	uint16_t src_port_count; /*Number of transactions with same src port*/
	uint32_t transaction_count;	/*Number of transactions for the particular (srcPi, dstIP) pair*/
	pattern patt;	/*Adaptive pattern feature vector for the particular (srcPi, dstIP) pair*/
} dnsTransaction;

/**/
typedef struct {
	char *qname;
	uint32_t remote_ip;
} dnsTransactionLogWrapper;
#ifdef __cplusplus
    extern "C" {
#endif
PACKET_SCORE classify_packet(const uint8_t *data, size_t rlen, dnsPacketInfo **pkt_info, DIRECTION drtcn);
void print_flow_feature_point(const pattern *pat, FILE *fp, char *tag);
void pattern_to_point(const pattern *pat, uint64_t *arr);
void print_pattern_point(const pattern *pat, FILE *fp, char *tag);
void print_flow_feature_point(const pattern *pat, FILE *fp, char *tag);
void print_pattern(const pattern *pat, char *tag);
void dns_flow_inspect(uint8_t *payload, uint32_t payload_len, struct in_addr src_ip, 
		struct in_addr dst_ip, DIRECTION drctn, pattern* const patt);
#ifdef __cplusplus
    }
#endif  //__CPLUSPLUS
#endif  //_DNSFW_FEATURES_H
