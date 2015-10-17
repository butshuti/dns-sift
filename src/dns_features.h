#ifndef _DNSFW_FEATURES_H
#define _DNSFW_FEATURES_H

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
    TRUE = 1,
    FALSE = 0
} BOOL;

typedef enum {
    OUT, IN
} direction;

typedef enum {
    NEW,        /*Previously unseen*/
    FREQUENT,   /*Seen more frequently*/
    POPULAR,    /*Known service endpoint (servers, search engine, proxy,...)*/
    BLACK,      /*Explicitly blacklisted*/
    NEGATIVE    /*Possibly tainted*/
} REPUTATION_SCORE;

typedef enum {
    ENCODING_STANDARD = 0,  /*Fullsense cleartext*/
    ENCODING_COMPRESSED, /*Compressed*/
    ENCODING_BASE64,    /*Or alternative acceptable encoding*/
    ENCODING_CRYPTO,    /*Successfully parse as either KEY, SIG, ...*/
    ENCODING_UNKNOWN    /*Obscure/unknown encoding*/
} ENCODING_TYPE;

typedef enum {
    PENDING,        /*Not yet seen/analyzed*/
    NORMAL,         /*Does not stand out*/
    BADFORMAT,      /*Malformatted reply*/
    PREDICTABLE,    /*Either repeatedly the same or negative*/
    IRRELEVANT      /*Same reply for too many different requests?*/
} REPLY_PATTERN_CATEGORY;

typedef struct {
    uint32_t packet_len;
    uint32_t protocol;
    uint32_t ttl;
    struct in_addr source, dest;
    unsigned short int sport, dport;
    char *qname, *cname, *dname, *ns;
    uint32_t flags;
    QTYPE qtype;
} dnsPacketInfo;

#pragma pack(push)
#pragma pack(1)     
typedef struct {
    uint32_t ttl;                               /*How large TTL in the reply*/
    uint16_t cname_len,                         /*Length of the query name*/
    labels_count,                               /*Number of labels in qname*/
    domain_freq,                                /*Frequency domain.tld was seen*/
    domain_variations,                          /*Variance in qname prefixes to domain.tld*/
    avg_request_size,                           /*Size of query packet*/
    avg_reply_size,                             /*Size of reply packet*/
    query_reply_size_ratio,                     /*just that!*/
    flags,                                      /*DNS header flags*/
    qname_entropy,                              /*What moon language is the qname?!*/
    mean_rtt;                                    /*just that!*/
    REPUTATION_SCORE reputation_score : 4;          /*see above!*/
    REPLY_PATTERN_CATEGORY answer_pattern : 4;      /*In correlation with observed patterns for the same domain queries*/  
    ENCODING_TYPE encoding_type : 3;                /*Tunnels will probably have a weird encoding*/
    BOOL resolv_conf_ns : 1,                        /*Sent to NS configured in resolv.conf?*/
        ns_badflag : 1,                             /*Sent to a badly-reputed NS?*/
        qname_badflag : 1,                          /*Querying for a badlooking domain?*/
        reply_badflag : 1,                          /*Answer pointing to tainted IPs?*/
        spoofed_src : 1;                            /*Is src_ip our IP?*/
} dnsFeatureVec;
#pragma pack(pop)

void get_packet_info(const uint8_t *data, size_t rlen, dnsPacketInfo **pkt_info);
#endif
