#ifndef _DNSFW_PARSE_H
#define _DNSFW_PARSE_H

#define MAX_LABEL_LENGTH 63 /*Maximum length for a label */
#define MAX_NAME_LENGTH 255 /*Maximum length for a name */
#define MAX_POINTERS 100 /*Not sure how many pointer resolutions are allowed in DNS message compression*/
#define MIN_RR_SIZE 10 /*Minimum holder for a RR's params, supposing an empty name and rdata*/
#define MIN_QUESTION_SIZE 6 /*Minimum holder for a question's params, supposing an empty name*/

/*
DNS flags.
*/
#define DNS_FLAGS_QR 0x8000
#define DNS_FLAGS_OPCODE 0x7800
#define DNS_FLAGS_AA 0x0400
#define DNS_FLAGS_TC 0x0200
#define DNS_FLAGS_RD 0x0100
#define DNS_FLAGS_RA 0x0080
#define DNS_FLAGS_RESERVED 0x0040
#define DNS_FLAGS_AD 0x0020
#define DNS_FLAGS_CD 0x0010
#define DNS_FLAGS_RCODE 0x000f


/*Popular DNS RR types*/
enum rr_type {
    RR_TYPE_A = 1,
    RR_TYPE_NS = 2,
    RR_TYPE_CNAME = 5,
    RR_TYPE_SOA = 6,
    RR_TYPE_PTR = 12,
    RR_TYPE_MX = 15,
    RR_TYPE_TXT = 16,
    RR_TYPE_SIG = 24,
    RR_TYPE_KEY = 25,
    RR_TYPE_AAAA = 28,
    RR_TYPE_SRV = 33,
    RR_TYPE_NAPTR = 35,
    RR_TYPE_DNAME = 39,
    RR_TYPE_OPT = 41,
    RR_TYPE_DS = 43,
    RR_TYPE_SSHFP = 44,
    RR_TYPE_IPSECKEY = 45,
    RR_TYPE_RRSIG = 46,
    RR_TYPE_NSEC = 47,
    RR_TYPE_DNSKEY = 48,
    RR_TYPE_NSEC3 = 50,
    RR_TYPE_NSEC3PARAM = 51,
    RR_TYPE_TLSA = 52,
    RR_TYPE_SPF = 99,
    RR_TYPE_TKEY = 249,
    RR_TYPE_TSIG = 250,
    RR_TYPE_AXFR = 252,
    RR_TYPE_ANY = 255,
    RR_TYPE_URI = 256,
    RR_TYPE_TA = 32768,
    RR_TYPE_DLV = 32769
};

typedef enum {
	parse_ok = 0,			/*Packet parsed successfully*/
	parse_malformed = 1,	/*Extracting DNS info failed*/
	parse_not_dns = 2,		/*not so DNS-looking*/
	parse_incomplete = 4,	/*Packet end reached before parsing ended*/
	parse_msg_unknown = 8,	/*Unknown opCode, RRtype, RRclass, or flags combination*/
	parse_memory_error = 16	/*Memory allocation failed?*/
} dns_parse_errors;

/*
This structure would describe a DNS question.
However, for simplicity, a question is just like a normal RR with an empty rdata and pointless ttl.
*/
typedef struct _q_{
    char *qname;
    uint16_t qtype;
    uint16_t qclass;
    struct _q_ *next;
} dns_question;

typedef struct _rr_{
    char *name;
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    uint16_t rdlength;
    char *rdata;
    struct _rr_ *next;
} dns_rr;

//#pragma pack(push)  /* push current alignment to stack */
//#pragma pack(1)     /* set alignment to 1 byte boundary */
typedef struct {
    unsigned int id : 16;
    unsigned int flags : 16;
    unsigned int qdcount : 16;
    unsigned int ancount : 16;
    unsigned int nscount : 16;
    unsigned int arcount : 16;
} dns_hdr;
//#pragma pack(pop)   /* restore original alignment from stack */

typedef struct {
    uint32_t opt_flags; /*for EDNS, OPT-pseudorecord's extended RCODE and flags*/
    dns_hdr *header;
    dns_rr *questions; /*We treat questions as normal RRs, with an empty RDATA and 0 ttl*/
    dns_rr *answers;
    dns_rr *authority;
    dns_rr *additional;
} dns_packet;

typedef struct flow{
    dns_packet *msg;
    long timestamp;
    long rtt;
    struct flow *next;
} dns_flow;

/*
Parse DNS packet from wire data
*/
dns_parse_errors dns_parse(const uint8_t *wiredata, uint32_t len, dns_packet **pkt);

#endif
