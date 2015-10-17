#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns_printer.h"
#include "dns_parse.h"

/*
Descriptions for DNS OPCODES
See http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
*/
char *opcode_str(uint32_t opcode)
{
    switch(opcode)
    {
        case 0:return "QUERY";
        case 2:return "STATUS";
        case 4:return "NOTIFY";
        case 5:return "UPDATE";
        default:return "Unassigned";
    }
}

/*
Descriptions for DNS RCODES
See http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml 
*/
char *rcode_str(uint16_t rcode, uint8_t tsig)
{
    switch(rcode)
    {
        case 0:return "NOERROR";
        case 1:return "FORMERR";
        case 2:return "SERVFAIL";
        case 3:return "NXDOMAIN";
        case 4:return "NOTIMP";
        case 5:return "REFUSED";
        case 6:return "YXDOMAIN";
        case 7:return "YXRRSET";
        case 8:return "NXRRSET";
        case 9:return "NOTAUTH";
        case 10:
        return "NOTZONE";
        /*This is weird: according to RFC's 6891 and 2845. But why 16 for both BADVERS and BADSIG (a TSIG ERROR) */
        case 16:
        {
            if(tsig){
                return "BADSIG";
            }else{
                return "BADVERS";
            }
        }
        case 17:return "BADKEY";
        case 18:return "BADTIME";
        case 19:return "BADMODE";
        case 21:return "BADALG";
        case 22:return "BADTRUNC";
        case 23:return "BADCOOKIE";
        default:return "Res/Not-Assigned";
    }
}

/*
Descriptions for DNS (RR) classes
See http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml 
*/
char *rclass_str(uint16_t rclass)
{
    switch(rclass)
    {
        case 1:return "IN";
        case 3:return "CH";
        case 4:return "HS";
        case 254:return "NONE";
        case 255:return "ANY";
        default:return "Non-Standard";
    }
}

/*
Descriptions for most common DNS (RR) types
See http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml 
*/
char *rtype_str(uint16_t rtype)
{
    switch(rtype)
    {
        case RR_TYPE_A:return "A";
        case RR_TYPE_NS:return "NS";
        case RR_TYPE_CNAME:return "CNAME";
        case RR_TYPE_SOA:return "SOA";
        case RR_TYPE_PTR:return "PTR";
        case RR_TYPE_MX:return "MX";
        case RR_TYPE_TXT:return "TXT";
        case RR_TYPE_SIG:return "SIG";
        case RR_TYPE_KEY:return "KEY";
        case RR_TYPE_AAAA:return "AAAA";
        case RR_TYPE_SRV:return "SRV";
        case RR_TYPE_OPT:return "OPT";
        case RR_TYPE_DS:return "DS";
        case RR_TYPE_SSHFP:return "SSHFP";
        case RR_TYPE_IPSECKEY:return "IPSECKEY";
        case RR_TYPE_RRSIG:return "RRSIG";
        case RR_TYPE_NSEC:return "NSEC";
        case RR_TYPE_DNSKEY:return "DNSKEY";
        case RR_TYPE_NSEC3:return "NSEC3";
        case RR_TYPE_NSEC3PARAM:return "NSEC3PARAM";
        case RR_TYPE_TLSA:return "TLSA";
        case RR_TYPE_SPF:return "SPF";
        case RR_TYPE_TKEY:return "TKEY";
        case RR_TYPE_TSIG:return "TSIG";
        case RR_TYPE_AXFR:return "AXFR";
        case RR_TYPE_URI:return "URI";
        case RR_TYPE_DLV:return "DLV";
        default:return "OTHER";
    }
}

/*
Print RRSet in dig format.
*/
void print_rrset(const dns_rr* rr_list, char *label)
{
    const dns_rr *rr = rr_list;
    printf(";; %s SECTION:\n", label);
    while(rr != NULL)
    {
        if(rr->rtype == RR_TYPE_OPT){
            printf(";; META-RR (OPT-pseudosection):\n; EDNS: %s version: %d, flags: %s; udp: %d\n%s\n", "", (rr->ttl >> 16) & 0x0ff, ((rr->ttl>> 15) && 0x1)? "do":"",
             rr->rclass, rr->rdata?rdata_str(rr->rdata, rr->rtype):"[EMPTY]");
        }else{
            printf("%s\t\t%d\t%s\t%s\t%s\n", rr->name, rr->ttl, rclass_str(rr->rclass), rtype_str(rr->rtype), rr->rdata?rdata_str(rr->rdata, rr->rtype):"[EMPTY]");
        }
        rr = rr->next;
    }
}

/*
Print DNS RDATA (either a domain name, an IP[v4|v6] address, or a base64-encoded text?
*/
char *rdata_str(char *rdata, uint16_t rtype)
{
    switch(rtype)
    {
        case RR_TYPE_CNAME:
        case RR_TYPE_DNAME:
        case RR_TYPE_NS:
            return rdata;
        case RR_TYPE_A:
        {
            uint8_t *ipv4 = (uint8_t*)rdata;
            char tmp[16];
            snprintf(tmp, 16, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
            tmp[15] = '\0';
            return strdup(tmp);
        }
        case RR_TYPE_AAAA:
        {
            uint16_t *ipv6 = (uint16_t*)rdata;
            char tmp[40];
            snprintf(tmp, 32, "%x:%x:%x:%x:%x:%x:%x:%x", ntohs(ipv6[0]), ntohs(ipv6[1]), ntohs(ipv6[2]), ntohs(ipv6[3]), ntohs(ipv6[4]), ntohs(ipv6[5]), ntohs(ipv6[6]), ntohs(ipv6[7]));
             tmp[39] = '\0';
            return strdup(tmp);
        }
        case RR_TYPE_RRSIG:
            return rrsig_str(rdata, rtype);
        case RR_TYPE_OPT:

        default:
            return rdata;    
    }
}

char *rrsig_str(char *rdata, uint16_t rtype)
{
    return "NOT-IMPL";
}

/*
Print DNS header
*/
void print_header(const dns_hdr *h, uint32_t opt_flags)
{
    uint16_t flags = ntohs(h->flags);
    uint16_t extended_rcode;
    /*[RFC2671] expands the RCODE space from 4 bits to 12 bits.
    The 8 upper bits of the extended RCODE come from upper 8 bits of the OPT RR's ttl*/
    extended_rcode = ((opt_flags >> 20) & 0x0ff0) | (flags & DNS_FLAGS_RCODE);
    uint8_t do_flag = (opt_flags>> 15) && 0x1;
    printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n", opcode_str(flags & DNS_FLAGS_OPCODE), rcode_str(extended_rcode, 0), ntohs(h->id));
    printf(";; flags:%s%s%s%s%s%s%s%s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
        (flags & DNS_FLAGS_QR)?" qr":"", (flags & DNS_FLAGS_AA)?" aa":"", (flags & DNS_FLAGS_TC)?" tc":"",
        (flags & DNS_FLAGS_RD)?" rd":"", (flags & DNS_FLAGS_RA)?" ra":"", (flags & DNS_FLAGS_AD)?" ad":"",
        (flags & DNS_FLAGS_CD)?" cd":"", do_flag?" do(from meta-RR)":"", ntohs(h->qdcount), ntohs(h->ancount), ntohs(h->nscount), ntohs(h->arcount));
}

/*
Print DNS packet
*/
void print_dns(const dns_packet *pkt)
{
    printf("\n_______________\n");
    print_header(pkt->header, pkt->opt_flags);
    print_rrset(pkt->questions, "QUESTIONS");
    print_rrset(pkt->answers, "ANSWER");
    print_rrset(pkt->authority, "AUTHORITY");
    print_rrset(pkt->additional, "ADDITIONAL");
    printf("\n_______________\n");
}
