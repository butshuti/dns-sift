#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "dns_parse.h"
#include "logger.h"
#include "dns_printer.h"


//#define stderr_log_debug(args...) fprintf(stderr, args)
#define stderr_log_debug(args...)
#define MAX_PKT_LEN 1492

extern void reverse(char*);

/*
Read a DNS name from a packet.
Special care must be taken here for COMPRESSION.
Parameters: packet, msg_start(index of first byte of msg ID), len (length of packet), pos (current position in packet)
The allocated ret_name points to a memory that should be explicitly deallocated.
Returns a DNS parse error code
*/
char *parse_rdata(const uint8_t *packet, const uint32_t msg_start, const uint32_t len, uint32_t *pos, const uint32_t maxlen, dns_parse_errors *err_code)
{
    if(*pos >= len)
    {
        stderr_log_debug("dns_parse::parse_rdata(): will not read after packet boundary!\n");
        *err_code = parse_incomplete;
        return NULL;
    }else if(maxlen > MAX_PKT_LEN){
    	stderr_log_debug("dns_parse::parse_rdata(): packet larger than MTU!\n");
        *err_code = parse_malformed;
        return NULL;
    }
    /*Now parse the name and update the position*/
    char name[maxlen];
    memset(name, 0, maxlen);
    uint32_t offs = 0;
    uint32_t initial_offset = 0, 
        copy_offset = 0 /*offset to the last byte filled in name*/, 
        num_pointers = 0 /*Watch number of pointers*/;
    while((packet[*pos] != 0) && (offs < len) && (copy_offset < maxlen))
    {
        //printf("===========NAME SIZE: %d .... pos: %d :::: 0x%02x 0x%02x=============\n\n", copy_offset, *pos, packet[*pos], packet[*pos+1]);
        uint16_t label_size = packet[*pos];
        //printf("Label size:............%d^^^^^^^^^^^^^^\n", label_size);
        /*Handle compression: follow pointers*/
        if(label_size >= 192){
            /*
            The following are acceptable as name representations:
                (1)a sequence of labels ending with a zero octet;
                (2)a pointer;
                (3)a sequence of labels ending with a pointer.
             This algorithm assumes at most 1 pointer in the local name (other pointers may be encountered when the first one is followed),
                so the offset after the first pointer will be returned.
            */
            if(initial_offset == 0)
            {
                /*Before resolving the first pointer, save next offset as the second octet after the length byte*/
                initial_offset = *pos + 2;
            }
            uint32_t pointer_addr = ((label_size & 63) << 8) + packet[(*pos)+1];
            num_pointers++;
            if(pointer_addr == 0)
            {
                stderr_log_debug("dns_parse::parse_rdata() -- invalid (ZERO) compression pointer at byte %d: 0x%02x 0x%02x.\n", msg_start+offs, packet[*pos], packet[*pos+1]);
                *err_code = parse_malformed;
                return NULL;
            }else if(pointer_addr + msg_start > len){
                stderr_log_debug("dns_parse::parse_rdata() -- invalid (TOO HIGH) compression pointer at byte %d of %d: 0x%02x 0x%02x.\n", msg_start+offs, len, packet[*pos], packet[*pos+1]);
                *err_code = parse_malformed;
                return NULL;
            }else if(num_pointers > MAX_POINTERS){
                stderr_log_debug("dns_parse::parse_rdata() -- too many compression pointers: %d.\n", num_pointers);
                *err_code = parse_malformed;
                return NULL;
            }
            *pos = msg_start + pointer_addr;
        }else{
            (*pos)++; /*Skip the length byte*/
            /*
           Extract normal label length
            */
            int i;
            for(i=0; i<label_size; i++)
            {
                uint8_t ch = packet[(*pos)++];
                if((ch > 31) && (ch < 127))
                {
                    name[copy_offset++] = ch;
                }
            }
            name[copy_offset++] = '.';
        }
    }
    if(copy_offset == 0)
    {
        /*Root label only?*/
        name[copy_offset++] = '.';
    }
    name[copy_offset] = 0;
    if(initial_offset != 0)
    {
        /*A redirection was followed, so return end of first redirection as final offset*/
        *pos = initial_offset;
    }else{
        (*pos)++;
    }
    char *ret_name = calloc(sizeof(char), strlen(name) + 1);
    if(!(ret_name)){
    	*err_code = parse_memory_error;
    	return NULL;
    }
    memcpy(ret_name, name, strlen(name));
    *err_code = parse_ok;
    return ret_name;
}

/*
Parse DNS question from buffer, starting from pos.
Here we treat questions as normal RRs, with an empty RDATA and 0 ttl
Returns DNS parse error code.
Question parameters copied to question.
*/
dns_parse_errors parse_question(const uint8_t *packet, uint32_t len, uint32_t *pos, dns_rr **question)
{
    if((*pos)+MIN_QUESTION_SIZE >= len)
    {
        stderr_log_debug("dns_parse::parse_question(): scan position out of packet boundary: [%d + %d] of %d.\n", *pos, MIN_QUESTION_SIZE, len);
        return parse_incomplete;
    }
    *question = calloc(sizeof(dns_rr), 1);
    if(!(*question))
    {
        stderr_log_debug("dns_parse::parse_question(): malloc!\n");
        return parse_memory_error;
    }
    dns_parse_errors ret = parse_msg_unknown;
    (*question)->name = parse_rdata(packet, 0, len, pos, MAX_NAME_LENGTH, &ret);
    reverse((*question)->name);
    if(ret != parse_ok){
    	free(*question);
    	return ret;
    }
    uint16_t qtype, qclass;
    qtype = (packet[*pos] << 8) + packet[(*pos)+1];
    qclass = (packet[(*pos)+2] << 8) + packet[(*pos)+3];
    (*pos) += 4;
    (*question)->rtype = qtype;
    (*question)->rclass = qclass;
    (*question)->ttl = 0;
    (*question)->rdlength = 0;
    (*question)->rdata = NULL;
    return parse_ok;
}

/*
Parse DNS RR from buffer, starting from pos.
Returns DNS parse error code.
RR data copied to rr.
*/
dns_parse_errors parse_rr(const uint8_t *packet, uint32_t len, uint32_t *pos, dns_rr **rr)
{
    if(((*pos)+MIN_RR_SIZE) > len)/*At least the rtype, rclass, ttl, and rdlength should be parseable*/
    {
        stderr_log_debug("dns_parse::parse_rr(): scan position out of packet boundary: (%d + %d) of %d.\n", pos, MIN_RR_SIZE, len);
        return parse_incomplete;
    }
    *rr = calloc(sizeof(dns_rr), 1);
    if(!(*rr))
    {
        stderr_log_debug("dns_parse::parse_rr(): malloc!\n");
        return parse_memory_error;
    }
    dns_parse_errors err_code = parse_msg_unknown;
    (*rr)->name = parse_rdata(packet, 0, len, pos, MAX_NAME_LENGTH, &err_code);
    if(err_code != parse_ok){
        free(*rr);
    	return err_code;
    }
    uint16_t rtype, rclass, rdlength;
    uint32_t ttl;
    rtype = (packet[*pos] << 8) + packet[(*pos)+1];
    rclass = (packet[(*pos)+2] << 8) + packet[(*pos)+3];
    ttl = (packet[(*pos)+4] << 24) + (packet[(*pos)+5] << 16) + (packet[(*pos)+6] << 8) + packet[(*pos)+7];
    rdlength = (packet[(*pos)+8] << 8) + packet[(*pos)+9];
    (*pos) += 10;
    (*rr)->rtype = rtype;
    (*rr)->rclass = rclass;
    (*rr)->ttl = ttl;
    (*rr)->rdlength = rdlength;
    /*
    Extract rdata. Remaining packet buffer must be at least rdlength.
    */
    if(((*pos) + (*rr)->rdlength) > len)
    {
        stderr_log_debug("dns_parse::parse_rr(): rdlength---scan position out of packet boundary: (%d + 0x%02x) of %d.\n", *pos, (*rr)->rdlength, len);
        stderr_log_debug("dns_parse::parse_rr(): rtype: 0x%02x, rclass: 0x%02x, ttl: 0x%02x\n", (*rr)->rtype, (*rr)->rclass, (*rr)->ttl);
        return parse_incomplete;
    }
    if(((*rr)->rtype == RR_TYPE_CNAME) || ((*rr)->rtype == RR_TYPE_DNAME) || ((*rr)->rtype == RR_TYPE_NS))
    {
        uint32_t temp_pos = *pos;
        (*rr)->rdata = parse_rdata(packet, 0, len, &temp_pos, MAX_NAME_LENGTH, &err_code);
        if(err_code != parse_ok){
		    free(*rr);
			return err_code;
		}
        (*pos) += (*rr)->rdlength;
    }else{
        (*rr)->rdata = calloc((*rr)->rdlength, 1);
        if((*rr)->rdata == NULL)
        {
            stderr_log_debug("dns_parse::parse_rr(): malloc!\n");
            return parse_memory_error;
        }
        memcpy((*rr)->rdata, packet+(*pos), (*rr)->rdlength);
        (*pos) += (*rr)->rdlength;
    }
    //printf("-----------------------rdlength: %d-----------------------\n", (*rr)->rdlength);
    return parse_ok;
}

/*
Extract section from packet buffer, parsing and filling in all RRs in section.
New buffer position placed in pos.
Returns DNS parse error code
*/
dns_parse_errors extract_section(uint32_t(*parse_funct)(const uint8_t*, uint32_t, uint32_t*, dns_rr**), 
    const uint8_t *packet, uint32_t len, uint32_t* pos, uint16_t num_rrs, dns_rr **rr)
{
    dns_rr *cur_rr = NULL, *prev_rr = NULL;
    uint32_t idx;
    for(idx=0; idx<num_rrs; idx++)
    {
        dns_parse_errors err_code = parse_funct(packet, len, pos, &cur_rr);
        if(err_code != parse_ok){
        	return err_code;
        }
        //stderr_log_debug("idx %d of %d: POS: %d = %p\n", idx, num_rrs, pos, cur_rr);
        if(prev_rr == NULL)
        {
            (*rr) = cur_rr;
            prev_rr = cur_rr;
        }else{
            prev_rr->next = cur_rr;
            prev_rr = cur_rr;
        }
    }
    return parse_ok;
}

/*
Parse DNS packet...
*/
dns_parse_errors dns_parse(const uint8_t *wiredata, uint32_t len, dns_packet **pkt)
{
	dns_parse_errors err_code = parse_msg_unknown;
    *pkt = calloc(sizeof(dns_packet), 1);
    if(!(*pkt))
    {
        return parse_memory_error;
    }
    (*pkt)->opt_flags = 0; /*To be filled from the OPT-pseudorecord's ttl*/
    (*pkt)->header = (dns_hdr*)wiredata;
    /*Rejecting queries qith multiple questions for now.*/
	if(ntohs((*pkt)->header->qdcount) > 1){
    	return parse_malformed;
    }
    uint32_t pos = sizeof(dns_hdr);
    //stderr_log_debug("\n================ID: 0x%02x ; Questions: %hu ; Answers: %hu ; Authority: %hu ; Additional: %hu =====================\n", 
    //        ntohs((*pkt)->header->id), ntohs((*pkt)->header->qdcount), ntohs((*pkt)->header->ancount), ntohs((*pkt)->header->nscount), ntohs((*pkt)->header->arcount));
    /*
    Extract questions.
    The RFC places no limit on the number of questions per query, though specified as "usually 1", 
    and none of the major DNS server libraries currently seem to support qdcount>1 (BIND, DjbDNS, MSDNS)...
    Go ahead and parse them anyway...just in case!
    */
    err_code = extract_section(parse_question, wiredata, len, &pos, ntohs((*pkt)->header->qdcount), &((*pkt)->questions));
    if(err_code != parse_ok){
    	return err_code;
    }
    /*
    Extract answers, if any.
    */
    if((ntohs((*pkt)->header->ancount) > 0) && (pos < len))
    {
        err_code = extract_section(parse_rr, wiredata, len, &pos, ntohs((*pkt)->header->ancount), &((*pkt)->answers));
        if(err_code != parse_ok){
			return err_code;
    	}
    }
    /*
    Extract authority RRs, if any.
    */
    if((ntohs((*pkt)->header->nscount) > 0) && (pos < len))
    {
        err_code = extract_section(parse_rr, wiredata, len, &pos, ntohs((*pkt)->header->nscount), &((*pkt)->authority));
        if(err_code != parse_ok){
			return err_code;
		}
    }
    
    /*
    Extract additional RRs, if any.
    */
    if((ntohs((*pkt)->header->arcount) > 0) && (pos < len))
    {
        err_code = extract_section(parse_rr, wiredata, len, &pos, ntohs((*pkt)->header->arcount), &((*pkt)->additional));
        if(err_code != parse_ok){
			return err_code;
		}
        dns_rr *rr = (*pkt)->additional;
        while(rr != NULL){
            if(rr->rtype == RR_TYPE_OPT){
                (*pkt)->opt_flags = rr->ttl;
                break;
            }
            rr = rr->next;
        }
    }
    if(pos > len)
    {
        stderr_log_debug("dns_parse::dns_parse(): position index out of packet size limit...Overflow?\n");
        return parse_malformed;
    }
    //print_dns(*pkt);
    return err_code;
}
