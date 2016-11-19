#include <cstdint>
#include <sys/types.h>
#include <netinet/ip.h>
#include "../src/dns/dns_features.h"
#include "../src/dns/flow_track.h"
#include "../src/dns/flow_features.h"
#include <iostream>

using namespace std; 

int main(){
	dnsTransaction *cur_t;
	struct	in_addr src_ip, dst_ip;
   uint16_t src_port = 345, dst_port=53;
   size_t rlen = 100;
	cur_t = (dnsTransaction *)malloc(sizeof(dnsTransaction));
	int i;
	for(i=0; i<20; i++){
		model_downlink_flow_features(&(cur_t->patt.flow_patt), src_ip.s_addr, dst_ip.s_addr, src_port, dst_port, rlen);
		model_uplink_flow_features(&(cur_t->patt.flow_patt), src_ip.s_addr, dst_ip.s_addr, src_port, dst_port, rlen);
		cout<<i<<"-QR: "<<cur_t->patt.flow_patt.flow_query_rate<<endl;
	}
	return 0;
}
