#ifndef __PROC_H__
#define __PROC_H__
 
#include "pkt.h"

void tcp_pkt_proc(const u_char * packet);
void udp_pkt_proc(const u_char *packet);
void pkt_callback(u_char *args,	const struct pcap_pkthdr *pkthdr, const u_char *packet);
void pkt_proc(s_pkt_gl* pkt_gl);

#endif




