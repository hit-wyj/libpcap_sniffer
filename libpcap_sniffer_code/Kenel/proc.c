
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "proc.h"


/**
 *  handle the tcp and udp package, for they have the same struct
 */

void tcp_udp_pkt_proc(const struct tcphdr * tcph){
        //TODO
}
static void echo_htable(s_pkt_gl * pkt_gl){
    
    htable_t * ht = pkt_gl->ht;
    s_ip_ele_gl * ip_ele_sr_tmp;
    
    if (!ht){
        printf("HTable is Empty \n");
        return;
    }
    
    printf("***********This is the %d loop************\n", pkt_gl->loop_cnt);
    int i;
    for (i = 0; i < ht->tablelen; i++) {
        ip_ele_sr_tmp = (s_ip_ele_gl *)ht->table[i];
        while (NULL != ip_ele_sr_tmp) {
            ip_ele_sr_tmp = (s_ip_ele_gl *)*(unsigned long *)(ip_ele_sr_tmp + ht->offset);
            printf("IP is:%s\t The Count is:%d\n", inet_ntoa(ip_ele_sr_tmp->ip_ele.sin_addr),ip_ele_sr_tmp->ip_cnt);
        }
    }
    
}

void pkt_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet){

    s_pkt_gl *pkt_gl = (s_pkt_gl *)args;
    struct my_ip_header *iph = (struct my_ip_header*)(packet + sizeof(struct ether_header));
    struct sockaddr_in source;
    struct sockaddr_in dest;
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->ip_src;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->ip_dst;
    s_ip_ele_gl  ip_ele_tmp;
    ip_ele_tmp.ip_ele = source;
    time_t now_time;
    switch (pkt_gl->pkt_src_mod) {
        case e_file_online:{
            if( time(&now_time) - time(&(pkt_gl->loop_s_time)) > DIFF_SECOND_NUM){
                pkt_gl->loop_s_time = now_time;
                pkt_gl->loop_cnt++;
                htable_init(pkt_gl->ht);
                echo_htable(pkt_gl);
            }
            break;
        }
        default:
            break;
    }
    
    s_ip_ele_gl * ip_ele_sr1 = htable_search(pkt_gl->ht, &ip_ele_tmp);
    if (!ip_ele_sr1) {
        ip_ele_sr1 = (s_ip_ele_gl *)malloc(sizeof(s_ip_ele_gl));
        ip_ele_sr1->ip_ele = source;
        ip_ele_sr1->ip_cnt = 1;
        htable_insert(pkt_gl->ht, ip_ele_sr1);
    }else{
         ip_ele_sr1->ip_cnt++;
    }
    
    ip_ele_tmp.ip_ele = dest;
    s_ip_ele_gl * ip_ele_sr2 = htable_search(pkt_gl->ht, &ip_ele_tmp);
    if (ip_ele_sr2) {
        ip_ele_sr2 = (s_ip_ele_gl *)malloc(sizeof(s_ip_ele_gl));
        ip_ele_sr2->ip_ele = source;
        ip_ele_sr2->ip_cnt = 1;
        htable_insert(pkt_gl->ht, ip_ele_sr2);
    }else{
        ip_ele_sr2->ip_cnt++;
    }
}

void pkt_proc(s_pkt_gl* pkt_gl){
	
	pcap_t* descr;
	char errbuf[PCAP_ERRBUF_SIZE];
    
    switch (pkt_gl->pkt_src_mod) {
        case e_file_offline:
            descr = pcap_open_offline(pkt_gl->dev, pkt_gl->pcap_path);
            break;
        case e_file_online:
            descr = pcap_open_live(pkt_gl->dev,BUFSIZ,0,-1,errbuf);
            break;
        default:
            printf("Config file error !/n");
            return;
    }

	if(descr == NULL){ 
		printf("pcap_open_live(): %s/n",errbuf); 
		return;
	}
    
	pcap_loop(descr, -1 , pkt_callback , (u_char *)pkt_gl);
    
    if (pkt_gl->pkt_src_mod == e_file_offline) {//主要是为了离线模式下的最后输出
        echo_htable(pkt_gl);
    }
    
}
