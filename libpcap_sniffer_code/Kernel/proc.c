
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
 *  输出htable中的统计数据信息，对应ip地址以及出现的次数
 */

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


/**
 *  每个数据包的回调处理函数，对所有数据包利用htable进行统计分析
 */

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
    if (!pkt_gl->pkt_src_mod && (time(&now_time) - time(&(pkt_gl->loop_s_time)) > DIFF_SECOND_NUM)){
        pkt_gl->loop_s_time = now_time;
        pkt_gl->loop_cnt++;
        echo_htable(pkt_gl);
        htable_init(pkt_gl->ht);
    }
    
    /**
      * 底下的代码重复度太高了，需要重构，但是一时没好的方案
      */
    
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

/**
 *  程序的核心处理流程入口，主要解决根据模式的选择就行抓包，并对抓包进行统计分析
 */

void pkt_proc(s_pkt_gl* pkt_gl){
	
	pcap_t* descr;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pkt_gl->pkt_src_mod ? (descr = pcap_open_offline(pkt_gl->dev, pkt_gl->pcap_path)) : (descr = pcap_open_live(pkt_gl->dev,BUFSIZ,0,-1,errbuf));

	if(descr == NULL){ 
		printf("pcap_open_live(): %s/n",errbuf); 
		return;
	}
    
	pcap_loop(descr, -1 , pkt_callback , (u_char *)pkt_gl);
    
    pkt_gl->pkt_src_mod ? (echo_htable(pkt_gl)) : 0;
    
}
