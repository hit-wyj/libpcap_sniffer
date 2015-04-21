#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "init.h"
#include "pkt.h"

static u_int ip_hash(void * value){
    
    s_ip_ele_gl *v = (s_ip_ele_gl *)value;
    return (v->ip_ele.sin_addr.s_addr % HT_ELEMENT_NUM);
    
}

static int ip_hash_cmp(void *value1, void *value2){

    s_ip_ele_gl *v1 = (s_ip_ele_gl *)value1;
    s_ip_ele_gl *v2 = (s_ip_ele_gl *)value2;
    return (v1->ip_ele.sin_addr.s_addr == v2->ip_ele.sin_addr.s_addr) ? 1 : 0;
    
}

static void ip_free(void *value){
    free(value);
}

static void gl_htable_init(s_pkt_gl *pkt_gl){
    pkt_gl->ht = htable_create(HT_ELEMENT_NUM, sizeof(s_ip_ele_gl), ip_free ,ip_hash, ip_hash_cmp);
    
    
}

static void read_config(s_pkt_gl *pkt_gl){
    
    FILE *fp;
    char lineBuffer[MAX_LINE_LEN];
    
    if ((fp = fopen("./Config/mode.config", "r")) == NULL){
        printf("Init Config File Error !\n");
        exit(-1);
    }
    
    while (fgets(lineBuffer, MAX_LINE_LEN, fp) != (char *) NULL) {
        
        if (!strpbrk("#", lineBuffer)) {//说明不是注释行
            if (strstr("ONLINE", lineBuffer)) {
                pkt_gl->pkt_src_mod = 1;
            }else if (strstr("OFFLINE", lineBuffer)){
                pkt_gl->pkt_src_mod = 2;
            }else if (strstr("FILEPATH", lineBuffer)){
                pkt_gl->pcap_path = (char *)malloc(PCAP_FILE_PATH_LEN);
                memcpy(pkt_gl->pcap_path, strstr("=",lineBuffer), PCAP_FILE_PATH_LEN);
            }
        }
        
    }
    fclose(fp);
    
}

/**
 *  初始化的入口函数，主要初始化s_pkt_gl的网卡设备编号、htable、处理模式以及离线路径等
 */
void* pkt_init(){

	s_pkt_gl *pkt_gl = (s_pkt_gl *)malloc(sizeof(s_pkt_gl));
    
    pkt_gl->loop_s_time = time((time_t *)NULL);
    
    read_config(pkt_gl);
	
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	
	dev = pcap_lookupdev(errbuf);
	
	if (dev == NULL){
		printf("%s\n",errbuf);
		return NULL;
	}
	
	pkt_gl->dev = "em2"; //暂时写死
    
    return pkt_gl;

}
