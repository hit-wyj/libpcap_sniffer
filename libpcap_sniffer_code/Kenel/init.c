#include <stdio.h>
#include <stdlib.h>

#include "init.h"
#include "pkt.h"

static u_int ip_hash(void * value){
    
    s_ip_ele_gl *v = (s_ip_ele_gl *)value;
    return (v->ip_ele.sin_addr.s_addr % HT_ELEMENT_NUM);
    
}

static int ip_hash_cmp(void *value1, void *value2){

    s_ip_ele_gl *v1 = (s_ip_ele_gl *)value1;
    s_ip_ele_gl *v2 = (s_ip_ele_gl *)value2;
    return (v1->ip_ele.sin_addr.s_addr == v2->ip_ele.sin_addr.s_addr)? 1 : 0;
    
}

static void ip_free(void *value){
    free(value);
}

static void gl_htable_init(s_pkt_gl *s_pk_gl){
    s_pk_gl->ht = htable_create(HT_ELEMENT_NUM, sizeof(s_ip_ele_gl), ip_free ,ip_hash, ip_hash_cmp);
    
    
}

static void read_config(s_pkt_gl * s_pk_gl){
    FILE *fp;
    char lineBuffer[MAX_LINE_LEN];
    if ((fp = fopen("./Config/mode.config", "r")) == NULL){
        printf("Init Config File Error !\n");
        exit(-1);
    }
    while (fgets(lineBuffer, MAX_LINE_LEN, fp) != (char *) NULL) {
        if (!strpbrk("#", lineBuffer)) {
//            if (<#condition#>) {
//                <#statements#>
//            }
        }
    }
    fclose(fp);
}

void* pkt_init(){

	s_pkt_gl *s_pk_gl = (s_pkt_gl *)malloc(sizeof(s_pkt_gl));
	
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	
	dev = pcap_lookupdev(errbuf);
	
	if(dev == NULL){
		printf("%s\n",errbuf);
		return NULL;
	}
	
	s_pk_gl->dev = dev;
    
    return s_pk_gl;

}
