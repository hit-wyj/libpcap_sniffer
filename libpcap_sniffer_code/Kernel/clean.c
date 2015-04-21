//
//  clean.c
//  libpcap_sniffer
//
//  Created by 王益静 on 15/4/21.
//  Copyright (c) 2015年 王益静. All rights reserved.
//

#include <stdlib.h>
#include "clean.h"
#include "pkt.h"

void clean (s_pkt_gl * pkt_gl){
    
    if (!pkt_gl) {
        return;
    }
    
    if (pkt_gl->pcap_path){
        free(pkt_gl->pcap_path);
    }
    
    if (pkt_gl->ht){
        free(pkt_gl->ht);
    }
    
    free(pkt_gl);
}