
#ifndef __PKT_H__
#define __PKT_H__

#include <arpa/inet.h>
#include "htable.h"

#define MAX_LINE_LEN 20
#define HT_ELEMENT_NUM 2000
#define DIFF_SECOND_NUM 180

enum _e_file_mode_{
    
    e_file_online = 1,
    e_file_offline = 2
    
};

typedef struct _s_pkt_global_{
    
	int pkt_src_mod;
	char *dev;
	char *log_file;
    char *pcap_path;
    htable_t *ht;
    time_t loop_s_time;
    int loop_cnt;
    
}s_pkt_gl;

typedef struct _s_ip_ele_global_{

    struct sockaddr_in ip_ele;
    int ip_cnt;
    struct s_ip_ele_gl * next;
    
}s_ip_ele_gl;


struct my_ip_header {
    
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    in_addr_t ip_src, ip_dst; /* source and dest address */
    
};

#endif
