#include <stdio.h>
#include <stdlib.h>
#include "init.h"
#include "proc.h"
#include "clean.h"

int main(){

	s_pkt_gl *pkt_gl = pkt_init();
	
	if (!pkt_gl ){        
		printf("[INIT ERROR]\n");
		exit(-1);
	}
	
	pkt_proc(pkt_gl); //如果在处理的时候突然崩了的话，pkt_gl没有释放资源，很危险的啊！
	
	clean(pkt_gl);
    
    return 0;
	
}
