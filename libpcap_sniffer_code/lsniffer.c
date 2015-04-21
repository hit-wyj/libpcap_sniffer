#include <stdio.h>
#include <stdlib.h>
#include "init.h"
#include "proc.h"

int main(){

	s_pkt_gl *s_pk_gl = pkt_init();
	
	if(!s_pk_gl){
		printf("[INIT ERROR]\n");
		exit(1);
	}
	
	pkt_proc(s_pk_gl);
	
	free(s_pk_gl);
	
}
