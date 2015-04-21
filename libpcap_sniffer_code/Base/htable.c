/**
 * @file htable.c
 * @author dufei@nismail.iie.ac.cn
 * @version 3.1.121117
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "htable.h"

/*
 Credit for primes table: Aaron Krowne
 http://br.endernet.org/~akrowne;http://planetmath.org/encyclopedia/GoodHashTablePrimes.html
*/
static const unsigned int primes[] = {
	53, 97, 193, 389,769, 1543, 3079, 6151,12289, 24593, 49157, 98317,	196613, 393241, 786433, 1572869,
	3145739, 6291469, 12582917, 25165843,50331653, 100663319, 201326611, 402653189,805306457, 1610612741
};
static const unsigned int prime_htable_length = sizeof(primes)/sizeof(primes[0]);
static const float max_load_factor = 0.918;

static void _tfree(void *it)
{
	free(it);
}

static unsigned int _thash (void *it)
{
	return (unsigned long)it;
}

static int _tcmp(void *pairA,void *pairB)
{
	return (unsigned long)pairA-(unsigned long)pairB;
}
/**************************************************************************************************/
htable_t * htable_create(unsigned int tablelen,unsigned int nodesize,void (*t_free)(void *),
							   unsigned int (*t_hash) (void*),int (*t_cmp) (void*,void*))
{
	htable_t *ht=NULL;
    unsigned int pindex, size;
    int ptr_len;	
    size = primes[0];
    ptr_len = sizeof(void *);	
	
	if(nodesize<=ptr_len){
		printf("[error]:Struct size is too small..\n");
		return NULL;
	}
	tablelen= tablelen/max_load_factor +1;
	/* Check requested hashtable isn'ht too large */
	if(tablelen > (1u << 30)) return NULL;
	/* Enforce size as prime */
    for(pindex=0; pindex < prime_htable_length; pindex++) {
        if (primes[pindex] > tablelen) { size = primes[pindex]; break; }
    }
	ht = (htable_t *)calloc(1,sizeof(htable_t));
    if (NULL == ht) return NULL; 	

	ht->table =(void **)calloc(size,sizeof(void *));
	if (NULL == ht->table) return NULL; 

	ht->tablelen = size;
    ht->offset = nodesize - ptr_len;
    ht->_free = t_free?t_free:_tfree;
    ht->_hash = t_hash?t_hash:_thash;
    ht->_cmp = t_cmp?t_cmp:_tcmp;

    ht->nodecount = 0;    
    ht->primeindex = pindex;    
	ht->loadlimit = size * max_load_factor+1;	

	return ht;
}

/**************************************************************************************************/
void htable_init(htable_t *ht)
{
	if(!ht) return;

	int i;
	void *cur, *alter;
	
	for (i = 0; i < ht->tablelen; i++)
	{
	    cur = ht->table[i];
	    while (NULL != cur){ 
	        alter = cur; 
			cur = (void *)*(unsigned long *)(cur+ht->offset);
			ht->_free(alter); 
		}
	}
    memset(ht->table, 0, ht->tablelen * sizeof(void *));
	ht->nodecount = 0;
}
/**************************************************************************************************/
unsigned int htable_count(htable_t *ht)
{
	if(!ht)return -1;
	
    return ht->nodecount;
}

/**************************************************************************************************/
int htable_insert(htable_t *ht, void *it)
{
	if(!ht)return -1;

	unsigned int index; 

	ht->nodecount += 1;
	index = ht->_hash(it)%ht->tablelen;
	*(unsigned long *)(it+ht->offset)  = (unsigned long)ht->table[index];
    ht->table[index] = it;
    
    return 0;
}
/**************************************************************************************************/
int htable_remove(htable_t *ht, void *it)
{
	if(!ht)return -1;
	
	void *cur=NULL, **pE=NULL; 	
    unsigned int index;
	
    index=ht->_hash(it)%ht->tablelen;	
    pE = &(ht->table[index]);
    cur = *pE;
    while (NULL != cur)
    {
        if (0==ht->_cmp(it,cur)){
            *pE = (void *)*(unsigned long *)(cur+ht->offset);
            ht->nodecount--;
            ht->_free(cur);
			cur=NULL;//add for array
            return 0;
        }
        pE = cur+ht->offset;
		cur = (void *)*(unsigned long *)(cur+ht->offset);
    }
    return 1;
}

/**************************************************************************************************/
void * htable_search(htable_t *ht, void *it)
{
	if(!ht)return NULL;
	
	void *cur=NULL;
    unsigned int index;

	index = ht->_hash(it)%ht->tablelen;
	cur = ht->table[index];
    while (NULL != cur){
		if (0==ht->_cmp(it, cur)) return cur;
        cur = (void *)*(unsigned long *)(cur+ht->offset);
	}
	return NULL;
}

/**************************************************************************************************/
void htable_free(htable_t *ht)
{
	if(!ht)return; 

    unsigned int i;
    void *cur=NULL, *alter=NULL;
	
	for (i = 0; i < ht->tablelen && ht->nodecount>0; i++)
    {
        cur = ht->table[i];
        while (NULL != cur){ 
        	alter = cur; 
			cur = (void *)*(unsigned long *)(cur+ht->offset);
			ht->_free(alter); 
			ht->nodecount --;
	    }
    }
	free(ht->table);
	free(ht);
}

/**************************************************************************************************/
void htable_traverse(htable_t *ht,void (*_handle)(void *,void *),void *param)
{
	if(!ht) return;
	
	int i;
   	void *cur=NULL,*rover=NULL;
	unsigned int node_count;	
 	
	node_count = ht->nodecount;
	for(i = 0; i < ht->tablelen && node_count>0; i++)
    {
    	rover = ht->table[i];
		while (NULL != rover)
		{
			cur=rover;			
		    rover = (void *)*(unsigned long *)(rover+ht->offset);
			_handle(cur,param);
			node_count --;
		}
	}
}

/*end of file*/


