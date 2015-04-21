/**
 * @file htable.h
 * @author dufei@nismail.iie.ac.cn
 * @version 3.1.121117
 */

#ifndef __HTABLE_H__
#define __HTABLE_H__



typedef struct _htable {
    unsigned int tablelen;
    void **table;
    unsigned int offset;
	
    void (*_free)(void *);
    unsigned int (*_hash) (void *);
    int (*_cmp) (void *, void *);
	
	unsigned int nodecount;
    unsigned int loadlimit;
    unsigned int primeindex;
}htable_t;

/***************************************exported functions*****************************************/

/*
 * Create a array from heap space and return the pointer.
 * tablelen:	minimum initial length of hashtable
 * nodesize:	size of struct in hashtable
 * t_free:		function for free struct
 * t_hash:		function for hashing
 * t_cmp:		function for determining struct equality:if equality return 0 else return ~0
 */
htable_t * htable_create(unsigned int tablelen,unsigned int nodesize,void (*t_free)(void *),
             				unsigned int (*t_hash) (void*),int (*t_cmp) (void*,void*));
                 

void htable_init(htable_t *ht); 

unsigned int htable_count(htable_t *ht);                

/*
 * return:	0  succeed
 *		   -1  ht is null
 */
int htable_insert(htable_t *ht,void *it);

/*
 * return:	0  succeed
 *			1  deletion failed
 *		   -1  ht is null
 */
int htable_remove(htable_t *ht, void *it);

void * htable_search(htable_t *ht, void *it);

void htable_free(htable_t *ht);

/*
 * traverse a array and handle each element.
 * ht:		the pointer of hashtable
 * _handle:	function for computing
 * param:	the pointer of second param in callback 
 */
void htable_traverse(htable_t *ht,void (*_handle)(void *,void *),void *param);

#endif /* __HTABLE_H__ */


