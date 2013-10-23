/*
   Memory Managment
   Written by Akira KANAI<kanai@sfc.wide.ad.jp>
   $Id: mem_mgmt.h,v 1.2 2006/09/18 18:56:41 kanai Exp $
*/
#ifndef _MEM_MGMT_H_
#define _MEM_MGMT_H_

#ifdef MEM_MGMT_DISP
#else /* MEM_MGMT_DISP */
#endif /* MEM_MGMT_DISP */

/* Includes */
#include <stdlib.h>
#include "llist_queue.h"

/* public */
struct llist_queue *mem_mgmt_root;

#define XMEM_MGMT_MAX_FILENAME 64
#define XMEM_MGMT_MAX_PURPOSE 32

/* Structs */
struct xmem_mgmt_data
{
  size_t size;
  char purpose[XMEM_MGMT_MAX_PURPOSE];
  char filename[XMEM_MGMT_MAX_FILENAME];
  void *addr;
  int line;
};

int mem_mgmt_lq_creat_func(struct llist_queue *ptr);
int mem_mgmt_lq_set_func(struct llist_queue *ptr, va_list ap);
int mem_mgmt_lq_dump_func(struct llist_queue *ptr);
int mem_mgmt_lq_destroy_func(struct llist_queue *ptr);
int mem_mgmt_lq_add(struct llist_queue *ptr, struct xmem_mgmt_data mgmt_data);
struct llist_queue *mem_mgmt_lq_find(struct llist_queue *root, void *addr);

void xmem_mgmt(void);
void *Xalloc(size_t size, const char *purpose, const char *filename, int line);
void xfree(void *ptr);
void xdump();

/* Defines */
#define xalloc(X, Y) Xalloc(X, Y, __FILE__, __LINE__)

#endif /* _MEM_MGMT_H_ */
