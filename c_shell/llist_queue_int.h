/*
 * LinkedLIST "int list module"
 * Written by Akira KANAI<kanai@sfc.wide.ad.jp>
 * $Id: llist_queue_int.h,v 1.2 2006/09/18 18:56:40 kanai Exp $
 */

#ifndef _LLIST_QUEUE_INT_H_
#define _LLIST_QUEUE_INT_H_

/* Header */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "llist_queue.h"


/* Define */
struct llist_queue *lq_int_find(struct llist_queue *root, int data);
int lq_int_count(struct llist_queue *root, int data);
int lq_int_creat_func(struct llist_queue *ptr);
int lq_int_set_func(struct llist_queue *ptr, va_list ap);
int lq_int_dump_func(struct llist_queue *ptr);
int lq_int_destroy_func(struct llist_queue *ptr);
int lq_int_add(struct llist_queue *ptr, int data);

#endif /* _LLIST_QUEUE_INT_H_ */
