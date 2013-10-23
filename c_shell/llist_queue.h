/*
	Linked List Queue
	$Id: llist_queue.h,v 1.4 2006/09/18 10:22:41 kanai Exp $
*/
#ifndef _LLIST_QUEUE_H_
#define _LLIST_QUEUE_H_ 

/* Header */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* Structure */
struct llist_queue{
	struct llist_queue *prev;
	struct llist_queue *next;
	void *data;
  int (*creat_func)(struct llist_queue *ptr);
  int (*set_func)(struct llist_queue *ptr, va_list ap);
  int (*dump_func)(struct llist_queue *ptr);
  int (*destroy_func)(struct llist_queue *ptr);
};

/* Define Function */
void lq_set_creat_func(struct llist_queue *ptr, int (*creat_func)(struct llist_queue *ptr));
void lq_set_set_func(struct llist_queue *ptr, int (*set_func)(struct llist_queue *ptr, va_list ap));
void lq_set_dump_func(struct llist_queue *ptr, int (*dump_func)(struct llist_queue *ptr));
void lq_set_destroy_func(struct llist_queue *ptr, int (*destroy_func)(struct llist_queue *ptr));
int (*lq_get_creat_func(struct llist_queue *ptr))();
int (*lq_get_set_func(struct llist_queue *ptr))();
int (*lq_get_dump_func(struct llist_queue *ptr))();
int (*lq_get_destroy_func(struct llist_queue *ptr))();
int lq_do_creat_func(struct llist_queue *ptr);
int lq_do_set_func(struct llist_queue *ptr, ...);
int lq_do_dump_func(struct llist_queue *ptr);
int lq_do_destroy_func(struct llist_queue *ptr);
int lq_do_func(int (*func)(), struct llist_queue *ptr);
void lq_set_data(struct llist_queue *ptr, void *data);
void *lq_get_data(struct llist_queue *ptr);
void lq_init(struct llist_queue *root);
void lq_set_next(struct llist_queue *ptr, struct llist_queue *next);
void lq_set_prev(struct llist_queue *ptr, struct llist_queue *prev);
struct llist_queue *lq_get_next(struct llist_queue *ptr);
struct llist_queue *lq_get_prev(struct llist_queue *ptr);
int lq_is_null(struct llist_queue *ptr);
int lq_cmp(struct llist_queue *ptr1, struct llist_queue *ptr2);
struct llist_queue *lq_creat(int (*creat_func)(struct llist_queue *ptr), int (*set_func)(struct llist_queue *ptr, va_list ap), int (*dump_func)(struct llist_queue *ptr), int (*destroy_dunc)(struct llist_queue *ptr));
struct llist_queue *lq_add_first(struct llist_queue *root);
struct llist_queue *lq_add_last(struct llist_queue *root);
void lq_delete_ptr(struct llist_queue *root, struct llist_queue *ptr);
void lq_dump(struct llist_queue *root);

#endif /* _LLIST_QUEUE_H_ */
