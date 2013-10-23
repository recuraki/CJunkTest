/*
 * LinkedLIST "int list module"
 * Written by Akira KANA<kanai@sfc.wide.ad.jp>
 * $Id: llist_queue_int.c,v 1.2 2006/09/18 18:56:40 kanai Exp $
 */

#include "llist_queue.h"
#include "llist_queue_int.h"
#include "mem_mgmt.h"

int lq_int_creat_func(struct llist_queue *ptr)
{
  int *i;

  i = xalloc(sizeof(int), "lq_int");
  lq_set_data(ptr, i);

  return 0;
}

int lq_int_set_func(struct llist_queue *ptr, va_list ap)
{
  int i, *i_ptr;
  i = va_arg(ap, int);
  i_ptr = lq_get_data(ptr);
  *i_ptr = i;

  return 0;
}

int lq_int_dump_func(struct llist_queue *ptr)
{
  int *i;

  i = lq_get_data(ptr);
  printf("Int: %d\n", *i);
  return 0;
}

int lq_int_destroy_func(struct llist_queue *ptr)
{
  int *i;

  i = lq_get_data(ptr);
  xfree(i);
  return 0;
}

int lq_int_add(struct llist_queue *ptr, int data)
{
  struct llist_queue *new;

  new = lq_add_last(ptr);
  lq_do_set_func(new, data);

  return 0;
}

struct llist_queue *lq_int_find(struct llist_queue *root, int data)
{
	struct llist_queue *ptr;
  int *i;

	for(ptr = root ; !lq_is_null(ptr); ptr = lq_get_next(ptr) ){
    i = lq_get_data(ptr); 
		if(*i == data){
			return ptr;
		}
	}

	return 0;
}

int lq_int_count(struct llist_queue *root, int data)
{
  struct llist_queue *ptr_next;
  struct llist_queue *ptr_next_next;

  ptr_next = lq_int_find(root, data);
  if(lq_is_null(ptr_next))
  {
    return(0);
  }
  ptr_next_next = lq_get_next(ptr_next);
  return(1 + lq_int_count(ptr_next_next, data));
}

