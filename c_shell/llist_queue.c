/*
 * LinkedLIST.c
 * Written by Akira KANAI<kanai@sfc.wide.ad.jp>
 * $Id: llist_queue.c,v 1.5 2006/09/18 18:56:40 kanai Exp $
 */

#include "llist_queue.h"
#include "mem_mgmt.h"

/*
 *
 * Manu Struct
 *
 */

void lq_set_creat_func(struct llist_queue *ptr, int (*creat_func)(struct llist_queue *ptr))
{
  ptr->creat_func = creat_func;
}

void lq_set_set_func(struct llist_queue *ptr, int (*set_func)(struct llist_queue *ptr, va_list ap))
{
  ptr->set_func = set_func;
}

void lq_set_dump_func(struct llist_queue *ptr, int (*dump_func)(struct llist_queue *ptr))
{
  ptr->dump_func = dump_func;
}

void lq_set_destroy_func(struct llist_queue *ptr, int (*destroy_func)(struct llist_queue *ptr))
{
  ptr->destroy_func = destroy_func;
}

int (*lq_get_creat_func(struct llist_queue *ptr))()
{
  return ptr->creat_func;
}

int (*lq_get_set_func(struct llist_queue *ptr))()
{
  return ptr->set_func;
}

int (*lq_get_dump_func(struct llist_queue *ptr))()
{
  return ptr->dump_func;
}

int (*lq_get_destroy_func(struct llist_queue *ptr))()
{
  return ptr->destroy_func;
}

int lq_do_creat_func(struct llist_queue *ptr)
{
  return lq_do_func(ptr->creat_func, ptr);
}

int lq_do_set_func(struct llist_queue *ptr, ...)
{
  int ret;
  va_list ap;

  va_start(ap, ptr);
  ret = ptr->set_func(ptr, ap);
  va_end(ap);

  return ret;
}

int lq_do_dump_func(struct llist_queue *ptr)
{
  return lq_do_func(ptr->dump_func, ptr);
}

int lq_do_destroy_func(struct llist_queue *ptr)
{
  return lq_do_func(ptr->destroy_func, ptr);
}

int lq_do_func(int (*func)(), struct llist_queue *ptr)
{
  if(func == 0)
  {
    /* Undefine */
    return 0;
  }
  /* Do */
  return func(ptr);
}

void lq_set_data(struct llist_queue *ptr, void *data)
{
  ptr->data = data;
}

void *lq_get_data(struct llist_queue *ptr)
{
  return ptr->data;
}

void lq_init(struct llist_queue *root)
{
	memset(root, 0, sizeof(struct llist_queue));
}

void lq_set_next(struct llist_queue *ptr, struct llist_queue *next)
{
  ptr->next = next;
}

void lq_set_prev(struct llist_queue *ptr, struct llist_queue *prev)
{
  ptr->prev = prev;
}

struct llist_queue *lq_get_next(struct llist_queue *ptr)
{
  return ptr->next;
}

struct llist_queue *lq_get_prev(struct llist_queue *ptr)
{
  return ptr->prev;
}

int lq_is_null(struct llist_queue *ptr)
{
  return(ptr == 0);
}

int lq_cmp(struct llist_queue *ptr1, struct llist_queue *ptr2)
{
  return(ptr1 == ptr2);
}

/*
 *
 * Main
 *
 */

struct llist_queue *lq_creat(int (*creat_func)(struct llist_queue *ptr), int (*set_func)(struct llist_queue *ptr, va_list ap), int (*dump_func)(struct llist_queue *ptr), int (*destroy_dunc)(struct llist_queue *ptr))
{
  struct llist_queue *new;

  new = xalloc(sizeof(struct llist_queue), "llist_queue");
  lq_init(new);
  lq_set_creat_func(new, creat_func);
  lq_set_set_func(new, set_func);
  lq_set_dump_func(new, dump_func);
  lq_set_destroy_func(new, destroy_dunc);
  lq_do_creat_func(new);
  return(new);
}

struct llist_queue *lq_add_first(struct llist_queue *root)
{
	struct llist_queue *new;
	struct llist_queue *next;

	new = lq_creat(root->creat_func, root->set_func, root->dump_func, root->destroy_func);
  next = lq_get_next(root);

	if(!lq_is_null(next))
  {
		lq_set_next(new, next);
		lq_set_prev(next, new);
	}
  else /* First Node */
  {
    lq_set_next(new, 0);
    lq_set_prev(root, new);
    lq_set_prev(new, root);
  }
	lq_set_next(root, new);

  return new;
}

struct llist_queue *lq_add_last(struct llist_queue *root)
{
	struct llist_queue *new;
	struct llist_queue *next;
	struct llist_queue *prev;

	new = lq_creat(root->creat_func, root->set_func, root->dump_func, root->destroy_func);

  next = lq_get_next(root);
  prev = lq_get_prev(root);

	if(lq_is_null(next))
  { /* first node */
		lq_set_next(root, new);
		lq_set_next(new, 0);
	  lq_set_prev(new, root);
		lq_set_prev(root, new);
	}
  else
  {
		lq_set_prev(root, new);
		lq_set_prev(new, prev);
		lq_set_next(prev, new);
	}

  return new;
}

void lq_delete_ptr(struct llist_queue *root, struct llist_queue *ptr)
{
	struct llist_queue *root_prev;
	struct llist_queue *root_next;
	struct llist_queue *ptr_prev;
	struct llist_queue *ptr_next;

  root_prev = lq_get_prev(root);
  root_next = lq_get_next(root);
  ptr_prev = lq_get_prev(ptr);
  ptr_next = lq_get_next(ptr);

  /* if erase root_node */
  if(lq_cmp(ptr, root))
  {
    fprintf(stderr, "ROOTNOOOOOOD\n");
    return;
  }

  lq_set_next(ptr_prev, ptr_next);
  if(lq_cmp(ptr, root_prev))
  { /* If will delete lastnode */
    if(lq_cmp(ptr, root_next))
    { /* If will delete LAST 1 NODE */
      lq_set_prev(root, 0);
    }
    else
    {
      lq_set_prev(root, ptr_prev);
    }
  }
  else
  { /* delete normal node */
    lq_set_next(ptr->prev, ptr->next);
    lq_set_prev(ptr->next, ptr->prev);
  }

	lq_do_destroy_func(ptr);
  xfree(ptr);
}

void lq_dump(struct llist_queue *root)
{
	struct llist_queue *ptr;
	
	fprintf(stderr, "LLIST_QUEUE_INT_DUMP:BEGIN\n");

	ptr = lq_get_next(root);

	for(;ptr != 0; ptr = lq_get_next(ptr))
  {
		fprintf(stderr, "LLIST_QUEUE_INT_DUMP[%x]-next:%x\n",
        (int)ptr, (int)lq_get_next(ptr));

    lq_do_dump_func(ptr);
	}

	fprintf(stderr, "LLIST_QUEUE_INT_DUMP:END\n");
}
