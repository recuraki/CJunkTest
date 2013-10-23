/*
 * Memory Managment
 * Written by Akira KANAI<kanai@sfc.wide.ad.jp>
 *  $Id: mem_mgmt.c,v 1.2 2006/09/18 18:56:41 kanai Exp $
 */

#include "mem_mgmt.h"
#include "llist_queue.h"

#ifdef MEM_MGMT

struct llist_queue *mem_mgmt_lq_add_last(struct llist_queue *root)
{
  struct llist_queue *new;
  struct llist_queue *next;
  struct llist_queue *prev;

  new = malloc(sizeof(struct llist_queue));
  memset(new, 0, sizeof(struct llist_queue));
  /*
  mgmt_data = malloc(sizeof(struct xmem_mgmt_data));
  new->data =  mgmt_data;
  */

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

void mem_mgmt_lq_delete_ptr(struct llist_queue *root, struct llist_queue *ptr)
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

}


void xmem_mgmt(void)
{
  struct xmem_mgmt_data *mgmt_data;

  mem_mgmt_root = malloc(sizeof(struct llist_queue));
  memset(mem_mgmt_root, 0, sizeof(struct llist_queue));

  mgmt_data = malloc(sizeof(struct xmem_mgmt_data));
  mem_mgmt_root->data =  mgmt_data;
}

void *Xalloc(size_t size, const char *purpose, const char *filename, int line)
{
  struct xmem_mgmt_data *mgmt_data;
  struct llist_queue *new;
  void *addr;

#ifdef MEM_MGMT_DISP
  fprintf(stderr, "MEM_MGMT: malloc request[size %d] at %s(line:%d)\n", size, filename, line);
#endif /* MEM_MGMT_DISP*/

  addr = malloc(size);
  mgmt_data = malloc(sizeof(struct xmem_mgmt_data));

  mgmt_data->size = size;
  mgmt_data->line = line;
  mgmt_data->addr = addr;
  strncpy(mgmt_data->filename, filename, XMEM_MGMT_MAX_FILENAME);
  strncpy(mgmt_data->purpose, purpose, XMEM_MGMT_MAX_PURPOSE);

  new = mem_mgmt_lq_add_last(mem_mgmt_root);
  new->data = mgmt_data;

  return(addr);
}

void xfree(void *ptr)
{
  fflush(stdout);
  struct llist_queue *lq_ptr;
  struct xmem_mgmt_data *mgmt_data;

#ifdef MEM_MGMT_DISP
  fprintf(stderr, "MEM_MGMT: free request[%x]\n", (int)ptr);
#endif /* MEM_MGMT_DISP*/

  lq_ptr = lq_get_next(mem_mgmt_root);

  for(;lq_ptr != 0; lq_ptr = lq_get_next(lq_ptr))
  {
    mgmt_data = (struct xmem_mgmt_data *)lq_get_data(lq_ptr);
    if(ptr == mgmt_data->addr)
    {
      free(lq_ptr->data);
      mem_mgmt_lq_delete_ptr(mem_mgmt_root, lq_ptr);
      free(ptr);
      return;
    }

  }

  fprintf(stderr, "CATION: cannot find memory\n");
  exit(1);
}

void xdump()
{
  struct llist_queue *ptr;
  struct xmem_mgmt_data *mgmt_data;

  fprintf(stderr, "XMEM_MGMT_DUMP_BEGIN\n");

  ptr = lq_get_next(mem_mgmt_root);

  for(;ptr != 0; ptr = lq_get_next(ptr))
  {
    mgmt_data = (struct xmem_mgmt_data *)lq_get_data(ptr);
    printf("[%x(%d)] allocated %s by %s(line:%d)\n",
        (int)mgmt_data->addr,
        mgmt_data->size,
        mgmt_data->purpose,
        mgmt_data->filename,
        mgmt_data->line);
  }

  fprintf(stderr, "XMEM_MGMT_DUMP_END\n");
}

#else
void xmem_mgmt(void) { }
void *Xalloc(size_t size, const char *purpose, const char *filename, int line) { return(malloc(size)); }
void xfree(void *ptr) { free(ptr); }
void xdump() { }
#endif /* MEM_MGMT */
