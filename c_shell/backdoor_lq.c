/*
 * Backdoor Linked List Control
 * Written by Akira KANAI<kanai@sfc.wide.ad.jp>
 * $Id
 */

#include "main.h"
#include "llist_queue.h"
#include "llist_queue_int.h"
#include "backdoor.h"
#include "mem_mgmt.h"

/*
 *
 * LQ Func 
 *
 */
int xconsole_cmd_creat_func(struct llist_queue *ptr)
{
  struct command_set *cmd;

  cmd = xalloc(sizeof(struct command_set), "commad_set");
  lq_set_data(ptr, cmd);

  return 0;
}

int xconsole_cmd_set_func(struct llist_queue *ptr, va_list ap)
{
  struct command_set cmd, *cmd_ptr;

  cmd = va_arg(ap, struct command_set);
  cmd_ptr = lq_get_data(ptr);
  *cmd_ptr = cmd;

  return 0;
}

int xconsole_cmd_dump_func(struct llist_queue *ptr)
{
  struct command_set  *cmd;

  cmd = lq_get_data(ptr);
  printf("[%s] func=%x nexrarg=%x\n",
	 cmd->name,
	 (int)cmd->cmd,
	 (int)cmd->next_arg);
  return 0;
}

int xconsole_cmd_destroy_func(struct llist_queue *ptr)
{
  int *cmd;

  cmd = lq_get_data(ptr);
  xfree(cmd);
  return 0;
}



int xconsole_cmd_add(struct llist_queue *ptr, struct command_set data)
{
  struct llist_queue *new;

  new = lq_add_last(ptr);
  lq_do_set_func(new, data);

  return 0;
}

/*
 * 
 * LQ Manu funcs 
 *
 */

struct llist_queue *console_create_cmd_root(void)
{
  return(0);
}

struct llist_queue *xconsole_cmd_find(struct llist_queue *root, char *data)
{
  struct llist_queue *ptr;
  struct command_set *cmd_ptr;

  for(ptr = root ; !lq_is_null(ptr); ptr = lq_get_next(ptr) )
    {
      cmd_ptr = lq_get_data(ptr); 
      if( strncmp(cmd_ptr->name, data, strlen(data))  == 0){
	return ptr;
      }
    }

  return 0;
}

struct llist_queue *xconsole_cmd_find_with_level(struct llist_queue *root, char *data, int level)
{
  struct llist_queue *ptr;
  struct command_set *cmd_ptr;
  char ptr_name[MAX_CMD_LEN];
  char *ptr_cmd_ptr;
  char *cp;

  for(ptr = root ; !lq_is_null(ptr); ptr = lq_get_next(ptr) )
    {
      cmd_ptr = lq_get_data(ptr); 

      strncpy(ptr_name, cmd_ptr->name, strlen(cmd_ptr->name));
      if( (ptr_cmd_ptr = xconsole_get_cmd_name_by_level(cmd_ptr->name, level) ) == 0)
	{
	  return(0);
	}
      cp = xconsole_parse_command(ptr_cmd_ptr);
      *cp = 0x00;

      printf("CMP[%s][%s]\n", data,ptr_cmd_ptr);

      if(strncmp(ptr_cmd_ptr, data, strlen(data)) == 0 ){
	return ptr;
      }
    }

  return 0;
}

int xconsole_cmd_count(struct llist_queue *root, char *data)
{
  struct llist_queue *ptr_next;
  struct llist_queue *ptr_next_next;

  ptr_next = xconsole_cmd_find(root, data);
  if(lq_is_null(ptr_next))
    {
      return(0);
    }
  ptr_next_next = lq_get_next(ptr_next);
  return(1 + xconsole_cmd_count(ptr_next_next, data));
}
