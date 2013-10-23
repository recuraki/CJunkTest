/*
 * Backdoor Console lq lib Header
 */

#ifndef _BACKDOOR_LQ_H_
#define _BACKDOOR_LQ_H_

#include "backdoor.h"
#include "llist_queue.h"

int xconsole_cmd_creat_func(struct llist_queue *ptr);
int xconsole_cmd_set_func(struct llist_queue *ptr, va_list ap);
int xconsole_cmd_dump_func(struct llist_queue *ptr);
int xconsole_cmd_destroy_func(struct llist_queue *ptr);
int xconsole_cmd_add(struct llist_queue *ptr, struct command_set data);
struct llist_queue *xconsole_cmd_find(struct llist_queue *root, char *data);
struct llist_queue *xconsole_cmd_find_with_level(struct llist_queue *root, char *data, int level);
int xconsole_cmd_count(struct llist_queue *root, char *data);


#endif /* _BACKDOOR_LQ_H_ */
