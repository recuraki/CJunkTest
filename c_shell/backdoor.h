#ifndef _BACKDOOR_H_
#define _BACKDOOR_H_

#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include "llist_queue.h"

#define MAX_CMD_LEN 1024
#define MAX_DESC_LEN 1024
#define MAX_SOCKET_NUM 1024


struct terminal_info{
  int sd;
  char cmd_buffer[MAX_CMD_LEN];
  int cmd_cursor;
};

struct command_set{
  char name[MAX_CMD_LEN];
  char desc[MAX_DESC_LEN];
  int (*cmd)();
  struct llist_queue *next_arg;
};

struct llist_queue *cmd_root;
struct terminal_info xconsole_ti[MAX_SOCKET_NUM];
struct termios orig_term[MAX_SOCKET_NUM];

#define CONTROL(_KEY) (_KEY - '@')

#ifndef MAX
#define MAX(a,b) (a > b ? a : b)
#endif /* MAX */
#ifndef MIN
#define MIN(a,b) (a < b ? a : b)
#endif /* MIN */


#define DEFINE_COMMAND(_CMD_FUNC, _CMD_NAME, _CMD_LINE, _DESC) \
  int _CMD_FUNC(int sd, int argc, char **argv); \
  struct command_set _CMD_NAME = { \
    _CMD_LINE, \
    _DESC, \
    _CMD_FUNC, \
    0 \
  };\
  int _CMD_FUNC(int sd, int argc, char **argv)

void xconsole_init_term(int sd);
void xconsole_init_shell(void);
void xconsole_clear_cmd_line_cur(int sd);
char *xconsole_parse_command(char *s);
char *xconsole_get_cmd_name_by_level(char *cmd_name, int level);
int xconsole_is_last_command(struct command_set *command_info, int level);
int xconsole_do_command(int sd, struct llist_queue *cmd_root, char *cmd, int level);
int xconsole_add_command(struct llist_queue *cmd_root, struct command_set *command_info, int level);
void xconsole_exit_func(int sd);
void xconsole_delete_current_char(int sd);
void xconsole_do_tab(int sd);
void xconsole_do_enter(int sd);
int xconsole_read(int in_sd, char ch);

#endif /* _BACKDOOR_H_ */
