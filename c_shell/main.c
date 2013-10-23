#include <sys/types.h>
#include <sys/uio.h>
#include <stdio.h>
#include <unistd.h>
#include <unistd.h>
#include <termios.h>

#include "backdoor.h"
#include "mem_mgmt.h"


DEFINE_COMMAND(show_hoge,
    show_hoge_info,
    "show hoge",
    "Show Data\n"
    "Test String Display\n")
{
  write(sd, "hoge\n", 5);

  return(0);
}

DEFINE_COMMAND(show_version,
    show_version_info,
    "show version",
    "Show Version\n"
    "Display Version\n")
{
  write(sd, "Version\n", 8);

  return(0);
}

DEFINE_COMMAND(show_memory,
    show_memory_info,
    "show memory",
    "Show Memory\n"
    "Display Memory\n")
{
  xdump();

  return(0);
}

DEFINE_COMMAND(exit_cmd,
	       exit_cmd_info,
	       "exit",
	       "Exit From Program\n"
	       "Exit From Program\n")
{
  exit(1);
}

int main(int argc, char **argv)
{
  char            ch;
  int in_sd;

  xmem_mgmt();

#if 0
  struct llist_queue *root_node;
  int *p1, *p2;
  p1 = xalloc(sizeof(int), "int");
  p2 = xalloc(sizeof(int), "int");
  xfree(p1);
  xfree(p2);
  p1 = xalloc(sizeof(int), "int");
  root_node = lq_creat(lq_int_creat_func, lq_int_set_func, lq_int_dump_func, lq_int_destroy_func);
  lq_int_add(root_node, 10);
  lq_int_add(root_node, 20);
  lq_int_add(root_node, 30);
  lq_delete_ptr(root_node, lq_int_find(root_node,20));
  xdump();
#endif

  xconsole_init_shell();
  xconsole_init_term(0);
  in_sd = 0;

  xconsole_add_command(cmd_root, &show_hoge_info, 0);
  xconsole_add_command(cmd_root, &show_version_info, 0);
  xconsole_add_command(cmd_root, &show_memory_info, 0);
  xconsole_add_command(cmd_root, &exit_cmd_info, 0);

  while(read(0, &ch, 1) > 0)
    {
      xconsole_read(in_sd, ch);
    }

  /* NOTREACHED */
  return(0);
}
