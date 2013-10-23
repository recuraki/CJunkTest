/*
 * Backdoor
 */

#include "backdoor.h"
#include "backdoor_lq.h"
#include "llist_queue.h"
#include "llist_queue_int.h"
#include "mem_mgmt.h"


void xconsole_init_term(int sd)
{
  struct termios  term;

  /* Init Teminal Info */
  memset(&xconsole_ti[sd], 0, sizeof(struct terminal_info));
  xconsole_ti[sd].sd = sd;  

  /* Init Terminal */
  tcgetattr(sd, &orig_term[sd]);
  memcpy(&term, &orig_term[sd], sizeof(term));
  // term.c_lflag &= !(ICANON | ECHO);
  term.c_lflag &= !(ICANON);
  term.c_lflag &= !(ECHO);
  term.c_lflag &= !(ECHOCTL);
  tcsetattr(sd, TCSANOW, &term);
}


void xconsole_init_shell(void)
{
  int i;

  /* Clear All Command Structure */
  for(i = 0; i < MAX_SOCKET_NUM; i++)
  {
    xconsole_clear_cmd_line_cur(i);
  }

  /* Create Command Root Node */
  cmd_root = lq_creat(xconsole_cmd_creat_func,
		      xconsole_cmd_set_func,
		      xconsole_cmd_dump_func,
		      xconsole_cmd_destroy_func);
}


void xconsole_clear_cmd_line_cur(int sd)
{
  xconsole_ti[sd].cmd_cursor = 0;
  memset(xconsole_ti[sd].cmd_buffer, 0, MAX_CMD_LEN);
}

char *xconsole_parse_command(char *s)
{
  char *c;

  for(c = s; *c != 0x00; c++)
    {
      if(*c == ' ' || *c == '\n')
	{
	  return(c);
	}
    }

  return(c);
}


char *xconsole_get_cmd_name_by_level(char *cmd_name, int level)
{
  char *c, *cp;
  int i;
  c = cmd_name;
  cp = cmd_name;

  for(i = 0; i < (level); i++)
    { 
      c = xconsole_parse_command(cp);
      if(*c == 0x00)
	{
	  fprintf(stderr, "xconsole_add_command: end\n");
	  return(0);
	}
      *c = 0x00;
       cp = c + 1;
    }

  return cp;
}


int xconsole_is_last_command(struct command_set *command_info, int level)
{
  char cur_name[MAX_CMD_LEN];

  strncpy(cur_name, command_info->name, strlen(command_info->name));

  if(xconsole_get_cmd_name_by_level(cur_name, level) == 0)
    {
      return(0);
    }

  return(1);
}


int xconsole_do_command(int sd, struct llist_queue *cmd_root, char *cmd, int level)
{
  char *c, *cp;
  char cur_name[MAX_CMD_LEN];
  struct llist_queue *cmd_node;
  struct command_set *cmd_ptr;
  int cmd_count;

  memset(cur_name, 0x00, MAX_CMD_LEN);
  strncpy(cur_name, cmd, strlen(cmd));
  if( (c = xconsole_get_cmd_name_by_level(cur_name, level) ) == 0)
    {
      return(0);
    }
  cp = xconsole_parse_command(cur_name);
  *cp = 0x00;

  printf("Do[%s]\n", c);

  cmd_count = xconsole_cmd_count(cmd_root, c);
  if(cmd_count > 1)
    { /* Much Over 2 Commands */
      printf("Over 2 Commands Muched\n");
      return(-1);
    }
  if( (cmd_node = xconsole_cmd_find(cmd_root, c)) != 0)
    { /* Find */
      cmd_ptr = cmd_node->data;
      if( xconsole_do_command(sd, cmd_ptr->next_arg, cmd, level + 1) == 0)
	{ /* Last Command */
	  if(cmd_ptr->cmd != 0)
	    { /* Do Command */
	      cmd_ptr->cmd(sd);
	    }
	}
      return(1);
    }
  else
    { /* no such as command */
      printf("No Such As Command\n");
      return(0);
    }
}


int xconsole_add_command(struct llist_queue *cmd_root, struct command_set *command_info, int level)
{
  char *c;
  char *cp;
  char cur_name[MAX_CMD_LEN];
  struct command_set new_cmd;
  struct llist_queue *cmd_node;
  struct llist_queue *new_cmd_root;
  struct command_set *cmd_ptr;

  printf("add func proc[%s] To [%x]\n", command_info->name, (int)cmd_root);


  strncpy(cur_name, command_info->name, strlen(command_info->name));
  if( (c = xconsole_get_cmd_name_by_level(cur_name, level) ) == 0)
    {
      return(0);
    }
  cp = xconsole_parse_command(cur_name);
  *cp = 0x00;

  if( (cmd_node = xconsole_cmd_find(cmd_root, c)) == 0)
    { /* Cannot Find Node  */
      cmd_node = lq_add_last(cmd_root);
      memcpy(&new_cmd, command_info, sizeof(struct command_set));
      memset(new_cmd.name ,0x00, MAX_CMD_LEN);
      new_cmd.next_arg = 0;
      new_cmd.cmd = 0;
      strncpy(new_cmd.name, c, strlen(c));
      lq_do_set_func(cmd_node, new_cmd);
      printf("Create to %x\n", (int)cmd_root);

    }
  else
    { /* Can Find Node */
    }

  if(xconsole_is_last_command(command_info, level + 1) == 0)
    { /* Last Command */
      cmd_ptr = cmd_node->data;
      cmd_ptr->cmd = command_info->cmd;
    }
  else
    { /* Continue */
      cmd_ptr = cmd_node->data;

      if(cmd_ptr->next_arg == 0x00)
	{
	  new_cmd_root = lq_creat(xconsole_cmd_creat_func,
				  xconsole_cmd_set_func,
				  xconsole_cmd_dump_func,
				  xconsole_cmd_destroy_func);

	  cmd_ptr->next_arg = new_cmd_root;
	}
      xconsole_add_command(new_cmd_root, command_info, level + 1);
    } 
  return(1);
}


void xconsole_exit_func(int sd)
{
  tcsetattr(0, TCSANOW, &orig_term[sd]);

  exit(0);
}


void xconsole_delete_current_char(int sd)
{
  if( xconsole_ti[sd].cmd_cursor == 0){
    return;
  }
  fputc(CONTROL('H'), stdout);
  fputc(' ', stdout);
  fputc(CONTROL('H'), stdout);
  xconsole_ti[sd].cmd_cursor--;
}


void xconsole_do_tab(int sd)
{
  printf("<TAB>\n");
}


void xconsole_do_enter(int sd)
{
	/* "\n" */
  write(sd, "\n", 1);

  /* Terminate */
  xconsole_ti[sd].cmd_buffer[xconsole_ti[sd].cmd_cursor] = 0x00;
  printf("\n");

  /* Debug Print */
  printf("Command was entered: %s\n",  xconsole_ti[sd].cmd_buffer);

  /* Do func */
  xconsole_do_command(sd, cmd_root, xconsole_ti[sd].cmd_buffer, 0);  

  /* Clear Current Command Line */
  xconsole_clear_cmd_line_cur(sd);
}


int xconsole_read(int in_sd, char ch)
{
  switch(ch)
    {
    case CONTROL('K'): // Ctl + K
      break;
#if 0
    case CONTROL('C'): // Ctl + C
      xconsole_exit_func(in_sd);
      break;
#endif
    case 0x7f: // DEL
    case 0x08: // BS
      xconsole_delete_current_char(in_sd);
      break;

    case 0x09: // Tab
    case 0x3f: // '?'
      xconsole_do_tab(in_sd);
      break;

		case 0x0d: // \r
			break;

    case 0x0a: // Enter
      xconsole_do_enter(in_sd);
      break;

    default:
      xconsole_ti[in_sd].cmd_buffer[xconsole_ti[in_sd].cmd_cursor] = ch;
      xconsole_ti[in_sd].cmd_cursor++;
      write(in_sd, &ch, 1);
      break;

    }

  return(0);
}
