#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/telnet.h>
#include <netdb.h>
#include <termios.h>

#define PORT 10000

#include "backdoor.h"
#include "mem_mgmt.h"


DEFINE_COMMAND(show_hoge,
	       show_hoge_info,
	       "show hoge",
	       "Show Data\n"
	       "Test String Display\n")
{
printf("Called sd %d\n", sd);
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


int main(int argv, char **argc){
  int ad;
  int sd;
  int len;
  int csin_len;
  int nodelay_buf;
  int read_buf;
  int write_buf;
  char *buf;
  struct sockaddr_in sin;
  struct sockaddr_in csin;
  char dont_linemode_cmd[] = { IAC, DONT, TELOPT_LINEMODE, '\0' };
  char telnet_echo_cmd[] = { IAC, WILL, TELOPT_ECHO, '\0' };
  char telnet_sga_cmd[] = { IAC, WILL, TELOPT_SGA, '\0' };

  xmem_mgmt();
  xconsole_init_shell();
  xconsole_add_command(cmd_root, &show_hoge_info, 0);
		xconsole_add_command(cmd_root, &show_version_info, 0);

  if((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0){
    perror("socket");
    exit(1);
  }

  memset(&sin, 0, sizeof(struct sockaddr_in));
  read_buf = 1;
  write_buf = 1;
  nodelay_buf = 1;
  sin.sin_family = PF_INET;
  sin.sin_port = htons(PORT);
  sin.sin_addr.s_addr = INADDR_ANY;

  if(bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0){
    perror("bind");
    exit(1);
  }

  listen(sd, 5);

  while(1){
    csin_len = sizeof(csin);
    if((ad = accept(sd, (struct sockaddr *)&csin, &csin_len)) < 0){
      perror("accept");
      exit(1);
    }
    if(setsockopt(ad, SOL_SOCKET, SO_RCVBUF, &read_buf, sizeof(read_buf)) < 0){
      perror("setsockoptread");
      exit(1);
    }
    /*
    if(setsockopt(ad, SOL_SOCKET, SO_SNDBUF, &write_buf, sizeof(write_buf)) < 0){
      perror("setsockoptwrite");
      exit(1);
    }
    if(setsockopt (ad, IPPROTO_TCP, TCP_NODELAY, (char *) &nodelay_buf, sizeof (nodelay_buf)) < 0){
      perror("setsockoptnodelay");
      exit(1);
    }
    */
    //write(ad, telnet_echo_cmd, 4);
    write(ad, telnet_sga_cmd, 4);
    write(ad, dont_linemode_cmd, 4);

    printf("accpeted\n");	
    xconsole_init_term(ad);
    while((len = read(ad, buf, 1)) >= 0){
      printf("[%c]\n", *buf);
      printf("[%02x]\n", *buf);
      xconsole_read(ad, *buf);
    }

    close(ad);
  }
  close(sd);
}
