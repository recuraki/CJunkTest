/*
 * MAC address replacer
 * Written by Akira KANAI< kanai at sfc.wide.ad.jp>
 * $Id: pcap_macreplacer.c,v 1.1 2007/10/23 08:20:32 kanai Exp $
 *
 * Compile:
 * gcc -Wall -o pcap_macreplacer pcap_macreplacer.c -lpcap
 *
 * Description:
 * This software replace MAC Addresses which are included in PCAP
 *
 */

#define SNAPLEN 1500

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

u_char replace_mac_addr[ETHER_ADDR_LEN];
u_char replace_mac_addr_with[ETHER_ADDR_LEN];

int mac_aton(char *str, u_char *dst);
int mac_aton_3_fields(char *str, u_char *dst, char separator);
int mac_aton_6_fields(char *str, u_char *dst, char separator);
void do_replace(const u_char *packet, struct pcap_pkthdr *header);

int main (int argc, char **argv) {
  pcap_t *pcapin, *pcapout;
  pcap_dumper_t *popen;
  struct pcap_pkthdr pcap_header;
  const u_char *packet;
  char errbuf[256];
  char *output = NULL;
  char *input = NULL;
  char *before_mac_str = NULL;
  char *after_mac_str = NULL;
  int ch;

  if (argc < 3)
    {
      printf("- MAC Address Replacer)\n");
      printf("$Id: pcap_macreplacer.c,v 1.1 2007/10/23 08:20:32 kanai Exp $\n");
      printf("usage: %s -i<infile1> -o<outfile> -b<before-ip-address> -a<after-ip-address>\n", argv[0]);
      printf("Ex: %s -i input.pcap -o output.pcap -b 00:10:20:30:40:50 -a 00:00:00:00:00:00 \n", argv[0]);
      printf("I support some mac address formats.");
      printf("six-fields MAC Address   : xx:xx:xx:xx:xx:xx or xx-xx-xx-xx-xx-xx or xx.xx.xx.xx.xx.xx\n");
      printf("three-fielfs MAC Address : xxxx:xxxx:xxxx    or xxxx-xxxx-xxxx    or xxxx.xxxx.xxxx\n");
      exit(-1);
    }

  /* Parse the command-line. */
  while ((ch = getopt(argc, argv, "o:i:b:a:")) != EOF)
    {
      switch ((char) ch) 
	{
	case 'o':
	  output = optarg;
	  break;
	case 'i':
	  input = optarg;
	  break;
	case 'b':
	  before_mac_str = optarg;
	  break;
	case 'a':
	  after_mac_str = optarg;
	  break;
	}
    }
 
  /* Sanity check */
  if (input == NULL) 
    { 
      printf("No input specified.\n");
      exit(-1); 
    }
  if (output == NULL) 
    {
      printf("No output specified.\n");
      exit(-1); 
    }
  if (before_mac_str == NULL)
    {
      printf("No ""BEFORE IP ADDRESS"" specified.\n");
      exit(-1); 
    }
  if (after_mac_str == NULL)
    {
      printf("No ""AFTER IP ADDRESS"" specified.\n");
      exit(-1); 
    }
  if( mac_aton(before_mac_str , replace_mac_addr) == 0)
    {
      printf("Unknown Str ""%s""\n", before_mac_str);
      exit(-1);
    }
  printf("--\n");
  if( mac_aton(after_mac_str , replace_mac_addr_with) == 0)
    {
      printf("Unknown Str ""%s""\n", after_mac_str);  
      exit(-1);
    }

  printf("replace %02x:%02x:%02x:%02x:%02x:%02x with %02x:%02x:%02x:%02x:%02x:%02x\n",
	 replace_mac_addr[0],
	 replace_mac_addr[1],
	 replace_mac_addr[2],
	 replace_mac_addr[3],
	 replace_mac_addr[4],
	 replace_mac_addr[5],
	 replace_mac_addr_with[0],
	 replace_mac_addr_with[1],
	 replace_mac_addr_with[2],
	 replace_mac_addr_with[3],
	 replace_mac_addr_with[4],
	 replace_mac_addr_with[5]);

  if ((pcapin = pcap_open_offline(input, errbuf)) == NULL) 
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    }

  if ((pcapout = pcap_open_dead(DLT_RAW, SNAPLEN)) == NULL) 
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    } 

  if( ( popen = pcap_dump_open(pcapin, output) ) == NULL)
    {
      printf("Error! %s\n", pcap_geterr(pcapout));
      exit(-1);
    }

  if( (packet = pcap_next(pcapin, &pcap_header) ) == NULL)
    {
      printf("Error: no packets in capture file %s\n", input);
      exit(-1);
    }

  while (packet != NULL)
    {
      do_replace(packet, &pcap_header);
      pcap_dump((u_char *)popen, &pcap_header, packet);
      packet = pcap_next(pcapin, &pcap_header);
    }

  pcap_dump_close(popen);
  pcap_close(pcapin);
  pcap_close(pcapout);
  exit(0);
}

void do_replace(const u_char *packet, struct pcap_pkthdr *header)
{
  struct ether_header *ethhdr;
  ethhdr = (struct ether_header *)(packet);

  if(ethhdr->ether_shost[0] == replace_mac_addr[0] &&
     ethhdr->ether_shost[1] == replace_mac_addr[1] &&
     ethhdr->ether_shost[2] == replace_mac_addr[2] &&
     ethhdr->ether_shost[3] == replace_mac_addr[3] &&
     ethhdr->ether_shost[4] == replace_mac_addr[4] &&
     ethhdr->ether_shost[5] == replace_mac_addr[5] )
    {
      memcpy(ethhdr->ether_shost, replace_mac_addr_with, ETHER_ADDR_LEN);
    }
  if(ethhdr->ether_dhost[0] == replace_mac_addr[0] &&
     ethhdr->ether_dhost[1] == replace_mac_addr[1] &&
     ethhdr->ether_dhost[2] == replace_mac_addr[2] &&
     ethhdr->ether_dhost[3] == replace_mac_addr[3] &&
     ethhdr->ether_dhost[4] == replace_mac_addr[4] &&
     ethhdr->ether_dhost[5] == replace_mac_addr[5] )
    {
      memcpy(ethhdr->ether_dhost, replace_mac_addr_with, ETHER_ADDR_LEN);
    }
}

int mac_aton(char *str, u_char *dst)
{
  if(mac_aton_6_fields(str, dst, ':') == 1){return(1);}
  if(mac_aton_6_fields(str, dst, '-') == 1){return(1);}
  if(mac_aton_6_fields(str, dst, '.') == 1){return(1);}
  if(mac_aton_3_fields(str, dst, ':') == 1){return(1);}
  if(mac_aton_3_fields(str, dst, '-') == 1){return(1);}
  if(mac_aton_3_fields(str, dst, '.') == 1){return(1);}
  return(0);
}

int mac_aton_3_fields(char *str, u_char *dst, char separator)
{
  char *c;
  int now_field = 0;
  static char mac_buffer[18];
  strncpy(mac_buffer, str, 18);
  u_char buf;
  u_char field_buf[4];
  int i;
  int have_empty;
  c = mac_buffer;

  for(i = 0; i < 4; i++)
    {
      field_buf[i] = 0xff;
    }

  for(;;)
    { /* for while(1) */
      if( ( (*c >= '0')  && (*c <= '9')  ) ||
	  ( (*c >= 'a')  && (*c <= 'f')  ) ||
	  ( (*c >= 'A')  && (*c <= 'F')  ) )
	{ /* char */

	  /*
	   * convert ascii to num
	   */
	  if( (*c >= '0')  && (*c <= '9') ) { buf = *c - '0'; }
	  if( (*c >= 'a')  && (*c <= 'f') ) { buf = *c - 'a' + 10; }
	  if( (*c >= 'A')  && (*c <= 'F') ) { buf = *c - 'A' + 10; }

	  /* 
	   * If read first char, set it higher char
	   * Else, set it lower char
	   */

	  have_empty = 0;
	  for(i = 0; i < 4; i++)
	    {
	      if(field_buf[i] == 0xff)
		{
		  field_buf[i] = buf;
		  have_empty = 1;
		  break;
		}
	    }
	  if(have_empty == 0)
	    {
	      return(0);
	    }
	} /* char */

      /* 
       * Is this end of this field  ?
       */
      else if (*c == separator || *c == 0x00)
	{ /* separetor */

	  /* 
	   * Did we process 2 fields?
	   * Ex. xxxx.xxxx
	   */
	  if( (*c == 0x00) &&
	      (now_field != 2))
	    {
	      return(0);
	    }

	  /* 
	   * Is this Empty Field?
	   * Ex. xx::xx:xx:xx:xx
	   */
	  if(field_buf[0] == 0xff) {
	    return(0);
	  }
     
	  for(i = 0; i < 4; i++)
	    {
	      if(field_buf[i] != 0xff){
		dst[2 * now_field] = (dst[2 * now_field] << 4) +
		  (char)(dst[2 * now_field + 1] >> 4);
		dst[2 * now_field + 1] = (dst[2 * now_field + 1]  << 4)+
		  (field_buf[i] & 0x0f);
	      }
	    }

	  if(*c == 0x00)
	    {
	      break;
	    }

	  /*
	   * Init Buffer
	   */
	  for(i = 0; i < 4; i++)
	    {
	      field_buf[i] = 0xff;
	    }
	  now_field++;
	} /* separetor */
      else
	{ /* OTHER CHAR */
	  return(0);
	}

      /*
       * how much colon does this have?
       * ex. xx:xx:xx:xx:xx:xx:xx:xx :p
       */
      if(now_field == 3)
	{
	  return(0);
	}

      c++;

    } /* for while(1) */

  /* ACCEPT :) */
  return(1);
}
int mac_aton_6_fields(char *str, u_char *dst, char separator)
{
  char *c;
  int now_field = 0;
  static char mac_buffer[18];
  strncpy(mac_buffer, str, 18);
  memset(dst, 0x00, ETHER_ADDR_LEN);
  u_char buf;
  u_char buf1 = 0xff;
  u_char buf2 = 0xff;

  c = mac_buffer;

  for(;;)
    { /* for while(1) */
      if( ( (*c >= '0')  && (*c <= '9')  ) ||
	  ( (*c >= 'a')  && (*c <= 'f')  ) ||
	  ( (*c >= 'A')  && (*c <= 'F')  ) )
	{ /* char */

	  /*
	   * convert ascii to num
	   */
	  if( (*c >= '0')  && (*c <= '9') ) { buf = *c - '0'; }
	  if( (*c >= 'a')  && (*c <= 'f') ) { buf = *c - 'a' + 10; }
	  if( (*c >= 'A')  && (*c <= 'F') ) { buf = *c - 'A' + 10; }

	  /* 
	   * If read first char, set it higher char
	   * Else, set it lower char
	   */

	  if(buf1 != 0xff && buf2 != 0xff)
	    {
	      return(0);
	    }

	  if(buf1 == 0xff)
	    {
	      buf1 = buf;
	    }
	  else if(buf2 == 0xff)
	    {
	      buf2 = buf;
	    }

	} /* char */

      /* 
       * Is this end of this field  ?
       */
      else if (*c == separator || *c == 0x00)
	{ /* separetor */

	  /* 
	   * Did we process 5 fields?
	   * Ex. xx:xx:xx:xx
	   */
	  if( (*c == 0x00) &&
	      (now_field != 5))
	    {
	      return(0);
	    }

	  /* 
	   * Is this Empty Field?
	   * Ex. xx::xx:xx:xx:xx
	   */
	  if(buf1 == 0xff) {
	    return(0);
	  }
	  /*
	   * is this 2 digits?
	   */
	  if(buf2 != 0xff)
	    {
	      dst[now_field] = buf1 << 4;
	      dst[now_field] += buf2;
	    }
	  /*
	   * or 1 digit?
	   */
	  else /* buf2 == 0xff */
	    {
	      dst[now_field] = buf1;

	    }

	  if(*c == 0x00)
	    {
	      break;
	    }

	  /*
	   * Init Buffer
	   */
	  buf1 = buf2 = 0xff;
	  now_field++;
	} /* separetor */
      else
	{ /* OTHER CHAR */
	  return(0);
	}

      /*
       * how much colon does this have?
       * ex. xx:xx:xx:xx:xx:xx:xx:xx :p
       */
      if(now_field == 6)
	{
	  return(0);
	}

      c++;

    } /* for while(1) */

  /* ACCEPT :) */
  return(1);
}
