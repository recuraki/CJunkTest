/*
 * PCAP file char counter
 * Written by Akira KANAI< kanai at sfc.wide.ad.jp>
 * $Id: pcap_asciicount.c,v 1.1 2008/10/20 08:38:00 kanai Exp $
 *
 * Compile:
 * gcc -Wall -o pcap_hexcount pcap_hexcount.c -lpcap
 *
 * Description:
 * 
 */

#define SNAPLEN 1500

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#ifndef BUFSIZ
#define BUFSIZ 4096
#endif /* BUFSIZ */

#ifndef IF_NAMSIZ
#define IF_NAMSIZ 8
#endif /* IF_NAMSIZ */

#ifndef MAX_PATHLEN
#define MAX_PATHLEN 1024
#endif /* MAX_PATHLEN */
char pcap_inputfile[MAX_PATHLEN];
char pcap_filter[BUFSIZ];

int count_ascii;
int count_nonascii;

void do_replace4(const u_char *packet, struct pcap_pkthdr *header);

void sign_dump_ascii_comment(u_char *data, int len)
{
  int i;

  putchar('#');
  for(i = 0; i < len; i++)
    {
      if(data[i] < 0x7f && data[i] > 0x1f)
	printf("%c", data[i]);
      else
	printf(".");
      if(data[i] < 0x7f && (data[i] > 0x1f || data[i] == 0x0a || data[i] == 0x0d))
	count_ascii++;
      else
	count_nonascii++;
    }
  printf("\n");
}



void usage(char *prog) {
  printf("%s  - Count Payload Count.\n", prog);
  printf("$Id: pcap_asciicount.c,v 1.1 2008/10/20 08:38:00 kanai Exp $\n");
  printf("usage: %s -i file [ -F expression ] \n", prog);
  exit(-1);
}


struct ip_address
{
  union
  {
    uint32_t laddr;
  uint16_t saddr[2];
  } addr;
};


/* GENERIC FUNCTIONS */
void usage(char *prog);

void do_replace4(const u_char *packet, struct pcap_pkthdr *header)
{
  struct ether_header *ethhdr;
  struct icmphdr *icmphdr;
  struct tcphdr *tcphdr;
  struct udphdr *udphdr;
  struct ip *iphdr;

  ethhdr = (struct ether_header *)(packet);
  if(ntohs(ethhdr->ether_type) != ETHERTYPE_IP)
    {
      return;
    }
  iphdr = (struct ip *)(packet + ETHER_HDR_LEN);

  //  printf("%s\n", inet_ntoa(iphdr->ip_src));

  if(iphdr->ip_p == IPPROTO_TCP)
    {
      tcphdr = (struct tcphdr *)(packet + ETHER_HDR_LEN + (iphdr->ip_hl * 4));
      //      printf("iplen: th_off: %d\n", ntohs(iphdr->ip_len) );
      sign_dump_ascii_comment((u_char *)(packet + (int)ETHER_HDR_LEN + (int)(iphdr->ip_hl * 4)+ (int)(tcphdr->th_off * 4)),
			      ntohs(iphdr->ip_len) - (iphdr->ip_hl * 4) - (tcphdr->th_off * 4));
    }
  else if(iphdr->ip_p == IPPROTO_UDP)
    {
      printf("udp\n");
    }
  else if(iphdr->ip_p == IPPROTO_ICMP)
    {
      printf("udp\n");
    }


}


int main (int argc, char **argv) {
  pcap_t *pcapin;
  struct pcap_pkthdr pcap_header;
  const u_char *packet;
  char errbuf[256];
  char *input = NULL;
  int ch;
  struct bpf_program fcode;

  count_ascii = 0;
  count_nonascii = 0;

  if (argc < 3)
    {
      usage(argv[0]);
    }

  //printf("# $Id: pcap_asciicount.c,v 1.1 2008/10/20 08:38:00 kanai Exp $\n");

  /* Parse the command-line. */
  while ((ch = getopt(argc, argv, "ho:i:F:")) != EOF)
    {
      switch ((char) ch) 
	{
	case 'h':
	  usage(argv[0]);
	  exit(0);
	  break;
	case 'i':
	  input = optarg;
	  break;
	case 'F': /* Filter */
	  fprintf(stderr, "# PCAP FILTER:%s\n", optarg);
	  strncpy(pcap_filter, optarg, BUFSIZ);
	  break;
	}
    }
 
  if (input == NULL) 
    {
      printf("No input specified.\n");
      exit(-1);
    }
  /* Open Pcap File */
  printf("# INPUT PCAP: (%s).\n", input);
  if ((pcapin = pcap_open_offline(input, errbuf)) == NULL) 
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    }

  /* Handling PCAP Filter */
  if(pcap_filter[0] != 0x00) /* Filter was been not to set */
    {
      if (pcap_compile(pcapin, &fcode, pcap_filter, 1, 0) < 0) {
        fprintf(stderr, "can't compile fileter\n");
        exit(1);
      }
      if (pcap_setfilter(pcapin, &fcode) < 0) {
        fprintf(stderr, "can't set filter\n");
        exit(1);
      }
    }

  if ( (packet = pcap_next(pcapin,&pcap_header) ) == NULL) 
    {
      printf("Error: no packets in capture file %s\n", input);
      exit(-1);
    }

  while(packet != NULL) 
    {
      do_replace4(packet, &pcap_header);
      packet = pcap_next(pcapin, &pcap_header);
    }

  pcap_close(pcapin);

  printf("# asc/noasc = %d/%d\n", count_ascii, count_nonascii);
  if( (count_ascii + count_nonascii) != 0)
    {
      printf("%.2f\n", (double)(count_ascii / (count_ascii + count_nonascii)) * 100);
    }
  else
    {
      printf("0\n");
    }
  return(0);
} 
