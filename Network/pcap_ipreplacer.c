/*
 * IP address replacer
 * Written by Akira KANAI< kanai at sfc.wide.ad.jp>
 * $Id: pcap_ipreplacer.c,v 1.1 2007/10/23 08:20:32 kanai Exp $
 *
 * Compile:
 * gcc -Wall -o pcap_ipreplacer pcap_ipreplacer.c -lpcap
 *
 * Description:
 * This software replace IP Addresses which are included in PCAP
 * and recaulcurate the checksum which is included in L4 header.
 * We can support IPv4 and IPv6.
 * TCP and UDP will be handled.
 * 
 * Future Work:
 * - Suppourt SCTP
 */

/*
 * MEMO: Don't forget to cast a XOR value to u_short.
 * XORed value is not u_short but it is 32bit numeric.
 */

/*
 * CODE-MEMO: recalc the checksum with 2 replaced datas.
 *
 * newchecksum = (u_short)~oldchecksum +
 * (u_short)~replaced_data[0] + (u_short)~replaced_data[1] +
 * (u_short)replaced_with_data[0] + (u_short)replaced_with_data[1];
 * newchecksum = (newchecksum >> 16) + (newchecksum & 0xffff);
 * return (u_short)~newchecksum;
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
u_short ip_checksum_recalc(u_short ip_sum, u_short replace_data, u_short replace_with_data);
/* IPv4 FUNCTIONS */
void do_replace4(const u_char *packet, struct pcap_pkthdr *header, struct in_addr replace_ip4_addr, struct in_addr replace_with_ip4_addr);
u_short do_recalc_ip4(u_short ip_sum, struct ip_address replace_ip4, struct ip_address replace_with_ip4);
void do_replace4_transport_checksum(const u_char *packet, struct ip_address replace_ip4, struct ip_address replace_with_ip4);
void do_replace4_ip_checksum(const u_char *packet, struct ip_address replace_ip4, struct ip_address replace_with_ip4);
void do_replace4_tcp_checksum(const u_char *packet, struct ip_address replace_ip4, struct ip_address replace_with_ip4);
void do_replace4_udp_checksum(const u_char *packet, struct ip_address replace_ip4, struct ip_address replace_with_ip4);
/* IPv6 FUNCTIONS */
void do_replace6(const u_char *packet, struct pcap_pkthdr *header, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr);
u_short do_recalc_ip6(u_short ip_sum, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr);
void do_replace6_transport_checksum(const u_char *packet, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr);
void do_replace6_tcp_checksum(const u_char *packet, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr);
void do_replace6_udp_checksum(const u_char *packet, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr);


void usage(char *prog) {
  printf("%s  - Replace IP Address Software.\n", prog);
  printf("$Id: pcap_ipreplacer.c,v 1.1 2007/10/23 08:20:32 kanai Exp $\n");
  printf("usage: %s [-v] -i<infile1> -o<outfile> -b<before-ip-address> -a<after-ip-address>\n", prog);
  printf("Ex: %s -i input.pcap -o output.pcap -b 192.168.0.1 -a 127.0.0.1\n", prog);
  exit(-1);
}

int main (int argc, char **argv) {
  pcap_t *pcapin, *pcapout;
  pcap_dumper_t *popen;
  struct pcap_pkthdr pcap_header;
  const u_char *packet;
  int proto;
  char errbuf[256];
  char *output = NULL;
  char *input = NULL;
  char *replace_ip_str = NULL;
  char *replace_with_ip_str = NULL;
  int ch;
  struct in_addr replace_ip4_addr;
  struct in_addr replace_with_ip4_addr;
  struct in6_addr replace_ip6_addr;
  struct in6_addr replace_with_ip6_addr;

  if (argc < 3)
    {
      usage(argv[0]);
    }

  printf("$Id: pcap_ipreplacer.c,v 1.1 2007/10/23 08:20:32 kanai Exp $\n");

  /* Parse the command-line. */
  while ((ch = getopt(argc, argv, "ho:i:b:a:")) != EOF)
    {
      switch ((char) ch) 
	{
	case 'o':
	  output = optarg;
	  break;
	case 'h':
	  usage(argv[0]);
	  break;
	case 'i':
	  input = optarg;
	  break;
	case 'b':
	  replace_ip_str = optarg;
	  break;
	case 'a':
	  replace_with_ip_str = optarg;
	  break;
	}
    }
 
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
  if (replace_ip_str == NULL)
    {
      printf("No ""replace IP ADDRESS"" specified.\n");
      exit(-1);
    }
  if (replace_with_ip_str == NULL)
    {
      printf("No ""replace_with IP ADDRESS"" specified.\n");
      exit(-1);
    }
  if( inet_pton(AF_INET, replace_ip_str ,&replace_ip4_addr) != 0)
    {
      proto = AF_INET;
    }
  else
    {
      /* If src is not IPv4, then check that it is IPv6? */
      if( inet_pton(AF_INET6, replace_ip_str ,&replace_ip6_addr) != 0)
	{
	  proto = AF_INET6;
	}
      else
	{
	  printf("Unknown Str ""%s""\n", replace_ip_str); 
	  exit(-1);
	}
    }
  if( inet_pton(AF_INET, replace_with_ip_str ,&replace_with_ip4_addr) != 0)
    {
      /* DST = INET, SRC=INET? */
      if(proto != AF_INET)
	{
	  printf("Protcol miss match\n");
	  exit(-1);
	}
    }
  else
    {
      if( inet_pton(AF_INET6, replace_with_ip_str ,&replace_with_ip6_addr) != 0)
	{
	  /* SRC = DST = INET6 */
	  proto = AF_INET6;
	}
      else
	{
	  printf("Unknown Str ""%s""\n", replace_with_ip_str);  exit(-1);
	  exit(-1);
	}
    }

  printf("INPUT PCAP: (%s).\n", input);
  if ((pcapin = pcap_open_offline(input, errbuf)) == NULL) 
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    }

  printf("OUTPUT PCAP: (%s).\n", output);
  if ((pcapout = pcap_open_dead(DLT_RAW, SNAPLEN)) == NULL) 
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    } 


  /*
   * DISPLAY REPLACE STATEMENT 
   */
  if(proto == AF_INET)
    {
      printf("PROTOCOL: AF_INET\n");
    }
  else if(proto == AF_INET6)
    {
      printf("PROTOCOL: AF_INET6\n");
    }
  printf("REPLACE: (%s -> %s)\n", replace_ip_str, replace_with_ip_str);


  if( ( popen = pcap_dump_open(pcapin, output) ) == NULL )
    {
      printf("Error! %s\n", pcap_geterr(pcapout));
      exit(-1);
    }

  if ( (packet =pcap_next(pcapin,&pcap_header) ) == NULL) 
    {
      printf("Error: no packets in capture file %s\n", input);
      exit(-1);
    }

  while(packet != NULL) 
    {
      if(proto == AF_INET)
	{
	  do_replace4(packet, &pcap_header, replace_ip4_addr, replace_with_ip4_addr);
	}
      else if(proto == AF_INET6)
	{
	  do_replace6(packet, &pcap_header, replace_ip6_addr, replace_with_ip6_addr);
	}
      pcap_dump((u_char *)popen, &pcap_header, packet);
      packet = pcap_next(pcapin, &pcap_header);
    } /* while */

  pcap_dump_close(popen);
  pcap_close(pcapin);
  pcap_close(pcapout);
  exit(0);
} /* main */


u_short ip_checksum_recalc(u_short ip_sum, u_short replace_data, u_short replace_with_data)
{
  uint32_t ip_sum_buf;
  ip_sum_buf = (u_short)~ip_sum + 
    (u_short)~replace_data +
    replace_with_data;
  ip_sum_buf = (ip_sum_buf >> 16 ) +
    (ip_sum_buf & 0xffff);
  return ((u_short)~ip_sum_buf);
}

/*
 * IPv6 header don't have header's checksum.
 * This function will recalc only L4 headers.
 */
void do_replace6(const u_char *packet, struct pcap_pkthdr *header, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr)
{
  struct ether_header *ethhdr;
  struct ip6_hdr *ip6hdr;

  ethhdr = (struct ether_header *)(packet);
  if(ntohs(ethhdr->ether_type) != ETHERTYPE_IPV6)
    {
      return;
    }

  ip6hdr = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);

  if(memcmp(&ip6hdr->ip6_src, &replace_ip6_addr, sizeof(struct in6_addr) ) == 0)
    {
      do_replace6_transport_checksum(packet, replace_ip6_addr, replace_with_ip6_addr);
      memcpy(&ip6hdr->ip6_src, &replace_with_ip6_addr, sizeof(struct in6_addr));
    }

  if(memcmp(&ip6hdr->ip6_dst, &replace_ip6_addr, sizeof(struct in6_addr) ) == 0)
    {
      do_replace6_transport_checksum(packet, replace_ip6_addr, replace_with_ip6_addr);
      memcpy(&ip6hdr->ip6_dst, &replace_with_ip6_addr, sizeof(struct in6_addr));
    }

}

u_short do_recalc_ip6(u_short ip_sum, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr)
{
  int i;

  for(i = 0; i <= 8; i++)
    {
      ip_sum = ip_checksum_recalc(ip_sum,
				  (u_short)replace_ip6_addr.__u6_addr.__u6_addr16[i],
				  (u_short)replace_with_ip6_addr.__u6_addr.__u6_addr16[i]);
    }

  return ip_sum;
}

void do_replace6_transport_checksum(const u_char *packet, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr)
{
  struct ip6_hdr *ip6hdr;
  ip6hdr = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
  if(ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
    {
      do_replace6_tcp_checksum(packet, replace_ip6_addr, replace_with_ip6_addr);
    }
  else if(ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP)
    {
      do_replace6_udp_checksum(packet, replace_ip6_addr, replace_with_ip6_addr);
    }
}

void do_replace6_tcp_checksum(const u_char *packet, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr)
{
  struct tcphdr *tcphdr;
  tcphdr = (struct tcphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr)); 
  tcphdr->th_sum = (u_short)htons(do_recalc_ip6(ntohs(tcphdr->th_sum),
						replace_ip6_addr,
						replace_with_ip6_addr));
}

void do_replace6_udp_checksum(const u_char *packet, struct in6_addr replace_ip6_addr, struct in6_addr replace_with_ip6_addr)
{
  struct udphdr *udphdr;
  udphdr = (struct udphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr)); 
  udphdr->uh_sum = (u_short)htons(do_recalc_ip6(ntohs(udphdr->uh_sum),
						replace_ip6_addr,
						replace_with_ip6_addr));
}

u_short do_recalc_ip4(u_short ip_sum, struct ip_address replace_ip4, struct ip_address replace_with_ip4)
{
  ip_sum = ip_checksum_recalc(ip_sum,
			      (u_short)replace_ip4.addr.saddr[0],
			      (u_short)replace_with_ip4.addr.saddr[0]);
  ip_sum = ip_checksum_recalc(ip_sum,
			      (u_short)replace_ip4.addr.saddr[1],
			      (u_short)replace_with_ip4.addr.saddr[1]);
  return ip_sum;
}

void do_replace4_ip_checksum(const u_char *packet, struct ip_address replace_ip4, struct ip_address replace_with_ip4)
{
  struct ip *iphdr;
  iphdr = (struct ip *)(packet + ETHER_HDR_LEN);
  iphdr->ip_sum = (u_short)htons(do_recalc_ip4(ntohs(iphdr->ip_sum),
					       replace_ip4,
					       replace_with_ip4));
}


void do_replace4_transport_checksum(const u_char *packet, struct ip_address replace_ip4, struct ip_address replace_with_ip4)
{
  struct ip *iphdr;
  iphdr = (struct ip *)(packet + ETHER_HDR_LEN);
  if(iphdr->ip_p == IPPROTO_TCP)
    {
      do_replace4_tcp_checksum(packet, replace_ip4, replace_with_ip4);
    }
  else if(iphdr->ip_p == IPPROTO_UDP)
    {
      do_replace4_udp_checksum(packet, replace_ip4, replace_with_ip4);
    }
}

void do_replace4_tcp_checksum(const u_char *packet, struct ip_address replace_ip4, struct ip_address replace_with_ip4)
{
  struct tcphdr *tcphdr;
  tcphdr = (struct tcphdr *)(packet + ETHER_HDR_LEN + 20); 
  tcphdr->th_sum = (u_short)htons(do_recalc_ip4(ntohs(tcphdr->th_sum),
						replace_ip4,
						replace_with_ip4));
}

void do_replace4_udp_checksum(const u_char *packet, struct ip_address replace_ip4, struct ip_address replace_with_ip4)
{
  struct udphdr *udphdr;
  udphdr = (struct udphdr *)(packet + ETHER_HDR_LEN + 20); 
  udphdr->uh_sum = (u_short)htons(do_recalc_ip4(ntohs(udphdr->uh_sum),
						replace_ip4,
						replace_with_ip4));
}


void do_replace4(const u_char *packet, struct pcap_pkthdr *header, struct in_addr replace_ip4_addr, struct in_addr replace_with_ip4_addr)
{
  struct ether_header *ethhdr;
  struct ip *iphdr;
  struct ip_address ip_before, ip_after;

  ethhdr = (struct ether_header *)(packet);
  if(ntohs(ethhdr->ether_type) != ETHERTYPE_IP)
    {
      return;
    }
  ip_after.addr.laddr = ntohl(replace_with_ip4_addr.s_addr);
  iphdr = (struct ip *)(packet + ETHER_HDR_LEN);

  if(iphdr->ip_src.s_addr == replace_ip4_addr.s_addr)
    {
      ip_before.addr.laddr = ntohl(iphdr->ip_src.s_addr);
      do_replace4_ip_checksum(packet, ip_before, ip_after);
      do_replace4_transport_checksum(packet, ip_before, ip_after);
      iphdr->ip_src.s_addr = replace_with_ip4_addr.s_addr;
    }

  if(iphdr->ip_dst.s_addr == replace_ip4_addr.s_addr)
    {
      ip_before.addr.laddr = ntohl(iphdr->ip_dst.s_addr);
      do_replace4_ip_checksum(packet, ip_before, ip_after);
      do_replace4_transport_checksum(packet, ip_before, ip_after);
      iphdr->ip_dst.s_addr = replace_with_ip4_addr.s_addr;
    }
}
