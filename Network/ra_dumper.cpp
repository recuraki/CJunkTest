/* C++ */
#include <iostream>

using namespace std;

/* C */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <fcntl.h>

#define FILENAMELEN 1024
#define BUFSIZ 1024

/*
 * struct 
 */
struct ra_packet
{
  u_int8_t  type;                        /* 134(0x86) */
  u_int8_t  code;                        /* 0 */
  u_int16_t checksum;                    /* 0 */
  u_int8_t  hoplimit;                    /* 64(0x40) */
  u_int8_t  flag;                        /* 0 */
  u_int16_t lifetime;                    /* 1800(0x0708) */
  u_int32_t reachabletime;               /* 0 */
  u_int32_t retranstime;                 /* 0 */
  u_int8_t  opt_type;                    /* 1 */
  u_int8_t  opt_src_len;                 /* 1(8byte) */
  u_int8_t  opt_src_mac[ETHER_ADDR_LEN]; /* */
  u_int8_t  opt_prefix_type;             /* 3 */
  u_int8_t  opt_prefix_len;              /* 4(32byte) */
  u_int8_t  opt_prefix_prefixlen;        /* 64(0x40) */
  u_int8_t  opt_prefix_flag;             /* 0xc0 */
  u_int32_t opt_prefix_validtime;        /* 30days = (0x00278d00) */
  u_int32_t opt_prefix_preferredtime;    /* 7days = (0x00093a80) */
  u_int32_t opt_prefix_NULL;             /* 0 */
  u_int8_t  opt_prefix_prefix[16];       /* */
};

class RaManager
{
private:
protected:
public:
};
class Ra
{
private:
protected:
public:
};

void pcap_proc(u_char *userdata, const struct pcap_pkthdr *h, const u_char *p);
void ra_proc(struct ra_packet *ra_packet);

int fd;
char buf[BUFSIZ];
int len; 

int main(int argc, char **argv)
{
  pcap_t *pd;
  int pflag = 0;
  int timeout = 1000;
  char ebuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 localnet;
  bpf_u_int32 netmask;
  pcap_handler callback;
  struct bpf_program fcode;
  char ifname[16];
  char filename[FILENAMELEN];
  char ch;

  /* Parse the command-line. */
  while ((ch = getopt(argc, argv, "i:w:")) != EOF)
    {
      switch ((char) ch) 
	{
	case 'i':
	  strncpy(ifname, optarg, 16);
	  break;
	case 'w':
	  strncpy(filename, optarg, FILENAMELEN);
	  break;
	}
    }

  if((fd = open(filename, O_WRONLY | O_CREAT | O_APPEND)) < 0)
    {
      perror("open");
      exit(-1);
    }


  /* FOR PCAP*/
  if ((pd = pcap_open_live(ifname, 200, !pflag, timeout, ebuf)) == NULL) {
    fprintf(stderr, "Can't open pcap deivce\n");
    exit(1);
  }
  if (pcap_lookupnet(ifname, &localnet, &netmask, ebuf) < 0) {
    fprintf(stderr, "Can't get interface informartions\n");
    exit(1);
  }
  if (pcap_compile(pd, &fcode, "icmp6", 1, netmask) < 0) {
    fprintf(stderr, "can't compile fileter\n");
    exit(1);
  }
  if (pcap_setfilter(pd, &fcode) < 0) {
    fprintf(stderr, "can't set filter\n");
    exit(1);
  }
  callback = pcap_proc;
  if (pcap_loop(pd, 0, callback, NULL) < 0) {
    (void)fprintf(stderr, "pcap_loop: error occurred\n");
    exit(1);
  }

  /* NOTREACH */

  close(fd);
  pcap_close(pd);
 
  return(0);
}

void log_proc(void)
{
  if(write(fd, buf, len) < 0){
    perror("write");
    exit(-1);
  }
}

void pcap_proc(u_char *userdata, const struct pcap_pkthdr *h, const u_char *p)
{
  struct ether_header *ethhdr;
  struct ip6_hdr *ip6hdr;
  struct ra_packet *ra_packet;
  struct timeval tv;

  ethhdr = (struct ether_header *)(p);
  if(ntohs(ethhdr->ether_type) != ETHERTYPE_IPV6)
    {
      return;
    }

  ip6hdr = (struct ip6_hdr *)(p + ETHER_HDR_LEN);
  if(ip6hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != 0x3a)
    {
      return;
    }

  ra_packet = (struct ra_packet *)(p + ETHER_HDR_LEN + sizeof(struct ip6_hdr));
  if(ra_packet->type != 0x86 ||
     ra_packet->code != 0)
    {
      return;
    }

  gettimeofday(&tv, NULL);
  len = snprintf(buf, BUFSIZ,
		 "[%2.6f] "
		 "src ipaddr[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x], ",
		 (double)tv.tv_sec +  (double)tv.tv_usec/1000000, 
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[0],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[1],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[2],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[3],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[4],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[5],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[6],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[7],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[8],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[9],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[10],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[11],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[12],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[13],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[14],
		 ip6hdr->ip6_src.__u6_addr.__u6_addr8[15]);
  log_proc();
  ra_proc(ra_packet);

}

void ra_proc(struct ra_packet *ra_packet)
{

  len = snprintf(buf, BUFSIZ,
		 "src addr[%02x:%02x:%02x:%02x:%02x:%02x], "
		 "advertisement[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x/%d]\n", 
		 ra_packet->opt_src_mac[0],
		 ra_packet->opt_src_mac[1],
		 ra_packet->opt_src_mac[2],
		 ra_packet->opt_src_mac[3],
		 ra_packet->opt_src_mac[4],
		 ra_packet->opt_src_mac[5],
		 ra_packet->opt_prefix_prefix[0],
		 ra_packet->opt_prefix_prefix[1],
		 ra_packet->opt_prefix_prefix[2],
		 ra_packet->opt_prefix_prefix[3],
		 ra_packet->opt_prefix_prefix[4],
		 ra_packet->opt_prefix_prefix[5],
		 ra_packet->opt_prefix_prefix[6],
		 ra_packet->opt_prefix_prefix[7],
		 ra_packet->opt_prefix_prefix[8],
		 ra_packet->opt_prefix_prefix[9],
		 ra_packet->opt_prefix_prefix[10],
		 ra_packet->opt_prefix_prefix[11],
		 ra_packet->opt_prefix_prefix[12],
		 ra_packet->opt_prefix_prefix[13],
		 ra_packet->opt_prefix_prefix[14],
		 ra_packet->opt_prefix_prefix[15],
		 ra_packet->opt_prefix_prefixlen);
  log_proc();
}
