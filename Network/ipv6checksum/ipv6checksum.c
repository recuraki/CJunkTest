/*
 * ICMPv6 CheckSum Calc
 * ICMPv6のチェックサム計算機
 * Written by Akira KANAI<kanai@wide.ad.jp>
 */

/*
 * 解説:
 * -i で与えられたIPv6パケットをみつけ、それがICMPv6であった場合
 * ICMPv6 CheckSumの検算を行います。
 */

/*
 * TODO:
 * -o で再計算後のを吐けるようにするとか？
 */

/*
 * gcc -Wall -o ipv6checksum ipv6checksum.c -lpcap
 */ 

// pcap的な最長snaplen
#ifndef SNAPLEN
#define SNAPLEN 1500
#endif /* SNAPLEN */

#ifndef BUFSIZ
#define BUFSIZ 4096
#endif /* BUFSIZ */

#define __USE_MISC 1

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
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
//#include <arpa/inet.h>

/* 関数定義 */
void do_proc(const u_char *packet, struct pcap_pkthdr *header);
u_int16_t do_calc_icmpv6(const u_char *packet, const u_char offset);

void usage(char *prog) {
  printf("%s  - ICMPv6 CheckSum Calc\n", prog);
  printf("$ Written by Akira KANAI<kanai@wide.ad.jp $\n");
  printf("usage: %s [-v] -i<infile1> -o<outfile> -b<before-ip-address> -a<after-ip-address>\n", prog);
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

struct icmpv6_header
{
  u_int8_t  type;                        /* 134(0x86) */
  u_int8_t  code;                        /* 0 */
  u_int16_t checksum;                    /* 0 */
};

int main(int argc, char **argv)
{
  char ch;
  char *output = NULL;
  char *input = NULL;
  pcap_t *pcapin;

  char errbuf[256];

  struct pcap_pkthdr pcap_header;
  const u_char *packet;

  if (argc < 3)
    {
      usage(argv[0]);
    }

  /* 引数処理 */
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

	}
    }

  /* -iがなければエラーを吐く(読むpcapが指定されていないから) */
  if (input == NULL)
    {
      printf("No input specified.\n");
      exit(-1);
    }

  /* pcapファイルを開きます */
  printf("INPUT PCAP: (%s).\n", input);
  if ((pcapin = pcap_open_offline(input, errbuf)) == NULL)
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    }

  /* まず、パケットを開き、パケットが何もなければエラー */
  /* 空のpcapを開いても困る */
  if ( (packet =pcap_next(pcapin,&pcap_header) ) == NULL)
    {
      printf("Error: no packets in capture file %s\n", input);
      exit(-1);
    }

  /* pcapinを最後まで読む */
  int inPktCount = 0; // n個目のパケット(wiresharkなどのNoと一緒) 
  while(packet != NULL)
    {

      inPktCount++; // パケットカウント追加

      /* パケットごとの処理 */
      printf("--------------\n");
      printf("Packet[%d]\n", inPktCount);
      do_proc(packet, &pcap_header);

      /* 次のパケットを読む */
      packet = pcap_next(pcapin, &pcap_header);

    } /* while */


  /* パケットのdesc閉じて終わり */
  pcap_close(pcapin);

  return(0);
}

void do_proc(const u_char *packet, struct pcap_pkthdr *header)
{
  int i;
  char buf[BUFSIZ];
  u_int8_t ipdst[16];
  u_int8_t hwsrc[6];
  u_int8_t hwdst[6];
  u_int32_t checksum;
  u_int8_t *payload;
  u_int8_t eui64src[8];


  struct ether_header *ethhdr;
  struct ip6_hdr *ip6hdr;
  struct icmp6_hdr *icmp6hdr;

  /* EtherのNextHeaderをみてIPv6じゃないならDISCARD */
  ethhdr = (struct ether_header *)(packet);
  if(ntohs(ethhdr->ether_type) != ETHERTYPE_IPV6)
    {
      return;
    }


  /* いまはICMPv6じゃないならDISCARD */
  ip6hdr = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);

  if(ip6hdr->ip6_nxt != IPPROTO_ICMPV6)
    {
      return;
    }
  
#if 0
  // 以下のようにIPv6Addrを表示することもできる
  for(i = 0; i < 8; i++)
    {
      printf("%x:", ntohs(ip6hdr->ip6_src.s6_addr16[i]));
      printf("%x:", ntohs(ip6hdr->ip6_src.__u6_addr.__u6_addr16[i]));
    }
#endif /* 0 */

  /* IPv6パケットのSrc, Dstを表示 */
  inet_ntop(AF_INET6, &ip6hdr->ip6_src, buf, BUFSIZ);
  printf("[Host] %s -> ", buf);
  inet_ntop(AF_INET6, &ip6hdr->ip6_dst, buf, BUFSIZ);
  printf(" %s", buf);
  printf("\n");

  /* ICMPv6ヘッダの位置を指定 */
  icmp6hdr = (struct icmp6_hdr *)(packet + ETHER_HDR_LEN  + sizeof(struct ip6_hdr));

  /* ICMPv6ヘッダをDumpします */
  printf("Type:%x, ", icmp6hdr->icmp6_type);
  printf("Code:%x, ", icmp6hdr->icmp6_code);
  printf("CurrentChecksum:%x \n", ntohs(icmp6hdr->icmp6_cksum));

  /* ICMPv6固有の処理 */
  /* 今はCheckSumの再計算 */
  do_calc_icmpv6(packet, ETHER_HDR_LEN + sizeof(struct ip6_hdr));
}

u_int16_t do_calc_icmpv6(const u_char *packet, const u_char offset)
{

#if 0
  struct ether_header *ethhdr;
#endif
  struct ip6_hdr *ip6hdr;
  struct icmp6_hdr *icmp6hdr;

  ip6hdr = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
  icmp6hdr = (struct icmp6_hdr *)(packet + ETHER_HDR_LEN  + sizeof(struct ip6_hdr));

  u_int32_t checksum;
  u_int16_t ck_tmp;
  u_int16_t *p_packet;
  checksum = 0;
  int i;

  /* Pseudo Header: 仮想ヘッダの計算 ここから */
 
  for(i = 0; i < 8; i++) {
    checksum += (u_int16_t)ntohs(ip6hdr->ip6_dst.s6_addr16[i]);
    //printf("add[dst]: %04x\n", (u_int16_t)ntohs(ip6hdr->ip6_dst.s6_addr16[i]));
  }

  for(i = 0; i < 8; i++) {
    checksum += (u_int16_t)ntohs(ip6hdr->ip6_src.s6_addr16[i]);
    //printf("add[src]: %04x\n", (u_int16_t)ntohs(ip6hdr->ip6_src.s6_addr16[i]));
  }


  checksum += (u_int16_t)ntohs(ip6hdr->ip6_plen);
  //printf("add[len]: %04x\n", (u_int16_t)ntohs(ip6hdr->ip6_plen));

  checksum += (u_int16_t)58;
  //printf("add[N_H]: %04x\n", 58);

  /* Pseudo Header: 仮想ヘッダの計算 ここまで */

  //printf("---- [ END HEADER ] ----\n" );

  /* ICMPv6 Header: ICMPv6ヘッダの計算 ここから */
  ck_tmp = icmp6hdr->icmp6_type << 8;
  ck_tmp += icmp6hdr->icmp6_code << 8;
  checksum += (u_int16_t)ck_tmp;
  //printf("add[T_C]: %04x\n", ck_tmp);

  ck_tmp = 0;
  checksum += (u_int16_t)ck_tmp;
  //printf("add[T_C]: %04x\n", ck_tmp);

  /* ここ、どうやって計算するのか分からなかったので手打ち。MTUをちゃんと足すこと！ */
  //DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
  checksum += (u_int16_t)0x0500;
  //printf("add[N_H]: %04x\n", 0x0500);
  //DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
  /* ICMPv6 Header: ICMPv6ヘッダの計算 ここまで */
  //printf("---- [ END ICMP] ----\n" );

  // ペイロードの計算
  p_packet = packet;
  p_packet += (ETHER_HDR_LEN /2 ) +  (sizeof(struct ip6_hdr) / 2) + (sizeof(struct icmp6_hdr) / 2);

  int c = 0;
  for(i = 0; i < (ntohs(ip6hdr->ip6_plen) - sizeof(struct icmp6_hdr)); i+=2)
    {
      //printf("offset: %d\n", i);
      //printf("count: %d\n", c);
      ck_tmp = ntohs(p_packet[c]);
      //printf("add[pay]: %04x - %c%c\n", ck_tmp, ck_tmp >> 8, ck_tmp <<8 >>8);
      checksum += ck_tmp;
      c++;
    }

  //printf("RESULT-before: %08x\n", checksum);
  //printf("RESULT-calc: %08x - %08x + %08x \n", 0xffff, (checksum >> 16) ,  ((u_int16_t)checksum << 16 >> 16)) ;
  //printf("RESULT-calc: %08x - %08x \n", 0xffff, (checksum >> 16) + ((u_int16_t)checksum << 16 >> 16)) ;

  /*
    1の補数和
    0xffff -: 補数を取る
    (checksum >>16)は繰り上がり部分
    (checksum << 16 >> 16)は下の16ビット
  */
    checksum = 0xffff - ( (checksum >>16) + (checksum << 16 >> 16) );

  printf("Calc-ICMPv6 CheckSum: %08x\n", checksum);
}

#if 0
 ここは参考資料
struct in6_addr {
  union {
    uint8_t         __u6_addr8[16];
    uint16_t        __u6_addr16[8];
    uint32_t        __u6_addr32[4];
  } __u6_addr;                    /* 128-bit IP6 address */
};

struct ip6_hdr {
  union {
    struct ip6_hdrctl {
      u_int32_t ip6_un1_flow; /* 20 bits of flow-ID */
      u_int16_t ip6_un1_plen; /* payload length */
      u_int8_t  ip6_un1_nxt;  /* next header */
      u_int8_t  ip6_un1_hlim; /* hop limit */
    } ip6_un1;
    u_int8_t ip6_un2_vfc;   /* 4 bits version, top 4 bits class */
  } ip6_ctlun;
  struct in6_addr ip6_src;        /* source address */
  struct in6_addr ip6_dst;        /* destination address */
} __packed;

struct icmp6_hdr {
  u_int8_t        icmp6_type;     /* type field */
  u_int8_t        icmp6_code;     /* code field */
  u_int16_t       icmp6_cksum;    /* checksum field */
  union {
    u_int32_t       icmp6_un_data32[1]; /* type-specific field */
    u_int16_t       icmp6_un_data16[2]; /* type-specific field */
    u_int8_t        icmp6_un_data8[4];  /* type-specific field */
  } icmp6_dataun;
} __packed;

- NEXT HEADER
#define IPPROTO_IP              0               /* dummy for IP */
#define IPPROTO_ICMP            1               /* control message protocol */
#define IPPROTO_IPV4            4               /* IPv4 encapsulation */
#define IPPROTO_TCP             6               /* tcp */
#define IPPROTO_UDP             17              /* user datagram protocol */
#define IPPROTO_ICMPV6          58              /* ICMP6 */
#endif 
