/*
 * PCAP snapper 64
 * Written by Akira KANAI< kanai at wide.ad.jp>
 * Compile:
 * gcc -Wall -lpcap -p pcap_snap64 pcap_snap64.c
 * 以下のオプションで標準のsnaplenを変更できる
 * -DSNAPLEN=40
 */

// SNAPLEN RAW dumpなので気にしなくていい
#ifndef SNAPLEN
#define SNAPLEN 64
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/time.h>

void usage(char *prog) 
{
  printf("usage: %s -i<infile> -o<outfile> -s<snaplen>\n", prog);
  exit(-1);
}


int main (int argc, char **argv) 
{
  pcap_t *pcap1, *pcapout;
  pcap_dumper_t *popen;
  struct pcap_pkthdr header1;
  const u_char *packet1;
  char errbuf[256];
  char *output = NULL;
  char *input1 = NULL;
  int ch;
  bpf_u_int32 sl = SNAPLEN;

  // 引数チェック
  if (argc < 2)
    {
      usage(argv[0]);
    }

  // 引数のパース
  while ((ch = getopt(argc, argv, "ho:i:s:")) != EOF) 
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
	  input1 = optarg;
	  break;
        case 's':
          sl = (bpf_u_int32) atoi(optarg);
          break;
	}
    }

  // 引数の詳細チェック
  if (input1 == NULL || 
      output == NULL) {
    usage(argv[0]);
    exit(-1); 
  }

  // ファイルのオープン(offline = fileモード)
  if((pcap1 = pcap_open_offline(input1, errbuf)) == NULL) 
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    }

  // 書き込み先ファイルのオープン
  if((pcapout = pcap_open_dead(DLT_RAW, SNAPLEN)) == NULL)
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    } 

  // 書き込み先ファイルをpcapのディスクリプタとして開く
  if((popen = pcap_dump_open(pcap1, output) ) == NULL) 
    {
      printf("Error! %s\n", pcap_geterr(pcapout));
      exit(-1);
    }

  // 読み込み元から1 packet受け取る
  if(( packet1 = pcap_next(pcap1, &header1) ) == NULL)
    { 
      printf("Error: no packets in capture file %s\n", input1);
      exit(-1);
    }

  // until EOF
  while(packet1 != NULL) {
    // dumpする際に書き込むデータ長はcaplenに入っているので、
    // SNAPLENより長ければSNAPLENにする
    header1.caplen = header1.caplen > sl ? sl : header1.caplen;
    // 書き込む
    pcap_dump((u_char *)popen, &header1, packet1 );
    // 次のパケットを得る
    packet1 = pcap_next(pcap1, &header1);
  }

  pcap_dump_close(popen);
  pcap_close(pcap1);
  pcap_close(pcapout);
  exit(0);
}
