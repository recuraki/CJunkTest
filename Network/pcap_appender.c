/*
 * PCAP Appender
 * Written by Akira KANAI< kanai at sfc.wide.ad.jp>
 * $Id: pcap_appender.c,v 1.1 2007/10/25 07:22:59 kanai Exp $
 *
 * Compile:
 * gcc -Wall -o pcap_appender pcap_appender.c -lpcap
 *
 * Description:
 * This software add a pcap file in a other pcap file.
 * And, shrink the delta time between both pcaps.
 *
 */
#define SNAPLEN 1500

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <sys/time.h>

void usage(char *prog) 
{
  printf("$Id: pcap_appender.c,v 1.1 2007/10/25 07:22:59 kanai Exp $\n");
  printf("%s - Append PCAP File\n", prog);
  printf("usage: %s -1<infile1> -2<infile2> -o<outfile>\n", prog);
  exit(-1);
}


int main (int argc, char **argv) 
{
  pcap_t *pcap1, *pcap2, *pcapout;
  pcap_dumper_t *popen;
  struct pcap_pkthdr header1, header2;
  const u_char *packet1, *packet2;
  char errbuf[256];
  struct timeval tv1, tv2, tvdiff, tvwork;
  char *output = NULL;
  char *input1 = NULL;
  char *input2 = NULL;
  int ch;

  if (argc < 3)
    {
      usage(argv[0]);
    }

  while ((ch = getopt(argc, argv, "ho:1:2:")) != EOF) 
    {
      switch ((char) ch) 
	{
	case 'o':
	  output = optarg;
	  break;
	case 'h':
	  usage(argv[0]);
	  break;
	case '1':
	  input1 = optarg;
	  break;
	case '2':
	  input2 = optarg;
	  break;
	}
    }
 
  if (input1 == NULL || 
      input2 == NULL ||
      output == NULL) {
    usage(argv[0]);
    exit(-1); 
  }

  if((pcap1 = pcap_open_offline(input1, errbuf)) == NULL) 
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    }
  if((pcap2 = pcap_open_offline(input2, errbuf)) == NULL) 
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    }

  if((pcapout = pcap_open_dead(DLT_RAW, SNAPLEN)) == NULL)
    {
      printf("Error: %s\n", errbuf);
      exit(-1);
    } 
  if((popen = pcap_dump_open(pcap1, output) ) == NULL) 
    {
      printf("Error! %s\n", pcap_geterr(pcapout));
      exit(-1);
    }
  if(( packet1 = pcap_next(pcap1, &header1) ) == NULL)
    { 
      printf("Error: no packets in capture file %s\n", input1);
      exit(-1);
    }
  if((  packet2 = pcap_next(pcap2, &header2)) == NULL) 
    {
      printf("Error: no packets in capture file %s\n", input2);
      exit(-1);
    }

  tv2 = header2.ts;

  while(packet1 != NULL) {
    pcap_dump((u_char *)popen, &header1, packet1);
    packet1 = pcap_next(pcap1, &header1);
  }

  tv1 = header1.ts;
  timersub(&tv1, &tv2, &tvdiff);
  printf("Diff: %2.6f\n", (double)tvdiff.tv_usec/1000000 + tvdiff.tv_sec );

  while (packet2 != NULL) 
    {
      timeradd(&header2.ts, &tvdiff, &tvwork);
      header2.ts = tvwork;
      pcap_dump((u_char *)popen, &header2, packet2);
      packet2 = pcap_next(pcap2, &header2);
    }
   
  pcap_dump_close(popen);
  pcap_close(pcap1);
  pcap_close(pcap2);
  pcap_close(pcapout);
  exit(0);
}
