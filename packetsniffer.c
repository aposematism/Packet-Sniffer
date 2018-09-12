#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>//Provides pcap
#include <arpa/inet.h>//Provides inet_ntoa.
#include <netinet/if_ether.h>//Provides the ethernet.
#include <netinet/udp.h>//Provides declarations for udp header
#include <netinet/tcp.h>//Provides declarations for tcp header
#include <netinet/ip.h>//Provides declarations for ipv4
#include <netinet/ip6.h>//Provides declarations for ipv6
#include <netinet/ip_icmp.h>//Provides declarations for icmp for ipv4
#include <netinet/icmp6.h>//Provides declarations for icmp for ipv6
#include <netinet/igmp.h>//Provides IGMP capacity.

/**

    To understand this code, read up from the bottom. I essentially used function prototypes sparingly.
    This code starts with the Transport Layer Handlers and goes down the layers as you scroll down.

    The main method executes whatever your PCAP file input is.
    So in my case, the command is "./sniffer collectedpackets". The first argument entered is the name of the file.
*/

//Function prototype is necessary as the pcap_loop is necessary for it.
void packetHandler(unsigned char * userdata, const struct pcap_pkthdr * pkthdr, const unsigned char * packet);
unsigned int ipv6Ext(unsigned int extnum, int * size, const unsigned char * packet);
unsigned int transportHandler(const unsigned char * packet, const struct pcap_pkthdr * pkthdr, unsigned int tProtocol, int * size);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);


//Fields
int totalcount = 1;

//Handles the transport portion.
unsigned int transportHandler(const unsigned char * packet, const struct pcap_pkthdr * pkthdr, unsigned int tProtocol, int * size){
  const struct tcphdr * tcp_header;
  const struct udphdr * udp_header;
  const struct icmp * icmp_header;
  const struct igmp * igmp_header;
  u_char * payload;
  switch(tProtocol){
    case IPPROTO_UDP:
      udp_header = (struct udphdr *)(packet+(*size));
      *size += sizeof(struct udphdr);
      //payload = (u_char *)(packet+size);
      printf("Transport Protocol: UDP ");
      printf("Source Port: %u Destination Port: %u \n", ntohs(udp_header->source), ntohs(udp_header->dest));
      printf("Payload Size: (%d Bytes)\n", ((int)pkthdr->len-(*size)));
      print_payload(packet, ((int)pkthdr->len-(*size)));
      break;
    case IPPROTO_TCP:
      tcp_header = (struct tcphdr *)(packet+(*size));
      *size += sizeof(struct tcphdr);
      //payload = (u_char *)(packet+size);
      printf("Transport Protocol: TCP ");
      printf("Source Port: %u Destination Port: %u \n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
      printf("Sequence: %u Acknowledge: %u\n", tcp_header->th_seq, tcp_header->th_ack);
      printf("Payload Size: (%d Bytes)\n", ((int)pkthdr->len-(*size)));
      print_payload(packet, ((int)pkthdr->len-(*size)));
      break;
    case IPPROTO_ICMP:
      icmp_header = (struct icmp *)(packet+(*size));
      *size += sizeof(struct icmp);
      printf("Transport Protocol: ICMPv4 ");
      printf("Type: %u Code: %u\n", icmp_header->icmp_type, icmp_header->icmp_code);
      printf("Payload Size: (%d Bytes)\n", ((int)pkthdr->len-(*size)));
      print_payload(packet, ((int)pkthdr->len-(*size)));
      break;
    case IPPROTO_IGMP:
      igmp_header = (struct igmp *)(packet+(*size));
      *size += sizeof(struct igmp);
      printf("Transport Protocol: IGMP ");
      printf("Type: 0x%x Code: %x\n", igmp_header->igmp_type, igmp_header->igmp_code);
      printf("Payload Size: (%d Bytes)\n", ((int)pkthdr->len-(*size)));
      print_payload(packet, ((int)pkthdr->len-(*size)));
      break;
  }
  return 0;
}

//Handles IPv4, primarily retrieving IP address information then passing it in turn.
unsigned int ipv4Handler(const struct ip * ipHeader, int * size){
  char sourceIP[INET_ADDRSTRLEN];
  char destinationIP[INET_ADDRSTRLEN];
  (*size) += sizeof(struct ip);
  inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIP, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ipHeader->ip_dst), destinationIP, INET_ADDRSTRLEN);
  printf("TTL: %d IP Protocol: %d ", ipHeader->ip_ttl, ipHeader->ip_p);
  printf("Source IP: %s Destination IP: %s\n", sourceIP, destinationIP);
  return ipHeader->ip_p;
}

//Handles ARP.
unsigned int arpHandler(const struct ether_arp * arpHeader){
  printf("Sender MAC: %x:%x:%x:%x:%x:%x ", arpHeader->arp_sha[0], arpHeader->arp_sha[1], arpHeader->arp_sha[2], arpHeader->arp_sha[3], arpHeader->arp_sha[4], arpHeader->arp_sha[5]);
  printf("Sender IP: %u.%u.%u.%u\n", arpHeader->arp_spa[0], arpHeader->arp_spa[1], arpHeader->arp_spa[2], arpHeader->arp_spa[3]);
  printf("Destination MAC: %x:%x:%x:%x:%x:%x ", arpHeader->arp_tha[0], arpHeader->arp_tha[1], arpHeader->arp_tha[2], arpHeader->arp_tha[3], arpHeader->arp_tha[4], arpHeader->arp_tha[5]);
  printf("Destination IP: %u.%u.%u.%u\n", arpHeader->arp_tpa[0], arpHeader->arp_tpa[1], arpHeader->arp_tpa[2], arpHeader->arp_tpa[3]);
}

//Handles IPv6. Passes the extension on to a function for extensions then returns only once it has moved beyond the extensions.
unsigned int ipv6Handler(const struct ip6_hdr * ip6Header, const unsigned char * packet, int * size){
  char sourceIP[INET6_ADDRSTRLEN];
  char destinationIP[INET6_ADDRSTRLEN];
  (*size) += sizeof(struct ip6_hdr);
  inet_ntop(AF_INET6, &(ip6Header->ip6_src), sourceIP, INET6_ADDRSTRLEN);
  inet_ntop(AF_INET6, &(ip6Header->ip6_dst), destinationIP, INET6_ADDRSTRLEN);
  int tProtocol = ipv6Ext(ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt, size, packet);
  printf("Source IP: %s Destination IP: %s\n", sourceIP, destinationIP);
  printf("TTL: %d Transport Protocol: %d\n", ip6Header->ip6_ctlun.ip6_un1.ip6_un1_hlim, ip6Header->ip6_ctlun.ip6_un1.ip6_un1_nxt);
  return tProtocol;
}

//Handles the IPv6 Extension headers. It attempts to catch the headers other than TCP and UDP so that they can be handled at a higher level.
unsigned int ipv6Ext(unsigned int extnum, int * size, const unsigned char * packet){
  switch(extnum){
    case IPPROTO_UDP://Ignore UDP which will be handled by method.
      break;
    case IPPROTO_TCP://Ignore TCP for the same reason as above.
      break;
    case IPPROTO_ICMP:
      break;
    case IPPROTO_HOPOPTS:
      printf("Hop-by-Hop Options\n");
      struct ip6_hbh * hop_header = (struct ip6_hbh *)(packet+(*size));//create the appropriate struct to store the data.
      (*size) += sizeof(struct ip6_hbh);//Update the value pointed to by size
      extnum = hop_header->ip6h_nxt;//Grab the next header
      extnum = ipv6Ext(extnum, size, packet);//retrieve the next header until a transport protocol is reached.
      break;
    case IPPROTO_DSTOPTS:
      printf("Destination Options\n");
      struct ip6_dest * dest_header = (struct ip6_dest *)(packet+(*size));
      (*size) += sizeof(struct ip6_dest);
      extnum = dest_header->ip6d_nxt;
      extnum = ipv6Ext(extnum, size, packet);
      break;
    case IPPROTO_ICMPV6:
      printf("ICMPv6\n");
      struct icmp6_hdr * icmp6_header = (struct icmp6_hdr *)(packet+(*size));
      (*size) += sizeof(struct icmp6_hdr);
      u_char * payload = (u_char *)(packet+sizeof(struct icmp6_hdr));
      printf("Type: %u Code: %u \n", icmp6_header->icmp6_type, icmp6_header->icmp6_code);
      break;
    case IPPROTO_ESP:
      printf("IPv6 Encap Sec. Payload\n");
      break;
    case IPPROTO_AH:
      printf("IPv6 Authentication Header\n");
      break;
    case IPPROTO_FRAGMENT:
      printf("IPv6 Fragment\n");
      struct ip6_frag * frag_header = (struct ip6_frag *)(packet+(*size));
      (*size) += sizeof(struct ip6_frag);
      extnum = frag_header->ip6f_nxt;
      extnum = ipv6Ext(extnum, size,packet);
      break;
    case IPPROTO_ROUTING:
      printf("IPv6 Routing\n");
      struct ip6_rthdr * routing_header = (struct ip6_rthdr *)(packet+(*size));
      printf("Routing Type: %u Segments Left: %u\n", routing_header->ip6r_type, routing_header->ip6r_segleft);
      (*size) += sizeof(struct ip6_rthdr);
      extnum = routing_header->ip6r_nxt;
      extnum = ipv6Ext(extnum, size, packet);
      break;
    default:
      printf("Unknown Extension Header\n");
  }
  return extnum;
}

//Handles the ethernet layer.
unsigned int etherHandler(const struct ether_header * eHeader, int * size){
  printf("Source MAC: %x:%x:%x:%x:%x:%x ",eHeader->ether_shost[0],eHeader->ether_shost[1],eHeader->ether_shost[2],eHeader->ether_shost[3],eHeader->ether_shost[4],eHeader->ether_shost[5]);
  printf("Destination MAC: %x:%x:%x:%x:%x:%x ",eHeader->ether_dhost[0],eHeader->ether_dhost[1],eHeader->ether_dhost[2],eHeader->ether_dhost[3],eHeader->ether_dhost[4],eHeader->ether_dhost[5]);
  printf("Protocol: 0x%x\n", ntohs(eHeader->ether_type));
  return ntohs(eHeader->ether_type);
}

//Handles the packet by passing it through various methods..
void packetHandler(unsigned char * userdata, const struct pcap_pkthdr * pkthdr, const unsigned char * packet){
  unsigned int ethType, tProtocol;
  const struct ether_header * ethernetHeader = (struct ether_header *)packet;
  int s = 0;
  int * size = &s;
  (*size) += sizeof(struct ether_header);
  printf("Packet #: %d\n", totalcount++);
  ethType = etherHandler(ethernetHeader, size);
  if(ethType == ETHERTYPE_IP){//IPv4
    printf("IPv4!\n");
    const struct ip * ipHeader = (struct ip *)(packet+(*size));
    tProtocol = ipv4Handler(ipHeader, size);
    transportHandler(packet, pkthdr, tProtocol, size);
  }
  else if(ethType == ETHERTYPE_ARP){//ARP
    printf("ARP!\n");
    const struct ether_arp * arpHeader = (struct ether_arp *)(packet+(*size));
    arpHandler(arpHeader);
  }
  else if(ethType == ETHERTYPE_IPV6){
    printf("IPv6!\n");
    const struct ip6_hdr * ipHeader = (struct ip6_hdr *)(packet+(*size));
    tProtocol = ipv6Handler(ipHeader, packet, size);
    transportHandler(packet, pkthdr, tProtocol, size);
  }
  printf("\n");
}

/*============================ Helper Methods ============================*/


//Sourced from: http://www.tcpdump.org/sniffex.c
/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}


//Sourced from: http://www.tcpdump.org/sniffex.c
/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len) {

    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

    return;
}

//Main method, starts the loop for each packet.
int main(int argc, char * argv[]){
  char * file;
  char error_buf[PCAP_ERRBUF_SIZE];
  pcap_t * handle = pcap_open_offline(argv[1], error_buf);//Argument during command for file read.
  if(handle == NULL){//Close if you can't open
    printf("Could not open file using PCAP.");
    exit(1);
  }
  //Main loop for this.
  if(argc == 3){
        if(pcap_loop(handle, atoi(argv[2]), packetHandler, NULL) < 0){
            printf("Some error has occured while processing the packets!\n");
            printf("%s\n", pcap_geterr(handle));
            return 1;
        }
    }
   /** else{
        if(pcap_loop(handle, 100, packetHandler, NULL) < 0){
            printf("Some error has occured while processing the packets!\n");
            printf("%s\n", pcap_geterr(handle));
            return 1;
        }
    }  */
  printf("Packet Read complete.\n");
  return 0;
}
