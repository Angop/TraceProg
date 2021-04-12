/* Angela Kerlin
 * CPE 464-01
 * Program 1 Trace */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdint.h>

# define MACSIZE 6
# define IPSIZE 4
# define ARPCODE 2054
# define IPCODE 2048
# define ICMPCODE 1
# define TCPCODE 6
# define UDPCODE 17
# define ETH_LEN 14
# define ICMP_REPLY 0
# define ICMP_REQ 8
# define HTTPPORT 80
# define BUFSIZE 10000
# define PSEUDOLEN 12

/* Structs for each header type */
typedef struct EthernetHeader *ethernetHeader;
struct EthernetHeader {
   uint8_t dest[MACSIZE];
   uint8_t src[MACSIZE];
   uint16_t nextType;
}__attribute__((packed));

typedef struct ArpHeader *arpHeader;
struct ArpHeader {
   uint16_t opcode;
   uint8_t senderMac[MACSIZE];
   uint8_t targetMac[MACSIZE];
   uint8_t senderIp[IPSIZE];
   uint8_t targetIp[IPSIZE];
}__attribute__((packed));

typedef struct IpHeader *ipHeader;
struct IpHeader {
   uint8_t headerLen;
   uint16_t tos;
   uint8_t ttl;
   uint16_t pduLen;
   uint8_t protocol;
   uint16_t checksum;
   uint16_t checksumVer; // value of my checksum calculation
   uint8_t senderIp[IPSIZE];
   uint8_t destIp[IPSIZE];
}__attribute__((packed));

typedef struct IcmpHeader *icmpHeader;
struct IcmpHeader {
   uint8_t type;
}__attribute__((packed));

typedef struct TcpHeader *tcpHeader;
struct TcpHeader {
   uint16_t srcPort;
   uint16_t destPort;
   uint32_t seqNum;
   uint32_t ackNum;
   uint16_t ackFlag;
   uint16_t synFlag;
   uint16_t rstFlag;
   uint16_t finFlag;
   uint16_t winSize;
   uint16_t checksum;
   uint16_t checksumVer;
}__attribute__((packed));

typedef struct UdpHeader *udpHeader;
struct UdpHeader {
   uint16_t srcPort;
   uint16_t destPort;
}__attribute__((packed));

void processPackets(pcap_t *pc);
void processPacket(struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
void verifyTCPChecksum(tcpHeader tcph, const u_char *pkt_data, int offset, ipHeader iph);

void parseEthernet(ethernetHeader eh, const u_char *pkt_data);
void parseARP(arpHeader arph, const u_char *pkt_data);
void parseIP(ipHeader iph, const u_char *pkt_data);
void parseICMP(icmpHeader icmph, const u_char *pkt_data, int offset);
void parseTCP(tcpHeader tcph, const u_char *pkt_data, int offset, ipHeader iph);
void parseUDP(udpHeader udph, const u_char *pkt_data, int offset);

void printEthernet(ethernetHeader eh);
void printARP(arpHeader arph);
void printIP(ipHeader iph);
void printICMP(icmpHeader icmph);
void printTCP(tcpHeader tcph);
void printUDP(udpHeader udph);
void printEtherType(uint16_t numType);
void printIpType(uint8_t numType);
void printChkHeader(uint8_t *chkheader);



int main(int argc, char *argv[]) {
   
   /* Open pcap file */
   pcap_t *pc;
   if (argc == 2) {
      /* open the pcap file */
      char errbuf[PCAP_ERRBUF_SIZE];
      if (!(pc=pcap_open_offline(argv[1], errbuf))) {
         fprintf(stderr, errbuf);
         fprintf(stderr, "\n");
         exit(0);
      }
   }

   else {
      /* invalid trace format */
      fprintf(stderr, "main: invalid trace format\n");
      exit(0);
   }

   processPackets(pc);

   pcap_close(pc);
   return 1;
}

void processPackets(pcap_t *pc) {
   int packetCount = 1;

   // process each packet
   int res = 0;
   struct pcap_pkthdr *pkt_header = NULL;
   const u_char *pkt_data = NULL;
   while ((res=pcap_next_ex(pc, &pkt_header, &pkt_data)) == 1) {
      printf("Packet number: %u  Frame Len: %u\n\n", packetCount, pkt_header->len);
      processPacket(pkt_header, pkt_data);
      packetCount++;
   }
   if (res == -1 || res == 0) {
      // Error occured
      pcap_perror(pc, "processPackets");
      exit(0);
   }
   // No packets left to read
}


void processPacket(struct pcap_pkthdr *pkt_header, const u_char *pkt_data) {
   struct EthernetHeader ethh;
   parseEthernet(&ethh, pkt_data);
   printEthernet(&ethh);
   
   if (ethh.nextType == ARPCODE) {
      // Arp header follows
      struct ArpHeader arph;
      parseARP(&arph, pkt_data);
      printARP(&arph);
   }
   else if (ethh.nextType == IPCODE) {
      // IP header follows
      struct IpHeader iph;
      parseIP(&iph, pkt_data);
      printIP(&iph);

      switch(iph.protocol) {
         case ICMPCODE: ;
            // ICMP
            struct IcmpHeader icmph;
            parseICMP(&icmph, pkt_data, ETH_LEN + iph.headerLen);
            printICMP(&icmph);
            break;
         case TCPCODE: ;
            // TCP
            struct TcpHeader tcph;
            parseTCP(&tcph, pkt_data, ETH_LEN + iph.headerLen, &iph);
            printTCP(&tcph);
            break;
         case UDPCODE: ;
            // UDP
            struct UdpHeader udph;
            parseUDP(&udph, pkt_data, ETH_LEN + iph.headerLen);
            printUDP(&udph);
            break;
         default:
            break;
      }
   }
   // else, unsupported header follows, do nothing
}

void parseEthernet(ethernetHeader eh, const u_char *pkt_data) {
   memcpy(&(eh->dest), pkt_data, MACSIZE);
   memcpy(&(eh->src), pkt_data + 6, MACSIZE);
   memcpy(&(eh->nextType), pkt_data + 12, sizeof(uint16_t));
   eh->nextType = ntohs(eh->nextType); // convert to host order
}

void printEthernet(ethernetHeader eh) {
   struct ether_addr temp;
   printf("\tEthernet Header\n");
   printf("\t\tDest MAC: ");
   memcpy(temp.ether_addr_octet, &(eh->dest), MACSIZE);
   printf(ether_ntoa(&temp));
   printf("\n\t\tSource MAC: ");
   memcpy(temp.ether_addr_octet, &(eh->src), MACSIZE);
   printf(ether_ntoa(&temp));
   printf("\n\t\tType: "); 
   printEtherType((eh->nextType));
   printf("\n\n");
}

void parseARP(arpHeader arph, const u_char *pkt_data) {
   int offset = ETH_LEN;
   memcpy(&(arph->opcode), pkt_data + (offset += 7), sizeof(uint16_t));
   memcpy(&(arph->senderMac), pkt_data + (offset=offset + 1), MACSIZE);
   memcpy(&(arph->senderIp), pkt_data + (offset=offset + 6), IPSIZE);
   memcpy(&(arph->targetMac), pkt_data + (offset=offset + 4), MACSIZE);
   memcpy(&(arph->targetIp), pkt_data + (offset=offset + 6), IPSIZE);
}

void printARP(arpHeader arph) {
   struct ether_addr mac;
   struct in_addr ip;
   printf("\tARP header\n");
   printf("\t\tOpcode: ");
   printf(((arph->opcode == 1) ? "Request\n" : 
      ((arph->opcode == 2) ? "Reply\n" : "Unsupported opcode\n")));

   printf("\t\tSender MAC: ");
   memcpy(mac.ether_addr_octet, &(arph->senderMac), MACSIZE);
   printf(ether_ntoa(&mac));
   printf("\n\t\tSender IP: ");
   memcpy(&(ip.s_addr), &(arph->senderIp), IPSIZE);
   printf(inet_ntoa(ip));
   printf("\n\t\tTarget MAC: ");
   memcpy(mac.ether_addr_octet, &(arph->targetMac), MACSIZE);
   printf(ether_ntoa(&mac));
   printf("\n\t\tTarget IP: ");
   memcpy(&(ip.s_addr), &(arph->targetIp), IPSIZE);
   printf(inet_ntoa(ip));
   printf("\n\n");
}

void parseIP(ipHeader iph, const u_char *pkt_data) {
   uint8_t hlen = pkt_data[ETH_LEN];
   hlen = 4 * (hlen & 0x0F); // hlen is in the last half of byte
   iph->headerLen = hlen;

   iph->tos = pkt_data[ETH_LEN + 1];
   memcpy(&(iph->pduLen), pkt_data + ETH_LEN + 2, sizeof(uint16_t));
   iph->pduLen = ntohs(iph->pduLen);
   iph->ttl = pkt_data[ETH_LEN + 8];
   iph->protocol = pkt_data[ETH_LEN + 9];
   
   // checksum
   memcpy(&(iph->checksum), pkt_data + ETH_LEN + 10, sizeof(uint16_t));
   iph->checksumVer = in_cksum(pkt_data + ETH_LEN, hlen);
   
   memcpy(&(iph->senderIp), pkt_data + ETH_LEN + 12, IPSIZE);
   memcpy(&(iph->destIp), pkt_data + ETH_LEN + 16, IPSIZE);
}

void printIP(ipHeader iph) {
   struct in_addr ip;
   printf("\tIP Header\n");
   printf("\t\tHeader Len: %u (bytes)\n", iph->headerLen);
   printf("\t\tTOS: 0x%x\n", iph->tos);
   printf("\t\tTTL: %u\n", iph->ttl);
   printf("\t\tIP PDU Len: %u (bytes)\n", iph->pduLen);
   printf("\t\tProtocol: ");
   printIpType(iph->protocol);
   printf("\n\t\tChecksum: %s (0x%x)\n", ((iph->checksumVer) == 0 ? "Correct" : "Incorrect"), iph->checksum);

   printf("\t\tSender IP: ");
   memcpy(&(ip.s_addr), &(iph->senderIp), IPSIZE);
   printf(inet_ntoa(ip));
   printf("\n\t\tDest IP: ");
   memcpy(&(ip.s_addr), &(iph->destIp), IPSIZE);
   printf(inet_ntoa(ip));
   printf("\n\n");

}

void parseICMP(icmpHeader icmph, const u_char *pkt_data, int offset) {
   icmph->type = pkt_data[offset];
}


void printICMP(icmpHeader icmph) {
   printf("\tICMP Header\n");
   printf("\t\tType: ");
   if (icmph->type == ICMP_REPLY) {
      printf("Reply\n\n");
   }
   else if (icmph->type == ICMP_REQ) {
      printf("Request\n\n");
   }
   else {
      printf("%d\n\n", icmph->type);
   }
}

void parseTCP(tcpHeader tcph, const u_char *pkt_data, int offset, ipHeader iph) {
   memcpy(&(tcph->srcPort), pkt_data + offset, sizeof(uint16_t));
   tcph->srcPort = ntohs(tcph->srcPort);
   memcpy(&(tcph->destPort), pkt_data + offset + 2, sizeof(uint16_t));
   tcph->destPort = ntohs(tcph->destPort);
   memcpy(&(tcph->seqNum), pkt_data + offset + 4, sizeof(uint32_t));
   tcph->seqNum = ntohl(tcph->seqNum);
   memcpy(&(tcph->ackNum), pkt_data + offset + 8, sizeof(uint32_t));
   tcph->ackNum = ntohl(tcph->ackNum);
   uint16_t flags = 0;
   memcpy(&flags, pkt_data + offset + 12, sizeof(uint16_t));
   flags = ntohs(flags);
   tcph->ackFlag = flags & 0x0010; // each flag is and with the position of corresponding bit
   tcph->synFlag = flags & 0x0002;
   tcph->rstFlag = flags & 0x0004;
   tcph->finFlag = flags & 0x0001;
   memcpy(&(tcph->winSize), pkt_data + offset + 14, sizeof(uint16_t));
   tcph->winSize = ntohs(tcph->winSize);
   memcpy(&(tcph->checksum), pkt_data + offset + 16, sizeof(uint16_t));
   tcph->checksum = ntohs(tcph->checksum);
   verifyTCPChecksum(tcph, pkt_data, offset, iph);
}


void printTCP(tcpHeader tcph) {
   printf("\tTCP Header\n");
   printf("\t\tSource Port: ");
   if (tcph->srcPort == HTTPPORT) {
      printf("HTTP\n");
   }
   else {
      printf(": %u\n", tcph->srcPort);
   }
   printf("\t\tDest Port: ");
   if (tcph->destPort == HTTPPORT) {
      printf("HTTP\n");
   }
   else {
      printf(": %u\n", tcph->destPort);
   }
   printf("\t\tSequence Number: %u\n", tcph->seqNum);
   printf("\t\tACK Number: ");
   if (tcph->ackFlag) {
      printf("%u\n", tcph->ackNum);
   }
   else {
      printf("<not valid>\n");
   }
   printf("\t\tACK Flag: %s\n", (tcph->ackFlag ? "Yes" : "No"));
   printf("\t\tSYN Flag: %s\n", (tcph->synFlag ? "Yes" : "No"));
   printf("\t\tRST Flag: %s\n", (tcph->rstFlag ? "Yes" : "No"));
   printf("\t\tFIN Flag: %s\n", (tcph->finFlag ? "Yes" : "No"));
   printf("\t\tWindow Size: %u\n", tcph->winSize);
   printf("\t\tChecksum: %s (0x%x)\n\n",
      (tcph->checksumVer == tcph->checksum ? "Correct" : "Incorrect"), tcph->checksum);
}

void parseUDP(udpHeader udph, const u_char *pkt_data, int offset) {
   memcpy(&(udph->srcPort), pkt_data + offset, sizeof(uint16_t));
   udph->srcPort = ntohs(udph->srcPort);
   memcpy(&(udph->destPort), pkt_data + offset + 2, sizeof(uint16_t));
   udph->destPort = ntohs(udph->destPort);
}
void printUDP(udpHeader udph) {
   printf("\tUDP Header\n");
   printf("\t\tSource Port: : %u\n", udph->srcPort);
   printf("\t\tDest Port: : %u\n\n", udph->destPort);
}

void verifyTCPChecksum(tcpHeader tcph, const u_char *pkt_data, int offset, ipHeader iph) {
   // create the pseudo header
   uint8_t chkheader[BUFSIZE] = {0};
   uint16_t totalLen;
   totalLen = iph->pduLen - iph->headerLen;
   totalLen = htons(totalLen); // not sure if this is the correct total len, its just header len

   memcpy(chkheader, &(iph->senderIp), IPSIZE);
   memcpy(chkheader + 4, &(iph->destIp), IPSIZE);
   chkheader[8] = 0;
   chkheader[9] = iph->protocol;
   memcpy(chkheader + 10, &totalLen, sizeof(uint16_t));

   // copy over the tcp header and data
   memcpy(chkheader + PSEUDOLEN, pkt_data + offset, (size_t)ntohs(totalLen));
   uint16_t zero = 0;
   memcpy(chkheader + PSEUDOLEN + 16, &zero, sizeof(uint16_t)); // set checksum in tcp psuedo header to zero
   tcph->checksumVer = ntohs(in_cksum(chkheader, PSEUDOLEN + ntohs(totalLen)));
}

void printChkHeader(uint8_t *chkheader) {
   // prints the psuedo header in hexidecimal, for testing purposes
   printf("\n\n");
   int i;
   for(i = 0; i < BUFSIZE; i++) {
      printf("%02x ", chkheader[i]);
      if (i % 8 == 0) {
         printf("  ");
      }
      if (i % 32 == 0) {
         printf("\n");
      }
   }
   printf("\n\n");
}

void printEtherType(uint16_t numType){
   switch(numType) {
      case IPCODE:
         printf("IP");
         break;
      case ARPCODE:
         printf("ARP");
         break;
      default:
         printf("unsupported type: hex: %x\n", numType);
         break;
   }
}

void printIpType(uint8_t numType){
   switch(numType) {
      case ICMPCODE:
         printf("ICMP");
         break;
     case TCPCODE: 
         printf("TCP");
         break;
     case UDPCODE: 
         printf("UDP");
         break;
      default:
         printf("Unknown");
         break;
   }
}











