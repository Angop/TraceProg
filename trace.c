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


/* Structs for each header type */
typedef struct EthernetHeader *ethernetHeader;
struct EthernetHeader {
   uint8_t dest[6];
   uint8_t src[6];
   uint16_t nextType;
}__attribute__((packed));

typedef struct ArpHeader *arpHeader;
struct ArpHeader {
   uint16_t opcode;
   uint8_t senderMac[6];
   uint8_t targetMac[6];
   uint8_t senderIp[4];
   uint8_t targetIp[4];
}__attribute__((packed));

typedef struct IpHeader *ipHeader;
struct IpHeader {
   uint8_t headerLen;
   uint16_t tos;
   uint8_t ttl;
   uint16_t pduLen;
   uint8_t protocol;
   uint16_t checksum;
   int checksumVer; // 0 is correct, else fail
   uint8_t senderIp[4];
   uint8_t destIp[4];
}__attribute__((packed));

typedef struct IcmpHeader *icmpHeader;
struct IcmpHeader {
   uint8_t type;
}__attribute__((packed));

typedef struct TcpHeader *tcpHeader;
struct TcpHeader {
   uint16_t srcPort;
   uint16_t destPort;
   uint32_t seqNum; // no htons
   uint32_t ackNum; // no htons
   uint16_t ackFlag;
   uint16_t synFlag;
   uint16_t rstFlag;
   uint16_t finFlag;
   uint16_t winSize;
   uint16_t checksum;
   uint8_t checksumVer;
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
void printEtherType(uint16_t numType, char *type);
void printIpType(uint8_t numType);



int main(int argc, char *argv[]) {
   
   /* Open pcap file dd encapsulate in function? */
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
      // TODO
      printf("Packet number: %u  Frame Len: %u\n\n", packetCount, pkt_header->len); // TODO get right frame size
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
   // TODO
   struct EthernetHeader ethh;
   parseEthernet(&ethh, pkt_data);
   printEthernet(&ethh);
   
   if (ethh.nextType == 2054) {
      // Arp header follows
      struct ArpHeader arph;
      parseARP(&arph, pkt_data);
      printARP(&arph);
   }
   else if (ethh.nextType == 2048) {
      // IP header follows
      struct IpHeader iph;
      parseIP(&iph, pkt_data);
      printIP(&iph);

      switch(iph.protocol) {
         case 1: ;
            // ICMP
            struct IcmpHeader icmph;
            parseICMP(&icmph, pkt_data, 14 + iph.headerLen);
            printICMP(&icmph);
            break;
         case 6: ;
            struct TcpHeader tcph;
            parseTCP(&tcph, pkt_data, 14 + iph.headerLen, &iph);
            printTCP(&tcph);
            break;
         case 17: ;
            struct UdpHeader udph;
            parseUDP(&udph, pkt_data, 14 + iph.headerLen);
            printUDP(&udph);
            break;
         default:
            break;
      }
      
   }
   // else, unsupported header follows, do nothing
}

void parseEthernet(ethernetHeader eh, const u_char *pkt_data) {
   // TODO: fix magic numbers
   memcpy(&(eh->dest), pkt_data, 6 * sizeof(uint8_t));
   memcpy(&(eh->src), pkt_data + 6, 6 * sizeof(uint8_t));
   memcpy(&(eh->nextType), pkt_data + 12, 2);
   eh->nextType = ntohs(eh->nextType); // convert to host order
}

void printEthernet(ethernetHeader eh) {
   // TODO: not printing things like 02 correctly
   struct ether_addr temp;
   char type[5] = { 0 };
   printf("\tEthernet Header\n");
   printf("\t\tDest MAC: ");
   memcpy(temp.ether_addr_octet, &(eh->dest), 6);
   printf(ether_ntoa(&temp));
   printf("\n\t\tSource MAC: ");
   memcpy(temp.ether_addr_octet, &(eh->src), 6);
   printf(ether_ntoa(&temp));
   printf("\n\t\tType: "); 
   printEtherType((eh->nextType), type);
   printf("\n\n");
}

void parseARP(arpHeader arph, const u_char *pkt_data) {
   int offset = 14;
   memcpy(&(arph->opcode), pkt_data + (offset += 7), 2 * sizeof(uint8_t));
   memcpy(&(arph->senderMac), pkt_data + (offset=offset + 1), 6 * sizeof(uint8_t));
   memcpy(&(arph->senderIp), pkt_data + (offset=offset + 6), 4 * sizeof(uint8_t));
   memcpy(&(arph->targetMac), pkt_data + (offset=offset + 4), 6 * sizeof(uint8_t));
   memcpy(&(arph->targetIp), pkt_data + (offset=offset + 6), 4 * sizeof(uint8_t));
}

void printARP(arpHeader arph) {
   struct ether_addr mac;
   struct in_addr ip;
   printf("\tARP header\n");
   printf("\t\tOpcode: ");
   printf(((arph->opcode == 1) ? "Request\n" : 
      ((arph->opcode == 2) ? "Reply\n" : "Unsupported opcode\n")));

   printf("\t\tSender MAC: ");
   memcpy(mac.ether_addr_octet, &(arph->senderMac), 6);
   printf(ether_ntoa(&mac));
   printf("\n\t\tSender IP: ");
   memcpy(&(ip.s_addr), &(arph->senderIp), 4);
   printf(inet_ntoa(ip));
   printf("\n\t\tTarget MAC: ");
   memcpy(mac.ether_addr_octet, &(arph->targetMac), 6);
   printf(ether_ntoa(&mac));
   printf("\n\t\tTarget IP: ");
   memcpy(&(ip.s_addr), &(arph->targetIp), 4);
   printf(inet_ntoa(ip));
   printf("\n\n");
}

void parseIP(ipHeader iph, const u_char *pkt_data) {
   // TODO magic numbers
   int offset = 14;
   uint8_t hlen = pkt_data[offset];
   hlen = 4 * (hlen & 0x0F);
   iph->headerLen = hlen;

   iph->tos = pkt_data[offset + 1];
   iph->ttl = pkt_data[offset + 8];
   memcpy(&(iph->pduLen), pkt_data + offset + 2, 2);
   iph->pduLen = ntohs(iph->pduLen);
   iph->protocol = pkt_data[offset + 9];
   
   // checksum
   memcpy(&(iph->checksum), pkt_data + offset + 10, 2);
   // TODO checksum check probably not working right
   iph->checksumVer = in_cksum(pkt_data + 14, hlen);
   
   memcpy(&(iph->senderIp), pkt_data + offset + 12, 4);
   memcpy(&(iph->destIp), pkt_data + offset + 16, 4);
}

void printIP(ipHeader iph) {
   // TODO
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
   memcpy(&(ip.s_addr), &(iph->senderIp), 4);
   printf(inet_ntoa(ip));
   printf("\n\t\tDest IP: ");
   memcpy(&(ip.s_addr), &(iph->destIp), 4);
   printf(inet_ntoa(ip));
   printf("\n\n");

}

void parseICMP(icmpHeader icmph, const u_char *pkt_data, int offset) {
   icmph->type = pkt_data[offset];
}

void printICMP(icmpHeader icmph) {
   printf("\tICMP Header\n");
   printf("\t\tType: ");
   if (icmph->type == 0) {
      printf("Reply\n\n");
   }
   else if (icmph->type == 8) {
      printf("Request\n\n");
   }
   else {
      printf("%d\n\n", icmph->type);
   }
}

void parseTCP(tcpHeader tcph, const u_char *pkt_data, int offset, ipHeader iph) {
   //TODO
   memcpy(&(tcph->srcPort), pkt_data + offset, 2);
   tcph->srcPort = ntohs(tcph->srcPort);
   memcpy(&(tcph->destPort), pkt_data + offset + 2, 2);
   tcph->destPort = ntohs(tcph->destPort);
   memcpy(&(tcph->seqNum), pkt_data + offset + 4, 4);
   tcph->seqNum = ntohl(tcph->seqNum);
   memcpy(&(tcph->ackNum), pkt_data + offset + 8, 4);
   tcph->ackNum = ntohl(tcph->ackNum);
   uint16_t flags = 0;
   memcpy(&flags, pkt_data + offset + 12, 2);
   flags = ntohs(flags);
   tcph->ackFlag = flags & 0x0010;
   tcph->synFlag = flags & 0x0002;
   tcph->rstFlag = flags & 0x0004;
   tcph->finFlag = flags & 0x0001;
   memcpy(&(tcph->winSize), pkt_data + offset + 14, 2);
   tcph->winSize = ntohs(tcph->winSize);
   memcpy(&(tcph->checksum), pkt_data + offset + 16, 2);
   tcph->checksum = ntohs(tcph->checksum);
   verifyTCPChecksum(tcph, pkt_data, offset, iph);
}

void printTCP(tcpHeader tcph) {
   printf("\tTCP Header\n");
   printf("\t\tSource Port: ");
   if (tcph->srcPort == 80) {
      printf("HTTP\n");
   }
   else {
      printf(": %u\n", tcph->srcPort);
   }
   printf("\t\tDest Port: ");
   if (tcph->destPort == 80) {
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
   printf("\t\tChecksum: %s (%d) (0x%x)\n\n", ((tcph->checksumVer) == 0 ? "Correct" : "Incorrect"),tcph->checksumVer, tcph->checksum);
}

void parseUDP(udpHeader udph, const u_char *pkt_data, int offset) {
   memcpy(&(udph->srcPort), pkt_data + offset, 2);
   udph->srcPort = ntohs(udph->srcPort);
   memcpy(&(udph->destPort), pkt_data + offset + 2, 2);
   udph->destPort = ntohs(udph->destPort);
}
void printUDP(udpHeader udph) {
   printf("\tUDP Header\n");
   printf("\t\tSource Port: : %u\n", udph->srcPort);
   printf("\t\tDest Port: : %u\n\n", udph->destPort);
}


void verifyTCPChecksum(tcpHeader tcph, const u_char *pkt_data, int offset, ipHeader iph) {
   // TODO worry about network order
   // create the pseudo header
   uint8_t chkheader[1000] = {0};
   uint16_t totalLen;
   memcpy(&totalLen, pkt_data + offset + 12, 2);
   totalLen = ((totalLen >> 12) * 4) + pkt_data[offset + 9]; // header len + segment len
   memcpy(chkheader, &(iph->senderIp), 4);
   memcpy(chkheader + 4, &(iph->destIp), 4);
   chkheader[8] = 0;
   chkheader[9] = iph->protocol;
   memcpy(chkheader + 10, &totalLen, 2);

   // copy over the tcp header and data
   memcpy(chkheader + 12, pkt_data + offset, totalLen); 
   tcph->checksumVer = in_cksum(chkheader, 12 + totalLen);
   printf("CHECKSUMVER VAL: %d",tcph->checksumVer);
}

void printEtherType(uint16_t numType, char *type){ // DO I STILL NEED TYPE FIELD?? dd
   // TODO magic numbers
   switch(numType) {
      case 2048:
         printf("IP");
         break;
      case 2054:
         printf("ARP");
         break;
      default:
         printf("unsupported type: hex: %x\n", numType);
         break;
   }
}

void printIpType(uint8_t numType){
   switch(numType) {
      case 1:
         printf("ICMP");
         break;
     case 6: 
         printf("TCP");
         break;
     case 17: 
         printf("UDP");
         break;
      default:
         printf("Unknown");
         break;
   }
}











