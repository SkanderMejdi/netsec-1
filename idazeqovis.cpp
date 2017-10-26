#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>


struct arpHdr {
  unsigned short int htype;          // Hardware type
  unsigned short int ptype;          // Protocol type
  unsigned char hlen;               // Hardware address length
  unsigned char plen;               // Protocol address length
  unsigned short int oper;           // ARP operation
  unsigned char sha[6];          // Sender hardware address.
  unsigned char spa[4];          // Sender protocol address.
  unsigned char tha[6];          // Target hardware address.
  unsigned char tpa[4];          // Target protocol address.
} __attribute__ ((packed));        // Les variables de la structure se suivent dans la mÃ©moire (pas "d'espace vide")

struct ethHdr{
  u_int8_t tha[6];                // Target hardware address
  u_int8_t sha[6];                // Source hardware address
  u_int16_t type;                 // Type/Length
} __attribute__ ((packed));

struct arpFull{
  struct ethHdr eth;                      // Ethernet packet information
  struct arpHdr arp;                      // ARP packet information
} arp;

void fill_header_request(char *srcip, char *dstip){
  int broadcastAddr[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; // FF:FF:FF:FF:FF:FF
  struct in_addr src, dst; // Needed to convert the IP with inet_addr

  memcpy(arp.arp.tha, broadcastAddr, 6); // Set the target hardware address in the ARP
  memcpy(arp.eth.tha, broadcastAddr, 6); // Same for the Ethernet protocol

  arp.eth.type = htons(ETH_P_ARP); // 0x0806 ARP protocol ID

  // now our Ethernet Packet is ready

  arp.arp.htype = htons(1); // 0x1 Ethernet Type
  arp.arp.ptype = htons(ETH_P_IP); // 0x0800 IP packets only
  arp.arp.hlen = 6;
  arp.arp.plen = 4;
  arp.arp.oper = htons(1); // 1 For request, 2 for reply (see previous Wiki page)

  src.s_addr = inet_addr(srcip);
  dst.s_addr = inet_addr(dstip);

  memcpy(&arp.arp.spa, (unsigned char *)&src.s_addr, 4); // Set the source IP address
  memcpy(&arp.arp.tpa, (unsigned char *)&dst.s_addr, 4); // Same for the target

}


void fill_header_reply(char *srcip, char *dstip, char *dsthwd){
  struct in_addr src, dst; // Needed to convert the IP with inet_addr
  char hardwareAddr[6] = {0};
  int i;
  for(i=0; i<6 ;i++){
    char *next;
    hardwareAddr[i] = strtol(dsthwd, &next, 16); // Hex value of char between ":"
    dsthwd=++next; // The next one
  }

  memcpy(arp.eth.tha, hardwareAddr, 6); // Set ther hardware address in Ethernet
  memcpy(arp.arp.tha, hardwareAddr, 6); // Same for ARP protocol

  arp.eth.type = htons(ETH_P_ARP); // 0x0806 ARP protocol ID

  arp.arp.htype = htons(1); // 0x1 Ethernet Type
  arp.arp.ptype = htons(ETH_P_IP); // 0x0800 IP packets only
  arp.arp.hlen = 6;
  arp.arp.plen = 4;
  arp.arp.oper = htons(2); // 1 For request, 2 for reply (see previous Wiki page)

  src.s_addr = inet_addr(srcip);
  dst.s_addr = inet_addr(dstip);

  memcpy(&arp.arp.spa, (unsigned char *)&src.s_addr, 4);
  memcpy(&arp.arp.tpa, (unsigned char *)&dst.s_addr, 4);

}


int sendArp(char *iface){
  struct sockaddr_ll device;
  struct ifreq ifr;
  int sockfd;
  char buffer[1024];

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  strncpy(ifr.ifr_name, iface, IFNAMSIZ); // Set the interface name (and fill with 0)
  ioctl(sockfd, SIOCGIFINDEX, &ifr);
  device.sll_ifindex = ifr.ifr_ifindex; // iface index
  ioctl(sockfd, SIOCGIFHWADDR, &ifr);
  memcpy(device.sll_addr, ifr.ifr_hwaddr.sa_data, 6); // iface hardware address

  device.sll_family = AF_PACKET; // Always AF_PACKET
  device.sll_protocol = htons(ETH_P_IP); //  0x0800 IP packets only
  device.sll_hatype = 1; // 0x1 (Ethernet hardware address)
  device.sll_halen = 6;


  /* Now our device structure is ready, we need to fill the sender information in ARP and Ethernet header */

  memcpy(arp.arp.sha, ifr.ifr_hwaddr.sa_data, 6); // Set the sender Mac address in ARP
  memcpy(arp.eth.sha, ifr.ifr_hwaddr.sa_data, 6); // Same for Ethernet

  close(sockfd); // We want to use it again

  if((sockfd = socket( PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
  {
    printf("SOCKET FAILED\n");
    return 1;
  }
  /*
  This is the most interesting point, let's see how it works
  PF_PACKET : Low level packet interface
  SOCK_RAW : Provides raw network protocol access.
  ETH_P_ARP : ARP protocol
  Now we have a raw socket and we can put everything we want in it !
  The kernel doesn't do anything with your packet, it's all yours
  */
  memcpy(buffer, &arp, sizeof(struct arpFull)); // Copy our structure (ARP header and EThernet Header to the buffer);
  if(sendto(sockfd, buffer, sizeof(struct arpFull), 0, (struct sockaddr *)&device, (socklen_t) sizeof(struct sockaddr_ll)) == -1){
    printf("Error");
    return 1;
  }

}

int main(int argc, char *argv[]){
  fill_header_request(argv[1], argv[2]); // argv[1] -> source IP (your IP) argv[2] -> destination IP (your target)
  sendArp("wlo1"); // Change the device name
  return 0;
}
