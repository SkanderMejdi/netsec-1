#include <stdlib.h> 
#include <sys/types.h>
#include <stdint.h>
#include<stdio.h>
#include <time.h> 
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> 
#include<stdlib.h>   
#include<string.h>  
#include<netinet/ip_icmp.h> 
#include<netinet/udp.h>   
#include<netinet/tcp.h>  
#include<netinet/ip.h>   
#include<netinet/if_ether.h>  
#include<net/ethernet.h> 
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>

typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */  
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t ;


void print_pcaphdr(pcap_hdr_t *header)
{
    printf("magic = %x\n", header->magic_number);
    printf("minor =%x\n", header->version_major);
    printf("major = %x\n", header->version_minor);
    printf("thiszone =%x\n", header->thiszone);
    printf("snaplen = %x\n", header->snaplen);
    printf("network = %x\n", header->network);
}
void print_pcaprec(pcaprec_hdr_t *header_rec)
{
    printf("ts_sec = %x\n", header_rec->ts_sec);
    printf("ts_usec = %x\n", header_rec->ts_usec);
    printf("incl = %x\n", header_rec->incl_len);
    printf("orig = %x\n", header_rec->orig_len);
}

static void print_eth(struct ethhdr *eth)
{
    printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : %u\n",(unsigned short)eth->h_proto);
}

static void print_ip_header(struct iphdr *ip_header,  struct sockaddr_in *source,  struct sockaddr_in *dest )
{

    printf("IP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)ip_header->version);
    printf("   |-IP Header Length  : %d Bytes\n",((unsigned int)(ip_header->ihl))*4);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(ip_header->tot_len));
    printf("   |-Identification    : %d\n",ntohs(ip_header->id));
    printf("   |-Protocol : %d\n",(unsigned int)ip_header->protocol);
    printf("   |-TTL      : %d\n",(unsigned int)ip_header->ttl);
    printf("   |-Type Of Service   : %d\n",(unsigned int)ip_header->tos);
    printf("   |-Checksum : %d\n",ntohs(ip_header->check));
    printf("   |-Source IP        : %s\n",inet_ntoa(source->sin_addr));
    printf("   |-Destination IP   : %s\n",inet_ntoa(dest->sin_addr));
}

static void print_udp_packet(struct udphdr *udp_header)
{
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udp_header->source));
    printf("   |-Destination Port : %d\n" , ntohs(udp_header->dest));
    printf("   |-UP Length       : %d\n" , ntohs(udp_header->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udp_header->check));
} 

static void print_icmp_packet(struct icmphdr *icmp_header)
{
     printf("\nICMP Header\n");
    printf("   |-Type : %d",(unsigned int)(icmp_header->type));
    if ((unsigned int)(icmp_header->type) == 11)
        printf("  (TTL Expired)\n");
    else if ((unsigned int)(icmp_header->type) == ICMP_ECHOREPLY)
        printf("  (ICMP Echo Reply)\n");
    printf("   |-Code : %d\n",(unsigned int)(icmp_header->code));
    printf("   |-Checksum : %x\n",ntohs(icmp_header->checksum));
}
int read_pcap(char *pcap_file)
{
   pcap_hdr_t header;
   char *str;
   struct iphdr ip_header;
   pcaprec_hdr_t header_rec;
   struct ethhdr eth;
   struct sockaddr_in source, dest;
   struct tcphdr tcp_header;
   struct udphdr udp_header;
   struct icmphdr icmp_header;
   FILE * fp;
   int size;
   fp = fopen(pcap_file, "r");
   if( fp == NULL) 
    {
        printf("Unable to  file.\n");
        exit(1);
    }
    printf("file opened\n");
    fseek(fp, 0, SEEK_SET);
    fread(&header, sizeof(pcap_hdr_t), 1, fp);
    print_pcaphdr(&header);
    while (fread(&header_rec, sizeof(pcaprec_hdr_t), 1, fp)){
    size = 0;
    print_pcaprec(&header_rec);
    fread(&eth, sizeof(struct ethhdr), 1, fp);
    print_eth(&eth);
    fread(&ip_header, sizeof(struct iphdr), 1, fp);
    source.sin_addr.s_addr = ip_header.saddr;     
    dest.sin_addr.s_addr = ip_header.daddr;
    print_ip_header(&ip_header,&source ,&dest);
    if (ip_header.protocol == 1 && fread(&icmp_header, sizeof(struct icmphdr), 1, fp)){
        size = ntohs(ip_header.tot_len) - 8;
        str = malloc(size + 1);
        memset(str, 0, size + 1);
        print_icmp_packet(&icmp_header);
        fread(str, sizeof(char) * size, 1, fp);
    }
    else if (ip_header.protocol == 6)//tcp
        continue; //print_tcp_packet(buffer , size);
    else if (ip_header.protocol == 17 && fread(&udp_header, sizeof(struct udphdr), 1, fp)){
        size = ntohs(udp_header.len) - 8;
        str = malloc(size + 1);
        memset(str, 0, size + 1);
        print_udp_packet(&udp_header);         
        fread(str, sizeof(char) * size, 1, fp);
    }
    else
        printf("Unknown type of packet");
    printf("data =\n");
    for (int i = 0; i < size; i++)
        printf("%02X",(unsigned int)str[i]);
    } 
    printf("\n");
    fclose(fp);
}
