#define MAX_LENGTH_PACKET 120000
#define LINE_LENGTH 16

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

int read_pcap(char *);
int create_pcap(char *);

int isAlphaNumberic(char c)
{
	if (c >= 32 && c <=128)
		return 1;
	return 0;
}


void PrintData (char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++){
        if(i!=0 && i% LINE_LENGTH == 0){
            printf("      ");
            for(j=i-16 ; j<i ; j++)
                (isAlphaNumberic(data[j])) ? printf("%c",(unsigned char)data[j]) : printf(".");
            printf("\n");
        }
        if(i% LINE_LENGTH == 0) 
            printf("  ");
        printf(" %02X",(unsigned int)data[i]);
  	}
 }

void print_ethernet_header(char* buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *)buffer; 
	printf("Ethernet Header\n");
    printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    printf("   |-Protocol            : %u\n",(unsigned short)eth->h_proto);
}

void print_ip_header(char* buffer, int size)
{
	struct sockaddr_in source, dest;
    print_ethernet_header(buffer, size);
    short ipheader_len;
    struct iphdr *ip_header = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
    ipheader_len = ip_header->ihl * 4;
    source.sin_addr.s_addr = ip_header->saddr;     
    dest.sin_addr.s_addr = ip_header->daddr;
   
    printf("IP Header\n");
    printf("   |-IP Version        : %d\n",(unsigned int)ip_header->version);
    printf("   |-IP Header Length  : %d Bytes\n",((unsigned int)(ip_header->ihl))*4);
    printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(ip_header->tot_len));
    printf("   |-Identification    : %d\n",ntohs(ip_header->id));
    printf("   |-Protocol : %d\n",(unsigned int)ip_header->protocol);
    printf("   |-TTL      : %d\n",(unsigned int)ip_header->ttl);
	printf("   |-Type Of Service   : %d\n",(unsigned int)ip_header->tos);
   	printf("   |-Checksum : %d\n",ntohs(ip_header->check));
    printf("   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    printf("   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));


}

void print_icmp_packet(char* buffer, int size)
{

    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short header_len = ip_header->ihl * 4; 
    struct icmphdr *icmp_header = (struct icmphdr *)(buffer + header_len + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + header_len + sizeof icmp_header; 

    printf("\nICMP Packet\n"); 
     
    print_ip_header(buffer, size);
    printf("\nICMP Header\n");
    printf("   |-Type : %d",(unsigned int)(icmp_header->type));
             
    if((unsigned int)(icmp_header->type) == 11)
        printf("  (TTL Expired)\n");
    else if((unsigned int)(icmp_header->type) == ICMP_ECHOREPLY)
        printf("  (ICMP Echo Reply)\n");

    printf("   |-Code : %d\n",(unsigned int)(icmp_header->code));
    printf("   |-Checksum : %d\n",ntohs(icmp_header->checksum));
    printf("\nIP Header\n");
    PrintData(buffer, header_len);
    printf("\nUDP Header\n");
    PrintData(buffer + header_len , sizeof (icmp_header));
    printf("\nData Payload\n");
    PrintData(buffer + header_size , (size - header_size) );
    printf("\n###########################################################");
}

void print_tcp_packet(char *buffer, int size)
{
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short header_len = ip_header->ihl * 4; 
    struct tcphdr *tcp_header=(struct tcphdr*)(buffer + header_len + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + header_len + tcp_header->doff*4;
     
    printf("TCP Packet\n");

    print_ip_header(buffer, size);
         
    printf("\n");
    printf("TCP Header\n");
    printf("   |-Source Port      : %u\n",ntohs(tcp_header->source));
    printf("   |-Destination Port : %u\n",ntohs(tcp_header->dest));
    printf("   |-Sequence Number    : %u\n",ntohl(tcp_header->seq));
    printf("   |-Acknowledge Number : %u\n",ntohl(tcp_header->ack_seq));
    printf("   |-Header Length      : %d BYTES\n", (unsigned int)tcp_header->doff*4);
    printf("   |-Urgent Flag          : %d\n",(unsigned int)tcp_header->urg);
    printf("   |-Acknowledgement Flag : %d\n",(unsigned int)tcp_header->ack);
    printf("   |-Synchronise Flag     : %d\n",(unsigned int)tcp_header->syn);
    printf("   |-Window         : %d\n",ntohs(tcp_header->window));
    printf("   |-Checksum       : %d\n",ntohs(tcp_header->check));
    printf("   |-Urgent Pointer : %d\n",tcp_header->urg_ptr);
    printf("\nIP Header\n");
    PrintData(buffer, header_len);         
    printf("\nTCP Header\n");
    PrintData(buffer + header_len,tcp_header->doff*4);
    printf("\nData Payload\n");    
    PrintData(buffer + header_size , size - header_size );
    printf("\n###########################################################\n");
}

void print_udp_packet(char *buffer, int size)
{
     
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
   	unsigned short header_len = ip_header->ihl * 4;
    struct udphdr *udp_header = (struct udphdr*)(buffer + header_len  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) +header_len + sizeof udp_header;
     
    printf("\nUDP Packet\n");
    print_ip_header(buffer, size);           
     
    printf("\nUDP Header\n");
    printf("   |-Source Port      : %d\n" , ntohs(udp_header->source));
    printf("   |-Destination Port : %d\n" , ntohs(udp_header->dest));
    printf("   |-UDP Length       : %d\n" , ntohs(udp_header->len));
    printf("   |-UDP Checksum     : %d\n" , ntohs(udp_header->check));
    printf("\nIP Header\n");
    PrintData(buffer , header_len);
    printf("\nUDP Header\n");
    PrintData(buffer + header_len , sizeof(udp_header));
    printf("\nData Payload\n");    
    PrintData(buffer + header_size , size - header_size);
    printf("\n###########################################################");
}

void check_packet(char* buffer, int size)
{
    struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
 	if (ip_header->protocol == 1)//icmp
 		print_icmp_packet( buffer , size);
    else if (ip_header->protocol == 6)//tcp
        print_tcp_packet(buffer , size);
    else if (ip_header->protocol == 17)// udp
        print_udp_packet(buffer , size);         
    else
    	printf("Unknown type of packet");
}

void capture_packet(){

	int data_size;
	int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	struct sockaddr socket_addr;
	int sockaddr_size = sizeof(socket_addr);

	 if(raw_socket < 0){
        perror("Socket Error");
        exit(1);
    }
   	char *buffer = malloc(sizeof(char *) * MAX_LENGTH_PACKET);
	while(1){
        data_size = recvfrom(raw_socket, buffer, MAX_LENGTH_PACKET, 0, &socket_addr, (socklen_t*)&sockaddr_size);
        if(data_size <0 ){
            printf("Recvfrom error\n");
            exit(1);
        }
        check_packet(buffer , data_size);
    }
    close(raw_socket);
}

int main(int ac, char**av)
{
    if (ac < 2){
        printf("option: -l = listen, -r {file_name} = read pcap, -c {file_name}= create pcap\n");
        exit(1);
    }
    if (!strcmp(av[1],"-l"))
        capture_packet();
    else if (!strcmp(av[1],"-r") && ac == 3)
        read_pcap(av[2]);
    else if (!strcmp(av[1],"-c") && ac == 3)
        create_pcap(av[2]);
    else
        printf("option: -l = listen, -r {file_name} = read pcap, -c {file_name}= create pcap");
    return 1;
}