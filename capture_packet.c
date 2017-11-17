#define MAX_LENGTH_PACKET 120000
#define LINE_LENGTH 16

#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h>
#include<ncurses.h>
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

static int y = 0;

int isAlphaNumberic(char c)
{
	if (c >= 32 && c <=128)
		return 1;
	return 0;
}


void PrintData (char* data , int Size, WINDOW *win)
{
    int i , j;
    for(i=0 ; i < Size ; i++){
        if(i!=0 && i% LINE_LENGTH == 0){
            mvwprintw(win, y, 1, "      ");
            for(j=i-16 ; j<i ; j++)
                (isAlphaNumberic(data[j])) ? mvwprintw(win, y, 1, "%c",(unsigned char)data[j]) : mvwprintw(win, y, 1, ".");
            mvwprintw(win, y, 1, "\n");
        }
        if(i% LINE_LENGTH == 0)
            mvwprintw(win, y, 1, "  ");
        mvwprintw(win, y, 1, " %02X",(unsigned int)data[i]);
  	}
 }

void print_ethernet_header(char* buffer, int size, WINDOW *win)
{
    struct ethhdr *eth = (struct ethhdr *)buffer;
	mvwprintw(win, y, 1, "Ethernet Header\n");
    mvwprintw(win, y, 1, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    mvwprintw(win, y, 1, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    mvwprintw(win, y, 1, "   |-Protocol            : %u\n",(unsigned short)eth->h_proto);
}

void print_ip_header(char* buffer, int size, WINDOW *win)
{
	struct sockaddr_in source, dest;
    print_ethernet_header(buffer, size, win);
    short ipheader_len;
    struct iphdr *ip_header = (struct iphdr *)(buffer  + sizeof(struct ethhdr) );
    ipheader_len = ip_header->ihl * 4;
    source.sin_addr.s_addr = ip_header->saddr;
    dest.sin_addr.s_addr = ip_header->daddr;

    mvwprintw(win, y, 1, "IP Header\n");
    mvwprintw(win, y, 1, "   |-IP Version        : %d\n",(unsigned int)ip_header->version);
    mvwprintw(win, y, 1, "   |-IP Header Length  : %d Bytes\n",((unsigned int)(ip_header->ihl))*4);
    mvwprintw(win, y, 1, "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(ip_header->tot_len));
    mvwprintw(win, y, 1, "   |-Identification    : %d\n",ntohs(ip_header->id));
    mvwprintw(win, y, 1, "   |-Protocol : %d\n",(unsigned int)ip_header->protocol);
    mvwprintw(win, y, 1, "   |-TTL      : %d\n",(unsigned int)ip_header->ttl);
	mvwprintw(win, y, 1, "   |-Type Of Service   : %d\n",(unsigned int)ip_header->tos);
   	mvwprintw(win, y, 1, "   |-Checksum : %d\n",ntohs(ip_header->check));
    mvwprintw(win, y, 1, "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    mvwprintw(win, y, 1, "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));


}

void print_icmp_packet(char* buffer, int size, WINDOW *win)
{

    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short header_len = ip_header->ihl * 4;
    struct icmphdr *icmp_header = (struct icmphdr *)(buffer + header_len + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + header_len + sizeof icmp_header;

    mvwprintw(win, y, 1, "\nICMP Packet\n");

    print_ip_header(buffer, size, win);
    mvwprintw(win, y, 1, "\nICMP Header\n");
    mvwprintw(win, y, 1, "   |-Type : %d",(unsigned int)(icmp_header->type));

    if((unsigned int)(icmp_header->type) == 11)
        mvwprintw(win, y, 1, "  (TTL Expired)\n");
    else if((unsigned int)(icmp_header->type) == ICMP_ECHOREPLY)
        mvwprintw(win, y, 1, "  (ICMP Echo Reply)\n");

    mvwprintw(win, y, 1, "   |-Code : %d\n",(unsigned int)(icmp_header->code));
    mvwprintw(win, y, 1, "   |-Checksum : %d\n",ntohs(icmp_header->checksum));
    mvwprintw(win, y, 1, "\nIP Header\n");
    PrintData(buffer, header_len, win);
    mvwprintw(win, y, 1, "\nUDP Header\n");
    PrintData(buffer + header_len , sizeof (icmp_header), win);
    mvwprintw(win, y, 1, "\nData Payload\n");
    PrintData(buffer + header_size , (size - header_size), win);
    mvwprintw(win, y, 1, "\n###########################################################");
}

void print_tcp_packet(char *buffer, int size, WINDOW *win)
{
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    unsigned short header_len = ip_header->ihl * 4;
    struct tcphdr *tcp_header=(struct tcphdr*)(buffer + header_len + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + header_len + tcp_header->doff*4;

    mvwprintw(win, y, 1, "TCP Packet\n");

    print_ip_header(buffer, size, win);

    mvwprintw(win, y, 1, "\n");
    mvwprintw(win, y, 1, "TCP Header\n");
    mvwprintw(win, y, 1, "   |-Source Port      : %u\n",ntohs(tcp_header->source));
    mvwprintw(win, y, 1, "   |-Destination Port : %u\n",ntohs(tcp_header->dest));
    mvwprintw(win, y, 1, "   |-Sequence Number    : %u\n",ntohl(tcp_header->seq));
    mvwprintw(win, y, 1, "   |-Acknowledge Number : %u\n",ntohl(tcp_header->ack_seq));
    mvwprintw(win, y, 1, "   |-Header Length      : %d BYTES\n", (unsigned int)tcp_header->doff*4);
    mvwprintw(win, y, 1, "   |-Urgent Flag          : %d\n",(unsigned int)tcp_header->urg);
    mvwprintw(win, y, 1, "   |-Acknowledgement Flag : %d\n",(unsigned int)tcp_header->ack);
    mvwprintw(win, y, 1, "   |-Synchronise Flag     : %d\n",(unsigned int)tcp_header->syn);
    mvwprintw(win, y, 1, "   |-Window         : %d\n",ntohs(tcp_header->window));
    mvwprintw(win, y, 1, "   |-Checksum       : %d\n",ntohs(tcp_header->check));
    mvwprintw(win, y, 1, "   |-Urgent Pointer : %d\n",tcp_header->urg_ptr);
    mvwprintw(win, y, 1, "\nIP Header\n");
    PrintData(buffer, header_len, win);
    mvwprintw(win, y, 1, "\nTCP Header\n");
    PrintData(buffer + header_len,tcp_header->doff*4, win);
    mvwprintw(win, y, 1, "\nData Payload\n");
    PrintData(buffer + header_size , size - header_size, win);
    mvwprintw(win, y, 1, "\n###########################################################\n");
}

void print_udp_packet(char *buffer, int size, WINDOW *win)
{

    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
   	unsigned short header_len = ip_header->ihl * 4;
    struct udphdr *udp_header = (struct udphdr*)(buffer + header_len  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) +header_len + sizeof udp_header;

    mvwprintw(win, y, 1, "\nUDP Packet\n");
    print_ip_header(buffer, size, win);

    mvwprintw(win, y, 1, "\nUDP Header\n");
    mvwprintw(win, y, 1, "   |-Source Port      : %d\n" , ntohs(udp_header->source));
    mvwprintw(win, y, 1, "   |-Destination Port : %d\n" , ntohs(udp_header->dest));
    mvwprintw(win, y, 1, "   |-UDP Length       : %d\n" , ntohs(udp_header->len));
    mvwprintw(win, y, 1, "   |-UDP Checksum     : %d\n" , ntohs(udp_header->check));
    mvwprintw(win, y, 1, "\nIP Header\n");
    PrintData(buffer , header_len, win);
    mvwprintw(win, y, 1, "\nUDP Header\n");
    PrintData(buffer + header_len , sizeof(udp_header), win);
    mvwprintw(win, y, 1, "\nData Payload\n");
    PrintData(buffer + header_size , size - header_size, win);
    mvwprintw(win, y, 1, "\n###########################################################");
}

void check_packet(char* buffer, int size, WINDOW *win)
{
  y = 0;
    struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
 	if (ip_header->protocol == 1)//icmp
 		print_icmp_packet( buffer , size, win);
    else if (ip_header->protocol == 6)//tcp
        print_tcp_packet(buffer , size, win);
    else if (ip_header->protocol == 17)// udp
        print_udp_packet(buffer , size, win);
    else
    	mvwprintw(win, y, 1, "Unknown type of packet");
}

// void capture_packet(){
//
// 	int data_size;
// 	int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
// 	struct sockaddr socket_addr;
// 	int sockaddr_size = sizeof(socket_addr);
//
// 	 if(raw_socket < 0){
//         perror("Socket Error");
//         exit(1);
//     }
//    	char *buffer = malloc(sizeof(char *) * MAX_LENGTH_PACKET);
// 	while(1){
//         data_size = recvfrom(raw_socket, buffer, MAX_LENGTH_PACKET, 0, &socket_addr, (socklen_t*)&sockaddr_size);
//         if(data_size <0 ){
//             mvwprintw(win, y, 1, "Recvfrom error\n");
//             exit(1);
//         }
//         check_packet(buffer , data_size);
//     }
//     close(raw_socket);
// }

// int main()
// {
// 	capture_packet();
// }
