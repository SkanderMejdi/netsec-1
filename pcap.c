#include <stdlib.h> 
#include <sys/types.h>
#include <stdint.h>
#include<stdio.h>
#include <time.h> 
#include<netinet/if_ether.h>
#include <linux/types.h>
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
} pcaprec_hdr_t;

int create_pcap(char *pcap_file)
{
	FILE *fp;
	pcap_hdr_t pcap;
	pcaprec_hdr_t pcaprec;
	pcap.magic_number = 0xa1b2c3d4;
	pcap.version_major =2;
	pcap.version_minor = 4;
	pcap.thiszone = 0;
	pcap.sigfigs = 0;
	pcap.snaplen = 4;
	pcap.network = 1; //LINKTYPE_NULL = 0  or LINKTYPE_ETHERNET =  1
	pcaprec.ts_sec = time(NULL);
	pcaprec.ts_usec = time(NULL) / 100;
	pcaprec.incl_len = 0xe7b4;
	pcaprec.orig_len = 0x0119;

	fp=fopen(pcap_file, "wb");
	if(fp==NULL) 
    {
        printf("Unable to create log.txt file.\n");
        exit(1);
    }
    fwrite(&pcap, 1,sizeof(pcap_hdr_t),fp);
    fwrite(&pcaprec, 1,sizeof(pcaprec_hdr_t),fp);
    printf("%s created\n", pcap_file);

	return 0;
}