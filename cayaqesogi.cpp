struct addressInfo {
	unsigned long ipAddr;
	unsigned long macAddr;
} addrInfo;

struct arpInformation {
	unsigned short	hdType;
	unsigned short	protoType;
	unsigned char	hdSize;
	unsigned char	protoSize;
	unsigned short 	opCode;
	struct addrInfo sAddr;
	struct addrInfo dAddr;
} arpInfo;

struct arpResponse {
	unsigned long 	d_addr;  // Destination: IntelCor_ec:42:e9 (fc:f8:ae:ec:42:e9)
	unsigned long 	s_addr; // Source: Cisco_df:c7:42 (00:16:c7:df:c7:42)
	struct aprInfo;
	char*			data;
} arpR;
