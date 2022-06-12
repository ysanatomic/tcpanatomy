#ifndef headers
#define headers

struct EthHeader { // the ethernet header is 14 bytes
	unsigned char destMACAddr[6];
	unsigned char srcMACAddr[6];
	unsigned char etherType[2];
};

struct IPv4Header {
	unsigned int version;
	unsigned int headerLength; // minimum value 5 (for 5 * 32 bits = 20 bytes)
	unsigned char sourceAddr[4];
	unsigned char destinationAddr[4];
    unsigned char protocol; 
	unsigned short totalLength; // we need multiple totalLengths because we do some transformations to get it the correct value
};

struct TCPHeader {
	unsigned short sourcePort;
	unsigned short destinationPort;
	// the nine flags below
	bool NS;
	bool CWR;
	bool ECE;
	bool URG;
	bool ACK;
	bool PSH;
	bool RST;
	bool SYN;
	bool FIN;
	unsigned short checksum;
	unsigned int seqNum; 
	unsigned int ackNum;
};

struct UDPHeader {
	unsigned short sourcePort;
	unsigned short destinationPort;
	unsigned short checksum;
	unsigned short length;
};

struct ICMPHeader {
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned int restOfHeader; 
};

struct Rules { // user rules -> what ips to show, etc
	bool displayV4;
	bool displayV6;
	bool displayPhysical;
	unsigned char addr[16]; // lower 4 bytes are just v4
	unsigned char src[16];
	unsigned char dest[16];
	unsigned short port;
	unsigned short srcPort;
	unsigned short destPort;
	unsigned short addrRuleMode; // the mode for the rules
	// mode 1 = addr set; mode 2 - src set; mode 4 - dest set;
	// bite-wise combinations allowed 111 - is all set (ex)
};	
#endif
