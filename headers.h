#ifndef headers
#define headers

struct EthHeader { // the ethernet header is 14 bytes
	unsigned char destMACAddr[6];
	unsigned char srcMACAddr[6];
	unsigned char etherType[2];
};

struct IPv4Headers {
	unsigned int version;
	unsigned int headerLength; // minimum value 5 (for 5 * 32 bits = 20 bytes)
	unsigned char sourceAddr[4];
	unsigned char destinationAddr[4];
    unsigned char protocol; 
	unsigned short totalLength; // we need multiple totalLengths because we do some transformations to get it the correct value
};

struct TCPHeaders {
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
	unsigned char* checksum;
};

#endif
