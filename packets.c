#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h> // tcp
#include <netinet/tcp.h> // tcp
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <string.h>
#include <malloc.h>
#include <stdbool.h>
#include "headers.h"


struct EthHeader;
struct IPv4Headers;

void printEthernetHeader(struct EthHeader ethHeader){ // format is sourcemac -> destionationmac : type
	printf("[");
	for (int i = 0; i < 6; i++)
		printf("%02x:", ethHeader.srcMACAddr[i]);
	printf(" -> ");
	for (int i = 0; i < 6; i++)
		printf("%02x:", ethHeader.destMACAddr[i]);
	printf(" - ");
	for (int i = 0; i < 2; i++)
		printf("%02x", ethHeader.etherType[i]);
	printf("] ");
}

void printAddrSrcDestv4(struct IPv4Headers ipHeaders){
	printf("(");
	for(int i = 0; i < 3; i++)
		printf("%u.", ipHeaders.sourceAddr[i]);
	printf("%u", ipHeaders.sourceAddr[3]); // this is separate so we omit the .
	printf(" -> ");
	for(int i = 0; i < 3; i++)
		printf("%u.", ipHeaders.destinationAddr[i]);
	printf("%u", ipHeaders.destinationAddr[3]); // this is separate so we omit the .
	printf(") ");
}

void handlePacket(unsigned char *buffer, bool displayV4, bool displayV6, bool displayPhysical){

	struct EthHeader ethHeader;
	memcpy(&ethHeader.destMACAddr, buffer, 6); 
	memcpy(&ethHeader.srcMACAddr, (buffer + 6), 6);
	memcpy(&ethHeader.etherType, (buffer + 12), 2);
	buffer = buffer + 14; // now we cut the ethernet header out as we don't need it
	// and move to the start of the IP header


	// now we check what IP protcol it uses
	int ipVersion = buffer[0] >> 4; // the higher 4 bits are the version
	if(ipVersion == 4 && displayV4) { 
		struct IPv4Headers ipHeaders;
		ipHeaders.version = ipVersion;
		ipHeaders.headerLength = buffer[0] & 0x0f; // the lower 4 bits are the length 
		memcpy(&ipHeaders.sourceAddr, (buffer + 12), 4); 
		memcpy(&ipHeaders.destinationAddr, (buffer + 16), 4);

		if(displayPhysical){ 
			printEthernetHeader(ethHeader);
		}

		printAddrSrcDestv4(ipHeaders);
		printf("\n");
	}
	else if(ipVersion == 6 && displayV6){
		if(displayPhysical){
			printEthernetHeader(ethHeader);
		}
		printf("TF we got a 6???");
		printf("\n");
	}

}