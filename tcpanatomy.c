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
size_t malloc_usable_size (void *ptr);

struct EthHeader { // the ethernet header is 14 bytes
	unsigned char destMACAddr[6];
	unsigned char srcMACAddr[6];
	unsigned char etherType[2];
};

void printEthernetHeader(struct EthHeader ethHeader);
void handlePacket(unsigned char*);



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

void handlePacket(unsigned char *buffer){

	struct EthHeader ethHeader;
	memcpy(&ethHeader.destMACAddr, buffer, 6); 
	memcpy(&ethHeader.srcMACAddr, (buffer + 6), 6);
	memcpy(&ethHeader.etherType, (buffer + 12), 2);
	buffer = buffer + 14; // now we cut the ethernet header out as we don't need it
	printEthernetHeader(ethHeader);
	// printf("%06x \n", ethHeader.srcMACAddr);
	// printf("%06x \n", ethHeader.etherType);

	for (int i = 0; i < 14; i++)
		printf("%02x ", buffer[i]);
}


int main(){

	struct sockaddr saddr;
	int saddr_size = sizeof saddr;

	printf("TCPAnatomy by Yordan Stoychev (Anatomic). \n");
	
	//int socket(int domain, int type, int protocol);
	//AF_PACKET for packets directly from l2
	//SOCK_RAW for raw packets
	//ETH_P_ALL to actually grab from all interfaces
	int sniffSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sniffSocket < 0){ // i.e. returned an error code

		printf("Socket could not be initiated \n");
		return 1;
	}
	else {
		printf("Socket successfully initiated; Listening... \n");
	}	

	//int one = 1;
	//const int *val = &one;
	//if (setsockopt (sniffSocket, IPPROTO_RAW, IP_HDRINCL, val, sizeof (one)) < 0)
	//{
	//	printf ("Error setting IP_HDRINCL. \n");
	//	exit(0);
	//}	

	unsigned char *buffer = (unsigned char *)malloc(65536);
	// pointer to the buffer that we allocate
	
	
	while(1){
		//ssize_t recvfrom(int sockfd, void *restrict buf, size_t len, int flags,
		// struct sockaddr *restrict src_addr,
		//   socklen_t *restrict addrlen);
		//                                                
		//int data_size = recvfrom(sniffSocket, buffer, sizeof(buffer), 0, (struct sockaddr *)&saddr, &saddr_size);
		int data_size = recvfrom(sniffSocket, buffer, malloc_usable_size(buffer), 0, NULL, NULL);
		if (data_size < 0) { // an error is returned
			printf("Failed to sniff packets \n");
			return 1;
		}
		printf("Sniffed a packet \n");
		handlePacket(buffer);
		//for (int i = 14; i 
		printf("\n");
	}
	close(sniffSocket);

	return 0;	
}
