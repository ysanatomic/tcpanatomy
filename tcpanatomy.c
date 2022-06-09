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
size_t malloc_usable_size (void *ptr);

struct EthHeader;
struct IPv4Headers;

bool displayPhysical = 0; // if it should display the mac addresses
bool displayV6 = 0; // if it should display the v6 addresses
bool displayV4 = 0; // if it should display the v4 addresses

char *HELP_MESSAGE = "Options:\n-v4 - displaying IPv4 packets\n-v6 - displaying IPv6 packets\n-p - displaying the physical route\n-A - all options enabled. \n";

void printEthernetHeader(struct EthHeader ethHeader);
void handlePacket(unsigned char*, bool displayV4, bool displayV6, bool displayPhysical);
void printAddrSrcDestv4(struct IPv4Headers ipHeaders);

int main(int argc, char *argv[]){


	printf("TCPAnatomy by Yordan Stoychev (Anatomic). \n");
	

	for(int i = 1; i<argc; i++){
		char *argument = argv[i];
		printf(argv[i]);
		if(strcmp(argument, "-p") == 0){ // physical
			displayPhysical = 1;
		}
		else if(strcmp(argument, "-v6") == 0){ // IPv6 packets
			displayV6 = 1;
		}
		else if(strcmp(argument, "-v4") == 0){ // IPv4 packets
			displayV4 = 1;
		}
		else if(strcmp(argument, "-A") == 0){
			displayV4 = 1;
			displayV6 = 1;
			displayPhysical = 1;
		}
	}
	if(!displayV4 && !displayV6){
		printf(HELP_MESSAGE);
		return 1;
	}

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


	unsigned char *buffer = (unsigned char *)malloc(65536);
	// pointer to the buffer that we allocate
	
	
	while(1){
		int data_size = recvfrom(sniffSocket, buffer, malloc_usable_size(buffer), 0, NULL, NULL);
		if (data_size < 0) { // an error is returned
			printf("Failed to sniff packets \n");
			return 1;
		}
		handlePacket(buffer, displayV4, displayV6, displayPhysical);
	}
	close(sniffSocket);

	return 0;	
}
