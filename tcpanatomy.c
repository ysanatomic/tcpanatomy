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
struct IPv4Header;

bool displayPhysical = 0; // if it should display the mac addresses
bool displayV6 = 0; // if it should display the v6 addresses
bool displayV4 = 0; // if it should display the v4 addresses

char *HELP_MESSAGE = "TCPANATOMY - Low-level lightweight network monitoring tool.\n"
"Written and maintained by Yordan Stoychev (anatomicys@gmail.com)\n"
"Options:\n"
"	-v4 - displaying IPv4 packets\n"
"	-v6 - displaying IPv6 packets\n"
"	-p - displaying the physical route of the frames\n"
"	-A - IPv4, IPv6 and physical route all displayed\n"
"	--addr - limit to a certain address (source or destination)\n"
"	--src - limit to a certain source address\n"
"	--dest - limit to a certain destination address\n"
"	--port - limit to a certain port (source or destination)\n"
"	--srcPort - limit to a certain source port\n"
"	--destPort - limit to a certain destination port\n";

void printEthernetHeader(struct EthHeader ethHeader);
void handlePacket(unsigned char*, bool displayV4, bool displayV6, bool displayPhysical);
void printAddrSrcDestv4(struct IPv4Header ipHeaders);
bool hasPrefix(const char *str);

int main(int argc, char *argv[]){		

	// struct Rules rules; 

	for(int i = 1; i<argc; i++){ // program a1 a2 a3
		char *argument = argv[i];
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
		else if(strcmp(argument, "--addr") == 0){
			if(!(i+1 < argc) || hasPrefix((const char*) argv[i+1])){
				printf("You have to specify an address.\n");
				return 1;
			}
			else {
				// split at dot or split at ::
				// and then put into the rules.addr
			}
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

bool hasPrefix(const char *str){
	const char *pre = "-";
	return strncmp(pre, str, strlen(pre)) == 0;
}