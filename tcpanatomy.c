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
"To be implemented: \n"
"	--port - limit to a certain port (source or destination)\n"
"	--srcPort - limit to a certain source port\n"
"	--destPort - limit to a certain destination port\n";

void printEthernetHeader(struct EthHeader ethHeader);
void handlePacket(unsigned char*, struct Rules rules);
void printAddrSrcDestv4(struct IPv4Header ipHeaders);
bool hasPrefix(const char *str);

void strAddrToBytesV4(char* input, unsigned char* addrP){
	char* token;
	char* string;
	char* tofree;

	string = strdup(input);


	if (string != NULL){

		tofree = string;
		short i = 0;
		char netBytes[16];
		while ((token = strsep(&string, ".")) != NULL)
		{
			netBytes[i] = (char) atoi(token);
			i++;
		}
		for(int j = i-1, k = 0; j >= 0; j--, k++){
			memcpy((addrP + 15 - k), &netBytes[j], 1);
		}

		free(tofree);
	}
}

int main(int argc, char *argv[]){		

	struct Rules rules; 

	// doing some setup
	memset(&rules.addr, 0, 16);
	memset(&rules.src, 0, 16);
	memset(&rules.dest, 0, 16);
	rules.displayPhysical = 0; // if it should display the mac addresses
	rules.displayV6 = 0; // if it should display the v6 addresses
	rules.displayV4 = 0; // if it should display the v4 addresses
	rules.addrRuleMode = 0;

	for(int i = 1; i<argc; i++){ // program a1 a2 a3
		char *argument = argv[i];
		if(strcmp(argument, "-p") == 0){ // physical
			rules.displayPhysical = 1;
		}
		else if(strcmp(argument, "-v6") == 0){ // IPv6 packets
			rules.displayV6 = 1;
		}
		else if(strcmp(argument, "-v4") == 0){ // IPv4 packets
			rules.displayV4 = 1;
		}
		else if(strcmp(argument, "-A") == 0){
			rules.displayV4 = 1;
			rules.displayV6 = 1;
			rules.displayPhysical = 1;
		}
		else if(strcmp(argument, "--addr") == 0){
			if(!(i+1 < argc) || hasPrefix((const char*) argv[i+1])){
				printf("You have to specify an address.\n");
				return 1;
			}
			else {
				strAddrToBytesV4(argv[i+1], &rules.addr);
				rules.addrRuleMode += 1;
				for(int i = 0; i < 16; i++){
					printf("Addr %i \n", rules.addr[i]);
				}
			}
		}
		else if(strcmp(argument, "--src") == 0){
			if(!(i+1 < argc) || hasPrefix((const char*) argv[i+1])){
				printf("You have to specify an address.\n");
				return 1;
			}
			else {
				strAddrToBytesV4(argv[i+1], &rules.src);
				rules.addrRuleMode += 2;
			}
		}
		else if(strcmp(argument, "--dest") == 0){
			if(!(i+1 < argc) || hasPrefix((const char*) argv[i+1])){
				printf("You have to specify an address.\n");
				return 1;
			}
			else {
				strAddrToBytesV4(argv[i+1], &rules.dest);
				rules.addrRuleMode += 4;
			}
		}
		
		
	}
	if(!rules.displayV4 && !rules.displayV6){
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
		handlePacket(buffer, rules);
	}
	close(sniffSocket);

	return 0;	
}

bool hasPrefix(const char *str){
	const char *pre = "-";
	return strncmp(pre, str, strlen(pre)) == 0;
}