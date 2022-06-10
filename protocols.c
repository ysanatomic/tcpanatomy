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
#include "protocols.h"
#include <stdlib.h>

void printTCP(struct TCPHeaders tcpheader);

// the buffer starts from the end of the ip header (i.e the beginning of the protocol header)
void handleProtocol(unsigned char* buffer, unsigned int protocolID){ 
    if(protocolID == 6) { // TCP 
        struct TCPHeaders tcpheader;
        memcpy(&tcpheader.sourcePort, buffer, 2);
        memcpy(&tcpheader.destinationPort, (buffer + 2), 2);
        
        tcpheader.sourcePort = ntohs( tcpheader.sourcePort);
        tcpheader.destinationPort = ntohs(tcpheader.destinationPort);

        // now we handle flag
        unsigned char nsByte; // the NS flag is in a sepratate byte
        memcpy(&nsByte, (buffer+12), 1);
        // now we have to get the last bit of the byte
        tcpheader.NS = nsByte & 1;

        unsigned char flagsByte;
        memcpy(&flagsByte, (buffer+13), 1);
        tcpheader.CWR = flagsByte & 128;
        tcpheader.ECE = flagsByte & 64;
        tcpheader.URG = flagsByte & 32;
        tcpheader.ACK = flagsByte & 16;
        tcpheader.PSH = flagsByte & 8;
        tcpheader.RST = flagsByte & 4;
        tcpheader.SYN = flagsByte & 2;
        tcpheader.FIN = flagsByte & 1;

        printTCP(tcpheader);

    }
}

void printTCP(struct TCPHeaders tcpheader){


    printf("[%i -> %i] ", tcpheader.sourcePort, tcpheader.destinationPort);

    if(tcpheader.FIN)
        printf("FIN ");
    if(tcpheader.SYN)
        printf("SYN ");
    if(tcpheader.RST)
        printf("RST ");
    if(tcpheader.PSH)
        printf("PSH ");
    if(tcpheader.ACK)
        printf("ACK ");
    if(tcpheader.URG)
        printf("URG ");
    if(tcpheader.ECE)
        printf("ECE ");
    if(tcpheader.CWR)
        printf("CWR ");
}