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

void printTCP(struct TCPHeader tcpheader);
struct TCPHeader handleTCP(unsigned char* buffer);
void printUDP(struct UDPHeader udpheader);
struct UDPHeader handleUDP(unsigned char* buffer);

// the buffer starts from the end of the ip header (i.e the beginning of the protocol header)
void handleProtocolIPv4(unsigned char* buffer, unsigned int protocolID){ 
    if(protocolID == 6) { // TCP 
        struct TCPHeader tcpheader = handleTCP(buffer);
        printTCP(tcpheader);
    }
    if(protocolID == 17) { // UDP
        struct UDPHeader udpheader = handleUDP(buffer);
        printUDP(udpheader);
    }
}


struct UDPHeader handleUDP(unsigned char* buffer){
    struct UDPHeader udpheader;
    memcpy(&udpheader.sourcePort, buffer, 2);
    memcpy(&udpheader.destinationPort, (buffer + 2), 2);
    memcpy(&udpheader.length, (buffer + 4), 2);
    memcpy(&udpheader.checksum, (buffer + 6), 2);

    udpheader.sourcePort = ntohs(udpheader.sourcePort);
    udpheader.destinationPort = ntohs(udpheader.destinationPort);
    udpheader.length = ntohs(udpheader.length);
    udpheader.checksum = ntohs(udpheader.checksum);

    return udpheader;

}

void printUDP(struct UDPHeader udpheader){
    printf("[%i -> %i] lenght %i ", udpheader.sourcePort, udpheader.destinationPort, udpheader.length);
}


struct TCPHeader handleTCP(unsigned char* buffer){
    struct TCPHeader tcpheader;
    memcpy(&tcpheader.sourcePort, buffer, 2);
    memcpy(&tcpheader.destinationPort, (buffer + 2), 2);
    memcpy(&tcpheader.checksum, (buffer + 16), 2);
    memcpy(&tcpheader.seqNum, (buffer + 4), 4);
    memcpy(&tcpheader.ackNum, (buffer + 8), 4);

    
    tcpheader.sourcePort = ntohs(tcpheader.sourcePort);
    tcpheader.destinationPort = ntohs(tcpheader.destinationPort);
    tcpheader.checksum = ntohs(tcpheader.checksum);
    tcpheader.seqNum = ntohs(tcpheader.seqNum);
    tcpheader.ackNum = ntohs(tcpheader.ackNum);

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

    return tcpheader;
}


void printTCP(struct TCPHeader tcpheader){


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
        printf("ACK %i ", tcpheader.ackNum);
    if(tcpheader.URG)
        printf("URG ");
    if(tcpheader.ECE)
        printf("ECE ");
    if(tcpheader.CWR)
        printf("CWR ");

    printf("seq %i ", tcpheader.seqNum);

}


