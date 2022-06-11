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

char* printTCP(struct TCPHeader tcpheader);
struct TCPHeader handleTCP(unsigned char* buffer);
char* printUDP(struct UDPHeader udpheader);
struct UDPHeader handleUDP(unsigned char* buffer);
char* printICMP(struct ICMPHeader icmpheader);
struct ICMPHeader handleICMP(unsigned char* buffer);



// the buffer starts from the end of the ip header (i.e the beginning of the protocol header)
char* handleProtocolIPv4(unsigned char* buffer, unsigned int protocolID){ // returns a string

    char *output = malloc(200); // 200 bytes more than enough
    memset(output, 0, 200);

    if(protocolID == 6) { // TCP 
        struct TCPHeader tcpheader = handleTCP(buffer);
        strcat(output, " TCP ");
        char* rtn = printTCP(tcpheader);
        strcat(output, rtn);
        free(rtn);
    }
    else if(protocolID == 17) { // UDP
        strcat(output, " UDP ");
        struct UDPHeader udpheader = handleUDP(buffer);
        char* rtn = printUDP(udpheader);
        strcat(output, rtn);
        free(rtn);
    }
    else if(protocolID == 1){
        strcat(output, " ICMP ");
        struct ICMPHeader icmpheader = handleICMP(buffer);
        char* rtn = printICMP(icmpheader);
        strcat(output, rtn);
        free(rtn);
    }
    else {
        printf(" UNKNOWN/UNCATEGORIZED PROTOCOL ");
    }

    return(output);

}

struct ICMPHeader handleICMP(unsigned char* buffer){
    struct ICMPHeader icmpheader;
    memcpy(&icmpheader.type, buffer, 1);
    memcpy(&icmpheader.code, (buffer + 1), 1);
    memcpy(&icmpheader.checksum, (buffer + 2), 2);
    memcpy(&icmpheader.restOfHeader, (buffer + 4), 2);

    icmpheader.type = ntohs(icmpheader.type);
    icmpheader.code = ntohs(icmpheader.code);
    icmpheader.checksum = ntohs(icmpheader.checksum);
    
    return icmpheader;
}

char* printICMP(struct ICMPHeader icmpheader){
    char *output = malloc(10); // 10 bytes more than enough
    memset(output, 0, 10);
    snprintf(output, 10, "%i:%i ", (unsigned short) icmpheader.type, (unsigned short) icmpheader.code);
    return output;
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

char* printUDP(struct UDPHeader udpheader){
    char *output = malloc(30);
    memset(output, 0, 30);
    snprintf(output, 30, "[%i -> %i] lenght %i ", udpheader.sourcePort, udpheader.destinationPort, udpheader.length);
    return(output);
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


char* printTCP(struct TCPHeader tcpheader){

    char *output = malloc(80);
    char *inmdl = malloc(30);
    memset(output, 0, 80);
    memset(inmdl, 0, 30);


    snprintf(inmdl, 30, "[%i -> %i] ", tcpheader.sourcePort, tcpheader.destinationPort);
    strcat(output, inmdl);
    memset(inmdl, 0, 30);


    if(tcpheader.FIN)
        strcat(output, "FIN ");
    if(tcpheader.SYN)
        strcat(output, "SYN ");
    if(tcpheader.RST)
        strcat(output, "RST ");
    if(tcpheader.PSH)
        strcat(output, "PSH ");
    if(tcpheader.ACK){
        snprintf(inmdl, 30, "ACK %i ", tcpheader.ackNum);
        strcat(output, inmdl);
        memset(inmdl, 0, 30);
    }

    if(tcpheader.URG)
        strcat(output, "URG ");
    if(tcpheader.ECE)
        strcat(output, "ECE ");
    if(tcpheader.CWR)
        strcat(output, "CWR ");

    snprintf(inmdl, 30, "seq %i ", tcpheader.seqNum);
    strcat(output, inmdl);
    return(output);
}


