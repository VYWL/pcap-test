#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define ETHERNET_HEADER_SIZE 14
#define IPv4_HEADER_SIZE 20
#define TCP_HEADER_SIZE 20

typedef struct _Param Param;
typedef struct EthernetHeader EtherHD;
typedef struct IPHeader IPHD;
typedef struct tcpHeader TCPHD;
typedef struct headerChecker HDCHK;

extern Param param;

void usage();
bool parse(Param* param, int argc, char* argv[]);
pcap_t* customized_pcap_open(Param* param, char * errbuf);
int isPacketTCP(const u_char* packet);

void printEthernetHeaderInfo(const u_char* packet);
void printIPv4HeaderInfo(const u_char* packet);
void printTCPHeaderInfo(const u_char* packet);
void printPacketInfo(const u_char* packet);
void printDATA8Byte(const u_char* packet);
void printMACAdress(u_char * macAdr);
void printHEX(u_char hexAdr);