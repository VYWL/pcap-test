#include "pcapTest.h"

struct _Param{
	char* dev_;
};

Param param = {
    .dev_ = NULL
};

struct EthernetHeader{
    uint8_t destinationMAC[6];
    uint8_t sourceMAC[6];
    uint16_t type;
};

struct IPHeader{
    uint8_t headerLength : 4;
    uint8_t version : 4;
    uint8_t typeOfService;
    uint16_t totalPacketLength;
    uint16_t identifier;
    uint16_t fragmentOffset;
    uint8_t ttl;
    uint8_t protocolID;
    uint8_t headerChecksum;
    struct in_addr sourceIP;
    struct in_addr destinationIP;
};

struct tcpHeader {
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint32_t sequenceNumber;
    uint32_t acknowledgeNumber;
    uint8_t _unused : 4;
    uint8_t offset : 4;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgentPointer;
};

struct headerChecker {
    uint8_t temp[20];
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

pcap_t* customized_pcap_open(Param* param, char * errbuf){
    pcap_t * ret_pcap = pcap_open_live(param->dev_, BUFSIZ, 1, 1000, errbuf);
	if (ret_pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param->dev_, errbuf);
		exit(-1);
	}
    return ret_pcap;
}

void printPacketInfo(const u_char* packet) {
        printEthernetHeaderInfo(packet);
        packet += ETHERNET_HEADER_SIZE;

        printIPv4HeaderInfo(packet);
        packet += IPv4_HEADER_SIZE;

        printTCPHeaderInfo(packet);
        packet += TCP_HEADER_SIZE;

        printDATA8Byte(packet);
}


void printMACAdress(u_char * macAdr) {
    for(int idx = 0; idx < 6; ++idx) {
        printf("%02x", macAdr[idx]);
        printf("%s", (idx == 5) ? "\n" : ":");
    }    
}

void printEthernetHeaderInfo(const u_char* packet) {
    EtherHD * ethernetHeader = NULL;
    ethernetHeader = (EtherHD*)packet;

    printf("# MAC Address \n");
    printf("Source : "); printMACAdress(ethernetHeader->sourceMAC);
    printf("Destination : "); printMACAdress(ethernetHeader->destinationMAC);
    printf("\n");
}

void printIPv4HeaderInfo(const u_char* packet) {
    IPHD * ipHeader = NULL;
    ipHeader = (IPHD*)packet;

    printf("# IP Address \n");
    printf("Source : %s\n", inet_ntoa(ipHeader->sourceIP));
    printf("Destination : %s\n", inet_ntoa(ipHeader->destinationIP));
    printf("\n");
    
}

void printTCPHeaderInfo(const u_char* packet) {
    TCPHD * tcpHeader = NULL;
    tcpHeader = (TCPHD*)packet;
    
    printf("# PORT \n");
    printf("Source : %d\n", ntohs(tcpHeader->sourcePort));
    printf("Destination : %d\n", ntohs(tcpHeader->destinationPort));
    printf("\n");
}

void printDATA8Byte(const u_char* packet) {
    printf("payLoad : ");
    HDCHK * temp = (HDCHK*)packet;
    for(int i = 0; i < 8; ++i){
        printf("%02x ", temp->temp[i]);
        temp->temp[i] = 0;
    }
    printf("\n");
}

void printHEX(u_char hexAdr){
    printf("%x\n", hexAdr);
}

int isPacketTCP(const u_char* packet) {
    packet += ETHERNET_HEADER_SIZE;
    IPHD * ipHeader = (IPHD*)packet;
    packet -= ETHERNET_HEADER_SIZE;

    return ipHeader->protocolID == 0x06 ? 1 : 0;
}