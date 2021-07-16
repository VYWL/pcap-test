#include "pcapTest.h"

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = customized_pcap_open(&param, errbuf);

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;

		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        if(!isPacketTCP(packet)) continue;
        
        printPacketInfo(packet);

        printf("Total %u bytes captured\n", header->caplen);
        printf("#####################################\n");

	}

	pcap_close(pcap);
}