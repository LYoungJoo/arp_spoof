#include <iostream>
#include <cstdint>
#include <pcap.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

using namespace std;

struct eth {
	u_int8_t srcmac[6];
	u_int8_t destmac[6];
	u_int16_t type;

	void printSrcMAC(eth *eth_header){
		cout << "Src MAC - ";
		for(int i = 0; i < 6; ++i) {
			printf("%2X", ((*eth_header).srcmac[i]));
			if ( i != 5)
				printf(":");
		}
		cout << endl;
	}

	void printDestMAC(eth *eth_header){
		cout << "Dest MAC - ";
		for(int i = 0; i < 6; ++i) {
			printf("%02X", ((*eth_header).destmac[i]));
			if ( i != 5)
				printf(":");
		}
		cout << endl;
	}
};

struct sendingarp {
    u_int8_t destmac[6];
    u_int8_t srcmac[6];
    u_int16_t type;
    u_int16_t hardware_type;
    u_int16_t protocol_type;
    u_int8_t hardware_len;
    u_int8_t protocol_len;
    u_int16_t operation_code;
    u_int8_t sender_mac[6];
    u_int8_t sender_ip[4];
    u_int8_t target_mac[6];
    u_int8_t target_ip[4];
};

struct arp_s {
	u_int16_t hardware_type;
	u_int16_t protocol_type;
	u_int8_t hardware_len;
	u_int8_t protocol_len;
	u_int16_t operation_code;
	u_int8_t sender_mac[6];
	u_int8_t sender_ip[4];
	u_int8_t target_mac[6];
	u_int8_t target_ip[4];

	void printarp(arp_s *arp_header){
		printf("hardware_type %x\n",ntohs(arp_header->hardware_type));
		printf("protocol_type : %x\n",arp_header->protocol_type);
		printf("hardware_len : %x\n", arp_header->hardware_len);
		printf("protocol_len : %x\n", arp_header->protocol_len);
		printf("operation_code : %x\n" , ntohs(arp_header->operation_code));
	}

};

struct char_mac { // transfer mac
	char mac1[2];
	char colon1;
	char mac2[2];
	char colon2;
	char mac3[2];
	char colon3;
	char mac4[2];
	char colon4;
	char mac5[2];
	char colon5;
	char mac6[2];
};

void getmac(char dev[20], char my_mac[6])
{
    FILE *fp;
    int state;
    char sum[200] = "ifconfig ";
    char buff[20];
    char tmp[20];
    char *ptr;
	char_mac *macaddr;

	
    strcpy(tmp,dev);
    strcat(tmp," | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'");
    strcat(sum, tmp);

    fp = popen(sum, "r");
    fgets(buff, 19, fp);
	strcpy(my_mac,buff);

	macaddr = (char_mac *)buff;
	printf("MY MAC ADD : %s\n\n",macaddr->mac1);
	my_mac[0] = strtol(macaddr->mac1, &ptr, 16);     
	my_mac[1] = strtol(macaddr->mac2, &ptr, 16);     
	my_mac[2] = strtol(macaddr->mac3, &ptr, 16);     
	my_mac[3] = strtol(macaddr->mac4, &ptr, 16);     
	my_mac[4] = strtol(macaddr->mac5, &ptr, 16);     
	my_mac[5] = strtol(macaddr->mac6, &ptr, 16);     

	return;
}


int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	//char filter_exp[] = "port 80";	/* The filter expression */
	char filter_exp[0];
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	bool chk;

	char my_mac[6]; // save my_mac
	eth *eth_header; // eth_header
	arp_s *arp_header; // arp_header
	sendingarp *send_arp; // arp_packet_str
	char senderip[20], targetip[20];
	const u_char *send_packet = (u_char *)malloc(60); // arp_packet

	if( argc > 3 && argc % 2 == 0 ){ 
		dev = pcap_lookupdev(errbuf);
		pcap_lookupnet(dev, &net, &mask, errbuf);

		inet_pton(AF_INET, argv[2], senderip);
		inet_pton(AF_INET, argv[3], targetip);
	}
	else {
		printf("argv error : ./arppac eth0 senderip targetip\n");
		return 0;
	}

	getmac(dev, my_mac);
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);


//////////////// Make Arp Packet ////////////////

	send_arp = (sendingarp *)send_packet;
		
	for(int i=0; i < 6; ++i)
		send_arp->destmac[i] = 0xff;
	for(int i=0; i < 6; ++i)
		send_arp->srcmac[i] = my_mac[i]^0xffffff00;

	send_arp->type = ntohs(0x0806);
	send_arp->hardware_type = ntohs(0x01); // eth
	send_arp->protocol_type = ntohs(0x0800); // ipv4
	send_arp->hardware_len = 0x6;
	send_arp->protocol_len = 0x4;
	send_arp->operation_code = ntohs(0x1); // reqeust

	for(int i=0; i < 6; ++i)
		send_arp->sender_mac[i] = my_mac[i]^0xffffff00;

	for(int i=0; i < 6; ++i)
		send_arp->sender_ip[i] = senderip[i]^0xffffff00;

	for(int i=0; i < 6; ++i)
		send_arp->target_mac[i] = 0x00;

	for(int i=0; i < 6; ++i)
		send_arp->target_ip[i] = targetip[i]^0xffffff00;
	
////////////////////////////////////////////////////

	for( int i = 0; i < 2000; ++i)
		pcap_sendpacket(handle,(const u_char *)send_arp,60);

	while(0 < (chk = pcap_next_ex(handle, &header, &packet)))
	{
		if (chk == 0)
			continue;
		else {
			eth_header = (eth *)packet;
			if ((*eth_header).type == ntohs(0x0806)) {
				arp_header = (arp_s*)(packet+14);
				if(arp_header->operation_code == ntohs(0x2)){
					cout << "======================== PACKET ========================" << endl;
					cout << "1) ETH HEADER" << endl;
					eth_header->printSrcMAC(eth_header);
					eth_header->printDestMAC(eth_header);
					cout << "2) ARP HEADER" << endl;
					arp_header->printarp(arp_header);
				}
				
			}
		}
	}
}
