#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

struct Network {
	char eth_dmac[6];
	char eth_smac[6];
	char ip_sip[4];
	char ip_dip[4];
	char tcp_sport[2];
	char tcp_dport[2];
	char data[400];
};

struct Network Network;

int main(int argc, char *argv[]) {
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	int result;
	int cnt = 0;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterrhandle));
		return(2);
	}
printf("-3s\t%-17s\t%-17s\t%-15s\t%-15s\t%-10s\t%-10s\t%-10s\n","num,"eth_dmac","eth_smac","ip_sip","ip_dip","tcp_sport","tcp_dport","data");
			
/* Grab  packet */
	while((Res = pcap_next_ex(handle, &header, &packet))>=0){
	/* Print its length */
	int i=0;
	int j=0;
	
		
	if(Res==0)
		continue;
	if(*(packet+23)!=0x6||(*(packet+12)!=0x8&&*(packet+13)!=0x0))
		continue;
	
	printf("%-3d\t",cnt);
	cnt++;
	for(i=0; i<6; i++){
		printf("%02x ", *(packet+i));
		//sprintf(p.eth_smac+(2*i), "%02x ",*(packet+i));		
		//p.eth_smac[i]=*(packet+i);
	}
	//printf("%s", p.eth_smac);
	printf("\t");
	for(;i<12; i++){
		printf("%02x ", *(packet+i));
		//sprintf(p.eth_dmac+(2*(i-6)), "%02x ",*(packet+i));		
	}
	//printf("%s", p.eth_dmac);
	
	j=26;
	printf("\t");
	for(i=j; i<j+4;i++)
	{
		printf("%03d", *(packet+i));
		if(i<j+3) printf(".");
	}printf("\t");
	
	j=30;
	for(i=j; i<j+4;i++)
	{
		printf("%03d", *(packet+i));
		if(i<j+3) printf(".");}
	printf("\t");
	j=34;
	int port=0;
	for(i=j; i<j+2; i++)
	if(i==j)
		port+=(int)*(packet+i)*16*16;
	else
		port+=(int)*(packet+i);
	printf("%-10d\t",port);
	j=36;
	port=0;
	for(i=j; i<j+2; i++)
	if(i==j)
		port+=(int)*(packet+i)*16*16;
	else
		port+=(int)*(packet+i);
	printf("%-10d\t",port);
	j=54;
	//for(i=j; i<(header->len); i++)
	for(i=j; i<j+21; i++)
		printf("%c", *(packet+i));
	printf("\n");
	/* And close the session */
	if(cnt==10)
		break;
}		pcap_close(handle);
	return(0);
}
