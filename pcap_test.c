#include <pcap.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )
 
#define FILTER_RULE "tcp port 80"
 
struct ether_addr
{
    unsigned char ether_addr_octet[6];
};
 
struct ether_header
{
    struct  ether_addr ether_dhost;
    struct  ether_addr ether_shost;
    unsigned short ether_type;
};
 
struct ip_header
{
    unsigned char ip_header_len:4;
    unsigned char ip_version:4;
    unsigned char ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned char ip_frag_offset:5;
    unsigned char ip_more_fragment:1;
    unsigned char ip_dont_fragment:1;
    unsigned char ip_reserved_zero:1;
    unsigned char ip_frag_offset1;
    unsigned char ip_ttl;
    unsigned char ip_protocol;
    unsigned short ip_checksum;
    struct in_addr ip_srcaddr;
    struct in_addr ip_destaddr;
};
 
struct tcp_header
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char ns:1;
    unsigned char reserved_part1:3;
    unsigned char data_offset:4;
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ecn:1;
    unsigned char cwr:1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};
 
void print_ether_header(const unsigned char *data);
int print_ip_header(const unsigned char *data);
int print_tcp_header(const unsigned char *data);
void print_data(const unsigned char *data);
 
int main(int argc, char* argv[]){

    char track[] = "Forensics";
    char name[] = "SeoKangYoun";
    printf("[bob6][%s]pcap_test[%s] \n", track, name);
    


    if (argc ==1){
        printf("Error pcap_test [option] \n");
        return 0;
    }

    bpf_u_int32 net;



	pcap_if_t *alldevs=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    int offset=0;
   
    if (pcap_findalldevs(&alldevs, errbuf)==-1){
            printf("dev find failed\n");
            return -1;
    }
    if (alldevs==NULL){
            printf("no devs found\n");
            return -1;
    }
    
    pcap_if_t *d;
    int i;
    int inum;

    inum = 1;
    for(d=alldevs, i=0; i<inum-1; d=d->next, i++);
 
    pcap_t  *fp;
    if ((fp = pcap_open_live(argv[1], 65536, 1, 20, errbuf))==NULL){
        printf("pcap open failed\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
 
    printf("pcap open successful\n");
 
        struct bpf_program  fcode;
    if (pcap_compile(fp, &fcode, FILTER_RULE, 1, NULL) < 0){
        printf("pcap compile failed\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    if (pcap_setfilter(fp, &fcode) <0 ){
        printf("pcap compile failed\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
 
    pcap_freealldevs(alldevs); 

    struct pcap_pkthdr *header;
   
    const unsigned char *pkt_data;
    int res;
    time_t timer_s = 0;
    time_t timer_e = 0; 
	timer_s = clock();

    while((res=pcap_next_ex(fp, &header,&pkt_data))>=0 && (timer_e - timer_s < 10000 )){
        if (res==0) continue;
	    print_ether_header(pkt_data);
    	pkt_data = pkt_data + 14;       
    	offset = print_ip_header(pkt_data);
    	pkt_data = pkt_data + offset;           
    	offset = print_tcp_header(pkt_data);
    	pkt_data = pkt_data + offset;     
    	print_data(pkt_data);
    	timer_e = clock();
    }

    printf("pcap end!!\n");

    return 0;
 
}
 
void print_ether_header(const unsigned char *data)
{
    struct  ether_header *eh;               
    unsigned short ether_type;                     
    eh = (struct ether_header *)data;       
    ether_type=ntohs(eh->ether_type);       
   
    if (ether_type!=0x0800)
    {
            printf("ether type wrong\n");
            return ;
    }
    
    printf("\n============ETHERNET HEADER==========\n");
    printf("Dst MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for dest
                eh->ether_dhost.ether_addr_octet[0],
                eh->ether_dhost.ether_addr_octet[1],
                eh->ether_dhost.ether_addr_octet[2],
                eh->ether_dhost.ether_addr_octet[3],
                eh->ether_dhost.ether_addr_octet[4],
                eh->ether_dhost.ether_addr_octet[5]);
    printf("Src MAC Addr [%02x:%02x:%02x:%02x:%02x:%02x]\n", // 6 byte for src
                eh->ether_shost.ether_addr_octet[0],
                eh->ether_shost.ether_addr_octet[1],
                eh->ether_shost.ether_addr_octet[2],
                eh->ether_shost.ether_addr_octet[3],
                eh->ether_shost.ether_addr_octet[4],
                eh->ether_shost.ether_addr_octet[5]);
}
 
int print_ip_header(const unsigned char *data){
    struct  ip_header *ih;         
    ih = (struct ip_header *)data;

    printf("\n============IP HEADER============\n");
    printf("IPv%d ver \n", ih->ip_version);
    printf("Packet Length : %d\n", ntohs(ih->ip_total_length)+14);
    printf("TTL : %d\n", ih->ip_ttl);
    if(ih->ip_protocol == 0x06)
    {
            printf("Protocol : TCP\n");
    }
    printf("Src IP Addr : %s\n", inet_ntoa(ih->ip_srcaddr) );
    printf("Dst IP Addr : %s\n", inet_ntoa(ih->ip_destaddr) );
   
    // return to ip header size
    return ih->ip_header_len*4;
}
 
int print_tcp_header(const unsigned char *data){
    struct  tcp_header *th;
    th = (struct tcp_header *)data;

    printf("\n============TCP HEADER============\n");
    printf("Src Port Num : %d\n", ntohs(th->source_port) );
    printf("Dest Port Num : %d\n", ntohs(th->dest_port) );
    printf("Flag :");
    if(ntohs(th->cwr))
    {
            printf(" CWR ");
    }
    if(ntohs(th->ecn))
    {
            printf(" ENC ");
    }
    if(ntohs(th->urg))
    {
            printf(" URG ");
    }
    if(ntohs(th->ack))
    {
            printf(" ACK ");
    }
    if(ntohs(th->psh))
    {
            printf(" PUSH ");
    }
    if(ntohs(th->rst))
    {
            printf(" RST ");
    }
    if(ntohs(th->syn))
    {
            printf(" SYN ");
    }
    if(ntohs(th->fin))
    {
            printf(" FIN ");
    }
   
    printf("\n");

    // return to tcp header size
    return th->data_offset*4;
}
 
void print_data(const unsigned char *data){
    printf("\n============DATA============\n");
    printf("%X\n", data);
}
