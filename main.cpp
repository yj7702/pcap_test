#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
//inet_ntop


struct ether_header *eth_h; 
struct ip *ip_h;
struct tcphdr *tcp_h; 
char * packet_data;

#define ETHERNET_SIZE 14
#define MAX_DATA 16

void viewdata(const uint8_t *packet, int ip_size, int tcp_size){

  ip_size = sizeof(struct ip);
  tcp_size = sizeof(struct tcphdr);

  packet_data = (char *)packet + ETHERNET_SIZE + ip_size + tcp_size;

  printf("Packet Data : ");
  for(int i=0; i<MAX_DATA; i++){
      printf("%02x", packet_data[i]);
        if(i%15==1)
          printf("\n");
    }
    printf("\n");
}


void getTCP(const uint8_t *packet, int ip_size){

  tcp_h = (struct tcphdr *)(packet+ ETHERNET_SIZE + ip_size);

  printf("Src Port : %d\n", ntohs(tcp_h->th_sport));
  printf("Dst Port: %d\n", ntohs(tcp_h->th_dport));
    
  int tcp_size = tcp_h->th_off*4;
  viewdata(packet, ip_size, tcp_size);

}


void getIP(const uint8_t *packet){

  ip_h = (struct ip *)(packet + ETHERNET_SIZE);

  char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &(ip_h->ip_src), s_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(ip_h->ip_dst), d_ip, INET_ADDRSTRLEN);
  printf("Src_IP : %s \n", s_ip);
  printf("Dst_IP : %s \n", d_ip);


  if(ip_h->ip_p == IPPROTO_TCP)
    {
        int ip_size = ip_h->ip_hl*4;
        getTCP(packet, ip_size);
    }
  else
    printf("Not TCP packet \n");
    

}

void getMAC(const uint8_t *packet){

  eth_h = (struct  ether_header*)packet; 

  printf("\n========================================\n\n");

  for(int i=0; i<ETHER_ADDR_LEN; i++){
    printf("%02x:", eth_h->ether_shost[i]);
  }
    printf("\b");
    printf("->");

  for(int i=0; i<ETHER_ADDR_LEN; i++){
      printf("%02x:", eth_h->ether_dhost[i]);
  }
      printf("\b");
      printf("\n");


    uint16_t eh_type = ntohs(eth_h->ether_type);
    if(eh_type == ETHERTYPE_IP) 
        getIP(packet); 
    else
        printf("Not Support Protocol \n");
}

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}



int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while(1) {
    struct pcap_pkthdr* header; //header info
    const u_char* packet; //start
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //printf("%u bytes captured\n", header->caplen);
    getMAC(packet);

  }

  pcap_close(handle);
  return 0;
}
