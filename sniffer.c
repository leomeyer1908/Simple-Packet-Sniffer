#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <netinet/if_ether.h> // For Ethernet header
#include <netinet/ip.h> // For IP header structure
#include <netinet/tcp.h> // For TCP header structure
#include <netinet/udp.h> // For UDP header

#define BUFFER_SIZE 1024
#define INTERFACE "en0" // Name of the virtual network interface


void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Print packet length
    printf("Packet length: %d\n", pkthdr->len);

    // Ethernet Header
    struct ether_header *eth_header = (struct ether_header *) packet;
    printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_header->ether_shost[0], eth_header->ether_shost[1],
        eth_header->ether_shost[2], eth_header->ether_shost[3],
        eth_header->ether_shost[4], eth_header->ether_shost[5]);
    printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        eth_header->ether_dhost[0], eth_header->ether_dhost[1],
        eth_header->ether_dhost[2], eth_header->ether_dhost[3],
        eth_header->ether_dhost[4], eth_header->ether_dhost[5]);

    // Determine the network layer protocol
    uint16_t ethertype = ntohs(eth_header->ether_type);
    if (ethertype == ETHERTYPE_IP) { // IPv4
        // IP Header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
        printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

        // Determine the transport layer protocol
        switch (ip_header->ip_p) {
            case IPPROTO_TCP: // TCP
                printf("Transport Protocol: TCP\n");
                // TCP Header
                struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                printf("Source Port: %d\n", ntohs(tcp_header->th_sport));
                printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
                break;
            case IPPROTO_UDP: // UDP
                printf("Transport Protocol: UDP\n");
                // UDP Header
                struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);
                printf("Source Port: %d\n", ntohs(udp_header->uh_sport));
                printf("Destination Port: %d\n", ntohs(udp_header->uh_dport));
                break;
            default:
                printf("Transport Protocol: Unknown\n");
                break;
        }
    } else {
        printf("Network Protocol: Unknown (EtherType: %04x)\n", ethertype);
    }

    printf("\n");
}

int main ()
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  printf("Settings up capture\n");
  // Open the virtual network interface for capturing packets
  handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", INTERFACE, errbuf);
      return 1;
  }

  printf("Starting capture loop\n");
  // Start capturing packets indefinitely
  pcap_loop(handle, -1, packet_handler, NULL);

  // Close the capture handle when done
  pcap_close(handle);

  return 0;
}
