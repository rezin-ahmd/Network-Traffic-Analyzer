#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define MAX_PACKETS 100

int packet_count = 0;

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (packet_count >= MAX_PACKETS) {
        pcap_breakloop((pcap_t *)user_data);
        return;
    }

    pcap_dumper_t *output_pcap = (pcap_dumper_t *)user_data;

    struct ethhdr *eth_header = (struct ethhdr *)packet;
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);

        printf("\n");
        printf("Protocol: TCP\n");
        printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
        printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
        printf("Source Port: %u\n", ntohs(tcp_header->source));
        printf("Destination Port: %u\n", ntohs(tcp_header->dest));
        printf("Header Length: %u bytes\n", tcp_header->doff * 4);
        printf("Payload Length: %u bytes\n", pkthdr->len - (sizeof(struct ethhdr) + ip_header->ihl * 4 + tcp_header->doff * 4));

        int payload_offset = sizeof(struct ethhdr) + ip_header->ihl * 4 + tcp_header->doff * 4;
        int payload_length = pkthdr->len - payload_offset;
        payload_length = payload_length > 16 ? 16 : payload_length; // Limit to 16 bytes for simplicity

        printf("Payload Data: ");
        for (int i = 0; i < payload_length; i++) {
            printf("%02X ", packet[payload_offset + i]);
        }
        printf("\n");

        // Store packet data in .pcap file
        pcap_dump((u_char *)output_pcap, pkthdr, packet);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header->ihl * 4);

        printf("\n");
        printf("Protocol: UDP\n");
        printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
        printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
        printf("Source Port: %u\n", ntohs(udp_header->source));
        printf("Destination Port: %u\n", ntohs(udp_header->dest));
        printf("Header Length: %u bytes\n", sizeof(struct udphdr));
        printf("Payload Length: %u bytes\n", pkthdr->len - (sizeof(struct ethhdr) + ip_header->ihl * 4 + sizeof(struct udphdr)));

        int payload_offset = sizeof(struct ethhdr) + ip_header->ihl * 4 + sizeof(struct udphdr);
        int payload_length = pkthdr->len - payload_offset;
        payload_length = payload_length > 16 ? 16 : payload_length; // Limit to 16 bytes for simplicity

        printf("Payload Data: ");
        for (int i = 0; i < payload_length; i++) {
            printf("%02X ", packet[payload_offset + i]);
        }
        printf("\n");

        // Store packet data in .pcap file
        pcap_dump((u_char *)output_pcap, pkthdr, packet);
    } else {
        printf("\n");
        printf("Protocol: Unknown\n");
    }

    packet_count++;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;

    // Open the capture interface (e.g., "eth0")
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface: %s\n", errbuf);
        return 1;
    }

    // Open a .pcap output file for writing
    pcap_dumper_t *output_pcap = pcap_dump_open(handle, "output.pcap");
    if (output_pcap == NULL) {
        fprintf(stderr, "Error opening output file\n");
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, packet_handler, (u_char *)output_pcap);

    // Close the output file and capture handle
    pcap_dump_close(output_pcap);
    pcap_close(handle);

    return 0;
}

