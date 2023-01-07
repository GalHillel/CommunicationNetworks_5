#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>

#define MAX_PACKET_SIZE 65535
#define true 1

typedef struct packet_data {
    char source_ip[16];
    char dest_ip[16];
    unsigned short source_port;
    unsigned short dest_port;
    time_t timestamp;
    unsigned short total_length;
    unsigned char cache_flag;
    unsigned char steps_flag;
    unsigned char type_flag;
    unsigned short status_code;
    char cache_control[64];
    char data[MAX_PACKET_SIZE];
} packet_data;

int main() {
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr hdr;
    struct packet_data packet_info;
    FILE *fp;
    char filename[64];
    pcap_if_t *devs;

    // Set the filename to the ID provided
    sprintf(filename, "211696521.txt");

    // Open the output file
    fp = fopen(filename, "w");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file\n");
        return 1;
    }

    // Find the device to sniff on
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Select the desired device
    for (dev = devs; dev != NULL; dev = dev->next) {
        if (strcmp(dev->name, "eth0") == 0) {
            // Use this device
            break;
        }
    }

    if (dev == NULL) {
        // No suitable device was found
        fprintf(stderr, "Error finding device\n");
        return 1;
    }

    // Open the device for sniffing
    handle = pcap_open_live(dev->name, MAX_PACKET_SIZE, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device for sniffing: %s\n", errbuf);
        return 1;
    }

    // Free the linked list of devices
    pcap_freealldevs(devs);

    // Set the filter to only capture TCP packets
    struct bpf_program filter;
    char filter_exp[] = "tcp";
    if (pcap_compile(handle, &filter, filter_exp, 0, 0) == -1) {
        fprintf(stderr, "Error setting filter\n");
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Error setting filter\n");
        return 1;
    }

    // Start sniffing packets
    while (true) {
        packet = pcap_next(handle, &hdr);
        if (packet == NULL) {
            // No packet was captured
            continue;
        }
        // Extract the packet information
        memcpy(packet_info.source_ip, packet + 12, 4);
        memcpy(packet_info.dest_ip, packet + 16, 4);
        memcpy(&packet_info.source_port, packet + 20, 2);
        memcpy(&packet_info.dest_port, packet + 22, 2);
        packet_info.timestamp = time(NULL);
        memcpy(&packet_info.total_length, packet + 2, 2);
        packet_info.cache_flag = packet[47] & 0x40;
        packet_info.steps_flag = packet[47] & 0x04;
        packet_info.type_flag = packet[47] & 0x02;
        memcpy(&packet_info.status_code, packet + 56, 2);
        memcpy(packet_info.cache_control, packet + 59, 64);
        memcpy(packet_info.data, packet + 123, hdr.len - 123);

        // Write the packet information to the file
        fprintf(fp, "source_ip: %d.%d.%d.%d\n", packet_info.source_ip[0], packet_info.source_ip[1],
                packet_info.source_ip[2], packet_info.source_ip[3]);
        fprintf(fp, "dest_ip: %d.%d.%d.%d\n", packet_info.dest_ip[0], packet_info.dest_ip[1], packet_info.dest_ip[2],
                packet_info.dest_ip[3]);
        fprintf(fp, "source_port: %d\n", packet_info.source_port);
        fprintf(fp, "dest_port: %d\n", packet_info.dest_port);
        fprintf(fp, "timestamp: %ld\n", packet_info.timestamp);
        fprintf(fp, "total_length: %d\n", packet_info.total_length);
        fprintf(fp, "cache_flag: %d\n", packet_info.cache_flag);
        fprintf(fp, "steps_flag: %d\n", packet_info.steps_flag);
        fprintf(fp, "type_flag: %d\n", packet_info.type_flag);
        fprintf(fp, "status_code: %d\n", packet_info.status_code);
        fprintf(fp, "cache_control: %s\n", packet_info.cache_control);
        fprintf(fp, "data: ");
        for (int i = 0; i < hdr.len - 123; i++) {
            fprintf(fp, "%02x", packet_info.data[i]);
        }
        fprintf(fp, "\n");
    }

    // Close the file and the handle
    fclose(fp);
    pcap_close(handle);

    return 0;
}