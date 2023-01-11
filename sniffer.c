#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define SIZE_ETHERNET 14
#define SNAP_LEN 65536
#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)

/* IP header */
struct sniff_ip {
    u_char ip_vhl;
    u_short ip_len;
    struct in_addr ip_src, ip_dst;
};

struct sniff_tcp {
    u_short th_sport;
    u_short th_dport;
    u_char th_offx2;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet);

struct sniff_ip *ip;
struct sniff_tcp *tcp;

char timestamp[256];
time_t now;
struct tm *tm;

/*
 * Define some variables for the packet to be written to file
 */
char source_ip[INET_ADDRSTRLEN];
char dest_ip[INET_ADDRSTRLEN];
u_short source_port, dest_port;
char data[256];

/*
 * Define some flags
 */
char cache_flag[] = "NA";
char steps_flag[] = "NA";
char type_flag[] = "NA";
char status_code[] = "NA";
char cache_control[] = "NA";

int main(int argc, char **argv) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    char filter_exp[] = "tcp";
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    /* check command line arguments */
    if (argc == 2) {
        dev = argv[1];
    } else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");
        exit(EXIT_FAILURE);
    } else {
        /* find a capture device if not specified on command line */
        pcap_if_t *allDevs;
        if (pcap_findalldevs(&allDevs, errbuf) == -1) {
            fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
            exit(1);
        }
        dev = allDevs[0].name;

        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                    errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
    int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    /* convert packet's fields to strings */
    inet_ntop(AF_INET, &(ip->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), dest_ip, INET_ADDRSTRLEN);
    source_port = ntohs(tcp->th_sport);
    dest_port = ntohs(tcp->th_dport);

    /* data */
    u_char *data_pointer = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
    int data_size = ntohs(ip->ip_len) - (size_ip + size_tcp);
    int i;
    for (i = 0; i < data_size; i++) {
        sprintf(data + (i * 2), "%02x", data_pointer[i]);
    }

    /* timestamp */
    now = time(0);
    tm = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm);

    /* construct the packet object */
    FILE *fp;
    fp = fopen("galgal.txt", "a");
    if (fp == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }
    fprintf(fp,
            "{ source_ip: %s, dest_ip: %s, source_port: %d, dest_port: %d, timestamp: %s, total_length: %d, cache_flag: %s, steps_flag: %s, type_flag: %s, status_code: %s, cache_control: %s, data: %s }\n",
            source_ip, dest_ip, source_port, dest_port, timestamp, ntohs(ip->ip_len), cache_flag, steps_flag, type_flag,
            status_code, cache_control, data);
    fclose(fp);
}