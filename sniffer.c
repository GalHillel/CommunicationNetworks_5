#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <time.h>

struct tcpHdr {
    u_int16_t source;
    u_int16_t dest;
    u_int32_t seq;
    u_int32_t ack_seq;
    u_int16_t doff:4;
    u_int8_t cwr:1;
    u_int8_t ece:1;
    u_int8_t urg:1;
    u_int8_t ack:1;
    u_int8_t psh:1;
};


void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

void gotPacket(const u_char *Buffer, int Size);

void printData(const u_char *data, int Size);

void printIpHeader(const u_char *Buffer);

void printEthernetHeader(const u_char *Buffer);

FILE *pFile;
struct sockaddr_in source, dest;
int tcp = 0, i, j;

int main()
{
    pcap_if_t *pAllDevs, *device;
    pcap_t *handle;

    char errBuf[100], *pDevName, devs[100][100];
    int count = 1, n;

    // First get the list of available devices
    printf("Finding available devices ... \n");
    if (pcap_findalldevs(&pAllDevs, errBuf))
    {
        printf("Error finding devices : %s", errBuf);
        exit(1);
    }
    

    // Print the available devices
    printf("Available Devices:\n");
    for (device = pAllDevs; device != NULL; device = device->next)
    {
        printf("%d. %s - %s\n", count, device->name, device->description);
        if (device->name != NULL)
        {
            strcpy(devs[count], device->name);
        }
        count++;
    }

    // Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d", &n);
    pDevName = devs[n];

    // Open the device for sniffing
    printf("Opening device %s for sniffing ... ", pDevName);
    handle = pcap_open_live(pDevName, 65536, 1, 0, errBuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s : %s\n", pDevName, errBuf);
        exit(1);
    }
    printf("Done\n");

    pFile = fopen("211696521_211696521.txt", "w");
    if (pFile == NULL)
    {
        printf("Unable to create file.");
    }

    // Put the device in sniff loop
    pcap_loop(handle, -1, processPacket, NULL);

    return 0;
}

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;

    // Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    if (iph->protocol == 6) // Check the Protocol and do accordingly...
    {
        tcp++;
        gotPacket(buffer, size);
    }
    printf("TCP : %d \r", tcp);
}

void printEthernetHeader(const u_char *Buffer)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(pFile, "\n");
    fprintf(pFile, "Ethernet Header\n");
    fprintf(pFile, "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0], eth->h_dest[1],
            eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(pFile, "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0], eth->h_source[1],
            eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(pFile, "   |-Protocol            : %u \n", (unsigned short)eth->h_proto);
}

void printIpHeader(const u_char *Buffer)
{
    printEthernetHeader(Buffer);

    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(pFile, "\n");
    fprintf(pFile, "IP Header\n");
    fprintf(pFile, "   |-IP Version        : %d\n", (unsigned int)iph->version);
    fprintf(pFile, "   |-IP Header Length  : %d Bytes\n", ((unsigned int)(iph->ihl)) * 4);
    fprintf(pFile, "   |-TTL               : %d\n", (unsigned int)iph->ttl);
    fprintf(pFile, "   |-Protocol          : %d\n", (unsigned int)iph->protocol);
    fprintf(pFile, "   |-Total Length      : %d\n", ntohs(iph->tot_len));
    fprintf(pFile, "   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
    fprintf(pFile, "   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void gotPacket(const u_char *Buffer, int Size)
{
    unsigned short ipHdrLen;

    struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
    ipHdrLen = iph->ihl * 4;

    struct tcpHdr *pTcpHdr = (struct tcpHdr *)(Buffer + ipHdrLen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + ipHdrLen + pTcpHdr->doff * 4;

    // Extract source and destination IP addresses, source and destination ports
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    // Extract timestamp
    struct timeval tv;
    gettimeofday(&tv, NULL);
    char buffer[30];
    strftime(buffer, 30, "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
    char sec[7];
    printf(sec, ".%06ld", tv.tv_usec);
    strcat(buffer, sec);

    fprintf(pFile, "\n\n***********************TCP Packet*************************\n");

    printIpHeader(Buffer);

    fprintf(pFile, "\n");
    fprintf(pFile, "TCP Header\n");
    fprintf(pFile, "   |-Source Port          : %u\n", ntohs(pTcpHdr->source));
    fprintf(pFile, "   |-Destination Port     : %u\n", ntohs(pTcpHdr->dest));
    fprintf(pFile, "   |-Sequence Number      : %u\n", ntohl(pTcpHdr->seq));
    fprintf(pFile, "   |-Acknowledge Number   : %u\n", ntohl(pTcpHdr->ack_seq));
    fprintf(pFile, "   |-Header Length        : %d BYTES\n", (unsigned int)pTcpHdr->doff * 4);
    fprintf(pFile, "   |-Cache Control        : %d\n", (unsigned int)pTcpHdr->psh);
    fprintf(pFile, "   |-Timestamp            : %s\n", buffer);
    fprintf(pFile, "   |-Cache Flag           : %d\n", (unsigned int)pTcpHdr->cwr);
    fprintf(pFile, "   |-Steps Flag           : %d\n", (unsigned int)pTcpHdr->ece);
    fprintf(pFile, "   |-Type Flag            : %d\n", (unsigned int)pTcpHdr->urg);
    fprintf(pFile, "   |-Status Code          : %d\n", (unsigned int)pTcpHdr->ack);
    fprintf(pFile, "\n");
    fprintf(pFile, "                        DATA Dump                         ");
    fprintf(pFile, "\n");

    fprintf(pFile, "IP Header\n");
    printData(Buffer, ipHdrLen);

    fprintf(pFile, "TCP Header\n");
    printData(Buffer + ipHdrLen, pTcpHdr->doff * 4);

    fprintf(pFile, "Data Payload\n");
    printData(Buffer + header_size, Size - header_size);

    fprintf(pFile, "\n###########################################################");
}

void printData(const u_char *data, int Size)
{
    for (i = 0; i < Size; i++)
    {
        if (i != 0 && i % 16 == 0) // if one line of hex printing is complete...
        {
            fprintf(pFile, "         ");
            for (j = i - 16; j < i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(pFile, "%c", (unsigned char)data[j]);

                else
                    fprintf(pFile, "."); // otherwise print a dot
            }
            fprintf(pFile, "\n");
        }

        if (i % 16 == 0)
            fprintf(pFile, "   ");
        fprintf(pFile, " %02X", (unsigned int)data[i]);

        if (i == Size - 1) // print the last spaces
        {
            for (j = 0; j < 15 - i % 16; j++)
            {
                fprintf(pFile, "   "); // extra spaces
            }

            fprintf(pFile, "         ");

            for (j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                {
                    fprintf(pFile, "%c", (unsigned char)data[j]);
                }
                else
                {
                    fprintf(pFile, ".");
                }
            }

            fprintf(pFile, "\n");
        }
    }
}