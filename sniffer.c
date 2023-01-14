#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define true 1

void ProcessPacket(unsigned char *, int);

void printIpHeader(unsigned char *);

void printTcpPacket(unsigned char *, int);

void printIcmpPacket(unsigned char *, int);

void PrintData(unsigned char *, int);

struct sockaddr_in source, dest;

int sockRaw, sockIcmp;
FILE *file;
int i, j, tcpCount = 0, icmpCount = 0;

int main()
{
    int sAddrSize, dataSize;
    struct sockaddr sockAddr;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    file = fopen("211696521_211696521.txt", "w");
    if (file == NULL)
        printf("Unable to create file");
    printf("Starting...\n");

    // Create a raw socket for TCP
    sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockRaw < 0)
    {
        printf("TCP Socket Error\n");
        return 1;
    }

    // Create a raw socket for ICMP
    sockIcmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockIcmp < 0)
    {
        printf("ICMP Socket Error\n");
        return 1;
    }

    while (true)
    {
        sAddrSize = sizeof sockAddr;
        // Receive a packet from the TCP socket
        dataSize = recvfrom(sockRaw, buffer, 65536, 0, &sockAddr, &sAddrSize);
        if (dataSize < 0)
        {
            printf("Recvfrom error on TCP socket, failed to get packets\n");
            return 1;
        }
        else if (dataSize > 0)
        {
            // printf("Sniffing TCP packet...");
            // Process the TCP packet
            ProcessPacket(buffer, dataSize);
        }

        // Receive a packet from the ICMP socket
        dataSize = recvfrom(sockIcmp, buffer, 65536, 0, &sockAddr, &sAddrSize);
        if (dataSize < 0)
        {
            printf("Recvfrom error on ICMP socket, failed to get packets\n");
            return 1;
        }
        else if (dataSize > 0)
        {
            // printf("Sniffing ICMP packet...");
            // Process the ICMP packet
            ProcessPacket(buffer, dataSize);
        }
    }
    close(sockRaw);
    close(sockIcmp);
    printf("Finished");
    return 0;
}

void ProcessPacket(unsigned char *buffer, int size)
{
    // Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr *)buffer;
    // Check the Protocol
    switch (iph->protocol)
    {
    // ICMP Protocol
    case 1:
        icmpCount++;
        printIcmpPacket(buffer, size);
        break;

        // TCP Protocol
    case 6:
        tcpCount++;
        printTcpPacket(buffer, size);
        break;
    }
    // For checking
    printf("TCP packets: %d ICMP packets: %d\r", tcpCount, icmpCount);
}

void printIpHeader(unsigned char *Buffer)
{
    struct iphdr *iph = (struct iphdr *)Buffer;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(file, "\n");
    fprintf(file, "IP Header\n");
    fprintf(file, "   |-IP Version        : %d\n", (unsigned int)iph->version);
    fprintf(file, "   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl,
            ((unsigned int)(iph->ihl)) * 4);
    fprintf(file, "   |-TTL      : %d\n", (unsigned int)iph->ttl);
    fprintf(file, "   |-Protocol : %d\n", (unsigned int)iph->protocol);
    fprintf(file, "   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
    fprintf(file, "   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

void printTcpPacket(unsigned char *Buffer, int Size)
{
    unsigned short size;

    struct iphdr *iph = (struct iphdr *)Buffer;
    size = iph->ihl * 4;

    struct tcphdr *tcpHdr = (struct tcphdr *)(Buffer + size);

    fprintf(file, "\n\n***********************TCP Packet*************************\n");

    printIpHeader(Buffer);

    fprintf(file, "\n");
    fprintf(file, "TCP Header\n");
    fprintf(file, "   |-Source Port      : %u\n", ntohs(tcpHdr->source));
    fprintf(file, "   |-Destination Port : %u\n", ntohs(tcpHdr->dest));
    fprintf(file, "   |-Header Length      : %d DWORDS or %d BYTES\n", (unsigned int)tcpHdr->doff,
            (unsigned int)tcpHdr->doff * 4);
    fprintf(file, "   |-Urgent Pointer : %d\n", tcpHdr->urg_ptr);
    fprintf(file, "\n");
    fprintf(file, "                        DATA Dump                         ");
    fprintf(file, "\n");

    fprintf(file, "IP Header\n");
    PrintData(Buffer, size);

    fprintf(file, "TCP Header\n");
    PrintData(Buffer + size, tcpHdr->doff * 4);

    fprintf(file, "Data Payload\n");
    PrintData(Buffer + size + tcpHdr->doff * 4, (Size - tcpHdr->doff * 4 - iph->ihl * 4));

    fprintf(file, "\n###########################################################");
}

void printIcmpPacket(unsigned char *Buffer, int Size)
{
    unsigned short size;

    struct iphdr *iph = (struct iphdr *)Buffer;
    size = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + size);

    fprintf(file, "\n\n***********************ICMP Packet*************************\n");

    printIpHeader(Buffer);

    fprintf(file, "\n");

    fprintf(file, "ICMP Header\n");
    fprintf(file, "   |-Type : %d", (unsigned int)(icmph->type));

    if ((unsigned int)(icmph->type) == 11)
        fprintf(file, "  (TTL Expired)\n");
    else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
        fprintf(file, "  (ICMP Echo Reply)\n");
    fprintf(file, "   |-Code : %d\n", (unsigned int)(icmph->code));
    fprintf(file, "\n");

    fprintf(file, "IP Header\n");
    PrintData(Buffer, size);

    fprintf(file, "ICMP Header\n");
    PrintData(Buffer + size, sizeof icmph);

    fprintf(file, "Data Payload\n");
    PrintData(Buffer + size + sizeof icmph, (Size - sizeof icmph - iph->ihl * 4));

    fprintf(file, "\n###########################################################");
}

void PrintData(unsigned char *data, int Size)
{

    for (i = 0; i < Size; i++)
    {
        if (i != 0 && i % 16 == 0)
        {
            fprintf(file, "         ");
            for (j = i - 16; j < i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(file, "%c", (unsigned char)data[j]);

                else
                    fprintf(file, ".");
            }
            fprintf(file, "\n");
        }

        if (i % 16 == 0)
            fprintf(file, "   ");
        fprintf(file, " %02X", (unsigned int)data[i]);

        if (i == Size - 1)
        {
            for (j = 0; j < 15 - i % 16; j++)
                fprintf(file, "   ");

            fprintf(file, "         ");

            for (j = i - i % 16; j <= i; j++)
            {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(file, "%c", (unsigned char)data[j]);
                else
                    fprintf(file, ".");
            }
            fprintf(file, "\n");
        }
    }
}