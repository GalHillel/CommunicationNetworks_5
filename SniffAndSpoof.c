#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define true 1

void ProcessPacket(unsigned char *, int);
void SendSpoofedEchoReply(struct iphdr *, struct icmphdr *);
unsigned short calculate_checksum(unsigned short *paddress, int len);

struct sockaddr_in source, dest;

int sockRaw;
int i, icmpCount = 0;

int main()
{
    int sAddrSize, dataSize;
    struct sockaddr sockAddr;

    unsigned char *buffer = (unsigned char *)malloc(65536);

    printf("Starting...\n");

    // Create a raw socket for ICMP
    sockRaw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockRaw < 0)
    {
        printf("ICMP Socket Error\n");
        return 1;
    }

    while (true)
    {
        sAddrSize = sizeof sockAddr;
        // Receive a packet from the ICMP socket
        dataSize = recvfrom(sockRaw, buffer, 65536, 0, &sockAddr, &sAddrSize);
        if (dataSize < 0)
        {
            printf("Recvfrom error on ICMP socket, failed to get packets\n");
            return 1;
        }
        else if (dataSize > 0)
        {
            // Process the ICMP packet
            ProcessPacket(buffer, dataSize);
        }
    }
    close(sockRaw);
    printf("Finished");
    return 0;
}

void ProcessPacket(unsigned char *buffer, int size)
{
    // Get the IP Header part of this packet
    struct iphdr *iph = (struct iphdr *)buffer;
    // Get the ICMP Header part of this packet
    struct icmphdr *icmph = (struct icmphdr *)(buffer + sizeof(struct iphdr));
    // Check the ICMP message type
    if (icmph->type == ICMP_ECHO)
    {
        icmpCount++;
        printf("Received an ICMP echo request\n");
        SendSpoofedEchoReply(iph, icmph);
    }
    // For checking
    printf("ICMP echo requests: %d\r", icmpCount);
}

void SendSpoofedEchoReply(struct iphdr *iph, struct icmphdr *icmph)
{
    // Create a raw socket for sending the spoofed packet
    int sockSend = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockSend < 0)
    {
        printf("Error creating send socket\n");
        return;
    }

    // Set the source IP address to be the same as the destination IP address in the received packet
    struct sockaddr_in spoofedSource;
    memset(&spoofedSource, 0, sizeof(spoofedSource));
    spoofedSource.sin_family = AF_INET;
    spoofedSource.sin_addr.s_addr = iph->daddr;
    // Create the spoofed ICMP echo reply packet
    unsigned char *spoofedPacket = (unsigned char *)malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
    struct iphdr *spoofedIph = (struct iphdr *)spoofedPacket;
    struct icmphdr *spoofedIcmph = (struct icmphdr *)(spoofedPacket + sizeof(struct iphdr));

    // Set the IP header fields of the spoofed packet
    spoofedIph->ihl = iph->ihl;
    spoofedIph->version = iph->version;
    spoofedIph->tos = iph->tos;
    spoofedIph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    spoofedIph->id = iph->id;
    spoofedIph->frag_off = iph->frag_off;
    spoofedIph->ttl = iph->ttl;
    spoofedIph->protocol = iph->protocol;
    spoofedIph->check = iph->check;
    spoofedIph->saddr = spoofedSource.sin_addr.s_addr;
    spoofedIph->daddr = iph->saddr;

    // Set the ICMP header fields of the spoofed packet
    spoofedIcmph->type = ICMP_ECHOREPLY;
    spoofedIcmph->code = 0;
    spoofedIcmph->un.echo.id = icmph->un.echo.id;
    spoofedIcmph->un.echo.sequence = icmph->un.echo.sequence;
    spoofedIcmph->checksum = 0;
    spoofedIcmph->checksum = calculate_checksum((unsigned short *)spoofedIcmph, sizeof(struct icmphdr));

    // Send the spoofed packet
    int sent = sendto(sockSend, spoofedPacket, spoofedIph->tot_len, 0, (struct sockaddr *)&spoofedSource, sizeof(spoofedSource));
    if (sent < 0)
    {
        printf("Error sending spoofed packet\n");
        // Create the spoofed ICMP echo reply packet
        unsigned char *spoofedPacket = (unsigned char *)malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
        struct iphdr *spoofedIph = (struct iphdr *)spoofedPacket;
        struct icmphdr *spoofedIcmph = (struct icmphdr *)(spoofedPacket + sizeof(struct iphdr));

        // Set the IP header fields of the spoofed packet
        spoofedIph->ihl = iph->ihl;
        spoofedIph->version = iph->version;
        spoofedIph->tos = iph->tos;
        spoofedIph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
        spoofedIph->id = iph->id;
        spoofedIph->frag_off = iph->frag_off;
        spoofedIph->ttl = iph->ttl;
        spoofedIph->protocol = iph->protocol;
        spoofedIph->check = iph->check;
        spoofedIph->saddr = spoofedSource.sin_addr.s_addr;
        spoofedIph->daddr = iph->saddr;

        // Set the ICMP header fields of the spoofed packet
        spoofedIcmph->type = ICMP_ECHOREPLY;
        spoofedIcmph->code = 0;
        spoofedIcmph->un.echo.id = icmph->un.echo.id;
        spoofedIcmph->un.echo.sequence = icmph->un.echo.sequence;
        spoofedIcmph->checksum = 0;
        spoofedIcmph->checksum = calculate_checksum((unsigned short *)spoofedIcmph, sizeof(struct icmphdr));

        // Send the spoofed packet
        int sent = sendto(sockSend, spoofedPacket, spoofedIph->tot_len, 0, (struct sockaddr *)&spoofedSource, sizeof(spoofedSource));
        if (sent < 0)
        {
            printf("Error sending spoofed packet\n");
        }
        else
        {
            printf("Sent spoofed ICMP echo reply\n");
        }

        close(sockSend);
    }
    else
    {
        printf("Sent spoofed ICMP echo reply\n");
    }

    close(sockSend);
}

unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    for (; len > 1; len -= 2) {
        sum += *w++;
    }
    if (len == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}