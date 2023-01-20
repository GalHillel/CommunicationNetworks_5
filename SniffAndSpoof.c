#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <sys/socket.h>

#define BUF_SIZE 1024
#define IP_HDRLEN sizeof(struct iphdr)
#define ICMP_HDRLEN sizeof(struct icmphdr)

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

void spoofEchoReply(const u_char *buffer, int size);

unsigned short checksum(unsigned short *buf, int len);

struct sockaddr_in source, dest;

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

    // Put the device in sniff loop
    pcap_loop(handle, -1, processPacket, NULL);

    pcap_close(handle);

    return 0;
}

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;

    // Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct icmphdr *icmph = (struct icmphdr *)(buffer + IP_HDRLEN + sizeof(struct ethhdr));

    if (icmph->type == 8) // Check the Protocol and do accordingly...
    {
        printf("Received ICMP Echo Request...\n");
        // Create a raw socket
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0)
        {
            perror("Error creating socket");
        }
        // Set the IP_HDRINCL option to include the IP header
        int optval = 1;
        setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval));

        // Create an ICMP packet
        char packet[BUF_SIZE];
        struct iphdr *ip_hdr = (struct iphdr *)packet;
        struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + IP_HDRLEN);

        // Fill in the IP header
        ip_hdr->daddr = iph->saddr;
        ip_hdr->saddr = iph->daddr;
        ip_hdr->ihl = iph->ihl;
        ip_hdr->check = iph->check;
        ip_hdr->id = iph->id;
        ip_hdr->version = iph->version;
        ip_hdr->frag_off = iph->frag_off;
        ip_hdr->protocol = iph->protocol;
        ip_hdr->tos = iph->tos;
        ip_hdr->ttl = iph->ttl;
        ip_hdr->tot_len = htons(sizeof(ip_hdr) + sizeof(struct icmphdr));
        // ip_hdr->check = checksum((unsigned short *)packet, IP_HDRLEN);

        // Fill in the ICMP header
        icmp_hdr->type = ICMP_ECHOREPLY;
        icmp_hdr->code = icmph->code;
        icmp_hdr->un.echo.id = icmph->un.echo.id;
        icmp_hdr->un.echo.sequence = icmph->un.echo.sequence;
        icmp_hdr->checksum = icmph->checksum;
        // icmp_hdr->checksum = checksum((unsigned short *) icmp_hdr, ICMP_HDRLEN);

        // Send the packet
        if (sendto(sockfd, packet, IP_HDRLEN + ICMP_HDRLEN, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
        {
            perror("Error sending packet");
        }
        else
        {
            printf("Sent ICMP Echo Reply.\n");
        }
        close(sockfd);
    }
}

// Function to calculate the checksum for an input buffer
unsigned short checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}