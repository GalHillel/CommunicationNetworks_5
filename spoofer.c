#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024

/**
 *This code takes two command line arguments: the IP address of the fake sender and the IP address of the intended recipient.
 *It creates a raw socket and sets the `IP_HDRINCL` option to include the IP header in the packet.
 *It then constructs both the IP header and the ICMP header and calculates the checksums for each.
 *Finally, it combines the headers into a single buffer and sends the packet using the `sendto` function.
 *To spoof other protocols, you will need to replace the `IPPROTO_ICMP` constant with the appropriate protocol number and replace the `struct icmphdr` type
 */

unsigned short checksum(unsigned short *buf, int len);

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <src_ip> <dst_ip>\n", argv[0]);
        return 1;
    }

    // Create a raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        return 1;
    }

    // Set the IP_HDRINCL option to include the IP header
    int optval = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0)
    {
        perror("Error setting IP_HDRINCL option");
        return 1;
    }

    // Create the IP header
    struct iphdr ip_hdr;
    memset(&ip_hdr, 0, sizeof(ip_hdr));
    ip_hdr.ihl = 5;
    ip_hdr.version = 4;
    ip_hdr.tos = 0;
    ip_hdr.tot_len = htons(sizeof(ip_hdr) + sizeof(struct icmphdr));
    ip_hdr.id = htons(rand());
    ip_hdr.frag_off = 0;
    ip_hdr.ttl = 64;
    ip_hdr.protocol = IPPROTO_ICMP;
    ip_hdr.check = 0;
    ip_hdr.saddr = inet_addr(argv[1]);
    ip_hdr.daddr = inet_addr(argv[2]);

    // Calculate the checksum for the IP header
    ip_hdr.check = checksum((unsigned short *)&ip_hdr, sizeof(ip_hdr));

    // Create the ICMP header
    struct icmphdr icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.code = 0;
    icmp_hdr.un.echo.id = 0;
    icmp_hdr.un.echo.sequence = 0;
    icmp_hdr.checksum = 0;

    // Calculate the checksum for the ICMP header
    icmp_hdr.checksum = checksum((unsigned short *)&icmp_hdr, sizeof(icmp_hdr));

    // Combine the IP and ICMP headers and send the packet
    char buf[BUF_SIZE];
    memcpy(buf, &ip_hdr, sizeof(ip_hdr));
    memcpy(buf + sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = ip_hdr.daddr;
    if (sendto(sockfd, buf, sizeof(ip_hdr) + sizeof(icmp_hdr), 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) <
        0)
    {
        perror("Error sending packet");
        return 1;
    }

    printf("Packet sent\n");

    // Close the socket
    close(sockfd);

    return 0;
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