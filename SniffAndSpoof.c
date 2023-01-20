#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>

unsigned short checksum(unsigned short *pAddress, int len);

void sendSpoof(struct iphdr *pIpHeader);

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

int main()
{

    char errBuf[PCAP_ERRBUF_SIZE], *device, devs[100][100], *filter = "icmp";
    struct bpf_program filter_exp;
    bpf_u_int32 net, mask;
    pcap_if_t *pAllDevs, *dev;
    pcap_t *handle;
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
    for (dev = pAllDevs; dev != NULL; dev = dev->next)
    {
        printf("%d. %s - %s\n", count, dev->name, dev->description);
        if (dev->name != NULL)
        {
            strcpy(devs[count], dev->name);
        }
        count++;
    }

    // Ask user which device to sniff
    printf("Enter the number of the device you want to sniff : ");
    scanf("%d", &n);

    // Open the device for sniffing
    printf("\nOpening device for sniffing ... \n");

    device = devs[n];

    if (pcap_lookupnet(device, &net, &mask, errBuf) == -1)
    {
        mask = 0;
        net = 0;
    }

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errBuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error opening device %s: %s\n", device, errBuf);
        return -1;
    }

    if (pcap_compile(handle, &filter_exp, filter, 0, net) == -1)
    {
        fprintf(stderr, "Error opening device %s: %s\n",
                filter, pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &filter_exp) == -1)
    {
        fprintf(stderr, "Error compiling filter %s: %s\n",
                filter, pcap_geterr(handle));
        return -1;
    }

    pcap_loop(handle, -1, processPacket, NULL);
    pcap_close(handle);
    pcap_freecode(&filter_exp);

    return 0;
}

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{

    struct iphdr *pIpHdr = (struct iphdr *)(buffer + 14);
    struct icmphdr *pIcmpHdr = (struct icmphdr *)(buffer + 14 + sizeof(struct iphdr));

    if (pIcmpHdr->type == 8)
    {
        printf("Received ICMP Echo Request...\n");
        char pong[1500];
        memset(pong, 0, 1500);
        struct iphdr *ipHeader = (struct iphdr *)(pong + 14);
        struct icmphdr *icmpHeader = ((struct icmphdr *)(pong + 14 + sizeof(struct iphdr)));
        ipHeader->daddr = pIpHdr->saddr;
        ipHeader->saddr = pIpHdr->daddr;
        ipHeader->ihl = pIpHdr->ihl;
        ipHeader->check = pIpHdr->check;
        ipHeader->id = pIpHdr->id;
        ipHeader->version = pIpHdr->version;
        ipHeader->frag_off = pIpHdr->frag_off;
        ipHeader->frag_off = pIpHdr->frag_off;
        ipHeader->version = pIpHdr->version;
        ipHeader->protocol = pIpHdr->protocol;
        ipHeader->tos = pIpHdr->tos;
        ipHeader->ttl = pIpHdr->ttl;
        ipHeader->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

        icmpHeader->code = pIcmpHdr->code;
        icmpHeader->type = ICMP_ECHOREPLY;
        icmpHeader->un.echo.id = pIcmpHdr->un.echo.id;
        icmpHeader->un.echo.sequence = pIcmpHdr->un.echo.sequence;
        icmpHeader->checksum = checksum((unsigned short *)icmpHeader, sizeof(struct icmphdr));

        sendSpoof(ipHeader);
    }
}

void sendSpoof(struct iphdr *pIpHeader)
{
    struct sockaddr_in dest_info;
    int optVal = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &optVal, sizeof(optVal));

    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = pIpHeader->daddr;

    if (sendto(sock, pIpHeader, ntohs(pIpHeader->tot_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0)
    {
        perror("Error sending packet");
    }
    else
    {
        printf("Sent ICMP Echo Reply.\n");
    }
    close(sock);
}

// Function to calculate the checksum for an input buffer
unsigned short checksum(unsigned short *pAddress, int len)
{
    int i = len;
    int sum = 0;
    unsigned short *w = pAddress;
    unsigned short answer = 0;

    while (i > 1)
    {
        sum += *w++;
        i -= 2;
    }
    if (i == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}