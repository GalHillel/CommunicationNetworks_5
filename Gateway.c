#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define P 80            // port number P
#define P_PLUS_1 81     // port number P+1
#define MAX_BUF_LEN 100 // maximum buffer length

int main(int argc, char *argv[])
{
    // check for correct number of command line arguments
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s hostname\n", argv[0]);
        exit(1);
    }

    // create a socket for sending datagrams
    int sockOut = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockOut < 0)
    {
        perror("Error creating outgoing socket");
        exit(1);
    }

    // create a socket for receiving datagrams
    int sockIn = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockIn < 0)
    {
        perror("Error creating incoming socket");
        exit(1);
    }

    // set up server address for outgoing socket
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(P_PLUS_1);
    inet_aton(argv[1], &serverAddr.sin_addr);
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

    // bind incoming socket to port P
    struct sockaddr_in myAddr;
    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(P);
    myAddr.sin_addr.s_addr = INADDR_ANY;
    memset(myAddr.sin_zero, '\0', sizeof myAddr.sin_zero);
    if (bind(sockIn, (struct sockaddr *)&myAddr, sizeof myAddr) < 0)
    {
        perror("Error binding incoming socket to port P");
        exit(1);
    }

    // enter infinite loop
    while (1)
    {
        // receive datagram from port P
        char buf[MAX_BUF_LEN];
        struct sockaddr_in senderAddr;
        socklen_t senderLen = sizeof senderAddr;
        int bytesReceived = recvfrom(sockIn, buf, MAX_BUF_LEN, 0, (struct sockaddr *)&senderAddr, &senderLen);
        if (bytesReceived < 0)
        {
            // add back carry outs from top 16 bits to low 16 bitsperror("Error receiving datagram on port P");
            exit(1);
        }

        // simulate unreliable network by discarding datagram with 50% probability
        float randNum = ((float)random()) / ((float)RAND_MAX);
        if (randNum > 0.5)
        {
            // forward datagram to host on port P+1
            int bytesSent = sendto(sockOut, buf, bytesReceived, 0, (struct sockaddr *)&serverAddr, sizeof serverAddr);
            if (bytesSent < 0)
            {
                perror("Error forwarding datagram to host on port P+1");
                exit(1);
            }
        }
    }
    // close sockets
    close(sockOut);
    close(sockIn);

    return 0;
}