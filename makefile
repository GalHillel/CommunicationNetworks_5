all: sniffer spoofer SniffAndSpoof

sniffer: sniffer.c
	gcc sniffer.c -o sniffer -lpcap

spoofer: spoofer.c
	gcc spoofer.c -o spoofer -lpcap

SniffAndSpoof: SniffAndSpoof.c
	gcc SniffAndSpoof.c -o SniffAndSpoof -lpcap

clean:
	rm -f *.o sniffer spoofer SniffAndSpoof
