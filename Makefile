all:
	gcc sniffer.c -o sniffer -lpcap

clean:
	rm -f sniffer
