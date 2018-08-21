all : pcap_test

pcap_test: pcap.o
	g++ -g -o pcap_test pcap.o -lpcap

main.o:
	g++ -g -c -o pcap.o pcap.cpp

clean:
	rm -f pcap_test
	rm -f *.o

