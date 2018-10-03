all : send_arp

send_arp: send_arp.o
	gcc -g -o send_arp send_arp.o -lpcap

send_arp.o:
	gcc -g -c -o send_arp.o send_arp.c

clean:
	rm -f send_arp
	rm -f *.o

