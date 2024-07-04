CC = gcc
CFLAGS=-Wall -O2
LIBS +=\
	-lpcap

all: count_pcs_tcp

count_pcs_tcp: count_pcs_tcp.c
	$(CC) $(CFLAGS) -o count_pcs_tcp count_pcs_tcp.c $(LIBS)

clean:
	rm -f count_pcs_tcp