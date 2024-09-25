CC=gcc
CFLAGS=-Wall -Wextra -g				

all: tcpServerMulti tcpServerSingle tcpServerSelect tcpClient tcpCPU

tcpServerMulti: tcpServerMulti.c
	$(CC) $(CFLAGS) tcpServerMulti.c -o tcpServerMulti

tcpServerSingle: tcpServerSingle.c
	$(CC) $(CFLAGS) tcpServerSingle.c -o tcpServerSingle

tcpServerSelect: tcpServerSelect.c
	$(CC) $(CFLAGS) tcpServerSelect.c -o tcpServerSelect

tcpClient: tcpClient.c
	$(CC) $(CFLAGS) tcpClient.c -o tcpClient

tcpCPU: tcpCPU.c
	$(CC) $(CFLAGS) tcpCPU.c -o tcpCPU

clean: 
	rm -f tcpServerMulti tcpClient tcpCPU

.PHONY: clean
