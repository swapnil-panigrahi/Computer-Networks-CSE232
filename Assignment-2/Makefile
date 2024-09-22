CC=gcc
CFLAGS=-Wall -Wextra -g

all: tcpServer tcpClient tcpCPU

tcpServer: tcpServer.c
	$(CC) $(CFLAGS) tcpServer.c -o tcpServer

tcpClient: tcpClient.c
	$(CC) $(CFLAGS) tcpClient.c -o tcpClient

tcpCPU: tcpCPU.c
	$(CC) $(CFLAGS) tcpCPU.c -o tcpCPU

clean: 
	rm -f tcpServer tcpClient tcpCPU

.PHONY: clean
