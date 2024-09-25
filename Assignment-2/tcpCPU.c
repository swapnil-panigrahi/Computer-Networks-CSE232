#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Usage: %s <IP> <PORT>\n", argv[0]);
    return -1;
  }

  char *serverIP = argv[1];
  int port = atoi(argv[2]);

  int clientSocket;
  struct sockaddr_in serverAddress;
  char buffer[BUFFER_SIZE];

  clientSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (clientSocket < 0) {
    perror("[-] Socket creation error\n");
    exit(EXIT_FAILURE);
  }
  printf("[+] Client Socket created\n");

  memset(&serverAddress, '\0', sizeof(serverAddress));
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(port);
  serverAddress.sin_addr.s_addr = inet_addr(serverIP);

  if (connect(clientSocket, (struct sockaddr *)&serverAddress,
              sizeof(serverAddress)) < 0) {
    perror("[-] Connection error\n");
    exit(EXIT_FAILURE);
  }
  printf("[+] Connection established\n");

  int flag=1;
  while (flag) {
    char input[BUFFER_SIZE];
    strcpy(buffer, "GET_CPU_USAGE");
    send(clientSocket, buffer, strlen(buffer), 0);

    memset(buffer, 0, BUFFER_SIZE);
    recv(clientSocket, buffer, BUFFER_SIZE, 0);
    printf("CPU Info: %s\n", buffer);
    if (strncmp(buffer, "SERVER_SHUTDOWN", strlen("SERVER_SHUTDOWN")) == 0) {
      break;
    }
    printf("\nClose connection?(Selecting no will fetch CPU usage again)(y/n):");
    scanf("%s", input);
    if (strcmp(input, "y") == 0) {
      flag=0;
    }
  }
  close(clientSocket);
  printf("[+] Connection closed, exiting...\n");

  return 0;
}
