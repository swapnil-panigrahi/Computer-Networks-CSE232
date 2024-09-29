#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

int clientSocket;
pthread_t receivingThread;
int shouldTerminate = 0;
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void signalHandler(int sig) {
  printf("[+] Closing Connection...\n");

  pthread_cancel(receivingThread);
  pthread_join(receivingThread, NULL);
  close(clientSocket);

  exit(0);
}

void *fetchMessages(void *args) {
  char buffer[BUFFER_SIZE];
  int ret;

  while (1) {
    memset(buffer, 0, BUFFER_SIZE);
    ret = recv(clientSocket, buffer, BUFFER_SIZE, 0);

    if (ret <= 0) {
      printf("[+] Server closed the connection\n");
      pthread_mutex_lock(&lock);
      shouldTerminate = 1;
      pthread_mutex_unlock(&lock);
      break;
    }

    if (strncmp(buffer, "SERVER_SHUTDOWN", strlen("SERVER_SHUTDOWN")) == 0) {
      printf("[+] Server is shutting down. Closing client.\n");
      pthread_mutex_lock(&lock);
      shouldTerminate = 1;
      pthread_mutex_unlock(&lock);
      break;
    }

    printf("\nServer: %s\n", buffer);
  }

  close(clientSocket);
  exit(0);
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Usage: %s <IP> <PORT>\n", argv[0]);
    return -1;
  }

  char *serverIP = argv[1];
  int port = atoi(argv[2]);

  int ret;
  struct sockaddr_in serverAddress;
  char buffer[BUFFER_SIZE];

  signal(SIGINT, signalHandler);

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

  ret = connect(clientSocket, (struct sockaddr *)&serverAddress,
                sizeof(serverAddress));
  if (ret < 0) {
    perror("[-] Connection error\n");
    exit(EXIT_FAILURE);
  }
  printf("[+] Connected established\n");

  if (pthread_create(&receivingThread, NULL, fetchMessages, NULL) != 0) {
    perror("[-] Failed to create server thread\n");
    exit(EXIT_FAILURE);
  }

  while (1) {
    pthread_mutex_lock(&lock);
    if (shouldTerminate) {
      pthread_mutex_unlock(&lock);
      break;
    }
    pthread_mutex_unlock(&lock);

    printf("Client: ");
    fgets(buffer, BUFFER_SIZE, stdin);

    pthread_mutex_lock(&lock);
    if (shouldTerminate) {
      pthread_mutex_unlock(&lock);
      break;
    }
    pthread_mutex_unlock(&lock);

    send(clientSocket, buffer, strlen(buffer), 0);
  }

  pthread_cancel(receivingThread);
  pthread_join(receivingThread, NULL);
  close(clientSocket);

  return 0;
}
