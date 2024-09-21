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

#define PORT 8080
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 100

void *acceptClients(void *arg);
void *receiveMessages(void *clientSock);
void signalHandler(int sig);
void sendMessages();

int clientSockets[MAX_CLIENTS];
int clientCount = 0;
pthread_mutex_t clientMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t clientThreads[MAX_CLIENTS];
int serverSocket;

int main() {
  struct sockaddr_in serverAddress;
  signal(SIGINT, signalHandler);
  pthread_t acceptThread;

  serverSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (serverSocket < 0) {
    perror("[-] Socket creation error\n");
    exit(EXIT_FAILURE);
  }
  printf("[+] Server Socket created\n");

  memset(&serverAddress, '\0', sizeof(serverAddress));
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port = htons(PORT);
  serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1");

  if (bind(serverSocket, (struct sockaddr *)&serverAddress,
           sizeof(serverAddress)) < 0) {
    perror("[-] Bind error\n");
    exit(EXIT_FAILURE);
  }
  printf("[+] Binding successful to port: %d\n", PORT);

  if (listen(serverSocket, 10) == 0) {
    printf("[+] Listening...\n");
  } else {
    perror("[-] Error while listening\n");
    exit(EXIT_FAILURE);
  }

  if (pthread_create(&acceptThread, NULL, acceptClients, NULL) != 0) {
    perror("[-] Failed to create accept thread\n");
    exit(EXIT_FAILURE);
  }

  sendMessages();
  pthread_join(acceptThread, NULL);

  close(serverSocket);
  return 0;
}

void *acceptClients(void *arg) {
  struct sockaddr_in clientAddress;
  socklen_t addrSize;

  while (1) {
    int newClientSock;
    addrSize = sizeof(clientAddress);
    newClientSock =
        accept(serverSocket, (struct sockaddr *)&clientAddress, &addrSize);

    if (newClientSock < 0) {
      perror("[-] Accept error\n");
      exit(EXIT_FAILURE);
    }

    pthread_mutex_lock(&clientMutex);
    clientSockets[clientCount++] = newClientSock;
    pthread_mutex_unlock(&clientMutex);

    printf("[+] Connection accepted from %s:%d\n",
           inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));

    if (pthread_create(&clientThreads[clientCount - 1], NULL, receiveMessages,
                       &newClientSock) != 0) {
      perror("[-] Failed to create thread for client\n");
      exit(EXIT_FAILURE);
    }
  }
}

void *receiveMessages(void *clientSock) {
  int sock = *(int *)clientSock;
  char buffer[BUFFER_SIZE];
  int ret;

  while (1) {
    memset(buffer, 0, BUFFER_SIZE);
    ret = recv(sock, buffer, BUFFER_SIZE, 0);

    if (ret < 0) {
      perror("[-] Error receiving data from client\n");
      break;
    } else if (ret == 0) {
      printf("[+] Client disconnected\n");
      break;
    }

    printf("Client: %s\n", buffer);
  }

  pthread_mutex_lock(&clientMutex);
  for (int i = 0; i < clientCount; i++) {
    if (clientSockets[i] == sock) {
      // Shift remaining clients down
      for (int j = i; j < clientCount - 1; j++) {
        clientSockets[j] = clientSockets[j + 1];
        clientThreads[j] = clientThreads[j + 1];
      }
      clientCount--;
      break;
    }
  }
  pthread_mutex_unlock(&clientMutex);

  close(sock);
  return NULL;
}

void signalHandler(int sig) {
  printf("[+] Closing server...\n");

  pthread_mutex_lock(&clientMutex);
  const char *shutdownMessage = "SERVER_SHUTDOWN";
  for (int i = 0; i < clientCount; i++) {
    send(clientSockets[i], shutdownMessage, strlen(shutdownMessage), 0);
  }
  pthread_mutex_unlock(&clientMutex);

  sleep(2);

  pthread_mutex_lock(&clientMutex);
  for (int i = 0; i < clientCount; i++) {
    close(clientSockets[i]);
  }
  pthread_mutex_unlock(&clientMutex);

  close(serverSocket);
  exit(0);
}

void sendMessages() {
  char buffer[BUFFER_SIZE];

  while (1) {
    memset(buffer, 0, BUFFER_SIZE);
    printf("Server: ");
    fgets(buffer, BUFFER_SIZE, stdin);

    pthread_mutex_lock(&clientMutex);
    for (int i = 0; i < clientCount; i++) {
      send(clientSockets[i], buffer, strlen(buffer), 0);
    }
    pthread_mutex_unlock(&clientMutex);
  }
}
