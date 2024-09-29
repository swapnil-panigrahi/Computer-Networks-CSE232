  #include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

void *acceptClients();
void *receiveMessages(void *clientSock);
void acceptConnections();
void signalHandler(int sig);
void sendMessages();

int maxClients;
int *clientSockets;
int clientCount = 0;
int serverSocket;
fd_set currentSockets, readySockets;

struct dirent *entry;
struct ProcessInfo {
  char name[256];
  int pid;
  long utime;
  long stime;
} processes[1024];

int compareCPUUsage(const void *a, const void *b) {
  const struct ProcessInfo *procA = (struct ProcessInfo *)a;
  const struct ProcessInfo *procB = (struct ProcessInfo *)b;
  long cpuTimeA = procA->utime + procA->stime;
  long cpuTimeB = procB->utime + procB->stime;
  return (cpuTimeB > cpuTimeA) - (cpuTimeB < cpuTimeA);
}

void fetchCPUProcesses(char *outputBuffer) {
  DIR *dir;
  struct dirent *entry;
  struct ProcessInfo processes[1024];
  int processCount = 0;

  if ((dir = opendir("/proc")) != NULL) {
    while ((entry = readdir(dir)) != NULL) {
      if (isdigit(entry->d_name[0])) {
        int pid = atoi(entry->d_name);
        char statPath[1024];
        sprintf(statPath, "/proc/%d/stat", pid);

        FILE *statFile = fopen(statPath, "r");
        if (statFile) {
          long utime, stime;
          char comm[256];
          fscanf(statFile,
                 "%*d (%[^)]) %*c %*d %*d %*d %*d %*d %*u %*lu %*lu %*lu %*lu "
                 "%lu %lu",
                 comm, &utime, &stime);
          strcpy(processes[processCount].name, comm);
          processes[processCount].pid = pid;
          processes[processCount].utime = utime;
          processes[processCount].stime = stime;
          processCount++;
          fclose(statFile);
        }
      }
    }
    closedir(dir);
  }

  qsort(processes, processCount, sizeof(struct ProcessInfo), compareCPUUsage);

  snprintf(outputBuffer, BUFFER_SIZE,
           "Top 2 Processes:\n1. %s (PID: %d) CPU Time: %ld\n2. %s (PID: %d) "
           "CPU Time: %ld\n",
           processes[0].name, processes[0].pid,
           processes[0].utime + processes[0].stime, processes[1].name,
           processes[1].pid, processes[1].utime + processes[1].stime);
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    printf("Usage: %s <IP> <PORT> <MAX_CLIENTS>\n", argv[0]);
    return -1;
  }

  char *ip = argv[1];
  int port = atoi(argv[2]);
  maxClients = atoi(argv[3]);

  clientSockets = malloc(maxClients * sizeof(int));

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
  serverAddress.sin_port = htons(port);
  serverAddress.sin_addr.s_addr = inet_addr(ip);

  if (bind(serverSocket, (struct sockaddr *)&serverAddress,
           sizeof(serverAddress)) < 0) {
    perror("[-] Bind error\n");
    exit(EXIT_FAILURE);
  }
  printf("[+] Binding successful to port: %d\n", port);

  if (listen(serverSocket, maxClients) == 0) {
    printf("[+] Listening...\n");
  } else {
    perror("[-] Error while listening\n");
    exit(EXIT_FAILURE);
  }

  acceptClients();
  return 0;
}

void *acceptClients() {

  //initialise my current set
  FD_ZERO(&currentSockets);
  FD_SET(serverSocket, &currentSockets);

  while (1) {
    //because select is destructive
    readySockets = currentSockets;

    if(select(FD_SETSIZE, &readySockets, NULL, NULL, NULL) < 0) {
       perror("[-] Select error\n");
       exit(EXIT_FAILURE);
    }

    for (int i = 0; i < FD_SETSIZE; i++) {
      if(FD_ISSET(i, &readySockets)) {
        if(i == serverSocket) {
          acceptConnections();
        }
        else {
          receiveMessages(&i);
        }
      }
    }

  }
}

void acceptConnections() {
  struct sockaddr_in clientAddress;
  socklen_t addrSize;
  int newClientSock;
  addrSize = sizeof(clientAddress);

  newClientSock =
      accept(serverSocket, (struct sockaddr *)&clientAddress, &addrSize);

  if (newClientSock < 0) {
    perror("[-] Accept error\n");
    exit(EXIT_FAILURE);
  }

  clientSockets[clientCount++] = newClientSock;
  FD_SET(newClientSock, &currentSockets);

  printf("[+] Connection accepted from %s:%d\n",
         inet_ntoa(clientAddress.sin_addr), ntohs(clientAddress.sin_port));
}


void *receiveMessages(void *clientSock) {
  int sock = *(int *)clientSock;
  char buffer[BUFFER_SIZE];
  int ret;


    memset(buffer, 0, BUFFER_SIZE);
    ret = recv(sock, buffer, BUFFER_SIZE, 0);

    if (ret < 0) {
      perror("[-] Error receiving data from client\n");
    } else if (ret == 0) {
      printf("[+] Client disconnected\n");
      for (int i = 0; i < clientCount; i++) {
        if (clientSockets[i] == sock) {
          for (int j = i; j < clientCount - 1; j++) {
            clientSockets[j] = clientSockets[j + 1];
          }
          clientCount--;
          break;
        }
      }
      FD_CLR(sock, &currentSockets);
      close(sock);
      return NULL;
    }

    if (strncmp(buffer, "GET_CPU_USAGE", 13) == 0) {
      printf("[+] Client requested CPU usage info\n");
      char cpuData[BUFFER_SIZE];
      fetchCPUProcesses(cpuData);
      send(sock, cpuData, strlen(cpuData), 0);
    } else {
      printf("Client: %s\n", buffer);
    }
  return NULL;
}

void signalHandler(int sig) {
  printf("[+] Closing server...\n");

  const char *shutdownMessage = "SERVER_SHUTDOWN";
  for (int i = 0; i < clientCount; i++) {
    send(clientSockets[i], shutdownMessage, strlen(shutdownMessage), 0);
  }

  sleep(2);
  for (int i = 0; i < clientCount; i++) {
    close(clientSockets[i]);
  }

  free(clientSockets);
  close(serverSocket);
  exit(0);
}

