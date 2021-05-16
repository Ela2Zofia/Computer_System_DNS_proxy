#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#define HEADER_SIZE 12
#define LOG_FILE "dns_svr.log"

typedef struct dns_packet_t{
    unsigned int size;
    unsigned char header[HEADER_SIZE];
    unsigned char* body;
}dns_packet;

dns_packet* read_packet(int fd, int size);

int process_packet(dns_packet** packet);

int create_upstream_socket(char* addr, char* port);