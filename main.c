// REFERENCE: part of network code is inspired by week9 workshop materials
#include "helper1.h"

#define PORT "8053"

int main(int argc, char* argv[]) {
    unsigned char len_buffer[2];
    
    int sockfd, clientfd, upstreamfd, re, n;
    struct addrinfo hints, *res;
    struct sockaddr_storage client_addr;
    socklen_t client_size;



    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    getaddrinfo(NULL, PORT, &hints, &res);

    // create socket
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0){
        perror("socket");
        exit(1);
    }

    // set socket options (useable port)
    re = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &re, sizeof(int))< 0){
        perror("setsockopt");
        exit(1);
    }

    // bind address to socket
    if (bind(sockfd, res->ai_addr, res->ai_addrlen) < 0){
        perror("bind");
        exit(1);
    }

    // listen for incoming connections
    if (listen(sockfd, 5) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

    client_size = sizeof(client_addr);
    while(1){
        clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_size);
        if (clientfd < 0){
            perror("accept");
            exit(1);
        }

        // read the first two byte of tcp packet,
        // which represents the length of the packet
        memset(len_buffer, 0, 2);
        read(clientfd, len_buffer, 2);
        unsigned int packet_size = len_buffer[0] << 8 | len_buffer[1];

        dns_packet* request_packet = read_packet(clientfd, packet_size);
        
        // for(int i = 0; i<12;i++){
        //     printf("%02x", request_packet->header[i]);
        // }
        // for(int i = 0; i<packet_size-12;i++){
        //     printf("%02x", request_packet->body[i]);
        // }
        // printf("\n");

        int valid = process_packet(&request_packet);

        if (!valid){
            unsigned char response[packet_size+2];
            memcpy(response, len_buffer,2);
            memcpy(&response[2], request_packet->header, HEADER_SIZE);
            memcpy(&response[2+HEADER_SIZE], request_packet->body, packet_size-HEADER_SIZE);

            n = write(clientfd, response, packet_size+2);
            
            if (n < 0) {
		        perror("socket");
		        exit(EXIT_FAILURE);
	        }
            
            close(clientfd);
            
            free(request_packet->body);
            free(request_packet);
        }else{
            upstreamfd = create_upstream_socket(argv[1], argv[2]);
            
            unsigned char request[packet_size+2];
            memcpy(request, len_buffer,2);
            memcpy(&request[2], request_packet->header, HEADER_SIZE);
            memcpy(&request[2+HEADER_SIZE], request_packet->body, packet_size-HEADER_SIZE);

            n = write(upstreamfd, request, packet_size+2);
            if (n < 0) {
		        perror("socket");
		        exit(EXIT_FAILURE);
	        }

            memset(len_buffer, 0, 2);
            read(upstreamfd, len_buffer, 2);
            unsigned int packet_size = len_buffer[0] << 8 | len_buffer[1];

            request_packet = read_packet(upstreamfd, packet_size);
            
            for(int i = 0; i<12;i++){
                printf("%02x", request_packet->header[i]);
            }
            for(int i = 0; i<request_packet->size-12;i++){
                printf("%02x", request_packet->body[i]);
            }
            printf("\n");

            process_packet(&request_packet);
            
            unsigned char response[request_packet->size+2];
            response[0] = request_packet->size & 65280;
            response[1] = request_packet->size & 255;
            memcpy(&response[2], request_packet->header, HEADER_SIZE);
            memcpy(&response[2+HEADER_SIZE], request_packet->body, request_packet->size-HEADER_SIZE);

            n=write(clientfd, response, request_packet->size+2);

            for(int i = 0; i < request_packet->size+2;i++){
                printf("%02x", response[i]);
            }
            printf("\n");


            if (n < 0) {
		        perror("socket");
		        exit(EXIT_FAILURE);
	        }

            close(clientfd);
            close(upstreamfd);
            free(request_packet->body);
            free(request_packet);

        }


        
    }
}

