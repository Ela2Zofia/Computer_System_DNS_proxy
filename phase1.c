#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#define HEADER_SIZE 12
#define LOG_FILE "dns_svr.log"

typedef struct header_t{
    unsigned char qr;
    unsigned char opcode;
    unsigned char aa;
    unsigned char tc;
    unsigned char rd;
    unsigned char ra;
    unsigned char rcode;
}header;


int main(int argc, char* argv[]) {
    // char* message_type = argv[1];
    int qr;
    unsigned char len_buffer[2];
    FILE* log_f = fopen(LOG_FILE,"a");

    // current timestamp
    struct tm * timeinfo;
    char time_stamp[25];
    time_t rawtime;
    time( &rawtime );
    timeinfo = localtime( &rawtime );
    strftime(time_stamp, 25, "%FT%T%z",timeinfo);
    
    // printf("%s\n", time_stamp);

    // read the first two byte of tcp packet, which represents the length of the packet
    read(0, len_buffer, 2);
    unsigned int size = len_buffer[0] << 8 | len_buffer[1];

    // read the head of DNS packet
    unsigned char header[HEADER_SIZE];
    read(0, header, 12);
    qr = header[2] >> 7;

    // read the rest of the packet/body
    unsigned char body[size-HEADER_SIZE];
    read(0, body, size-HEADER_SIZE);

    // for(int i = 0; i < HEADER_SIZE;i++){
    //     printf("%02x", header[i]);
        
    // }
    // printf("\n");
    // for(int i = 0; i < size - HEADER_SIZE;i++){
    //     printf("%02x", body[i]);
    // }
    // printf("\n");
    

    // get the length of the requested URL
    int index = 0;
    int dots = 0;
    int question_len = 0;
    while(body[index]){
        question_len += (int)body[index];
        index+=(int)body[index] + 1;
        dots++;
    }

    // get the URL
    index = 0;
    char url[question_len+dots];
    int tmp = 0;
    while(body[index]){
        int section_len = body[index];
        for(int i = 0; i < section_len; i++){
            url[tmp] = body[index+i+1];
            tmp++;
        }
        index += section_len + 1;
        if(body[index]){
            url[tmp] = '.';
            tmp++;
        }
    }
    url[tmp] = '\0';
    
    // write log file
    if(!qr){
        // index position increase to QTYPE
        index++;
        int qtype = body[index] << 8 | body[index+1];
        fprintf(log_f, "%s requested %s\n", time_stamp, url);
        fflush(log_f);
        if(qtype!=28){
            fprintf(log_f, "%s unimplemented request\n",time_stamp);
            fflush(log_f);   
        }
        // jump to the end of QCLASS
        index+=2;
        // unsigned int qtype = ((body[index] << 8) | body[index+1]);
        index++;
    }else{
        
        // index position increase to answer section
        index+=5;
        // unsigned int name_pointer = (body[index] << 8 | body[index+1]) - 49152;
        
        // index position to TYPE field
        index+=2;
        unsigned int type = body[index] << 8 | body[index+1];
        
        // index position to CLASS field
        index+=2;
        // unsigned int class = ((body[index] << 8) | body[index+1]);
        
        // index position to RDLENGTH field
        index+=2;
        // unsigned int ttl = body[index] << 24 
        //     | body[index+1] << 16 
        //     | body[index+2] << 8 
        //     | body[index+3];

        // inde position to RDATA field
        index+=4;
        unsigned int ip_len = body[index] << 8 | body[index+1];
        index+=2;
        unsigned char ip[ip_len];
        char ip_text[INET6_ADDRSTRLEN];
        memcpy(ip, &body[index], ip_len);
        inet_ntop(AF_INET6, ip, ip_text, INET6_ADDRSTRLEN);
        // printf("%s\n", ip_text);

        if(type == 28){
            fprintf(log_f, "%s %s is at %s\n", time_stamp, url, ip_text);
            fflush(log_f);
        }

    }

    // printf("%s\n", url);
    
    fclose(log_f);
}