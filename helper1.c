#include "helper1.h"

#define INVALID 0
#define VALID 1


dns_packet* read_packet(int fd, int size){
    unsigned char buffer[size];
    dns_packet* packet = malloc(sizeof(dns_packet));
    packet->body = malloc((size-HEADER_SIZE)*sizeof(unsigned char));
    packet->size = size;
    int n, already_read;
    n = 0;
    already_read = 0;

    // read untill all is recieved
    while(already_read < size){
        n = read(fd, &buffer[already_read], size-already_read);
        if (n < 1){
            break;
        }
        already_read += n;
    }
    
    // read the header of DNS packet
    memcpy(packet->header, buffer, HEADER_SIZE);

    // read the rest of the packet/body
    memcpy(packet->body, &buffer[HEADER_SIZE], size-HEADER_SIZE);
    
    return packet;
}


int process_packet(dns_packet** packet) {
    unsigned char* header = (*packet)->header;
    unsigned char* body = (*packet)->body;
    
    unsigned int qr, rcode, n_answer, nscount, arcount;
    // current timestamp
    struct tm * timeinfo;
    char time_stamp[25];
    time_t rawtime;
    time( &rawtime );
    timeinfo = localtime( &rawtime );
    strftime(time_stamp, 25, "%FT%T%z",timeinfo);


    qr = header[2] >> 7;
    rcode = header[3] & 15;
    n_answer = header[6] << 8 | header[7];
    // nscount = header[8] << 8 | header[9];
    // arcount = header[10] << 8 | header[11];
    if(rcode != 0) {
        // change rcode to 4
        header[3] = header[3] | 4;
        return INVALID;
    }


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
    
    FILE* log_f = fopen(LOG_FILE,"a");
    // write log file
    if(!qr){
        // if the message is a request
        // index position increase to QTYPE
        index++;
        int qtype = body[index] << 8 | body[index+1];
        fprintf(log_f, "%s requested %s\n", time_stamp, url);
        fflush(log_f);

        // if a request is recieved with non-AAAA question
        if(qtype!=28){
            fprintf(log_f, "%s unimplemented request\n",time_stamp);
            fflush(log_f);
            
            // change qr type to 1
            header[2] = header[2] | 128;
            // change rcode to 4
            header[3] = header[3] & 0;
            header[3] = header[3] | 4;

            // recursive available
            header[3] = header[3] | 128;
            fclose(log_f);
            return INVALID;
        }else{
            return VALID;
        }
        


        // jump to the begining of QCLASS
        index+=2;
        // unsigned int qclass = ((body[index] << 8) | body[index+1]);
        
        // increment to the end of the question section
        index++;
    }else{
        // if the message is a response
        
        // index position increase to answer section
        index+=5;
        int answer_start_index = index;
        int answer_end_index = answer_start_index;
        // unsigned int name_pointer = (body[index] << 8 | body[index+1]);
        
        // index position to TYPE field
        index+=2;
        unsigned int type = body[index] << 8 | body[index+1];

        // if response is recieved with non-AAAA record
        if (type != 28){
            index = answer_start_index;
            // change rcode to 4
            header[3] = header[3] | 4;
            
            // set anwser number to 0
            header[6] = header[6] & 0;
            header[7] = header[7] & 0;
            // set nscount and arcount to 0
            header[8] = header[8] & 0;
            header[9] = header[9] & 0;
            header[10] = header[10] & 0;
            header[11] = header[11] & 0;

            for(int i = 0; i < n_answer; i++){
                index += 2; // NAME
                index += 2; // TYPE
                index += 2; // CLASS
                index += 4; // TTL
                unsigned int ip_len = body[index] << 8 | body[index+1];
                index += 2; // RDLENGTH
                index += ip_len; // RDATA
            }

            answer_end_index = index;
            int answser_len = answer_end_index - answer_start_index;
            (*packet)->size = answer_start_index + HEADER_SIZE;
            unsigned char* new_body = malloc(((*packet)->size-HEADER_SIZE) * sizeof(unsigned char));
            
            // if (nscount+arcount != 0){
            //     memcpy(new_body, body, answer_start_index);
            //     memcpy(&new_body[answer_start_index], &body[answer_end_index], (*packet)->size-HEADER_SIZE-answer_end_index);
            // }else{
                
            // }
            
            memcpy(new_body, body, (*packet)->size-HEADER_SIZE);
            free(body);
            (*packet)->body = new_body;

            fclose(log_f);
            return INVALID;
        }else{
            // index position to CLASS field
            index+=2;
            // unsigned int class = ((body[index] << 8) | body[index+1]);
            
            // index position to RDLENGTH field
            index+=2;
            // unsigned int ttl = body[index] << 24 
            //     | body[index+1] << 16 
            //     | body[index+2] << 8 
            //     | body[index+3];

            // index position to RDATA field
            index+=4;
            unsigned int ip_len = body[index] << 8 | body[index+1];
            
            index+=2;
            unsigned char ip[ip_len];
            char ip_text[INET6_ADDRSTRLEN];
            memcpy(ip, &body[index], ip_len);
            inet_ntop(AF_INET6, ip, ip_text, INET6_ADDRSTRLEN);
            
            printf("%s\n", ip_text);
            
            fprintf(log_f, "%s %s is at %s\n", time_stamp, url, ip_text);
            fflush(log_f);
        }
        

    }

    printf("%s\n", url);
    fclose(log_f);
    return VALID;
}


int create_upstream_socket(char* addr, char* port){
    printf("Start to contact upstream\n");
    
    int sockfd;
    struct addrinfo hints, *servinfo, *rp;

    memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
    
    if ((getaddrinfo(addr, port, &hints, &servinfo)) < 0) {
		perror("getaddrinfo");
		exit(1);
	}

    for (rp = servinfo; rp != NULL; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		// printf("upstream: %d\n",sockfd);
        if (sockfd == -1){
			continue;
        }
		if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1){
            printf("upstream: connection successful\n");
			break; // success
        }
		close(sockfd);
	}

    if (rp == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(1);
	}

    return sockfd;
}
