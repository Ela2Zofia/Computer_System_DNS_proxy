#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    char* message_type = argv[1];
    unsigned char len_buffer[2];
    read(0, len_buffer, 2);
    int size = len_buffer[0]+len_buffer[1];
    printf("%d\n", size);
}
