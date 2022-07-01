#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
   
int main(int argc, char *argv[])
{
    int size;
    unsigned long *buf1, *buf2, *buf3;
 
    fprintf(stderr,"The house of Force"); 
 
    buf1 = malloc(256);
    buf1[33] = 0xffffffffffffffff;
 
    buf2 = malloc(0xffffffffffffeee0);
 
    buf3 = malloc(256);
 
    buf3[0] = 0x4141414141414141;
 
    free(buf3);
   
    return 0;
}