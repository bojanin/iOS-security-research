//
//  main.c
//  double free
//
//  Created by Tommy Bojanin on 1/3/19.
//  Copyright © 2019 Tommy Bojanin. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// example of UaF vuln. If you dont nullify ptr, memory locations can be printed out for ASLR bypass
void useAfterFree(void) {
    puts("[*] Allocating use after free ptr.");
    void *ptr = malloc(64);
    puts("[*] Freeing ptr.");
    free(ptr);

    printf("[*] Memory location of ptr: %p \n\n", ptr);
}

void doubleFree(char *str) {
    // allocate a ptr and then free its memory 3 times

    puts("[*] Allocating ptr.");
    void *ptr = malloc(64);
    puts("[*] Freeing ptr.");
    free(ptr);


    puts("[*] Allocating ptr2.");
    void *ptr2 = malloc(64);
    puts("[*] Freeing ptr.");
    free(ptr);


    puts("[*] Allocating ptr3");
    void *ptr3 = malloc(64);
    puts("[*] Freeing ptr.");
    free(ptr);

    puts("[*] Copying string into ptr3 heap location.");
    strcpy((char*)ptr3, str);

    printf("[*] Value of ptr2: %s\n\n", (char*)ptr2);
}


int main(int argc, const char * argv[]) {
    puts("Double Free example");
    puts("--------------------------");
    doubleFree("This is an examaple of double free.");
    puts("Double Free example:");
    puts("--------------------------");
    useAfterFree();

    return 0;
}
