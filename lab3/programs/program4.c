// #include<stdio.h>
// #include<stdlib.h>
// #include<string.h>

// char* getString() {
//     char message[100] = "Hello World!";
//     char* ret = message;
//     return ret;
// }

// void program4() {
//     printf("String: %s\n", getString());
// }

// int main() {
//     program4();
// }


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* getString() {
    char* ret = malloc(100 * sizeof(char));  // Allocate memory on the heap
    if (ret == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    strcpy(ret, "Hello World!");  // Copy the string into allocated memory
    return ret;
}

void program4() {
    char* str = getString();
    printf("String: %s\n", str);
    free(str);  // Free allocated memory
}

int main() {
    program4();
}
