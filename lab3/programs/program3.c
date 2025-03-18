// #include<stdio.h>
// #include<stdlib.h>
// #include<string.h>

// void* program3(unsigned N) {
//     void *arr = malloc(N * sizeof(*arr));
//     if((N < 1) || (arr = NULL)) {
//         printf("%s\n", "Memory allocation falied!");
//         return NULL;
//     }
//     printf("%s\n", "Memory allocation success!");
//     return arr;
// }

// int main() {
//     int* arr = (int*)program3(4); // Should typically succeed
//     free(arr);
// }


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void* program3(unsigned N) {
    void *arr = malloc(N * sizeof(int));  // Fix: Correct memory allocation
    if ((N < 1) || (arr == NULL)) {      // Fix: Correct NULL check
        printf("Memory allocation failed!\n");
        return NULL;
    }
    printf("Memory allocation success!\n");
    return arr;
}

int main() {
    int* arr = (int*)program3(4);  // Should typically succeed
    if (arr != NULL) {
        free(arr);  // Fix: Ensure memory is freed
    }
}
