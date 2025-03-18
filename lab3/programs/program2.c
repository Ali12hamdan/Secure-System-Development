#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void work(int* arr, unsigned N) {
    for (int i = 1; i < N; i++) {
        arr[i] = arr[i - 1] * 2;
    }
}

void program2(unsigned N) {
    int* arr = (int*)malloc(N * sizeof(*arr));
    if (arr == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    memset(arr, 0, N * sizeof(*arr));  // Fix: Initialize the whole array
    arr[0] = 1;
    
    work(arr, N);  // No free inside work()
    
    for (int i = 0; i < N; i++) {
        printf("arr[%d] = %d\n", i, arr[i]);
    }

    free(arr);  // Free after usage
}

int main() {
    program2(4);  // Should print the array [1, 2, 4, 8]
}
