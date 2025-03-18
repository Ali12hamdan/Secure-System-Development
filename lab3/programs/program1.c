// #include<stdio.h>
// #include<stdlib.h>

// void program1(int N) {
//     int *arr = malloc(N);
//     for(int i = 0; i < N; i++) {
//         arr[i] = i * i;
//         printf("arr[%d] = %d\n", i, arr[i]);
//     }
// }

// int main() {
//     program1(4); // Should print the array [0, 1, 4, 9]
// }

#include <stdio.h>
#include <stdlib.h>

void program1(int N) {
    int *arr = malloc(N * sizeof(int));  // Correct allocation
    if (arr == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < N; i++) {
        arr[i] = i * i;
        printf("arr[%d] = %d\n", i, arr[i]);
    }

    free(arr);  // Free allocated memory
}

int main() {
    program1(4);  // Should print the array [0, 1, 4, 9]
}
