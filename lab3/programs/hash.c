// #include <stddef.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include "hash.h"

// // Returns the index where the key should be stored
// int HashIndex(char* key) {
//     int sum;
//     for (char* c = key; c; c++) {
//         sum += *c;
//     }
//     return sum;
// }

// // Allocates memory for the HashMap
// HashMap* HashInit() {
//     return malloc(sizeof(HashMap));
// }

// // Inserts PairValue into the map, if the value exists, increase ValueCount
// void HashAdd(HashMap *map, PairValue *value) {
//     int idx = HashIndex(value->KeyName);
//     if (map->data[idx]) 
//         value->Next = map->data[idx]->Next;

//     map->data[idx] = value;	
// }

// // Returns PairValue from the map if a given key is found
// PairValue* HashFind(HashMap *map, const char* key) {
//     unsigned idx = HashIndex(key);
    
//     for(PairValue* val = map->data[idx]; val != NULL; val = val->Next) {
//         if (strcmp(val->KeyName, key))
//             return val;
//     }
    
//     return NULL; 
// }

// // Deletes the entry with the given key from the map
// void HashDelete(HashMap *map, const char* key) {
//     unsigned idx = HashIndex(key);

//     for(PairValue* val = map->data[idx], *prev = NULL; val != NULL; prev = val, val = val->Next) {
//         if (strcmp(val->KeyName, key)) {
//             if (prev)
//                 prev->Next = val->Next;
//             else
//                 map->data[idx] = val->Next;
//         }
//     }
// }

// // Prints all content of the map
// void HashDump(HashMap *map) {
//     for(unsigned i = 0; i < MAP_MAX; i++) {
//         for(PairValue* val = map->data[i]; val != NULL; val = val->Next) {
//             printf(val->KeyName);
//         }
//     }
// }


// int main() {
//     HashMap* map = HashInit();
//     printf("%s\n", "HashInit() Successful");
    
//     PairValue pv1 = { .KeyName = "test_key", .ValueCount = 1, .Next = NULL };
//     PairValue pv2 = { .KeyName = "other_key", .ValueCount = 1, .Next = NULL };
    
//     printf("HashAdd(map, '%s')\n", pv1.KeyName);
//     HashAdd(map, &pv1);

//     printf("HashAdd(map, '%s')\n", pv1.KeyName);
//     HashAdd(map, &pv1);

//     printf("HashAdd(map, '%s')\n", pv2.KeyName);
//     HashAdd(map, &pv2);

//     printf("HashFind(map, %s) = ", pv1.KeyName);
//     PairValue* result = HashFind(map, pv1.KeyName);
//     if(result) {
//         printf("{'%s': %d}\n", result->KeyName, result->ValueCount);
//     }
//     else {
//         printf("%s\n", "Not found");
//     }
    
//     printf("%s", "HashDump(map) = ");
//     HashDump(map);

//     printf("HashDelete(map, '%s')\n", pv1.KeyName);
//     HashDelete(map, pv1.KeyName);

//     printf("HashFind(map, %s) = ", pv1.KeyName);
//     result = HashFind(map, pv1.KeyName); 
//     if(result) {
//         printf("{'%s': %d}\n", result->KeyName, result->ValueCount);
//     }
//     else {
//         printf("%s\n", "Not found");
//     }

//     printf("%s", "HashDump(map) = ");
//     HashDump(map);

//     free(map);
// }


// #include <stddef.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include "hash.h"

// // Returns a valid index for the key
// int HashIndex(const char* key) {
//     int sum = 0;
//     for (const char* c = key; *c != '\0'; c++) {
//         sum += *c;
//     }
//     return sum % MAP_MAX;  // Ensure within bounds
// }

// // Allocates memory for the HashMap and initializes it
// HashMap* HashInit() {
//     HashMap* map = malloc(sizeof(HashMap));
//     if (map == NULL) {
//         perror("Memory allocation failed");
//         exit(EXIT_FAILURE);
//     }
//     memset(map->data, 0, sizeof(map->data));  // Initialize to NULL
//     return map;
// }

// // Inserts a PairValue into the map
// void HashAdd(HashMap *map, const char *key, unsigned valueCount) {
//     int idx = HashIndex(key);

//     // Allocate memory for a new PairValue
//     PairValue *newPair = malloc(sizeof(PairValue));
//     if (newPair == NULL) {
//         perror("Memory allocation failed");
//         exit(EXIT_FAILURE);
//     }

//     strncpy(newPair->KeyName, key, KEY_STRING_MAX - 1);
//     newPair->KeyName[KEY_STRING_MAX - 1] = '\0';  // Ensure null termination
//     newPair->ValueCount = valueCount;
//     newPair->Next = map->data[idx];

//     map->data[idx] = newPair;
// }

// // Returns a PairValue if the key is found
// PairValue* HashFind(HashMap *map, const char* key) {
//     int idx = HashIndex(key);
    
//     for (PairValue* val = map->data[idx]; val != NULL; val = val->Next) {
//         if (strcmp(val->KeyName, key) == 0) {  // Fix: Proper comparison
//             return val;
//         }
//     }
    
//     return NULL; 
// }

// // Deletes an entry with a given key from the map
// void HashDelete(HashMap *map, const char* key) {
//     int idx = HashIndex(key);
//     PairValue *val = map->data[idx], *prev = NULL;

//     while (val != NULL) {
//         if (strcmp(val->KeyName, key) == 0) {
//             if (prev) {
//                 prev->Next = val->Next;
//             } else {
//                 map->data[idx] = val->Next;
//             }
//             free(val);  // Fix: Proper deallocation
//             return;
//         }
//         prev = val;
//         val = val->Next;
//     }
// }

// // Prints all content of the map
// void HashDump(HashMap *map) {
//     for (unsigned i = 0; i < MAP_MAX; i++) {
//         for (PairValue* val = map->data[i]; val != NULL; val = val->Next) {
//             printf("%s\n", val->KeyName);  // Fix: Safe format string
//         }
//     }
// }

// // Free all memory in HashMap
// void HashFree(HashMap *map) {
//     for (unsigned i = 0; i < MAP_MAX; i++) {
//         PairValue* val = map->data[i];
//         while (val) {
//             PairValue* next = val->Next;
//             free(val);
//             val = next;
//         }
//     }
//     free(map);
// }

// int main() {
//     HashMap* map = HashInit();
//     printf("HashInit() Successful\n");

//     HashAdd(map, "test_key", 1);
//     HashAdd(map, "other_key", 1);

//     printf("HashFind(map, test_key) = ");
//     PairValue* result = HashFind(map, "test_key");
//     if (result) {
//         printf("{'%s': %d}\n", result->KeyName, result->ValueCount);
//     } else {
//         printf("Not found\n");
//     }

//     printf("HashDump(map):\n");
//     HashDump(map);

//     printf("HashDelete(map, test_key)\n");
//     HashDelete(map, "test_key");

//     printf("HashFind(map, test_key) = ");
//     result = HashFind(map, "test_key");
//     if (result) {
//         printf("{'%s': %d}\n", result->KeyName, result->ValueCount);
//     } else {
//         printf("Not found\n");
//     }

//     printf("HashDump(map) after deletion:\n");
//     HashDump(map);

//     HashFree(map);  // Fix: Properly free all allocated memory
// }




#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"

// Returns a valid index for the key
int HashIndex(const char* key) {
    int sum = 0;
    for (const char* c = key; *c != '\0'; c++) {
        sum += *c;
    }
    return sum % MAP_MAX;  // Ensure within bounds
}

// Allocates memory for the HashMap and initializes it
HashMap* HashInit() {
    HashMap* map = malloc(sizeof(HashMap));
    if (map == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    memset(map->data, 0, sizeof(map->data));  // Initialize to NULL
    return map;
}

// Inserts a PairValue into the map
void HashAdd(HashMap *map, const char *key, unsigned valueCount) {
    int idx = HashIndex(key);

    // Allocate memory for a new PairValue
    PairValue *newPair = malloc(sizeof(PairValue));
    if (newPair == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    // Safe string copy to prevent buffer overflow
    strncpy(newPair->KeyName, key, KEY_STRING_MAX - 1);
    newPair->KeyName[KEY_STRING_MAX - 1] = '\0';  // Ensure null termination
    newPair->ValueCount = valueCount;
    newPair->Next = map->data[idx];

    map->data[idx] = newPair;
}

// Returns a PairValue if the key is found
PairValue* HashFind(HashMap *map, const char* key) {
    int idx = HashIndex(key);
    
    for (PairValue* val = map->data[idx]; val != NULL; val = val->Next) {
        if (strcmp(val->KeyName, key) == 0) {  // Fix: Proper comparison
            return val;
        }
    }
    
    return NULL; 
}

// Deletes an entry with a given key from the map
void HashDelete(HashMap *map, const char* key) {
    int idx = HashIndex(key);
    PairValue *val = map->data[idx], *prev = NULL;

    while (val != NULL) {
        if (strcmp(val->KeyName, key) == 0) {
            if (prev) {
                prev->Next = val->Next;
            } else {
                map->data[idx] = val->Next;
            }
            free(val);  // Fix: Proper deallocation
            return;
        }
        prev = val;
        val = val->Next;
    }
}

// Prints all content of the map
void HashDump(HashMap *map) {
    for (unsigned i = 0; i < MAP_MAX; i++) {
        for (PairValue* val = map->data[i]; val != NULL; val = val->Next) {
            printf("%s\n", val->KeyName);  // Fix: Safe format string
        }
    }
}

// Free all memory in HashMap
void HashFree(HashMap *map) {
    for (unsigned i = 0; i < MAP_MAX; i++) {
        PairValue* val = map->data[i];
        while (val) {
            PairValue* next = val->Next;
            free(val);
            val = next;
        }
    }
    free(map);
}

int main() {
    HashMap* map = HashInit();
    printf("HashInit() Successful\n");

    HashAdd(map, "test_key", 1);
    HashAdd(map, "other_key", 1);

    printf("HashFind(map, test_key) = ");
    PairValue* result = HashFind(map, "test_key");
    if (result) {
        printf("{'%s': %d}\n", result->KeyName, result->ValueCount);
    } else {
        printf("Not found\n");
    }

    printf("HashDump(map):\n");
    HashDump(map);

    printf("HashDelete(map, test_key)\n");
    HashDelete(map, "test_key");

    printf("HashFind(map, test_key) = ");
    result = HashFind(map, "test_key");
    if (result) {
        printf("{'%s': %d}\n", result->KeyName, result->ValueCount);
    } else {
        printf("Not found\n");
    }

    printf("HashDump(map) after deletion:\n");
    HashDump(map);

    HashFree(map);  // Fix: Properly free all allocated memory
}
