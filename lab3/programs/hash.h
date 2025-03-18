// #ifndef __HASH__
// #define __HASH__

//     // Forward declaration (to avoid compiler warnings about incomplete type)
//     struct PairValue;

//     // PairValue Type defintion
//     typedef struct PairValue {
//         #define KEY_STRING_MAX 255
// 		char KeyName[KEY_STRING_MAX];
//         unsigned ValueCount;
//         struct PairValue* Next;
//     } PairValue;

// 	typedef struct {
//         #define MAP_MAX 128
// 		PairValue* data[MAP_MAX];
// 	} HashMap;

//     HashMap* HashInit();
//     void HashAdd(HashMap *map, PairValue *value);
//     void HashDelete(HashMap *map, const char* key);
//     PairValue* HashFind(HashMap *map, const char* key);
//     void HashDump(HashMap *map);

// #endif


#ifndef __HASH__
#define __HASH__

#define KEY_STRING_MAX 255
#define MAP_MAX 128

// PairValue Type definition
typedef struct PairValue {
    char KeyName[KEY_STRING_MAX];
    unsigned ValueCount;
    struct PairValue* Next;
} PairValue;

typedef struct {
    PairValue* data[MAP_MAX];
} HashMap;

HashMap* HashInit();
void HashAdd(HashMap *map, const char *key, unsigned valueCount);
void HashDelete(HashMap *map, const char* key);
PairValue* HashFind(HashMap *map, const char* key);
void HashDump(HashMap *map);
void HashFree(HashMap *map);

#endif
