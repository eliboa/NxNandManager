#pragma once



typedef unsigned long long int u64;

typedef struct _NxStorage
{
    int type;
    u64 size;
} NxStorage;

template<typename T, size_t ARR_SIZE>
size_t array_countof(T(&)[ARR_SIZE]) { return ARR_SIZE; }
