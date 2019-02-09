#pragma once

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;
typedef char s8;


template<typename T, size_t ARR_SIZE>
size_t array_countof(T(&)[ARR_SIZE]) { return ARR_SIZE; }
