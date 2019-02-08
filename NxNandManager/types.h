#pragma once

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;
typedef char s8;


typedef struct _NxStorage
{
	int type;
	u64 size;
	BOOL isDrive;

} NxStorage;

typedef struct _GptHeader
{
	u64 signature;
	u32 revision;
	u32 size;
	u32 crc32;
	u32 res1;
	u64 my_lba;
	u64 alt_lba;
	u64 first_use_lba;
	u64 last_use_lba;
	u8 disk_guid[0x10];
	u64 part_ent_lba;
	u32 num_part_ents;
	u32 part_ent_size;
	u32 part_ents_crc32;
	u8 res2[420];
} GptHeader;

typedef struct _GptEntry
{
	u8 type_guid[0x10];
	u8 part_guid[0x10];
	u64 lba_start;
	u64 lba_end;
	u64 attrs;
	u16 name[36];
} GptEntry;

typedef struct _GptPartition
{
	u32 lba_start;
	u32 lba_end;
	u64 attrs;
	s8 name[37];
} GptPartition;


template<typename T, size_t ARR_SIZE>
size_t array_countof(T(&)[ARR_SIZE]) { return ARR_SIZE; }
