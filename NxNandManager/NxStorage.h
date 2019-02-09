#pragma once
#include <windows.h>
#include <string>
#include "utils.h"

using namespace std;

#define BUFSIZE 262144
#define MD5LEN  16
#define INVALID 1000
#define BOOT0   1001
#define BOOT1   1002
#define RAWNAND 1003
#define UNKNOWN 1004
#define NX_GPT_FIRST_LBA 1
#define NX_GPT_NUM_BLOCKS 33
#define NX_EMMC_BLOCKSIZE 512
#define GPT_PART_NAME_LEN 36
#define DEFAULT_BUFF_SIZE 0x40000

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long int u64;
typedef char s8;

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


typedef struct GptPartition GptPartition;
struct GptPartition {
	u32 lba_start;
	u32 lba_end;
	u64 attrs;
	s8 name[37];
	GptPartition *next;
};

typedef struct NxStorage NxStorage;
struct NxData {
	int type;
	u64 size;
	BOOL isDrive;
	GptPartition *firstPartion;
};

class NxStorage {
	public: 
		NxStorage(const char* storage);
		int GetIOHandle(HANDLE* hHandle, DWORD dwDesiredAccess, const char* partition = NULL, u64 *bytesToRead = NULL);
		BOOL dumpStorage(HANDLE* hHandleIn, HANDLE* hHandleOut, u64* readAmount, u64* writeAmount, u64 bytesToWrite, HCRYPTHASH* hHash = NULL);
		const char* GetNxStorageTypeAsString();		

	private:
		BOOL ParseGpt(unsigned char* gptHeader);
		void InitStorage();

	public:
		const char* path;
		LPWSTR pathLPWSTR;
		int type;
		u64 size;
		BOOL isDrive;
		DISK_GEOMETRY pdg;
		int partCount;
		GptPartition *firstPartion;
};