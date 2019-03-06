#pragma once
#include <windows.h>
#include <Wincrypt.h>
#include <iostream>
#include "Shlwapi.h"
#include <string>
#include "utils.h"

using namespace std;

#define BUFSIZE   0x40000
#define MD5LEN    16
#define INVALID   1000
#define BOOT0     1001
#define BOOT1     1002
#define RAWNAND	  1003
#define PARTITION 1005
#define UNKNOWN   1004
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

typedef struct MagicOffsets MagicOffsets;
struct MagicOffsets {
	u64 offset;
	const char* magic;
	u64 size;
	int type;
	float fw;
};

typedef struct NxPartition NxPartition;
struct NxPartition {
	s8 name[37];
	u64 size;
};

typedef struct NxSplitFile NxSplitFile;
struct NxSplitFile {
	u64 offset;
	u64 size;
	wchar_t file_path[_MAX_PATH];
	NxSplitFile *next = NULL;
};

typedef struct NxHandle NxHandle;
struct NxHandle {
	HANDLE h;
	wchar_t path[_MAX_PATH];
	u64 off_start = 0;
	u64 off_end = 0;
	u64 off_max = 0;
	u64 readAmount = 0;
};

static MagicOffsets mgkOffArr[] =
{	
	// { offset, magic, size, type, firwmare }
	// BOOT0 => Look for boot_data_version + block_size_log2 + page_size_log2
	{ 0x0530, "010021000E00000009000000", 12, BOOT0, 0},
	// BOOT1 => Look for PK11 magic	
	{ 0x13B4, "504B3131", 4, BOOT1, 1},
	{ 0x13F0, "504B3131", 4, BOOT1, 2},
	{ 0x1424, "504B3131", 4, BOOT1, 3},	
	{ 0x12E8, "504B3131", 4, BOOT1, 4},
	{ 0x12D0, "504B3131", 4, BOOT1, 5},	
	{ 0x12F0, "504B3131", 4, BOOT1, 6},
	{ 0x40AF8,"504B3131", 4, BOOT1, 7},
	// RAWNAND -> Look for GPT partition 
	{ 0x200, "4546492050415254", 8, RAWNAND, 0 }	
};

static NxPartition partInfoArr[] =
{
	{ "PRODINFO",               0x003FBC00  },
	{ "PRODINFOF",              0x00400000  },
	{ "BCPKG2-1-Normal-Main",   0x00800000  },
	{ "BCPKG2-2-Normal-Sub",    0x00800000  },
	{ "BCPKG2-3-SafeMode-Main", 0x00800000  },
	{ "BCPKG2-4-SafeMode-Sub",  0x00800000  },
	{ "BCPKG2-5-Repair-Main",   0x00800000  },
	{ "BCPKG2-6-Repair-Sub",    0x00800000  },
	{ "SAFE",                   0x04000000  },
	{ "SYSTEM",                 0xA0000000  },
	{ "USER",                   0x680000000 }
};

class NxStorage {
	public: 
		NxStorage(const char* storage=NULL);

		void ClearHandles();
		BOOL GetSplitFile(NxSplitFile* pFile, const char* partition);
		BOOL GetSplitFile(NxSplitFile* pFile, u64 offset);
        int DumpToStorage(NxStorage *out, const char* partition, u64* readAmount, u64* writeAmount, u64* bytesToWrite, HCRYPTHASH* hHash = NULL);
        int RestoreFromStorage(NxStorage *in, const char* partition, u64* readAmount, u64* writeAmount, u64* bytesToWrite);
        const char* GetNxStorageTypeAsString();
		void InitStorage();		
		int GetMD5Hash(HCRYPTHASH *hHash, u64* readAmount = NULL);
		std::string GetMD5Hash(const char* partition = NULL);	
		u64 IsValidPartition(const char * part_name, u64 part_size = NULL);
        bool setAutoRCM(bool enable);
        bool DEBUG_MODE;

	private:
		BOOL ParseGpt(unsigned char* gptHeader);

	public:
		const char* path;
		LPWSTR pathLPWSTR;
		int type;
		u64 size;
		u64 raw_size;
		u64 fileDiskTotalBytes;
		u64 fileDiskFreeBytes;
		BOOL isDrive;
		BOOL backupGPTfound;
		DISK_GEOMETRY pdg;
		GptPartition *firstPartion;
		int partCount;
		BOOL autoRcm;
		s8 partitionName[37];
		BOOL isSplitted = FALSE;
		NxSplitFile *lastSplitFile;
		int splitFileCount = 0;
		HCRYPTPROV h_Prov = 0;
		HCRYPTHASH h_Hash = 0;
		NxHandle handle;
		HANDLE handle_out;
		u64 bytesToRead;
		u64 bytesAmount;       
};

std::string BuildChecksum(HCRYPTHASH hHash);

