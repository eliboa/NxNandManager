#pragma once

#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <windows.h>
#include <winioctl.h>
#include "types.h"
#include <sys/stat.h>
#include <iostream>

#define BUFSIZE 262144
#define MD5LEN  16
#define BOOT0   1001
#define BOOT1   1002
#define RAWNAND 1003
#define UNKNOWN 1004
#define NX_GPT_FIRST_LBA 1
#define NX_GPT_NUM_BLOCKS 33
#define NX_EMMC_BLOCKSIZE 512
#define GPT_PART_NAME_LEN 36

BOOL GetStorageInfo(LPWSTR storage, NxStorage* nxdata);
BOOL ParseGpt(unsigned char *gptHeader);

wchar_t *convertCharArrayToLPCWSTR(const char* charArray);
LPWSTR convertCharArrayToLPWSTR(const char* charArray);
u64 GetFilePointerEx (HANDLE hFile);
unsigned long sGetFileSize(std::string filename);
std::string GetLastErrorAsString();
std::string hexStr(unsigned char *data, int len);
BOOL AskYesNoQuestion(const char* question);
const char* GetNxStorageTypeAsString(int type);