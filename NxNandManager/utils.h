#pragma once
#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <windows.h>
#include <winioctl.h>
#include "types.h"
#include <sys/stat.h>
#include <iostream>

// MinGW
#if defined(__MINGW32__) || defined(__MINGW64__)
#   define _ELPP_MINGW 1
#else
#   define _ELPP_MINGW 0
#endif // defined(__MINGW32__) || defined(__MINGW64__)
// Some special functions that are special for VC++
// This is to prevent CRT security warnings and to override deprecated methods but at the same time
// MinGW does not support some functions, so we need to make sure that proper function is used.
#if defined(_ELPP_MINGW)
#   define sprintf_s snprintf
#endif

/*
BOOL GetStorageInfo(LPWSTR storage, NxStorage* nxdata);
BOOL ParseGpt(NxStorage* nxStorage, unsigned char *gptHeader);
*/

wchar_t *convertCharArrayToLPCWSTR(const char* charArray);
LPWSTR convertCharArrayToLPWSTR(const char* charArray);
u64 GetFilePointerEx (HANDLE hFile);
unsigned long sGetFileSize(std::string filename);
std::string GetLastErrorAsString();
std::string hexStr(unsigned char *data, int len);
BOOL AskYesNoQuestion(const char* question);
//const char* GetNxStorageTypeAsString(int type);
std::string GetReadableSize(u64 size);
void throwException(const char* errorStr=NULL);
std::string ListPhysicalDrives();
char * flipAndCodeBytes(const char * str, int pos, int flip, char * buf);