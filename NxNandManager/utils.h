#pragma once
#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <windows.h>
#include <winioctl.h>
#include "types.h"
#include <sys/stat.h>
#include <iostream>

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
char* ListPhysicalDrives();
char * flipAndCodeBytes(const char * str, int pos, int flip, char * buf);