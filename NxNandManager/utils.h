#pragma once
#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <windows.h>
#include <winioctl.h>
#include "types.h"
#include <sys/stat.h>
#include <iostream>
#include <chrono>
#include <iomanip>

// MinGW
#if defined(__MINGW32__) || defined(__MINGW64__) || defined(__MSYS__)
#   define strcpy_s strcpy
#   define sprintf_s snprintf
#endif

// ERRORS
#define ERR_WRONG_USE			-1001
#define ERR_INVALID_INPUT		-1002
#define ERR_INVALID_OUTPUT		-1003
#define ERR_INVALID_PART		-1004
#define ERR_IO_MISMATCH			-1005
#define ERR_INPUT_HANDLE		-1006
#define ERR_OUTPUT_HANDLE		-1007
#define ERR_CRYPTO_MD5			-1008
#define ERR_NO_LIST_DISK		-1009
#define ERR_NO_SPACE_LEFT		-1010
#define ERR_COPY_SIZE			-1011
#define ERR_MD5_COMPARE			-1012
#define ERR_INIT_GUI			-1013


wchar_t *convertCharArrayToLPCWSTR(const char* charArray);
LPWSTR convertCharArrayToLPWSTR(const char* charArray);
u64 GetFilePointerEx (HANDLE hFile);
unsigned long sGetFileSize(std::string filename);
std::string GetLastErrorAsString();
std::string hexStr(unsigned char *data, int len);
BOOL AskYesNoQuestion(const char* question);
std::string GetReadableSize(u64 size);
std::string GetReadableElapsedTime(std::chrono::duration<double> elapsed_seconds);
void throwException(int rc, const char* errorStr=NULL);
void throwException(const char* errorStr=NULL);
std::string ListPhysicalDrives(BOOL noError=FALSE);
char * flipAndCodeBytes(const char * str, int pos, int flip, char * buf);
std::string ExePath();

template<class T>
T base_name(T const & path, T const & delims = "/\\")
{
	return path.substr(path.find_last_of(delims) + 1);
}
template<class T>
T remove_extension(T const & filename)
{
	typename T::size_type const p(filename.find_last_of('.'));
	return p > 0 && p != T::npos ? filename.substr(0, p) : filename;
}