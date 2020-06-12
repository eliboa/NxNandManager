#ifndef __utils_h__
#define __utils_h__

extern bool isdebug;
extern bool isGUI;

#include <stdio.h>
#include <string>
#include <sys/types.h>
#include <windows.h>
#include <winioctl.h>
#include <Wincrypt.h>
#include "types.h"
#include <sys/stat.h>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <wchar.h>
#include <algorithm>
#include <sstream>
#include <tchar.h>
#include <locale>
#include <codecvt>
#include <vector>
#include "win_ioctl.h"
#include "types.h"
#include "../gui/gui.h"

#if defined(ENABLE_GUI)
#include "../gui/debug.h"
#endif

// MinGW
#if defined(__MINGW32__) || defined(__MINGW64__) || defined(__MSYS__)
#define strcpy_s strcpy
#define sprintf_s snprintf
#endif

//CRYPTO
#define ENCRYPT 1
#define DECRYPT 2

#define SUCCESS 0
// ERRORS
#define ERR_WRONG_USE			   -1001
#define ERR_INVALID_INPUT		   -1002
#define ERR_INVALID_OUTPUT		   -1003
#define ERR_INVALID_PART		   -1004
#define ERR_IO_MISMATCH			   -1005
#define ERR_INPUT_HANDLE		   -1006
#define ERR_OUTPUT_HANDLE		   -1007
#define ERR_CRYPTO_MD5			   -1008
#define ERR_NO_LIST_DISK		   -1009
#define ERR_NO_SPACE_LEFT		   -1010
#define ERR_COPY_SIZE			   -1011
#define ERR_MD5_COMPARE			   -1012
#define ERR_INIT_GUI			   -1013
#define ERR_WORK_RUNNING		   -1014
#define ERR_WHILE_COPY             -1015
#define NO_MORE_BYTES_TO_COPY      -1016
#define ERR_RESTORE_TO_SPLIT	   -1017
#define ERR_DECRYPT_CONTENT		   -1018
#define ERR_RESTORE_CRYPTO_MISSING -1019
#define ERR_CRYPTO_KEY_MISSING	   -1020
#define ERR_CRYPTO_GENERIC  	   -1021
#define ERR_CRYPTO_NOT_ENCRYPTED   -1022
#define ERR_CRYPTO_ENCRYPTED_YET   -1023
#define ERR_CRYPTO_DECRYPTED_YET   -1024
#define ERR_RESTORE_CRYPTO_MISSIN2 -1025
#define ERROR_DECRYPT_FAILED	   -1026
#define ERR_RESTORE_UNKNOWN_DISK   -1027
#define ERR_IN_PART_NOT_FOUND      -1028
#define ERR_OUT_PART_NOT_FOUND     -1029
#define ERR_KEYSET_NOT_EXISTS      -1030
#define ERR_KEYSET_EMPTY           -1031
#define ERR_FILE_ALREADY_EXISTS    -1032
#define ERR_CRYPTO_RAW_COPY        -1033
#define ERR_NX_TYPE_MISSMATCH      -1034
#define ERR_OUTPUT_NOT_MMC         -1035
#define ERR_OUT_DISMOUNT_VOL       -1036
#define ERR_WHILE_WRITE			   -1037
#define ERR_PART_CREATE_FAILED	   -1038
#define ERR_USER_ABORT             -1039
#define ERR_BAD_CRYPTO             -1040
#define ERR_VOL_MOUNT_FAILED       -1041
#define ERR_INVALID_NAND           -1042
#define ERR_INVALID_BOOT0          -1043
#define ERR_INVALID_BOOT1          -1044
#define ERR_OUTPUT_NOT_DRIVE       -1045
#define ERR_CREATE_DIR_FAILED      -1046
#define ERR_CREATE_ZIP             -1047
#define ERR_CREATE_FILE_FAILED     -1048
#define ERR_FORMAT_BAD_PART        -1049

typedef struct ErrorLabel ErrorLabel;
struct ErrorLabel {
	int error;
	const char* label;
};

static ErrorLabel ErrorLabelArr[] =
{
	{ ERR_WORK_RUNNING, "Work already in process"},
	{ ERR_INPUT_HANDLE, "Failed to get handle to input file/disk"},
	{ ERR_OUTPUT_HANDLE, "Failed to get handle to output file/disk"},
	{ ERR_NO_SPACE_LEFT, "Output disk : not enough space !"},
	{ ERR_CRYPTO_MD5, "Crypto provider error"},
	{ ERR_MD5_COMPARE, "Data integrity error : checksums are differents.\nAn error must have occurred during the copy"},
	{ ERR_RESTORE_TO_SPLIT, "Restore to splitted dump is not supported"},
	{ ERR_WHILE_COPY, "An error occured during copy"},
	{ ERR_IO_MISMATCH, "Input type/size doesn't match output size/type"},
    { ERR_NX_TYPE_MISSMATCH, "Input type doesn't match output type"},
	{ ERR_INVALID_INPUT, "Input is not a valid NX storage"},
    { ERR_INVALID_NAND, "Input is missing or is not a valid NAND (FULL NAND or RAWNAND"},
    { ERR_INVALID_BOOT0, "BOOT0 is missing or is not valid"},
    { ERR_INVALID_BOOT1, "BOOT0 is missing or is not valid"},
	{ ERR_INVALID_OUTPUT, "Output is not a valid NX storage"},
	{ ERR_DECRYPT_CONTENT, "Failed to validate decrypted content (wrong keys ?)"},
    { ERR_RESTORE_CRYPTO_MISSING, "Trying to restore decrypted content to encrypted content"},
	{ ERR_RESTORE_CRYPTO_MISSIN2, "Trying to restore encrypted content to decrypted content"},
    { ERR_CRYPTO_KEY_MISSING, "Trying to decrypt/encrypt content but some keys are missing (configure keyset)"},
	{ ERROR_DECRYPT_FAILED, "Decryption validation failed (wrong keys ?)"},
	{ ERR_CRYPTO_NOT_ENCRYPTED, "Input file is not encrypted"},
	{ ERR_CRYPTO_ENCRYPTED_YET, "Input file is already encrypted"},
	{ ERR_CRYPTO_DECRYPTED_YET, "Input file is already decrypted"},
	{ ERR_IN_PART_NOT_FOUND, "Partition not found in \"input\""},
	{ ERR_OUT_PART_NOT_FOUND, "Partition not found in \"output\""},
	{ ERR_RESTORE_UNKNOWN_DISK, "Cannot restore to an unknown disk"},
    { ERR_FILE_ALREADY_EXISTS, "Output file/directory already exits"},
	{ ERR_OUTPUT_NOT_MMC, "Output must be removable media (MMC)"},
	{ ERR_OUT_DISMOUNT_VOL, "Failed to dismount volume(s) in output drive"},
	{ ERR_WHILE_WRITE, "Failed to write to output file/disk"},
    { ERR_PART_CREATE_FAILED, "Failed to create new partition"},
    { ERR_USER_ABORT, "Work aborted by user"},
    { ERR_BAD_CRYPTO, "Failed to validate crypto (wrong keys ?)"},
    { ERR_VOL_MOUNT_FAILED, "Failed to mount new FAT32 partition. Needed files for CFW (Atmosphere) cannot be created"},
    { ERR_OUTPUT_NOT_DRIVE, "Output is not a volume/drive"},
    { ERR_CREATE_DIR_FAILED, "Failed to create directory in ouput drive/volume"},
    { ERR_CREATE_FILE_FAILED, "Failed to create file in ouput drive/volume"},
    { ERR_CREATE_ZIP, "An error occured while creating archive (zip)"},
    { ERR_FORMAT_BAD_PART, "Partition formating is only possible for USER et SYSTEM"}
};

typedef struct KeySet KeySet;
struct KeySet {
	char crypt0[33];
	char tweak0[33];
	char crypt1[33];
	char tweak1[33];
	char crypt2[33];
	char tweak2[33];
	char crypt3[33];
	char tweak3[33];
};

void dbg_printf (const char *format, ...);
void dbg_wprintf (const wchar_t *format, ...);

wchar_t *convertCharArrayToLPCWSTR(const char* charArray);
LPWSTR convertCharArrayToLPWSTR(const char* charArray);
u64 GetFilePointerEx (HANDLE hFile);
unsigned long sGetFileSize(std::string filename);
std::string GetLastErrorAsString();
std::string hexStr(unsigned char *data, int len);
BOOL AskYesNoQuestion(const char* question, void* p_arg1 = NULL, void* p_arg2 = NULL);
std::string GetReadableSize(u64 size);
std::string GetReadableElapsedTime(std::chrono::duration<double> elapsed_seconds);
void throwException(int rc, const char* errorStr=NULL);
void throwException(const char* errorStr=NULL, void* p_arg1 = NULL, void* p_arg2 = NULL);
char * flipAndCodeBytes(const char * str, int pos, int flip, char * buf);
std::string ExePath();
HMODULE GetCurrentModule();
bool file_exists(const wchar_t *fileName);
int digit_to_int(char d);
int hex_to_int(char c);
int hex_to_ascii(char c, char d);
std::string hexStr_to_ascii(const char* hexStr);

static DWORD crc32table[256];
static bool crc32Intalized = false;
DWORD crc32Hash(const void *data, DWORD size);

template<class T>
T base_name(T const & path, T const & delims = "/\\")
{
	return path.substr(path.find_last_of(delims) + 1);
}

template<class T>
T base_nameW(T const & path, T const & delims = L"/\\")
{
	return path.substr(path.find_last_of(delims) + 1);
}
template<class T>
T remove_extension(T const & filename)
{
	typename T::size_type const p(filename.find_last_of('.'));
	return p > 0 && p != T::npos ? filename.substr(0, p) : filename;
}
template<class T>
T remove_extensionW(T const & filename)
{
	typename T::size_type const p(filename.find_last_of(L'.'));
	return p > 0 && p != T::npos ? filename.substr(0, p) : filename;
}
template<class T>
T get_extension(T const & filename)
{
	typename T::size_type const p(filename.find_last_of('.'));
	return p > 0 && p != T::npos ? filename.substr(p, T::npos) : filename;
}
template<class T>
T get_extensionW(T const & filename)
{
	typename T::size_type const p(filename.find_last_of(L'.'));
	return p > 0 && p != T::npos ? filename.substr(p, T::npos) : filename;
}

template< typename T >
std::string int_to_hex(T i)
{
	std::stringstream stream;
	stream << "0x"
		<< std::setfill('0') //<< std::setw(sizeof(T) * 2)
		<< std::uppercase
		<< std::hex << i;

	return stream.str();
}
template<typename T, size_t ARR_SIZE>
size_t array_countof(T(&)[ARR_SIZE]) { return ARR_SIZE; }
template <typename I> std::string n2hexstr(I w, size_t hex_len = sizeof(I) << 1) {
	static const char* digits = "0123456789ABCDEF";
	std::string rc(hex_len, '0');
	for (size_t i = 0, j = (hex_len - 1) * 4; i<hex_len; ++i, j -= 4)
		rc[i] = digits[(w >> j) & 0x0f];
	return rc;
}

template <typename T>
bool is_in(const T& v, std::initializer_list<T> lst)
{
    return std::find(std::begin(lst), std::end(lst), v) != std::end(lst);
}

template <typename T>
bool not_in(const T& v, std::initializer_list<T> lst)
{
    return std::find(std::begin(lst), std::end(lst), v) == std::end(lst);
}

std::string ltrim(const std::string& s);
std::string rtrim(const std::string& s);
std::string trim(const std::string& s);

bool is_file(const char* path);
bool is_dir(const char* path);
int parseKeySetFile(const char *keyset_file, KeySet *biskeys);
u32 u32_val(u8* buf);

template<typename M> inline void* GetMethodPointer(M ptr)
{
    return *reinterpret_cast<void**>(&ptr);
}

#endif
