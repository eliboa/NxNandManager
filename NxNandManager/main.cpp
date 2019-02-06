// NxNandManager
//

#include "stdafx.h"
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <iostream>
#include <chrono>
#include <ctime>  
#include <sys/types.h>
#include <sys/stat.h>
#include <Wincrypt.h>
#include "types.h"

using namespace std;
#define BUFSIZE 262144
#define MD5LEN  16


//#define wszDrive L"\\\\.\\PHYSICALDRIVE3"

wchar_t *convertCharArrayToLPCWSTR(const char* charArray)
{
	wchar_t* wString = new wchar_t[4096];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}

LPWSTR convertCharArrayToLPWSTR(const char* charArray)
{
	int nSize = MultiByteToWideChar(CP_ACP, 0, charArray, -1, NULL, 0);
	LPWSTR wString = new WCHAR[nSize];
	MultiByteToWideChar(CP_ACP, 0, charArray, -1, wString, 4096);
	return wString;
}

BOOL GetDriveGeometry(LPWSTR wszPath, DISK_GEOMETRY *pdg)
{
	HANDLE hDevice = INVALID_HANDLE_VALUE;  // handle to the drive to be examined 
	BOOL bResult = FALSE;                 // results flag
	DWORD junk = 0;                     // discard results

	hDevice = CreateFileW(wszPath,          // drive to open
		0,                // no access to the drive
		FILE_SHARE_READ | // share mode
		FILE_SHARE_WRITE,
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		0,                // file attributes
		NULL);            // do not copy file attributes

	if (hDevice == INVALID_HANDLE_VALUE)    // cannot open the drive
	{
		return (FALSE);
	}

	bResult = DeviceIoControl(hDevice,                       // device to be queried
		IOCTL_DISK_GET_DRIVE_GEOMETRY, // operation to perform
		NULL, 0,                       // no input buffer
		pdg, sizeof(*pdg),            // output buffer
		&junk,                         // # bytes returned
		(LPOVERLAPPED)NULL);          // synchronous I/O

	CloseHandle(hDevice);

	return (bResult);
}

unsigned long sGetFileSize(std::string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

std::string GetMD5Hash(const char* szPath) {

	std::string md5hash;
	LPWSTR wszPath = convertCharArrayToLPWSTR(szPath);
	unsigned long DiskSize = sGetFileSize(szPath);
	HANDLE hDisk;
	
	// Get handle to the file or I/O device
	hDisk = CreateFileW(wszPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (hDisk == INVALID_HANDLE_VALUE)
	{
		printf("%s", "Could not open %s\n", wszPath);
		CloseHandle(hDisk);
	}
	else {
		BOOL bSuccess;
		DWORD buffSize = BUFSIZE, bytesRead = 0, cbHash = 0;
		BYTE buffRead[BUFSIZE], rgbHash[MD5LEN];
		ULONGLONG readAmount = 0;
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";
		cbHash = MD5LEN;
		
		// Get handle to the crypto provider
		if (!CryptAcquireContext(&hProv,  NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) 
		{
			printf("CryptAcquireContext failed");
			CloseHandle(hDisk);
			return NULL;
		}

		// Create new hash
		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			printf("CryptCreateHash failed");
			CloseHandle(hDisk);
			return NULL;
		}

		// Read stream
		while (bSuccess = ReadFile(hDisk, buffRead, buffSize, &bytesRead, NULL))
		{
			if (0 == bytesRead) break;
			readAmount += bytesRead;

			// Hash every read buffer
			if (!CryptHashData(hHash, buffRead, bytesRead, 0))
			{
				printf("CryptHashData failed: \n");
				CryptReleaseContext(hProv, 0);
				CryptDestroyHash(hHash);
				CloseHandle(hDisk);
				return NULL;
			}

			printf("Computing MD5 checksum... (%d%%) \r", (readAmount * 100) / DiskSize);
		}
		printf("\n");
		CloseHandle(hDisk);
		
		// Build checksum
		if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
		{
			char *buf;
			size_t sz;
			for (DWORD i = 0; i < cbHash; i++)
			{
				sz = snprintf(NULL, 0, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				buf = (char *)malloc(sz + 1);
				snprintf(buf, sz + 1, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				md5hash.append(buf);
			}
			return md5hash;
		}
		else
		{
			printf("CryptGetHashParam failed\n");
		}
	}	
	return NULL;
}

std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

int main(int argc, char* argv[])
{
	printf("NxNandManager by eliboa \n");
	const char* output = nullptr;
	const char* input = nullptr;
	BOOL BYPASS_MD5SUM = FALSE;
	BOOL DEBUG_MODE = FALSE;

	// Arguments, controles & usage
	auto PrintUsage = []() -> int
	{
		printf("Usage: NxNandManager.exe -i inputFilename.bin -o outputFilename.bin [lFlags] \n");
		return -1;
	};

	if (argc == 1) 
	{
		PrintUsage();
		return -1;
	}

	for (int i = 1; i < argc; i++)
	{
		char* currArg = argv[i];
		const char INPUT_ARGUMENT[] = "-i";
		const char OUTPUT_ARGUMENT[] = "-o";
		const char BYPASS_MD5SUM_FLAG[] = "BYPASS_MD5SUM";
		const char DEBUG_MODE_FLAG[] = "DEBUG_MODE";
		
		if (_strnicmp(currArg, INPUT_ARGUMENT, array_countof(INPUT_ARGUMENT) - 1) == 0 && i < argc) 
			input = argv[++i];		
		if (_strnicmp(currArg, OUTPUT_ARGUMENT, array_countof(OUTPUT_ARGUMENT) - 1) == 0 && i < argc) 
			output = argv[++i];
		if (_strnicmp(currArg, BYPASS_MD5SUM_FLAG, array_countof(BYPASS_MD5SUM_FLAG) - 1) == 0) 
			BYPASS_MD5SUM = TRUE;
		if (_strnicmp(currArg, DEBUG_MODE_FLAG, array_countof(DEBUG_MODE_FLAG) - 1) == 0) 
			DEBUG_MODE = TRUE;			
	}

	if (nullptr == output || nullptr == input) {
		PrintUsage();
		return -1;
	}

	if (DEBUG_MODE) {
		printf("INPUT is %s. Length is %d. \n", input, strlen(input));
		printf("OUTPUT is %s. Length is %d. \n", output, strlen(output));
		printf("BYPASS_MD5SUM is %s. \n", BYPASS_MD5SUM ? "true" : "false");
	}


	// LPWSTR wszDrive = L"\\\\.\\PHYSICALDRIVE3";
	LPWSTR wszDrive = convertCharArrayToLPWSTR(input);
	DISK_GEOMETRY pdg = { 0 };
	BOOL isDrive = FALSE;      
	unsigned long long DiskSize = 0;

	isDrive = GetDriveGeometry(wszDrive, &pdg);

	if (isDrive)
	{
		DiskSize = pdg.Cylinders.QuadPart * (ULONG)pdg.TracksPerCylinder 
			* (ULONG)pdg.SectorsPerTrack * (ULONG)pdg.BytesPerSector;
		
		if (DEBUG_MODE) {
			wprintf(L"Drive path      = %ws\n", wszDrive);
			wprintf(L"Cylinders       = %I64d\n", pdg.Cylinders);
			wprintf(L"Tracks/cylinder = %ld\n", (ULONG)pdg.TracksPerCylinder);
			wprintf(L"Sectors/track   = %ld\n", (ULONG)pdg.SectorsPerTrack);
			wprintf(L"Bytes/sector    = %ld\n", (ULONG)pdg.BytesPerSector);
			wprintf(L"Disk size       = %I64d (Bytes)\n"
				L"                = %.2f (Gb)\n",
				DiskSize, (double)DiskSize / (1024 * 1024 * 1024));
		}
	}
	else
	{
		DiskSize = sGetFileSize(input);
		if (DiskSize <= 0)
		{
			wprintf(L"Unable to detect input %ld.\n", GetLastError());
			system("PAUSE");
			return 0;
		}
	}

	// Get handle to the file or I/O device
	HANDLE hDisk;
	hDisk = CreateFileW(wszDrive, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (hDisk == INVALID_HANDLE_VALUE)
	{
		if(isDrive) printf("Could not open physical drive. Make sur to run this program as an administrator.\n");
		else printf("Error while opening %s \n", input);
		CloseHandle(hDisk);
	}
	else {
		printf("%s", "Successfully open the drive/file \n");
		auto start = std::chrono::system_clock::now();

		BOOL bSuccess;
		DWORD buffSize = BUFSIZE, bytesRead = 0, bytesWrite = 0, cbHash = 0;
		BYTE buffRead[BUFSIZE], rgbHash[MD5LEN];
		ULONGLONG readAmount = 0;
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";
		std::string md5hash;		
		cbHash = MD5LEN;
		
		ofstream binOutput;
		binOutput.open(output, ofstream::out | ofstream::binary);
		
		if (!BYPASS_MD5SUM)
		{
			// Get handle to the crypto provider
			if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				DWORD dwStatus = GetLastError();
				printf("CryptAcquireContext failed: %d\n", dwStatus);
				CloseHandle(hDisk);
				system("PAUSE");
				return 0;
			}

			// Create the hash
			if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
			{
				printf("CryptCreateHash failed");
				CloseHandle(hDisk);
				system("PAUSE");
				return 0;
			}
		}
		else {
			printf("MD5 Checksum validation bypassed\n");
		}

		// Read stream
		while (bSuccess = ReadFile(hDisk, buffRead, buffSize, &bytesRead, NULL))
		{
			if (0 == bytesRead) break;
			readAmount += bytesRead;

			//printf("read %ld of %ld\n", bytesRead, readAmount);
			//
			//if(readAmount > BUFSIZE * 10) break;
			//

			if (!BYPASS_MD5SUM)
			{
				// Hash every read buffer
				if (!CryptHashData(hHash, buffRead, bytesRead, 0))
				{
					printf("CryptHashData failed: \n");
					CryptReleaseContext(hProv, 0);
					CryptDestroyHash(hHash);
					CloseHandle(hDisk);
					system("PAUSE");
					return 0;
				}
			}

			// Write buffer to output stream
			binOutput.write((char*)buffRead, bytesRead);
			bytesWrite += bytesRead;
			//printf("write %ld of %ld\n", bytesRead, bytesWrite);

			printf("Dumping raw data... (%d%%) \r", (readAmount * 100) / DiskSize);			

		}
		printf("\nFinished. %ld bytes\n", readAmount);
		binOutput.close();
		CloseHandle(hDisk);

		// Check dump integrity
		if (!BYPASS_MD5SUM)
		{
			// Build checksum for input file/drive
			if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
			{
				char *buf;
				size_t sz;
				for (DWORD i = 0; i < cbHash; i++)
				{
					sz = snprintf(NULL, 0, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
					buf = (char *)malloc(sz + 1);
					snprintf(buf, sz + 1, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
					md5hash.append(buf);
				}
			}
			else
			{
				printf("\nFailed to get hash value.\n");
				system("PAUSE");
				return 0;
			}
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);

			// Compute then compare output checksum
			if (md5hash == GetMD5Hash(output)) printf("Verified (checksums are IDENTICAL)\n");
			else printf("ERROR : checksums are DIFFERENT \n");
		}

		// Compute elapsed time
		auto end = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed_seconds = end - start;
		std::time_t end_time = std::chrono::system_clock::to_time_t(end);
		printf("Elapsed time : %.2f s.\n", elapsed_seconds.count());		
	}

	system("PAUSE");
	return 0;
}

