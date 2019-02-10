// NxNandManager

//#define ENABLE_GUI  1 // Comment this line to compile for CLI version only

#if defined(ENABLE_GUI)
	#include "stdafx.h"
#endif
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <iostream>
#include <chrono>
#include <ctime>
#include <Wincrypt.h>
#include <sys/types.h>
#include "types.h"
#include "utils.h"
#include "NxStorage.h"

#if defined(ENABLE_GUI)
	#include "MainDialog.h"
	CWinApp theApp;
#endif

using namespace std;

BOOL BYPASS_MD5SUM = FALSE;
BOOL DEBUG_MODE = FALSE;

std::string GetMD5Hash(const char* szPath)
{
	NxStorage* nxdata = (NxStorage*)malloc(sizeof(NxStorage));
	std::string md5hash;
	LPWSTR wszPath = convertCharArrayToLPWSTR(szPath);

	// Get handle to the file or I/O device
	HANDLE hDisk;
	hDisk = CreateFileW(wszPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hDisk == INVALID_HANDLE_VALUE)
	{
		printf("Could not open %s\n", wszPath);
		CloseHandle(hDisk);
	} else {

		BOOL bSuccess;
		DWORD buffSize = BUFSIZE, bytesRead = 0, cbHash = 0;
		BYTE buffRead[BUFSIZE], rgbHash[MD5LEN];
		ULONGLONG readAmount = 0;
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";
		cbHash = MD5LEN;

		// Get handle to the crypto provider
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
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
			if (0 == bytesRead)
			{
				break;
			}
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

			printf("Computing MD5 checksum... (%d%%) \r", (int)(readAmount * 100 / nxdata->size));
		}
		printf("\n");
		CloseHandle(hDisk);

		// Build checksum
		if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
		{
			char* buf;
			size_t sz;
			for (DWORD i = 0; i < cbHash; i++)
			{
				sz = snprintf(NULL, 0, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				buf = (char*)malloc(sz + 1);
				snprintf(buf, sz + 1, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
				md5hash.append(buf);
			}
			return md5hash;
		} else {
			printf("CryptGetHashParam failed\n");
		}
	}
	return NULL;
}
int main(int argc, char* argv[])
{
	//printf("NxNandManager by eliboa \n");
	const char* output = NULL;
	const char* input = NULL;
	BOOL info = FALSE, gui = FALSE;
	int io_num = 1;
	const char* partition = NULL;

	// Arguments, controls & usage
	auto PrintUsage = []() -> int {
		printf("Usage: NxNandManager.exe -i inputFilename|physicalDisk -o outputFilename|physicalDisk [-part=nxPartitionName] [lFlags] \n\n");
		printf("lFlags could be:\n");
		printf("BYPASS_MD5SUM: Doesn't check the MD5 during the dump, take less time but very less secure.\n");
		printf("DEBUG_MODE: Enable the debug mode.\n");
		throwException();
		return -1;
	};

	if (argc == 1)
	{
		PrintUsage();
	}

	const char GUI_ARGUMENT[] = "--gui";
	const char INPUT_ARGUMENT[] = "-i";
	const char OUTPUT_ARGUMENT[] = "-o";
	const char PARTITION_ARGUMENT[] = "-part";
	const char INFO_ARGUMENT[] = "--info";
	const char BYPASS_MD5SUM_FLAG[] = "BYPASS_MD5SUM";
	const char DEBUG_MODE_FLAG[] = "DEBUG_MODE";

	for (int i = 1; i < argc; i++)
	{
		char* currArg = argv[i];
		if (strncmp(currArg, GUI_ARGUMENT, array_countof(GUI_ARGUMENT) - 1) == 0)
		{
			gui = TRUE;
		}
		if (strncmp(currArg, INPUT_ARGUMENT, array_countof(INPUT_ARGUMENT) - 1) == 0 && i < argc)
		{
			input = argv[++i];
		}
		if (strncmp(currArg, OUTPUT_ARGUMENT, array_countof(OUTPUT_ARGUMENT) - 1) == 0 && i < argc)
		{
			output = argv[++i];
		}
		if (strncmp(currArg, PARTITION_ARGUMENT, array_countof(PARTITION_ARGUMENT) - 1) == 0)
		{
			u32 len= array_countof(PARTITION_ARGUMENT) - 1;
			if (currArg[len] == '=')
			{
				partition = &currArg[len + 1];
			}
			else if (currArg[len] == 0)
			{
				if (i == argc - 1) return PrintUsage();
			}
		}
		if (strncmp(currArg, INFO_ARGUMENT, array_countof(INFO_ARGUMENT) - 1) == 0)
		{
			info = TRUE;
		}
		if (strncmp(currArg, BYPASS_MD5SUM_FLAG, array_countof(BYPASS_MD5SUM_FLAG) - 1) == 0)
		{
			BYPASS_MD5SUM = TRUE;
		}
		if (strncmp(currArg, DEBUG_MODE_FLAG, array_countof(DEBUG_MODE_FLAG) - 1) == 0)
		{
			DEBUG_MODE = TRUE;
		}
	}

	#if defined(ENABLE_GUI)
	if (gui)
	{
		HMODULE hModule = ::GetModuleHandle(nullptr);
		if (hModule != nullptr)
		{
			if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
			{
				wprintf(L"Fatal Error: MFC initialization failed\n");
				return 1;
			}
		} else {
			wprintf(L"Fatal Error: GetModuleHandle failed\n");
			return -1;
		}

		MainDialog dlg(input, output);
		dlg.DoModal();
		return 0;
	}
	#endif
	
	if (NULL == input || (NULL == output && !info))
	{
		PrintUsage();
		return -1;
	}
	if (NULL != output && NULL != input) io_num = 2;

	if (DEBUG_MODE)
	{
		printf("INPUT ARGUMENT is %s. \n", input);
		printf("OUTPUT ARGUMENT is %s. \n", output);
		if (NULL != partition) printf("PARTITION ARGUMENT is %s. \n", partition);
		printf("BYPASS_MD5SUM is %s. \n", BYPASS_MD5SUM ? "true" : "false");
	}

	NxStorage nxdata(input);
	NxStorage nxdataOut(output);

	if (nxdata.type == INVALID)
	{
		if (nxdata.isDrive)
		{
			printf("Could not open physical drive. Make sure to run this program as an administrator.\n");
		} else {
			printf("Error while opening %s \n", input);
		}
		throwException();
	}
	if (NULL != output && !info)
	{
		if (nxdataOut.size > 0 && !nxdataOut.isDrive)
		{
			// Output file already exists					
			if (!AskYesNoQuestion("Output file already exists. Do you want to overwrite it ?"))
			{
				throwException("Operation cancelled.\n");
			}
		}

		if (nxdataOut.isDrive)
		{
			// Output is a logical drive
			printf("\nYOU ARE ABOUT TO COPY DATA TO A PHYSICAL DRIVE\n"
				"            BE VERY CAUTIOUS !!!\n\n");
			if (nxdata.type != nxdataOut.type)
			{
				printf("Input data type (%s) doesn't match output data type (%s)\n", nxdata.GetNxStorageTypeAsString(), nxdataOut.GetNxStorageTypeAsString());
				if (!AskYesNoQuestion("Are you REALLY sure you want to continue ?"))
				{
					throwException("Operation cancelled.\n");
				}
			}
			if (nxdata.size != nxdataOut.size || nxdata.type == nxdataOut.type)
			{
				if (nxdata.size != nxdataOut.size)
				{
					printf("Input data size (%I64d bytes) doesn't match output data size (%I64d bytes)\n", nxdata.size, nxdataOut.size);
				}
				if (!AskYesNoQuestion("Are you REALLY sure you want to continue ?"))
				{
					throwException("Operation cancelled.\n");
				}
			}
		}
	}

	// iterate input/output
	for (int i = 1; i <= io_num; i++)
	{
		BOOL isInput = i == 2 ? FALSE : TRUE;

		// --info option specified
		if (info)
		{
			NxStorage* curNxdata = i == 2 ? &nxdataOut : &nxdata;
			if (io_num == 2) printf("--- %s ---\n", isInput ? "INPUT" : "OUTPUT");
			printf("File/Disk : %s\n", curNxdata->isDrive ? "Disk" : "File");
			printf("NAND type : %s\n", curNxdata->GetNxStorageTypeAsString());
			printf("Size      : %s\n", GetReadableSize(curNxdata->size).c_str());
			if (NULL != curNxdata->firstPartion)
			{
				int i = 0;
				GptPartition *cur = curNxdata->firstPartion;
				while (NULL != cur)
				{
					u64 size = ((u64)cur->lba_end - (u64)cur->lba_start) * (int)NX_EMMC_BLOCKSIZE;
					printf("%s%02d %s  (%s)\n", i == 0 ? "Partitions: " : "            ", ++i, cur->name, GetReadableSize(size).c_str());
					cur = cur->next;
				}
			}
			// If there's nothing left to do, exit (we don't want to pursue with i/o operations)
			if (i == io_num)
			{
				system("PAUSE");
				return 0;
			}
		}
	}

	if (nxdata.size > 0 && nxdataOut.type != INVALID)
	{
		HANDLE hDisk, hDiskOut;
		u64 bytesToRead = nxdata.size, readAmount = 0, writeAmount = 0;
		BOOL bSuccess;
		int rc;

		// Get handle for input
		rc = nxdata.GetIOHandle(&hDisk, GENERIC_READ, partition, NULL != partition ? &bytesToRead : NULL);
		if (rc < -1)
		{
			throwException("Failed to get handle to input file/disk\n");
		}
		else if (rc == -1)
		{
			if (!AskYesNoQuestion("Unable to detect partition from input. Continue anyway (dump all partitions) ?"))
			{
				throwException("Operation canceled\n");
			}
		}

		// Get handle for output
		rc = nxdataOut.GetIOHandle(&hDiskOut, GENERIC_WRITE, partition, NULL != partition ? &bytesToRead : NULL);
		if (rc < -1)
		{
			throwException("Failed to get handle to output file/disk\n");
		}
		else if (rc == -1 && nxdataOut.type == RAWNAND)
		{
			if (!AskYesNoQuestion("Unable to detect partition from output. Continue anyway (will overwrite to entire file/disk) ?"))
			{
				throwException("Operation canceled\n");
			}
		}

		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";
		std::string md5hash;
		DWORD cbHash = MD5LEN;
		BYTE rgbHash[MD5LEN];

		if (!BYPASS_MD5SUM)
		{
			// Get handle to the crypto provider
			if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				DWORD dwStatus = GetLastError();
				printf("CryptAcquireContext failed: %d\n", dwStatus);
				CloseHandle(hDisk);
				throwException();
			}

			// Create the hash
			if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
			{
				CloseHandle(hDisk);
				throwException("CryptCreateHash failed\n");
			}
		} else {
			printf("MD5 Checksum validation bypassed\n");
		}

		// Read stream
		auto start = std::chrono::system_clock::now();

		while (bSuccess = nxdata.dumpStorage(&hDisk, &hDiskOut, &readAmount, &writeAmount, bytesToRead, !BYPASS_MD5SUM ? &hHash : NULL))
		{
			int percent = (u64)writeAmount * 100 / (u64)bytesToRead;
			printf("Copying raw data from input %s (type: %s%s%s) to output %s... (%d%%) \r",
				nxdata.isDrive ? "drive" : "file",
				nxdata.GetNxStorageTypeAsString(), nxdata.size != bytesToRead && NULL != partition ? ", partition: " : "",
				nxdata.size != bytesToRead && NULL != partition ? partition : "",
				nxdataOut.isDrive ? "drive" : "file",
				percent);
		}
		printf("\nFinished. %s dumped\n", GetReadableSize(writeAmount).c_str());
		CloseHandle(hDisk);
		CloseHandle(hDiskOut);

		if (writeAmount != bytesToRead)
		{
			printf("ERROR : %I64d bytes to read but %I64d bytes written\n", bytesToRead, writeAmount);
			throwException();
		}

		// Check dump integrity
		if (!BYPASS_MD5SUM)
		{
			// Build checksum for input file/drive
			if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
			{
				char* buf;
				size_t sz;
				for (DWORD i = 0; i < cbHash; i++)
				{
					sz = snprintf(NULL, 0, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
					buf = (char*)malloc(sz + 1);
					snprintf(buf, sz + 1, "%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
					md5hash.append(buf);
				}
			} else {
				throwException("\nFailed to get hash value.\n");
			}
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);

			if (DEBUG_MODE)
			{
				printf("MD5 sum for INPUT is %s\n", md5hash.c_str());
			}

			// Compute then compare output checksum
			if (md5hash == GetMD5Hash(output))
			{
				printf("Verified (checksums are IDENTICAL)\n");
			} else {
				printf("ERROR : checksums are DIFFERENT \n");
			}
		}

		// Compute elapsed time
		auto end = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed_seconds = end - start;
		printf("Elapsed time : %.2fs.\n", elapsed_seconds.count());

	}
	system("PAUSE");
	return 0;
}

