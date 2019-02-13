// NxNandManager
//#define ENABLE_GUI  1 // Comment this line to compile for CLI version only

#if defined(ENABLE_GUI)
	#include "stdafx.h"
	#include <afxwinappex.h>
#endif
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <iostream>
#include <ctime>
#include <Wincrypt.h>
#include <sys/types.h>
#include "types.h"
#include "utils.h"
#include "NxStorage.h"
#include "NxNandManager.h"

#if defined(ENABLE_GUI)
	#include "MainDialog.h"
	CWinAppEx theApp;
#endif

using namespace std;

BOOL BYPASS_MD5SUM = FALSE;
bool DEBUG_MODE = false;
//BOOL DEBUG_MODE = FALSE;
BOOL FORCE = FALSE;
BOOL LIST = FALSE;

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
		printf("Usage: NxNandManager.exe [--gui] [--list] [--info] -i inputFilename|\\\\.\\PhysicalDiskX -o outputFilename|\\\\.\\PhysicalDiskX [-part=nxPartitionName] [lFlags] \n\n");
		printf("Params are:\n\n");
		printf("--gui : Start the program in graphical mode, doesn't need other params.\n");
		printf("--list : List compatible device for dump/restaure, doesn't need other params.\n");
		printf("--info: Display infos for the input device/file witch is passed for input param, must be used with -i param only.");
		printf("-i \"input_path\" : Input device/file.");
		printf("-o \"output_path\" : Output device/file.");
		printf("-part : Dump/restaure for a specific partition of the rawnand, value could be \"PRODINFO\", \"PRODINFOF\", \"BCPKG2-1-Normal-Main\", \"BCPKG2-2-Normal-Sub\", \"BCPKG2-3-SafeMode-Main\", \"BCPKG2-4-SafeMode-Sub\", \"BCPKG2-5-Repair-Main\", \"BCPKG2-6-Repair-Sub\", \"SAFE\", \"SYSTEM\" or \"USER\".");
		printf("lFlags could be:\n");
		printf("BYPASS_MD5SUM: Doesn't check the MD5 during the copy, take less time but very less secure.\n");
		printf("DEBUG_MODE: Enable the debug mode.\n");
		printf("FORCE : Doesn't ask any questions during the program.\n");
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
	const char LIST_ARGUMENT[] = "--list";
	const char BYPASS_MD5SUM_FLAG[] = "BYPASS_MD5SUM";
	const char DEBUG_MODE_FLAG[] = "DEBUG_MODE";
	const char FORCE_FLAG[] = "FORCE";

	for (int i = 1; i < argc; i++)
	{
		char* currArg = argv[i];
		if (strncmp(currArg, LIST_ARGUMENT, array_countof(LIST_ARGUMENT) - 1) == 0)
		{
			LIST = TRUE;
		}
		#if defined(ENABLE_GUI)
			if (strncmp(currArg, GUI_ARGUMENT, array_countof(GUI_ARGUMENT) - 1) == 0)
			{
				gui = TRUE;
			}
		#endif
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
		if (strncmp(currArg, FORCE_FLAG, array_countof(FORCE_FLAG) - 1) == 0)
		{
			FORCE = TRUE;
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

	if (LIST && !gui)
	{
		printf("%s", ListPhysicalDrives().c_str());
		return 0;
	}

	if (NULL == input || (NULL == output && !info))
	{
		PrintUsage();
		return -1;
	}
	if (NULL != output && NULL != input) io_num = 2;

	if (FORCE)
	{
		printf("Force mode activated, no questions will be asked.\n");
	}

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
			if (!FORCE)
			{
				// Output file already exists					
				if (!AskYesNoQuestion("Output file already exists. Do you want to overwrite it ?"))
				{
					throwException("Operation cancelled.\n");
				}
			}
		}

		if (nxdataOut.isDrive)
		{
			// Output is a logical drive
			if (!FORCE)
			{
				printf("\nYOU ARE ABOUT TO COPY DATA TO A PHYSICAL DRIVE\n"
					"            BE VERY CAUTIOUS !!!\n\n");
			}
			if (nxdataOut.type == RAWNAND && nxdata.type == UNKNOWN && NULL != partition)
			{
				printf("Input data type is (%s) and output data type is (%s), you try to restaure a partition, be very cautious.\n", nxdata.GetNxStorageTypeAsString(), nxdataOut.GetNxStorageTypeAsString());
				if (!FORCE)
				{
					if (!AskYesNoQuestion("Are you REALLY sure you want to continue ?"))
					{
						throwException("Operation cancelled.\n");
					}
				}
			} else {
				if (nxdata.type != nxdataOut.type)
				{
					printf("Input data type (%s) doesn't match output data type (%s)\n", nxdata.GetNxStorageTypeAsString(), nxdataOut.GetNxStorageTypeAsString());
					printf("For security reason, you can't continue.\n");
					return 40;
				}
				if (!FORCE)
				{
					if (!AskYesNoQuestion("Are you REALLY sure you want to continue ?"))
					{
						throwException("Operation cancelled.\n");
					}
				}
			}
			u64 in_size = nxdata.raw_size > 0 ? nxdata.raw_size : nxdata.size;
			u64 out_size = nxdataOut.raw_size > 0 ? nxdataOut.raw_size : nxdataOut.size;
			if (in_size != out_size || nxdata.type == nxdataOut.type)
			{
				if (in_size != out_size && NULL == partition)
				{
					printf("Input data size (%I64d bytes) doesn't match output data size (%I64d bytes)\n", nxdata.size, nxdataOut.size);
					if (!FORCE)
					{
						if (!AskYesNoQuestion("Are you REALLY sure you want to continue ?"))
						{
							throwException("Operation cancelled.\n");
						}
					} else {
						printf("You can't continue in force mode for security reason.");
						return 41;
					}
				}
			}
		}
	}

	// --info option specified
	if (info)
	{
		// iterate input/output
		for (int i = 1; i <= io_num; i++)
		{
			BOOL isInput = i == 2 ? FALSE : TRUE;

			NxStorage* curNxdata = i == 2 ? &nxdataOut : &nxdata;
			if (io_num == 2) printf("--- %s ---\n", isInput ? "INPUT" : "OUTPUT");
			printf("File/Disk : %s\n", curNxdata->isDrive ? "Disk" : "File");
			printf("NAND type : %s\n", curNxdata->GetNxStorageTypeAsString());
			if(curNxdata->type == BOOT0) printf("AutoRCM   : %s\n", curNxdata->autoRcm ? "ENABLED" : "DISABLED");			
			printf("Size      : %s\n", GetReadableSize(curNxdata->size).c_str());
			if (NULL != curNxdata->firstPartion)
			{
				int i = 0;
				GptPartition *cur = curNxdata->firstPartion;
				while (NULL != cur)
				{
					u64 size = ((u64)cur->lba_end - (u64)cur->lba_start) * (int)NX_EMMC_BLOCKSIZE;
					printf("%s%02d %s  (%s)\n", i == 1 ? "Partitions: " : "            ", ++i, cur->name, GetReadableSize(size).c_str());
					cur = cur->next;
				}
			}
			if(curNxdata->type == RAWNAND) printf("Backup GPT: %s\n", curNxdata->backupGPTfound ? "FOUND" : "MISSING !!!");
			// If there's nothing left to do, exit (we don't want to pursue with i/o operations)
			if (i == io_num)
			{
				return 0;
			}
		}
	}

	if (nxdata.size > 0)
	{
		HANDLE hDisk, hDiskOut;
		u64 bytesToRead = nxdata.size, readAmount = 0, writeAmount = 0;
		if (nxdata.type == RAWNAND && nxdata.raw_size > 0 && NULL == partition)
		{
			bytesToRead = nxdata.raw_size;
		}
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
			if (!FORCE)
			{
				if (!AskYesNoQuestion("Unable to detect partition from input. Continue anyway (dump all partitions) ?"))
				{
					throwException("Operation canceled\n");
				}
			} else {
				printf("No partition detected for your input, you can't continue in force mode for security reason.");
				return 42;
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
			if (!FORCE)
			{
				if (!AskYesNoQuestion("Unable to detect partition from output. Continue anyway (will overwrite entire file/disk) ?"))
				{
					throwException("Operation canceled\n");
				}
			} else {
				printf("No partitions detected in your Rawnand output, you can't continue in force mode for security reason.");
				return 43;
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
		int percent = -1;
		auto start = std::chrono::system_clock::now();
		while (bSuccess = nxdata.dumpStorage(&hDisk, &hDiskOut, &readAmount, &writeAmount, bytesToRead, !BYPASS_MD5SUM ? &hHash : NULL))
		{
			int new_percent = (u64)writeAmount * 100 / (u64)bytesToRead;
			if (new_percent > percent) {
				percent = new_percent;
				printf("Copying from input %s (type: %s%s%s) to output %s... (%d%%) \r",
					nxdata.isDrive ? "drive" : "file",
					nxdata.GetNxStorageTypeAsString(), nxdata.size != bytesToRead && NULL != partition ? ", partition: " : "",
					nxdata.size != bytesToRead && NULL != partition ? partition : "",
					nxdataOut.isDrive ? "drive" : "file",
					percent);
			}
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

			// Compute then compare output checksums
			nxdataOut.InitStorage(); // We need to update output obj first (mandatory!)
			if (md5hash == nxdataOut.GetMD5Hash())
			{
				printf("Verified (checksums are IDENTICAL)\n");
			} else {
				printf("ERROR : checksums are DIFFERENT \n");
			}
		}

		// Compute elapsed time
		auto end = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed_seconds = end - start;
		printf("Elapsed time : %s.\n", GetReadableElapsedTime(elapsed_seconds).c_str());
	}
	return 0;
}

