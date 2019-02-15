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
	printf("[ NxNandManager v1.0-beta ]\n\n");
	const char* output = NULL;
	const char* input = NULL;
	BOOL info = FALSE, gui = FALSE;
	int io_num = 1;
	const char* partition = NULL;

	// Arguments, controls & usage
	auto PrintUsage = []() -> int {
		printf("usage: NxNandManager [--gui] [--list] [--info] -i <inputFilename|\\\\.\\PhysicalDiskX>\n"
			   "                     -o <outputFilename|\\\\.\\PhysicalDiskX> [-part=nxPartitionName] [<lFlags>]\n\n"
			   "  --gui       Start the program in graphical mode, doesn't need other argument\n"
			   "  --list      List compatible NX physical disks\n"
			   "  --info      Display information about input/output file or device\n"
			   "  -i          Path to input file or device\n"
			   "  -o          Path to output file or device\n"
			   "  -part       Partition to copy (apply to both input & output if possible)\n"
			   "              Value could be \"PRODINFO\", \"PRODINFOF\", \"BCPKG2-1-Normal-Main\"\n" 
			   "              \"BCPKG2-2-Normal-Sub\", \"BCPKG2-3-SafeMode-Main\", \"BCPKG2-4-SafeMode-Sub\",\n"
			   "              \"BCPKG2-5-Repair-Main\", \"BCPKG2-6-Repair-Sub\", \"SAFE\", \"SYSTEM\" or \"USER\"\n\n");

		printf("  lFlags:     \"BYPASS_MD5SUM\" to bypass MD5 integrity checks (faster but less secure)\n"
			   "  -------     \"FORCE\" to disable prompt for user input (no question asked)\n"
			   "              \"DEBUG_MODE\" to display debug information\n");

		throwException(ERR_WRONG_USE);
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
		} else if (strncmp(currArg, GUI_ARGUMENT, array_countof(GUI_ARGUMENT) - 1) == 0)
		{
			#if defined(ENABLE_GUI)
				gui = TRUE;
			#endif
		} else if (strncmp(currArg, INPUT_ARGUMENT, array_countof(INPUT_ARGUMENT) - 1) == 0 && i < argc)
		{
			input = argv[++i];
		} else if (strncmp(currArg, OUTPUT_ARGUMENT, array_countof(OUTPUT_ARGUMENT) - 1) == 0 && i < argc)
		{
			output = argv[++i];
		} else if (strncmp(currArg, PARTITION_ARGUMENT, array_countof(PARTITION_ARGUMENT) - 1) == 0)
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
		} else if (strncmp(currArg, INFO_ARGUMENT, array_countof(INFO_ARGUMENT) - 1) == 0)
		{
			info = TRUE;
		} else if (strncmp(currArg, BYPASS_MD5SUM_FLAG, array_countof(BYPASS_MD5SUM_FLAG) - 1) == 0)
		{
			BYPASS_MD5SUM = TRUE;
		} else if (strncmp(currArg, DEBUG_MODE_FLAG, array_countof(DEBUG_MODE_FLAG) - 1) == 0)
		{
			DEBUG_MODE = TRUE;
		} else if (strncmp(currArg, FORCE_FLAG, array_countof(FORCE_FLAG) - 1) == 0)
		{
			FORCE = TRUE;
		} else {
			printf("Argument (%s) is not allowed.\n\n", currArg);
			PrintUsage();
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
				throwException(ERR_INIT_GUI, "Fatal Error: GUI MFC initialization failed");
			}
		} else {
			throwException(ERR_INIT_GUI, "Fatal Error: GetModuleHandle failed");
		}

		MainDialog dlg(input, output);
		dlg.DoModal();
		exit(EXIT_SUCCESS);
	}
	#endif

	if (LIST && !gui)
	{
		printf("%s", ListPhysicalDrives().c_str());
		exit(EXIT_SUCCESS);
	}

	if (NULL == input || (NULL == output && !info))
	{
		PrintUsage();
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
			printf("Could not open input physical drive. Make sure to run this program as an administrator.\n");
		} else {
			printf("Error while opening input file : %s \n", input);
		}
		throwException(ERR_INVALID_INPUT);
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
			printf("NAND type : %s%s%s\n", curNxdata->GetNxStorageTypeAsString(), 
				NULL != curNxdata->partitionName ? " " : "", curNxdata->partitionName);
			if (curNxdata->type == BOOT0) printf("AutoRCM   : %s\n", curNxdata->autoRcm ? "ENABLED" : "DISABLED");
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
			if (curNxdata->type == RAWNAND) printf("Backup GPT: %s\n", curNxdata->backupGPTfound ? "FOUND" : "MISSING !!!");
			// If there's nothing left to do, exit (we don't want to pursue with i/o operations)
			if (i == io_num)
			{
				exit(EXIT_SUCCESS);
			}
		}
		exit(EXIT_SUCCESS);
	}

	// COPY TO OUTPUT
	if (NULL != output)
	{


		// COPY TO FILE
		if (!nxdataOut.isDrive)
		{
			if (NULL != partition && !nxdata.IsValidPartition(partition) && nxdata.type != PARTITION)
			{
				if (!FORCE)
				{
					if (!AskYesNoQuestion("Unable to detect partition from input. Continue anyway (dump all partitions) ?"))
					{
						throwException("Operation canceled\n");
					}
				} else {
					throwException(ERR_INVALID_PART, "No partition detected for input, you can't continue in force mode for security reason.");
				}
			}
			if (nxdataOut.size > 0 && !FORCE)
			{
				// Output file already exists					
				if (!AskYesNoQuestion("Output file already exists. Do you want to overwrite it ?"))
				{
					throwException("Operation cancelled.\n");
				}
			}
		}

		// RESTORE TO PHYSICAL DRIVE
		if (nxdataOut.isDrive)
		{
			// Restoring to physical drive, BYPASS_MD5SUM set to TRUE (default)
			BYPASS_MD5SUM = TRUE;

			// Output must RAWNAND type
			if (nxdataOut.type != RAWNAND)
			{
				printf("Output (physical drive) unidentified (type = %s)\n", nxdataOut.GetNxStorageTypeAsString());
				throwException(ERR_INVALID_OUTPUT);
			}			

			// If input type is PARTITION & -part not specified, look for a match in output GPT
			if (nxdata.type == PARTITION && NULL == partition)
			{
				if (!nxdataOut.IsValidPartition(nxdata.partitionName, nxdata.size))
				{
					printf("Input partition (%s, %I64d bytes) not found in output stream (or size does not match)\n", nxdata.partitionName, nxdata.size);
					throwException(ERR_IO_MISMATCH);
				} else {
					// -part arg set as input file partition
					partition = nxdata.partitionName;
				}
			}
			printf("\nYOU ARE ABOUT TO COPY DATA TO A PHYSICAL DRIVE\n"
				"            BE VERY CAUTIOUS !!!\n\n");
			// If partition argument is specified
			if (NULL != partition)
			{
				u64 part_size = -1;
				// Partition MUST exists in input stream (if RAWNAND)
				if (nxdata.type == RAWNAND)
				{					
					part_size = nxdata.IsValidPartition(partition);
					if (part_size<0)
					{
						throwException(ERR_INVALID_PART, "Partition not found in input stream (-i)");
					}
				}
				// Input partition -part arg (if PARTITION)
				if (nxdata.type == PARTITION)
				{
					if (strncmp(partition, nxdata.partitionName, strlen(nxdata.partitionName)) != 0)
					{
						printf("Input partition file (%s) mismatch -part argument (%s)\n", nxdata.partitionName, partition);
						throwException(ERR_INVALID_PART);
					}
				}
				// Partition must exists on output drive & size must match input size 
				if (!nxdataOut.IsValidPartition(partition, part_size ? part_size : nxdata.size))
				{
					printf("Input partition (%s, %I64d bytes) not found in output stream (or size does not match)\n", partition, nxdata.size);
					throwException(ERR_IO_MISMATCH);
				}
			} else {
				// Partition argument is not specified				
				if (nxdata.type != nxdataOut.type)
				{
					printf("Input data type (%s) doesn't match output data type (%s)\n", nxdata.GetNxStorageTypeAsString(), nxdataOut.GetNxStorageTypeAsString());
					throwException(ERR_IO_MISMATCH, "For security reason, you can't continue");
				}

				if (nxdata.size != nxdataOut.size && NULL == partition)
				{
					printf("Input data size (%I64d bytes) doesn't match output data size (%I64d bytes)\n", nxdata.size, nxdataOut.size);
					if (!FORCE)
					{
						if (!AskYesNoQuestion("Are you REALLY sure you want to continue ?"))
						{
							throwException("Operation cancelled.\n");
						}
					} else {
						throwException(ERR_IO_MISMATCH, "For security reason, you can't continue");
					}
				}				
			}
			if (!FORCE)
			{
				if (!AskYesNoQuestion("Are you REALLY sure you want to continue ?"))
				{
					throwException("Operation cancelled.\n");
				}
			}
		}
	}
	
	// COPY
	if (nxdata.size > 0)
	{
		HANDLE hDisk, hDiskOut;
		u64 bytesToRead = nxdata.size, readAmount = 0, writeAmount = 0;
		BOOL bSuccess;
		int rc;

		// Get handle for input
		if (nxdata.type == PARTITION) 
		{
			rc = nxdata.GetIOHandle(&hDisk, GENERIC_READ, NULL);
		} else {
			rc = nxdata.GetIOHandle(&hDisk, GENERIC_READ, NULL, partition, NULL != partition ? &bytesToRead : NULL);
		}
		if (rc < 0)
		{
			throwException(ERR_INPUT_HANDLE, "Failed to get handle to input file/disk\n");
		}

		// Get handle for output
		rc = nxdataOut.GetIOHandle(&hDiskOut, GENERIC_WRITE, bytesToRead, partition, NULL != partition ? &bytesToRead : NULL);
		if (rc < 0)
		{
			if(rc == ERR_NO_SPACE_LEFT) throwException(ERR_NO_SPACE_LEFT, "Output disk : not enough space !");
			else throwException(ERR_OUTPUT_HANDLE, "Failed to get handle to output file/disk\n");
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
				throwException(ERR_CRYPTO_MD5);
			}

			// Create the hash
			if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
			{
				CloseHandle(hDisk);
				throwException(ERR_CRYPTO_MD5, "CryptCreateHash failed\n");
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
			throwException(ERR_COPY_SIZE);
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
				throwException(ERR_CRYPTO_MD5, "\nFailed to get hash value.");
			}
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);

			if (DEBUG_MODE)
			{
				printf("MD5 sum for INPUT is %s\n", md5hash.c_str());
			}

			// Compute then compare output checksums
			nxdataOut.InitStorage(); // We need to update output obj first (mandatory!)
			if (md5hash == nxdataOut.GetMD5Hash(partition))
			{
				printf("Verified (checksums are IDENTICAL)\n");
			} else {
				throwException(ERR_MD5_COMPARE, "ERROR : checksums are DIFFERENT");
			}
		}

		// Compute elapsed time
		auto end = std::chrono::system_clock::now();
		std::chrono::duration<double> elapsed_seconds = end - start;
		printf("Elapsed time : %s.\n", GetReadableElapsedTime(elapsed_seconds).c_str());
	}
	exit(EXIT_SUCCESS);
}

