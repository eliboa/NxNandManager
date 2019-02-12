#include "NxStorage.h"
#include "NxNandManager.h"

NxStorage::NxStorage(const char* storage)
{
	if (DEBUG_MODE) printf("NxStorage::NxStorage - path = %s\n", storage);
	path = storage;
	pathLPWSTR = convertCharArrayToLPWSTR(storage);
	type = UNKNOWN;
	size = 0;
	isDrive = FALSE;
	pdg = { 0 };
	partCount = 0;
	firstPartion = NULL;

	this->InitStorage();
}

// Initialize and retrieve storage information
void NxStorage::InitStorage()
{
	if (DEBUG_MODE) printf("NxStorage::InitStorage - Initialize\n");
	HANDLE hDevice = INVALID_HANDLE_VALUE;
	BOOL bResult = FALSE;
	DWORD junk = 0;	

	hDevice = CreateFileW(pathLPWSTR,
		0,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);

	if (hDevice != INVALID_HANDLE_VALUE)
	{
		// Get drive geometry
		if (DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pdg, sizeof(pdg), &junk, (LPOVERLAPPED)NULL))
		{
			isDrive = TRUE;
			size = pdg.Cylinders.QuadPart * (ULONG)pdg.TracksPerCylinder * (ULONG)pdg.SectorsPerTrack * (ULONG)pdg.BytesPerSector;
			if (DEBUG_MODE) printf("NxStorage::InitStorage - Drive size is %I64d bytes\n", size);
		}
	}
	CloseHandle(hDevice);

	// Open new handle for read
	HANDLE hStorage;
	hStorage = CreateFileW(pathLPWSTR, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (hStorage == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hStorage);
		type = INVALID;
		if (DEBUG_MODE) printf("NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - %s\n", path);
		return;
	}

	DWORD bytesRead = 0;
	BYTE buff[0x200];
	BYTE sbuff[0x200];
	// Look for for magic offset
	for (int i=0; i < array_countof(mgkOffArr); i++)
	{
		if(DEBUG_MODE)
		{
			printf("Looking for magic \"%s\" at offset %I64d\n", mgkOffArr[i].magic, mgkOffArr[i].offset);
		}
		u64 ptrReadOffset = (int)(mgkOffArr[i].offset / NX_EMMC_BLOCKSIZE) * NX_EMMC_BLOCKSIZE;
		u64 ptrInBuffOffset = mgkOffArr[i].offset % NX_EMMC_BLOCKSIZE;
		DWORD dwPtr = SetFilePointer(hStorage, ptrReadOffset, NULL, FILE_BEGIN);
		if (dwPtr != INVALID_SET_FILE_POINTER)
		{				
			ReadFile(hStorage, buff, 0x200, &bytesRead, NULL);
			memcpy(sbuff, &buff[ptrInBuffOffset], mgkOffArr[i].size);	
			if (0 != bytesRead && (hexStr(sbuff, mgkOffArr[i].size) == mgkOffArr[i].magic))
			{					
				type = mgkOffArr[i].type;
				if(DEBUG_MODE) printf("magic offset found ! Type = %s, firmware = %.2f\n", GetNxStorageTypeAsString(), mgkOffArr[i].fw);
				break;			
			}
		}
	}	

	// Read & parse GPT
	if (type == RAWNAND)
	{
		DWORD dwPtr = SetFilePointer(hStorage, 0x200, NULL, FILE_BEGIN);
		if (dwPtr != INVALID_SET_FILE_POINTER)
		{
			BYTE buffGpt[0x4200];
			ReadFile(hStorage, buffGpt, 0x4200, &bytesRead, NULL);
			if (0 != bytesRead)
			{
				type = RAWNAND;
				this->ParseGpt(buffGpt);
			}
		}
	}

	// Get size
	LARGE_INTEGER Lsize;
	if (!isDrive)
	{
		if (!GetFileSizeEx(hStorage, &Lsize))
		{
			printf("NxStorage::InitStorage GetFileSizeEx failed.\n");
		} else {
			size = Lsize.QuadPart;
			if (DEBUG_MODE) printf("NxStorage::InitStorage - File size = %I64d bytes\n", size);
		}
	}
	CloseHandle(hStorage);
}

// Parse GUID Partition Table
BOOL NxStorage::ParseGpt(unsigned char* gptHeader)
{
	GptHeader *hdr = (GptHeader *)gptHeader;
	// Iterate partitions backwards (from GPT header) 
	for (int i = hdr->num_part_ents - 1; i >= 0; --i)
	{
		// Get GPT entry
		GptEntry *ent = (GptEntry *)(gptHeader + (hdr->part_ent_lba - 1) * NX_EMMC_BLOCKSIZE + i * sizeof(GptEntry));

		// Set new partition
		partCount++;
		GptPartition *part = (GptPartition *)malloc(sizeof(GptPartition));
		part->lba_start = ent->lba_start;
		part->lba_end = ent->lba_end;
		part->attrs = ent->attrs;
		char name[37];
		for (u32 i = 0; i < 36; i++)
		{
			part->name[i] = ent->name[i];
		}
		part->name[36] = '0';

		// Add partition to linked list
		part->next = firstPartion;
		firstPartion = part;

		if (DEBUG_MODE) printf("NxStorage::ParseGpt - Partition %s found\n", part->name);
	}

	return hdr->num_part_ents > 0 ? TRUE : FALSE;
}

// Get handle to drive/file for read/write operation
// & set pointers to a specific partition if specified
int NxStorage::GetIOHandle(HANDLE* hHandle, DWORD dwDesiredAccess, const char* partition, u64 *bytesToRead)
{
	if (dwDesiredAccess == GENERIC_READ)
	{
		// Get handle for reading
		*hHandle = CreateFileW(pathLPWSTR, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	} else {
		// Get handle for writing
		*hHandle = CreateFileW(pathLPWSTR, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			isDrive ? OPEN_EXISTING : CREATE_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	}

	if (*hHandle == INVALID_HANDLE_VALUE)
	{
		if (DEBUG_MODE) printf("NxStorage::GetIOHandle - Failed to get handle for read/write to %s\n", path);
		return -3;
	}

	if (NULL != partition && NULL != bytesToRead && type == RAWNAND)
	{
		// Iterate GPT entry
		GptPartition *cur = firstPartion;
		while (NULL != cur)
		{
			// If partition exists in i/o stream
			if (strncmp(cur->name, partition, strlen(partition)) == 0)
			{
				// Try to set pointers
				if (SetFilePointer(*hHandle, cur->lba_start * NX_EMMC_BLOCKSIZE, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
				{
					*bytesToRead = (cur->lba_end - cur->lba_start + 1) * NX_EMMC_BLOCKSIZE;
					return 0;
				} else {
					if (DEBUG_MODE) printf("NxStorage::GetIOHandle - Failed to set pointer to specific partition %s\n", partition);
					return -2;
				}
				break;
			}
			cur = cur->next;
		}
		return -1;
	}
	return 0;
}

// Dump raw data from hHandleIn to hHandleOut.  This function must be called recursively until it returns FALSE;
BOOL NxStorage::dumpStorage(HANDLE* hHandleIn, HANDLE* hHandleOut, u64* readAmount, u64* writeAmount, u64 bytesToWrite, HCRYPTHASH* hHash)
{
	BYTE buffer[DEFAULT_BUFF_SIZE], wbuffer[DEFAULT_BUFF_SIZE];
	u64 buffSize = DEFAULT_BUFF_SIZE;
	DWORD bytesRead = 0, bytesWritten = 0, bytesWrite = 0;

	if (NULL != bytesToWrite && *writeAmount >= bytesToWrite)
	{
		return FALSE;
	}

	// Read buffer
	if (!ReadFile(*hHandleIn, buffer, buffSize, &bytesRead, NULL))
	{
		return FALSE;
	}
	if (0 == bytesRead)
	{
		return FALSE;
	}
	*readAmount += (DWORD) bytesRead;

	if (NULL != bytesToWrite && *readAmount > bytesToWrite)
	{
		// Adjust write buffer
		memcpy(wbuffer, &buffer[0], buffSize - (*readAmount - bytesToWrite));
		bytesWrite = buffSize - (*readAmount - bytesToWrite);
		if (bytesWrite == 0)
		{
			return FALSE;
		}
	} else {
		// Copy read to write buffer
		memcpy(wbuffer, &buffer[0], buffSize);
		bytesWrite = buffSize;
	}

	if (NULL != hHash)
	{
		CryptHashData(*hHash, wbuffer, bytesWrite, 0);
	}

	if(!WriteFile(*hHandleOut, wbuffer, bytesWrite, &bytesWritten, NULL))
	{
		printf("Error during write operation : %s \n", GetLastErrorAsString().c_str());
		return FALSE;
	} else {
		*writeAmount += (DWORD) bytesWritten;
	}
	return TRUE;
}

std::string NxStorage::GetMD5Hash()
{
	if(DEBUG_MODE) printf("GetMD5Hash begin for %s\n", path);
	std::string md5hash;

	// Get handle to the file or I/O device
	HANDLE hDisk;
	if(GetIOHandle(&hDisk, GENERIC_READ) < 0)
	{
		printf("Could not open %s\n", path);
		CloseHandle(hDisk);
		return "";
	} 

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

	if(DEBUG_MODE) printf("GetMD5Hash, CryptoHash created\n");
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
		printf("Computing MD5 checksum... (%d%%) \r", (int)(readAmount * 100 / size));
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
	return "";
}

const char* NxStorage::GetNxStorageTypeAsString()
{
	switch (type)
	{
	case BOOT0:
		return "BOOT0";
		break;
	case BOOT1:
		return "BOOT1";
		break;
	case RAWNAND:
		return "RAWNAND";
		break;
	case INVALID:
		return "INVALID";
		break;
	default:
		return "UNKNOWN";
		break;
	}
}