#include "NxStorage.h"

NxStorage::NxStorage(const char* storage, KeySet *p_biskeys)
{
	DEBUG_MODE = false;
	if (DEBUG_MODE) printf("NxStorage::NxStorage - path = %s\n", storage);
	path = storage;
	pathLPWSTR = NULL;
	type = UNKNOWN;
	size = 0, fileDiskTotalBytes = 0, fileDiskFreeBytes = 0;
	isDrive = false, backupGPTfound = false, autoRcm = false, crypto = false, isEncrypted = false;
	pdg = { 0 };
	partCount = 0;
	firstPartion = NULL;
	lastSplitFile = NULL;
	partitionName[0] = '\0';
	handle.h = NULL;
	handle_out = NULL;
	exFat_driver = false;
	fw_detected = false;
	this->InitKeySet(p_biskeys);
	if (NULL != storage)
	{
		pathLPWSTR = convertCharArrayToLPWSTR(storage);
		this->InitStorage();
	}

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

	// Get available free space
	if (!isDrive)
	{
		if (NULL == path) return;
		std::string path_str = std::string(path);
		std::size_t pos = path_str.find(base_name(path_str));
		std::string dir = path_str.substr(0, pos);
		if (dir.length() == 0)
		{
			dir = ExePath();
		}
		DWORD dwSectPerClust, dwBytesPerSect, dwFreeClusters, dwTotalClusters;
		LPWSTR wpath = convertCharArrayToLPWSTR(dir.c_str());

		BOOL fResult = GetDiskFreeSpace(wpath, &dwSectPerClust, &dwBytesPerSect, &dwFreeClusters, &dwTotalClusters);
		if (fResult)
		{
			fileDiskTotalBytes = (u64)dwTotalClusters * dwSectPerClust * dwBytesPerSect;
			fileDiskFreeBytes = (u64)dwFreeClusters * dwSectPerClust * dwBytesPerSect;

			if (DEBUG_MODE)
			{
				wprintf(L"Free space  = %I64d GB\n", fileDiskFreeBytes / (1024 * 1024 * 1024));
				wprintf(L"Total space = %I64d GB\n", fileDiskTotalBytes / (1024 * 1024 * 1024));
			}
		}
	}

	// Open new handle for read
	HANDLE hStorage;
	hStorage = CreateFileW(pathLPWSTR, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (hStorage == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hStorage);
		type = INVALID;
		if (DEBUG_MODE) printf("NxStorage::InitStorage - No such file or drive (INVALID_HANDLE) - %s\n", path);
	}


	// Get size
	LARGE_INTEGER Lsize;
	if (!isDrive)
	{
		if (!GetFileSizeEx(hStorage, &Lsize))
		{
			if (DEBUG_MODE) printf("NxStorage::InitStorage GetFileSizeEx failed.\n");
		} else {
			size = Lsize.QuadPart;
			if (DEBUG_MODE) printf("NxStorage::InitStorage - File size = %I64d bytes\n", size);
		}
	}

	if (type == INVALID) return;

	DWORD bytesRead = 0;
	BYTE buff[0x200];
	BYTE sbuff[0x200];
	// Look for for magic offset
	for (int i=0; i < (int)array_countof(mgkOffArr); i++)
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

	// Try to identify partition files (comparing file name & file size)
	// -> this is pretty shitty but we'll just stick with this for now)
	if (type == UNKNOWN)
	{
		for (int i = 0; i < (int)array_countof(partInfoArr); i++)
		{
			std::string basename = base_name(std::string(path));
			basename = remove_extension(basename);
			if (strncmp(partInfoArr[i].name, basename.c_str(), strlen(basename.c_str())) == 0 && partInfoArr[i].size == size)
			{
				strcpy_s(partitionName, partInfoArr[i].name);
				type = PARTITION;
				break;
			}
		}
	}

	// Find decrypted partition
	if(type == PARTITION)
	{
		if (strcmp(partitionName, "PRODINFO") == 0 || strcmp(partitionName, "PRODINFOF") == 0 || 
			strcmp(partitionName, "SAFE") == 0 || strcmp(partitionName, "SYSTEM") == 0 || strcmp(partitionName, "USER") == 0)
		{
			isEncrypted = TRUE; // Default value

			// Check for decrypted content
			unsigned char buf[DEFAULT_BUFF_SIZE];				
			SetFilePointer(hStorage, 0, NULL, FILE_BEGIN);
			ReadFile(hStorage, buf, DEFAULT_BUFF_SIZE, &bytesRead, NULL);
			if (0 != bytesRead && ValidateDecryptBuf(buf, partitionName))
				isEncrypted = FALSE;
		}
	}


	// Detect autoRCM
	if (type == BOOT0)
	{
		DWORD dwPtr = SetFilePointer(hStorage, 0x200, NULL, FILE_BEGIN);
		if (dwPtr != INVALID_SET_FILE_POINTER)
		{
			ReadFile(hStorage, buff, 0x200, &bytesRead, NULL);
			if (0 != bytesRead)
			{
				if(buff[0x10] != 0xF7) autoRcm = TRUE;
				else autoRcm = FALSE;
			}
		}
	}

	// RAWNAND Init
	if (type == RAWNAND)
	{
		// Read & parse GPT
		isEncrypted = TRUE; // Default value
		DWORD dwPtr = SetFilePointer(hStorage, 0x200, NULL, FILE_BEGIN);
		if (dwPtr != INVALID_SET_FILE_POINTER)
		{
			BYTE buffGpt[0x4200];
			ReadFile(hStorage, buffGpt, 0x4200, &bytesRead, NULL);
			if (0 != bytesRead)
			{
				type = UNKNOWN; // Reset type, we'll look for real Nx partitions when parsing GPT
				this->ParseGpt(buffGpt);
			}
		}

		// Look for backup GPT
		LARGE_INTEGER liDistanceToMove;
		liDistanceToMove.QuadPart = size - NX_EMMC_BLOCKSIZE;
		DWORD dwPtr2 = SetFilePointerEx(hStorage, liDistanceToMove, NULL, FILE_BEGIN);
		if (dwPtr2 != INVALID_SET_FILE_POINTER)
		{
			BYTE buffGpt[NX_EMMC_BLOCKSIZE];
			ReadFile(hStorage, buffGpt, NX_EMMC_BLOCKSIZE, &bytesRead, NULL);
			if (0 != bytesRead)
			{
				GptHeader *hdr = (GptHeader *)buffGpt;
				if (hdr->num_part_ents > 0)
				{
					backupGPTfound = TRUE;
				}
			}
		}

		
		if (crypto)
		{
			// Look for firmware version
			fat32_read("SYSTEM");
			// Look for serial number
			prodinfo_read();
		}
	}

	if (type == PARTITION && std::string(partitionName).substr(0, 6).compare("SYSTEM") == 0 &&(crypto || !isEncrypted))
		fat32_read();

	if (type == PARTITION && std::string(partitionName).substr(0, 8).compare("PRODINFO") == 0 && strlen(partitionName) == 8 &&(crypto || !isEncrypted))
		prodinfo_read();	

	// Look for splitted dump
	if (type == RAWNAND && !backupGPTfound && !isDrive) {

		// Overwrite object type
		type = UNKNOWN;

		// Explode file path as wide strings
		wstring Lfilename(this->pathLPWSTR);
		wstring extension(get_extension(Lfilename));
		wstring basename(remove_extension(Lfilename));

		// Look for an integer in path extension
		int f_number, f_digits, f_type = 0;
		if(wcslen(extension.c_str()) > 1)
		{
			wstring number = extension.substr(1, wcslen(extension.c_str()));
			if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
			{
				// If extension is integer
				f_number = std::stoi(number);
				f_digits = wcslen(number.c_str());
				if(f_digits <= 2) f_type = 1;
			}
		}
		// Look for an integer in base name (2 digits max)
		if(f_type == 0)
		{
			wstring number = basename.substr(wcslen(basename.c_str()) - 2, wcslen(basename.c_str()));
			if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
			{
				f_number = std::stoi(number);
				f_digits = 2;
				f_type = 2;
			} else {
				number = basename.substr(wcslen(basename.c_str()) - 1, wcslen(basename.c_str()));
				if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
				{
					f_number = std::stoi(number);
					f_digits = 1;
					f_type = 2;
				}
			}
		}

		// Integer found in path
		if(f_type > 0)
		{
			int i = f_number;
			splitFileCount = 0;
			LARGE_INTEGER Lsize;
			HANDLE hFile;
			u64 s_size = 0;
			wstring path = Lfilename;
			string mask("%0" + to_string(f_digits) + "d");

			// For each splitted file
			do {
				hFile = CreateFileW(&path[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
				if (!GetFileSizeEx(hFile, &Lsize))
					break;

				++splitFileCount;

				// New NxSplitFile
				NxSplitFile *splitfile = reinterpret_cast<NxSplitFile *>(malloc(sizeof(NxSplitFile)));
				wcscpy(splitfile->file_path, path.c_str());
				splitfile->offset = s_size;
				splitfile->size = static_cast<u64>(Lsize.QuadPart);
				splitfile->next = lastSplitFile;
				lastSplitFile = splitfile;

				s_size += splitfile->size;

				// Format path to next file
				char new_number[10];
				sprintf_s(new_number, 10, mask.c_str(), ++i);
				wstring wn_number = convertCharArrayToLPWSTR(new_number);
				if(f_type == 1)
					path = basename + L"." + wn_number;
				else
					path = basename.substr(0, wcslen(basename.c_str()) - f_digits) + wn_number + extension;
			} while (is_file_exist(path.c_str()));

			// If more than one file found & total size = GPT raw size
			if (splitFileCount > 1)
			{
				isSplitted = TRUE;
				size = s_size;
				if(raw_size == s_size)
				{
					// Look for backup GPT in last split file (mandatory for splitted dump)
					LARGE_INTEGER liDistanceToMove;
					liDistanceToMove.QuadPart = lastSplitFile->size - NX_EMMC_BLOCKSIZE;
					DWORD dwPtr = SetFilePointerEx(hFile, liDistanceToMove, NULL, FILE_BEGIN);
					if (dwPtr != INVALID_SET_FILE_POINTER)
					{
						BYTE buffGpt[NX_EMMC_BLOCKSIZE];
						ReadFile(hFile, buffGpt, NX_EMMC_BLOCKSIZE, &bytesRead, NULL);
						if (0 != bytesRead)
						{
							GptHeader *hdr = (GptHeader *)buffGpt;
							if (hdr->num_part_ents > 0)
							{
								backupGPTfound = TRUE;
								type = RAWNAND;
							}
						}
					}
				}
			}
		}
	}

	CloseHandle(hStorage);
}

void::NxStorage::InitKeySet(KeySet *p_biskeys)
{
	if(NULL == p_biskeys)
	{
		biskeys = NULL;
		crypto = false;
		return;
	}
	biskeys = p_biskeys;
	crypto = true;
	return;
}

// Parse GUID Partition Table
BOOL NxStorage::ParseGpt(unsigned char* gptHeader)
{
	GptHeader *hdr = (GptHeader *)gptHeader;

	// Check for valid GPT
	std::string s(reinterpret_cast<const char *>(gptHeader));
	if (s.find("EFI PART") == std::string::npos)
	{
		type = UNKNOWN;
		return FALSE;
	}

	// Get raw disk size
	if(hdr->alt_lba > 0)
	{
		raw_size = (hdr->alt_lba + 1) * NX_EMMC_BLOCKSIZE;
		// Overload disk size with size defined in primary GPT
		if(raw_size > size && isDrive)
			size = (hdr->alt_lba + 1) * NX_EMMC_BLOCKSIZE;
	}

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
		for (u32 i = 0; i < 36; i++)
		{
			part->name[i] = ent->name[i];
		}
		part->name[36] = '0';

		// GPT contains NX NAND partition
		if (strcmp(part->name, "PRODINFO") == 0)
		{
			type = RAWNAND;
		}
		// Add partition to linked list
		part->next = firstPartion;
		firstPartion = part;

		if (DEBUG_MODE) printf("NxStorage::ParseGpt - %s found\n", part->name);
	}

	return hdr->num_part_ents > 0 ? TRUE : FALSE;
}

BOOL NxStorage::GetSplitFile(NxSplitFile* pFile, const char* partition)
{
	if (type != RAWNAND || !isSplitted || NULL == firstPartion) return NULL;

	GptPartition *part = firstPartion;
	while (NULL != part)
	{
		if (strncmp(part->name, partition, strlen(partition)) == 0)
		{
			u64 seek_off = (u64)part->lba_start * NX_EMMC_BLOCKSIZE;
			NxSplitFile *file = lastSplitFile;
			while (NULL != file)
			{
				if (seek_off >= file->offset && seek_off < file->offset + file->size)
				{
					*pFile = *file;
					return TRUE;
				}
				file = file->next;
			}
		}
		part = part->next;
	}
	return FALSE;
}

BOOL NxStorage::GetSplitFile(NxSplitFile* pFile, u64 offset)
{
	if (type != RAWNAND || !isSplitted) return NULL;
	NxSplitFile *file = lastSplitFile;
	while (NULL != file)
	{
		if (offset >= file->offset && offset < file->offset + file->size)
		{
			*pFile = *file;
			return TRUE;
		}
		file = file->next;
	}
	return FALSE;
}

void NxStorage::ClearHandles()
{
	CloseHandle(handle.h);
	CloseHandle(handle_out);
	//handle.path.empty();
	handle.off_end = 0;
	handle.off_start = 0;
	handle.readAmount = 0;
	handle.off_max = 0;
	bytesToRead = 0;
}

int NxStorage::RestoreFromStorage(NxStorage *in, const char* partition, u64* readAmount, u64* writeAmount, u64* bytesToWrite)
{
	// First iteration
	if (handle.readAmount == 0)
	{
		u64 out_off_start = 0;
		*bytesToWrite = size;
		// Restore to splitted dump not supported yet
		if (isSplitted)
			return ERR_RESTORE_TO_SPLIT;


		// Set crypto if restoring decrypted partition file to RAWNAND
		encrypt = false;
		if(type == RAWNAND && NULL != partition && in->type == PARTITION && !in->isEncrypted)
		{
			// Restoring from decrypted file and keyset missing
			if(!in->crypto && (	strcmp(partition, "PRODINFO") == 0  || 
				strcmp(partition, "PRODINFOF") == 0 || strcmp(partition, "SAFE") == 0 || 
				strcmp(partition, "USER") == 0 		|| strcmp(partition, "SYSTEM") == 0))
				return ERR_RESTORE_CRYPTO_MISSING;
			
			else
			{
				encrypt = true;
                if(setCrypto(in->partitionName) > 0)
                    p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), DEFAULT_BUFF_SIZE);
                else
                    return ERR_CRYPTO_KEY_MISSING;
			}
		}	

		// Default path is input object path
		wcscpy(handle.path, in->pathLPWSTR);
		// If partition specified
		if (NULL != partition && strlen(partition) > 0)
		{
			// Iterate GPT entry for output
			GptPartition *part = firstPartion;
			while (NULL != part)
			{
				if (strncmp(part->name, partition, strlen(partition)) == 0)
				{
					out_off_start = (u64)part->lba_start * NX_EMMC_BLOCKSIZE;
					*bytesToWrite = ((u64)part->lba_end - (u64)part->lba_start + 1) * (int)NX_EMMC_BLOCKSIZE;
					break;
				}
				part = part->next;
			}

			// No partition found
			if(out_off_start <= 0)
				return ERR_INVALID_PART;

			bytesToRead = in->size;
			if(in->type == RAWNAND)
			{
				// Iterate GPT entry for input
				GptPartition *part = in->firstPartion;
				while (NULL != part)
				{
					if (strncmp(part->name, partition, strlen(partition)) == 0)
					{
						handle.off_start = (u64)part->lba_start * NX_EMMC_BLOCKSIZE;
						handle.off_end = (u64)part->lba_end * NX_EMMC_BLOCKSIZE;
						handle.off_max = handle.off_end;
						bytesToRead = ((u64)part->lba_end - (u64)part->lba_start + 1) * (int)NX_EMMC_BLOCKSIZE;
						break;
					}
					part = part->next;
				}

				// No partition found
				if(handle.off_end <= 0)
					return ERR_INVALID_PART;

				//Overwrite some values for splitted dump
				if (in->isSplitted)
				{
					NxSplitFile splitFile;
					if (!in->GetSplitFile(&splitFile, partition))
						return ERR_INVALID_PART;
					wcscpy(handle.path, splitFile.file_path);
					handle.off_max = handle.off_start + (splitFile.size - handle.off_start);
				}
			}
		}
		// No partition specified
		else
		{
			handle.off_start = 0;
			handle.off_end = in->size;
			handle.off_max = in->size;
			if (in->isSplitted) {
				NxSplitFile *file = in->lastSplitFile, *first;
				while (NULL != file)
				{
					first = file;
					file = file->next;
				}
				handle.off_max = first->offset + first->size;
			}
			bytesToRead = in->size;
		}

		if(*bytesToWrite == 0)
			return ERR_INVALID_OUTPUT;

		if(bytesToRead == 0)
			return ERR_INVALID_INPUT;

		if(*bytesToWrite != bytesToRead)
			return ERR_IO_MISMATCH;

		// Get handle for output
		handle_out = CreateFileW(pathLPWSTR, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (handle_out == INVALID_HANDLE_VALUE)
			return ERR_OUTPUT_HANDLE;

		// Set pointer if needed
		if(out_off_start > 0)
		{
			LARGE_INTEGER liDistanceToMove;
			liDistanceToMove.QuadPart = out_off_start;
			if (SetFilePointerEx(handle_out, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
				return ERR_OUTPUT_HANDLE;
		}

		// Get handle for input
		handle.h = CreateFileW(&handle.path[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (handle.h == INVALID_HANDLE_VALUE)
			return ERR_INPUT_HANDLE;

		// Set pointer if needed
		if (handle.off_start > 0)
		{
			LARGE_INTEGER liDistanceToMove;
			liDistanceToMove.QuadPart = handle.off_start;
			if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
				return ERR_INPUT_HANDLE;
		}
	}
	// Switch to next splitted file
	else if(in->isSplitted && handle.off_start + handle.readAmount >= handle.off_max && *writeAmount < *bytesToWrite)
	{
		NxSplitFile splitFile;
		if (!in->GetSplitFile(&splitFile, handle.off_start + handle.readAmount))
			return ERR_INPUT_HANDLE;
		wcscpy(handle.path, splitFile.file_path);
		handle.off_max += splitFile.size;

		CloseHandle(handle.h);
		// Get handle for input
		handle.h = CreateFileW(&handle.path[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (handle.h == INVALID_HANDLE_VALUE)
			return ERR_INPUT_HANDLE;
	}

	if (*writeAmount >= *bytesToWrite)
		return NO_MORE_BYTES_TO_COPY;


	// Read
	BYTE *buffer = new BYTE[DEFAULT_BUFF_SIZE];
	DWORD bytesRead = 0, bytesWrite = 0, bytesWritten = 0;
	if (!ReadFile(handle.h, buffer, DEFAULT_BUFF_SIZE, &bytesRead, NULL))
	{
		delete[] buffer;
		return ERR_WHILE_COPY;
	}

	if (bytesRead == 0)
		return NO_MORE_BYTES_TO_COPY;

	*readAmount += bytesRead;
	handle.readAmount += bytesRead;


	// Encrypt data
	if(encrypt)
	{
		u64 block_num = handle.readAmount / DEFAULT_BUFF_SIZE - 1;
		p_crypto->encrypt(buffer, block_num);
	}

	// Write
	BYTE *wbuffer = new BYTE[DEFAULT_BUFF_SIZE];
	if (*readAmount > *bytesToWrite)
	{
		// Adjust write buffer
		memcpy(wbuffer, &buffer[0], DEFAULT_BUFF_SIZE - (*readAmount - *bytesToWrite));
		bytesWrite = DEFAULT_BUFF_SIZE - (*readAmount - *bytesToWrite);
		if (bytesWrite == 0)
		{
			delete[] buffer;
			delete[] wbuffer;
			return ERR_WHILE_COPY;
		}
	} else {
		// Copy read to write buffer
		memcpy(wbuffer, &buffer[0], DEFAULT_BUFF_SIZE);
		bytesWrite = bytesRead;
	}

	if (!WriteFile(handle_out, wbuffer, bytesWrite, &bytesWritten, NULL))
	{
		delete[] buffer;
		delete[] wbuffer;
		return ERR_WHILE_COPY;
	}

	*writeAmount += (DWORD)bytesWritten;

    /*
	if (*writeAmount >= *bytesToWrite)
		delete p_crypto;
    */

	delete[] buffer;
	delete[] wbuffer;

	return 1;
}

int NxStorage::DumpToStorage(NxStorage *out, const char* partition, u64* readAmount, u64* writeAmount, u64* bytesToWrite, HCRYPTHASH* hHash)
{	
	// First iteration
	if (handle.readAmount == 0)
	{
		// Default input is self object path
		wcscpy(handle.path, pathLPWSTR);
		//handle.path = this->pathLPWSTR;

		// Init crypto
		if ((NULL != partition && strlen(partition) > 0 || type == PARTITION) && (isEncrypted || out->crypto) && crypto)
		{
            if(setCrypto(type == PARTITION ? partitionName : partition) > 0)
                p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), DEFAULT_BUFF_SIZE);
            else
                return ERR_CRYPTO_KEY_MISSING;
			//printf("NxStorage::DumpToStorage - new xts_crypto() \n");
		}	
 
		// If partition specified
		if (NULL != partition && strlen(partition) > 0)
		{
			// Iterate GPT entry
			GptPartition *part = firstPartion;
			while (NULL != part)
			{
				if (strncmp(part->name, partition, strlen(partition)) == 0)
				{
					handle.off_start = (u64)part->lba_start * NX_EMMC_BLOCKSIZE;
					handle.off_end = (u64)part->lba_end * NX_EMMC_BLOCKSIZE;
					handle.off_max = handle.off_end;
					bytesToRead = ((u64)part->lba_end - (u64)part->lba_start + 1) * (int)NX_EMMC_BLOCKSIZE;
					break;
				}
				part = part->next;
			}

			// No partition found
			if(handle.off_end <= 0) return ERR_INVALID_PART;

			//Overwrite some values for splitted dump
			if (isSplitted)
			{
				NxSplitFile splitFile;
				if (!GetSplitFile(&splitFile, partition)) return ERR_INVALID_PART;
				//handle.path = splitFile.file_path;
				wcscpy(handle.path, splitFile.file_path);
				handle.off_max = handle.off_start + (splitFile.size - handle.off_start);
			}
		}
		// No partition specified
		else
		{
			handle.off_start = 0;
			handle.off_end = this->size;
			handle.off_max = this->size;
			if (isSplitted) {
				NxSplitFile *file = lastSplitFile, *first;
				while (NULL != file)
				{
					first = file;
					file = file->next;
				}
				handle.off_max = first->offset + first->size;
			}
			bytesToRead = this->size;
		}

		// Check available space for output disk
		if (!out->isDrive && out->fileDiskFreeBytes > 0 && bytesToRead - out->size > out->fileDiskFreeBytes)
		{
			return ERR_NO_SPACE_LEFT;
		}

		// Get handle for input
		handle.h = CreateFileW(&handle.path[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (handle.h == INVALID_HANDLE_VALUE)
			return ERR_INPUT_HANDLE;

		// Set pointer if needed
		if (handle.off_start > 0)
		{
			LARGE_INTEGER liDistanceToMove;
			liDistanceToMove.QuadPart = handle.off_start;
			if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
				return ERR_INPUT_HANDLE;
		}

		// Get handle for output
		handle_out = CreateFileW(out->pathLPWSTR, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (handle_out == INVALID_HANDLE_VALUE)
			return ERR_OUTPUT_HANDLE;
	}

	// Switch to next splitted file
	else if(isSplitted && handle.off_start + handle.readAmount >= handle.off_max && *writeAmount < *bytesToWrite)
	{
		NxSplitFile splitFile;
		if (!GetSplitFile(&splitFile, handle.off_start + handle.readAmount))
			return ERR_INPUT_HANDLE;
		//handle.path = splitFile.file_path;
		wcscpy(handle.path, splitFile.file_path);
		handle.off_max += splitFile.size;

		CloseHandle(handle.h);
		// Get handle for input
		handle.h = CreateFileW(&handle.path[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (handle.h == INVALID_HANDLE_VALUE) return ERR_INPUT_HANDLE;
	}

	*bytesToWrite = bytesToRead;

	if (*writeAmount >= *bytesToWrite)
		return NO_MORE_BYTES_TO_COPY;

	// Read
	BYTE *buffer = new BYTE[DEFAULT_BUFF_SIZE];
	DWORD bytesRead = 0, bytesWrite = 0, bytesWritten = 0;
	if (!ReadFile(handle.h, buffer, DEFAULT_BUFF_SIZE, &bytesRead, NULL))
	{
		delete[] buffer;
		return ERR_WHILE_COPY;
	}

	if (bytesRead == 0)
		return NO_MORE_BYTES_TO_COPY;

	*readAmount += bytesRead;
	handle.readAmount += bytesRead;

	// Decrypt
	u64 block_num = handle.readAmount / DEFAULT_BUFF_SIZE - 1;
	if(isEncrypted && crypto)
	{
		p_crypto->decrypt(buffer, block_num);

		// Validate first block
		if(block_num == 0 && !ValidateDecryptBuf(buffer, type == PARTITION ? partitionName : partition))		
			return ERR_DECRYPT_CONTENT;
	}
	// Encrypt
	else if (!isEncrypted && out->crypto)
		p_crypto->encrypt(buffer, block_num);

	// Write
	BYTE *wbuffer = new BYTE[DEFAULT_BUFF_SIZE];
	if (*readAmount > *bytesToWrite)
	{
		// Adjust write buffer
		memcpy(wbuffer, &buffer[0], DEFAULT_BUFF_SIZE - (*readAmount - *bytesToWrite));
		bytesWrite = DEFAULT_BUFF_SIZE - (*readAmount - *bytesToWrite);
		if (bytesWrite == 0)
		{
			delete[] buffer;
			delete[] wbuffer;
			return ERR_WHILE_COPY;
		}
	} else {
		// Copy read to write buffer
		memcpy(wbuffer, &buffer[0], DEFAULT_BUFF_SIZE);
		bytesWrite = bytesRead;
	}

	if (NULL != hHash)
	{
		CryptHashData(*hHash, wbuffer, bytesWrite, 0);
	}

	if (!WriteFile(handle_out, wbuffer, bytesWrite, &bytesWritten, NULL))
	{
		delete[] buffer;
		delete[] wbuffer;
		return ERR_WHILE_COPY;
	}

	*writeAmount += (DWORD)bytesWritten;

    /*
    if (*writeAmount >= *bytesToWrite && NULL != p_crypto)
		delete p_crypto;
    */
	delete[] buffer;
	delete[] wbuffer;

	return 1;
}

int NxStorage::GetMD5Hash(HCRYPTHASH *hHash, u64* readAmount)
{

	auto releaseContext = [this]() -> void {
			CryptReleaseContext(this->h_Prov, 0);
			CloseHandle(this->handle_out);
			return;
};


	if (0 == *readAmount)
	{
		bytesToRead = 0;
		bytesAmount = 0;
		if (readAmount != NULL) *readAmount = 0;

		// Get handle to the crypto provider
		if (!CryptAcquireContext(&h_Prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			CryptReleaseContext(h_Prov, 0);
			return ERR_CRYPTO_MD5;
		}

		// Get handle to file
		handle_out = CreateFileW(pathLPWSTR, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
		if (handle_out == INVALID_HANDLE_VALUE)
		{
			return ERR_INPUT_HANDLE;
		}
		// Create new hash
		if (!CryptCreateHash(h_Prov, CALG_MD5, 0, 0, hHash))
		{
			CloseHandle(handle_out);
			return ERR_CRYPTO_MD5;
		}
		bytesToRead = size;
	}

	if (bytesAmount >= bytesToRead)
	{
		CloseHandle(handle_out);
		return NO_MORE_BYTES_TO_COPY;
	}

	BYTE *buffRead = new BYTE[BUFSIZE];
	BYTE rgbHash[MD5LEN];
	BYTE *hbuffer = new BYTE[BUFSIZE];

	DWORD bytesRead = 0, bytesHash = 0;;

	// Read buffer
	if(!ReadFile(handle_out, buffRead, BUFSIZE, &bytesRead, NULL))
	{
		CloseHandle(handle_out);
		delete[] buffRead;
		delete[] hbuffer;
		return ERR_CRYPTO_MD5;
	}

	if (0 == bytesRead)
	{
		CloseHandle(handle_out);
		delete[] buffRead;
		delete[] hbuffer;
		return NO_MORE_BYTES_TO_COPY;
	}

	bytesAmount += bytesRead;
	if(readAmount != NULL) *readAmount += bytesRead;

	if(bytesAmount > bytesToRead)
	{
		// Adjust buffer
		memcpy(hbuffer, &buffRead[0], BUFSIZE - (bytesAmount - bytesToRead));
		bytesHash = BUFSIZE - (bytesAmount - bytesToRead);
		if (bytesHash == 0)
		{
			CloseHandle(handle_out);
			delete[] buffRead;
			delete[] hbuffer;
			return ERR_CRYPTO_MD5;
		}
	} else {
		// Copy buffer
		memcpy(hbuffer, &buffRead[0], BUFSIZE);
		bytesHash = bytesRead;
	}
	// Hash buffer
	if (!CryptHashData(*hHash, hbuffer, bytesHash, 0))
	{
		CloseHandle(handle_out);
		delete[] buffRead;
		delete[] hbuffer;
		return ERR_CRYPTO_MD5;
	}

	delete[] buffRead;
	delete[] hbuffer;

	int percent = (u64)bytesAmount * 100 / (u64)bytesToRead;
	return percent;
}

std::string BuildChecksum(HCRYPTHASH hHash)
{
	std::string md5hash;
	DWORD cbHash = MD5LEN;
	BYTE rgbHash[MD5LEN];
	CHAR rgbDigits[] = "0123456789abcdef";
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
		CryptDestroyHash(hHash);
		return md5hash;
	}
	CryptDestroyHash(hHash);
	return "";
}

std::string NxStorage::GetMD5Hash(const char* partition)
{
	if(DEBUG_MODE) printf("GetMD5Hash begin for %s\n", path);
	std::string md5hash;

	// Get handle to the file or I/O device
	//HANDLE hDisk;
	u64 bytesToRead = size;
	handle_out = CreateFileW(pathLPWSTR, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (handle_out == INVALID_HANDLE_VALUE)
		//if(GetIOHandle(&hDisk, GENERIC_READ, NULL, partition, &bytesToRead) < 0)
	{
		printf("Could not open %s\n", path);
		CloseHandle(handle_out);
		return "";
	}

	//printf("MD5 DEBUG bytesToRead = %I64d \n ", bytesToRead);

	BOOL bSuccess;
	DWORD buffSize = BUFSIZE, bytesRead = 0, cbHash = 0, bytesHash = 0;
	BYTE buffRead[BUFSIZE], rgbHash[MD5LEN], hbuffer[BUFSIZE];
	ULONGLONG readAmount = 0;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	cbHash = MD5LEN;

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		printf("CryptAcquireContext failed");
		CloseHandle(handle_out);
		return NULL;
	}

	// Create new hash
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		printf("CryptCreateHash failed");
		CloseHandle(handle_out);
		return NULL;
	}

	if(DEBUG_MODE) printf("GetMD5Hash, CryptoHash created\n");
	// Read stream
	while (bSuccess = ReadFile(handle_out, buffRead, buffSize, &bytesRead, NULL))
	{

		if (0 == bytesRead)
		{
			break;
		}
		readAmount += (u64) bytesRead;

		if (readAmount > bytesToRead)
		{
			// Adjust write buffer
			memcpy(hbuffer, &buffRead[0], buffSize - (readAmount - bytesToRead));
			bytesHash = buffSize - (readAmount - bytesToRead);
			if (bytesHash == 0)
			{
				return FALSE;
			}
		} else {
			// Copy read to write buffer
			memcpy(hbuffer, &buffRead[0], buffSize);
			bytesHash = bytesRead;
		}
		// Hash every read buffer
		if (!CryptHashData(hHash, hbuffer, bytesHash, 0))
		{
			printf("CryptHashData failed: \n");
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(handle_out);
			return NULL;
		}

		printf("Computing MD5 checksum... (%d%%) \r", (int)(readAmount * 100 / bytesToRead));

		if(readAmount >= bytesToRead) break;
	}
	printf("\n");
	CloseHandle(handle_out);

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
		printf("md5hash = %s\n", md5hash.c_str());
	} else {
		printf("CryptGetHashParam failed\n");
	}
	return "";
}

const char* NxStorage::GetNxStorageTypeAsString()
{
	std::string buffStr;
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
	case PARTITION:
		return "PARTITION";
		break;
	default:
		return "UNKNOWN";
		break;
	}
}

u64 NxStorage::IsValidPartition(const char * part_name, u64 part_size)
{
	// Iterate GPT entry
	GptPartition *cur = firstPartion;
	while (NULL != cur)
	{
		if (strncmp(cur->name, part_name, strlen(part_name)) == 0)
		{
			u64 cur_size = (cur->lba_end - cur->lba_start + 1) * NX_EMMC_BLOCKSIZE;
			if (part_size == NULL) return cur_size;
			else if (cur_size == part_size) return cur_size;
		}
		cur = cur->next;
	}
	return -1;
}

bool NxStorage::setAutoRCM(bool enable)
{
	if (type != BOOT0)
		return false;

	HANDLE hStorage;
	hStorage = CreateFileW(pathLPWSTR, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (hStorage == INVALID_HANDLE_VALUE)
		return false;

	DWORD dwPtr = SetFilePointer(hStorage, 0x200, NULL, FILE_BEGIN);
	if (dwPtr != INVALID_SET_FILE_POINTER)
	{
		DWORD bytesRead = 0;
		BYTE buff[0x200];
		ReadFile(hStorage, buff, 0x200, &bytesRead, NULL);
		if (0 == bytesRead)
		{
			CloseHandle(hStorage);
			return false;
		}
		u8 randomXor = 0;
		if(enable) {
			do
			{
				randomXor = (unsigned)time(NULL) & 0xFF; // Bricmii style of bricking.
			} while (!randomXor); // Avoid the lottery.
			buff[0x10] ^= randomXor;
		}
		else {
			buff[0x10] = 0xF7;
		}


		dwPtr = SetFilePointer(hStorage, 0x200, NULL, FILE_BEGIN);
		if (dwPtr == INVALID_SET_FILE_POINTER)
		{
			CloseHandle(hStorage);
			return false;
		}
		WriteFile(hStorage, buff, 0x200, &bytesRead, NULL);
		if (0 == bytesRead)
		{
			CloseHandle(hStorage);
			return false;
		}

		CloseHandle(hStorage);
		return true;
	}

}

int NxStorage::setCrypto(const char * partition)
{
	if(!crypto)
        return ERR_CRYPTO_GENERIC;

	if (strcmp(partition, "PRODINFO") == 0 || (strcmp(partition, "PRODINFOF") == 0))
	{
        if(std::string(biskeys->crypt0).length() != 32 || std::string(biskeys->tweak0).length() != 32)
			return ERR_CRYPTO_KEY_MISSING;
		key_crypto = hex_string::decode(biskeys->crypt0);
		key_tweak = hex_string::decode(biskeys->tweak0);
	} 
	else if (strcmp(partition, "SAFE") == 0)
	{
        if(std::string(biskeys->crypt1).length() != 32 || std::string(biskeys->tweak1).length() != 32)
            return ERR_CRYPTO_KEY_MISSING;
		key_crypto = hex_string::decode(biskeys->crypt1);
		key_tweak = hex_string::decode(biskeys->tweak1);
	}
	else if (strcmp(partition, "SYSTEM") == 0)
	{
        if(std::string(biskeys->crypt2).length() != 32 || std::string(biskeys->tweak2).length() != 32)
            return ERR_CRYPTO_KEY_MISSING;
		key_crypto = hex_string::decode(biskeys->crypt2);
		key_tweak = hex_string::decode(biskeys->tweak2);
	}
	else if (strcmp(partition, "USER") == 0)
	{
        if(std::string(biskeys->crypt3).length() != 32 || std::string(biskeys->tweak3).length() != 32)
            return ERR_CRYPTO_KEY_MISSING;
		key_crypto = hex_string::decode(biskeys->crypt3);
		key_tweak = hex_string::decode(biskeys->tweak3);
	}
	else 
		return ERR_CRYPTO_KEY_MISSING;

    return 1;
}

bool NxStorage::ValidateDecryptBuf(unsigned char *buf, const char* partition)
{
	if ((strcmp(partition, "PRODINFO") == 0 && hexStr(buf, 4).compare("43414C30") == 0) || 
		(strcmp(partition, "PRODINFOF") == 0 && hexStr(&buf[0x680], 6).compare("434552544946") == 0) ||
		(strcmp(partition, "SAFE") == 0 || strcmp(partition, "SYSTEM") == 0 || strcmp(partition, "USER") == 0) && hexStr(&buf[0x47], 7).compare("4E4F204E414D45") == 0)
	{
		return true;
	}	
	return false;
}

int NxStorage::fat32_read(const char* partition)
{
	ClearHandles();

	// If partition specified
	if (NULL != partition && strlen(partition) > 0)
	{
		// Iterate GPT entry
		GptPartition *part = firstPartion;
		while (NULL != part)
		{
			if (strncmp(part->name, partition, strlen(partition)) == 0)
			{
				handle.off_start = (u64)part->lba_start * NX_EMMC_BLOCKSIZE;
				handle.off_end = (u64)part->lba_end * NX_EMMC_BLOCKSIZE;
				handle.off_max = handle.off_end;
				bytesToRead = ((u64)part->lba_end - (u64)part->lba_start + 1) * (int)NX_EMMC_BLOCKSIZE;
				break;
			}
			part = part->next;
		}

		// No partition found
		if (handle.off_end <= 0) return ERR_INVALID_PART;

	}
	// No partition specified
	else
	{
		handle.off_start = 0;
		handle.off_end = this->size;
		handle.off_max = this->size;
		if (isSplitted) {
			NxSplitFile *file = lastSplitFile, *first;
			while (NULL != file)
			{
				first = file;
				file = file->next;
			}
			handle.off_max = first->offset + first->size;
		}
		bytesToRead = this->size;
	}

	// Get handle 
	handle.h = CreateFileW(pathLPWSTR, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (handle.h == INVALID_HANDLE_VALUE)
		return ERR_INPUT_HANDLE;

	// Set pointer if needed
	LARGE_INTEGER liDistanceToMove;
	if (handle.off_start > 0)
	{		
		liDistanceToMove.QuadPart = handle.off_start;
		if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
			return ERR_INPUT_HANDLE;
	}

	BYTE *buffer = new BYTE[CLUSTER_SIZE];
	DWORD bytesRead = 0;

	// Read first cluster
	if (!ReadFile(handle.h, buffer, CLUSTER_SIZE, &bytesRead, NULL))
		return ERR_WHILE_COPY;

	bool do_crypto = false;
	if (!ValidateDecryptBuf(buffer, NULL != partition ? partition : "SYSTEM"))
	{
		if (!crypto)
			return ERR_CRYPTO_KEY_MISSING;

		int rc = setCrypto(partition ? partition : "SYSTEM");
		if (rc <= 0)
			return rc;

		p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);

		p_crypto->decrypt(buffer, 0);

		if (!ValidateDecryptBuf(buffer, partition ? partition : "SYSTEM"))
		{
			delete p_crypto;
			return ERR_DECRYPT_CONTENT;
		}
		
		do_crypto = true;
	}	

	// Get FS attributes
	fs_attr fs;
	fat32_read_attr(buffer, &fs);
	u64 root_addr = (fs.num_fats * fs.fat_size * fs.bytes_per_sector) + (fs.reserved_sector_count * fs.bytes_per_sector);
	int num_cluster = root_addr / CLUSTER_SIZE;

	// Set pointer to root	
	if (DEBUG_MODE) printf("Root Directory Region offset = %I64d \n", root_addr);
	liDistanceToMove.QuadPart = handle.off_start + root_addr;
	if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
		return ERR_INPUT_HANDLE;

	// Read root entry
	if (!ReadFile(handle.h, buffer, CLUSTER_SIZE, &bytesRead, NULL))
		return ERR_WHILE_COPY;
	
	if(do_crypto)
		p_crypto->decrypt(buffer, num_cluster);

	int buf_off = 0;
	u64 contents_off = 0, regist_off = 0, save_off = 0;

	// Look for /CONTENTS et /REGIST~ dir
	u64 cur_offset = root_addr;
	int nca_found = 0;

	// Parse directory table
	while (cur_offset == root_addr || buffer[0] == 0x2E)
	{
		for (int i = 0; i < 32; i++)
		{			
			struct fat32_entry dir;
			memcpy(&dir, &buffer[buf_off], 32);

			if (dir.filename[0] == 0x00)
				break;

			if (std::string(dir.filename).compare(0, 8, "CONTENTS") == 0) {
				contents_off = fs.bytes_per_sector * ((dir.first_cluster - 2) * fs.sectors_per_cluster) + root_addr;

			} 
			else if (std::string(dir.filename).compare(0, 7, "REGIST~") == 0) {
				regist_off = fs.bytes_per_sector * ((dir.first_cluster - 2) * fs.sectors_per_cluster) + root_addr;
			}
			else if (std::string(dir.filename).compare(0, 4, "SAVE") == 0) {
				save_off = fs.bytes_per_sector * ((dir.first_cluster - 2) * fs.sectors_per_cluster) + root_addr;
			}
			/*
			else {

				// Look for NCA 
				unsigned char ext[3];
				memcpy(&ext, &dir.filename[8], 3);
				if (strcmp(hexStr(ext, 3).c_str(), "4E4341") == 0)
				{
					nca_found++;
					// Get nca fiename
					std::string filename = get_longfilename(buffer, buf_off, 3);

					if (DEBUG_MODE) printf("%s (off %s)\n", filename.c_str(), int_to_hex((int)cur_offset + buf_off).c_str());

					// Look for firmware version
					for (int l = 0; l < (int)array_countof(sytemTitlesArr); l++)
					{
						if (filename.compare(std::string(sytemTitlesArr[l].nca_filename)) == 0)
						{
							memcpy(&fw_version, &sytemTitlesArr[l].fw_version, sizeof(&sytemExFatTitlesArr[l].fw_version));
							fw_detected = true;
						}
					}

					// Look for exFat driver
					for (int l = 0; l < (int)array_countof(sytemExFatTitlesArr); l++)
					{
						if (filename.compare(std::string(sytemExFatTitlesArr[l].nca_filename)) == 0)
						{
							if(!fw_detected)
								memcpy(&fw_version, &sytemExFatTitlesArr[l].fw_version, sizeof(&sytemExFatTitlesArr[l].fw_version));
							exFat_driver = true;
						}
					}
				}
			}
			*/

			if (DEBUG_MODE && dir.attributes == 0x10) {
				int t_off = fs.bytes_per_sector * ((dir.first_cluster - 2) * fs.sectors_per_cluster) + root_addr;
				printf("SUB DIR at off %d : %s (first cluster %d, off2 %s)\n", cur_offset+ buf_off, dir.filename, 
					dir.first_cluster, int_to_hex(t_off).c_str());
			}

			buf_off += 32;
		}

		// Read next cluster
		if (!fat32_read_next_cluster(&buffer[0], do_crypto, num_cluster))
			break;

		num_cluster++;
		cur_offset += CLUSTER_SIZE;
		buf_off = 0;

	}

	if (contents_off <= 0 || regist_off <= 0 || save_off <= 0)
		return -1;

	// Iterate contents, registered & save entries
	for (int num_dir = 0; num_dir < 3; num_dir++)
	{
		u64 dir_off;
		if (num_dir == 0) dir_off = contents_off;
		if (num_dir == 1) dir_off = regist_off;
		else dir_off = save_off;

		// Set pointer to file table	
		if (DEBUG_MODE) printf("CONTENTS file table %d \n", num_dir + 1);
		liDistanceToMove.QuadPart = handle.off_start + dir_off;

		if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
			return ERR_INPUT_HANDLE;

		// Read first cluster 
		num_cluster = dir_off / CLUSTER_SIZE;
		if (!ReadFile(handle.h, buffer, CLUSTER_SIZE, &bytesRead, NULL))
			return ERR_WHILE_COPY;

		if (do_crypto)
			p_crypto->decrypt(buffer, num_cluster);

		// Iterate file entries
		int i = 0, lfn_length = 0;;
		while (1)
		{			
			struct fat32_entry dir;
			memcpy(&dir, &buffer[i], 0x20);

			if (dir.filename[0] == 0x00)
			{
				break;
			}

			if (dir.attributes == 0x0F)
				lfn_length++;

			unsigned char basename[8];
			memcpy(&basename, &dir.filename, 8);

			// Subdir found
			if (dir.attributes == 0x10)
			{
				int nYear = (dir.modified_date >> 9);
				int nMonth = (dir.modified_date << 7);
				nMonth = nMonth >> 12;
				int nDay = (dir.modified_date << 11);
				nDay = nDay >> 11;

				if (DEBUG_MODE) printf("Modification Date    : %d/%d/%d\n", nDay, nMonth, (nYear + 1980));

				std::string filename = get_longfilename(buffer, i, lfn_length);
				if (DEBUG_MODE) printf("=> %s (off %s)\n", filename.c_str(), int_to_hex((int)dir_off + i).c_str(), lfn_length);
				
				// If SAVE sub dir
				if (num_dir == 2 && filename.compare(0, 16, "8000000000000060") == 0 )
				{
					if (DEBUG_MODE) printf("8000000000000060 FOUND \n");
				}


			}

			unsigned char ext[3];
			memcpy(&ext, &dir.filename[8], 3);
			// If NCA file found
			if ((dir.attributes == 0x20 || dir.attributes == 0x30) && strcmp(hexStr(ext, 3).c_str(), "4E4341") == 0) {

				nca_found++;
				// Get nca fiename
				std::string filename = get_longfilename(buffer, i, lfn_length);

				if (DEBUG_MODE) printf("%s (off %s)\n", filename.c_str(), int_to_hex((int)dir_off + i).c_str());

				// Look for firmware version
				for (int l = 0; l < (int)array_countof(sytemTitlesArr); l++)
				{
					if (filename.compare(std::string(sytemTitlesArr[l].nca_filename)) == 0)
					{
						memcpy(&fw_version, &sytemTitlesArr[l].fw_version, sizeof(&sytemExFatTitlesArr[l].fw_version));
						fw_detected = true;
					}
				}

				// Look for exFat driver
				for (int l = 0; l < (int)array_countof(sytemExFatTitlesArr); l++)
				{
					if (filename.compare(std::string(sytemExFatTitlesArr[l].nca_filename)) == 0)
					{
						if (!fw_detected)
							memcpy(&fw_version, &sytemExFatTitlesArr[l].fw_version, sizeof(&sytemExFatTitlesArr[l].fw_version));
						exFat_driver = true;
					}
				}
			}		

			// Switch to next cluster if needed
			if (i == CLUSTER_SIZE - 0x20)
			{

				if (!fat32_read_next_cluster(&buffer[0], do_crypto, num_cluster))
					break;

				num_cluster++;
				i = 0;
			}
			else {
				i += 0x20;
			}

			if (dir.attributes != 0x0F)
				lfn_length = 0;
		}

	}

	if (DEBUG_MODE) printf("Total of %d NCA found\n", nca_found);

	if (NULL != p_crypto)
		delete p_crypto;

	ClearHandles();
	return 1;
}

std::string NxStorage::get_longfilename(BYTE *buffer, int offset, int length) {
	unsigned char filename[40];
	int x = 0;
	// Get long filename
	for (int j = 1; j <= 3; j++)
	{

		int off = offset - (j * 0x20);
		LFN lfn;
		memcpy(&lfn, &buffer[off], 0x20);

		for (int k = 0; k < sizeof(lfn.fileName_Part1); k = k + 2) {
			memcpy(&filename[x], &lfn.fileName_Part1[k], 1);
			x++;
		}
		for (int k = 0; k < sizeof(lfn.fileName_Part2); k = k + 2) {
			memcpy(&filename[x], &lfn.fileName_Part2[k], 1);
			x++;
		}
		for (int k = 0; k < sizeof(lfn.fileName_Part3); k = k + 2) {
			memcpy(&filename[x], &lfn.fileName_Part3[k], 1);
			x++;
		}
	}
	return std::string(reinterpret_cast<const char*>(filename));
}

int NxStorage::fat32_read_next_cluster(BYTE *buffer, bool do_crypto, int num_cluster)
{
	DWORD bytesRead = 0;
	if (!ReadFile(handle.h, buffer, CLUSTER_SIZE, &bytesRead, NULL))
		return ERR_WHILE_COPY;

	if (bytesRead <= 0)
		return -1;

	num_cluster++;

	if (do_crypto)
		p_crypto->decrypt(buffer, num_cluster);
}

int NxStorage::fat32_read_attr(BYTE *cluster, fs_attr *fat32_attr)
{
	memcpy(&fat32_attr->bytes_per_sector, &cluster[0xB], 2);
	memcpy(&fat32_attr->sectors_per_cluster, &cluster[0xD], 1);
	memcpy(&fat32_attr->reserved_sector_count, &cluster[0xE], 2);
	memcpy(&fat32_attr->num_fats, &cluster[0x10], 1);
	memcpy(&fat32_attr->fat_size, &cluster[0x24], 4);
	memcpy(&fat32_attr->label, &cluster[0x47], 11);
	
	return 1;
}

int NxStorage::prodinfo_read()
{
	ClearHandles();

	if(DEBUG_MODE) printf("prodinfo_read begin\n");
	if(type == RAWNAND)
	{
		if (DEBUG_MODE) printf("prodinfo_read, type RAWNAND\n");
		// Iterate GPT entry
		GptPartition *part = firstPartion;
		while (NULL != part)
		{
			if (strncmp(part->name, "PRODINFO", strlen("PRODINFO")) == 0)
			{
				
				handle.off_start = (u64)part->lba_start * NX_EMMC_BLOCKSIZE;
				handle.off_end = (u64)part->lba_end * NX_EMMC_BLOCKSIZE;
				handle.off_max = handle.off_end;
				bytesToRead = ((u64)part->lba_end - (u64)part->lba_start + 1) * (int)NX_EMMC_BLOCKSIZE;
				if (DEBUG_MODE) printf("prodinfo_read, PRODINFO part found (offet %I64d)\n", int_to_hex((int)handle.off_start).c_str());
				break;
			}
			part = part->next;
		}

		// No partition found
		if (handle.off_end <= 0) 
			return ERR_INVALID_PART;
	}
	else if (type == PARTITION && std::string(partitionName).compare(0, 8, "PRODINFO") == 0 
			 && std::string(partitionName).compare(0, 9, "PRODINFOF") != 0)
	{
		handle.off_start = 0;
		handle.off_end = this->size;
		handle.off_max = this->size;
	} else {
		return ERR_INVALID_PART;	
	}

	// Get handle 
	handle.h = CreateFileW(pathLPWSTR, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (handle.h == INVALID_HANDLE_VALUE)
		return ERR_INPUT_HANDLE;

	// Set pointer if needed
	LARGE_INTEGER liDistanceToMove;
	if (handle.off_start > 0)
	{
		liDistanceToMove.QuadPart = handle.off_start;
		if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
			return ERR_INPUT_HANDLE;
	}

	BYTE *buffer = new BYTE[CLUSTER_SIZE];
	DWORD bytesRead = 0;

	if (DEBUG_MODE) printf("PRODINFO read at offset %s \n", int_to_hex((int)handle.off_start).c_str());

	// Read first cluster
	if (!ReadFile(handle.h, buffer, CLUSTER_SIZE, &bytesRead, NULL))
		return ERR_WHILE_COPY;

	bool do_crypto = false;
	if (!ValidateDecryptBuf(buffer, "PRODINFO"))
	{
		if (!crypto)
			return ERR_CRYPTO_KEY_MISSING;

		int rc = setCrypto("PRODINFO");
		if (rc <= 0)
			return rc;

		p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);

		p_crypto->decrypt(buffer, 0);

		if (!ValidateDecryptBuf(buffer, "PRODINFO"))
		{
			delete p_crypto;
			return ERR_DECRYPT_CONTENT;
		}		
		do_crypto = true;
	}	

	if (DEBUG_MODE) printf("PRODINFO crypt ok\n");

	memcpy(&serial_number, &buffer[0x250], 18);
	
	if (NULL != p_crypto)
		delete p_crypto;

	ClearHandles();
	return 1;
}
