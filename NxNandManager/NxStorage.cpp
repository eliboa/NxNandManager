#include "NxStorage.h"

NxStorage::NxStorage(const char* storage, KeySet *p_biskeys, bool debug_mode)
{
    DEBUG_MODE = debug_mode ? true : false;
    //DEBUG_MODE = true;
	bool crypto = false;
	if (DEBUG_MODE) printf("NxStorage::NxStorage - path = %s\n", storage);
	path = storage;
	pathLPWSTR = NULL;

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

	type = UNKNOWN;
	size = 0, fileDiskTotalBytes = 0, fileDiskFreeBytes = 0;
	isDrive = false, backupGPTfound = false, autoRcm = false, isEncrypted = false, b_MayBeNxStorage = false;
	pdg = { 0 };
	partCount = 0;
	firstPartion = NULL;
	curPartition = NULL;
	lastSplitFile = NULL;
	partitionName[0] = '\0';
	handle.h = NULL;
	handle_out = NULL;
	exFat_driver = false;
	fw_detected = false;
	bad_crypto = false;
	memset(fw_version, 0, sizeof fw_version);
	memset(deviceId, 0, sizeof deviceId);
	macAddress.empty();

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
	bool TXNand = false;

	// Look for magic offset
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

	if (type == PRODINFO || type == PRODINFOF)
	{
		strcpy_s(partitionName, type == PRODINFO ? "PRODINFO" : "PRODINFOF");
		type = PARTITION;
	}

	// Dynamic search for PK11 magic (BOOT1)
	if(type == UNKNOWN && size == 0x400000)
	{
		DWORD readamount = 0;
		while (readamount < size) 
		{
			DWORD dwPtr = SetFilePointer(hStorage, readamount, NULL, FILE_BEGIN);
			if (dwPtr == INVALID_SET_FILE_POINTER)
				break;
			
			ReadFile(hStorage, buff, 0x200, &bytesRead, NULL);
			readamount += 0x200;

			std::string haystack(buff, buff + 0x200);
			std::size_t n;
			n = haystack.find("PK11");

			// Found needle in a haystack
			if (n != std::string::npos) {
				type = BOOT1;
				break;
			}
		}
	}
	
	// Try to identify partition files (comparing file name & file size)
	// -> this is pretty shitty but we'll just stick with this for now)
	if (!isDrive && type == UNKNOWN)
	{
		for (int i = 0; i < (int)array_countof(partInfoArr); i++)
		{
			std::string basename = base_name(std::string(path));			
			basename = remove_extension(basename);
			std::transform(basename.begin(), basename.end(),basename.begin(), ::toupper);
            if (strncmp(partInfoArr[i].name, basename.c_str(), strlen(basename.c_str())) == 0 && partInfoArr[i].size == size)
			{
				strcpy_s(partitionName, partInfoArr[i].name);
				if(strcmp(partitionName, "CAL0")  == 0)
					strcpy_s(partitionName, "PRODINFO");
				type = PARTITION;
				break;
			}
			else if (partInfoArr[i].size == size)
			{
				b_MayBeNxStorage = true;
			}
		}
	}

	// FULL EMMC
	if (type == RAWMMC)
	{
		mmc.lba_start = 0;
		mmc.lba_end = size / NX_EMMC_BLOCKSIZE;
		mmc.boot0_lba_start = 0;
		mmc.boot1_lba_start = mmc.boot0_lba_start + 0x2000;
		mmc.rawnand_lba_start = mmc.boot1_lba_start + 0x2000;
	}

	if (type == TXNAND)
	{
		mmc.lba_start = 0;
		mmc.boot0_lba_start = 2;
		mmc.boot1_lba_start = mmc.boot0_lba_start + 0x2000;
		mmc.rawnand_lba_start = mmc.boot1_lba_start + 0x2000;
		mmc.lba_end = size - NX_EMMC_BLOCKSIZE;
		TXNand = true;
		type = RAWMMC;
	}

	// EmuMMC & TX emuNAND partition
	if (isDrive && (type == UNKNOWN || TXNand))
    {
		CloseHandle(hStorage);		
		DiskSector ds;
		CPartitionManager pm;
		unsigned char buff[NX_EMMC_BLOCKSIZE] = { 0 };
		pm.m_bIncludeExtendedPartitionDefinitions = true;

		wstring ws(pathLPWSTR);
		std::string spath = string(ws.begin(), ws.end());
		//std::string spath(pathLPWSTR);
		for (auto & c : spath) c = toupper(c);
		std::size_t n = spath.find("PHYSICALDRIVE");
		if (n != std::string::npos) {
			std::string volume = spath.substr(n+13);			
			int vol = std::stoi(volume);			
			if (ds.OpenPhysicalDrive(vol)) {

				if (pm.ReadPartitionTable(vol, 0)) {
					// Iterate partitions
					size_t nbPartsTotal = 0, nbParts = pm.partlist.size();
					for (size_t i = 0; i < nbParts; i++)
					{
						partition_info &pi = pm.partlist[i];

						// Set size for TX NAND drive
						if (TXNand && i == 0) {
							mmc.lba_end = pi.lba_start - 1;
							size = (mmc.lba_end - mmc.lba_start + 1) * NX_EMMC_BLOCKSIZE;
							type = RAWMMC;
							break;
						}
						
						// Offset must be in range
						if (pi.lba_start + 0x8002 > pi.lba_end)
							continue;

						// Look for BOOT0 at offset pi.lba_start + 0x8002 + 0x130						
						ULONGLONG sector = pi.lba_start + 0x8002;
						ds.ReadSector(sector, &buff);

						// BOOT0 FOUND
						if (hexStr(&buff[0x130], 12) == "010021000E00000009000000") {
							//size = (pi.lba_end - pi.lba_start + 1) * NX_EMMC_BLOCKSIZE;
							mmc.lba_start = pi.lba_start;
							mmc.lba_end = pi.lba_end;
							mmc.boot0_lba_start = pi.lba_start + 0x8000;
							mmc.boot1_lba_start = mmc.boot0_lba_start + 0x2000;
							mmc.rawnand_lba_start = mmc.boot1_lba_start + 0x2000;

							if (DEBUG_MODE) printf("RAWMMC FOUND, BOOT0 starts at sector %llu, BOOT1 at %llu, RAWNAND at %llu\n",
								mmc.boot0_lba_start, mmc.boot1_lba_start, mmc.rawnand_lba_start);

							type = RAWMMC;
							break;
						}
					}
				}
			}
		}
		ds.Close();
		pm.Close();
		hStorage = CreateFileW(pathLPWSTR, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	}

	// Partition crypto validation
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
			
			// Validate crypto
			else if (crypto)
			{
				BYTE buffer[CLUSTER_SIZE];
				if (ReadBufferAtOffset(buffer, 0) > 0)
				{
					setCrypto(partitionName);
					p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);
					p_crypto->decrypt(buffer, 0); // 0 because we only read first cluster
					delete p_crypto;

					// Validate decrypted buffer
					if (!ValidateDecryptBuf(buffer, partitionName))
					{
						if (DEBUG_MODE) printf("BAD crypto for %s partition\n", partitionName);

						// There's something wrong with crypto keys
						bad_crypto = true;
					}
					else if (DEBUG_MODE) printf("GOOD crypto for %s partition\n", partitionName);
				}
			}
		}
	}

	// Detect autoRCM & bootloader version
	if (type == BOOT0 || type == RAWMMC)
	{
		LARGE_INTEGER liDistanceToMove;
		liDistanceToMove.QuadPart = 0x200;
		if (type == RAWMMC)
			liDistanceToMove.QuadPart += mmc.boot0_lba_start * NX_EMMC_BLOCKSIZE;

		DWORD dwPtr = SetFilePointerEx(hStorage, liDistanceToMove, NULL, FILE_BEGIN);
		if (dwPtr != INVALID_SET_FILE_POINTER)
		{
			// Get autoRCM state
			ReadFile(hStorage, buff, 0x200, &bytesRead, NULL);
			if (0 != bytesRead)
			{
				if(buff[0x10] != 0xF7) autoRcm = TRUE;
				else autoRcm = FALSE;
			}
			// Get bootloader version
			liDistanceToMove.QuadPart += 0x2000;
			SetFilePointerEx(hStorage, liDistanceToMove, NULL, FILE_BEGIN);
			ReadFile(hStorage, buff, 0x200, &bytesRead, NULL);
			if (0 != bytesRead)
			{
				memcpy(&bootloader_ver, &buff[0x130], sizeof(unsigned char));
			} 

		}
	}

	// RAWNAND Init
	if (type == RAWNAND || type == RAWMMC)
	{		
		bool was_mmc = false;
		u64 last_cluster = 0;
		LARGE_INTEGER liDistanceToMove;
		liDistanceToMove.QuadPart = 0x200;
		if (type == RAWMMC) {
			was_mmc = true;
			liDistanceToMove.QuadPart += mmc.rawnand_lba_start * NX_EMMC_BLOCKSIZE;
		}

		// Read & parse GPT
		DWORD dwPtr = SetFilePointerEx(hStorage, liDistanceToMove, NULL, FILE_BEGIN);
		if (dwPtr != INVALID_SET_FILE_POINTER)
		{
			BYTE buffGpt[0x4200];
			ReadFile(hStorage, buffGpt, 0x4200, &bytesRead, NULL);
			if (0 != bytesRead)
			{

				//if (DEBUG_MODE) printf("GPT BUFFER \n%s\n", hexStr(buffGpt, 512).c_str());

				type = UNKNOWN; // Reset type, we'll look for real Nx partitions when parsing GPT								
				this->ParseGpt(buffGpt);

				// If NAND type was RAWMMC
				if (type == RAWNAND && was_mmc) {
					type = RAWMMC;
				}

				// Get last sector & set real offsets for GPP
				GptPartition *cur = firstPartion;
				while (NULL != cur)
				{
					if (type == RAWMMC)
					{
						cur->lba_start += mmc.rawnand_lba_start;
						cur->lba_end += mmc.rawnand_lba_start;
					}
					if(last_cluster < cur->lba_end) last_cluster = cur->lba_end;
					cur = cur->next;
				}

				if (type == RAWMMC)
				{
					size = size = (last_cluster - mmc.boot0_lba_start + 1) * NX_EMMC_BLOCKSIZE;

					// Add BOOT1 partition
					GptPartition *part2 = (GptPartition *)malloc(sizeof(GptPartition));
					part2->isEncrypted = false;
					part2->lba_start = mmc.boot1_lba_start;
					part2->lba_end = mmc.boot1_lba_start + 0x2000 - 1;
					memset(part2->name, 0, 36);
					memcpy(part2->name, "BOOT1", 5);
					part2->next = firstPartion;

					// Add BOOT0 partition
					GptPartition *part1 = (GptPartition *)malloc(sizeof(GptPartition));
					part1->isEncrypted = false;
					part1->lba_start = mmc.boot0_lba_start;
					part1->lba_end = mmc.boot0_lba_start + 0x2000 - 1;
					memset(part1->name, 0, 36);
					memcpy(part1->name, "BOOT0", 5);
					part1->next = part2;
					firstPartion = part1;

				}

					//printf("mmc boot0 lba start %I64d, part start %I64d\n", mmc.boot0_lba_start, part1->lba_start);
				
			}
		}

		// Look for backup GPT		
        liDistanceToMove.QuadPart = last_cluster * NX_EMMC_BLOCKSIZE + 0x20400000;
			
		if (DEBUG_MODE) printf("Looking for backup GPT at offset %s, sector %s\n", n2hexstr(liDistanceToMove.QuadPart, 10).c_str(), n2hexstr(liDistanceToMove.QuadPart / NX_EMMC_BLOCKSIZE, 10).c_str());

		DWORD dwPtr2 = SetFilePointerEx(hStorage, liDistanceToMove, NULL, FILE_BEGIN);
		if (dwPtr2 != INVALID_SET_FILE_POINTER)
		{
			unsigned char buffGpt[NX_EMMC_BLOCKSIZE];
			ReadFile(hStorage, buffGpt, NX_EMMC_BLOCKSIZE, &bytesRead, NULL);
			if (0 != bytesRead)
			{
				if(hexStr(&buffGpt[0], 8) == "4546492050415254")
				{
					backupGPTfound = TRUE;					
				}
			}
		}

	}

	// Look for splitted dump
	if (type == RAWNAND && !backupGPTfound && !isDrive) {

		// Overwrite object type
		type = UNKNOWN;

		// Explode file path as wide strings
		wstring Lfilename(this->pathLPWSTR);
        wstring extension(get_extension(Lfilename));
		wstring basename(remove_extension(Lfilename));

        if(extension.compare(basename) == 0 )
            extension.erase();

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

				CloseHandle(hFile);

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
					hFile = CreateFileW(&lastSplitFile->file_path[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
					// Look for backup GPT in last split file (mandatory for splitted dump)
					LARGE_INTEGER liDistanceToMove;
					liDistanceToMove.QuadPart = lastSplitFile->size - NX_EMMC_BLOCKSIZE;
					DWORD dwPtr = SetFilePointerEx(hFile, liDistanceToMove, NULL, FILE_BEGIN);
					if (dwPtr != INVALID_SET_FILE_POINTER)
					{
						unsigned char buffGpt[NX_EMMC_BLOCKSIZE];                        
						ReadFile(hFile, buffGpt, NX_EMMC_BLOCKSIZE, &bytesRead, NULL);
						if (0 != bytesRead)
						{
							//GptHeader *hdr = (GptHeader *)buffGpt;
							//if (hdr->num_part_ents > 0)
							if (hexStr(&buffGpt[0], 8) == "4546492050415254")
							{
								backupGPTfound = TRUE;
								type = RAWNAND;
							}
						}
						CloseHandle(hFile);
					}
				}
			}
		}
	}


	if (type == PARTITION && std::string(partitionName).substr(0, 6).compare("SYSTEM") == 0 && ((crypto && !bad_crypto) || !isEncrypted))
		fat32_read();

	if (type == PARTITION && std::string(partitionName).substr(0, 8).compare("PRODINFO") == 0 && strlen(partitionName) == 8 && ((crypto && !bad_crypto) || !isEncrypted))
		prodinfo_read();

	// RAWNAND crypto validation & init operations
	if (type == RAWNAND || type == RAWMMC)
	{
		BYTE buffer[CLUSTER_SIZE];

		// For each partition
		GptPartition *part = firstPartion;
		while (NULL != part)
		{
			if (DEBUG_MODE) printf("Validate crypto for %s partition (%s) \n", part->name, part->isEncrypted ? "encrypted" : "decrypted");

			// Read buffer for the so called "encrypted" partition
			u64 offset = (u64)part->lba_start * NX_EMMC_BLOCKSIZE;
			if (part->isEncrypted && ReadBufferAtOffset(buffer, offset) > 0)
			{
				// If partition already decrypted
				if (ValidateDecryptBuf(buffer, part->name))
					part->isEncrypted = false;
				else
					isEncrypted = true; // RAWNAND is encrypted if at least one partition is encrypted

				if (part->isEncrypted && crypto)
				{
					part->bad_crypto = false;

					setCrypto(part->name);
					p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);
					p_crypto->decrypt(buffer, 0); // 0 because we only read first cluster
					delete p_crypto;

					// Validate decrypted buffer
					if (!ValidateDecryptBuf(buffer, part->name))
					{
						if (DEBUG_MODE) printf("BAD crypto for %s partition\n", part->name);

						// There's something wrong with crypto keys
						part->bad_crypto = true;
						bad_crypto = true;
					}
					else if (DEBUG_MODE) printf("GOOD crypto for %s partition\n", part->name);				
				}
			}

			// Do operations on un/decrypted partitions
			if (!part->isEncrypted || (part->isEncrypted && crypto && !part->bad_crypto))
			{

				if (strcmp(part->name, "SYSTEM") == 0)
					fat32_read(part->name);

				if (strcmp(part->name, "PRODINFO") == 0)
					prodinfo_read();;
			}

			// Switch to next partition
			part = part->next;
		}
	}

	CloseHandle(hStorage);
	ClearHandles();
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
		part->bad_crypto = false;
		part->isEncrypted = false;
		
		for (u32 i = 0; i < 36; i++)
		{
			part->name[i] = ent->name[i];
			part->name[i+1] = '0';
		}
		part->name[36] = '0';

		// GPT contains NX NAND partition
		if (strcmp(part->name, "PRODINFO") == 0)
		{
			type = RAWNAND;
		}

		if (strcmp(part->name, "PRODINFO") == 0 || strcmp(part->name, "PRODINFOF") == 0 || strcmp(part->name, "SAFE") == 0 ||
			strcmp(part->name, "SYSTEM") == 0 || strcmp(part->name, "USER") == 0)
		{
			part->isEncrypted = true;
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

int NxStorage::ReadBufferAtOffset(BYTE *buffer, u64 offset, int length)
{
	//if (DEBUG_MODE) printf("ReadBufferAtOffset off %s\n", int_to_hex(offset).c_str());
	// Get real offset (in case of splitted files)
	u64 real_off = offset;
	NxSplitFile file;
	if (isSplitted) 
	{		
		if (!GetSplitFile(&file, offset))
			return -2;

		real_off = offset - file.offset;
		if (DEBUG_MODE) printf("ReadBufferAtOffset -> real_off is %s\n", int_to_hex(real_off).c_str());
	}

	///if (DEBUG_MODE) printf("ReadBufferAtOffset -> Create new handle\n");

	// Default input is self object path
	if(!isSplitted) 
		wcscpy(handle.path, pathLPWSTR);
		
	// Overwrite path for splitted file
	else if(wcscmp(handle.path, file.file_path) != 0)
		wcscpy(handle.path, file.file_path); 

	// Get new handle
	handle.h = CreateFileW(&handle.path[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (handle.h == INVALID_HANDLE_VALUE) 
		return ERR_INPUT_HANDLE;

	//if (DEBUG_MODE) printf("ReadBufferAtOffset -> Set pointer at off %s\n", int_to_hex(real_off).c_str());
	// Set pointer
	LARGE_INTEGER liDistanceToMove;
	liDistanceToMove.QuadPart = real_off;
	if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		ClearHandles();
		return ERR_INPUT_HANDLE;
	}

	if (DEBUG_MODE) printf("ReadBufferAtOffset -> ReadFile, length %s\n", int_to_hex(length).c_str());

	// Read buffer
	DWORD bytesRead = 0;
	if (!ReadFile(handle.h, buffer, length, &bytesRead, NULL)) {
		//if (DEBUG_MODE) printf("ReadBufferAtOffset -> ReadFile fails : %s\n", GetLastErrorAsString().c_str());
		ClearHandles();
		return -1;
	}

	//if (DEBUG_MODE) printf("ReadBufferAtOffset ends, %d bytes read\n", bytesRead);
	ClearHandles();
	return bytesRead;
}

int NxStorage::WriteBufferAtOffset(BYTE *buffer, u64 offset, int length)
{
	//if (DEBUG_MODE) printf("ReadBufferAtOffset off %s\n", int_to_hex(offset).c_str());
	// Get real offset (in case of splitted files)
	u64 real_off = offset;
	NxSplitFile file;
	if (isSplitted)
	{
		if (!GetSplitFile(&file, offset))
			return -2;

		real_off = offset - file.offset;
		if (DEBUG_MODE) printf("ReadBufferAtOffset -> real_off is %s\n", int_to_hex(real_off).c_str());
	}

	///if (DEBUG_MODE) printf("ReadBufferAtOffset -> Create new handle\n");

	// Default input is self object path
	if (!isSplitted)
		wcscpy(handle.path, pathLPWSTR);

	// Overwrite path for splitted file
	else if (wcscmp(handle.path, file.file_path) != 0)
		wcscpy(handle.path, file.file_path);

	// Get new handle
	handle.h = CreateFileW(&handle.path[0], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (handle.h == INVALID_HANDLE_VALUE) {
        std::string errorstr = GetLastErrorAsString();
		return ERR_OUTPUT_HANDLE;        
    }


	//if (DEBUG_MODE) printf("ReadBufferAtOffset -> Set pointer at off %s\n", int_to_hex(real_off).c_str());
	// Set pointer
	LARGE_INTEGER liDistanceToMove;
	liDistanceToMove.QuadPart = real_off;
	if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		ClearHandles();
		return ERR_OUTPUT_HANDLE;
	}

	if (DEBUG_MODE) printf("WriteBufferAtOffset -> WriteFile, length %s\n", int_to_hex(length).c_str());

	// Read buffer
	DWORD bytesRead = 0;
	if (!WriteFile(handle.h, buffer, length, &bytesRead, NULL))
	{
		//if (DEBUG_MODE) printf("ReadBufferAtOffset -> ReadFile fails : %s\n", GetLastErrorAsString().c_str());
		ClearHandles();
		return -1;
	}

	//if (DEBUG_MODE) printf("ReadBufferAtOffset ends, %d bytes read\n", bytesRead);
	ClearHandles();
	return bytesRead;
}

void NxStorage::ClearHandles()
{
    DWORD lpdwFlags[100];
    if(GetHandleInformation(handle.h, lpdwFlags))
    {
        CloseHandle(handle.h);
    }
    if(GetHandleInformation(handle_out, lpdwFlags))
    {
        CloseHandle(handle_out);
    }
	//handle.path.empty();
	handle.off_end = 0;
	handle.off_start = 0;
	handle.readAmount = 0;
	handle.off_max = 0;
	handle.decrypt = false;
	handle.encrypt = false;
	bytesToRead = 0;
}

int NxStorage::RestoreFromStorage(NxStorage *in, const char* partition, u64* readAmount, u64* writeAmount, u64* bytesToWrite)
{
	DWORD toRead = DEFAULT_BUFF_SIZE;

	// First iteration
	if (handle.readAmount == 0)
	{
		u64 out_off_start = 0;
		handle.block_num = 0;
		do_crypto = false;

		*bytesToWrite = size;
		// Restore to splitted dump not supported yet
		if (isSplitted)
			return ERR_RESTORE_TO_SPLIT;

		if (crypto)
			handle.encrypt = true;

		if (handle.encrypt && in->isEncrypted)
			return ERR_CRYPTO_ENCRYPTED_YET;

		// Default path is input object path
		wcscpy(handle.path, in->pathLPWSTR);

		// Restoring to RAWNAND
		if (type == RAWNAND || type == RAWMMC)
		{
			// Restoring to a single partition
			if (NULL != partition && strlen(partition) > 0)
			{
				// Get partition in output
				GptPartition* out_part = GetPartitionByName(partition);
				if (NULL == out_part)
					return ERR_INVALID_PART;

				// Set offset to begin in output rawnand
				out_off_start = (u64)out_part->lba_start * NX_EMMC_BLOCKSIZE;
				*bytesToWrite = ((u64)out_part->lba_end - (u64)out_part->lba_start + 1) * (int)NX_EMMC_BLOCKSIZE;
				bytesToRead = in->size;

				// If input is a rawnand file 
				if (in->type == RAWNAND || in->type == RAWMMC)
				{
					// Get partition in input
					GptPartition* in_part = in->GetPartitionByName(partition);
					if (NULL == in_part)
						return ERR_INVALID_PART;

					// Set offset to begin in input rawnand
					handle.off_start = (u64)in_part->lba_start * NX_EMMC_BLOCKSIZE;
					handle.off_end = (u64)in_part->lba_end * NX_EMMC_BLOCKSIZE;
					handle.off_max = handle.off_end;
					bytesToRead = ((u64)in_part->lba_end - (u64)in_part->lba_start + 1) * (int)NX_EMMC_BLOCKSIZE;

					// Overwrite some values for splitted dump
					if (in->isSplitted)
					{
						NxSplitFile splitFile;
						if (!in->GetSplitFile(&splitFile, partition))
							return ERR_INVALID_PART;
						wcscpy(handle.path, splitFile.file_path);
						handle.off_max = handle.off_start + (splitFile.size - handle.off_start);
					}

					// Restoring from encrypted partition to decrypted partition
					if (!out_part->isEncrypted && in_part->isEncrypted)
					{
						return ERR_RESTORE_CRYPTO_MISSIN2;
						/*
						if (in_part->bad_crypto)
							return ERROR_DECRYPT_FAILED;

						handle.decrypt = true;
						do_crypto = true;
						*/
					}

					// Restoring from decrypted partition to encrypted partition
					if (out_part->isEncrypted && !in_part->isEncrypted)
					{
						// If crypto missing, return error
						if (!crypto)
							return ERR_RESTORE_CRYPTO_MISSING;

						handle.encrypt = true;
						do_crypto = true;
					}
				}
				
				// If input is a PARTITION file
				else if (in->type == PARTITION)
				{

					// Set offset to begin in input PARTITION
					handle.off_start = 0;
					handle.off_end = in->size;
					handle.off_max = in->size;
					bytesToRead = in->size;

					// Restoring from encrypted partition to decrypted partition
					if (!out_part->isEncrypted && in->isEncrypted)
					{
						//if (!in->crypto)
							return ERR_RESTORE_CRYPTO_MISSIN2;
						/*
						if (in->bad_crypto)
							return ERROR_DECRYPT_FAILED;

						handle.decrypt = true;
						do_crypto = true;
						*/
					}

					// Restoring from decrypted partition to encrypted partition
					if (out_part->isEncrypted && !in->isEncrypted)
					{
						// If crypto missing, return error
						if (!crypto)
							return ERR_RESTORE_CRYPTO_MISSING;

						handle.encrypt = true;
						do_crypto = true;
					}
				}
				else
				{
					return ERR_INVALID_PART;
				}
			
				if (do_crypto)
				{
					if (setCrypto(partition) > 0)
						p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), DEFAULT_BUFF_SIZE);
					else
						return ERR_CRYPTO_KEY_MISSING;
				}
			}
			// Restoring to full nand
			else
			{
				// input is encrypted but output is not
				if (in->isEncrypted && !isEncrypted)
				{
					//if(!in->crypto)
						return ERR_RESTORE_CRYPTO_MISSIN2;
					/*
					if (in->bad_crypto)
						return ERROR_DECRYPT_FAILED;

					handle.decrypt = true;
					do_crypto = true;
					*/

				}
				// output is encrypted but input is not
				if (isEncrypted && !in->isEncrypted)
				{
					if(!crypto)
						return ERR_RESTORE_CRYPTO_MISSING;

					handle.encrypt = true;
					do_crypto = true;
				}

				// Set offset to begin in RAWMMC
				handle.off_start = 0;
				if (in->type == RAWMMC && in->type == RAWNAND)
					out_off_start = mmc.rawnand_lba_start * NX_EMMC_BLOCKSIZE;;
				if (in->type == RAWMMC && type == RAWMMC) {
					handle.off_start = in->mmc.boot0_lba_start * NX_EMMC_BLOCKSIZE;
					out_off_start = mmc.boot0_lba_start * NX_EMMC_BLOCKSIZE;
				}
				handle.off_end = in->size;
				handle.off_max = in->size;

				// Overwrite some values for splitted dump
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
			
		}
		// Restoring to boot partitions
		else
		{
			handle.off_start = 0;
			handle.off_end = in->size;
			handle.off_max = in->size;
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
		if (handle_out == INVALID_HANDLE_VALUE) {
			if (DEBUG_MODE) printf("ERROR %s\n", GetLastErrorAsString().c_str());
			
			return ERR_OUTPUT_HANDLE;
		}
			
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
	else {
		handle.block_num++;
	}

	if ((NULL == partition || strlen(partition) <= 0) && (in->type == RAWNAND || in->type == RAWMMC) && crypto)
	{
		// Trick : Read only 0x400 to get to PRODINFO (0x4400) next time
		/*
		if ((in->type == RAWNAND && handle.readAmount == 0x4000) || (in->type == RAWMMC && handle.readAmount == (in->mmc.rawnand_lba_start - in->mmc.lba_start) * NX_EMMC_BLOCKSIZE + 0x4000))
			toRead = 0x400;
		*/

		// First iteration
		if (handle.readAmount == 0) {
			nextPartition = in->firstPartion;
			curPartition = NULL;
			do_crypto = false;
		}

		// When current partition ends
		if (do_crypto && NULL != curPartition && handle.off_start + handle.readAmount >= ((u64)curPartition->lba_end * NX_EMMC_BLOCKSIZE + NX_EMMC_BLOCKSIZE)) {
			do_crypto = false;
		}

		// When next partition beggins
		if (NULL != nextPartition && handle.off_start + handle.readAmount == (u64)nextPartition->lba_start * NX_EMMC_BLOCKSIZE)
		{
			if (DEBUG_MODE)
				printf("SWITCH TO %s, offset %s\n", nextPartition->name, int_to_hex(handle.readAmount).c_str());

			// Set new current/next
			curPartition = nextPartition;
			nextPartition = curPartition->next;

			// Do we need to use crypto ?
			// Encrypt only native encrypted partitions
			do_crypto = ((handle.encrypt && !curPartition->isEncrypted && (strcmp(curPartition->name, "PRODINFO") == 0 ||
				strcmp(curPartition->name, "PRODINFOF") == 0 || strcmp(curPartition->name, "SAFE") == 0 ||
				strcmp(curPartition->name, "USER") == 0 || strcmp(curPartition->name, "SYSTEM") == 0))) ? true : false;


			if (do_crypto)
			{

				if (setCrypto(curPartition->name) > 0)
					p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);
				else
					return ERR_CRYPTO_KEY_MISSING;

				if (DEBUG_MODE)
					printf("DO CRYPTO for %s (%s), offset %s\n", curPartition->name, curPartition->isEncrypted ? "encrypted" : "decrypted", int_to_hex(handle.readAmount).c_str());

				handle.block_num = 0;
			}
		}

		// Resize buffer if needed before switching to next partition
		/*
		if (NULL != curPartition && NULL != nextPartition && (u64)handle.readAmount + CLUSTER_SIZE > (u64)curPartition->lba_end * NX_EMMC_BLOCKSIZE + NX_EMMC_BLOCKSIZE) {
			toRead = ((u64)curPartition->lba_end * NX_EMMC_BLOCKSIZE + NX_EMMC_BLOCKSIZE) - handle.readAmount;
			if (DEBUG_MODE)
				printf("RESIZE BUFFER, new size %s \n", int_to_hex(toRead).c_str());
		}
		*/

		// Resize buffer to reach next partition next time 
		if (NULL != nextPartition && handle.off_start + handle.readAmount + toRead > (u64)nextPartition->lba_start * NX_EMMC_BLOCKSIZE)
		{
			toRead = (u64)nextPartition->lba_start * NX_EMMC_BLOCKSIZE - handle.off_start - handle.readAmount;
			if (DEBUG_MODE)
				printf("RESIZE BUFFER, new size %s \n", int_to_hex(toRead).c_str());
		}

	}
	
	// Switch to next splitted file
	else if(handle.readAmount > 0 && in->isSplitted && handle.off_start + handle.readAmount >= handle.off_max && *writeAmount < *bytesToWrite)
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
	if (!ReadFile(handle.h, buffer, toRead, &bytesRead, NULL))
	{
		delete[] buffer;
		return ERR_WHILE_COPY;
	}

	if (bytesRead == 0)
		return NO_MORE_BYTES_TO_COPY;

	*readAmount += bytesRead;
	handle.readAmount += bytesRead;


	// Encrypt data
	if(do_crypto)
	{
		p_crypto->encrypt(buffer, handle.block_num);
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
		memcpy(wbuffer, &buffer[0], bytesRead);
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

	DWORD toRead = DEFAULT_BUFF_SIZE;

	// First iteration
	if (handle.readAmount == 0)
	{
		do_crypto = false;

		// Default input is self object path
		wcscpy(handle.path, pathLPWSTR);
		//handle.path = this->pathLPWSTR;

		if (out->crypto)
			handle.encrypt = true;
		else if (crypto)
			handle.decrypt = true;

        if(NULL == partition || strlen(partition) <= 0)
        {
            if (handle.decrypt && !isEncrypted)
                return ERR_CRYPTO_NOT_ENCRYPTED;

            if (handle.encrypt && isEncrypted)
                return ERR_CRYPTO_ENCRYPTED_YET;
        }

		if (handle.decrypt && bad_crypto)
			return ERROR_DECRYPT_FAILED;
			
 
		handle.readAmount = 0;
		handle.block_num = 0;

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

					// Init crypto
					if ((part->isEncrypted && handle.decrypt) || (!part->isEncrypted && handle.encrypt))
					{
						if (setCrypto(partition) > 0)
							p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), DEFAULT_BUFF_SIZE);
						else
							return ERR_CRYPTO_KEY_MISSING;

						do_crypto = true;
						if (DEBUG_MODE) printf("DO CRYPTO FOR %\n", type == PARTITION ? partitionName : partition);
					}
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
			// Init crypto
			if (type == PARTITION && ((isEncrypted && handle.decrypt) || (!isEncrypted && handle.encrypt)))
			{
				if (setCrypto(partitionName) > 0)
					p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), DEFAULT_BUFF_SIZE);
				else
					return ERR_CRYPTO_KEY_MISSING;

				do_crypto = true;
				if (DEBUG_MODE) printf("DO CRYPTO FOR %\n", type == PARTITION ? partitionName : partition);
			}

			handle.off_start = 0;
			if (type == RAWMMC)
				handle.off_start = mmc.boot0_lba_start * NX_EMMC_BLOCKSIZE;

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
	else {
		handle.block_num++;
	}

	// Switch to next splitted file
	if(handle.readAmount > 0 && isSplitted && handle.off_start + handle.readAmount >= handle.off_max && *writeAmount < *bytesToWrite)
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

    if ((NULL == partition || strlen(partition) == 0) && (type == RAWNAND || type == RAWMMC) && crypto)
	{
		// Trick : Read only 0x400 to get to PRODINFO (0x4400) next time
		/*
		if (handle.readAmount == 0x4000 && type == RAWNAND)
			toRead = 0x400;
		*/

		// First iteration
		if (handle.readAmount == 0) {
			nextPartition = firstPartion;
			curPartition = NULL;
			do_crypto = false;
		}


		// When current partition ends
		if (do_crypto && NULL != curPartition && handle.off_start + handle.readAmount >= ((u64)curPartition->lba_end * NX_EMMC_BLOCKSIZE + NX_EMMC_BLOCKSIZE)) {
			do_crypto = false;
		}		

		// When next partition beggins
		if (NULL != nextPartition && handle.off_start + handle.readAmount == (u64)nextPartition->lba_start * NX_EMMC_BLOCKSIZE)
		{
			if (DEBUG_MODE)
				printf("SWITCH TO %s, offset %s\n", nextPartition->name, int_to_hex(handle.readAmount).c_str());
			
			// Set new current/next
			curPartition = nextPartition;
			nextPartition = curPartition->next;
			
			// Do we need to use crypto ?
			// Encrypt only native encrypted partitions
			do_crypto = ((handle.encrypt && !curPartition->isEncrypted && (strcmp(curPartition->name, "PRODINFO") == 0 ||
						  strcmp(curPartition->name, "PRODINFOF") == 0 || strcmp(curPartition->name, "SAFE") == 0 ||
						  strcmp(curPartition->name, "USER") == 0 || strcmp(curPartition->name, "SYSTEM") == 0))
						  || (handle.decrypt && curPartition->isEncrypted)) ? true : false;

			if (do_crypto)
			{				
				if (handle.decrypt && curPartition->bad_crypto)
					return ERROR_DECRYPT_FAILED;

				if (setCrypto(curPartition->name) > 0)
					p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);
				else
					return ERR_CRYPTO_KEY_MISSING;

				if (DEBUG_MODE) 
					printf("DO CRYPTO for %s (%s), offset %s\n", curPartition->name, curPartition->isEncrypted ? "encrypted" : "decrypted", int_to_hex(handle.readAmount).c_str());

				handle.block_num = 0;
			}
		}

		// Resize buffer to reach next partition next time 
		if (NULL != nextPartition && handle.off_start + handle.readAmount + toRead > (u64)nextPartition->lba_start * NX_EMMC_BLOCKSIZE)
		{
			toRead = (u64)nextPartition->lba_start * NX_EMMC_BLOCKSIZE - handle.off_start - handle.readAmount;
			if (DEBUG_MODE)
				printf("RESIZE BUFFER, new size %s \n", int_to_hex(toRead).c_str());
		}
		/*
		// Resize buffer if needed before switching to next partition
		if (NULL != curPartition && NULL != nextPartition && (u64)handle.off_start + handle.readAmount + CLUSTER_SIZE > (u64)curPartition->lba_end * NX_EMMC_BLOCKSIZE + NX_EMMC_BLOCKSIZE) {
			toRead = ((u64)curPartition->lba_end * NX_EMMC_BLOCKSIZE + NX_EMMC_BLOCKSIZE) - handle.off_start - handle.readAmount;
			if (DEBUG_MODE)
				printf("RESIZE BUFFER, new size %s \n", int_to_hex(toRead).c_str());
		}
		*/
	}
	
	*bytesToWrite = bytesToRead;

	if (*writeAmount >= *bytesToWrite)
		return NO_MORE_BYTES_TO_COPY;

	// Read
	BYTE *buffer = new BYTE[DEFAULT_BUFF_SIZE];
	DWORD bytesRead = 0, bytesWrite = 0, bytesWritten = 0;
	if (!ReadFile(handle.h, buffer, toRead, &bytesRead, NULL))
	{
		delete[] buffer;
		return ERR_WHILE_COPY;
	}

	if (bytesRead == 0)
		return NO_MORE_BYTES_TO_COPY;

	*readAmount += bytesRead;
	handle.readAmount += bytesRead;

	// Decrypt
	if(handle.decrypt && do_crypto)
	{
		p_crypto->decrypt(buffer, handle.block_num);
	}
	// Encrypt
	else if (handle.encrypt && do_crypto)
		p_crypto->encrypt(buffer, handle.block_num);
	
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
		memcpy(wbuffer, &buffer[0], bytesRead);
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
	case RAWMMC:
		return "FULL EMMC";
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
	if (type != BOOT0 && type != RAWMMC)
		return false;

	HANDLE hStorage;
	hStorage = CreateFileW(pathLPWSTR, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (hStorage == INVALID_HANDLE_VALUE)
		return false;

	u64 offset = 0;
	if (type == RAWMMC)
		offset = mmc.boot0_lba_start * NX_EMMC_BLOCKSIZE;
	offset += 0x200;

	DWORD dwPtr = SetFilePointer(hStorage, offset, NULL, FILE_BEGIN);
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


		dwPtr = SetFilePointer(hStorage, offset, NULL, FILE_BEGIN);
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

	if (DEBUG_MODE) printf("FAT32 read partition %s\n", partition ? partition : partitionName);

	do_crypto = false;

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

	// readCluster auto func
	auto readCluster = [this](BYTE *buffer, u64 offset) -> int {

		DWORD bytesRead = 0;

		LARGE_INTEGER liDistanceToMove;
		liDistanceToMove.QuadPart = handle.off_start + offset;
		if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
			return ERR_INPUT_HANDLE;

		if (!ReadFile(handle.h, buffer, CLUSTER_SIZE, &bytesRead, NULL))
			return ERR_WHILE_COPY;

		if (do_crypto)
			p_crypto->decrypt(buffer, offset / CLUSTER_SIZE);

		return bytesRead;
	};

	// Parse dir table auto func
	auto parseDirTable = [this](BYTE *buffer, fat32_dir_entry *parentEntry = NULL) -> fat32_dir_entry* {
		fat32_dir_entry *p_rootdir_tmp = NULL, *first_entry = NULL;
		int buf_off = 0, lfn_length = 0;

		while (buf_off < CLUSTER_SIZE)
		{
			fat32_entry dir;
			memcpy(&dir, &buffer[buf_off], 32);

			if (dir.filename[0] == 0x00 || dir.reserved != 0x00)
				break;

			if (dir.attributes == 0x0F)
				lfn_length++;

			if ((dir.attributes == 0x10 && dir.filename[0] != 0x2E) || dir.attributes == 0x20 || dir.attributes == 0x30) {

				// Create to new entry
				fat32_dir_entry *rootdir = new fat32_dir_entry();
				memcpy(&rootdir->entry, &dir, 0x20);

				if (dir.attributes == 0x10)
					rootdir->is_directory = true;

				// Get filename 
				rootdir->filename = dir.filename;
				if (lfn_length > 0)
					rootdir->filename = get_longfilename(buffer, buf_off, lfn_length);

				// Set pointer to next entry
				if (NULL != p_rootdir_tmp)
					p_rootdir_tmp->next = rootdir;

				// Save first pointer
				if (NULL == first_entry)
					first_entry = rootdir;

				p_rootdir_tmp = rootdir;


				// Look for specific filenames

				// If NCA file found
				unsigned char ext[3];
				memcpy(&ext, &dir.filename[8], 3);
				if (strcmp(hexStr(ext, 3).c_str(), "4E4341") == 0)
				{

					//if (DEBUG_MODE) printf("%s (off %s)\n", filename.c_str(), int_to_hex((int)dir_off + i).c_str());

					// Look for firmware version
					for (int l = 0; l < (int)array_countof(sytemTitlesArr); l++)
					{
						if (rootdir->filename.compare(std::string(sytemTitlesArr[l].nca_filename)) == 0)
						{							
							memcpy(&fw_version, &sytemTitlesArr[l].fw_version, strlen(sytemExFatTitlesArr[l].fw_version));
							if (DEBUG_MODE) printf("firmware version found searching nca (%s)", fw_version);
							fw_detected = true;
						}
					}

					// Look for exFat driver
					for (int l = 0; l < (int)array_countof(sytemExFatTitlesArr); l++)
					{
						if (rootdir->filename.compare(std::string(sytemExFatTitlesArr[l].nca_filename)) == 0)
						{
							if (!fw_detected) {
								memcpy(&fw_version, &sytemExFatTitlesArr[l].fw_version, strlen(sytemExFatTitlesArr[l].fw_version));
								if (DEBUG_MODE) printf("firmware version found searching nca [exFat] (%s)", fw_version);
							}
							exFat_driver = true;
						}
					}
				}
				// Get last boot time from /save/8000000000000060
				if (NULL != parentEntry && rootdir->filename.compare(0, 16, "8000000000000060") == 0
					&& hexStr(reinterpret_cast<unsigned char*>(parentEntry->entry.filename), 5).compare("5341564520") == 00)
				{
					sprintf(last_boot, "%02d/%02d/%04d %02d:%02d:%02d",
						rootdir->entry.modified_date & 0x1f,
						(rootdir->entry.modified_date >> 5) & 0xf,
						1980 + (rootdir->entry.modified_date >> 9),
						rootdir->entry.modified_time >> 11,
						(rootdir->entry.modified_time >> 5) & 0x3f,
						rootdir->entry.modified_time & 0x1f);
				}

				// Get address of journal report (/save/80000000000000d1)
				if (NULL != parentEntry && rootdir->filename.compare(0, 16, "80000000000000d1") == 0
					&& hexStr(reinterpret_cast<unsigned char*>(parentEntry->entry.filename), 5).compare("5341564520") == 00) // parent is "/save" (hex val)
				{
					journal_report_off = fs.bytes_per_sector * ((rootdir->entry.first_cluster - 2) * fs.sectors_per_cluster) + (fs.num_fats * fs.fat_size * fs.bytes_per_sector) + (fs.reserved_sector_count * fs.bytes_per_sector);
					journal_report_off_end = journal_report_off + rootdir->entry.file_size;

					//if (DEBUG_MODE) printf("/save/80000000000000d1 ENDS AT %s\n", int_to_hex(journal_report_off + rootdir->entry.file_size).c_str());
				}

				// Get address of play report (/save/80000000000000a1)
				if (NULL != parentEntry && rootdir->filename.compare(0, 16, "80000000000000a1") == 0
					&& hexStr(reinterpret_cast<unsigned char*>(parentEntry->entry.filename), 5).compare("5341564520") == 00) // parent is "/save" (hex val)
				{
					play_report_off = fs.bytes_per_sector * ((rootdir->entry.first_cluster - 2) * fs.sectors_per_cluster) + (fs.num_fats * fs.fat_size * fs.bytes_per_sector) + (fs.reserved_sector_count * fs.bytes_per_sector);
					play_report_off_end = play_report_off + rootdir->entry.file_size;
					
					//if (DEBUG_MODE) printf("/save/80000000000000a1 ENDS AT %s\n", int_to_hex(play_report_off + rootdir->entry.file_size).c_str());
				}
			}

			if (dir.attributes != 0x0F)
				lfn_length = 0;

			buf_off += 32;
		}

		return first_entry;
	};

	BYTE *buffer = new BYTE[CLUSTER_SIZE];

	// Read first cluster
	readCluster(buffer, 0);

	// Check whether to use crypto or not
	if (!ValidateDecryptBuf(buffer, NULL != partition ? partition : partitionName))
	{
		if (!crypto)
			return ERR_CRYPTO_KEY_MISSING;

		int rc = setCrypto(partition ? partition : partitionName);
		if (rc <= 0)
			return rc;

		p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);

		p_crypto->decrypt(buffer, 0);

		if (!ValidateDecryptBuf(buffer, partition ? partition : partitionName))
		{
			delete p_crypto;
			return ERR_DECRYPT_CONTENT;
		}
		
		do_crypto = true;
	}	

	// Get FS attributes
	fat32_read_attr(buffer, &fs);
	u64 root_addr = (fs.num_fats * fs.fat_size * fs.bytes_per_sector) + (fs.reserved_sector_count * fs.bytes_per_sector);
	int num_cluster = root_addr / CLUSTER_SIZE;

	int buf_off = 0, nca_found = 0, lfn_length = 0;;
	u64 contents_off = 0, regist_off = 0, save_off = 0, save06_off, cur_offset = root_addr;

	// Read root cluster
	readCluster(buffer, root_addr);
	if (DEBUG_MODE) printf("Root Directory Region offset = %s \n", int_to_hex(root_addr).c_str());

	// Parse root directory
	fat32_dir_entry *rootdir_first_entry = parseDirTable(buffer);
	if (NULL == rootdir_first_entry)
		return -1;

	auto printEntry = [this](fat32_dir_entry *cur_entry, fs_attr fs, u64 root_addr) -> int {
        //if (!DEBUG_MODE)
			return 1;

		char str_buff[20];
		//u64 off = fs.bytes_per_sector * ((cur_entry->entry.first_cluster - 2) * fs.sectors_per_cluster) +  (fs.num_fats * fs.fat_size * fs.bytes_per_sector) + (fs.reserved_sector_count * fs.bytes_per_sector);
		u64 off = fs.bytes_per_sector * ((cur_entry->entry.first_cluster - 2) * fs.sectors_per_cluster) + root_addr;
		sprintf(str_buff, "%02d/%02d/%04d %02d:%02d:%02d",
			cur_entry->entry.modified_date & 0x1f,
			(cur_entry->entry.modified_date >> 5) & 0xf,
			1980 + (cur_entry->entry.modified_date >> 9),
			cur_entry->entry.modified_time >> 11,
			(cur_entry->entry.modified_time >> 5) & 0x3f,
			cur_entry->entry.modified_time & 0x1f);

		printf("%s %-40s %s %-10s first_data_off %s\n", 
			cur_entry->is_directory ? "=>" : "  ",
			cur_entry->filename.c_str(), 
			str_buff,
			cur_entry->entry.file_size > 0 ? GetReadableSize(cur_entry->entry.file_size).c_str() : "",
			int_to_hex(off).c_str());
		return 1;
	};

	// Parse subdir entries
	fat32_dir_entry *cur_entry = rootdir_first_entry;
	while (NULL != cur_entry)
	{		
		printEntry(cur_entry, fs, root_addr);
		
		// Read first cluster
		u64 fcluster_off = fs.bytes_per_sector * ((cur_entry->entry.first_cluster - 2) * fs.sectors_per_cluster) + root_addr;
		if (cur_entry->is_directory && readCluster(buffer, fcluster_off) > 0) {
			
			cur_entry->subdir = parseDirTable(buffer, cur_entry);

			// Second level subdir parsing
			fat32_dir_entry *s_cur_entry = cur_entry->subdir;
			BYTE *s_buffer = new BYTE[CLUSTER_SIZE];
			while (NULL != s_cur_entry) {

				printEntry(s_cur_entry, fs, root_addr);
				u64 s_fcluster_off = fs.bytes_per_sector * ((s_cur_entry->entry.first_cluster - 2) * fs.sectors_per_cluster) + root_addr;
				
				if (s_cur_entry->is_directory && readCluster(s_buffer, s_fcluster_off) > 0) {

					s_cur_entry->subdir = parseDirTable(s_buffer, s_cur_entry);

					if(DEBUG_MODE && NULL != s_cur_entry->subdir) {
						fat32_dir_entry *ss_cur_entry = s_cur_entry->subdir;
						while (NULL != ss_cur_entry) {
							printEntry(ss_cur_entry, fs, root_addr);
							ss_cur_entry = ss_cur_entry->next;
						}
					}

				}
				s_cur_entry = s_cur_entry->next;
			}
			
			delete s_buffer;
		}
		cur_entry = cur_entry->next;
	}	


	// Check for firmare version in play report
    bool search_fmw = FALSE, report_based_fwm = FALSE;
    if (play_report_off > 0 && readCluster(buffer, play_report_off) > 0)
	{
		search_fmw = true;

		if (DEBUG_MODE) printf("Searching patterns in PLAY REPORTS at offset %s\n", int_to_hex(play_report_off).c_str());
		u64 cur_off = play_report_off + CLUSTER_SIZE;
		s8 fwv[10]  = { 0 }; 
		while (cur_off < play_report_off_end) {

			std::string haystack(buffer, buffer + CLUSTER_SIZE);
			std::size_t n;

			n = haystack.find("os_version");
			if (n != std::string::npos) {

				strcpy(fwv, haystack.substr(n + 11, 5).c_str());								
				if (strcmp(fwv, fw_version) > 0)
				{
					if(DEBUG_MODE) printf("Newer firmware version found in PLAY REPORTS (%s) \n", fwv);
					memcpy(fw_version, fwv, 5);		
					fw_detected = true;
                    report_based_fwm = true;
				}					
			}

			// Read next cluster
			if(readCluster(buffer, cur_off) > 0) cur_off += CLUSTER_SIZE;
			else break;
		}
	}

	// Check for firmware version in journal
	if (journal_report_off > 0 && (search_fmw || strlen(serial_number) <= 3 ) && readCluster(buffer, journal_report_off) > 0)
	{        
		if (DEBUG_MODE) printf("Searching patterns in JOURNAL at offset %s\n", int_to_hex(journal_report_off).c_str());

		u64 cur_off = journal_report_off + CLUSTER_SIZE;
		s8 fwv[10] = { 0 };

		while (cur_off < journal_report_off_end) {

			std::string haystack(buffer, buffer + CLUSTER_SIZE);
			std::size_t n;

			if (search_fmw)
			{
				n = haystack.find("OsVersion");
				if (n != std::string::npos) {

					strcpy(fwv, haystack.substr(n + 10, 5).c_str());
					if (strcmp(fwv, fw_version) > 0)
					{
						if (DEBUG_MODE) printf("Newer firmware version found in JOURNAL (%s) \n", fwv);
						memcpy(fw_version, fwv, 5);
						fw_detected = true;
                        report_based_fwm = true;
					}
				}
			}

			if (strlen(serial_number) <= 3)
			{				
				n = haystack.find("\xACSerialNumber");
				if (n != std::string::npos) {
					strcpy(serial_number, haystack.substr(n + 14, 14).c_str());
					if (DEBUG_MODE) printf("Serial Number found in JOURNAL (%s) \n", serial_number);

					if (!search_fmw)
						break;
				}
			}

			// Read next cluster
			if (readCluster(buffer, cur_off) > 0) cur_off += CLUSTER_SIZE;
			else break;
		}
	}

    if (report_based_fwm && search_fmw)
		strcat(fw_version, " (or higher)");

	if (NULL != p_crypto)
		delete p_crypto;

	delete buffer;

	ClearHandles();
	return 1;
}

// Get FAT32 long filename
std::string NxStorage::get_longfilename(BYTE *buffer, int offset, int length) {
	unsigned char filename[40];
	int x = 0;
	for (int j = 1; j <= length; j++)
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

	if(DEBUG_MODE) printf("PRODINFO read\n");
	if(type == RAWNAND || type == RAWMMC)
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
		if (SetFilePointerEx(handle.h, liDistanceToMove, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			ClearHandles();
			if (DEBUG_MODE) printf("ERROR while setting pointer to PRODINFO at offset %s \n", int_to_hex((int)handle.off_start).c_str());
			return ERR_INPUT_HANDLE;
		}
	}

	BYTE *buffer = new BYTE[CLUSTER_SIZE];
	DWORD bytesRead = 0;

	if (DEBUG_MODE) printf("PRODINFO reading at offset %s \n", int_to_hex((int)handle.off_start).c_str());

	// Read first cluster
	if (!ReadFile(handle.h, buffer, CLUSTER_SIZE, &bytesRead, NULL)) {
		ClearHandles();
		return ERR_WHILE_COPY;
	}

	bool do_crypto = false;
	if (!ValidateDecryptBuf(buffer, "PRODINFO"))
	{
		if (!crypto) {
			ClearHandles();
			return ERR_CRYPTO_KEY_MISSING;
		}
		int rc = setCrypto("PRODINFO");
		if (rc <= 0) {
			return rc;
		}

		p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);

		p_crypto->decrypt(buffer, 0);

		if (!ValidateDecryptBuf(buffer, "PRODINFO"))
		{
			delete p_crypto;
			ClearHandles();
			return ERR_DECRYPT_CONTENT;
		}		
		do_crypto = true;
	}	

	memcpy(&serial_number, &buffer[0x250], 18);
	memset(&deviceId, 0x00, 21);
	memcpy(&deviceId, &buffer[0x544], 20);
	s8 t_wlanMacAddress[7] = { 0 };
	memset(&t_wlanMacAddress, 0x00, 7);
	memcpy(&t_wlanMacAddress, &buffer[0x210], 6);

    std::string t_macAddress = hexStr(reinterpret_cast<unsigned char*>(t_wlanMacAddress), 6);
	for (std::string::size_type i = 0; i < t_macAddress.size(); i++) {
		macAddress += t_macAddress[i];
        if (i & 1 && i != t_macAddress.size() - 1) {
			macAddress.append("-");
		}
	}

	if (DEBUG_MODE) {
		printf("PRODINFO device id %s \n", deviceId);
		printf("PRODINFO wlanMacAddress %s \n", hexStr(reinterpret_cast<unsigned char*>(wlanMacAddress), 6).c_str());
	}

	if (NULL != p_crypto)
		delete p_crypto;

	ClearHandles();
	return 1;
}

GptPartition* NxStorage::GetPartitionByName(const char * partition)
{
	if (NULL == firstPartion)
		return NULL;

	GptPartition *cur = firstPartion;
	while (NULL != cur)
	{
		if (strncmp(cur->name, partition, strlen(partition)) == 0)
			return cur;
		cur = cur->next;
	}
	return NULL;
}

int NxStorage::Incognito()
{
	u64 off_start;
	GptPartition* cal0 = NULL;
	int block_num = 0;
	do_crypto = false;

	if (type == PARTITION && NULL != partitionName && strcmp(partitionName, "PRODINFO") == 0)
	{
		off_start = 0;
	}
	else if (type == RAWNAND || type == RAWMMC)
	{
		cal0 = GetPartitionByName("PRODINFO");
		if (NULL == cal0)
			return -1;

		off_start = (u64)cal0->lba_start * NX_EMMC_BLOCKSIZE;
	}
	else
	{
		return -1;
	}

	ClearHandles();
	BYTE buf1[CLUSTER_SIZE];

	// Read first cluster
	if (ReadBufferAtOffset(buf1, off_start) <= 0)
		return -1;

	if (!ValidateDecryptBuf(buf1, "PRODINFO"))
	{
		if (!crypto)
			return ERR_CRYPTO_KEY_MISSING;

		if ((NULL == cal0 && bad_crypto) || (NULL != cal0 && cal0->bad_crypto))
			return ERROR_DECRYPT_FAILED;

		if (setCrypto("PRODINFO") > 0)
			p_crypto = new xts_crypto(key_crypto.data(), key_tweak.data(), CLUSTER_SIZE);
		else
			return ERR_CRYPTO_KEY_MISSING;

		p_crypto->decrypt(buf1, block_num);

		if (!ValidateDecryptBuf(buf1, "PRODINFO"))
			return ERROR_DECRYPT_FAILED;

		do_crypto = true;

	}

	// Read cal0 data size
	uint32_t calib_data_size;
	memcpy(&calib_data_size, &buf1[0x08], 0x04);
		
	// Set new buffer for cal0 data
	BYTE *buffer = new BYTE[calib_data_size + 0x40];

	// Copy first cluster
	int buf_size = CLUSTER_SIZE;
	memcpy(&buffer[0], buf1, buf_size);		

	// Copy next cluster until calib data size is reached
	while (buf_size < (calib_data_size + 0x40))
	{
		if (ReadBufferAtOffset(buf1, off_start + buf_size) <= 0)
			return -1;

		block_num++;
		if(do_crypto)
			p_crypto->decrypt(buf1, block_num);

		memcpy(&buffer[buf_size], buf1, CLUSTER_SIZE);
		buf_size += CLUSTER_SIZE;
	}

	uint32_t cert_size;
	memcpy(&cert_size, &buffer[0x0AD0], 0x04);
		

	if (DEBUG_MODE) printf("CAL0, wiping out S/N, client cert, private key, device id, device cert & device key (incognito)\n");

	memset(&buffer[0x0AE0], 0, 0x800);  // client cert
	memset(&buffer[0x3AE0], 0, 0x130);  // private key
	memset(&buffer[0x35E1], 0, 0x006);  // deviceId
	memset(&buffer[0x36E1], 0, 0x006);  // deviceId
	memset(&buffer[0x02B0], 0, 0x180);  // device cert
	memset(&buffer[0x3D70], 0, 0x240);  // device cert
	memset(&buffer[0x3FC0], 0, 0x240);  // device key

	const char junkSerial[] = "XAW00000000000";
	memcpy(&buffer[0x0250], junkSerial, strlen(junkSerial));

	// Generate new SHA256 hash for wiped cert		
	unsigned char *cert = new unsigned char[cert_size];
	memcpy(cert, &buffer[0x0AE0], cert_size);
	unsigned char hash[0x20];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, cert, cert_size);
	SHA256_Final(hash, &sha256);
	// Write new hash
	memcpy(&buffer[0x12E0], &hash[0], 0x20);
	if (DEBUG_MODE) printf("cert new hash is %s\n", hexStr(hash, 0x20).c_str());

	// Generate new SHA256 hash for calibration data
	unsigned char *calib_data = new unsigned char[calib_data_size];
	memcpy(calib_data, &buffer[0x040], calib_data_size);
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, calib_data, calib_data_size);
	SHA256_Final(hash, &sha256);
	memcpy(&buffer[0x20], &hash[0], 0x20);
	if(DEBUG_MODE) printf("cal0 new hash is %s\n", hexStr(hash, 0x20).c_str());


	// Write cal0
	int num_buff = (calib_data_size + 0x40) / CLUSTER_SIZE;
	block_num = 0;
	for (int i = 0; i < num_buff; i++)
	{	
		memcpy(buf1, &buffer[i * CLUSTER_SIZE], CLUSTER_SIZE);

		if (do_crypto)
			p_crypto->encrypt(buf1, block_num);

		if (WriteBufferAtOffset(buf1, off_start + (i * CLUSTER_SIZE)) <= 0)
			return -1;

		block_num++;
	}

	if (DEBUG_MODE) printf("Write cal0 (%d clusters)\n", num_buff);

	return 1;

}
