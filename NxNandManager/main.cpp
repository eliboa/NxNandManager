#include "NxNandManager.h"

int startGUI(int argc, char *argv[])
{
#if defined(ENABLE_GUI)
	QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
	QApplication a(argc, argv);
	MainWindow w;
	a.setStyleSheet("QMessageBox {messagebox-text-interaction-flags: 12;}");
	w.show();
	return a.exec();
#else
	throwException(ERR_INIT_GUI, "GUI unavailable. This build is CLI only");
	return -1;
#endif
}

int main(int argc, char *argv[])
{
	std::setlocale(LC_ALL, "en_US.utf8");
    printf("[ NxNandManager v2.0 ]\n\n");
	const char *input = NULL, *output = NULL, *partition = NULL, *keyset = NULL;
	BOOL info = FALSE, gui = FALSE, setAutoRCM = FALSE, autoRCM = FALSE, decrypt = FALSE, encrypt = FALSE;
	int io_num = 1;

	// Arguments, controls & usage
	auto PrintUsage = []() -> int {
		printf("usage: NxNandManager -i <inputFilename|\\\\.\\PhysicalDriveX>\n"
			"           -o <outputFilename|\\\\.\\PhysicalDrivekX> [Options] [Flags]\n\n"
			"=> Arguments:\n\n"
			"  -i                Path to input file/drive\n"
			"  -o                Path to output file/drive\n"
			"  -part=            Partition to copy (apply to both input & output if possible)\n"
			"                    Possible values are PRODINFO, PRODINFOF, SAFE, SYSTEM, USER,\n"
			"                    BCPKG2-2-Normal-Sub, BCPKG2-3-SafeMode-Main, etc. (see --info)\n\n"
			"  -d                Decrypt content (-keyset mandatory)\n"
			"  -e                Encrypt content (-keyset mandatory)\n"
			"  -keyset           Path to keyset file (bis keys)\n\n"
			"=> Options:\n\n"
			#if defined(ENABLE_GUI)
			"  --gui             Start the program in graphical mode, doesn't need other argument\n"
			#endif
			"  --list            Detect and list compatible NX physical drives (ie, mounted with memloader)\n"
			"  --info            Display information about input/output (depends on NAND type):\n"
			"                    NAND type, partitions, encryption, autoRCM status... \n"
			"                    ...more info when -keyset provided: firmware ver., S/N, last boot date\n\n"
			"  --enable_autoRCM  Enable auto RCM. -i must point to a valid BOOT0 file/drive\n"
			"  --disable_autoRCM Disable auto RCM. -i must point to a valid BOOT0 file/drive\n\n"
		);

		printf("=> Flags:\n\n"
			"                    \"BYPASS_MD5SUM\" to bypass MD5 integrity checks (faster but less secure)\n"
			   "                    \"FORCE\" to disable prompt for user input (no question asked)\n");

		throwException(ERR_WRONG_USE);
		return -1;
	};

	if (argc == 1)
	{
#if defined(ENABLE_GUI)
		printf("No argument specified. Switching to GUI mode...\n");
		PROCESS_INFORMATION pi;
		STARTUPINFO si;
		BOOL ret = FALSE;
		DWORD flags = CREATE_NO_WINDOW;
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&si, sizeof(STARTUPINFO));
		si.cb = sizeof(STARTUPINFO);
		wchar_t buffer[_MAX_PATH];
		GetModuleFileName(GetCurrentModule(), buffer, _MAX_PATH);
		wstring module_path(buffer);
		module_path.append(L" --gui");
		ret = CreateProcess(NULL, &module_path[0], NULL, NULL, NULL, flags, NULL, NULL, &si, &pi);
		exit(EXIT_SUCCESS);
#else
		PrintUsage();
#endif
	}

	const char GUI_ARGUMENT[] = "--gui";
	const char INPUT_ARGUMENT[] = "-i";
	const char OUTPUT_ARGUMENT[] = "-o";
	const char PARTITION_ARGUMENT[] = "-part";
	const char INFO_ARGUMENT[] = "--info";
	const char LIST_ARGUMENT[] = "--list";
	const char AUTORCMON_ARGUMENT[] = "--enable_autoRCM";
	const char AUTORCMOFF_ARGUMENT[] = "--disable_autoRCM";
	const char BYPASS_MD5SUM_FLAG[] = "BYPASS_MD5SUM";
	const char DEBUG_MODE_FLAG[] = "DEBUG_MODE";
	const char FORCE_FLAG[] = "FORCE";
	const char KEYSET_ARGUMENT[] = "-keyset";
	const char DECRYPT_ARGUMENT[] = "-d";
	const char ENCRYPT_ARGUMENT[] = "-e";

	for (int i = 1; i < argc; i++)
	{
		char* currArg = argv[i];
		if ((strncmp(currArg, AUTORCMON_ARGUMENT, array_countof(AUTORCMON_ARGUMENT) - 1) == 0 && setAutoRCM == true) || (strncmp(currArg, AUTORCMOFF_ARGUMENT, array_countof(AUTORCMOFF_ARGUMENT) - 1) == 0 && setAutoRCM  == true))
		{
			printf("Arguments (--enable_autoRCM) and (--disable_autoRCM) cannot be used at the same time.\n\n");
			PrintUsage();
		}
		if (strncmp(currArg, LIST_ARGUMENT, array_countof(LIST_ARGUMENT) - 1) == 0)
		{
			LIST = TRUE;
		} else if (strncmp(currArg, GUI_ARGUMENT, array_countof(GUI_ARGUMENT) - 1) == 0)
		{
			gui = TRUE;
		} else if (strncmp(currArg, INPUT_ARGUMENT, array_countof(INPUT_ARGUMENT) - 1) == 0 && i < argc)
		{
			input = argv[++i];
		} else if (strncmp(currArg, OUTPUT_ARGUMENT, array_countof(OUTPUT_ARGUMENT) - 1) == 0 && i < argc)
		{
			output = argv[++i];
		} else if (strncmp(currArg, PARTITION_ARGUMENT, array_countof(PARTITION_ARGUMENT) - 1) == 0)
		{
			u32 len = array_countof(PARTITION_ARGUMENT) - 1;
			if (currArg[len] == '=')
			{
				partition = &currArg[len + 1];
			} else if (currArg[len] == 0)
			{
				if (i == argc - 1) return PrintUsage();
			}
		} else if (strncmp(currArg, INFO_ARGUMENT, array_countof(INFO_ARGUMENT) - 1) == 0)
		{
			info = TRUE;
		} else if (strncmp(currArg, AUTORCMON_ARGUMENT, array_countof(AUTORCMON_ARGUMENT) - 1) == 0)
		{
			setAutoRCM = TRUE;
			autoRCM = TRUE;
		} else if (strncmp(currArg, AUTORCMOFF_ARGUMENT, array_countof(AUTORCMOFF_ARGUMENT) - 1) == 0)
		{
			setAutoRCM = TRUE;
			autoRCM = FALSE;
		} else if (strncmp(currArg, BYPASS_MD5SUM_FLAG, array_countof(BYPASS_MD5SUM_FLAG) - 1) == 0)
		{
			BYPASS_MD5SUM = TRUE;
		} else if (strncmp(currArg, DEBUG_MODE_FLAG, array_countof(DEBUG_MODE_FLAG) - 1) == 0)
		{
			DEBUG_MODE = TRUE;
		} else if (strncmp(currArg, FORCE_FLAG, array_countof(FORCE_FLAG) - 1) == 0)
		{
			FORCE = TRUE;
		} else if (strncmp(currArg, KEYSET_ARGUMENT, array_countof(KEYSET_ARGUMENT) - 1) == 0 && i < argc)
		{
			keyset = argv[++i];
		} else if (strncmp(currArg, DECRYPT_ARGUMENT, array_countof(DECRYPT_ARGUMENT) - 1) == 0)
		{
			decrypt = TRUE;
		} else if (strncmp(currArg, ENCRYPT_ARGUMENT, array_countof(ENCRYPT_ARGUMENT) - 1) == 0)
		{
			encrypt = TRUE;
		} else {
			printf("Argument (%s) is not allowed.\n\n", currArg);
			PrintUsage();
		}
	}

	if (gui)
	{
		startGUI(argc, argv);
		return 0;
	}

	if (LIST && !gui)
	{
		printf("%s", ListPhysicalDrives().c_str());
		exit(EXIT_SUCCESS);
	}

	if (NULL == input || (NULL == output && !info && !setAutoRCM ))
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
	
	KeySet biskeys;
	bool do_crypto = false;
	if(decrypt || encrypt || NULL != keyset) {

		if(!parseKeySetFile(keyset, &biskeys))
		{
			printf("Error while parsing keyset file.\n");
			exit(EXIT_FAILURE);
		}

		if (encrypt || decrypt || (NULL != keyset && info))
			do_crypto = true;
			
		if (DEBUG_MODE)
		{
			printf("BIS 0 CRYPT=%s\n", biskeys.crypt0);
			printf("BIS 0 TWEAK=%s\n", biskeys.tweak0);
			printf("BIS 1 CRYPT=%s\n", biskeys.crypt1);
			printf("BIS 1 TWEAK=%s\n", biskeys.tweak1);
			printf("BIS 2 CRYPT=%s\n", biskeys.crypt2);
			printf("BIS 2 TWEAK=%s\n", biskeys.tweak2);
			printf("BIS 3 CRYPT=%s\n", biskeys.crypt3);
			printf("BIS 3 TWEAK=%s\n", biskeys.tweak3);
		}			
	}

	printf("Accessing input...\r");
	NxStorage nxdata(input, (do_crypto) ? &biskeys : NULL, DEBUG_MODE);
	printf("Accessing output...\r");
	NxStorage nxdataOut(output, (do_crypto && encrypt) ? &biskeys : NULL, DEBUG_MODE);
	printf("                      \r");

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

	if(setAutoRCM)
	{
		if(NULL != output)
		{
			printf("Output is forbidden when %s argument is provided", autoRCM ? "--enable_autoRCM" : "--disable_autoRCM");
			throwException(ERR_WRONG_USE);
		}
		if(nxdata.type != BOOT0)
			throwException("Input must be a valid BOOT0 file/drive");

		if(!nxdata.setAutoRCM(autoRCM))
		{
			printf("Failed to %s autoRCM", autoRCM ? "enable" : "disable");
			throwException();
		}
		else
		{
			printf("Done. autoRCM is %s. \nSwitching to --info mode\n\n", autoRCM ? "enabled" : "disabled");
			info = TRUE;
			nxdata.InitStorage();
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
			printf("NAND type      : %s%s%s%s\n", curNxdata->GetNxStorageTypeAsString(),
				curNxdata->type == PARTITION ? " " : "", curNxdata->type == PARTITION ? curNxdata->partitionName : "",
				curNxdata->isSplitted ? " (splitted dump)" : "");
			printf("File/Disk      : %s\n", curNxdata->isDrive ? "Disk" : "File");
			printf("Encrypted      : %s%s\n", curNxdata->isEncrypted ? "Yes" : "No", 
				curNxdata->type != RAWNAND && curNxdata->isEncrypted && curNxdata->bad_crypto ? "  !!! DECRYPTION FAILED !!!" : "");
			if (curNxdata->type == BOOT0) printf("AutoRCM        : %s\n", curNxdata->autoRcm ? "ENABLED" : "DISABLED");
			printf("Size	       : %s\n", GetReadableSize(curNxdata->size).c_str());
			if(curNxdata->type == BOOT0)
				printf("Bootloader ver.: %d\n", static_cast<int>(curNxdata->bootloader_ver));
			if(curNxdata->fw_detected)
			{
				printf("Firmware ver.  : %s\n", curNxdata->fw_version);
				if(curNxdata->exFat_driver) printf("ExFat driv.: Detected\n");
			}
			if (strlen(curNxdata->last_boot) > 0)
				printf("Last boot      : %s\n", curNxdata->last_boot);

			if (strlen(curNxdata->serial_number) > 3)
				printf("Serial number  : %s\n", curNxdata->serial_number);

			if (NULL != curNxdata->firstPartion)
			{
				int i = 0;
				GptPartition *cur = curNxdata->firstPartion;
				while (NULL != cur)
				{
					u64 size = ((u64)cur->lba_end - (u64)cur->lba_start) * (int)NX_EMMC_BLOCKSIZE;														 
					printf("%s%02d %s  (%s)%s\n", i == 1 ? "\nPartitions     : \n                 " : "                 ", ++i, 
						cur->name, GetReadableSize(size).c_str(), cur->isEncrypted && cur->bad_crypto ? "  !!! DECRYPTION FAILED !!!" : "");

					cur = cur->next;
				}
			}
			if (curNxdata->type == RAWNAND) {
				if (curNxdata->backupGPTfound)
				{
					printf("Backup GPT     : FOUND (offset 0x%s)\n", n2hexstr((u64)curNxdata->size - NX_EMMC_BLOCKSIZE, 8).c_str());
				} else {
					printf("Backup GPT     : /!\\ Missing or invalid !!!\n");
				}			

			}
			printf("\n");

			if (curNxdata->bad_crypto)
				exit(ERROR_DECRYPTION_FAILED);
		}
		// If there's nothing left to do, exit (we don't want to pursue with i/o operations)
		exit(EXIT_SUCCESS);
	}

	if (NULL == output || nxdata.size == 0) // Nothing to copy from/to
		exit(EXIT_SUCCESS);

	// COPY TO FILE
	if (!nxdataOut.isDrive)
	{
		if (NULL != partition && !nxdata.IsValidPartition(partition) && nxdata.type != PARTITION)
		{
			if (!FORCE)
			{
				if (!AskYesNoQuestion("Unable to detect partition from input. Continue anyway (full dump) ?"))
				{
					throwException("Operation canceled\n");
				}
				partition = NULL;
			} else
			{
				throwException(ERR_INVALID_PART, "No partition detected for input, you can't continue in force mode for security reason.");
			}
		}
		if (nxdataOut.size > 0 && !FORCE)
		{
			// Output file already exists
			char question[256];
			if(nxdataOut.type == RAWNAND || nxdataOut.type == BOOT0 || nxdataOut.type == BOOT1)
				sprintf(question, "Output is an existing %s file. Do you want to restore from input ?", nxdataOut.GetNxStorageTypeAsString());
			else
				sprintf(question,"Output file already exists. Do you want to overwrite it ?");
			if (!AskYesNoQuestion(question))
			{
				throwException("Operation cancelled.\n");
			}
		}
	}

	// RESTORE TO PHYSICAL DRIVE
	if (nxdataOut.isDrive)
	{
		// Output must RAWNAND type
		if (nxdataOut.type != RAWNAND && nxdataOut.type != BOOT0 && nxdataOut.type != BOOT1)
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
			}
			else
			{
				// -part arg set as input file partition
				partition = nxdata.partitionName;
			}
		}
		printf("\nYOU ARE ABOUT TO COPY DATA TO A PHYSICAL DRIVE\n"
			   "			BE VERY CAUTIOUS !!!\n\n");
		// If partition argument is specified
		if (NULL != partition)
		{
			u64 part_size = -1;
			// Partition MUST exists in input stream (if RAWNAND)
			if (nxdata.type == RAWNAND)
			{
				part_size = nxdata.IsValidPartition(partition);
				if (part_size < 0)
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
		}
		else
		{
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
				}
				else
				{
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

	// Let's copy
	u64 bytesToRead = nxdata.size, readAmount = 0, writeAmount = 0;
	int rc, percent;

	// Restore to valid Nx Storage type
	if (nxdataOut.type == RAWNAND || nxdataOut.type == BOOT0 || nxdataOut.type == BOOT1)
	{
		if (!BYPASS_MD5SUM)
			printf("Restoring to existing storage => MD5 verification is bypassed\n");

		while (rc = nxdataOut.RestoreFromStorage(&nxdata, partition, &readAmount, &writeAmount, &bytesToRead))
		{
			if (rc < 0)
				break;

			int percent2 = (u64)writeAmount * 100 / (u64)bytesToRead;
			if (percent2 > percent)
			{
				percent = percent2;
				printf("Restoring from input %s (type: %s%s%s) to output %s (type: %s%s%s)... (%d%%) \r",
					   nxdata.isDrive ? "drive" : "file",
					   nxdata.GetNxStorageTypeAsString(), nxdata.size != bytesToRead && NULL != partition ? ", partition: " : "",
					   nxdata.size != bytesToRead && NULL != partition ? partition : "",
					   nxdataOut.isDrive ? "drive" : "file",
					   nxdataOut.GetNxStorageTypeAsString(), nxdataOut.size != bytesToRead && NULL != partition ? ", partition: " : "",
					   nxdataOut.size != bytesToRead && NULL != partition ? partition : "",
					   percent);
			}
		}
		printf("\n");
		if (rc != NO_MORE_BYTES_TO_COPY)
		{
			throwException(rc);
		}
		else if (writeAmount != bytesToRead)
		{
			printf("ERROR : %I64d bytes to read but %I64d bytes written", bytesToRead, writeAmount);
			throwException();
		}
		else
		{
			printf("Done! %s restored to %s", GetReadableSize(writeAmount).c_str(), nxdataOut.GetNxStorageTypeAsString());
		}
		nxdataOut.ClearHandles();
	}
	// Dump to file
	else
	{
		// Crypto
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0, hHash_out = 0;
		CHAR rgbDigits[] = "0123456789abcdef";
		std::string md5hash, md5hashOut;
		DWORD cbHash = MD5LEN;
		BYTE rgbHash[MD5LEN];

		if (!BYPASS_MD5SUM)
		{
			// Get handle to the crypto provider
			if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
				throwException(ERR_CRYPTO_MD5);

			// Create the hash
			if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
				throwException(ERR_CRYPTO_MD5);
		}
		else
		{
			printf("MD5 Checksum validation bypassed\n");
		}

		// Copy		
		percent = 0;
		while (rc = nxdata.DumpToStorage(&nxdataOut, partition, &readAmount, &writeAmount, &bytesToRead, !BYPASS_MD5SUM ? &hHash : NULL))
		{
			if (rc < 0)
				break;

			int percent2 = writeAmount * 100 / bytesToRead;

			if (percent2 > percent)
			{
				percent = percent2;
				printf("Copying from input %s (type: %s%s%s) to output %s... (%d%%) \r",
					   nxdata.isDrive ? "drive" : "file",
					   nxdata.GetNxStorageTypeAsString(), nxdata.size != bytesToRead && NULL != partition ? ", partition: " : "",
					   nxdata.size != bytesToRead && NULL != partition ? partition : "",
					   nxdataOut.isDrive ? "drive" : "file",
					   percent);
			}
		}
		
		if (rc != NO_MORE_BYTES_TO_COPY)
		{
			throwException(rc);
		}
		else if (writeAmount != bytesToRead)
		{
			printf("ERROR : %I64d bytes to read but %I64d bytes written\n", bytesToRead, writeAmount);
			throwException();
		}
		printf("\n");

		nxdata.ClearHandles();

		// Check dump integrity
		if (!BYPASS_MD5SUM)
		{
			md5hash = BuildChecksum(hHash);
			// Compute then compare output checksums
			nxdataOut.InitStorage();
			int p_percent = 0;
			u64 readAmout = 0;
			while (true)
			{
				int percent = nxdataOut.GetMD5Hash(&hHash_out, &readAmout);
				if (percent < 0)
					break;

				if (percent > p_percent)
				{
					printf("Computing MD5 checksum... (%d%%) \r", percent);
					p_percent = percent;
				}
			}
			printf("\n");
			md5hashOut = BuildChecksum(hHash_out);

			if (md5hash != md5hashOut)
			{
				throwException(ERR_MD5_COMPARE);
			}
			else
			{
				printf("Done & verified (checksums are IDENTICAL)\n");
			}
		}
	}

	exit(EXIT_SUCCESS);
}
