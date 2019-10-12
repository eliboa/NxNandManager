/*
 * Copyright (c) 2019 eliboa
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "NxStorage.h"
#include "NxPartition.h"
#include "res/utils.h"
#include <clocale>

BOOL BYPASS_MD5SUM = FALSE;
BOOL DEBUG_MODE = FALSE;
BOOL FORCE = FALSE;
BOOL LIST = FALSE;

void printStorageInfo(NxStorage *storage)
{
    printf("NAND type      : %s%s\n", storage->getNxTypeAsStr(), storage->isSplitted() ? " (splitted dump)" : "");
    wprintf(L"Path           : %s", storage->m_path);
    if (storage->isSplitted())
        printf(" (+%d)", storage->nxHandle->getSplitCount() - 1);
    printf("\n");

    char c_path[MAX_PATH] = { 0 };
    std::wcstombs(c_path, storage->m_path, wcslen(storage->m_path));
    if (storage->type == INVALID && is_dir(c_path))
        printf("File/Disk      : Directory");
    else 
        printf("File/Disk      : %s", storage->isDrive() ? "Disk" : "File");
    if (storage->type == RAWMMC)
        printf(" (0x%s - 0x%s)\n", n2hexstr(u64(storage->mmc_b0_lba_start * NX_BLOCKSIZE), 10).c_str(), n2hexstr(u64(storage->mmc_b0_lba_start * NX_BLOCKSIZE) + storage->size() - 1, 10).c_str());
    else printf("\n");
    if(storage->type != INVALID) printf("Size           : %s\n", GetReadableSize(storage->size()).c_str());

    if (!storage->isNxStorage())
        return;


    printf("Encrypted      : %s%s\n", storage->isEncrypted() ? "Yes" : "No", storage->badCrypto() ? "  !!! DECRYPTION FAILED !!!" : "");
    if (storage->type == BOOT0 || storage->type == RAWMMC) printf("AutoRCM        : %s\n", storage->autoRcm ? "ENABLED" : "DISABLED");
    if (storage->type == BOOT0)
        printf("Bootloader ver.: %d\n", static_cast<int>(storage->bootloader_ver));    
    if (strlen(storage->fw_version) > 0)
    {
        printf("Firmware ver.  : %s\n", storage->fw_version);
        if (storage->type == RAWNAND || storage->type == RAWMMC || storage->type == SYSTEM) printf("ExFat driver   : %s\n", storage->exFat_driver ? "Detected" : "Undetected");
    }
    
    // TODO
    //if (strlen(storage->last_boot) > 0)
    //    printf("Last boot      : %s\n", storage->last_boot);

    if (strlen(storage->serial_number) > 3)
        printf("Serial number  : %s\n", storage->serial_number);

    if (strlen(storage->deviceId) > 0)
        printf("Device Id      : %s\n", storage->deviceId);

    if (storage->macAddress.length() > 0)
        printf("MAC Address    : %s\n", storage->macAddress.c_str());

    if (storage->partitions.size() <= 1)
        return;

    int i = 0;
    for (NxPartition *part : storage->partitions)
    {
        printf("%s%02d %s  (%s%s)%s\n", i == 1 ? "\nPartitions     : \n                 " : "                 ", ++i, part->partitionName().c_str(),
            GetReadableSize(part->size()).c_str(), part->isEncryptedPartition() ? " encrypted" : "", part->badCrypto() ? "  !!! DECRYPTION FAILED !!!" : "");
    }

    if (storage->type == RAWMMC || storage->type == RAWNAND)
    {
        if(storage->backupGPT())
            printf("Backup GPT     : FOUND (offset 0x%s)\n", n2hexstr(storage->backupGPT(), 10).c_str());
        else
            printf("Backup GPT     : /!\\ Missing or invalid !!!\n");

    }
}

int elapsed_seconds = 0;
void printCopyProgress(int mode, const char *storage_name, timepoint_t begin_time, u64 bytesCount, u64 bytesTotal)
{
    auto time = std::chrono::system_clock::now();
    std::chrono::duration<double> tmp_elapsed_seconds = time - begin_time;

    if (!((int)tmp_elapsed_seconds.count() > elapsed_seconds))
        return;

    elapsed_seconds = tmp_elapsed_seconds.count();
    std::chrono::duration<double> remaining_seconds = (tmp_elapsed_seconds / bytesCount) * (bytesTotal - bytesCount);
    char label[0x40];
    if(mode == MD5_HASH) sprintf(label, "Computing MD5 hash for");
    else if (mode == RESTORE) sprintf(label, "Restoring to");
    else sprintf(label, "Copying");
    printf("%s %s... %s /%s (%d%%) - Remaining time: %s          \r", label, storage_name, GetReadableSize(bytesCount).c_str(), 
        GetReadableSize(bytesTotal).c_str(), bytesCount * 100 / bytesTotal, GetReadableElapsedTime(remaining_seconds).c_str());
}

int main(int argc, char *argv[])
{
    
    std::setlocale(LC_ALL, "en_US.utf8");
    printf("[ NxNandManager v3.0.0-a by eliboa ]\n\n");
    const char *input = NULL, *output = NULL, *partitions = NULL, *keyset = NULL;
    BOOL info = FALSE, gui = FALSE, setAutoRCM = FALSE, autoRCM = FALSE, decrypt = FALSE, encrypt = FALSE, incognito = FALSE;
    int io_num = 1;

    // Arguments, controls & usage
    auto PrintUsage = []() -> int {
        printf("usage: NxNandManager -i <inputFilename|\\\\.\\PhysicalDriveX>\n"
            "           -o <outputFilename|\\\\.\\PhysicalDrivekX> [Options] [Flags]\n\n"
            "=> Arguments:\n\n"
            "  -i                Path to input file/drive\n"
            "  -o                Path to output file/drive\n"
            "  -part=            Partition(s) to copy (apply to both input & output if possible)\n"
            "                    Use a comma (\",\") separated list to provide multiple partitions\n"
            "                    Possible values are PRODINFO, PRODINFOF, SAFE, SYSTEM, USER,\n"
            "                    BCPKG2-2-Normal-Sub, BCPKG2-3-SafeMode-Main, etc. (see --info)\n\n"
            "  -d                Decrypt content (-keyset mandatory)\n"
            "  -e                Encrypt content (-keyset mandatory)\n"
            "  -keyset           Path to keyset file (bis keys)\n\n"
            "=> Options:\n\n"
#if defined(ENABLE_GUI)
            "  --gui             Start the program in graphical mode, doesn't need other argument\n"
#endif
            "  --list            Detect and list compatible NX physical drives (memloader/mmc emunand partition)\n"
            "  --info            Display information about input/output (depends on NAND type):\n"
            "                    NAND type, partitions, encryption, autoRCM status... \n"
            "                    ...more info when -keyset provided: firmware ver., S/N, last boot date\n\n"
            "  --incognito       Wipe all console unique id's and certificates from CAL0 (a.k.a incognito)\n"
            "                    Only apply to input type RAWNAND or PRODINFO partition\n"
            "  --enable_autoRCM  Enable auto RCM. -i must point to a valid BOOT0 file/drive\n"
            "  --disable_autoRCM Disable auto RCM. -i must point to a valid BOOT0 file/drive\n\n"
        );

        printf("=> Flags:\n\n"
            "                    \"BYPASS_MD5SUM\" to bypass MD5 integrity checks (faster but less secure)\n"
            "                    \"FORCE\" to disable prompt for user input (no question asked)\n");

        throwException(ERR_WRONG_USE);
        return -1;
    };

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
    const char INCOGNITO_ARGUMENT[] = "--incognito";

    for (int i = 1; i < argc; i++)
    {
        char* currArg = argv[i];
        if (!strncmp(currArg, LIST_ARGUMENT, array_countof(LIST_ARGUMENT) - 1))
            LIST = TRUE;

        else if (!strncmp(currArg, GUI_ARGUMENT, array_countof(GUI_ARGUMENT) - 1))
            gui = TRUE;

        else if (!strncmp(currArg, INPUT_ARGUMENT, array_countof(INPUT_ARGUMENT) - 1) && i < argc)
            input = argv[++i];

        else if (!strncmp(currArg, OUTPUT_ARGUMENT, array_countof(OUTPUT_ARGUMENT) - 1) && i < argc)
            output = argv[++i];

        else if (!strncmp(currArg, PARTITION_ARGUMENT, array_countof(PARTITION_ARGUMENT) - 1))
        {
            u32 len = array_countof(PARTITION_ARGUMENT) - 1;            
            if (currArg[len] == '=')
                partitions = &currArg[len + 1];
            else if (currArg[len] == 0 && i == argc - 1)
                return PrintUsage();
        }
        else if (!strncmp(currArg, INFO_ARGUMENT, array_countof(INFO_ARGUMENT) - 1))
            info = TRUE;

        else if (!strncmp(currArg, AUTORCMON_ARGUMENT, array_countof(AUTORCMON_ARGUMENT) - 1))
        {
            setAutoRCM = TRUE;
            autoRCM = TRUE;
        }
        else if (!strncmp(currArg, AUTORCMOFF_ARGUMENT, array_countof(AUTORCMOFF_ARGUMENT) - 1))
        {
            setAutoRCM = TRUE;
            autoRCM = FALSE;
        }
        else if (!strncmp(currArg, BYPASS_MD5SUM_FLAG, array_countof(BYPASS_MD5SUM_FLAG) - 1))
            BYPASS_MD5SUM = TRUE;

        else if (!strncmp(currArg, DEBUG_MODE_FLAG, array_countof(DEBUG_MODE_FLAG) - 1))
            DEBUG_MODE = TRUE;

        else if (!strncmp(currArg, FORCE_FLAG, array_countof(FORCE_FLAG) - 1))
            FORCE = TRUE;

        else if (!strncmp(currArg, KEYSET_ARGUMENT, array_countof(KEYSET_ARGUMENT) - 1) && i < argc)
            keyset = argv[++i];

        else if (!strncmp(currArg, DECRYPT_ARGUMENT, array_countof(DECRYPT_ARGUMENT) - 1))
            decrypt = TRUE;

        else if (!strncmp(currArg, ENCRYPT_ARGUMENT, array_countof(ENCRYPT_ARGUMENT) - 1))
            encrypt = TRUE;

        else if (!strncmp(currArg, INCOGNITO_ARGUMENT, array_countof(INCOGNITO_ARGUMENT) - 1))
            incognito = TRUE;

        else {
            printf("Argument (%s) is not allowed.\n\n", currArg);
            PrintUsage();
        }
    }

    if (LIST)
    {
        printf("Listing drives...\r");
        std:string drives = ListPhysicalDrives();
        if (!drives.length())
        {
            printf("No compatible drive found!\n");
            exit(EXIT_SUCCESS);
        }
        printf("Compatible drives :    \n");
        printf("%s", drives.c_str());
        exit(EXIT_SUCCESS);
    }

    if (nullptr == input || (nullptr == output && !info && !setAutoRCM && !incognito))
        PrintUsage();

    if ((encrypt || decrypt) && nullptr == keyset)
    {
        printf("-keyset missing\n\n");
        PrintUsage();
    }

    if (FORCE)
        printf("Force mode activated, no questions will be asked.\n");

    ///
    ///  I/O Init
    ///

    // New NxStorage for input
    printf("Accessing input...\r");
    NxStorage nx_input = NxStorage(input);
    printf("                      \r");

    if (nx_input.type == INVALID)
    {
        if (nx_input.isDrive())
            throwException(ERR_INVALID_INPUT, "Failed to open input disk. Make sure to run this program as an administrator.");
        else 
            throwException("Failed to open input : %s", (void*)input);
    }

    // Set keys for input
    if (nullptr != keyset && is_in(nx_input.setKeys(keyset), { ERR_KEYSET_NOT_EXISTS, ERR_KEYSET_EMPTY }))
        throwException("Failed to get keys from %s", (void*)keyset);


    // Input specific actions
    // 
    if (setAutoRCM)
    {
        if(nullptr == nx_input.getNxPartition(BOOT0))
            throwException("Cannot apply autoRCM to input type %s", (void*)nx_input.getNxTypeAsStr());

        if (!nx_input.setAutoRcm(autoRCM))
            throwException("Failed to apply autoRCM!");
        else 
            printf("autoRCM %s\n", autoRCM ? "enabled" : "disabled");
    }
    //
    if (incognito)
    {
        NxPartition *cal0 = nx_input.getNxPartition(PRODINFO);
        if (nullptr == cal0)
            throwException("Cannot apply Incognito to input type %s\n" 
                "Incognito can only be applied to input types \"RAWNAND\", \"FULL NAND\" or \"PRODINFO\"\n", 
                (void*)nx_input.getNxTypeAsStr());

        bool do_backup = true;
        if (!FORCE && !AskYesNoQuestion("Incognito will wipe out console unique id's and cert's from CAL0.\n"
            "Make sure you have a backup of PRODINFO partition in case you want to restore CAL0 in the future.\n"
            "Do you want to make a backup of PRODINFO now ?"))
            do_backup = false;

        // Backup CAL0
        if (do_backup)
        {
            if (is_file("PRODINFO.backup"))
                remove("PRODINFO.backup");

            u64 bytesCount = 0, bytesToRead = cal0->size();
            int rc;
            while (!(rc = cal0->dumpToFile("PRODINFO.backup", NO_CRYPTO, &bytesCount)));
            if (rc != NO_MORE_BYTES_TO_COPY)
                throwException(rc);

            printf("\"PRODINFO.backup\" file created in application directory\n");
        }

        if (int rc = nx_input.applyIncognito())
            throwException(rc);

        printf("Incognito successfully applied to input\n");
    }

    if (info)
    {
        printf("\n -- INPUT -- \n");
        printStorageInfo(&nx_input);
    }

    // Exit if output is not specified
    if (nullptr == output)
        exit(EXIT_SUCCESS);

    // Exit if input is not a valid NxStorage
    if (!nx_input.isNxStorage())
        throwException(ERR_INVALID_INPUT);

    // New NxStorage for output
    printf("Accessing output...\r");
    NxStorage nx_output = NxStorage(output);
    printf("                      \r");

    // Set keys for output
    if (nullptr != keyset)
        nx_output.setKeys(keyset);

    if (info)
    {
        printf("\n -- OUTPUT -- \n");
        printStorageInfo(&nx_output);
        printf("\n");
    }

    ///
    ///  I/O Controls
    ///

    std::vector<const char*> v_partitions;
    int crypto_mode = BYPASS_MD5SUM ? NO_CRYPTO : MD5_HASH;

    // Output is unknown disk
    if (nx_output.type == INVALID && nx_output.isDrive())
        throwException("Output is an unknown drive/disk!");

    // A list of partitions is provided
    if (nullptr != partitions)
    {        
        // Explode partitions string        
        std::string pattern(","); // insert delimiter at beginning of string to get first partition from strok()
        pattern.append(partitions);
        char *partition, *ch_parts = strdup(pattern.c_str());
        while ((partition = strtok(!v_partitions.size() ? ch_parts : nullptr, ",")) != nullptr) v_partitions.push_back(partition);

        // For each partition in param string
        for (const char* part_name : v_partitions)
        {
            // Partition must exist in input
            NxPartition *in_part = nx_input.getNxPartition(part_name);
            if (nullptr == in_part)
                throwException("Partition %s not found in input (-i)", (void*)part_name);

            // Validate crypto mode
            if (decrypt && !in_part->isEncryptedPartition())
                throwException("Partition %s is not encrypted", (void*)in_part->partitionName().c_str());

            else if (decrypt && in_part->badCrypto())
                throwException("Failed to validate crypto for partition %s", (void*)in_part->partitionName().c_str());

            else if (encrypt && in_part->isEncryptedPartition())
                throwException("Partition %s is already encrypted", (void*)in_part->partitionName().c_str());

            else if (encrypt && !in_part->nxPart_info.isEncrypted)
                throwException("Partition %s cannot be encrypted", (void*)in_part->partitionName().c_str());

            // Restore controls
            if (nx_output.isNxStorage())
            {
                NxPartition *out_part = nx_output.getNxPartition(part_name);
                // Partition must exist in output (restore only)
                if (nullptr == out_part)
                    throwException("Partition %s not found in output (-o)", (void*)part_name);

                // Prevent restoring decrypted partition to native encrypted partitions
                if (is_in(nx_output.type, { RAWNAND, RAWMMC }) && out_part->nxPart_info.isEncrypted &&
                    (decrypt || (!encrypt && !in_part->isEncryptedPartition())))
                    throwException("Cannot restore decrypted partition %s to NxStorage type %s ", 
                        (void*) in_part->partitionName().c_str(), (void*)nx_output.getNxTypeAsStr());
            }
        }
    }
    // No partition provided
    else 
    {
        // Output is valid NxStorage(restore), types should match
        if (nx_output.isNxStorage() && nx_input.type != nx_output.type)
            throwException("Input type (%s) doesn't match output type (%s)", 
                (void*)nx_input.getNxTypeAsStr(), (void*)nx_output.getNxTypeAsStr());

        // Control crypto mode
        if (encrypt || decrypt)
        {
            if (nx_input.partitions.size() > 1)
                throwException("Partition(s) to be %s must be provided through \"-part\" argument",
                    decrypt ? (void*)"decrypted" : (void*)"encrypted");

            if (decrypt && !nx_input.isEncrypted())
                throwException(ERR_CRYPTO_NOT_ENCRYPTED);

            if (decrypt && nx_input.badCrypto())
                throwException(ERROR_DECRYPT_FAILED);

            else if (encrypt && nx_input.isEncrypted())
                throwException(ERR_CRYPTO_ENCRYPTED_YET);

            else if (encrypt && !nx_input.getNxPartition()->nxPart_info.isEncrypted)
                throwException("Partition %s cannot be encrypted", (void*)nx_input.getNxPartition()->partitionName().c_str());            

            // Add partition to copy list
            v_partitions.push_back(nx_input.getNxPartition()->partitionName().c_str());
        }

        // Prevent restoring decrypted partition to native encrypted partitions
        if (is_in(nx_output.type, { RAWNAND, RAWMMC }) && nx_output.getNxPartition()->nxPart_info.isEncrypted
            && (decrypt || (!encrypt && !nx_input.isEncrypted())))
            throwException("Cannot restore decrypted partition to NxStorage type %s ", (void*)nx_output.getNxTypeAsStr());
    }

    // If only one part to dump, output cannot be a dir
    if (!nx_output.isNxStorage() && !v_partitions.size() && is_dir(output))
        throwException("Output cannot be a directory");

    // If more then one part to dump, output must be a dir
    if (!nx_output.isNxStorage() && v_partitions.size() > 1 && !is_dir(output))
        throwException("Output must be a directory");

    if(info)
        throwException("--info argument provided, exit (remove arg from command to perform dump/restore operation).\n");

    // Prevent system from going into sleep mode
    SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);
    
    ///
    /// Dump to new file
    ///    
    if (!nx_output.isNxStorage())
    {
        // Release output handle
        nx_output.nxHandle->clearHandle();

        // Output file already exists
        if (is_file(output))
        {
            if (!FORCE && !AskYesNoQuestion("Output file already exists. Do you want to overwrite it ?"))
                throwException("Operation cancelled");

            remove(output);
            if (is_file(output))
                throwException("Failed to delete output file");
        }

        // Full dump
        if (!v_partitions.size())
        {
            printf("FULL DUMP\n");

            // Init some vars
            int rc = 0;
            u64 bytesCount = 0, bytesToRead = nx_input.size();
            timepoint_t begin_time = std::chrono::system_clock::now();
            elapsed_seconds = 0;

            // Copy
            printf("Copying %s...\r", nx_input.getNxTypeAsStr());
            while (!(rc = nx_input.dumpToFile(output, crypto_mode, &bytesCount)))
                printCopyProgress(COPY, nx_input.getNxTypeAsStr(), begin_time, bytesCount, bytesToRead);

            std::chrono::duration<double> elapsed_total = std::chrono::system_clock::now() - begin_time;

            // Failure
            if (rc != NO_MORE_BYTES_TO_COPY)
                throwException(rc);

            // EOF
            printf("%s dumped. %s - Elapsed time: %s                         \n", nx_input.getNxTypeAsStr(),
                GetReadableSize(bytesCount).c_str(), GetReadableElapsedTime(elapsed_total).c_str());

            // Compute & compare md5 hashes
            if (crypto_mode == MD5_HASH)
            {
                HCRYPTHASH in_hash = nx_input.nxHandle->md5Hash();
                std::string in_sum = BuildChecksum(in_hash);
                    
                NxStorage out_storage = NxStorage(output);
                timepoint_t md5_begin_time = std::chrono::system_clock::now();
                bytesCount = 0;
                elapsed_seconds = 0;
                bytesToRead = out_storage.size();

                printf("Computing MD5 hash for %s...\r", nx_input.getNxTypeAsStr());
                while (!out_storage.nxHandle->hash(&bytesCount))
                    printCopyProgress(MD5_HASH, nx_input.getNxTypeAsStr(), md5_begin_time, bytesCount, bytesToRead);

                elapsed_total = std::chrono::system_clock::now() - md5_begin_time;

                if (bytesCount != bytesToRead)
                    throwException("Failed to compute MD5 hash for output");

                HCRYPTHASH out_hash = out_storage.nxHandle->md5Hash();
                std::string out_sum = BuildChecksum(out_hash);
                if (!in_sum.compare(out_sum))
                    printf("Verified (MD5 checksums are the same : \"%s\"). Elapsed time: %s          \n", 
                        out_sum.c_str(), GetReadableElapsedTime(elapsed_total).c_str());
                else
                    throwException("Failed to validate integrity (MD5 checksums are different %s != %s)",
                        (void*)in_sum.c_str(), (void*)out_sum.c_str());
            }
        }
        // Dump one or several partitions (-part is provided)
        else
        {           
            // Check if file already exists
            for (const char *part_name : v_partitions)
            {
                char new_out[MAX_PATH];
                strcpy(new_out, output);
                strcat(new_out, "\\");
                strcat(new_out, part_name);
                if (is_file(new_out))
                {
                    if (!FORCE && !AskYesNoQuestion("The following output file already exists :\n- %s\nDo you want to overwrite it ?", (void*)new_out))
                        throwException("Operation cancelled");

                    remove(new_out);
                    if (is_file(new_out))
                        throwException("Failed to delete output file %s", new_out);                            
                }
            }
            
            // Copy each partition            
            for (const char *part_name : v_partitions)
            {
                NxPartition *partition = nx_input.getNxPartition(part_name);

                // Set crypto mode
                if ((encrypt && !partition->isEncryptedPartition()) && partition->nxPart_info.isEncrypted ||
                    (decrypt && partition->isEncryptedPartition()))
                    crypto_mode = encrypt ? ENCRYPT : DECRYPT;
                else 
                    crypto_mode = BYPASS_MD5SUM ? NO_CRYPTO : MD5_HASH;

                char new_out[MAX_PATH];
                if (is_dir(output)) {
                    strcpy(new_out, output);
                    strcat(new_out, "\\");
                    strcat(new_out, part_name);
                }
                else strcpy(new_out, output);;
                
                // Init some vars
                timepoint_t begin_time = std::chrono::system_clock::now();
                u64 bytesCount = 0, bytesToRead = partition->size();
                elapsed_seconds = 0;
                int rc = 0;                

                // Copy
                printf("Copying %s...\r", partition->partitionName().c_str());
                while (!(rc = partition->dumpToFile(new_out, crypto_mode, &bytesCount)))
                    printCopyProgress(COPY, partition->partitionName().c_str(), begin_time, bytesCount, bytesToRead);

                std::chrono::duration<double> elapsed_total = std::chrono::system_clock::now() - begin_time;

                // Failure
                if (rc != NO_MORE_BYTES_TO_COPY)
                    throwException(rc);
                
                // EOF
                printf("%s dumped. %s - Elapsed time: %s                         \n", partition->partitionName().c_str(),
                    GetReadableSize(bytesCount).c_str(), GetReadableElapsedTime(elapsed_total).c_str());
                
                // Compute & compare md5 hashes
                if (crypto_mode == MD5_HASH)
                {
                    HCRYPTHASH in_hash = nx_input.nxHandle->md5Hash();
                    std::string in_sum = BuildChecksum(in_hash);

                    NxStorage out_storage = NxStorage(new_out);
                    timepoint_t md5_begin_time = std::chrono::system_clock::now();
                    bytesCount = 0;
                    elapsed_seconds = 0;
                    bytesToRead = out_storage.size();

                    printf("Computing MD5 hash for %s...\r", partition->partitionName().c_str());
                    while (!out_storage.nxHandle->hash(&bytesCount))
                        printCopyProgress(MD5_HASH, partition->partitionName().c_str(), md5_begin_time, bytesCount, bytesToRead);

                    elapsed_total = std::chrono::system_clock::now() - md5_begin_time;

                    if (bytesCount != bytesToRead)
                        throwException("Failed to compute MD5 hash for output");

                    HCRYPTHASH out_hash = out_storage.nxHandle->md5Hash();
                    std::string out_sum = BuildChecksum(out_hash);
                    if (!in_sum.compare(out_sum))
                        printf("Verified (MD5 checksums are the same : \"%s\"). Elapsed time: %s          \n",
                            out_sum.c_str(), GetReadableElapsedTime(elapsed_total).c_str());
                    else
                        throwException("Failed to validate integrity (MD5 checksums are different %s != %s)",
                        (void*)in_sum.c_str(), (void*)out_sum.c_str());
                }
            }
        }
    }

    ///
    /// Restore to NxStorage
    ///
    else
    {
        // Full restore
        if (!v_partitions.size())
        {
            if (!FORCE && !AskYesNoQuestion("%s to be fully restored. Are you sure you want to continue ?", (void*)nx_output.getNxTypeAsStr()))
                throwException("Operation cancelled");

            // Init some vars
            crypto_mode = NO_CRYPTO;
            int rc = 0;
            u64 bytesCount = 0, bytesToRead = nx_input.size();
            timepoint_t begin_time = std::chrono::system_clock::now();
            elapsed_seconds = 0;

            // Copy
            printf("Restoring to %s...\r", nx_output.getNxTypeAsStr());            
            while (!(rc = nx_output.restoreFromStorage(&nx_input, crypto_mode, &bytesCount)))
                printCopyProgress(RESTORE, nx_output.getNxTypeAsStr(), begin_time, bytesCount, bytesToRead);

            std::chrono::duration<double> elapsed_total = std::chrono::system_clock::now() - begin_time;

            // Failure
            if (rc != NO_MORE_BYTES_TO_COPY)
                throwException(rc);

            // EOF
            printf("%s restored. %s - Elapsed time: %s                         \n", nx_output.getNxTypeAsStr(),
                GetReadableSize(bytesCount).c_str(), GetReadableElapsedTime(elapsed_total).c_str());
        }
        // Restore one or several partitions
        else
        {
            std::string parts;
            for (const char *part_name : v_partitions) parts.append("- ").append(part_name).append("\n");
            if (!FORCE && !AskYesNoQuestion("The following partition%s will be restored :\n%sAre you sure you want to continue ?", 
                v_partitions.size() > 1 ? (void*)"s" : (void*)"", (void*)parts.c_str()))
                throwException("Operation cancelled");

            // Copy each partition            
            for (const char *part_name : v_partitions)
            {
                NxPartition *in_part = nx_input.getNxPartition(part_name);
                NxPartition *out_part = nx_output.getNxPartition(part_name);

                // Set crypto mode
                if ((encrypt && !in_part->isEncryptedPartition()) && in_part->nxPart_info.isEncrypted ||
                    (decrypt && in_part->isEncryptedPartition()))
                    crypto_mode = encrypt ? ENCRYPT : DECRYPT;
                else
                    crypto_mode = BYPASS_MD5SUM ? NO_CRYPTO : MD5_HASH;

                // Init some vars
                timepoint_t begin_time = std::chrono::system_clock::now();
                u64 bytesCount = 0, bytesToRead = in_part->size();
                elapsed_seconds = 0;
                int rc = 0;

                // Restore
                printf("Restoring %s...\r", out_part->partitionName().c_str());
                while (!(rc = out_part->restoreFromStorage(&nx_input, crypto_mode, &bytesCount)))
                    printCopyProgress(COPY, in_part->partitionName().c_str(), begin_time, bytesCount, bytesToRead);

                std::chrono::duration<double> elapsed_total = std::chrono::system_clock::now() - begin_time;

                // Failure
                if (rc != NO_MORE_BYTES_TO_COPY)
                    throwException(rc);

                // EOF
                printf("%s restored. %s - Elapsed time: %s                         \n", out_part->partitionName().c_str(),
                    GetReadableSize(bytesCount).c_str(), GetReadableElapsedTime(elapsed_total).c_str());
            }
        }
    }

    SetThreadExecutionState(ES_CONTINUOUS);
    exit(EXIT_SUCCESS);
}

