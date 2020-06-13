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
#include "NxNandManager.h"
#include "NxStorage.h"
#include "NxPartition.h"

#include "res/utils.h"

BOOL BYPASS_MD5SUM = FALSE;
bool isdebug = FALSE;
bool isGUI = FALSE;

BOOL FORCE = FALSE;
BOOL LIST = FALSE;
BOOL FORMAT_USER = FALSE;

int startGUI(int argc, char *argv[])
{
#if defined(ENABLE_GUI)

    if (isdebug)
    {
        QFile outFile("log_file.txt");
        outFile.open(QIODevice::WriteOnly | QIODevice::Truncate);

        // redirect stdout
        _dup2(outFile.handle(), _fileno(stdout));

        // redirect stderr
        _dup2(_fileno(stdout), _fileno(stderr));
    }

    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication a(argc, argv);
    isGUI = true;
    a.setApplicationName("NxNandManager");
    MainWindow w;
    a.setStyleSheet("QMessageBox {messagebox-text-interaction-flags: 12;}");
    w.show();
    return a.exec();
#else
    throwException(ERR_INIT_GUI, "GUI unavailable. This build is CLI only");
    return -1;
#endif
}

void printStorageInfo(NxStorage *storage)
{
    char c_path[MAX_PATH] = { 0 };
    std::wcstombs(c_path, storage->m_path, wcslen(storage->m_path));

    printf("NAND type      : %s%s\n", storage->getNxTypeAsStr(), storage->isSplitted() ? " (splitted dump)" : "");
    printf("Path           : %s", c_path);
    if (storage->isSplitted())
        printf(" (+%d)", storage->nxHandle->getSplitCount() - 1);
    printf("\n");

    if (storage->type == INVALID && is_dir(c_path))
        printf("File/Disk      : Directory");
    else 
        printf("File/Disk      : %s", storage->isDrive() ? "Disk" : "File");
    if (storage->type == RAWMMC)
        printf(" (0x%s - 0x%s)\n", n2hexstr((u64)storage->mmc_b0_lba_start * NX_BLOCKSIZE, 10).c_str(), n2hexstr((u64)storage->mmc_b0_lba_start * NX_BLOCKSIZE + storage->size() - 1, 10).c_str());
    else printf("\n");
    if(storage->type != INVALID) 
    {
        printf("Size           : %s", GetReadableSize(storage->size()).c_str());
        if(storage->isSinglePartType() && storage->getNxPartition()->freeSpace)
            printf(" (free space %s)", GetReadableSize(storage->getNxPartition()->freeSpace).c_str());
        printf("\n");
    }
    if (!storage->isNxStorage())
        return;


    printf("Encrypted      : %s%s\n", storage->isEncrypted() ? "Yes" : "No", storage->badCrypto() ? "  !!! DECRYPTION FAILED !!!" : "");
    if (storage->type == BOOT0 || storage->type == RAWMMC) {
        printf("AutoRCM        : %s\n", storage->autoRcm ? "ENABLED" : "DISABLED");
        printf("Bootloader ver.: %d\n", static_cast<int>(storage->bootloader_ver));    
    }
    if (storage->firmware_version.major > 0)
    {
        printf("Firmware ver.  : %s\n", storage->getFirmwareVersion().c_str());
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
        printf("%s %s", !i ? "\nPartitions : \n -" : " -", part->partitionName().c_str());
        printf(" (%s", GetReadableSize(part->size()).c_str());
        if (part->freeSpace)
            printf(", free space %s", GetReadableSize(part->freeSpace).c_str());
        printf("%s)%s", part->isEncryptedPartition() ? " encrypted" : "", part->badCrypto() ? "  !!! DECRYPTION FAILED !!!" : "");

        dbg_printf(" [0x%s - 0x%s]", n2hexstr((u64)part->lbaStart() * NX_BLOCKSIZE, 10).c_str(), n2hexstr((u64)part->lbaStart() * NX_BLOCKSIZE + part->size()-1, 10).c_str());

        printf("\n");
        i++;
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

void printProgress(ProgressInfo pi)
{
    auto time = std::chrono::system_clock::now();
    std::chrono::duration<double> tmp_elapsed_seconds = time - pi.begin_time;

    if (!((int)tmp_elapsed_seconds.count() > elapsed_seconds) && pi.bytesCount != 0 && pi.bytesCount != pi.bytesTotal)
        return;

    elapsed_seconds = tmp_elapsed_seconds.count();
    std::chrono::duration<double> remaining_seconds = (tmp_elapsed_seconds / pi.bytesCount) * (pi.bytesTotal - pi.bytesCount);
    std::string buf = GetReadableElapsedTime(remaining_seconds).c_str();
    char label[0x40];

    if (pi.bytesCount == pi.bytesTotal)
    {
        if (pi.mode == MD5_HASH) sprintf(label, "verified");
        else if (pi.mode == RESTORE) sprintf(label, "restored");
        else if (pi.mode == RESIZE) sprintf(label, "resized");
        else if (pi.mode == CREATE) sprintf(label, "created");
        else if (pi.mode == ZIP) sprintf(label, "archived");
        else sprintf(label, "dumped");
        printf("%s%s %s. %s - Elapsed time: %s                                              \n", pi.isSubProgressInfo ? "  " : "",
            pi.storage_name, label, GetReadableSize(pi.bytesTotal).c_str(), GetReadableElapsedTime(tmp_elapsed_seconds).c_str());
    }
    else
    {
        if (pi.mode == MD5_HASH) sprintf(label, "Computing MD5 hash for");
        else if (pi.mode == RESTORE) sprintf(label, "Restoring to");
        else if (pi.mode == RESIZE) sprintf(label, "Resizing");
        else if (pi.mode == CREATE) sprintf(label, "Creating");
        else if (pi.mode == ZIP) sprintf(label, "Archiving");
        else sprintf(label, "Copying");
        printf("%s%s %s... %s /%s (%d%%)", pi.isSubProgressInfo ? "  " : "", label, pi.storage_name,
            GetReadableSize(pi.bytesCount).c_str(), GetReadableSize(pi.bytesTotal).c_str(), pi.bytesCount * 100 / pi.bytesTotal);
        if (elapsed_seconds) printf(" - Remaining time: %s             \r", buf.c_str());
        else printf("                                          \r");
    }    
}

int main(int argc, char *argv[])
{
    
    //std::setlocale(LC_ALL, "en_US.utf8");
    std::setlocale(LC_ALL, "");
    std::locale::global(std::locale(""));
    printf("[ NxNandManager v4.0 by eliboa ]\n\n");
    const char *input = nullptr, *output = nullptr, *partitions = nullptr, *keyset = nullptr, *user_resize = nullptr, *boot0 = nullptr, *boot1 = nullptr;
    BOOL info = false, gui = false, setAutoRCM = false, autoRCM = false, decrypt = false, encrypt = false;
    BOOL incognito = false, createEmuNAND = false, zipOutput = false, passThroughZeroes = false;
    EmunandType emunandType = unknown;
    u64 chunksize = 0;
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
            "                    BCPKG2-2-Normal-Sub, BCPKG2-3-SafeMode-Main, etc. (see --info)\n"
            "                    You can use \"-part=RAWNAND\" to dump RAWNAND from input type FULL NAND\n\n"
            "  -d                Decrypt content (-keyset mandatory)\n"
            "  -e                Encrypt content (-keyset mandatory)\n"
            "  -keyset           Path to keyset file (bis keys)\n\n"
            "  -user_resize=     Size in Mb for new USER partition in output\n"
            "                    Only applies to input type RAWNAND or FULL NAND\n"
            "                    Use FORMAT_USER flag to format partition during copy\n"
            "                    GPT and USER's FAT will be modified\n"
            "                    output (-o) must be a new file\n"
            "  -split=N          When this argument is provided output file will be\n"
            "                    splitted in several part. N = chunksize in MB\n"
            "=> Options:\n\n"
#if defined(ENABLE_GUI)
            "  --gui             Start the program in graphical mode, doesn't need other argument\n"
#endif
            "  --list            Detect and list compatible NX physical drives (memloader/mmc emunand partition)\n"
            "  --info            Display information about input/output (depends on NAND type):\n"
            "                    NAND type, partitions, encryption, autoRCM status... \n"
            "                    ...more info when -keyset provided: firmware ver., S/N, device ID...\n\n"
            "  --incognito       Wipe all console unique id's and certificates from CAL0 (a.k.a incognito)\n"
            "                    Only applies to input type RAWNAND or PRODINFO\n\n"
            "  --enable_autoRCM  Enable auto RCM. -i must point to a valid BOOT0 file/drive\n"
            "  --disable_autoRCM Disable auto RCM. -i must point to a valid BOOT0 file/drive\n\n");

        printf("=> Flags:\n\n"
            "                    \"BYPASS_MD5SUM\" to bypass MD5 integrity checks (faster but less secure)\n"
            "                    \"FORMAT_USER\" to format USER partition (-user_resize arg mandatory)\n"
            "                    \"ZIP\" to create a zip archive for output file(s)\n"
            "                    \"PASSTHROUGH_0\" to fill unallocated clusetes in FAT with zeroes (keyset needed)\n"
            "                    \"FORCE\" to disable prompt for user input (no question asked)\n\n");

        printf("=> Emunand creation tool:\n\n"
               " Submit the following arguments to create an emunand on microSD card:\n"
               "   -i               Input path to a valid RAWNAND or FULL NAND file/drive\n"
               "   -boot0           Input path to a valid BOOT0 file/drive (not needed if input is FULL NAND)\n"
               "   -boot1           Input path to a valid BOOT1 file/drive (not needed if input is FULL NAND)\n"
               "   -o               Path to SD volume (i.e drive letter) or physical drive\n"
               "                    If -o is not provided, the program will display a list a compatible outputs\n\n"
               " Additionally, submit one of the following arguments:\n"
               "  --create_partition_emunand        To create a partition based emunand compatible with both Atmosphere\n"
               "                                    and SX OS. Another partition (FAT32) will be created with space left.\n"
               "                                    -o must point to a physical drive (ex \\\\.\\PhysicalDrive3)\n"
               "  --create_filebased_emunand_AMS    To create a file based emunand for Atmosphere (emuMMC) \n"
               "                                    -o must point to a drive letter (ex F:)\n"
               "  --create_filebased_emunand_SXOS   To create a file based emunand for SX OS \n"
               "                                    -o must point to a drive letter (ex F:)\n\n");

        throwException(ERR_WRONG_USE);
        return -1;
    };

    if (argc == 1)
    {
#if defined(ENABLE_GUI)
        printf("No argument provided. Switching to GUI mode...\n");
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
    const char INCOGNITO_ARGUMENT[] = "--incognito";
    const char RESIZE_USER_ARGUMENT[] = "-user_resize";
    const char FORMAT_USER_FLAG[] = "FORMAT_USER";
    const char CREATE_SD_AMS_EMUNAND_ARGUMENT[] = "--create_filebased_emunand_AMS";
    const char CREATE_SD_SXOS_EMUNAND_ARGUMENT[] = "--create_filebased_emunand_SXOS";
    const char CREATE_RAWBASED_EMUNAND_ARGUMENT[] = "--create_partition_emunand";
    const char BOOT0_ARGUMENT[] = "-boot0";
    const char BOOT1_ARGUMENT[] = "-boot1";
    const char SPLIT_OUTPUT_ARGUMENT[] = "-split";
    const char ZIP_OUTPUT_FLAG[] = "ZIP";
    const char PASSTHROUGH_0[] = "PASSTHROUGH_0";

    for (int i = 1; i < argc; i++)
    {
        char* currArg = argv[i];
        if (!strncmp(currArg, LIST_ARGUMENT, array_countof(LIST_ARGUMENT) - 1))
            LIST = true;

        else if (!strncmp(currArg, GUI_ARGUMENT, array_countof(GUI_ARGUMENT) - 1))
            gui = true;

        else if (!strncmp(currArg, CREATE_SD_AMS_EMUNAND_ARGUMENT, array_countof(CREATE_SD_AMS_EMUNAND_ARGUMENT) - 1))
        {
            createEmuNAND = true;
            emunandType = fileBasedAMS;
        }
        else if (!strncmp(currArg, CREATE_SD_SXOS_EMUNAND_ARGUMENT, array_countof(CREATE_SD_SXOS_EMUNAND_ARGUMENT) - 1))
        {
            createEmuNAND = true;
            emunandType = fileBasedSXOS;
        }
        else if (!strncmp(currArg, CREATE_RAWBASED_EMUNAND_ARGUMENT, array_countof(CREATE_RAWBASED_EMUNAND_ARGUMENT) - 1))
        {
            createEmuNAND = true;
            emunandType = rawBased;
        }
        else if (!strncmp(currArg, INPUT_ARGUMENT, array_countof(INPUT_ARGUMENT) - 1) && i < argc)
            input = argv[++i];

        else if (!strncmp(currArg, OUTPUT_ARGUMENT, array_countof(OUTPUT_ARGUMENT) - 1) && i < argc)
            output = argv[++i];

        else if (!strncmp(currArg, BOOT0_ARGUMENT, array_countof(BOOT0_ARGUMENT) - 1) && i < argc)
            boot0 = argv[++i];

        else if (!strncmp(currArg, BOOT1_ARGUMENT, array_countof(BOOT1_ARGUMENT) - 1) && i < argc)
            boot1 = argv[++i];

        else if (!strncmp(currArg, PARTITION_ARGUMENT, array_countof(PARTITION_ARGUMENT) - 1))
        {
            u32 len = array_countof(PARTITION_ARGUMENT) - 1;            
            if (currArg[len] == '=')
                partitions = &currArg[len + 1];
            else if (currArg[len] == 0 && i == argc - 1)
                return PrintUsage();
        }
        else if (!strncmp(currArg, SPLIT_OUTPUT_ARGUMENT, array_countof(SPLIT_OUTPUT_ARGUMENT) - 1))
        {
            u32 len = array_countof(SPLIT_OUTPUT_ARGUMENT) - 1;
            if (currArg[len] == '=')
                chunksize = std::stoull(&currArg[len + 1]) * 1024 * 1024;
            else if (currArg[len] == 0 && i == argc - 1)
                return PrintUsage();
        }
        else if (!strncmp(currArg, RESIZE_USER_ARGUMENT, array_countof(RESIZE_USER_ARGUMENT) - 1))
        {
            u32 len = array_countof(RESIZE_USER_ARGUMENT) - 1;
            if (currArg[len] == '=')
                user_resize = &currArg[len + 1];
            else if (currArg[len] == 0 && i == argc - 1)
                return PrintUsage();
        }
        else if (!strncmp(currArg, INFO_ARGUMENT, array_countof(INFO_ARGUMENT) - 1))
            info = true;

        else if (!strncmp(currArg, AUTORCMON_ARGUMENT, array_countof(AUTORCMON_ARGUMENT) - 1))
        {
            setAutoRCM = true;
            autoRCM = true;
        }
        else if (!strncmp(currArg, AUTORCMOFF_ARGUMENT, array_countof(AUTORCMOFF_ARGUMENT) - 1))
        {
            setAutoRCM = true;
            autoRCM = FALSE;
        }
        else if (!strncmp(currArg, BYPASS_MD5SUM_FLAG, array_countof(BYPASS_MD5SUM_FLAG) - 1))
            BYPASS_MD5SUM = true;

        else if (!strncmp(currArg, DEBUG_MODE_FLAG, array_countof(DEBUG_MODE_FLAG) - 1))
            isdebug = true;

        else if (!strncmp(currArg, FORCE_FLAG, array_countof(FORCE_FLAG) - 1))
            FORCE = true;

        else if (!strncmp(currArg, PASSTHROUGH_0, array_countof(PASSTHROUGH_0) - 1))
            passThroughZeroes = true;

        else if (!strncmp(currArg, ZIP_OUTPUT_FLAG, array_countof(ZIP_OUTPUT_FLAG) - 1))
            zipOutput = true;

        else if (!strncmp(currArg, FORMAT_USER_FLAG, array_countof(FORMAT_USER_FLAG) - 1))
            FORMAT_USER = true;

        else if (!strncmp(currArg, KEYSET_ARGUMENT, array_countof(KEYSET_ARGUMENT) - 1) && i < argc)
            keyset = argv[++i];

        else if (!strncmp(currArg, DECRYPT_ARGUMENT, array_countof(DECRYPT_ARGUMENT) - 1))
            decrypt = true;

        else if (!strncmp(currArg, ENCRYPT_ARGUMENT, array_countof(ENCRYPT_ARGUMENT) - 1))
            encrypt = true;

        else if (!strncmp(currArg, INCOGNITO_ARGUMENT, array_countof(INCOGNITO_ARGUMENT) - 1))
            incognito = true;

        else {
            printf("Argument (%s) is not allowed.\n\n", currArg);
            PrintUsage();
        }
    }

    if (gui)
    {
        startGUI(argc, argv);
        exit(EXIT_SUCCESS);
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

    if (nullptr == input || (nullptr == output && !info && !setAutoRCM && !incognito &&!createEmuNAND))
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

    wchar_t input_path[MAX_PATH];
    int nSize = MultiByteToWideChar(CP_UTF8, 0, input, -1, NULL, 0);
    MultiByteToWideChar(CP_UTF8, 0, input, -1, input_path, nSize > MAX_PATH ? MAX_PATH : nSize);

    if (wcscmp(nx_input.m_path, input_path))
    {
        char c_path[MAX_PATH] = { 0 };
        std::wcstombs(c_path, nx_input.m_path, wcslen(nx_input.m_path));
        printf("-i automatically replaced by %s\n", c_path);
    }


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

            NxHandle *outHandle = new NxHandle("PRODINFO.backup", 0);
            params_t par;
            par.partition = PRODINFO;
            u64 bytesCount = 0, bytesToRead = cal0->size();
            int rc = nx_input.dump(outHandle, par, printProgress);

            if(rc != SUCCESS)
                throwException(rc);
            delete outHandle;
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

    if (createEmuNAND && nullptr == output)
    {

        if (not_in(nx_input.type, {RAWNAND, RAWMMC}))
            throwException("input is not a valid \"RAWNAND\" or \"FULL NAND\"");

        std::vector<diskDescriptor> disks, available_disks;
        std::vector<volumeDescriptor> available_volumes;
        GetDisks(&disks);
        for (diskDescriptor disk : disks)
        {
            if (emunandType == rawBased && disk.removableMedia && disk.size > nx_input.size() + 0x8000000)
                available_disks.push_back(disk);

            if (emunandType == rawBased)
                continue;

            for (volumeDescriptor vol : disk.volumes)
            {
                if (vol.volumeFreeBytes > nx_input.size() + 0x800000)
                    available_volumes.push_back(vol);
            }

        }

        if (!available_disks.size() && !available_volumes.size())
            throwException("Unable to detect any%s drive with sufficient capacity to create emuNAND\n", emunandType == rawBased ? (void*)" removable" : (void*)"");

        if (emunandType == rawBased)
        {
            printf("List of removable disks large enough to create a raw based emunand: \n");
            for (diskDescriptor disk : available_disks)
                printf("- \\\\.\\PhysicalDrive%d (%s - %s %s)\n", disk.diskNumber, GetReadableSize(disk.size).c_str(), disk.vId.c_str(), disk.pId.c_str());

        }
        else
        {
            printf("List of volumes with enough free space to create a file based emunand: \n");
            for (volumeDescriptor vol : available_volumes)
            {
                std::transform(vol.mountPt.begin(), vol.mountPt.end(), vol.mountPt.begin(), ::toupper);
                printf("- %s: (%s)\n",  std::string(vol.mountPt.begin(), vol.mountPt.end()).c_str(), GetReadableSize(vol.size).c_str());
            }
        }
        exit(EXIT_SUCCESS);
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

    // Output specific actions
    //
    if (createEmuNAND)
    {
        dbg_printf("Create emunand\n");
        dbg_printf(" boot0 = %s\n", boot0);
        dbg_printf(" boot1 = %s\n", boot1);
        int rc;
        if (emunandType == rawBased)
        {
            if (!FORCE && !AskYesNoQuestion("All existing data on target disk will be erase. Continue ?"))
                throwException("Operation aborted");
            rc = nx_input.createMmcEmuNand(output, printProgress, boot0, boot1);
        }
        else
        {
            rc = nx_input.createFileBasedEmuNand(emunandType, std::string("\\\\.\\").append(output).c_str(), printProgress, boot0, boot1);
        }
        if (rc != SUCCESS)
            throwException(rc);

        exit(EXIT_SUCCESS);
    }
    //
    if (nullptr != user_resize)
    {
        if (not_in(nx_input.type, { RAWNAND, RAWMMC }))
            throwException("-user_resize on applies to input type \"RAWNAND\" or \"FULL NAND\"");

        if (nx_output.isNxStorage() || is_dir(output) || nx_output.isDrive())
            throwException("-user_resize argument provided, output (-o) should be a new file");

        NxPartition *user = nx_input.getNxPartition(USER);

        if (nullptr == user->crypto() || user->badCrypto())
            throwException("Bad crypto or missing keyset");

        std::string s_new_size(user_resize);
        int new_size = 0;
        try {
            new_size = std::stoi(s_new_size);
        }
        catch (...) {
            throwException("-user_resize invalid value");
        }
        
        if (new_size % 64) {
            new_size = (new_size / 64 + 1) * 64;
            ///printf("-user_resize new value is %d (aligned to 64Mb)\n");
        }
        
        u32 user_new_size = new_size * 0x800; // Size in sectors. 1Mb = 0x800 sectores
        u64 user_min = (u64)user_new_size * 0x200 / 1024 / 1024;
        u32 min_size = (u32)((user->size() - user->freeSpace) / 0x200); // 0x20000 = size for 1 cluster in FAT
        u64 min = FORMAT_USER ? 64 : (u64)min_size * 0x200 / 1024 / 1024;
        if (min % 64) min = (min / 64) * 64 + 64;

        if (user_min < min) 
              throwException("-user_resize mininmum value is %I64d (%s)", (void *)min, (void*)GetReadableSize((u64)min * 1024 * 1024).c_str());

        if (info)
            throwException("--info argument provided, exit (remove arg from command to perform resize).\n");

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

        if (FORMAT_USER && !FORCE && !AskYesNoQuestion("USER partition will be formatted in output file. Are you sure you want to continue ?"))
            throwException("Operation cancelled");

        SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_AWAYMODE_REQUIRED);


        params_t par;
        par.user_new_size = user_new_size;
        par.format_user = FORMAT_USER;

        NxHandle *outHandle = new NxHandle(output);
        int rc = nx_input.dump(outHandle, par, printProgress);
        // Failure
        if (rc != SUCCESS)
            throwException(rc);

        delete outHandle;

        SetThreadExecutionState(ES_CONTINUOUS);

        exit(EXIT_SUCCESS);
    }

    ///
    ///  I/O Controls
    ///

    std::vector<const char*> v_partitions;
    bool dump_rawnand = false;
    int crypto_mode = BYPASS_MD5SUM ? NO_CRYPTO : MD5_HASH;

    // Output is unknown disk
    if (nx_output.type == INVALID && nx_output.isDrive())
        throwException("Output is an unknown drive/disk!");
    
    // Create new list for partitions and put -part arg in it
    char l_partitions[MAX_PATH] = { 0 };
    if (nullptr != partitions) {
        strcpy(l_partitions, ",");
        strcat(l_partitions, partitions);
    }

    // No partition provided
    if (!strlen(l_partitions))
    {
        // Output is dir OR output contains several partitions but no partition provided
        if (is_dir(output) || (nx_output.isNxStorage() && !nx_output.isSinglePartType() && nx_input.type != nx_output.type))
        {
            // Push every partition that is in both input & output to copy list OR simply in input if output is a dir
            for (NxPartition *in_part : nx_input.partitions)
            {
                NxPartition *out_part = nx_output.getNxPartition(in_part->type());
                if (is_dir(output) || (nullptr != out_part && in_part->size() <= out_part->size())) 
                {
                    strcat(l_partitions, ",");
                    strcat(l_partitions, in_part->partitionName().c_str());
                }
            }
        }
        
        // If no partition in copy list -> full dump or restore
        if (!strlen(l_partitions))
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
                //v_partitions.push_back(nx_input.getNxPartition()->partitionName().c_str());
                strcat(l_partitions, ",");
                strcat(l_partitions, nx_input.getNxPartition()->partitionName().c_str());
            }
        }
    }

    // A list of partitions is provided
    if (strlen(l_partitions))
    {
        // Explode partitions string        
        std::string pattern;
        pattern.append(l_partitions);
        char *partition, *ch_parts = strdup(pattern.c_str());
        while ((partition = strtok(!v_partitions.size() ? ch_parts : nullptr, ",")) != nullptr) v_partitions.push_back(partition);

        // For each partition in param string
        for (const char* part_name : v_partitions)
        {

            if (!strcmp(part_name, "RAWNAND") && nx_input.type == RAWMMC && !nx_output.isNxStorage())
            {
                v_partitions.clear();
                dump_rawnand = true;
                break;
            }

            // Partition must exist in input
            NxPartition *in_part = nx_input.getNxPartition(part_name);
            if (nullptr == in_part)
                throwException("Partition %s not found in input (-i)", (void*)part_name);

            // Validate crypto mode
            if (decrypt && !in_part->isEncryptedPartition() && in_part->nxPart_info.isEncrypted)
                throwException("Partition %s is not encrypted", (void*)in_part->partitionName().c_str());

            else if (decrypt && in_part->badCrypto())
                throwException("Failed to validate crypto for partition %s", (void*)in_part->partitionName().c_str());

            else if (encrypt && in_part->isEncryptedPartition() && in_part->nxPart_info.isEncrypted)
                throwException("Partition %s is already encrypted", (void*)in_part->partitionName().c_str());

            else if (encrypt && !in_part->nxPart_info.isEncrypted && v_partitions.size() == 1)
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

    // If only one part to dump, output cannot be a dir
    if (!nx_output.isNxStorage() && !v_partitions.size() && is_dir(output))
        throwException("Output cannot be a directory");

    // If more then one part to dump, output must be a dir
    if (!nx_output.isNxStorage() && v_partitions.size() > 1 && !is_dir(output))
        throwException("Output must be a directory");

    // List partitions to be copied for user
    if (info && v_partitions.size() > 1)
    {
        std::string label;
        if (encrypt) label.append("encrypted and ");
        else if (decrypt) label.append("decrypted and ");

        printf(" -- COPY --\nThe following partitions will be %s%s from input to ouput : \n", label.c_str(), nx_output.isNxStorage() ? "restored" : "dumped");
        for (const char* partition : v_partitions) {
            printf("-%s\n", partition);
        }
        printf("\n");

        if (is_in(nx_output.type, { RAWMMC, RAWNAND }))
            printf("WARNING : GPT & GPT backup will not be overwritten in output. NO RAW RESTORE, ONLY PARTITIONS\n");
    }

    if (info)        
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

            if (dump_rawnand)
                printf("BOOT0 & BOOT1 skipped (RAWNAND only)\n");

            params_t par;
            par.chunksize = chunksize;
            par.rawnand_only = dump_rawnand;
            par.crypto_mode = crypto_mode;
            par.zipOutput = zipOutput;
            par.passThroughZero = passThroughZeroes;

            NxHandle *outHandle = new NxHandle(output, chunksize);
            int rc = nx_input.dump(outHandle, par, printProgress);
            // Failure
            if (rc != SUCCESS)
                throwException(rc);

            delete outHandle;
        }
        // Dump one or several partitions (-part is provided)
        else
        {           
            // Check if file already exists
            int i = 0;
            std::vector<int> indexes;
            for (const char *part_name : v_partitions)
            {
                char new_out[MAX_PATH];
                strcpy(new_out, output);
                strcat(new_out, "\\");
                strcat(new_out, part_name);
                if (is_file(new_out))
                {
                    if (!FORCE && !AskYesNoQuestion("The following output file already exists :\n- %s\nDo you want to overwrite it ?", (void*)new_out))
                    {                        
                        if (!v_partitions.size())
                            throwException("Operation canceled");

                        indexes.push_back(i);
                    }
                    else
                    {
                        remove(new_out);
                        if (is_file(new_out))
                            throwException("Failed to delete output file %s", new_out);
                    }
                }
                i++;
            }
            // Delete partitions user wants to keep from copy list
            for(int i : indexes)
                v_partitions.erase(v_partitions.begin() + i);
            
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
                else strcpy(new_out, output);

                params_t par;
                par.chunksize = chunksize;
                par.crypto_mode = crypto_mode;
                par.partition = partition->type();
                par.zipOutput = zipOutput;
                par.passThroughZero = passThroughZeroes;

                NxHandle *outHandle = new NxHandle(new_out, chunksize);
                int rc = nx_input.dump(outHandle, par, printProgress);

                // Failure
                if (rc != SUCCESS)
                    throwException(rc);

                delete outHandle;
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

            params_t par;
            par.crypto_mode = crypto_mode;
            int rc = nx_output.restore(&nx_input, par, printProgress);

            // Failure
            if (rc != SUCCESS)
                throwException(rc);
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

                params_t par;
                par.crypto_mode = crypto_mode;
                par.partition = in_part->type();

                int rc = nx_output.restore(&nx_input, par, printProgress);

                // Failure
                if (rc != SUCCESS)
                    throwException(rc);
            }
        }
    }

    SetThreadExecutionState(ES_CONTINUOUS);

    exit(EXIT_SUCCESS);
}

