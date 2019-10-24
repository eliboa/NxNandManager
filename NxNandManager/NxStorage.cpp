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

NxStorage::NxStorage(const char *p_path)
{
    dbg_printf("NxStorage::NxStorage() begins for %s\n", std::string(p_path).c_str());
    type = INVALID;
    memset(fw_version, 0, 48);
    memset(deviceId, 0, 21);
    memset(serial_number, 0, 18);
    m_backupGPT = 0;
    m_size = 0;

    // Convert char buff (p_buff) to wchar array (m_path)
    int nSize = MultiByteToWideChar(CP_UTF8, 0, p_path, -1, NULL, 0);
    if (nSize > MAX_PATH) nSize = MAX_PATH;
    if (nSize == 0)
        return;
    MultiByteToWideChar(CP_UTF8, 0, p_path, -1, m_path, nSize);

    // Get handle to file/disk
    nxHandle = new NxHandle(this);
    if (!nxHandle->exists)
        return;

    // Get size from handle (will probably be overwritten later)
    m_size = nxHandle->size();
    m_freeSpace = nxHandle->getDiskFreeSpace();
    dbg_printf("NxStorage::NxStorage() size is %I64d (diskFreeBytes = %I64d)\n", m_size, m_freeSpace);

    // Init var.
    type = UNKNOWN;
    DWORD bytesRead;
    BYTE buff[NX_BLOCKSIZE];

    // Get NxType with magic
    for (MagicOffsets mgk : mgkOffArr)
    {
        if (mgk.offset > m_size)
            continue;

        int remain = mgk.offset % NX_BLOCKSIZE; // Block align
        if (nxHandle->read(mgk.offset - remain, buff, &bytesRead, NX_BLOCKSIZE) && hexStr(&buff[remain], mgk.size) == mgk.magic)
        {            
            type = mgk.type;
            dbg_printf("NxStorage::NxStorage() - MAGIC found at offset %s, type is %s\n", 
                n2hexstr(mgk.offset, 10).c_str(), getNxTypeAsStr());
            break;
        }
    }

    // Find needle (PK11) in haystack (BOOT1)
    if (type == UNKNOWN && m_size <= 0x400000)
    {
        nxHandle->initHandle();
        while (nxHandle->read(buff, &bytesRead, NX_BLOCKSIZE))
        {        
            std::string haystack(buff, buff + NX_BLOCKSIZE);
            if (haystack.find("PK11") != std::string::npos) {
                type = BOOT1;
                dbg_printf("NxStorage::NxStorage() - BOOT1 identified by looking for needle (PK11) in haystack (all file)\n");
                break;
            }
        }
    }

    // Single partition file identified
    if (isSinglePartType())
    {
        // Add new Nxpartition
        NxPartition *part = new NxPartition(this, getNxTypeAsStr(), (u32)0, (u32)m_size / NX_BLOCKSIZE - 1);
    }

    // Identify single partition file (comparing file name & file size)
    if (type == UNKNOWN && !nxHandle->isDrive())
    {
        std::wstring basenameW = base_nameW(std::wstring(m_path));
        std::string basename(basenameW.begin(), basenameW.end());
        basename = remove_extension(basename);
        std::transform(basename.begin(), basename.end(), basename.begin(), ::toupper);

        for (NxPart part : NxPartArr)
        {
            std::string p_name(part.name);
            std::transform(p_name.begin(), p_name.end(), p_name.begin(), ::toupper);

            if (!basename.compare(p_name) && part.size == m_size)
            {                
                type = getNxTypeAsInt(part.name);
                // Add new Nxpartition
                NxPartition *part = new NxPartition(this, basename.c_str(), (u32)0, (u32)m_size / NX_BLOCKSIZE - 1);
                break;
            }
            else if (part.size == m_size)
                b_MayBeNxStorage = true;
        }
    }
    

    // Look for emuMMC partition
    if (type == UNKNOWN)
    {        
        nxHandle->initHandle();
        u8 *mbr = (u8 *)malloc(0x200);

        // If first sector is MBR
        if (nxHandle->read(mbr, &bytesRead, NX_BLOCKSIZE) && hexStr(&mbr[0x200 - 2], 2) == "55AA")
        {
            u8 *efi_part = (u8 *)malloc(0x200);            
            u32 curr_part_size = 0, sector_start = 0, sector_count = 0;
            memcpy(mbr, mbr + 0x1BE, 0x40); // Get partitions

            // Iterate MBR primary partitions
            for (int i = 1; i < 4; i++)
            {                       
                sector_start = *(u32 *)&mbr[0x08 + (0x10 * i)];
                sector_count = *(u32 *)&mbr[0x0C + (0x10 * i)];

                if (!sector_start)
                    continue;

                if (nxHandle->read(sector_start + 0xC001, efi_part, &bytesRead, NX_BLOCKSIZE)
                    && !memcmp(efi_part, "EFI PART", 8)) //GPT header
                {
                    type = RAWMMC;
                    mmc_b0_lba_start = sector_start + 0x8000;
                    m_size = (u64)(sector_count - 0x8000) * NX_BLOCKSIZE;
                    m_freeSpace = m_size;
                    dbg_printf("NxStorage::NxStorage() - emuMMC found at offset %s\n", n2hexstr(mmc_b0_lba_start * NX_BLOCKSIZE, 10).c_str());
                    break;
                }
                else if (nxHandle->read((u32)sector_start + 0x4001, efi_part, &bytesRead, NX_BLOCKSIZE)
                    && !memcmp(efi_part, "EFI PART", 8)) //GPT header
                {
                    type = RAWMMC;
                    mmc_b0_lba_start = sector_start;                    
                    m_size = (u64)sector_count * NX_BLOCKSIZE;
                    m_freeSpace = m_size;
                    dbg_printf("NxStorage::NxStorage() - emuMMC found at offset %s\n", n2hexstr(mmc_b0_lba_start * NX_BLOCKSIZE, 10).c_str());
                    break;
                }
            }

            // Look for "foreign" emunand ^^
            if (type != RAWMMC && nxHandle->read((u32)0x4003, efi_part, &bytesRead, NX_BLOCKSIZE) && !memcmp(efi_part, "EFI PART", 8))
            {
                type = RAWMMC;
                mmc_b0_lba_start = 2;
                sector_start = *(u32 *)&mbr[0x08];
                m_freeSpace = (u64)(sector_start - mmc_b0_lba_start) * NX_BLOCKSIZE;
                dbg_printf("NxStorage::NxStorage() - foreign emuNAND found at offset %s\n", n2hexstr(mmc_b0_lba_start * NX_BLOCKSIZE, 10).c_str());
            }
            free(efi_part);
        }
        free(mbr);        
    }

    // RAWNAND or FULL NAND : Add NxPartition for each GPP or BOOT partition
    if(is_in(type, {RAWNAND, RAWMMC}))
    {        
        nxHandle->initHandle();
        u32 gpt_sector = type == RAWMMC ? 0x4001 : 1;
        unsigned char buff[0x4200];
        bool cal0_found = false;
        u64 partitions_total_size = 0;
        u32 last_sector = 0;

        // Read and parse GPT
        if (nxHandle->read(gpt_sector, buff, &bytesRead, 0x4200) && !memcmp(&buff[0], "EFI PART", 8))
        {
            // Add BOOT0 & BOOT1 as NxPartitions (RAWMMC)
            if (type == RAWMMC)
            {
                NxPartition *boot0 = new NxPartition(this, "BOOT0", 0, 0x1FFF);
                NxPartition *boot1 = new NxPartition(this, "BOOT1", 0x2000, 0x3FFF);                
                partitions_total_size += boot0->size() + boot1->size();
            }
            GptHeader *hdr = (GptHeader *)buff;
            
            if(isdebug)
            {
                dbg_printf("-- GPT header --\nstarts at lba %I64d (off 0x%s)\n", hdr->my_lba, n2hexstr((u64)hdr->my_lba * NX_BLOCKSIZE, 10).c_str());
                dbg_printf("backup at lba %I64d (off 0x%s)\n", hdr->alt_lba, n2hexstr((u64)hdr->alt_lba * NX_BLOCKSIZE, 10).c_str());
                dbg_printf("first use lba %I64d (off 0x%s)\n", hdr->first_use_lba, n2hexstr((u64)hdr->first_use_lba * NX_BLOCKSIZE, 10).c_str());
                dbg_printf("last use lba %I64d (off 0x%s)\n", hdr->last_use_lba, n2hexstr((u64)hdr->last_use_lba * NX_BLOCKSIZE, 10).c_str());
                
                dbg_printf("GPT Header CRC32 = %I32d\n", hdr->crc32);
                unsigned char header[92];
                memcpy(header, buff, 92);
                header[16] = 0;
                header[17] = 0;
                header[18] = 0;
                header[19] = 0;
                dbg_printf("GPT Header CRC32 new hash = %I32d\n", crc32Hash(header, 92));

                dbg_printf("Table CRC32 = %I32d\n", hdr->part_ents_crc32);
                unsigned char *table = new unsigned char[hdr->num_part_ents * hdr->part_ent_size];
                u32 off = (hdr->part_ent_lba - 1) * NX_BLOCKSIZE;
                memcpy(&table[0], &buff[off], hdr->num_part_ents * hdr->part_ent_size);
                dbg_printf("Table CRC32 new hash = %I32d\n", crc32Hash(table, hdr->num_part_ents * hdr->part_ent_size));
                delete[] table;
            }

            // Iterate GPP 
            for (int i = 0; i < hdr->num_part_ents; i++)
            {                                
                // Get GPT entry
                GptEntry *ent = (GptEntry *)(buff + (hdr->part_ent_lba - 1) * NX_BLOCKSIZE + i * sizeof(GptEntry));

                s8 part_name[37] = { 0 };
                for (int i = 0; i < 36; i++) { part_name[i] = ent->name[i]; }

                // First partition should be PRODINFO
                if (!cal0_found && !strcmp(part_name, "PRODINFO"))
                    cal0_found = true;

                if (!cal0_found)
                    break;

                u32 lba_start = 0;
                if (type == RAWMMC)
                    lba_start += 0x4000;
                // Add new Nxpartition
                NxPartition *part = new NxPartition(this, part_name, lba_start + ent->lba_start, lba_start + ent->lba_end);
                partitions_total_size += part->size();
                
                if (!strcmp(part_name, "PRODINFO"))
                    cal0_found = true;                

                if (lba_start + ent->lba_end > last_sector)
                    last_sector = lba_start + ent->lba_end;
            }
            
            if (cal0_found)
            {
                
                // Look for backup GPT                
                //u64 off = m_size - NX_BLOCKSIZE;
                u64 off = (u64)hdr->alt_lba * NX_BLOCKSIZE;
                if (type == RAWMMC) off += 0x4000 * NX_BLOCKSIZE;
                /*
                if (nxHandle->isDrive())
                {                   
                    off = (u64)last_sector * NX_BLOCKSIZE + 0x20400000;
                    if (off > nxHandle->size()) {
                        m_size = off + NX_BLOCKSIZE;
                        nxHandle->setSize(off + NX_BLOCKSIZE);
                    }
                } 
                */
                nxHandle->initHandle();

                memset(buff, 0, 8);
                if (nxHandle->read(off, buff, &bytesRead, 0x200) && !memcmp(&buff[0], "EFI PART", 8))
                {
                    m_backupGPT = off;
                    m_size = off + NX_BLOCKSIZE;
                    dbg_printf("NxStorage::NxStorage() - backup GPT found at offset %s\n", n2hexstr(m_backupGPT, 10).c_str());
                }
            }
        }

        if (!cal0_found)
        {
            dbg_printf("NxStorage::NxStorage() - Error CAL0 not found in %s\n", getNxTypeAsStr());
            type = UNKNOWN;
            partitions.clear();
        }
    }

    // Look for splitted dump
    if (type == RAWNAND && !m_backupGPT && !nxHandle->isDrive()) 
    {        
        type = UNKNOWN;
        if (nxHandle->detectSplittedStorage())
        {
            dbg_printf("NxStorage::NxStorage() - Splitted storage detected!\n");

            // Look for backup GPT
            u64 off = nxHandle->size() - NX_BLOCKSIZE;
            unsigned char buff[0x200] = { 0 };

            //dbg_printf("NxStorage::NxStorage() Look for backup GPT at offset %s\n", n2hexstr(off).c_str());
            if (nxHandle->read(off, buff, &bytesRead, 0x200) && !memcmp(&buff[0], "EFI PART", 8))
            {
                type = RAWNAND;
                b_isSplitted = true;
                m_size = nxHandle->size();
                m_backupGPT = off;
                dbg_printf("NxStorage::NxStorage() - backup GPT found in splitted storage at offset %s\n", n2hexstr(off, 10).c_str());
            }
            else
            {
                dbg_printf("NxStorage::NxStorage() - Error backup GPT not found for Splitted at offset %s\n", n2hexstr(off, 10).c_str());
                nxHandle->setSplitted(false);
            }
        }
    }

    // Detect autoRCM & bootloader version
    if (is_in(type, { BOOT0, RAWMMC }))
    {
        nxHandle->initHandle();
        
        // Get auto RCM status
        if (nxHandle->read((u64)0x200, buff, &bytesRead, NX_BLOCKSIZE))
            autoRcm = buff[0x10] != 0xF7 ? true : false;
        
        // Get bootloader version
        if (nxHandle->read((u64)0x2200, buff, &bytesRead, NX_BLOCKSIZE))
            memcpy(&bootloader_ver, &buff[0x130], sizeof(unsigned char));
    }
    
    // Retrieve info for decrypted partitions
    if (not_in(type, { UNKNOWN, INVALID }))
        setStorageInfo();
    
    dbg_printf("NxStorage::NxStorage() size is %I64d (diskFreeBytes = %I64d)\n", m_size, m_freeSpace);
}

NxStorage::~NxStorage()
{
    //printf("NxStorage::~NxStorage() DESTRUCTOR \n");
    if(partitions.size())
        partitions.clear();
    if (nullptr != nxHandle) delete nxHandle;
}

int NxStorage::setKeys(const char* keyset)
{
    dbg_wprintf(L"NxStorage::setKeys(%s) for %s\n", keyset, m_path);

    memset(keys.crypt0, 0, 33);
    memset(keys.tweak0, 0, 33);
    memset(keys.crypt1, 0, 33);
    memset(keys.tweak1, 0, 33);
    memset(keys.crypt2, 0, 33);
    memset(keys.tweak2, 0, 33);
    memset(keys.crypt3, 0, 33);
    memset(keys.tweak3, 0, 33);

    int num_keys = 0;
    ifstream readFile(keyset);
    string readout;
    std::string delimiter = ":";
    std::string value = "";

    if (readFile.is_open())
    {
        while (getline(readFile, readout)) {
            value.clear();
            if (readout.find("BIS KEY 0 (crypt)") != std::string::npos) {
                value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
                strcpy_s(keys.crypt0, value.substr(0, 32).c_str());
                num_keys++;
            }
            else if (readout.find("BIS KEY 0 (tweak)") != std::string::npos) {
                value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
                strcpy_s(keys.tweak0, value.substr(0, 32).c_str());
                num_keys++;
            }
            else if (readout.find("BIS KEY 1 (crypt)") != std::string::npos) {
                value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
                strcpy_s(keys.crypt1, value.substr(0, 32).c_str());
                num_keys++;
            }
            else if (readout.find("BIS KEY 1 (tweak)") != std::string::npos) {
                value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
                strcpy_s(keys.tweak1, value.substr(0, 32).c_str());
                num_keys++;
            }
            else if (readout.find("BIS KEY 2 (crypt)") != std::string::npos) {
                value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
                strcpy_s(keys.crypt2, value.substr(0, 32).c_str());
                num_keys++;
            }
            else if (readout.find("BIS KEY 2 (tweak)") != std::string::npos) {
                value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
                strcpy_s(keys.tweak2, value.substr(0, 32).c_str());
                num_keys++;
            }
            else if (readout.find("BIS KEY 3 (crypt)") != std::string::npos) {
                value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
                strcpy_s(keys.crypt3, value.substr(0, 32).c_str());
                num_keys++;
            }
            else if (readout.find("BIS KEY 3 (tweak)") != std::string::npos) {
                value = trim(readout.substr(readout.find(delimiter) + 2, readout.length() + 1));
                strcpy_s(keys.tweak3, value.substr(0, 32).c_str());
                num_keys++;
            }
            else if (readout.find("bis_key_00") != std::string::npos) {
                value = trim(readout.substr(readout.find("=") + 2, readout.length() + 1));
                strcpy_s(keys.crypt0, value.substr(0, 32).c_str());
                strcpy_s(keys.tweak0, value.substr(32, 32).c_str());
                num_keys += 2;
            }
            else if (readout.find("bis_key_01") != std::string::npos) {
                value = trim(readout.substr(readout.find("=") + 2, readout.length() + 1));
                strcpy_s(keys.crypt1, value.substr(0, 32).c_str());
                strcpy_s(keys.tweak1, value.substr(32, 32).c_str());
                num_keys += 2;
            }
            else if (readout.find("bis_key_02") != std::string::npos) {
                value = trim(readout.substr(readout.find("=") + 2, readout.length() + 1));
                strcpy_s(keys.crypt2, value.substr(0, 32).c_str());
                strcpy_s(keys.tweak2, value.substr(32, 32).c_str());
                num_keys += 2;
            }
            else if (readout.find("bis_key_03") != std::string::npos) {
                value = trim(readout.substr(readout.find("=") + 2, readout.length() + 1));
                strcpy_s(keys.crypt3, value.substr(0, 32).c_str());
                strcpy_s(keys.tweak3, value.substr(32, 32).c_str());
                num_keys += 2;
            }
        }
    }
    else
    {
        return ERR_KEYSET_NOT_EXISTS;
    }

    readFile.close();

    if (!num_keys)
        return ERR_KEYSET_EMPTY;
    
    m_keySet_set = true;

    // toupper keys
    for (int i = 0; i < strlen(keys.crypt0); i++) keys.crypt0[i] = toupper(keys.crypt0[i]);
    for (int i = 0; i < strlen(keys.crypt1); i++) keys.crypt1[i] = toupper(keys.crypt1[i]);
    for (int i = 0; i < strlen(keys.crypt2); i++) keys.crypt2[i] = toupper(keys.crypt2[i]);
    for (int i = 0; i < strlen(keys.crypt3); i++) keys.crypt3[i] = toupper(keys.crypt3[i]);
    for (int i = 0; i < strlen(keys.tweak0); i++) keys.tweak0[i] = toupper(keys.tweak0[i]);
    for (int i = 0; i < strlen(keys.tweak1); i++) keys.tweak1[i] = toupper(keys.tweak1[i]);
    for (int i = 0; i < strlen(keys.tweak2); i++) keys.tweak2[i] = toupper(keys.tweak2[i]);
    for (int i = 0; i < strlen(keys.tweak3); i++) keys.tweak3[i] = toupper(keys.tweak3[i]);
    
    BYTE buff[CLUSTER_SIZE];
    DWORD bytesRead;

    for (NxPartition *part : partitions)
        part->setBadCrypto(false);

    memset(&fw_version, 0, strlen(fw_version));
    memset(&deviceId, 0x00, 21);
    macAddress.empty();
    memset(serial_number, 0, strlen(serial_number));

    // Set and validate crypto + retrieve information from encrypted partitions
    NxPartition *cal0 = getNxPartition(PRODINFO);
    if (nullptr != cal0 && !cal0->setCrypto(keys.crypt0, keys.tweak0))
        cal0->setBadCrypto(true);

    NxPartition *system = getNxPartition(SYSTEM);
    if (nullptr != system && !system->setCrypto(keys.crypt2, keys.tweak2))
        system->setBadCrypto(true);
            
    NxPartition *prodinfof = getNxPartition(PRODINFOF);
    if (nullptr != prodinfof && !prodinfof->setCrypto(keys.crypt0, keys.tweak0))
        prodinfof->setBadCrypto(true);

    NxPartition *safe = getNxPartition(SAFE);
    if (nullptr != safe && !safe->setCrypto(keys.crypt1, keys.tweak1))
       safe->setBadCrypto();
    
    NxPartition *user = getNxPartition(USER);
    if (nullptr != user && !user->setCrypto(keys.crypt2, keys.tweak2))
        user->setBadCrypto(true);

    // Retrieve information from encrypted partitions
    if (!badCrypto())
        setStorageInfo();

    if (badCrypto()) 
    {
        dbg_wprintf(L"NxStorage::setKeys(%s) BAD crypto for %s\n", keyset, m_path);
        return ERROR_DECRYPT_FAILED;
    }

    return SUCCESS;
}

void NxStorage::setStorageInfo(int partition)
{
    BYTE buff[CLUSTER_SIZE];
    DWORD bytesRead;

    if (partition == PRODINFO || !partition)
    {
        NxPartition *cal0 = getNxPartition(PRODINFO);
        if (nullptr != cal0 && !cal0->badCrypto() && (!cal0->isEncryptedPartition() || nullptr != cal0->crypto()))
        {
            nxHandle->initHandle(cal0->isEncryptedPartition() ? DECRYPT : NO_CRYPTO, cal0);
            if (nxHandle->read(buff, nullptr, CLUSTER_SIZE))
            {
                // Copy serial number and device id
                memcpy(&serial_number, &buff[0x250], 18);
                memset(&deviceId, 0x00, 21);
                memcpy(&deviceId, &buff[0x544], 20);

                // Copy wlan mac address
                s8 t_wlanMacAddress[7] = { 0 };
                macAddress = "";
                memcpy(&t_wlanMacAddress, &buff[0x210], 6);
                std::string t_macAddress = hexStr(reinterpret_cast<unsigned char*>(t_wlanMacAddress), 6);
                for (std::string::size_type i = 0; i < t_macAddress.size(); i++) {
                    macAddress += t_macAddress[i];
                    if (i & 1 && i != t_macAddress.size() - 1)
                        macAddress.append("-");
                }

            }
        }
    }
    
    if (partition == SYSTEM || !partition)
    {
        NxPartition *system = getNxPartition(SYSTEM);
        if (nullptr != system && !system->badCrypto() && (!system->isEncryptedPartition() || nullptr != system->crypto()))
        {

            //dbg_printf("Get Storage information for SYSTEM\n");
            std::vector<fat32::dir_entry> dir_entries;
            unsigned char buff[CLUSTER_SIZE];

            // Retrieve fw version & exFat driver from NCA in /Contents/registered
            if (system->fat32_dir(&dir_entries, "/Contents/registered"))
            {
                for (fat32::dir_entry nca : dir_entries)
                {
                    //dbg_printf("Found NCA %s\n", nca.filename.c_str());
                    for (NxSystemTitles title : systemTitlesArr)
                    {
                        if (!nca.filename.compare(std::string(title.nca_filename)))
                        {
                            //dbg_printf("Found NCA for fw %s\n", title.fw_version);
                            memcpy(fw_version, title.fw_version, strlen(title.fw_version));
                            break;
                        }
                    }

                    for (NxSystemTitles title : exFatTitlesArr)
                    {
                        if (!nca.filename.compare(std::string(title.nca_filename)))
                        {
                            exFat_driver = true;
                            break;
                        }
                    }
                }
            }

            // Read journal report => /save/80000000000000d1
            if (system->fat32_dir(&dir_entries, "/save/80000000000000d1"))
            {
                fat32::dir_entry *journal = &dir_entries[0];
                u64 cur_off = journal->data_offset;
                u64 max_off = cur_off + journal->entry.file_size;
                s8 fwv[10] = { 0 };

                // Read all journal data --> Let's just assume file is not fragmented in SYSTEM (TODO : Scan FAT for fragmentation)
                while (cur_off < max_off && nxHandle->read(cur_off, buff, &bytesRead, CLUSTER_SIZE))
                {
                    std::string haystack(buff, buff + CLUSTER_SIZE);

                    // Find needle (firmware version) in haystack
                    std::size_t n = haystack.find("OsVersion");
                    if (n != std::string::npos)
                    {
                        strcpy(fwv, haystack.substr(n + 10, 5).c_str());
                        //dbg_printf("Reading /save/80000000000000d1 - OsVersion %s\n", fwv);
                        if (strcmp(fwv, fw_version) > 0) // Only overwrite for higher fw version
                            memcpy(fw_version, fwv, 5);
                    }

                    // Find needle (serial number) in haystack
                    n = haystack.find("\xACSerialNumber");
                    if (!strlen(serial_number) && n != std::string::npos)
                        strcpy(serial_number, haystack.substr(n + 14, 14).c_str());

                    cur_off += bytesRead;
                }
            }
            
            // Read play report => /save/80000000000000a1 --> Let's just assume file is not fragmented in SYSTEM (TODO : Scan FAT for fragmentation)
            if (system->fat32_dir(&dir_entries, "/save/80000000000000a1"))
            {                

                fat32::dir_entry *play_report = &dir_entries[0];
                u64 cur_off = play_report->data_offset;
                u64 max_off = cur_off + play_report->entry.file_size;
                s8 fwv[10] = { 0 };

                //dbg_printf("FOUND %s, off %s, first lba is %I32d\n", play_report->filename.c_str(), n2hexstr(cur_off, 10).c_str(), play_report->data_first_lba); 
                // Read all play report data
                while (cur_off < max_off && nxHandle->read(cur_off, buff, &bytesRead, CLUSTER_SIZE))
                {
                    //dbg_printf("Reading /save/80000000000000a1\n"); 
                    std::string haystack(buff, buff + CLUSTER_SIZE);
                    
                    // Find needle (firmware version) in haystacks
                    std::size_t n = haystack.find("os_version");
                    if (n != std::string::npos)
                    {
                        strcpy(fwv, haystack.substr(n + 11, 5).c_str());
                        if (strcmp(fwv, fw_version) > 0) // Only overwrite for higher fw version
                            memcpy(fw_version, fwv, 5);
                    }
                    cur_off += bytesRead;
                }
            }        
        }
    }
    /*
    if (partition == USER || !partition)
    {
        NxPartition *user = getNxPartition(USER);
        if (nullptr != user && !user->badCrypto() && (!user->isEncryptedPartition() || nullptr != user->crypto()))
        {
            dbg_printf("USER - free space/total space : %s/%s\n", GetReadableSize(user->fat32_getFreeSpace()).c_str(), GetReadableSize(user->size()).c_str());

            std::vector<fat32::dir_entry> dir_entries;
            if (user->fat32_dir(&dir_entries, "/"))
            {
                for (fat32::dir_entry file : dir_entries)
                {
                    dbg_printf("-%s\n", file.filename.c_str());
                }
            }

        }
    }
    */
}

int NxStorage::dumpToFile(const char* file, int crypto_mode, u64 *bytesCount, bool rawnand_only)
{
    if (!*bytesCount)
    {       
        if (crypto_mode == DECRYPT || crypto_mode == ENCRYPT)
            return ERR_CRYPTO_RAW_COPY;

        std::ifstream infile(file);
        if (infile.good())
        {
            infile.close();
            return ERR_FILE_ALREADY_EXISTS;
        }

        p_ofstream = new std::ofstream(file, std::ofstream::binary);
        nxHandle->initHandle(crypto_mode);

        // Skip boot partitions if rawnanand_only
        if (rawnand_only && type == RAWMMC)
            nxHandle->setPointer((u64)0x4000 * NX_BLOCKSIZE);

        m_buff_size = nxHandle->getDefaultBuffSize();
        m_buffer = new BYTE[m_buff_size];
        memset(m_buffer, 0, m_buff_size);

        dbg_printf("NxStorage::dumpToFile(file=%s, crypto_mode=%d, bytesCount=%s)\n", file, crypto_mode, n2hexstr(*bytesCount, 8).c_str());
    }

    DWORD bytesRead = 0;
    if (!nxHandle->read(m_buffer, &bytesRead, m_buff_size))
    {
        p_ofstream->close();
        delete p_ofstream;
        delete[] m_buffer;

        if (*bytesCount == size() || (rawnand_only && type == RAWMMC && *bytesCount == size() - (u64)0x4000 * NX_BLOCKSIZE))
            return NO_MORE_BYTES_TO_COPY;

        dbg_printf("NxStorage::dumpToFile() ERROR, failed to read storage at bytesCount %s\n", n2hexstr(*bytesCount, 8).c_str());
        return ERR_WHILE_COPY;
    }

    p_ofstream->write((char *)&m_buffer[0], bytesRead);
    *bytesCount += bytesRead;
    return SUCCESS;
}

int NxStorage::restoreFromStorage(NxStorage* input, int crypto_mode, u64 *bytesCount)
{
    if (!*bytesCount)
    {        
        if (input->type == INVALID || input->type == UNKNOWN)
            return ERR_INVALID_INPUT;

        if (input->type != this->type)
            return ERR_NX_TYPE_MISSMATCH;

        if (crypto_mode == DECRYPT || crypto_mode == ENCRYPT)
            return ERR_CRYPTO_RAW_COPY;

        if ((input->size() > size() && !m_freeSpace) || (m_freeSpace && input->size() > m_freeSpace)) // Alow restore overflow if freeSpace is available
            return ERR_IO_MISMATCH;

        if (not_in(crypto_mode, { ENCRYPT, DECRYPT }) && input->isEncrypted() && !isEncrypted())
            return ERR_RESTORE_CRYPTO_MISSIN2;

        if (not_in(crypto_mode, { ENCRYPT, DECRYPT }) && !input->isEncrypted() && isEncrypted())
            return ERR_RESTORE_CRYPTO_MISSING;

        // Init handles for both input & output
        input->nxHandle->initHandle(crypto_mode);
        this->nxHandle->initHandle(NO_CRYPTO);
        
        // Restoring to RAWMMC, allow restore from larger input
        if (type == RAWMMC && m_freeSpace)
            this->nxHandle->setOffMax(m_freeSpace);

        m_buff_size = input->nxHandle->getDefaultBuffSize();
        m_buffer = new BYTE[m_buff_size];
        memset(m_buffer, 0, m_buff_size);

        dbg_wprintf(L"NxStorage::restoreFromStorage(NxStorage=%s, crypto_mode=%d, bytesCount=%I64d)\n", input->m_path, crypto_mode, *bytesCount);
    }

    DWORD bytesRead = 0;
    if (!input->nxHandle->read(m_buffer, &bytesRead, m_buff_size))
    {
        delete[] m_buffer;
        dbg_printf("NxStorage::restoreFromStorage() ERROR, failed to read storage at bytesCount %s\n", n2hexstr(*bytesCount, 8).c_str());        
        return ERR_WHILE_COPY;
    }

    DWORD bytesWrite = 0;
    if (!this->nxHandle->write(m_buffer, &bytesWrite, bytesRead))
    {
        delete[] m_buffer;

        if (*bytesCount + bytesWrite != size())
        {
            dbg_printf("NxStorage::restoreFromStorage() ERROR, failed to write storage at bytesCount %s\n", n2hexstr(*bytesCount, 8).c_str());
            return ERR_WHILE_COPY;
        }
    }

    *bytesCount += bytesWrite;

    if (*bytesCount == input->size())
        return NO_MORE_BYTES_TO_COPY;

    return SUCCESS;
}

int NxStorage::resizeUser(const char *file, u32 new_size, u64 *bytesCount, u64 *bytesToRead, bool format)
{
    DWORD bytesRead = 0;
    if (!*bytesCount)
    {
        // Controls
        if (not_in(type, { RAWNAND, RAWMMC }))
            return ERR_INVALID_INPUT;

        if (isEncrypted() && !m_keySet_set)
            return ERR_CRYPTO_KEY_MISSING;

        if (isEncrypted() && badCrypto())
            return ERROR_DECRYPT_FAILED;

        //u32 cl_new_size = (u64)(new_size * NX_BLOCKSIZE) / CLUSTER_SIZE;

        NxPartition *user = getNxPartition(USER);

        if (!user->isEncryptedPartition())
            return ERR_INVALID_INPUT;

        u32 new_fat_size = new_size / 0x1000;
        u32 new_total_size = new_fat_size + new_size + 32; // 32 sectors (1 cluster) reserved
        u32 user_min_size = format ? (u32) 64 * 1024 / NX_BLOCKSIZE : (u32)((user->size() - user->freeSpace) / 0x200);

        // Adjust new_size if too small
        if (new_total_size < user_min_size)
            new_total_size = user_min_size;

        // Align new size (64 Mb)
        /*
        if (new_total_size / 0x20000 < 1)
            new_total_size = 0x20000;
        else if (new_total_size % 0x20000)
            new_total_size = (new_total_size / 0x20000) * 0x20000 + 0x20000;
        */

        m_user_new_size = new_total_size - 32; // Subtract reserved sectores for full size
        m_user_new_size = m_user_new_size - (m_user_new_size / 0x1001); // Substract FAT size
        m_user_total_size = new_total_size;

        dbg_printf("NxStorage::resizeUser() m_user_new_size = %I32d, m_user_total_size = %I32d \n", m_user_new_size, m_user_total_size);

        // Get handle for output
        std::ifstream infile(file);
        if (infile.good())
        {
            infile.close();
            return ERR_FILE_ALREADY_EXISTS;
        }
        p_ofstream = new std::ofstream(file, std::ofstream::binary);
        // Bytes count for output
        bytes_count = 0;

        // Set copy vars
        m_gpt_lba_start = type == RAWMMC ? 0x4000 : 0;
        m_user_lba_start = user->lbaStart();
        m_user_lba_end = user->lbaEnd() - (u32)(user->freeSpace / NX_BLOCKSIZE + NX_BLOCKSIZE);

        // Init input handle & buffer
        nxHandle->initHandle(NO_CRYPTO);
        m_buff_size = DEFAULT_BUFF_SIZE;
        m_buffer = new BYTE[DEFAULT_BUFF_SIZE];
        memset(m_buffer, 0, DEFAULT_BUFF_SIZE);
    }

    // Reach GPT - Resize USER partition
    if (*bytesCount == (u64)m_gpt_lba_start * NX_BLOCKSIZE)
    {
        dbg_printf("NxStorage::resizeUser() - REACH GPT\n");

        delete[] m_buffer;
        m_buffer = new BYTE[CLUSTER_SIZE];
        m_buff_size = CLUSTER_SIZE;

        if (!nxHandle->read(m_buffer, &bytesRead, m_buff_size))
        {
            delete[] m_buffer;
            delete p_ofstream;
            return ERR_WHILE_COPY;
        }
        *bytesCount += m_buff_size;

        // GPT Header
        GptHeader *hdr = (GptHeader *)(m_buffer + 0x200);

        // Get entry for USER & resize
        u32 table_off = 0x200 + (hdr->part_ent_lba - 1) * NX_BLOCKSIZE;
        GptEntry *user_ent = (GptEntry *)(m_buffer + table_off + (hdr->num_part_ents - 1) * hdr->part_ent_size);
        user_ent->lba_end = user_ent->lba_start + m_user_total_size - 1;

        // New CRC32 for partition table
        u32 table_size = hdr->num_part_ents * hdr->part_ent_size;
        unsigned char *table = new unsigned char[table_size];
        memcpy(&table[0], &m_buffer[table_off], table_size);
        hdr->part_ents_crc32 = crc32Hash(table, table_size);
        dbg_printf("NxStorage::resizeUser() - new CRC32 for partition table %I32d\n", hdr->part_ents_crc32);
        delete[] table;

        // New values for header
        hdr->last_use_lba = user_ent->lba_end;
        hdr->alt_lba = hdr->last_use_lba + 33;

        dbg_printf("NxStorage::resizeUser() - new GPT header - user_bla_ends %I32d,  backup_gpt_bla %I32d\n", user_ent->lba_end, hdr->alt_lba);

        // Set new backup GPT off
        m_user_new_bckgpt = hdr->alt_lba;
        if (type == RAWMMC) m_user_new_bckgpt += 0x4000;
        *bytesToRead = (u64)(m_user_new_bckgpt + 1) * NX_BLOCKSIZE;

        // New CRC32 for header
        unsigned char header[92];
        memcpy(&header[0], &hdr[0], 92);
        memset(&header[16], 0, 4);
        hdr->crc32 = crc32Hash(header, 92);

        // Save GPT header
        memcpy(gpt_header_buffer, &hdr[0], 0x200);

        // Write GPT buffer
        p_ofstream->write((char *)&m_buffer[0], m_buff_size);
        bytes_count += m_buff_size;

        // Change buffer size
        delete[] m_buffer;
        m_buffer = new BYTE[DEFAULT_BUFF_SIZE];
        m_buff_size = DEFAULT_BUFF_SIZE;

        return SUCCESS;
    }

    // Reach USER - Resize FAT
    else if (*bytesCount == (u64)m_user_lba_start * NX_BLOCKSIZE)
    {
        dbg_printf("NxStorage::resizeUser() - REACH USER\n");
        // New buffer size is CLUSTER
        delete[] m_buffer;
        m_buffer = new BYTE[CLUSTER_SIZE];
        m_buff_size = CLUSTER_SIZE;

        NxPartition *user = getNxPartition(USER);
        nxHandle->initHandle(DECRYPT, user);
        cpy_cl_count_out = 0;

        // Read first cluster
        if (!nxHandle->read(m_buffer, &bytesRead, m_buff_size))
        {
            delete[] m_buffer;
            delete p_ofstream;
            return ERR_WHILE_COPY;
        }
        *bytesCount += CLUSTER_SIZE;

        // Get FAT size from boot sector
        u32 fat_size;
        u8 num_fats;
        memcpy(&fat_size, &m_buffer[0x24], 4);
        memcpy(&num_fats, &m_buffer[0x10], 1);
        u32 cluster_num = fat_size * NX_BLOCKSIZE / CLUSTER_SIZE;

        // New FAT size
        u32 new_fat_size = m_user_new_size / 0x1000; // each entry in cluster map is 4 bytes long
        u32 new_cluster_num = new_fat_size * NX_BLOCKSIZE / CLUSTER_SIZE;
        memcpy(&m_buffer[0x24], &new_fat_size, 4);

        dbg_printf("NxStorage::resizeUser() - new FAT size %I32d (previous %I32d)\n", new_fat_size, fat_size);

        // Encrypt cluster
        user->crypto()->encrypt(m_buffer, cpy_cl_count_out);

        // Write first cluster
        p_ofstream->write((char *)&m_buffer[0], CLUSTER_SIZE);
        cpy_cl_count_out++;
        bytes_count += CLUSTER_SIZE;

        // Read & Write needed clusters for new FAT        
        // For each FAT
        for (int j(0); j < (unsigned int)num_fats; j++)
        {            
            u32 clusters_to_copy = new_cluster_num > cluster_num ? cluster_num : new_cluster_num;
            if (format) clusters_to_copy = 0;

            // Write needed clusters from input FAT
            for (int i(1); i <= cluster_num; i++)
            {
                // Always read the entire input FAT, even if not copied, to get bytesCount & good pointer for USER data
                nxHandle->read(m_buffer, nullptr, CLUSTER_SIZE);
                *bytesCount += CLUSTER_SIZE;
                
                // Write only if needed
                if (i <= clusters_to_copy && !format)
                {
                    user->crypto()->encrypt(m_buffer, cpy_cl_count_out);;
                    p_ofstream->write((char *)&m_buffer[0], CLUSTER_SIZE);
                    cpy_cl_count_out++;
                    bytes_count += CLUSTER_SIZE;
                }
            }

            // Fill output FAT with more clusters if needed
            if (new_cluster_num > clusters_to_copy)
            {
                clusters_to_copy = new_cluster_num - clusters_to_copy;
                for (int i(1); i <= clusters_to_copy; i++)
                {                    
                    memset(m_buffer, 0, CLUSTER_SIZE); // Clear buffer
                    // Format
                    if (i == 1 && format) {
                        unsigned char first_fats[12] = { 0xf8, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0x0f, 0xf8, 0xff, 0xff, 0x0f };
                        memcpy(&m_buffer[0], first_fats, 12);
                    }

                    user->crypto()->encrypt(m_buffer, cpy_cl_count_out);;
                    p_ofstream->write((char *)&m_buffer[0], CLUSTER_SIZE);
                    cpy_cl_count_out++;
                    bytes_count += CLUSTER_SIZE;
                }
            }
        }
        return SUCCESS;
    }

    // Copy USER
    else  if (*bytesCount > (u64)m_user_lba_start * NX_BLOCKSIZE)
    {
        // Copy from input
        if ((*bytesCount <= (u64)m_user_lba_end * NX_BLOCKSIZE) && !format)
        {
            dbg_printf("COPY USER DATA FROM INPUT\n");
            // Read and encrypt from input
            nxHandle->read(m_buffer, nullptr, CLUSTER_SIZE);
            getNxPartition(USER)->crypto()->encrypt(m_buffer, cpy_cl_count_out);
            p_ofstream->write((char *)&m_buffer[0], CLUSTER_SIZE);
            cpy_cl_count_out++;
            *bytesCount += CLUSTER_SIZE;

            return SUCCESS;
        }
        // Fill output
        else
        {
            u64 cur_off = p_ofstream->tellp();
            u64 bck_gpt_off = (u64)m_user_new_bckgpt * NX_BLOCKSIZE;
            memset(m_buffer, 0, CLUSTER_SIZE); // Clear buffer
            getNxPartition(USER)->crypto()->encrypt(m_buffer, cpy_cl_count_out);
            cpy_cl_count_out++;

            // Fill with empty buffer until GPT backup offset
            if (cur_off < bck_gpt_off)
            {
                p_ofstream->write((char *)&m_buffer[0], CLUSTER_SIZE);
                *bytesCount += CLUSTER_SIZE;

                return SUCCESS;
            }
            else
            {
                if (cur_off == bck_gpt_off)
                {
                    p_ofstream->write((char *)&gpt_header_buffer[0], 0x200);
                    *bytesCount += CLUSTER_SIZE;
                }

                p_ofstream->close();
                delete[] m_buffer;
                delete p_ofstream;

                return cur_off == bck_gpt_off ? NO_MORE_BYTES_TO_COPY : ERR_WHILE_COPY;
            }
        }
        return SUCCESS;
    }

    // Every other iteration
    else
    {
        // Read buffer
        if (!nxHandle->read(m_buffer, &bytesRead, m_buff_size))
        {
            delete[] m_buffer;
            delete p_ofstream;
            dbg_printf("NxStorage::resizeUser() - ERROR UNTYPED BUFFER\n");
            return ERR_WHILE_COPY;
        }

        // Resize buffer 
        if (*bytesCount + bytesRead > (u64)m_user_lba_start * NX_BLOCKSIZE)
            bytesRead -= (u32)(*bytesCount + bytesRead - (u64)(m_user_lba_start * NX_BLOCKSIZE));

        // Write buffer
        p_ofstream->write((char *)&m_buffer[0], bytesRead);
        *bytesCount += bytesRead;
        return SUCCESS;
    }
    return ERR_WHILE_COPY;
}

const char* NxStorage::getNxTypeAsStr()
{
    for (NxStorageType t : NxTypesArr)
    {
        if (type == t.type)
            return t.name;
    }
    return "UNKNOWN";
}

int NxStorage::getNxTypeAsInt(const char* type)
{
    if (nullptr == type)
        return this->type;

    for (NxStorageType t : NxTypesArr)
    {
        if (!strncmp(t.name, type, strlen(type)))
            return t.type;
    }
    return UNKNOWN;
}

bool NxStorage::badCrypto()
{
    for (NxPartition *p : partitions)
        if (p->badCrypto())
            return true;

    return false;
}

bool NxStorage::isEncrypted()
{
    for (NxPartition *p : partitions)
        if (p->isEncryptedPartition())
            return true;

    return false;
}

bool NxStorage::isSinglePartType(int part_type)
{
    if (!part_type)
        part_type = type;

    if (is_in(part_type, { BOOT0 , BOOT1 , PRODINFO, PRODINFOF, BCPKG21, BCPKG22, BCPKG23, BCPKG24, BCPKG25, BCPKG26, SAFE, SYSTEM, USER }))
        return true;

    return false;
}

bool NxStorage::isNxStorage()
{
    if (type == UNKNOWN || type == INVALID)
        return false;

    return true;
}

NxPartition* NxStorage::getNxPartition()
{
    return getNxPartition(type);
}

NxPartition* NxStorage::getNxPartition(int part_type)
{
    if (!part_type || partitions.size() == 0)
        return nullptr;


    for (NxPartition *cur_part : partitions)
    {
        if (cur_part->type() == part_type)
            return cur_part;
    }
    return nullptr;
}

NxPartition* NxStorage::getNxPartition(const char* part_name)
{
    if (nullptr == part_name || partitions.size() == 0)
        return nullptr;

    string partname(part_name);
    std::transform(partname.begin(), partname.end(), partname.begin(), ::toupper);

    for (NxPartition *cur_part : partitions)
    {
        string cur_part_name(cur_part->partitionName());
        std::transform(cur_part_name.begin(), cur_part_name.end(), cur_part_name.begin(), ::toupper);

        //printf("COMPARE %s TO %s\n", cur_part_name.c_str(), partname.c_str());
        if (!cur_part_name.compare(partname))
            return cur_part;
    }
    return nullptr;
}

bool NxStorage::isDrive() { return nxHandle->isDrive(); }

bool NxStorage::partitionExists(const char* partition_name)
{
    bool found = false;
    for (NxPartition *part : partitions)
    {
        if (!part->partitionName().compare(partition_name))
        {
            found = true;
            break;
        }
    }
    return found;
}

bool NxStorage::setAutoRcm(bool enable)
{
    NxPartition *boot0 = getNxPartition(BOOT0);
    if (nullptr == boot0)
        return false;

    nxHandle->initHandle(NO_CRYPTO, boot0);
    DWORD bytesRead = 0;
    BYTE buff[0x200];

    if (nxHandle->read((u64)0x200, buff, &bytesRead, NX_BLOCKSIZE))
    {
        u8 randomXor = 0;
        if (enable) {
            do randomXor = (unsigned)time(NULL) & 0xFF; // Bricmii style of bricking.
            while (!randomXor); // Avoid the lottery.
            buff[0x10] ^= randomXor;
        }
        else buff[0x10] = 0xF7;

        if (nxHandle->write((u64)0x200, buff, &bytesRead, 0x200))
        {
            autoRcm = enable;
            return true;
        }
    }
    return false;
}

int NxStorage::applyIncognito()
{
    NxPartition *cal0 = getNxPartition(PRODINFO);
    if (nullptr == cal0)
        return ERR_IN_PART_NOT_FOUND;

    if(cal0->isEncryptedPartition() && (cal0->badCrypto() || nullptr == cal0->crypto()))
        return ERROR_DECRYPT_FAILED;

    nxHandle->initHandle(!cal0->isEncryptedPartition() ? NO_CRYPTO : DECRYPT, cal0);
    BYTE cl_buffer[CLUSTER_SIZE];
    DWORD bytesRead = 0;

    // Read first cluster
    if (!nxHandle->read(cl_buffer, &bytesRead, CLUSTER_SIZE)) 
        return ERR_INPUT_HANDLE;
    
    // Read cal0 data size
    uint32_t calib_data_size;
    memcpy(&calib_data_size, &cl_buffer[0x08], 0x04);

    // Set new buffer for cal0 data and push first cluster in it
    BYTE *buffer = new BYTE[calib_data_size + 0x40];
    memcpy(&buffer[0], cl_buffer, CLUSTER_SIZE);

    // Read and push needed clusters
    int buf_size = CLUSTER_SIZE;
    while (buf_size < (calib_data_size + 0x40))
    {
        if (!nxHandle->read(cl_buffer, &bytesRead, CLUSTER_SIZE))
            break;

        memcpy(&buffer[buf_size], cl_buffer, CLUSTER_SIZE);
        buf_size += CLUSTER_SIZE;
    }

    // Get cert size
    uint32_t cert_size;
    memcpy(&cert_size, &buffer[0x0AD0], 0x04);

    // Erase data, the way blawar's incognito does it
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
    memcpy(&buffer[0x12E0], &hash[0], 0x20);
    delete[] cert;

    // Generate new SHA256 hash for calibration data
    unsigned char *calib_data = new unsigned char[calib_data_size];
    memcpy(calib_data, &buffer[0x040], calib_data_size);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, calib_data, calib_data_size);
    SHA256_Final(hash, &sha256);
    memcpy(&buffer[0x20], &hash[0], 0x20);
    delete[] calib_data;

    // Push back clusters
    nxHandle->initHandle(!cal0->isEncryptedPartition() ? NO_CRYPTO : ENCRYPT, cal0);
    int num_cluster = buf_size / CLUSTER_SIZE - 1;
    for (int i = 0; i <= num_cluster; i++)
    {
        memcpy(&cl_buffer[0], &buffer[i*CLUSTER_SIZE], CLUSTER_SIZE);
        if (!nxHandle->write(cl_buffer, &bytesRead, CLUSTER_SIZE))
        {
            delete[] buffer;
            return ERR_INPUT_HANDLE;
        }
    }

    setStorageInfo(PRODINFO);
    delete[] buffer;
    return SUCCESS;
}

std::string BuildChecksum(HCRYPTHASH hHash)
{
    std::string md5hash;
    DWORD cbHash = 16;
    BYTE rgbHash[16];
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

std::string ListPhysicalDrives()
{
    int num_drive = 0;
    std::string compatibleDrives;

    for (int drive = 0; drive < 16; drive++)
    {
        char driveName[256];
        sprintf_s(driveName, 256, "\\\\.\\PhysicalDrive%d", drive);

        NxStorage storage = NxStorage(driveName);        
        //printf("Drive %s is type %s\n", driveName, storage.getNxTypeAsStr());
        if (storage.isNxStorage())
            compatibleDrives.append(driveName).append(" [" + GetReadableSize(storage.size()) + " - " + storage.getNxTypeAsStr() + "]\n");
        
    }
    return compatibleDrives;
}
