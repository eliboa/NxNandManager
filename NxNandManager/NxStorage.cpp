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


static MagicOffsets mgkOffArr[] =
{
    // { offset, magic, size, type, firwmare }
    { 0, "43414C30", 4, PRODINFO}, // PRODINFO ("CAL0" at offset 0x0)
    { 0x680, "434552544946", 6, PRODINFOF}, // PRODINFOF ("CERTIF at offset 0x680")
    { 0x200, "4546492050415254", 8, RAWNAND, 0 }, // RAWNAND ("EFI PART" at offset 0x200)
    //{ 0x200, "54584E414E44", 6, TXNAND, 0}, // TX hidden paritition ("TXNAND" at offset 0x200)
    { 0x800200, "4546492050415254", 8, RAWMMC, 0}, // RAWMMC ("EFI PART" at offset 0x80000, i.e after 2 x 0x40000 for each BOOT)
    { 0x1800200, "4546492050415254", 8, EMMC_PART, 0}, // RAWMMC
    { 0x0530, "010021000E00000009000000", 12, BOOT0, 0}, // BOOT0 (boot_data_version + block_size_log2 + page_size_log2 at offset 0x530)
    // BOOT1 => Look for PK11 magic
    { 0x13B4, "504B3131", 4, BOOT1, 1},
    { 0x13F0, "504B3131", 4, BOOT1, 2},
    { 0x1424, "504B3131", 4, BOOT1, 3},
    { 0x12E8, "504B3131", 4, BOOT1, 4},
    { 0x12D0, "504B3131", 4, BOOT1, 5},
    { 0x12F0, "504B3131", 4, BOOT1, 6},
    { 0x40AF8,"504B3131", 4, BOOT1, 7},
    { 0x40ADC,"504B3131", 4, BOOT1, 8},
    { 0x40ACC,"504B3131", 4, BOOT1, 8.1},
    { 0x40AC0,"504B3131", 4, BOOT1, 9}
};


static NxStorageType NxTypesArr[] =
{
    { INVALID  , "INVALID" },
    { BOOT0    , "BOOT0" },
    { BOOT1    , "BOOT1" },
    { RAWNAND  , "RAWNAND" },
    { PARTITION, "PARTITION" },
    { RAWMMC   , "FULL NAND" },
    { TXNAND   , "TXNAND" },
    { PRODINFO , "PRODINFO" },
    { PRODINFOF, "PRODINFOF" },
    { BCPKG21  , "BCPKG2-1-Normal-Main" },
    { BCPKG22  , "BCPKG2-2-Normal-Sub" },
    { BCPKG23  , "BCPKG2-3-SafeMode-Main" },
    { BCPKG24  , "BCPKG2-4-SafeMode-Sub" },
    { BCPKG25  , "BCPKG2-5-Repair-Main" },
    { BCPKG26  , "BCPKG2-6-Repair-Sub" },
    { SAFE     , "SAFE" },
    { SYSTEM   , "SYSTEM" },
    { USER     , "USER" },
    { UNKNOWN  , "UNKNOWN" }
};

static NxSystemTitles systemTitlesArr[] = {
    { "9.1.0", "c5fbb49f2e3648c8cfca758020c53ecb.nca"},
    { "9.0.1", "fd1ffb82dc1da76346343de22edbc97c.nca"},
    { "9.0.0", "a6af05b33f8f903aab90c8b0fcbcc6a4.nca"},
    { "8.1.0", "7eedb7006ad855ec567114be601b2a9d.nca"},
    { "8.0.1", "6c5426d27c40288302ad616307867eba.nca"},
    { "8.0.0", "4fe7b4abcea4a0bcc50975c1a926efcb.nca"},
    { "7.0.1", "e6b22c40bb4fa66a151f1dc8db5a7b5c.nca"},
    { "7.0.0", "c613bd9660478de69bc8d0e2e7ea9949.nca"},
    { "6.2.0", "6dfaaf1a3cebda6307aa770d9303d9b6.nca"},
    { "6.1.0", "1d21680af5a034d626693674faf81b02.nca"},
    { "6.0.1", "663e74e45ffc86fbbaeb98045feea315.nca"},
    { "6.0.0", "258c1786b0f6844250f34d9c6f66095b.nca"},
    { "6.0.0 (pre-release)", "286e30bafd7e4197df6551ad802dd815.nca"},
    { "5.1.0", "fce3b0ea366f9c95fe6498b69274b0e7.nca"},
    { "5.0.2", "c5758b0cb8c6512e8967e38842d35016.nca"},
    { "5.0.1", "7f5529b7a092b77bf093bdf2f9a3bf96.nca"},
    { "5.0.0", "faa857ad6e82f472863e97f810de036a.nca"},
    { "4.1.0", "77e1ae7661ad8a718b9b13b70304aeea.nca"},
    { "4.0.1", "d0e5d20e3260f3083bcc067483b71274.nca"},
    { "4.0.0", "f99ac61b17fdd5ae8e4dda7c0b55132a.nca"},
    { "3.0.2", "704129fc89e1fcb85c37b3112e51b0fc.nca"},
    { "3.0.1", "9a78e13d48ca44b1987412352a1183a1.nca"},
    { "3.0.0", "7bef244b45bf63efb4bf47a236975ec6.nca"},
    { "2.3.0", "d1c991c53a8a9038f8c3157a553d876d.nca"},
    { "2.2.0", "7f90353dff2d7ce69e19e07ebc0d5489.nca"},
    { "2.1.0", "e9b3e75fce00e52fe646156634d229b4.nca"},
    { "2.0.0", "7a1f79f8184d4b9bae1755090278f52c.nca"},
    { "1.0.0", "a1b287e07f8455e8192f13d0e45a2aaf.nca"}
};

static NxSystemTitles exFatTitlesArr[] = {
    {"9.1.0", "c9bd4eda34c91a676de09951bb8179ae.nca" },
    {"9.0.1", "3b444768f8a36d0ddd85635199f9676f.nca" },
    {"9.0.0", "3b444768f8a36d0ddd85635199f9676f.nca" },
    {"8.1.0", "96f4b8b729ade072cc661d9700955258.nca" },
    {"8.0.1", "b2708136b24bbe206e502578000b1998.nca" },
    {"8.0.0", "b2708136b24bbe206e502578000b1998.nca" },
    {"7.0.1", "02a2cbfd48b2f2f3a6cec378d20a5eff.nca" },
    {"7.0.0", "58c731cdacb330868057e71327bd343e.nca" },
    {"6.2.0", "97cb7dc89421decc0340aec7abf8e33b.nca" },
    {"6.1.0", "d5186022d6080577b13f7fd8bcba4dbb.nca" },
    {"6.0.1", "d5186022d6080577b13f7fd8bcba4dbb.nca" },
    {"6.0.0", "d5186022d6080577b13f7fd8bcba4dbb.nca" },
    {"6.0.0 (pre-release)", "711b5fc83a1f07d443dfc36ba606033b.nca" },
    {"5.1.0", "c9e500edc7bb0fde52eab246028ef84c.nca" },
    {"5.0.2", "432f5cc48e6c1b88de2bc882204f03a1.nca" },
    {"5.0.1", "432f5cc48e6c1b88de2bc882204f03a1.nca" },
    {"5.0.0", "432f5cc48e6c1b88de2bc882204f03a1.nca" },
    {"4.1.0", "458a54253f9e49ddb044642286ca6485.nca" },
    {"4.0.1", "090b012b110973fbdc56a102456dc9c6.nca" },
    {"4.0.0", "090b012b110973fbdc56a102456dc9c6.nca" },
    {"3.0.2", "e7dd3c6cf68953e86cce54b69b333256.nca" },
    {"3.0.1", "17f9864ce7fe3a35cbe3e3b9f6185ffb.nca" },
    {"3.0.0", "9e5c73ec938f3e1e904a4031aa4240ed.nca" },
    {"2.3.0", "4a94289d2400b301cbe393e64831f84c.nca" },
    {"2.2.0", "4a94289d2400b301cbe393e64831f84c.nca" },
    {"2.1.0", "4a94289d2400b301cbe393e64831f84c.nca" },
    {"2.0.0", "f55a04978465ebf5666ca93e21b26dd2.nca" },
    {"1.0.0", "3b7cd379e18e2ee7e1c6d0449d540841.nca" }
};

static u8 tx_sector[112] = {
    0x54, 0x58, 0x4E, 0x41, 0x4E, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x41, 0x74, 0x6D, 0x6F, 0x73, 0x70, 0x68, 0x65,
    0x72, 0x65, 0x2D, 0x4E, 0x58, 0x20, 0x20, 0x52, 0x6F, 0x63, 0x6B, 0x69,
    0x6E, 0x67, 0x20, 0x74, 0x68, 0x65, 0x20, 0x53, 0x77, 0x69, 0x74, 0x63,
    0x68, 0x20, 0x66, 0x6F, 0x72, 0x65, 0x76, 0x65, 0x72, 0x20, 0x61, 0x6E,
    0x64, 0x20, 0x62, 0x65, 0x79, 0x6F, 0x6E, 0x64, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xA4, 0x03,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x4E, 0x78, 0x4E, 0x61, 0x6E, 0x64, 0x4D, 0x61, 0x6E, 0x61, 0x67, 0x65,
    0x72, 0x00, 0x00, 0x00
};


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
    std::string s(p_path);

    wchar_t w_p[MAX_PATH];
    mbstowcs(m_path, p_path, MAX_PATH);
    dbg_wprintf(L"NxStorage::NxStorage() m_path is %s\n", m_path);

    // Get handle to file/disk
    nxHandle = new NxHandle(this);
    if (!nxHandle->exists)
        return;

    nxHandle->detectSplittedStorage();

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
        dbg_printf("NxStorage::NxStorage() - Looking for magic %s at offset %s\n", mgk.magic, n2hexstr(mgk.offset, 10).c_str());
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

            if (!basename.compare(p_name))
            {
                bool found = false;
                if (p_name == "USER") found = true;
                else if (part.size != m_size && part.magic != nullptr)
                {
                    // If size doesn't match, check for magic if file is unencrypted
                    unsigned char first_cluster[CLUSTER_SIZE];
                    nxHandle->initHandle(NO_CRYPTO);
                    if(nxHandle->read(first_cluster, nullptr, CLUSTER_SIZE) && !memcmp(&first_cluster[part.magic_off], part.magic, strlen(part.magic)))
                        found = true;
                }
                else if (part.size == m_size) found = true;

                if (found)
                {
                    type = getNxTypeAsInt(part.name);
                    // Add new Nxpartition
                    NxPartition *part = new NxPartition(this, basename.c_str(), (u32)0, (u32)m_size / NX_BLOCKSIZE - 1);
                    break;
                }
            }
            else if (part.size == m_size)
                b_MayBeNxStorage = true;
        }
    }
    
    // Look for emuMMC partition
    if (type == UNKNOWN)
    {        
        /*
        nxHandle->initHandle();
        mbr_t mbr2;
        if (nxHandle->read(&mbr2, &bytesRead, NX_BLOCKSIZE))
        {
            dbg_printf("MBR2 =\n%s\n", hexStr((u8*)&mbr2, NX_BLOCKSIZE).c_str());
            dbg_printf("MBR2.bootstrap =\n%s\n", hexStr((u8*)mbr2.bootstrap_area, 0x1BE).c_str());     
            dbg_printf("MBR2.part1 = %s\n", hexStr(reinterpret_cast<unsigned char *>(&mbr2.parts[0]), 0x10).c_str());
            u32 sector_start = u32_val(mbr2.parts[0].lba_start);
            u64 size = (u64)u32_val(mbr2.parts[0].lba_count) * NX_BLOCKSIZE;
            dbg_printf("MBR2.part1 sector_start = %I32d, size = %s\n", sector_start, GetReadableSize(size).c_str());
            dbg_printf("MBR2.part2 = %s\n", hexStr(reinterpret_cast<unsigned char *>(&mbr2.parts[1]), 0x10).c_str());
            dbg_printf("MBR2.part3 = %s\n", hexStr(reinterpret_cast<unsigned char *>(&mbr2.parts[2]), 0x10).c_str());
            dbg_printf("MBR2.part4 = %s\n", hexStr(reinterpret_cast<unsigned char *>(&mbr2.parts[3]), 0x10).c_str());
            dbg_printf("MBR SIGNATURE = %s\n", hexStr(mbr2.signature, 2).c_str());
            dbg_printf("MBR2 mbr_t size %I32d, mbr_part_t size %I32d, bootstrap_area size %I32d, signature size %I32d \n", 
                sizeof(mbr_t), sizeof(mbr_part_t), sizeof(mbr2.bootstrap_area), sizeof(mbr2.signature)); 
            
        }
        */

        nxHandle->initHandle();
        mbr_t mbr;
        WCHAR  volumeName[MAX_PATH] = L"";

        // If first sector is MBR
        if (nxHandle->read(&mbr, &bytesRead, NX_BLOCKSIZE) && hexStr(mbr.signature, 2) == "55AA")
        {
            u8 *efi_part = (u8 *)malloc(0x200);            
            u32 curr_part_size = 0, sector_start = 0, sector_count = 0;         

            // Iterate MBR primary partitions
            for (int i = 1; i < 4; i++)
            {                       
                sector_start = u32_val(mbr.parts[i].lba_start);
                sector_count = u32_val(mbr.parts[i].lba_count);

                if (!sector_start)
                    continue;

                // Get volume name for partition
                if (nxHandle->getVolumeName(volumeName, sector_start))
                {
                    dbg_wprintf(L"getVolumeName() returns %s", volumeName);

                    // Recreate new NxHandle for volume
                    wcscpy(m_path, volumeName);
                    delete nxHandle;
                    nxHandle = new NxHandle(this);                    

                    if (nxHandle->read((u32)0xC001, efi_part, &bytesRead, NX_BLOCKSIZE)
                        && !memcmp(efi_part, "EFI PART", 8)) //GPT header
                    {
                        type = RAWMMC;
                        mmc_b0_lba_start = 0x8000;
                        m_freeSpace = m_size;
                        m_size = (u64)(sector_count - 0x8000) * NX_BLOCKSIZE;
                        break;
                    }
                    else if (nxHandle->read((u32)sector_start + 0x4001, efi_part, &bytesRead, NX_BLOCKSIZE)
                        && !memcmp(efi_part, "EFI PART", 8)) //GPT header
                    {
                        type = RAWMMC;
                        mmc_b0_lba_start = 0;
                        m_freeSpace = m_size;
                        m_size = (u64)sector_count * NX_BLOCKSIZE;
                        break;
                    }
                }
                // No volume found for partition, stay on physical drive
                else
                {
                    if (nxHandle->read(sector_start + 0xC001, efi_part, &bytesRead, NX_BLOCKSIZE)
                        && !memcmp(efi_part, "EFI PART", 8)) //GPT header
                    {
                        type = RAWMMC;
                        mmc_b0_lba_start = sector_start + 0x8000;
                        m_size = (u64)(sector_count - 0x8000) * NX_BLOCKSIZE;
                        m_freeSpace = m_size;
                        break;
                    }
                    else if (nxHandle->read((u32)sector_start + 0x4001, efi_part, &bytesRead, NX_BLOCKSIZE)
                        && !memcmp(efi_part, "EFI PART", 8)) //GPT header
                    {
                        type = RAWMMC;
                        mmc_b0_lba_start = sector_start;
                        m_size = (u64)sector_count * NX_BLOCKSIZE;
                        m_freeSpace = m_size;
                        break;
                    }
                }
            }

            // Look for "foreign" emunand ^^
            if (type != RAWMMC && nxHandle->read((u32)0x4003, efi_part, &bytesRead, NX_BLOCKSIZE) && !memcmp(efi_part, "EFI PART", 8))
            {
                type = RAWMMC;
                mmc_b0_lba_start = 2;
                sector_start = u32_val(mbr.parts[0].lba_start);
                m_freeSpace = (u64)(sector_start - mmc_b0_lba_start) * NX_BLOCKSIZE;                
            }
            free(efi_part);
        }
    }

    // RAWNAND or FULL NAND : Add NxPartition for each GPP or BOOT partition
    if(is_in(type, {RAWNAND, RAWMMC, EMMC_PART }))
    {        
        if (type == EMMC_PART)
        {
            mmc_b0_lba_start = 0x8000;
            type = RAWMMC;
        }

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
                
                dbg_printf("GPT Header CRC32 = %I32d\n", hdr->c_crc32);
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
                dbg_printf("Offset from hdr->alt_lba is %s\n", n2hexstr(off, 12).c_str());
                if (type == RAWMMC)
                    off += 0x4000 * NX_BLOCKSIZE;
                m_size = off + NX_BLOCKSIZE;
               
                nxHandle->initHandle();

                memset(buff, 0, 8);
                if (nxHandle->read(off, buff, &bytesRead, 0x200) && !memcmp(&buff[0], "EFI PART", 8))
                {
                    m_backupGPT = off;
                    dbg_printf("NxStorage::NxStorage() - backup GPT found at offset %s\n", n2hexstr(m_backupGPT, 10).c_str());
                    if (type == EMMC_PART) type = RAWMMC;
                }
                //dbg_printf("GPTbackup buff\n%s\n", hexStr(buff, 0x200).c_str());
            }
        }

        if (!cal0_found)
        {
            dbg_printf("NxStorage::NxStorage() - Error CAL0 not found in %s\n", getNxTypeAsStr());
            type = UNKNOWN;
            partitions.clear();
        }
    }


    dbg_printf("NxStorage::NxStorage() - TYPE IS %s\n", getNxTypeAsStr());
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

        // Read package1loader header (copied from Atmosphere/fusee/fusee-secondary/src/nxboot.c)
        if (nxHandle->read((u64)0x100000, buff, &bytesRead, NX_BLOCKSIZE))
        {
            package1ldr_header_t pk1ldr;
            memcpy(&pk1ldr, &buff[0], 0x20);            
            switch (pk1ldr.version) {
                case 0x01:          /* 1.0.0 */
                    firmware_version_boot0.major = 1;
                    firmware_version_boot0.minor = 0;
                    firmware_version_boot0.micro = 0;
                    break;
                case 0x02:          /* 2.0.0 - 2.3.0 */
                    firmware_version_boot0.major = 2;
                    break;
                case 0x04:          /* 3.0.0 and 3.0.1 - 3.0.2 */
                    firmware_version_boot0.major = 3;
                    firmware_version_boot0.minor = 0;
                    if (memcmp(pk1ldr.build_timestamp, "20170519", 8) == 0)
                        firmware_version_boot0.micro = 0;
                    break;
                case 0x07:          /* 4.0.0 - 4.1.0 */
                    firmware_version_boot0.major = 4;
                    break;
                case 0x0B:          /* 5.0.0 - 5.1.0 */
                    firmware_version_boot0.major = 5;
                    break;
                case 0x0E:         /* 6.0.0 - 6.2.0 */
                    firmware_version_boot0.major = 6;
                    if (memcmp(pk1ldr.build_timestamp, "20181107", 8) == 0) {
                        firmware_version_boot0.minor = 2;
                        firmware_version_boot0.micro = 0;
                    }
                    break;      
                case 0x0F:          /* 7.0.0 - 7.0.1 */
                    firmware_version_boot0.major = 7;
                    firmware_version_boot0.minor = 0;
                    break;
                case 0x10: {        /* 8.0.0 - 9.0.0 */
                    if (memcmp(pk1ldr.build_timestamp, "20190314", 8) == 0) {
                        firmware_version_boot0.major = 8;
                        firmware_version_boot0.minor = 0;
                    } else if (memcmp(pk1ldr.build_timestamp, "20190531", 8) == 0) {
                        firmware_version_boot0.major = 8;
                        firmware_version_boot0.minor = 1;
                    } else if (memcmp(pk1ldr.build_timestamp, "20190809", 8) == 0) {
                        firmware_version_boot0.major = 9;
                    }
                    break;
                }
            }
            if(firmware_version_boot0.major > 0)
                firmware_version = firmware_version_boot0;
            dbg_printf("NxStorage::NxStorage() - firmware version = %s\n", getFirmwareVersion(&firmware_version_boot0).c_str());
        }
    }
    
    // Retrieve info for decrypted partitions
    if (not_in(type, { UNKNOWN, INVALID }))
        setStorageInfo();
    
    dbg_printf("NxStorage::NxStorage() size is %I64d (diskFreeBytes = %I64d). type is %s\n", m_size, m_freeSpace, getNxTypeAsStr());    
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
                            dbg_printf("Found NCA for fw %s\n", title.fw_version);
                            memcpy(fw_version, title.fw_version, strlen(title.fw_version));
                            setFirmwareVersion(&firmware_version, title.fw_version);
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
                        strcpy(fwv, haystack.substr(n + 10, 10).c_str());
                        char *buf;
                        if ((buf = strtok(fwv, "\xb0")) != nullptr) // 0xB0 terminated value (msgpack)
                        {
                            firmware_version_t fwv_tmp;
                            setFirmwareVersion(&fwv_tmp, buf);
                            //dbg_printf("Reading /save/80000000000000d1 - OsVersion %s\n", getFirmwareVersion(&fwv_tmp).c_str());

                            if (fwv_cmp(fwv_tmp, firmware_version) > 0)
                            {
                                dbg_printf("%s is greater than %s\n", getFirmwareVersion(&fwv_tmp).c_str(), getFirmwareVersion().c_str());
                                firmware_version = fwv_tmp;
                            }
                        }
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
                    
                    // Find needle (firmware version) in haystack
                    std::size_t n = haystack.find("os_version");
                    if (n != std::string::npos)
                    {
                        strcpy(fwv, haystack.substr(n + 11, 10).c_str());
                        char *buf;
                        if ((buf = strtok(fwv, "\xb1")) != nullptr) // 0xB1 terminated value (msgpack)
                        {
                            firmware_version_t fwv_tmp;
                            setFirmwareVersion(&fwv_tmp, buf);

                            if (fwv_cmp(fwv_tmp, firmware_version) > 0)
                            {
                                dbg_printf("%s is greater than %s\n", getFirmwareVersion(&fwv_tmp).c_str(), getFirmwareVersion().c_str());
                                firmware_version = fwv_tmp;
                            }
                        }
                    }
                    cur_off += bytesRead;
                }
            }

            // overwrite fw version if value found in journal/play report is greater than fw version in 
            // package1ldr (trick for downgraded NAND, only works for FULL NAND)
            if(firmware_version_boot0.major > 0 && firmware_version_boot0.major < firmware_version.major)
                firmware_version = firmware_version_boot0;
        }
    }
}

int NxStorage::dumpControl(params_t par)
{
    if (!isNxStorage())
        return ERR_INVALID_INPUT;

    if (par.partition != UNKNOWN && nullptr == getNxPartition(par.partition))
        return ERR_IN_PART_NOT_FOUND;

    for (part_params_t partPar : par.parts)
        if (nullptr == getNxPartition(partPar.nx_type))
            return ERR_IN_PART_NOT_FOUND;


    bool b_isEncrypted = false, b_badCrypto = false;
    NxPartition *in_part;
    if(isSinglePartType() || par.partition != UNKNOWN)
    {
        if (par.partition != UNKNOWN)
            in_part = getNxPartition(par.partition);
        else
            in_part = getNxPartition();

        b_isEncrypted = in_part->isEncryptedPartition();
        b_badCrypto = in_part->badCrypto();
    }
    else
    {
        b_isEncrypted = isEncrypted();
        b_badCrypto = badCrypto();
    }


    // Crypto check
    if (b_isEncrypted && (is_in(par.crypto_mode, {ENCRYPT, DECRYPT}) || par.passThroughZero))
    {
        if (!isCryptoSet())
            return ERR_CRYPTO_KEY_MISSING;

        if (b_badCrypto)
            return ERR_BAD_CRYPTO;
    }

    // Trying to encrypt already encrypted content
    if (par.crypto_mode == ENCRYPT && b_isEncrypted)
        return ERR_CRYPTO_ENCRYPTED_YET;
    // Trying
    if (par.crypto_mode == DECRYPT && !b_isEncrypted)
        return ERR_CRYPTO_DECRYPTED_YET;

    // USER resize controls
    if (par.user_new_size)
    {
        NxPartition *user = getNxPartition(USER);
        if (nullptr == user)
            return ERR_IN_PART_NOT_FOUND;

        if (user->isEncryptedPartition())
        {
            if (!isCryptoSet())
                return ERR_CRYPTO_KEY_MISSING;

            if (user->badCrypto())
                return ERR_BAD_CRYPTO;
        }
    }

    return SUCCESS;
}

int NxStorage::dump(NxHandle *outHandle, params_t par, void(*updateProgress)(ProgressInfo))
{
    // Do controls
    int rc = dumpControl(par);
    if (rc != SUCCESS)
        return rc;

    if (outHandle->exists)
        return ERR_FILE_ALREADY_EXISTS;

    // Single partition dump
    if(isSinglePartType() || par.partition != UNKNOWN)
    {
        NxPartition *in_part;
        if (par.partition != UNKNOWN)
            in_part = getNxPartition(par.partition);
        else
            in_part = getNxPartition();

        part_params_t *in_part_param = GetPartParam(&par, in_part->type());
        part_params_t params;
        if (nullptr != in_part_param)
            params = *in_part_param;
        else
        {
            params.crypto_mode = par.crypto_mode;
            params.passThroughZero = par.passThroughZero;
            params.zipOutput = par.zipOutput;
        }
        int rc = in_part->dump(outHandle, params, updateProgress);
        return rc;
    }

    // NAND dump
    ProgressInfo pi;
    DWORD bytesCount = 0, bytesWrite = 0;
    bool sendProgress = nullptr != updateProgress ? true : false;
    std::wstring fwpath = outHandle->getPath();

    // Init buffer and handle
    BYTE *buffer = new BYTE[DEFAULT_BUFF_SIZE];
    nxHandle->initHandle(par.crypto_mode);

    // Init progress info
    pi.mode = COPY;
    sprintf(pi.storage_name, getNxTypeAsStr());
    pi.begin_time = std::chrono::system_clock::now();
    pi.bytesTotal = size();
    if(par.isSubParam) pi.show = false;
    if (par.user_new_size)
    {
        u32 gptbck_lba = getNxPartition(USER)->lbaStart() + par.user_new_size + 32;
        pi.bytesTotal = (u64)(gptbck_lba + 1) * NX_BLOCKSIZE;
    }

    if (sendProgress && !par.isSubParam)
        updateProgress(pi);

    // Error lambda func
    auto error = [&] (int rc)
    {
        delete [] buffer;        
        if (isDrive())
            nxHandle->unlockVolume();
        return rc;
    };

    // Lock volume
    if (isDrive())
        nxHandle->lockVolume();

    // Create and lock input HASH
    if(par.crypto_mode == MD5_HASH)
        nxHandle->lockHash();

    // Dump BOOT partitions
    if(type == RAWMMC)
    {
        NxPartition *boot0 = getNxPartition(BOOT0);
        NxPartition *boot1 = getNxPartition(BOOT1);

        if(!par.rawnand_only)
        {
            part_params_t params;
            params.isSubParam = true;            
            int rc = boot0->dump(outHandle, params, updateProgress);
            if (rc != SUCCESS)
                return error(rc);

            pi.bytesCount += boot0->size();
            if (sendProgress) updateProgress(pi);

            rc = boot1->dump(outHandle, params, updateProgress);
            if (rc != SUCCESS)
                return error(rc);

            pi.bytesCount += boot1->size();
        }
        else pi.bytesCount += boot0->size() + boot1->size(); // Skip boot
        if (sendProgress) updateProgress(pi);
    }

    // UserDataRoot (GPT header)
    nxHandle->initHandle(par.crypto_mode);
    nxHandle->setPointer(pi.bytesCount);
    if(!nxHandle->read(buffer, &bytesCount, 0x4400))
        return error(ERR_WHILE_COPY);

    // NAND resize => Update GPT
    unsigned char gpt_header_backup[0x200];
    if (par.user_new_size)
    {
        // Cluster align new size (32 sectors per cluster)
        par.user_new_size = (par.user_new_size / 32) * 32;

        GptHeader *hdr = (GptHeader *)(buffer + 0x200);

        // Get entry for USER & resize partition in GPT header
        u32 table_off = 0x200 + (hdr->part_ent_lba - 1) * NX_BLOCKSIZE;
        GptEntry *user_ent = (GptEntry *)(buffer + table_off + (hdr->num_part_ents - 1) * hdr->part_ent_size);
        user_ent->lba_end = user_ent->lba_start + par.user_new_size - 1;

        // New CRC32 for partition table
        u32 table_size = hdr->num_part_ents * hdr->part_ent_size;
        unsigned char *table = new unsigned char[table_size];
        memcpy(&table[0], &buffer[table_off], table_size);
        hdr->part_ents_crc32 = crc32Hash(table, table_size);
        delete[] table;

        // New values for header
        hdr->last_use_lba = user_ent->lba_end;
        hdr->alt_lba = hdr->last_use_lba + 33;

        // New CRC32 for header
        unsigned char header[92];
        memcpy(&header[0], &hdr[0], 92);
        memset(&header[16], 0, 4);
        hdr->c_crc32 = crc32Hash(header, 92);

        // Save GPT header
        memcpy(gpt_header_backup, &hdr[0], 0x200);
    }


    // Write UserDataRoot
    if(!outHandle->write(buffer, &bytesCount, 0x4400))
        return error(ERR_WHILE_COPY);

    pi.bytesCount += 0x4400;
    if (sendProgress) updateProgress(pi);

    for (NxPartition *in_part : this->partitions)
    {
        // Skip boot partitions
        if (is_in(in_part->type(), {BOOT0, BOOT1}))
            continue;

        // Skip USER if resize
        if (par.user_new_size && in_part->type() == USER)
            break;

        // Set params for partition
        part_params_t *in_part_param = GetPartParam(&par, in_part->type());
        part_params_t params;
        if(nullptr != in_part_param)
            memcpy(&params, in_part_param, sizeof(part_params_t));
        else if (is_in(in_part->type(), { SYSTEM, USER }))
            params.passThroughZero = par.passThroughZero;

        params.isSubParam = true;
        int rc = in_part->dump(outHandle, params, updateProgress);
        if (rc != SUCCESS)
            return error(rc);

        pi.bytesCount += in_part->size();
        if (sendProgress) updateProgress(pi);
    }

    // USER resize (& format)
    if (par.user_new_size)
    {
        NxPartition *user = getNxPartition(USER);
        nxHandle->initHandle(user->isEncryptedPartition() ? DECRYPT : NO_CRYPTO, user);
        u32 fat_size = fat32::getFatSize(par.user_new_size);
        u32 fat_size_in_cluster = fat_size / 32;
        u32 user_size_in_cluster = par.user_new_size / 32;
        BYTE *s_buffer = new BYTE[CLUSTER_SIZE];
        u32 cur_cluster_num = 0;

        ProgressInfo spi;
        spi.mode = RESIZE;
        spi.isSubProgressInfo = true;
        spi.bytesTotal = (u64)user_size_in_cluster * CLUSTER_SIZE;
        sprintf(spi.storage_name, user->partitionName().c_str());
        if (sendProgress) updateProgress(spi);

        // Read reserved sectors
        if (!nxHandle->read(s_buffer, &bytesCount, CLUSTER_SIZE))
            return error(ERR_WHILE_COPY);

        // Overwrite FAT size & sectors count (in both boot sectors)
        fat32::boot_sector *bs = (fat32::boot_sector *)(s_buffer);
        bs->fat_size = fat_size;
        bs->sectors_count = par.user_new_size;
        bs = (fat32::boot_sector *)(s_buffer + bs->bs_first_copy_sector * NX_BLOCKSIZE);
        bs->fat_size = fat_size;
        bs->sectors_count = par.user_new_size;

        // Encrypt reserved sectors
        if (user->isEncryptedPartition())
            user->crypto()->encrypt(s_buffer, cur_cluster_num++);

        // Write reserved sectors
        if (!outHandle->write(s_buffer, &bytesWrite, CLUSTER_SIZE))
            return error(ERR_WHILE_COPY);

        spi.bytesCount += CLUSTER_SIZE;
        if (sendProgress) updateProgress(spi);

        // For each FAT
        for (int x(0); x < 2; x++)
        {
            // For each cluster in FAT
            for (u32 i(0); i < fat_size_in_cluster; i++)
            {
                memset(s_buffer, 0, CLUSTER_SIZE);
                // Write first 3 FAT entries (each entry is 4 bytes long)
                if (!i)
                {
                    u8 first_entries[12] = { 0xf8, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0x0f };
                    memcpy(s_buffer, first_entries, ARRAYSIZE(first_entries));
                }

                if (user->isEncryptedPartition())
                    user->crypto()->encrypt(s_buffer, cur_cluster_num++);

                if (!outHandle->write(s_buffer, &bytesWrite, CLUSTER_SIZE))
                    return error(ERR_WHILE_COPY);

                spi.bytesCount += bytesWrite;
                if (sendProgress) updateProgress(spi);
            }
        }

        // Encrypt & write empty root cluster
        memset(s_buffer, 0, CLUSTER_SIZE);
        if (user->isEncryptedPartition())
            user->crypto()->encrypt(s_buffer, cur_cluster_num++);

        if (!outHandle->write(s_buffer, &bytesWrite, CLUSTER_SIZE))
            return error(ERR_WHILE_COPY);

        spi.bytesCount += bytesWrite;
        if (sendProgress) updateProgress(spi);

        // Write empty data clusters (encryption is not needed)
        memset(s_buffer, 0, CLUSTER_SIZE);
        while (cur_cluster_num < user_size_in_cluster)
        {
            if (!outHandle->write(s_buffer, &bytesWrite, CLUSTER_SIZE))
                return error(ERR_WHILE_COPY);

            spi.bytesCount += bytesWrite;
            if (sendProgress) updateProgress(spi);

            cur_cluster_num++;
        }

        pi.bytesCount += spi.bytesTotal;
        if (sendProgress) updateProgress(pi);
    }

    // Last sectors
    nxHandle->initHandle(par.crypto_mode);
    nxHandle->setPointer((u64)((getNxPartition(USER)->lbaEnd() + 1) * NX_BLOCKSIZE));

    while(pi.bytesCount < pi.bytesTotal)
    {
        int buff_size = DEFAULT_BUFF_SIZE;
        if (pi.bytesCount + DEFAULT_BUFF_SIZE > pi.bytesTotal)
            buff_size = pi.bytesTotal - pi.bytesCount;

        if (!nxHandle->read(buffer, &bytesCount, buff_size))
            return error(ERR_WHILE_COPY);

        if (!outHandle->write(buffer, &bytesWrite, bytesCount))
            return error(ERR_WHILE_COPY);

        pi.bytesCount += bytesWrite;
        if (sendProgress) updateProgress(pi);
    }

    // Ovewrite backup GPT after resize
    if (par.user_new_size)
    {
         GptHeader *hdr = (GptHeader *)(gpt_header_backup);
         outHandle->clearHandle();
         if (outHandle->getChunkSize())
         {
             outHandle->setPath(outHandle->getFistPartPath());
             outHandle->createHandle();
             outHandle->detectSplittedStorage();
         }
         else outHandle->createHandle();

         outHandle->setPointer((u64)(hdr->alt_lba * NX_BLOCKSIZE));
         if(!outHandle->write(gpt_header_backup, &bytesWrite, NX_BLOCKSIZE))
            return error(ERR_WHILE_COPY);
    }

    if (isDrive())
        nxHandle->unlockVolume();

    // Check completeness
    if (pi.bytesCount != pi.bytesTotal)
        return error(ERR_WHILE_COPY);

    if(par.crypto_mode == MD5_HASH)
    {
        nxHandle->unlockHash();

        // Get checksum for input
        HCRYPTHASH in_hash = nxHandle->md5Hash();
        std::string in_sum = BuildChecksum(in_hash);

        // Recreate outHandle
        outHandle->clearHandle();
        if (outHandle->getChunkSize())
        {
            outHandle->setPath(outHandle->getFistPartPath());
            outHandle->createHandle();
            outHandle->detectSplittedStorage();
        }
        else outHandle->createHandle();

        // Init Progress Info
        pi.bytesCount = 0;
        if (sendProgress)
        {
            pi.mode = MD5_HASH;
            pi.begin_time = std::chrono::system_clock::now();
            pi.elapsed_seconds = 0;
            updateProgress(pi);
        }

        // Hash output file
        while (outHandle->hash(&pi.bytesCount))
        {
            if(stopWork)
                return error(userAbort());

            if (sendProgress)
                updateProgress(pi);
        }

        // Check completeness
        if (pi.bytesCount != pi.bytesTotal)
            return error(ERR_MD5_COMPARE);

        // Get checksum for output
        HCRYPTHASH out_hash = outHandle->md5Hash();
        std::string out_sum = BuildChecksum(out_hash);

        // Compare checksums
        if (in_sum.compare(out_sum))
            return error(ERR_MD5_COMPARE);

    }

    if (par.zipOutput)
    {
        outHandle->closeHandle();
        outHandle->setPath(fwpath);
        outHandle->createHandle();
        outHandle->detectSplittedStorage();
        outHandle->closeHandle();

        std::wstring zip_pathw;
        outHandle->getJoinFileName(zip_pathw, fwpath);
        std::string zip_path(zip_pathw.begin(), zip_pathw.end());
        zip_path.append(".zip");

        pi.mode = ZIP;
        pi.bytesCount = 0;
        sprintf(pi.storage_name, base_name(zip_path).c_str());

        if (sendProgress) updateProgress(pi);

        do
        {
            std::string cur_path(fwpath.begin(), fwpath.end());
            ZipFile::AddFile(zip_path, cur_path, DeflateMethod::Create(), updateProgress);

            ZipArchive::Ptr zipArchive = ZipFile::Open(zip_path);
            ZipArchiveEntry::Ptr zipEntry = zipArchive->GetEntry(base_name(cur_path));
            if (zipEntry == nullptr || zipEntry->GetSize() != sGetFileSize(cur_path))
                return error(ERR_CREATE_ZIP);

            remove(cur_path.c_str());

            pi.bytesCount += zipEntry->GetSize();
            if (sendProgress) updateProgress(pi);

            if(!outHandle->isSplitted() || !outHandle->getNextSplitFile(fwpath, fwpath))
                 break;
        } while(file_exists(fwpath.c_str()));
    }

    delete [] buffer;
    return SUCCESS;
}

int NxStorage::restore(NxStorage* input, params_t par, void(*updateProgress)(ProgressInfo))
{
    // Controls
    if (input->type == INVALID || input->type == UNKNOWN)
        return ERR_INVALID_INPUT;

    // Switch to single partition if output is NAND, input is single partition and partition not provided
    if (!isSinglePartType() && input->isSinglePartType() && par.partition == UNKNOWN)
        par.partition = input->getNxTypeAsInt();

    // Single partition restore
    if(isSinglePartType() || par.partition != UNKNOWN)
    {
        NxPartition *in_part = nullptr;
        if (isSinglePartType())
            in_part = getNxPartition();
        else
            in_part = getNxPartition(par.partition);

        if (nullptr == in_part)
            return ERR_IN_PART_NOT_FOUND;

        part_params_t *in_part_param = GetPartParam(&par, in_part->type());
        part_params_t params;
        if (nullptr != in_part_param) params.crypto_mode = in_part_param->crypto_mode;
        else params.crypto_mode = par.crypto_mode;

        int rc = in_part->restore(input, params, updateProgress);
        return rc;
    }

    // NAND restore
    if (input->type != this->type)
        return ERR_NX_TYPE_MISSMATCH;

    if (par.crypto_mode == DECRYPT || par.crypto_mode == ENCRYPT)
        return ERR_CRYPTO_RAW_COPY;

    if (input->size() != size()) // Alow restore overflow if freeSpace is available
        return ERR_IO_MISMATCH;

    if (input->isEncrypted() && !isEncrypted())
        return ERR_RESTORE_CRYPTO_MISSIN2;

    if (!input->isEncrypted() && isEncrypted())
        return ERR_RESTORE_CRYPTO_MISSING;

    ProgressInfo pi;
    DWORD bytesCount = 0, bytesWrite = 0;
    bool sendProgress = nullptr != updateProgress ? true : false;
    pi.bytesCount = 0;
    pi.bytesTotal = input->size();
    if (sendProgress)
    {
        pi.mode = RESTORE;
        sprintf(pi.storage_name, getNxTypeAsStr());
        pi.begin_time = std::chrono::system_clock::now();
        updateProgress(pi);
    }

    // Init buffer and handle
    BYTE *buffer = new BYTE[DEFAULT_BUFF_SIZE];
    nxHandle->initHandle(NO_CRYPTO);
    input->nxHandle->initHandle(NO_CRYPTO);

    // Lock output volume
    if (isDrive())
        nxHandle->lockVolume();

    // Lock input volume
    if (input->isDrive())
        input->nxHandle->lockVolume();

    // Error lambda func
    auto error = [&] (int rc)
    {
        delete [] buffer;
        if (isDrive())
            nxHandle->unlockVolume();

        if (input->isDrive())
            input->nxHandle->lockVolume();
        return rc;
    };

    // Restore BOOT partitions
    if(type == RAWMMC)
    {
        NxPartition *boot0 = getNxPartition(BOOT0);
        NxPartition *boot1 = getNxPartition(BOOT1);

        part_params_t params;
        params.isSubParam = true;
        int rc = boot0->restore(input, params, updateProgress);
        if (rc != SUCCESS)
            return error(rc);

        pi.bytesCount += boot0->size();
        if (sendProgress) updateProgress(pi);

        rc = boot1->restore(input, params, updateProgress);
        if (rc != SUCCESS)
            return error(rc);

        pi.bytesCount += boot1->size();

        if (sendProgress) updateProgress(pi);
    }

    // UserDataRoot (GPT header)
    input->nxHandle->initHandle(par.crypto_mode);
    input->nxHandle->setPointer(pi.bytesCount);
    if(!input->nxHandle->read(buffer, &bytesCount, 0x4400))
        return error(ERR_WHILE_COPY);

    // Write UserDataRoot
    this->nxHandle->initHandle(NO_CRYPTO);
    this->nxHandle->setPointer(pi.bytesCount);
    if(!nxHandle->write(buffer, &bytesCount, 0x4400))
        return error(ERR_WHILE_COPY);

    pi.bytesCount += 0x4400;
    if (sendProgress) updateProgress(pi);

    for (NxPartition *in_part : input->partitions)
    {
        // Skip boot partitions
        if (is_in(in_part->type(), {BOOT0, BOOT1}))
            continue;

        in_part->nxHandle->initHandle(NO_CRYPTO, in_part);
        ProgressInfo subPi;
        subPi.bytesCount = 0;
        subPi.bytesTotal = in_part->size();
        subPi.isSubProgressInfo = true;
        if (sendProgress)
        {
            subPi.mode = RESTORE;
            sprintf(subPi.storage_name, input->getNxTypeAsStr(in_part->type()));
            updateProgress(subPi);
        }

        while(in_part->nxHandle->read(buffer, &bytesCount, DEFAULT_BUFF_SIZE))
        {
            if(stopWork) return error(userAbort());

            if (!nxHandle->write(buffer, &bytesWrite, bytesCount))
                break;

            subPi.bytesCount += bytesWrite;
            if (sendProgress) updateProgress(subPi);
        }

        if(subPi.bytesCount != subPi.bytesTotal)
            return error(ERR_WHILE_COPY);

        pi.bytesCount += subPi.bytesCount;
        if (sendProgress) updateProgress(pi);

    }

    // Last sectors
    input->nxHandle->setPointer(pi.bytesCount);
    input->nxHandle->initHandle(par.crypto_mode);
    this->nxHandle->initHandle(NO_CRYPTO);
    this->nxHandle->setPointer(pi.bytesCount);
    while(pi.bytesCount < pi.bytesTotal)
    {
        if (!input->nxHandle->read(buffer, &bytesCount, DEFAULT_BUFF_SIZE))
            return error(ERR_WHILE_COPY);

        DWORD bytesWrite;
        if (!nxHandle->write(buffer, &bytesWrite, bytesCount))
            return error(ERR_WHILE_COPY);

        pi.bytesCount += bytesWrite;
        if (sendProgress) updateProgress(pi);
    }

    // Check completeness
    if (pi.bytesCount != pi.bytesTotal)
        return error(ERR_WHILE_COPY);

    delete [] buffer;
    if (isDrive())
        nxHandle->unlockVolume();

    if (input->isDrive())
        input->nxHandle->lockVolume();

    return SUCCESS;
}


int NxStorage::resizeUser(NxHandle *outHandle, u32 user_new_size, void(&updateProgress)(ProgressInfo*))
{
    // Controls
    if (not_in(type, { RAWNAND, RAWMMC }))
        return ERR_INVALID_INPUT;

    if (isEncrypted() && !m_keySet_set)
        return ERR_CRYPTO_KEY_MISSING;

    if (isEncrypted() && badCrypto())
        return ERROR_DECRYPT_FAILED;

    if (outHandle->exists)
        return ERR_FILE_ALREADY_EXISTS;

    NxPartition *user = getNxPartition(USER);

    if (!user->isEncryptedPartition())
        return ERR_INVALID_INPUT;

    // Useful vars
    DWORD bytesCount = 0;
    u32 gpt_lba_start = type == RAWMMC ? 0x4000 : 0;
    u32 user_new_fat_size = (user_new_size - 32) / ((256 * 32 + 2) / 2);
    u32 user_min_lba = (u32)((user->size() - user->freeSpace) / NX_BLOCKSIZE);
    bool format = user_new_size < user_min_lba ? true : false;
    unsigned char gpt_header_backup[0x200];

    // Init buffer and handle
    BYTE *buffer = new BYTE[DEFAULT_BUFF_SIZE];
    nxHandle->initHandle(NO_CRYPTO);

    // Init progress info
    ProgressInfo pi;
    pi.mode = RESIZE;
    sprintf(pi.storage_name, getNxTypeAsStr());
    pi.begin_time = std::chrono::system_clock::now();
    pi.bytesCount = 0;
    pi.bytesTotal = size() - user->size() + (u64)(user_new_size * NX_BLOCKSIZE);
    updateProgress(&pi);

    // Error lambda func
    auto error = [&] (int rc)
    {
        delete [] buffer;
        if (isDrive())
            nxHandle->unlockVolume();
        return rc;
    };

    // Lock volume
    if (isDrive())
        nxHandle->lockVolume();

    // Write BOOT partitions
    if(type == RAWMMC)
    {
        // One iteration per partition (DEFAULT_BUFF_SIZE = BOOT size)
        for(int i(0); i < 2; i++)
        {
            if (!nxHandle->read(buffer, &bytesCount, DEFAULT_BUFF_SIZE)
             || !outHandle->write(buffer, &bytesCount, DEFAULT_BUFF_SIZE))
                return error(ERR_WHILE_COPY);

            pi.bytesCount += DEFAULT_BUFF_SIZE;
            updateProgress(&pi);
        }
    }

    // UserDataRoot (GPT header)
    if(!nxHandle->read(buffer, &bytesCount, 0x4400))
        return error(ERR_WHILE_COPY);

    GptHeader *hdr = (GptHeader *)(buffer + 0x200);

    // Get entry for USER & resize partition in GPT header
    u32 table_off = 0x200 + (hdr->part_ent_lba - 1) * NX_BLOCKSIZE;
    GptEntry *user_ent = (GptEntry *)(buffer + table_off + (hdr->num_part_ents - 1) * hdr->part_ent_size);
    user_ent->lba_end = user_ent->lba_start + user_new_size - 1;

    // New CRC32 for partition table
    u32 table_size = hdr->num_part_ents * hdr->part_ent_size;
    unsigned char *table = new unsigned char[table_size];
    memcpy(&table[0], &m_buffer[table_off], table_size);
    hdr->part_ents_crc32 = crc32Hash(table, table_size);
    delete[] table;

    // New values for header
    hdr->last_use_lba = user_ent->lba_end;
    hdr->alt_lba = hdr->last_use_lba + 33;

    // New CRC32 for header
    unsigned char header[92];
    memcpy(&header[0], &hdr[0], 92);
    memset(&header[16], 0, 4);
    hdr->c_crc32 = crc32Hash(header, 92);

    // Save GPT header
    memcpy(gpt_header_backup, &hdr[0], 0x200);

    // Write UserDataRoot
    if(!outHandle->write(buffer, &bytesCount, 0x4400))
        return error(ERR_WHILE_COPY);

    pi.bytesCount += 0x4400;
    updateProgress(&pi);

    // Write NAND until USER partition starts
    u64 user_off = user->lbaStart() * NX_BLOCKSIZE;
    while(pi.bytesCount < user_off)
    {
        u32 buff_size = pi.bytesCount + DEFAULT_BUFF_SIZE > user_off ? user_off - pi.bytesCount : DEFAULT_BUFF_SIZE;

        if (!nxHandle->read(buffer, &bytesCount, buff_size)
         || !outHandle->write(buffer, &bytesCount, buff_size))
            return error(ERR_WHILE_COPY);

        pi.bytesCount += buff_size;
        updateProgress(&pi);
    }

    // Copy & resize USER FAT32
    delete [] buffer;
    buffer = new BYTE[CLUSTER_SIZE];
    nxHandle->initHandle(DECRYPT, user);
    u32 cpy_cl_count_out = 0;

    // Read first cluster
    if (!nxHandle->read(buffer, &bytesCount, CLUSTER_SIZE))
        return error(ERR_WHILE_COPY);

    // TO DO Continue

    delete [] buffer;
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
        if (isDrive() && !nxHandle->lockVolume())
            dbg_printf("failed to lock volume\n");

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
            if (isDrive() && !nxHandle->unlockVolume())
                dbg_printf("failed to unlock volume\n");
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
        hdr->c_crc32 = crc32Hash(header, 92);

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
            p_ofstream->close();
            delete[] m_buffer;
            delete p_ofstream;
            if (isDrive() && !nxHandle->unlockVolume())
                dbg_printf("failed to unlock volume\n");
            return ERR_WHILE_COPY;
        }
        *bytesCount += CLUSTER_SIZE;

        // Get FAT size from boot sector
        u32 fat_size;
        u8 num_fats;
        u32 sectors_count;
        memcpy(&fat_size, &m_buffer[0x24], 4);
        memcpy(&num_fats, &m_buffer[0x10], 1);
        u32 cluster_num = fat_size * NX_BLOCKSIZE / CLUSTER_SIZE;

        // New FAT size
        u32 new_fat_size = m_user_new_size / 0x1000; // each entry in cluster map is 4 bytes long
        u32 new_cluster_num = new_fat_size * NX_BLOCKSIZE / CLUSTER_SIZE;
        memcpy(&m_buffer[0x24], &new_fat_size, 4);
        // New FAT total cluster count
        memcpy(&m_buffer[0x20], &m_user_total_size, 4);


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
                u64 size = cur_off + CLUSTER_SIZE > bck_gpt_off ? bck_gpt_off - cur_off : CLUSTER_SIZE;
                p_ofstream->write((char *)&m_buffer[0], size);
                *bytesCount += size;

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
                if (isDrive() && !nxHandle->unlockVolume())
                    dbg_printf("failed to unlock volume\n");

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
            if (isDrive() && !nxHandle->unlockVolume())
                dbg_printf("failed to unlock volume\n");

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

const char* NxStorage::getNxTypeAsStr(int a_type)
{
    int cur_type = a_type ? a_type : type;
    for (NxStorageType t : NxTypesArr)
    {
        if (cur_type == t.type)
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

        if (isDrive() && !nxHandle->lockVolume())
            dbg_printf("failed to lock volume\n");

        if (nxHandle->write((u64)0x200, buff, &bytesRead, 0x200))
        {
            autoRcm = enable;
            if (isDrive() && !nxHandle->unlockVolume())
                dbg_printf("failed to unlock volume\n");
            return true;
        }
        if (isDrive() && !nxHandle->unlockVolume())
            dbg_printf("failed to unlock volume\n");
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

    if (isDrive() && !nxHandle->lockVolume())
        dbg_printf("failed to lock volume\n");
    
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
            if (isDrive() && !nxHandle->unlockVolume())
                dbg_printf("failed to unlock volume\n");
            return ERR_INPUT_HANDLE;
        }
    }

    setStorageInfo(PRODINFO);
    delete[] buffer;
    if (isDrive() && !nxHandle->unlockVolume())
        dbg_printf("failed to unlock volume\n");
    return SUCCESS;
}

int NxStorage::createMmcEmuNand(const char* mmc_path, void(*updateProgress)(ProgressInfo))
{

    if (this->type != RAWMMC)
        return -1;

    NxStorage mmc(mmc_path);

    if (!mmc.isDrive())
        return ERR_OUTPUT_NOT_MMC;

    // Recreate handle for mmc (because mmc can already 0b0e a0000000000000000000000 valid NxStorage)
    mbstowcs(mmc.m_path, mmc_path, MAX_PATH);
    mmc.m_size = 0;
    mmc.mmc_b0_lba_start = 0;
    delete mmc.nxHandle;
    mmc.nxHandle = new NxHandle(&mmc);
   
    // Read MMC boot sector
    DWORD bytesRead;
    mbr_t mbr, mbr_tmp;
    if (!mmc.nxHandle->read(&mbr, &bytesRead, NX_BLOCKSIZE))
        return ERR_OUTPUT_HANDLE;
        
    if (hexStr(mbr.signature, 2) != "55AA")
        return ERR_OUTPUT_NOT_MMC;

    // Copy boot sector
    memcpy(&mbr_tmp, &mbr, sizeof(mbr_t));

    // Lock volume
    mmc.nxHandle->lockVolume();

    // Calculate new values for MBR
    u32 nand_sector_count = (u32)(this->m_size / NX_BLOCKSIZE);
    u32 mmc_sector_count = (u32)(mmc.nxHandle->size() / NX_BLOCKSIZE);
    u32 first_part_lba_start = u32((nand_sector_count + 3) / 32 + 1) * 32; //cluster align
    u32 first_part_lba_count = mmc_sector_count - first_part_lba_start;
    chs_t first_part_chs_start;
    LBAtoCHS(mmc.nxHandle->pdg, first_part_lba_start, first_part_chs_start);
 
    // MMC not large enough
    if (nand_sector_count + 0x200 > mmc_sector_count)
        return ERR_NO_SPACE_LEFT; 

    // Set new values for MBR first partition
    memcpy(&mbr.parts[0].status, "\x00", 1);
    memcpy(&mbr.parts[0].type, "\x0B", 1); // FAT32 with CHS
    memcpy(mbr.parts[0].lba_start, &first_part_lba_start, 4);
    memcpy(mbr.parts[0].lba_count, &first_part_lba_count, 4);
    memcpy(&mbr.parts[0].first_sector, &first_part_chs_start, sizeof(chs_t));
    memcpy(&mbr.parts[0].last_sector, "\xfe\xff\xff", sizeof(chs_t));

    // Memset other partitions
    for (int i(1); i < 4; i++)
        memset(&mbr.parts[i], 0, sizeof(mbr_part_t));

    // Dismount all volumes
    if (!mmc.nxHandle->dismountAllVolumes())
        return ERR_OUT_DISMOUNT_VOL;

    // Clean partitions
    for (int i(0); i < 4; i++)
        memset(&mbr_tmp.parts[i], 0, sizeof(mbr_part_t));

    if (!mmc.nxHandle->write((u32)0, &mbr_tmp, &bytesRead, NX_BLOCKSIZE))
        return ERR_WHILE_WRITE;

    // Write "TXNAND" sector (mandatory to boot emuNAND via SX OS)
    u8 buffer[NX_BLOCKSIZE];
    memset(buffer, 0, NX_BLOCKSIZE);
    memcpy(buffer, tx_sector, ARRAYSIZE(tx_sector));
    if (!mmc.nxHandle->write(buffer, &bytesRead, NX_BLOCKSIZE))
        return ERR_WHILE_WRITE;    


    // Set new boot sector for user partition
    u8 bts[NX_BLOCKSIZE];
    memset(bts, 0, NX_BLOCKSIZE);
    memcpy(bts, fat32::fat32_default_boot_sector, ARRAYSIZE(fat32::fat32_default_boot_sector));
    u8 bs_sign[2] = { 0x55, 0xAA };
    memcpy(bts + NX_BLOCKSIZE - 2, bs_sign, 2);
    fat32::boot_sector *bs = (fat32::boot_sector*)(bts);
    bs->sectors_count = first_part_lba_count;
    u32 data_sectors_count = bs->sectors_count - bs->reserved_sector_count;
    bs->fat_size = data_sectors_count / ((256 * bs->sectors_per_cluster + 2) / 2);


    ProgressInfo pi, spi;
    pi.mode = CREATE;
    sprintf(pi.storage_name, "emuNAND");
    pi.begin_time = std::chrono::system_clock::now();
    pi.bytesCount = 0;
    pi.bytesTotal = size() + (u64((bs->reserved_sector_count + bs->fat_size * bs->num_fats) * NX_BLOCKSIZE + CLUSTER_SIZE));
    updateProgress(pi);
    spi.isSubProgressInfo = true;

    //
    // Copy NAND
    //

    // Init and lock volume
    this->nxHandle->initHandle(NO_CRYPTO);
    if (isDrive())
        nxHandle->lockVolume();
    // Set new buffer
    int buff_size = nxHandle->getDefaultBuffSize();
    BYTE* cpy_buffer = new BYTE[buff_size];
    memset(cpy_buffer, 0, buff_size);
    bytesRead = 0;
    DWORD bytesWrite = 0;

    // Sub Progress
    spi.mode = COPY;
    sprintf(spi.storage_name, getNxTypeAsStr());
    spi.bytesCount = 0;
    spi.bytesTotal = size();
    updateProgress(spi);

    // Copy
    while(this->nxHandle->read(cpy_buffer, &bytesRead, buff_size))
    {
        if(stopWork) return userAbort();

        if (!mmc.nxHandle->write(cpy_buffer, &bytesWrite, bytesRead))
            break;

        spi.bytesCount += bytesWrite;
        updateProgress(spi);
    }

    delete[] cpy_buffer;
    if (isDrive())
        nxHandle->unlockVolume();

    // Check completeness
    if (spi.bytesCount != spi.bytesTotal)
        return ERR_WHILE_COPY;

    pi.bytesCount += spi.bytesTotal;
    updateProgress(pi);

    // Set pointer to user partition in mmc output
    if (!mmc.nxHandle->setPointer((u64)first_part_lba_start * NX_BLOCKSIZE))
        return ERR_WHILE_WRITE;

    // Sub Progress
    spi.mode = CREATE;
    sprintf(spi.storage_name, "FAT32 partition");
    spi.bytesCount = 0;
    spi.bytesTotal = (bs->reserved_sector_count + bs->fat_size * bs->num_fats) * NX_BLOCKSIZE + CLUSTER_SIZE;
    updateProgress(spi);

    // Write boot & info sectors
    for (int j(0); j < 2; j++)
    {
        // Write bs
        if (!mmc.nxHandle->write(bts, &bytesRead, NX_BLOCKSIZE))
            return ERR_WHILE_WRITE;

        spi.bytesCount += NX_BLOCKSIZE;
        updateProgress(spi);

        // Write info sector
        if (!mmc.nxHandle->write(&fat32::fat32_default_info_sector, &bytesRead, NX_BLOCKSIZE))
            return ERR_WHILE_WRITE;

        spi.bytesCount += NX_BLOCKSIZE;
        updateProgress(spi);

        // Write 4 sectors
        for (int i(0); i < 4; i++)
        {
            memset(buffer, 0, NX_BLOCKSIZE);
            if (!i) memcpy(buffer + NX_BLOCKSIZE - 2, bs_sign, 2);
            if (!mmc.nxHandle->write(&fat32::fat32_default_info_sector, &bytesRead, NX_BLOCKSIZE))
                return ERR_WHILE_WRITE;

            spi.bytesCount += NX_BLOCKSIZE;
            updateProgress(spi);
        }
    }
    u32 cur_sector = 12;

    // Write reserved sectors
    memset(buffer, 0, NX_BLOCKSIZE);
    int res = bs->reserved_sector_count - cur_sector;
    for (int i(0); i < res; i++)
    {
        if (!mmc.nxHandle->write(buffer, &bytesRead, NX_BLOCKSIZE))
            return ERR_WHILE_WRITE;

        spi.bytesCount += NX_BLOCKSIZE;
        updateProgress(spi);
    }
    
    // Write FAT
    u64 fat_size = (u64)(bs->fat_size * NX_BLOCKSIZE);
    u8 *buff = (u8*)malloc(CLUSTER_SIZE);
    memset(buff, 0, CLUSTER_SIZE);
    // For each FAT
    for (int j(0); j < (unsigned int)bs->num_fats; j++)
    {
        u64 cur_off = 0;        
        // Fill cluster map
        while (cur_off < fat_size)
        {
            if(stopWork) return userAbort();

            if(!cur_off)
            {
                u8 first_nybbles[12] = { 0xf8, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0x0f, 0xf8, 0xff, 0xff, 0x0f };
                memcpy(buff, first_nybbles, ARRAYSIZE(first_nybbles));
            }

            u32 buff_size = CLUSTER_SIZE;
            if (cur_off + buff_size > fat_size) buff_size = fat_size - cur_off;

            if (!mmc.nxHandle->write(buff, &bytesRead, buff_size))
                return -12;

            if (!cur_off) memset(buff, 0, CLUSTER_SIZE);

            cur_off += buff_size;
            spi.bytesCount += buff_size;
            updateProgress(spi);

            dbg_printf("Writing %I64d bytes of FAT %d (%I64d)\r", cur_off, j, fat_size);
        }
        dbg_printf("\n");
    }
    // Write empty cluster for root dir
    if (!mmc.nxHandle->write(buff, &bytesRead, CLUSTER_SIZE))
        return -12;

    spi.bytesCount += CLUSTER_SIZE;
    updateProgress(spi);

    free(buff);

    // Write MBR
    if (!mmc.nxHandle->write((u32)0, &mbr, &bytesRead, NX_BLOCKSIZE))
        return ERR_WHILE_WRITE;

    // Unlock volume
    mmc.nxHandle->unlockVolume();

    pi.bytesCount += spi.bytesTotal;
    updateProgress(pi);

    // Get volume name for user partition
    WCHAR  volumeName[MAX_PATH] = L"";
    if (!mmc.nxHandle->getVolumeName(volumeName, first_part_lba_start))
        return ERR_PART_CREATE_FAILED;
    //dbg_wprintf(L"Volume name: %s\n", volumeName);
    

    TCHAR Buf[MAX_PATH];    
    TCHAR Volume[] = TEXT("");
    TCHAR AvailableDrive[] = L"";
    bool already_mounted = false;
    wchar_t I;
    wcscat(Volume, volumeName);
    wcscat(Volume, L"\\\0");
    wchar_t Drive[4] = L"d:\\";
    dbg_wprintf(L"Volume name: %s\n", Volume);
   

    // Look for existing or available mounting point
    for (I = L'd'; I < L'z'; I++)
    {
        // Stamp the drive for the appropriate letter.
        Drive[0] = I;

        bool bFlag = GetVolumeNameForVolumeMountPoint(
            Drive,     // input volume mount point or directory
            Buf,       // output volume name buffer
            MAX_PATH); // size of volume name buffer


        if (bFlag)
        {
            dbg_wprintf(L" - comparing %s\n", Buf);
            if (!lstrcmp(Buf, Volume))
            {
                already_mounted = true;
                AvailableDrive[0] = I;
                break;
            }            
        }
        else if (!lstrlen(AvailableDrive)) AvailableDrive[0] = I;
    }

    if (!lstrlen(AvailableDrive))
        return ERR_VOL_MOUNT_FAILED;
    
    // Set mount point for user partition
    if (!already_mounted)
    {
        BOOL  fResult;
        TCHAR szDriveLetter[3];
        std::vector<diskDescriptor> disks;
        GetDisks(&disks);
        for(diskDescriptor disk : disks)
            for(volumeDescriptor vol : disk.volumes)
                if(!vol.volumeName.compare(volumeName) && vol.mountPt.length())
                {
                    dbg_wprintf(L"%s found! %s (%d)\n", vol.volumeName.c_str(), vol.mountPt.c_str(), vol.mountPt.length());
                    std::wstring Drive(vol.mountPt);
                    Drive.append(L":\\");
                    dbg_wprintf(L"Drive = %s\n", Drive.c_str());
                    fResult = DeleteVolumeMountPoint(Drive.c_str());
                }

        szDriveLetter[0] = AvailableDrive[0];
        szDriveLetter[1] = TEXT(':');
        szDriveLetter[2] = TEXT('\0');
        TCHAR szDriveLetterAndSlash[4];
        szDriveLetterAndSlash[0] = AvailableDrive[0];
        szDriveLetterAndSlash[1] = TEXT(':');
        szDriveLetterAndSlash[2] = TEXT('\\');
        szDriveLetterAndSlash[3] = TEXT('\0');

        fResult = DefineDosDevice(DDD_RAW_TARGET_PATH, szDriveLetter, volumeName);
        if (!fResult)
            dbg_wprintf(TEXT("DefineDosDevice failed : %s\n"), GetLastErrorAsString().c_str());


        fResult = DefineDosDevice(DDD_RAW_TARGET_PATH | DDD_REMOVE_DEFINITION | DDD_EXACT_MATCH_ON_REMOVE, szDriveLetter, volumeName);

        if (!fResult)
            dbg_wprintf(TEXT("DefineDosDevice failed\n"), GetLastError());

        std::wstring volAndSlash(volumeName);
        volAndSlash.append(L"\\");
        //dbg_wprintf(L"SetVolumeMountPoint(%s, %s)\n", szDriveLetterAndSlash, volAndSlash.c_str());
        fResult = SetVolumeMountPoint(szDriveLetterAndSlash, volAndSlash.c_str());

        if (!fResult)
        {
            dbg_printf("SetVolumeMountPoint failed %s (%d)\n", GetLastErrorAsString().c_str(), GetLastError());
            return ERR_VOL_MOUNT_FAILED;
        }
    }

    AvailableDrive[1] = TEXT('\0');
    std::wstring drive(AvailableDrive);
    std::wstring path(drive + L":\\emuMMC");
    if(!CreateDirectoryW(path.c_str(), nullptr))
        dbg_wprintf(L"Failed to mkdir %s (%s)\n", path.c_str(), GetLastErrorAsString().c_str());

    std::string filepath (path.begin(), path.end());
    filepath.append("\\emummc.ini");
    std::ofstream emummcIni (filepath);
    if (emummcIni.is_open())
    {
        emummcIni << "[emummc]\n";
        emummcIni << "enabled=1\n";
        emummcIni << "sector=0x2\n";
        emummcIni << "path=emuMMC/ER00\n";
        emummcIni << "id=0x0000\n";
        emummcIni << "nintendo_path=Emutendo\n";
        emummcIni.close();
    }
    else dbg_printf("Failed to create %s\n", filepath.c_str());

    path.append(L"\\ER00");
    if(!CreateDirectoryW(path.c_str(), nullptr))
        dbg_wprintf(L"Failed to mkdir %s (%s)\n", path.c_str(), GetLastErrorAsString().c_str());

    filepath.clear();
    filepath.append(path.begin(), path.end());
    filepath.append("\\raw_based");
    std::ofstream raw_based (filepath, std::ofstream::binary);
    u8 content[4] = { 0x02, 0x00, 0x00, 0x00 };
    if (!raw_based.write((char *)&content[0], 4))
        dbg_printf("Failed to write %s\n", filepath.c_str());
    raw_based.close();

    path.clear();
    path.append(drive + L":\\Emutendo");
    if(!CreateDirectoryW(path.c_str(), nullptr))
        dbg_wprintf(L"Failed to mkdir %s (%s)\n", path.c_str(), GetLastErrorAsString().c_str());


    return SUCCESS;
}

int NxStorage::createFileBasedEmuNand(EmunandType emu_type, const char* volume_path, void(*updateProgress)(ProgressInfo), const char* boot0_path, const char* boot1_path)
{
    if (not_in(type, {RAWMMC, RAWNAND}))
        return ERR_INVALID_NAND;

    if (not_in(emu_type, {fileBasedAMS, fileBasedSXOS}) || nullptr == volume_path)
        return -1;

    if (type == RAWNAND) {
        if (nullptr == boot0_path)
            return ERR_INVALID_BOOT0;
        if (nullptr == boot1_path)
            return ERR_INVALID_BOOT1;
    }

    NxPartition *boot0, *boot1;
    NxHandle *curNxHandle = nullptr;
    NxStorage *nx1 = nullptr, *nx2 = nullptr;
    u64 nand_size = 0;

    // return lambda func
    auto end = [&] (int rc)
    {
        if (nullptr != nx1) delete nx1;
        if (nullptr != nx2) delete nx2;
        if (nullptr != curNxHandle) delete curNxHandle;
        if (isDrive()) nxHandle->unlockVolume();
        return rc;
    };

    if (type == RAWMMC)
    {
        boot0 = getNxPartition(BOOT0);
        if (nullptr == boot0) return end(ERR_INVALID_BOOT0);

        boot1 = getNxPartition(BOOT1);
        if (nullptr == boot1) return end(ERR_INVALID_BOOT1);

        nand_size = size();
    }
    else
    {
        nx1 = new NxStorage(boot0_path);
        if (nx1->type != BOOT0) return end(ERR_INVALID_BOOT0);
        boot0 = nx1->getNxPartition(BOOT0);

        nx2 = new NxStorage(boot1_path);
        if (nx2->type != BOOT1) return end(ERR_INVALID_BOOT1);
        boot1 = nx2->getNxPartition(BOOT1);

        nand_size = size() + boot0->size() + boot1->size();
    }

    LPWSTR wpath = convertCharArrayToLPWSTR(volume_path);
    volumeDescriptor vol;
    if (!GetVolumeDescriptor(&vol, wpath))
        return end(ERR_OUTPUT_NOT_DRIVE);

    if (vol.volumeFreeBytes < nand_size)
        return end(ERR_NO_SPACE_LEFT);

    std::string volume(volume_path), cur_dir, emu_dir;
    auto getDir = [&] (const char *path) { return std::string(volume + path); };
    auto n22dstr = [&] (int n) { char ns[4]; sprintf_s(ns, 4, "%02d", n); return std::string(ns); };
    switch (emu_type) {
    case fileBasedAMS : {

        // Get emuNAND availbale number
        int emu_count(0);
        for (int i(0); i <= 99; i++)
        {
            std::string path("\\emuMMC\\SD" + std::string(n22dstr(i)));
            cur_dir = getDir(path.c_str());
            if (is_dir(cur_dir.c_str())) emu_count = i + 1;
            else break;
        }

        cur_dir = getDir("\\emuMMC");
        if (!is_dir(cur_dir.c_str()) && !CreateDirectoryA(cur_dir.c_str(), nullptr))
            return end(ERR_CREATE_DIR_FAILED);

        std::string sd_emu_dir("\\emuMMC\\SD" + std::string(n22dstr(emu_count)));
        cur_dir = getDir(sd_emu_dir.c_str());
        if (!CreateDirectoryA(cur_dir.c_str(), nullptr))
            return end(ERR_CREATE_DIR_FAILED);

        cur_dir = getDir(std::string(sd_emu_dir + "\\eMMC").c_str());
        if (!CreateDirectoryA(cur_dir.c_str(), nullptr))
            return end(ERR_CREATE_DIR_FAILED);

        emu_dir = cur_dir;
        break;
    }
    case fileBasedSXOS : {

        cur_dir = getDir("\\sxos");
        if (!is_dir(cur_dir.c_str()) && !CreateDirectoryA(cur_dir.c_str(), nullptr))
            return end(ERR_CREATE_DIR_FAILED);

        cur_dir = getDir("\\sxos\\emunand");
        if (is_dir(cur_dir.c_str()))
            return end(ERR_FILE_ALREADY_EXISTS);

        if (!CreateDirectoryA(cur_dir.c_str(), nullptr))
            return end(ERR_CREATE_DIR_FAILED);

        emu_dir = cur_dir;
        break;
    }}

    ProgressInfo pi;
    pi.mode = CREATE;
    sprintf(pi.storage_name, "file based emuNAND");
    pi.begin_time = std::chrono::system_clock::now();
    pi.bytesTotal = type == RAWMMC ? size() : boot0->size() + boot1->size() + size();

    updateProgress(pi);

    // Copy boot partitions
    for (int i(0); i < 2; i++)
    {
        if (emu_type == fileBasedAMS)
            cur_dir = emu_dir + "\\BOOT" + std::to_string(i);
        else
            cur_dir = emu_dir + "\\boot" + std::to_string(i) + ".bin";
        curNxHandle= new NxHandle(cur_dir.c_str());
        part_params_t par;
        par.isSubParam = true;
        NxPartition *part = i ? boot1 : boot0;
        if (int rc = part->dump(curNxHandle, par, updateProgress))
            return end(rc);

        delete curNxHandle;
        pi.bytesCount += part->size();
    }

    // Copy RAWNAND
    params_t par;
    par.isSubParam = true;
    if (type == RAWMMC) par.rawnand_only = true;
    if (emu_type == fileBasedAMS)
    {
        cur_dir = emu_dir + "\\00";
        par.chunksize = 0xFE000000;
    }
    else
    {
        par.chunksize = 0xFFFE0000;
        cur_dir = emu_dir + "\\full.00.bin";
    }
    curNxHandle= new NxHandle(cur_dir.c_str(), par.chunksize);
    if (int rc = dump(curNxHandle, par, updateProgress))
        return end(rc);

    pi.bytesCount = pi.bytesTotal;
    updateProgress(pi);
    return end(SUCCESS);
}

void NxStorage::clearHandles()
{
    p_ofstream->close();
}

std::string NxStorage::getFirmwareVersion(firmware_version_t* fmv)
{
    if(nullptr == fmv)
        fmv = &firmware_version;

    if(fmv->major <= 0)
        return "unknown";

    std::string s;

    char buff[100];
    snprintf(buff, sizeof(buff), "%d.", fmv->major);
    s.append(buff);

    if(fmv->minor > -1)
    {
        snprintf(buff, sizeof(buff), "%d", fmv->minor);
        s.append(buff);
        if(fmv->micro > -1)
        {
            s.append(".");
            snprintf(buff, sizeof(buff), "%d", fmv->micro);
            s.append(buff);
        }
    }
    else s.append("x");
    
    return s;
}

void NxStorage::setFirmwareVersion(firmware_version_t *fwv, const char* fwv_string)
{
    int i(0);
    char *buf2, *buf = strdup(fwv_string);
    while((buf2 = strtok(buf, ".")) != nullptr)
    {
        buf = nullptr;
        try {
            int number = std::stoi(std::string(buf2));
            switch(i) {
                case 0:
                    fwv->major = number;
                    break;
                case 1:
                    fwv->minor = number;
                    break;
                case 2:
                    fwv->micro = number;
                    break;
            }
        } catch (std::exception const &e) {
            break;
        }
        i++;
    }
}

int NxStorage::fwv_cmp(firmware_version_t fwv1, firmware_version_t fwv2)
{
    if(fwv1.major > fwv2.major)
        return 1;
    if(fwv1.major < fwv2.major)
        return -1;
    if(fwv1.minor > fwv2.minor)
        return 1;
    if(fwv1.minor < fwv2.minor)
        return -1;
    if(fwv1.micro > fwv2.micro)
        return 1;
    if(fwv1.micro < fwv2.micro)
        return -1;
    
    return 0;
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
