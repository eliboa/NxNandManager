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

#ifndef __NxStorage_h__
#define __NxStorage_h__

extern bool isdebug;

#include <openssl/sha.h>
#include "res/utils.h"
#include "res/types.h"
#include "res/fat32.h"
#include "res/mbr.h"
#include "NxHandle.h"
#include "NxPartition.h"
#include "NxCrypto.h"

typedef struct MagicOffsets MagicOffsets;
struct MagicOffsets {
    u64 offset;
    const char* magic;
    u64 size;
    int type;
    float fw;
};

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

// GUID Partition Table structures
typedef struct _GptHeader
{
    u64 signature;
    u32 revision;
    u32 size;
    u32 crc32;
    u32 res1;
    u64 my_lba;
    u64 alt_lba;
    u64 first_use_lba;
    u64 last_use_lba;
    u8 disk_guid[0x10];
    u64 part_ent_lba;
    u32 num_part_ents;
    u32 part_ent_size;
    u32 part_ents_crc32;
    u8 res2[420];
} GptHeader;

typedef struct _GptEntry
{
    u8 type_guid[0x10];
    u8 part_guid[0x10];
    u64 lba_start;
    u64 lba_end;
    u64 attrs;
    u16 name[36];
} GptEntry;

struct NxStorageType
{
    int type;
    const char* name;
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

typedef struct NxSystemTitles NxSystemTitles;
struct NxSystemTitles {
    const char fw_version[48];
    const char nca_filename[40];
};



static NxSystemTitles systemTitlesArr[] = {
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

static u8 tx_sector[85] = {
    0x54, 0x58, 0x4E, 0x41, 0x4E, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x41, 0x74, 0x6D, 0x6F, 0x73, 0x70, 0x68, 0x65,
    0x72, 0x65, 0x2D, 0x4E, 0x58, 0x20, 0x20, 0x52, 0x6F, 0x63, 0x6B, 0x69,
    0x6E, 0x67, 0x20, 0x74, 0x68, 0x65, 0x20, 0x53, 0x77, 0x69, 0x74, 0x63,
    0x68, 0x20, 0x66, 0x6F, 0x72, 0x65, 0x76, 0x65, 0x72, 0x20, 0x61, 0x6E,
    0x64, 0x20, 0x62, 0x65, 0x79, 0x6F, 0x6E, 0x64, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xA4, 0x03,
    0x02
};



typedef struct NxKeys NxKeys;
struct NxKeys {
    bool set = false;
    char crypt0[33];
    char tweak0[33];
    char crypt1[33];
    char tweak1[33];
    char crypt2[33];
    char tweak2[33];
    char crypt3[33];
    char tweak3[33];
};

typedef struct {
    uint32_t package1loader_hash;
    uint32_t secmon_hash;
    uint32_t nx_bootloader_hash;
    uint32_t _0xC;
    char build_timestamp[0x0E];
    uint8_t _0x1E;
    uint8_t version;
} package1ldr_header_t;

typedef struct {
    int major = -1;
    int minor = -1;
    int micro = -1;
} firmware_version_t;

class NxHandle;
class NxCrypto;
class NxPartition;

class NxStorage 
{
    public:
        NxStorage(const char* storage = nullptr);
        ~NxStorage();

    private:
        // Private member variables
        u64 m_size;
        u64 m_backupGPT = 0;
        bool b_cryptoSet = false;
        bool b_isSplitted = false;
        bool m_keySet_set = false;
        u64 m_freeSpace = 0;

        // Specific vars to handle copy        
        std::ofstream *p_ofstream;
        BYTE *m_buffer;
        int m_buff_size;
        u64 bytes_count;
        u32 m_gpt_lba_start, m_user_lba_start, m_user_lba_end, m_user_new_size, m_user_total_size, m_user_new_bckgpt, cpy_cl_count_in, cpy_cl_count_out;
        unsigned char gpt_header_buffer[0x200];

    
        std::vector<const char*> v_cpy_partitions;

        // Private member functions
        void setStorageInfo(int partition = 0);

    public:
        // Public member variables
        wchar_t m_path[MAX_PATH];        
        int type = INVALID;
        s8 fw_version[48];
        firmware_version_t firmware_version;
        firmware_version_t firmware_version_boot0;
        s8 serial_number[18];
        s8 deviceId[21];
        std::string macAddress;
        unsigned char bootloader_ver = 0;
        bool autoRcm = false;
        bool exFat_driver = false;
        NxKeys keys;

        u32 mmc_b0_lba_start = 0;
        bool b_MayBeNxStorage = false;
        
        NxHandle *nxHandle;
        std::vector<NxPartition *> partitions;
        NxCrypto *nxCrypto;

        // Getters
        u64 backupGPT() { return m_backupGPT; };
        u64 size() { return m_size; };
        bool isCryptoSet() { return b_cryptoSet; };
        bool isSplitted() { return b_isSplitted; };
        bool isEncrypted();
        bool isDrive();
        bool badCrypto();
        bool isNxStorage();
        bool partitionExists(const char* partition_name);

        // Public methods                
        int setKeys(const char* keyset_path);
        const char* getNxTypeAsStr();
        NxPartition* getNxPartition();
        NxPartition* getNxPartition(int part_type);
        NxPartition* getNxPartition(const char* part_name);
        int getNxTypeAsInt(const char* type = nullptr);
        bool isSinglePartType(int type = 0);
        int dumpToFile(const char *file, int crypt_mode, void(&updateProgress)(ProgressInfo*), bool rawnand_only = false);
        int dumpToFile(const char *file, int crypt_mode, u64 *bytesCount, bool rawnand_only = false);
        int restoreFromStorage(NxStorage* input, int crypto_mode, void(&updateProgress)(ProgressInfo*));
        int restoreFromStorage(NxStorage* input, int crypto_mode, u64 *bytesCount);
        int resizeUser(const char *file, u32 new_size, u64 *bytesCount, u64 *bytesToRead, bool format = false);
        bool setAutoRcm(bool enable);
        int applyIncognito();
        void clearHandles();
        std::string getFirmwareVersion(firmware_version_t *fmv = nullptr);
        void setFirmwareVersion(firmware_version_t *fwv, const char* fwv_string);
        int fwv_cmp(firmware_version_t fwv1, firmware_version_t fwv2);
        int createMmcEmuNand(NxStorage* mmc, const char* mmc_drive, void(&updateProgress)(ProgressInfo*));
};

std::string BuildChecksum(HCRYPTHASH hHash);
std::string ListPhysicalDrives();

#endif