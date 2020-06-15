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
#include <fileapi.h>
#include <openssl/sha.h>
#include "res/utils.h"
#include "res/types.h"
#include "res/fat32.h"
#include "res/mbr.h"
#include "res/progress_info.h"
#include "NxHandle.h"
#include "NxPartition.h"
#include "NxCrypto.h"
#include "lib/ZipLib/ZipFile.h"
#include "lib/ZipLib/streams/memstream.h"
#include "lib/ZipLib/methods/Bzip2Method.h"

typedef struct MagicOffsets MagicOffsets;
struct MagicOffsets {
    u64 offset;
    const char* magic;
    u64 size;
    int type;
    float fw;
};


// GUID Partition Table structures
typedef struct _GptHeader
{
    u64 signature;
    u32 revision;
    u32 size;
    u32 c_crc32;
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

typedef struct NxSystemTitles NxSystemTitles;
struct NxSystemTitles {
    const char fw_version[48];
    const char nca_filename[40];
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

enum EmunandType { unknown, fileBasedAMS, fileBasedSXOS, rawBased };

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
        //unsigned char bootloader_ver = 0;
        int bootloader_ver = 0;
        bool autoRcm = false;
        bool exFat_driver = false;
        NxKeys keys;

        u32 mmc_b0_lba_start = 0;
        bool b_MayBeNxStorage = false;
        
        NxHandle *nxHandle = nullptr;
        std::vector<NxPartition *> partitions;
        NxCrypto *nxCrypto;
        bool stopWork = false;

        // Getters
        u64 backupGPT() { return m_backupGPT; }
        u64 size() { return m_size; }
        bool isCryptoSet() { return m_keySet_set; }
        bool isSplitted();
        bool isEncrypted();
        bool isDrive();
        bool badCrypto();
        bool isNxStorage();
        bool partitionExists(const char* partition_name);

        // Public methods                
        int setKeys(const char* keyset_path);
        const char* getNxTypeAsStr(int type = 0);
        NxPartition* getNxPartition();
        NxPartition* getNxPartition(int part_type);
        NxPartition* getNxPartition(const char* part_name);
        int getNxTypeAsInt(const char* type = nullptr);
        bool isSinglePartType(int type = 0);

        int dump(NxHandle *outHandle, params_t params, void(*updateProgress)(ProgressInfo) = nullptr);
        int dumpControl(params_t par);
        int restore(NxStorage* input, params_t params, void(*updateProgress)(ProgressInfo) = nullptr);

        bool setAutoRcm(bool enable);
        int applyIncognito();
        void clearHandles();
        std::string getFirmwareVersion(firmware_version_t *fmv = nullptr);
        void setFirmwareVersion(firmware_version_t *fwv, const char* fwv_string);
        int fwv_cmp(firmware_version_t fwv1, firmware_version_t fwv2);
        int createMmcEmuNand(const char* mmc_path, void(*updateProgress)(ProgressInfo), const char* boot0_path, const char* boot1_path);
        int createFileBasedEmuNand(EmunandType type, const char* volume_path, void(*updateProgress)(ProgressInfo), const char* boot0_path, const char* boot1_path);
        int userAbort(){stopWork = false; return ERR_USER_ABORT;}
};

std::string BuildChecksum(HCRYPTHASH hHash);
std::string ListPhysicalDrives();

#endif
