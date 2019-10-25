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

#ifndef __NxPartition_h__
#define __NxPartition_h__

#include <stdio.h>
#include <string>
#include <string.h> 
#include "res/types.h"
#include "res/fat32.h"
#include "NxHandle.h"
#include "NxCrypto.h"
#include "NxStorage.h"

using namespace std;

typedef struct NxPart NxPart;
struct NxPart {
    s8 name[37];
    int type;
    u64 size;
    bool isEncrypted;    
    const char* magic;
    u64 magic_off;
};

static NxPart NxPartArr[] =
{
    { "BOOT0",                   BOOT0    ,0x00400000 , false , NULL, 0},
    { "BOOT1",                   BOOT1    ,0x00400000 , false , NULL, 0},
    { "PRODINFO",                PRODINFO ,0x003FBC00 , true  , "CAL0", 0},
    { "PRODINFOF",               PRODINFOF,0x00400000 , true  , "CERTIF", 0x680},
    { "BCPKG2-1-Normal-Main",    BCPKG21  ,0x00800000 , false , NULL, 0},
    { "BCPKG2-2-Normal-Sub",     BCPKG22  ,0x00800000 , false , NULL, 0},
    { "BCPKG2-3-SafeMode-Main",  BCPKG23  ,0x00800000 , false , NULL, 0},
    { "BCPKG2-4-SafeMode-Sub",   BCPKG24  ,0x00800000 , false , NULL, 0},
    { "BCPKG2-5-Repair-Main",    BCPKG25  ,0x00800000 , false , NULL, 0},
    { "BCPKG2-6-Repair-Sub",     BCPKG26  ,0x00800000 , false , NULL, 0},
    { "SAFE",                    SAFE     ,0x04000000 , true  , "NO NAME", 0x47},
    { "SYSTEM",                  SYSTEM   ,0xA0000000 , true  , "NO NAME", 0x47},
    { "USER",                    USER     ,0x680000000, true  , "NO NAME", 0x47}
};

class NxStorage;
class NxCrypto;
class NxHandle;

class NxPartition
{
    // Constructors
    public:
        NxPartition(NxStorage *parent, const char* p_name, u32 lba_start, u32 lba_end, u64 attrs = 0);
        ~NxPartition();
    
    // Member variables
    private:
        NxStorage *parent;        
        u32 m_lba_start = 0;
        u32 m_lba_end = 0;
        u64 m_attrs = 0;
        s8  m_name[37];
        int m_type;
        bool m_isEncrypted = false;
        bool m_bad_crypto = false;    
        bool m_isValidPartition = false;
        NxCrypto *nxCrypto;
        std::ofstream p_ofstream;
        BYTE *m_buffer;
        int m_buff_size;
        u64 bytes_count;

    public:
        u64 freeSpace = 0;

    // Member methods
    public:
        NxHandle *nxHandle;
        NxPart nxPart_info;

        // Getters
        std::string partitionName();
        u32 lbaStart();
        u32 lbaEnd();
        u64 size();
        bool badCrypto() { return m_bad_crypto; };
        int type() { return m_type; };
        NxCrypto* crypto() { return nxCrypto; };
        
        // Setters
        void setBadCrypto(bool bad = true) { m_bad_crypto = bad; };

        // Boolean    
        bool isValidPartition();
        bool isEncryptedPartition();  

        //Methods
        bool fat32_dir(std::vector<fat32::dir_entry> *entries, const char *dir);
        u64 fat32_getFreeSpace();   
        bool setCrypto(char* crypto, char* tweak);
        int compare(NxPartition *partition);
        int dumpToFile(const char *file, int crypt_mode, u64 *bytesCount);
        int restoreFromStorage(NxStorage* input, int crypto_mode, u64 *bytesCount);
        void clearHandles();
};

#endif