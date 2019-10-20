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

#ifndef __NxHandle_h__
#define __NxHandle_h__

#include <windows.h>
#include <winioctl.h>
#include <Wincrypt.h>
#include <string>
#include <string.h> 
#include "res/types.h"
#include "NxPartition.h"
#include "NxStorage.h"
#include "res/utils.h"

using namespace std;

typedef struct NxSplitFile NxSplitFile;
struct NxSplitFile {
    u64 offset;
    u64 size;
    wchar_t file_path[MAX_PATH];
    NxSplitFile *next = NULL;
};

class NxStorage;
class NxPartition;
class NxCrypto;

class NxHandle {

    // Constructors
    public: 
        explicit NxHandle(NxStorage *parent);
        ~NxHandle();

    // Private member variables
    private:

        NxStorage *parent;
        HANDLE m_h;

        // Offsets & I/O member variables
        u64 m_off_start = 0;
        u64 m_off_end = 0;
        u64 m_off_max = 0;
        u64 m_size = 0;
        u64 m_readAmount = 0;
        u32 m_cur_block = 0;
        LARGE_INTEGER lp_CurrentPointer;
        LARGE_INTEGER li_DistanceToMove;

        // Geometry & size
        u64 m_totalSize = 0;
        u64 m_fileDiskTotalBytes;
        u64 m_fileDiskFreeBytes;

        // Splitted storage
        NxSplitFile *m_lastSplitFile;
        NxSplitFile *m_curSplitFile;
        int m_splitFileCount = 0;
        bool b_isSplitted = false;

        // Crypto
        HCRYPTPROV h_WinCryptProv;
        HCRYPTHASH m_md5_hash;
        BYTE m_md5_buffer[DEFAULT_BUFF_SIZE];
        NxCrypto *nxCrypto;
        int m_crypto = NO_CRYPTO;
    
        // Boolean
        bool b_isDrive = false;

        // Methods
        NxSplitFile* getSplitFile(u64 offset);        

    public:

        // Public variables
        bool exists = false;

        // Getters
        bool isDrive() { return b_isDrive; };
        u64  size() { return m_size; };
        bool isSplitted() { return b_isSplitted; };
        int getCryptoMode() { return m_crypto; };
        HCRYPTHASH md5Hash() { return m_md5_hash; };
        int getSplitCount() { return m_splitFileCount; };
        int getDefaultBuffSize();
        NxCrypto* crypto() { return nxCrypto; };

        // Setters
        void setSplitted(bool b) { b_isSplitted = b; };
        void setSize(u64 u_size) { m_size = u_size; };
        void setCrypto(int crypto_mode = NO_CRYPTO) { m_crypto = crypto_mode; };

        // Public methods
        void initHandle(int crypto_mode = NO_CRYPTO, NxPartition *partition = nullptr);
        bool detectSplittedStorage();        
        void clearHandle();
        bool read(void *buffer, DWORD* bytesRead, DWORD length = 0);
        bool read(u64 offset, void *buffer, DWORD* bytesRead, DWORD length = 0);
        bool read(u32 lba, void *buffer, DWORD* bytesRead, DWORD length = 0);
        bool write(void *buffer, DWORD* bytesWrite, DWORD length = 0);
        bool write(u64 offset, void *buffer, DWORD* bytesWrite, DWORD length = 0);
        bool createFile(wchar_t *path, int io_mode = GENERIC_READ);
        bool hash(u64* bytesCount);
        bool setPointer(u64 offset);
};

#endif