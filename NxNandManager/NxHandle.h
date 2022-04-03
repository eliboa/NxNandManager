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
#include <iostream>
#include <string>
#include <mutex>
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
    HANDLE handle = nullptr;
    NxSplitFile *next = nullptr;
};

typedef struct splitFileName_t splitFileName_t;
struct splitFileName_t {
    int f_number = 0;
    int f_digits = 0;
    int f_type = 0;
};

typedef struct _cluster_cache_t {
    bool valid;
    u32 clu_number;
    u8 data[CLUSTER_SIZE];
} cluster_cache_t;

class NxStorage;
class NxPartition;
class NxCrypto;

class NxHandle {

    // Constructors
    public: 
        explicit NxHandle(NxStorage *parent);
        explicit NxHandle(const char *path, u64 chunksize = 0);
        explicit NxHandle(const wstring &path, u64 chunksize = 0);
        ~NxHandle();

    // Private member variables
    private:

        NxStorage *parent = nullptr;
        HANDLE m_h;

        // Offsets & I/O member variables
        std::wstring m_path;
        std::wstring m_firstPart_path;
        u64 m_off_start = 0;
        u64 m_off_end = 0;
        u64 m_off_max = 0;
        u64 m_size = 0;
        u64 m_readAmount = 0;
        u64 m_writeAmount = 0;
        u32 m_cur_block = 0;
        u64 m_chunksize = 0;

        LARGE_INTEGER lp_CurrentPointer;
        LARGE_INTEGER li_DistanceToMove;
        u64 virtual_currentPtr() { return (u64)lp_CurrentPointer.QuadPart - m_off_start; }
        u64 real_currentPtr() { return (u64)lp_CurrentPointer.QuadPart; }
        u64 split_currentPtr() { return m_curSplitFile ? (u64)lp_CurrentPointer.QuadPart - m_curSplitFile->offset : (u64)lp_CurrentPointer.QuadPart; }
        // Geometry & size
        u64 m_totalSize = 0;
        u64 m_fileDiskTotalBytes;
        u64 m_fileDiskFreeBytes;
        bool m_isReadOnly = false;

        // Splitted storage
        NxSplitFile *m_lastSplitFile = nullptr;
        NxSplitFile *m_curSplitFile = nullptr;
        int m_splitFileCount = 0;
        bool b_isSplitted = false;

        // Crypto
        HCRYPTPROV h_WinCryptProv;
        HCRYPTHASH m_md5_hash;
        bool m_isHashLocked = false;
        NxCrypto *nxCrypto;
        int m_crypto = NO_CRYPTO;

        // Boolean
        bool b_isDrive = false;

        // Member functions
        void constructor(const wstring &path, u64 chunksize);
        NxSplitFile* getSplitFile(u64 offset);        
        void do_crypto(u8* buffer, u32 buff_size, u64 start_offset);

        // Mutex
        std::mutex _read_write_mutex;

    public:

        // Public variables
        bool exists = false;
        DISK_GEOMETRY pdg;

        // Getters
        NxStorage* getParent() { return parent;}
        HANDLE getHandle() { return m_h; }
        bool isDrive() { return b_isDrive; }
        u64  size() { return m_size; }
        bool isSplitted() { return b_isSplitted; }
        int getCryptoMode() { return m_crypto; }
        HCRYPTHASH md5Hash() { return m_md5_hash; }
        int getSplitCount() { return m_splitFileCount; }
        u64 getChunkSize() { return m_chunksize; }
        std::wstring getPath() { return m_path; }
        NxSplitFile* getLastSplitFile() { return m_lastSplitFile; }
        std::wstring getFistPartPath() { return m_firstPart_path; }
        int getDefaultBuffSize();
        u64 getDiskFreeSpace() { return m_fileDiskFreeBytes; }
        u64 getCurrentPointer() { return lp_CurrentPointer.QuadPart - m_off_start; }
        NxCrypto* crypto() { return nxCrypto; }
        bool isReadOnly() { return m_isReadOnly; }

        // Setters
        void setSplitted(bool b) { b_isSplitted = b; }
        void setSize(u64 u_size) { m_size = u_size; }
        void setOffMax(u64 off) { m_off_max = m_off_start + off; }
        void setCrypto(int crypto_mode = NO_CRYPTO) { m_crypto = crypto_mode; }
        void setPath(std::wstring path) { m_path = path; }
        void lockHash();
        void unlockHash() { m_isHashLocked = false; }
        void setChunksize(u64 size) { m_chunksize = size; }

        // Public member functions
        void initHandle(int crypto_mode = NO_CRYPTO, NxPartition *partition = nullptr);
        bool detectSplittedStorage();
        splitFileName_t getSplitFileNameAttributes(std::wstring filepath = L"");
        bool getNextSplitFile(std::wstring &next_file, std::wstring cur_filepath = L"");
        bool getJoinFileName(std::wstring &join_name, std::wstring cur_filepath);
        void clearHandle();
        void closeHandle();
        bool read(void *buffer, DWORD* bytesRead, DWORD length = 0);
        bool read(u64 offset, void *buffer, DWORD* bytesRead, DWORD length = 0);
        bool read(u32 lba, void *buffer, DWORD* bytesRead, DWORD length = 0);
        bool write(void *buffer, DWORD* bytesWrite, DWORD length = 0);
        bool write(u64 offset, void *buffer, DWORD* bytesWrite, DWORD length = 0);
        bool write(u32 sector, void *buffer, DWORD* bw, DWORD length);
        bool createFile(wchar_t *path, unsigned long io_mode = GENERIC_READ, HANDLE *handle = nullptr);
        void createHandle(unsigned long io_mode = GENERIC_READ);
        bool hash(string storage_name, void(*updateProgress)(ProgressInfo));
        bool setPointer(u64 offset);
        bool dismountVolume();
        bool dismountAllVolumes();
        bool lockVolume();
        bool unlockVolume();
        bool lockFile();
        bool ejectVolume();
        bool getVolumeName(WCHAR *pVolumeName, u32 start_sector);



};

#endif
