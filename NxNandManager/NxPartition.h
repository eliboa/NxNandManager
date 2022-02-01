/*
 * Copyright (c) 2021 eliboa
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
#include "NxStorage.h"
#include "res/types.h"
#include "res/fat32.h"
#include "NxHandle.h"
#include "NxCrypto.h"
#include "res/progress_info.h"
#include "lib/fatfs/diskio.h"
#include <mutex>
#if defined(ENABLE_GUI)
#include <QObject>
#endif

#include "virtual_fs/virtual_fs.h"
namespace virtual_fs {
    class virtual_fs;
}
typedef struct NxPart NxPart;
struct NxPart {
    s8 name[37];
    int type;
    int fs;
    u64 size;
    bool isEncrypted;    
    const char* magic;
    u64 magic_off;
};


static NxPart NxPartArr[] =
{
    { "BOOT0",                   BOOT0    , RAW,    0x00400000 , false , NULL, 0},
    { "BOOT1",                   BOOT1    , RAW,    0x00400000 , false , NULL, 0},
    { "PRODINFO",                PRODINFO , RAW,    0x003FBC00 , true  , "CAL0", 0},
    { "PRODINFOF",               PRODINFOF, FAT12,  0x00400000 , true  , "CERTIF", 0x680},
    { "BCPKG2-1-Normal-Main",    BCPKG21  , RAW,    0x00800000 , false , NULL, 0},
    { "BCPKG2-2-Normal-Sub",     BCPKG22  , RAW,    0x00800000 , false , NULL, 0},
    { "BCPKG2-3-SafeMode-Main",  BCPKG23  , RAW,    0x00800000 , false , NULL, 0},
    { "BCPKG2-4-SafeMode-Sub",   BCPKG24  , RAW,    0x00800000 , false , NULL, 0},
    { "BCPKG2-5-Repair-Main",    BCPKG25  , RAW,    0x00800000 , false , NULL, 0},
    { "BCPKG2-6-Repair-Sub",     BCPKG26  , RAW,    0x00800000 , false , NULL, 0},
    { "SAFE",                    SAFE     , FAT32,  0x04000000 , true  , "NO NAME", 0x47},
    { "SYSTEM",                  SYSTEM   , FAT32,  0xA0000000 , true  , "NO NAME", 0x47},
    { "USER",                    USER     , FAT32,  0x680000000, true  , "NO NAME", 0x47}
};

class NxStorage;
class NxCrypto;
class NxHandle;

enum VFSOptions {
    NoOption            = 0,
    ReadOnly            = 1,
    VirtualNXA          = 2
};
DEFINE_ENUM_FLAG_OPERATORS(VFSOptions)

class NxPartition
#if defined(ENABLE_GUI)
    : public QObject
{
    Q_OBJECT
#else
{
#endif
    // Constructors
    public:
        NxPartition(NxStorage *parent, const char* p_name, u32 lba_start, u32 lba_end, u64 attrs = 0);
        ~NxPartition();
        NxStorage *parent;

    private:
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
        fat32::fs_attr m_fs;
        bool m_fsSet = false;

        // Mutex
        std::mutex _fs_mutex;

        // Filesystem
        FATFS m_fatfs;

        // Virtual fs & virtual disk
        virtual_fs::virtual_fs *m_vfs = nullptr;
        WCHAR m_mount_point[5] = L" :\\\0";
        bool m_is_vfs_mounted = false;

    public:
        u64 freeSpace = 0;
        u64 freeSpaceRaw = 0;
        u64 availableTotSpace = 0;
        NxHandle *nxHandle;
        bool stopWork = false;
        NxPart nxPart_info;

        // Getters
        std::string partitionName();
        u32 lbaStart();
        u32 lbaEnd();
        u64 size();
        int type() { return m_type; }
        NxCrypto* crypto() { return nxCrypto; }
        fat32::fs_attr fs_attr() { return m_fs; }
        FATFS *fs() { return &m_fatfs; }
        virtual_fs::virtual_fs *vfs() { return m_vfs; }
        NxStorage* nxStorage() { return parent; }
        void getVolumeMountPoint(WCHAR *mountPoint);
        wstring getVolumeMountPoint();

        // Setters
        void setBadCrypto(bool bad = true) { m_bad_crypto = bad; }
        void setVolumeMountPoint(WCHAR *mountPoint);

        // Boolean    
        bool isValidPartition();
        bool isEncryptedPartition();
        bool isGood();
        bool badCrypto() { return m_bad_crypto; }

        // Member function
        bool fat32_dir(std::vector<fat32::dir_entry> *entries, const char *dir);
        u64 fat32_getFreeSpace(u64* contiguous = nullptr, u64* available = nullptr);
        bool fat32_isFreeCluster(u32 cluster_num, u32 *clus_count = nullptr);
        bool setCrypto(char* crypto, char* tweak);
        int compare(NxPartition *partition);
        int dump(NxHandle *outHandle, part_params_t params, void(*updateProgress)(ProgressInfo) = nullptr);
        int restore(NxStorage* input, part_params_t params, void(*updateProgress)(ProgressInfo) = nullptr);
        int formatPartition(void(*updateProgress)(ProgressInfo) = nullptr);
        void clearHandles();
        int userAbort(){stopWork = false; return ERR_USER_ABORT;}

        // Filesystem
        wstring fs_prefix(const wchar_t* path = L"");
        int mount_fs();
        int unmount_fs();
        int unmount_vfs();
        bool is_mounted() { return m_fatfs.fs_type > 0; }
        bool is_vfs_mounted() { return m_is_vfs_mounted; }
        int mount_vfs(bool run = true, wchar_t driveLetter = L'\0', VFSOptions options = NoOption, void(*clb_func_ptr)(NTSTATUS) = nullptr);

        FRESULT f_open (FIL* fp, const TCHAR* path, BYTE mode);				/* Open or create a file */
        FRESULT f_opendir (DIR* dp, const TCHAR* path);						/* Open a directory */
        FRESULT f_mkdir (const TCHAR* path);								/* Create a sub directory */
        FRESULT f_unlink (const TCHAR* path);								/* Delete an existing file or directory */
        FRESULT f_rename (const TCHAR* path_old, const TCHAR* path_new);	/* Rename/Move a file or directory */
        FRESULT f_stat (const TCHAR* path, FILINFO* fno);					/* Get file status */
        FRESULT f_chmod (const TCHAR* path, BYTE attr, BYTE mask);			/* Change attribute of a file/dir */
        FRESULT f_utime (const TCHAR* path, const FILINFO* fno);			/* Change timestamp of a file/dir */
        FRESULT f_getfree (const TCHAR* path, DWORD* nclst, FATFS** fatfs);	/* Get number of free clusters on the drive */
        FRESULT f_readdir (DIR* dp, FILINFO* fno);
#if defined(ENABLE_GUI)
signals:
        void vfs_mounted_signal();
        void vfs_unmounted_signal();
        void vfs_callback(long status);
#endif
};
#endif
