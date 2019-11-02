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

#include "NxHandle.h"

NxHandle::NxHandle(NxStorage *p)
{
    if (nullptr == p)
        return;

    parent = p;    

    // Create new file
    m_h = CreateFileW(parent->m_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (m_h != INVALID_HANDLE_VALUE)
    {        
        // Get drive geometry
        DISK_GEOMETRY pdg;
        DWORD junk = 0;
        if (DeviceIoControl(m_h, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pdg, sizeof(pdg), &junk, (LPOVERLAPPED)NULL))
        {
            b_isDrive = true;
            m_totalSize = pdg.Cylinders.QuadPart * (ULONG)pdg.TracksPerCylinder * (ULONG)pdg.SectorsPerTrack * (ULONG)pdg.BytesPerSector;
            m_size = m_totalSize;
            exists = true;
        }
    }
    CloseHandle(m_h);    

    // Open file/disk
    if (!createFile(parent->m_path, GENERIC_READ))
        return;

    // Get size for file
    LARGE_INTEGER Lsize;
    if (!b_isDrive && GetFileSizeEx(m_h, &Lsize))
    {
        m_size = Lsize.QuadPart;
        m_totalSize = m_size;
        exists = true;
    }

    // Get available space on disk for file
    if (!b_isDrive)
    {        
        std::wstring path_str = std::wstring(parent->m_path);
        std::size_t pos = path_str.find(base_nameW(path_str));
        std::wstring dir = path_str.substr(0, pos);
        if (dir.length() == 0)
        {
            wchar_t buffer[MAX_PATH];
            GetModuleFileNameW(NULL, buffer, MAX_PATH);
            dir = std::wstring(buffer);
        }

        DWORD dwSectPerClust, dwBytesPerSect, dwFreeClusters, dwTotalClusters;
        BOOL fResult = GetDiskFreeSpaceW(dir.c_str(), &dwSectPerClust, &dwBytesPerSect, &dwFreeClusters, &dwTotalClusters);
        if (fResult)
        {
            m_fileDiskTotalBytes = (u64)dwTotalClusters * dwSectPerClust * dwBytesPerSect;
            m_fileDiskFreeBytes = (u64)dwFreeClusters * dwSectPerClust * dwBytesPerSect;
        }
    }

    initHandle();
}

NxHandle::~NxHandle()
{
    clearHandle();
    NxSplitFile *current = m_lastSplitFile, *next;
    while (nullptr != current)
    {
        next = current->next;
        delete current;
        current = next;
    }
}

void NxHandle::initHandle(int crypto_mode, NxPartition *partition)
{
    u64 tmp_size = !parent->size() || isSplitted() ? m_size : parent->size();
    m_off_start = (u64)parent->mmc_b0_lba_start * NX_BLOCKSIZE;
    m_off_end = m_off_start + tmp_size - 1;
    m_off_max = m_off_end;
    m_readAmount = 0;
    m_cur_block = 0;
    lp_CurrentPointer.QuadPart = 0;
    m_crypto = crypto_mode;

    if (nullptr != partition)
    {
        m_off_start = ((u64)parent->mmc_b0_lba_start + (u64)partition->lbaStart()) * NX_BLOCKSIZE;
        m_off_end = m_off_start + (((u64)partition->lbaEnd() - (u64)partition->lbaStart() + 1) * NX_BLOCKSIZE) - 1;

        if(m_crypto == DECRYPT || m_crypto == ENCRYPT)
        {
            nxCrypto = partition->crypto();
        }
    }

    if (m_crypto == MD5_HASH)
    {
        // Get handle to the crypto provider
        CryptAcquireContext(&h_WinCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        // Create new hash
        CryptCreateHash(h_WinCryptProv, CALG_MD5, 0, 0, &m_md5_hash);
    }

    // Set pointer at start
    setPointer(0);
    
    /*
    dbg_printf("NxHandle::initHandle() set for %s, current pointer is %s - m_off_start = %s, m_off_end = %s, crypto_mode = %d\n",
        nullptr != partition ? partition->partitionName().c_str() : "NxStorage", n2hexstr(lp_CurrentPointer.QuadPart, 10).c_str(), 
        n2hexstr(m_off_start, 10).c_str(), n2hexstr(m_off_end, 10).c_str(), m_crypto);
    */
}

bool NxHandle::detectSplittedStorage()
{
    wstring Lfilename(parent->m_path);
    wstring extension(get_extensionW((Lfilename)));
    wstring basename(remove_extensionW(Lfilename));

    string basename_tmp(basename.begin(), basename.end());

    if (extension.compare(basename) == 0)
        extension.erase();

    // Look for an integer in path extension
    int f_number, f_digits, f_type = 0;
    if (wcslen(extension.c_str()) > 1)
    {
        
        wstring number = extension.substr(1, wcslen(extension.c_str()));
        if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
        {
            // Extension is integer
            f_number = std::stoi(number);
            f_digits = wcslen(number.c_str());
            if (f_digits <= 2) f_type = 1;
        }
    }
    // Look for an integer in base name (2 digits max)
    if (f_type == 0)
    {
        wstring number = basename.substr(wcslen(basename.c_str()) - 2, wcslen(basename.c_str()));
        if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
        {            
            f_number = std::stoi(number);
            f_digits = 2;
            f_type = 2;
        }
        else {
            number = basename.substr(wcslen(basename.c_str()) - 1, wcslen(basename.c_str()));
            if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
            {
                f_number = std::stoi(number);
                f_digits = 1;
                f_type = 2;
            }
        }
    }

    // Integer found in path
    if (f_type > 0)
    {
        int i = f_number;
        m_splitFileCount = 0;
        LARGE_INTEGER Lsize;
        u64 s_size = 0;
        wstring path = Lfilename;
        string mask("%0" + to_string(f_digits) + "d");                

        clearHandle();

        // For each splitted file
        do {
            // Get handle 
            createFile(&path[0]);

            if (!GetFileSizeEx(m_h, &Lsize))
                break;            

            // New NxSplitFile
            NxSplitFile *splitfile = reinterpret_cast<NxSplitFile *>(malloc(sizeof(NxSplitFile)));
            wcscpy(splitfile->file_path, path.c_str());
            splitfile->offset = s_size;
            splitfile->size = static_cast<u64>(Lsize.QuadPart);
            splitfile->next = m_lastSplitFile;
            m_lastSplitFile = splitfile;

            // First split file is current split file
            if (!m_splitFileCount)
                m_curSplitFile = splitfile;

            s_size += splitfile->size;

            ++m_splitFileCount;
            clearHandle();            

            // Format path to next file
            char new_number[10];
            sprintf_s(new_number, 10, mask.c_str(), ++i);
            wstring wn_number = convertCharArrayToLPWSTR(new_number);
            if (f_type == 1)
                path = basename + L"." + wn_number;
            else
                path = basename.substr(0, wcslen(basename.c_str()) - f_digits) + wn_number + extension;

        } while (file_exists(path.c_str()));

        clearHandle();

        // Get handle for original file
        createFile(parent->m_path, GENERIC_READ);        

        // If more than one file found
        if (m_splitFileCount > 1)
        {
            // New handle size
            m_size = s_size;
            b_isSplitted = true;
            initHandle();
            return true;
        }
    }
    return false;
}

bool NxHandle::createFile(wchar_t *path, int io_mode)
{
    if (io_mode != GENERIC_READ && io_mode != GENERIC_WRITE)
        return false;

    if (io_mode == GENERIC_READ)
        m_h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    else
        m_h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    
    if (m_h == INVALID_HANDLE_VALUE)
    {
        dbg_wprintf(L"NxHandle::createFile() for %s ERROR %s\n", path, GetLastErrorAsString().c_str());
        CloseHandle(m_h);
        return false;
    }

    if (b_isDrive && !lockVolume())
        dbg_printf("failed to lock volume\n");
    
    if (b_isDrive && !dismountVolume())
        dbg_printf("failed to dismount volume\n");

    return true;
}

bool NxHandle::setPointer(u64 offset)
{
    if (b_isSplitted)
    {
        u64 real_offset = m_off_start + offset - m_curSplitFile->offset;;
        NxSplitFile *file = getSplitFile(m_off_start + offset);
        if (nullptr == file)
            return false;

        if (wcscmp(file->file_path, m_curSplitFile->file_path))
        {            
            // Switch to next split file
            createFile(file->file_path);
            real_offset = m_off_start + offset - file->offset;
            m_curSplitFile = file;

           // dbg_printf("NxHandle::setPointer Switch to split, real offset = %s \n", n2hexstr(real_offset, 12).c_str());           
        }

        li_DistanceToMove.QuadPart = real_offset;
        if (SetFilePointerEx(m_h, li_DistanceToMove, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            return false;

        
        lp_CurrentPointer.QuadPart = m_curSplitFile->offset + real_offset;
        //dbg_printf("NxHandle::setPointer - lp_CurrentPointer = %s (real = %s)\n", n2hexstr(lp_CurrentPointer.QuadPart, 12).c_str(),
        //    n2hexstr(real_offset, 12).c_str());
    }
    else
    {
        li_DistanceToMove.QuadPart = m_off_start + offset;
        if (SetFilePointerEx(m_h, li_DistanceToMove, &lp_CurrentPointer, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
        {
            dbg_printf("INVALID POINTER\n");
            return false;
        }
    }

    //dbg_printf("NxHandle::setPointer(%s) real offset = %s\n", n2hexstr(offset, 12).c_str(), n2hexstr(m_off_start + offset, 12).c_str());

    return true;
}

bool NxHandle::read(void *buffer, DWORD* br, DWORD length)
{
    if(nullptr != br) *br = 0;
    DWORD bytesRead;

    // Set default buffer size 
    if (!length) 
        length = getDefaultBuffSize();

    // TO-DO : Resize buffer if there's not enough bytes in split file
    if (b_isSplitted)
    {
        NxSplitFile *file = getSplitFile((u64)lp_CurrentPointer.QuadPart);
        if (nullptr == file)
            return false;

        // Switch to next split file (in setPointer(u64 off))
        if (wcscmp(file->file_path, m_curSplitFile->file_path)) 
        {            
            setPointer(lp_CurrentPointer.QuadPart - m_off_start);
        }
    }
    
    /*
    dbg_printf("NxHandle::read(buffer, bytesRead=%I64d, length=%s) at offset %s crypto mode = %d\n",
    nullptr != br ? *br : 0, n2hexstr(length, 6).c_str(), n2hexstr(lp_CurrentPointer.QuadPart, 10).c_str(), 
    m_crypto);
    */

    // eof
    if (lp_CurrentPointer.QuadPart > m_off_end) {        
        
        dbg_printf("NxHandle::read reach eof (cur = %s, m_off_end = %s)\n",
            n2hexstr(lp_CurrentPointer.QuadPart, 10).c_str(),
            n2hexstr(m_off_end, 10).c_str());
        
        return false;
    }

    if (!ReadFile(m_h, buffer, length, &bytesRead, NULL)) {
        dbg_printf("NxHandle::read ReadFile error\n");
        return false;
    }

    if (bytesRead == 0)
    {
        dbg_printf("NxHandle::read 0 BYTE read\n");
        return false;
    }

    // Encrypt/Decrypt buffer
    //printf("READ CRYPTO %d, LENGTH %s\n", m_crypto, n2hexstr(length, 10).c_str());
    if (is_in(m_crypto, { ENCRYPT, DECRYPT }) && nxCrypto != nullptr && length == CLUSTER_SIZE)
    {
        m_cur_block = (lp_CurrentPointer.QuadPart - m_off_start) / CLUSTER_SIZE;
        if (m_crypto == ENCRYPT) {            
            nxCrypto->encrypt((unsigned char*)buffer, m_cur_block);
        }
        else
            nxCrypto->decrypt((unsigned char*)buffer, m_cur_block);
    }

    //dbg_printf("NxHandle::read done, %I32d bytes\n", bytesRead);

    lp_CurrentPointer.QuadPart += bytesRead;

    if (nullptr != br)
    {
        // Resize buffer length if eof is reached
        if (lp_CurrentPointer.QuadPart > m_off_end)
        {
            u32 bytes = lp_CurrentPointer.QuadPart - m_off_end - 1;
            printf("Resize buffer original %I32d b, new %I32d b (cur_off = %s, m_off_end = %s)\n", bytesRead, bytes, 
                n2hexstr(lp_CurrentPointer.QuadPart, 10).c_str(), n2hexstr(m_off_end, 10).c_str());
            *br = bytesRead - bytes;
        }
        else *br = bytesRead;
    }

    // Hash buffer
    if (m_crypto == MD5_HASH)
    {
        CryptHashData(m_md5_hash, (BYTE*)buffer, nullptr != br ? *br : bytesRead, 0);
    }

    //dbg_printf("NxHandle::read returns %I64d bytes\n", bytesRead);
    return true;

}

bool NxHandle::read(u64 offset, void *buffer, DWORD* bytesRead, DWORD length)
{

    if ((offset % NX_BLOCKSIZE) && b_isDrive)
        return false;

    // Set new pointer if needed
    if (lp_CurrentPointer.QuadPart != m_off_start + offset && !setPointer(offset))
            return false;
    
    return read(buffer, bytesRead, length);
}

bool NxHandle::read(u32 lba, void *buffer, DWORD* bytesRead, DWORD length)
{
    u64 offset = (u64) lba * NX_BLOCKSIZE;
    return read(offset, buffer, bytesRead, length);
}

bool NxHandle::write(void *buffer, DWORD* bw, DWORD length)
{
    if (nullptr != bw) *bw = 0;
    if (!length) length = getDefaultBuffSize();
    DWORD bytesWrite;

    // TO-DO : Resize buffer if there's not enough bytes in split file
    if (b_isSplitted)
    {
        NxSplitFile *file = getSplitFile((u64)lp_CurrentPointer.QuadPart);
        if (nullptr == file)
            return false;

        // Switch to next split file (in setPointer(u64 off))
        if (wcscmp(file->file_path, m_curSplitFile->file_path))
            setPointer(lp_CurrentPointer.QuadPart - m_off_start);
    }

    // eof
    if (lp_CurrentPointer.QuadPart > m_off_max) {
        dbg_printf("NxHandle::write reach EOF\n");
        return false;
    }

    /*
    dbg_printf("NxHandle::write(buffer, bytesRead=%I64d, length=%s) at offset %s - crypto_mode = %d\n",
        nullptr != bw ? *bw : 0, n2hexstr(length, 6).c_str(), n2hexstr(lp_CurrentPointer.QuadPart, 10).c_str(), m_crypto);
    
    dbg_printf("NxHandle::write - buffer is \n%s\n", hexStr((unsigned char*)buffer, length).c_str());
    */
    // Resize buffer if eof
    if (lp_CurrentPointer.QuadPart + length > m_off_end)
    {
        u32 bytes = lp_CurrentPointer.QuadPart + length - m_off_end - 1;
        length -= bytes;
        dbg_printf("NxHandle::write - buffer resized to %I32d bytes\n", length);
    }

    // Encrypt buffer
    if (m_crypto == ENCRYPT && nxCrypto != nullptr && length == CLUSTER_SIZE)
    {
        m_cur_block = (lp_CurrentPointer.QuadPart - m_off_start) / CLUSTER_SIZE;
        nxCrypto->encrypt((unsigned char*)buffer, m_cur_block);
    }

    if (!WriteFile(m_h, buffer, length, &bytesWrite, NULL))
    {
        DWORD errorMessageID = ::GetLastError();
        dbg_printf("NxHandle::write - FAILED WriteFile - %I32d : %s", errorMessageID, GetLastErrorAsString().c_str());
        return false;
    }
    if (bytesWrite == 0) {
        dbg_printf("NxHandle::write - FAILED NO BYTE WRITE\n");
        return false;
    }

    lp_CurrentPointer.QuadPart += bytesWrite;
    *bw = bytesWrite;
    return true;
}

bool NxHandle::write(u64 offset, void *buffer, DWORD* bw, DWORD length)
{
    if ((offset % NX_BLOCKSIZE) && b_isDrive)
        return false;

    // Set new pointer if needed
    if (lp_CurrentPointer.QuadPart != m_off_start + offset && !setPointer(offset))
        return false;

    return write(buffer, bw, length);
}

bool NxHandle::hash(u64* bytesCount)
{
    if (!*bytesCount)
    {
        initHandle(MD5_HASH);
        memset(m_md5_buffer, 0, DEFAULT_BUFF_SIZE);
    }

    DWORD bytesRead = 0;
    bool success = false;
    if (!(read(m_md5_buffer, &bytesRead, DEFAULT_BUFF_SIZE)))
        success = true;

    *bytesCount += bytesRead;
    return success;
}

NxSplitFile* NxHandle::getSplitFile(u64 offset)
{
    if (!b_isSplitted)
        return nullptr;

    NxSplitFile *file = m_lastSplitFile;
    while (nullptr != file)
    {
        if (offset >= file->offset && offset < file->offset + file->size) 
            return file;

        file = file->next;
    }

    return nullptr;
}

void NxHandle::clearHandle()
{
    //dbg_printf("NxHandle::clearHandle()\n");
    DWORD lpdwFlags[100];
    if (GetHandleInformation(m_h, lpdwFlags))
    {
        CloseHandle(m_h);
    }
    initHandle();
}

int NxHandle::getDefaultBuffSize()
{
    int size = DEFAULT_BUFF_SIZE;
    if (is_in(m_crypto, {ENCRYPT, DECRYPT}))
        size = CLUSTER_SIZE;

    //printf("getDefaultBuffSize crypto_mode = %d, returns %s\n", m_crypto, n2hexstr(size, 10).c_str());
    return size;
}

void NxHandle::closeHandle()
{
    CloseHandle(m_h);
}

bool NxHandle::dismountVolume()
{
    DWORD dwBytesReturned;

    return DeviceIoControl(m_h,
        FSCTL_DISMOUNT_VOLUME,
        NULL, 0,
        NULL, 0,
        &dwBytesReturned,
        NULL);
}

#define LOCK_TIMEOUT 10000 // 10 Seconds
#define LOCK_RETRIES 20

bool NxHandle::lockVolume()
{
   
    DWORD dwBytesReturned;
    DWORD dwSleepAmount;
    int nTryCount;

    dwSleepAmount = LOCK_TIMEOUT / LOCK_RETRIES;

    // Do this in a loop until a timeout period has expired
    for (nTryCount = 0; nTryCount < LOCK_RETRIES; nTryCount++) 
    {
        dbg_printf("try %d to lock volume\n", nTryCount);
        if (DeviceIoControl(m_h,
            FSCTL_LOCK_VOLUME,
            NULL, 0,
            NULL, 0,
            &dwBytesReturned,
            NULL))
            return TRUE;

        Sleep(dwSleepAmount);
    }
    return FALSE;
}

bool NxHandle::lockFile()
{
    LARGE_INTEGER off, size;
    off.QuadPart = m_off_start;
    size.QuadPart = m_off_max - m_off_start;
    OVERLAPPED sOverlapped;
    sOverlapped.Offset = off.LowPart;
    sOverlapped.OffsetHigh = off.HighPart;

    //dbg_printf("lockFile() ");

    if (LockFileEx(
        m_h,
        LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
        0,
        size.LowPart,
        size.HighPart,
        &sOverlapped
    )) return true; 
     
    dbg_printf("failed to LockFileEx %d : %s\n", GetLastError(), GetLastErrorAsString().c_str());
    return false;
}

bool NxHandle::ejectVolume()
{
    DWORD dwBytesReturned;

    return DeviceIoControl(m_h,
        IOCTL_STORAGE_EJECT_MEDIA,
        NULL, 0,
        NULL, 0,
        &dwBytesReturned,
        NULL);
}

bool NxHandle::getVolumeName(WCHAR *pVolumeName, u32 start_sector)
{
    std::wstring drive(parent->m_path);
    std::transform(drive.begin(), drive.end(), drive.begin(), ::toupper);
    std::size_t pos = drive.find(L"PHYSICALDRIVE");
    if (pos == std::string::npos)
        return false;

    int driveNumber = stoi(drive.substr(pos + 13, 2));
    dbg_printf("Drive number is %d\n", driveNumber);

    HANDLE handle = INVALID_HANDLE_VALUE;
    WCHAR  VolumeName[MAX_PATH] = L"";
    size_t Index = 0;
    BOOL   Success = FALSE;

    // Get handle to first volume
    handle = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));

    if (handle == INVALID_HANDLE_VALUE)
        return false;

    for (;;)
    {
        Index = wcslen(VolumeName) - 1;

        if (VolumeName[0] != L'\\' || VolumeName[1] != L'\\' || VolumeName[2] != L'?'  || 
            VolumeName[3] != L'\\' || VolumeName[Index] != L'\\')
        {
            dbg_printf("FindFirstVolumeW/FindNextVolumeW returned a bad path: %s\n", VolumeName);
            break;
        }

        VolumeName[Index] = L'\0'; //remove trailing backslash
        //dbg_wprintf(L"Volume name: %s\n", VolumeName);

        HANDLE hHandle = CreateFile(VolumeName
            , GENERIC_READ | GENERIC_WRITE
            , FILE_SHARE_WRITE | FILE_SHARE_READ
            , NULL
            , OPEN_EXISTING
            , FILE_ATTRIBUTE_NORMAL
            , NULL);

        DWORD dwBytesReturned = 0;
        VOLUME_DISK_EXTENTS volumeDiskExtents;

        BOOL bResult = DeviceIoControl(
            hHandle,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            NULL,
            0,
            &volumeDiskExtents,
            sizeof(volumeDiskExtents),
            &dwBytesReturned,
            NULL);
        CloseHandle(hHandle);

        if (!bResult)
            break;

        for (DWORD n = 0; n < volumeDiskExtents.NumberOfDiskExtents; ++n)
        {
            PDISK_EXTENT pDiskExtent = &volumeDiskExtents.Extents[n];
            dbg_printf("Disk number: %d\n", pDiskExtent->DiskNumber);
            dbg_printf("DBR start sector: %I64d\n", pDiskExtent->StartingOffset.QuadPart / 512);

            // If volume found 
            if (pDiskExtent->DiskNumber == driveNumber && pDiskExtent->StartingOffset.QuadPart / 512 == (u64)start_sector)
            {
                //wcscpy(pVolumeName, VolumeName);
                memcpy(pVolumeName, VolumeName, MAX_PATH);
                FindVolumeClose(handle);
                return true;
            }
        }

        // Get handle to next volume
        if (!FindNextVolumeW(handle, VolumeName, ARRAYSIZE(VolumeName)))
            break;
    }

    FindVolumeClose(handle);
    return false;
}

