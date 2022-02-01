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

    m_path = std::wstring(parent->m_path);
    createHandle();
}

NxHandle::NxHandle(const char *path, u64 chunksize)
{
    // Convert char buff to wchar array
    wchar_t w_path[MAX_PATH];
    mbstowcs(w_path, path, MAX_PATH);
    constructor(wstring(w_path), chunksize);
}
NxHandle::NxHandle(const wstring &path, u64 chunksize)
{
    constructor(path, chunksize);
}

void NxHandle::constructor(const wstring &path, u64 chunksize)
{
    m_chunksize = chunksize;
    m_path = path;
    if (m_chunksize)
    {
        splitFileName_t fna = getSplitFileNameAttributes(m_path);
        if (!fna.f_type)
            m_path.append(L".00");

        m_firstPart_path = m_path;
    }
    createHandle(GENERIC_WRITE);
}

void NxHandle::createHandle(unsigned long io_mode)
{
    m_h = CreateFileW(m_path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (m_h != INVALID_HANDLE_VALUE)
    {
        // Get drive geometry        
        DWORD junk = 0, junk2;
        if (DeviceIoControl(m_h, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pdg, sizeof(pdg), &junk, (LPOVERLAPPED)NULL))
        {
            b_isDrive = true;
            m_totalSize = pdg.Cylinders.QuadPart * (ULONG)pdg.TracksPerCylinder * (ULONG)pdg.SectorsPerTrack * (ULONG)pdg.BytesPerSector;
            m_size = m_totalSize;
            exists = true;
        }
        m_isReadOnly = b_isDrive && !DeviceIoControl(m_h, IOCTL_DISK_IS_WRITABLE, NULL, 0, &junk, 0, &junk2, (LPOVERLAPPED)NULL);
    }
    CloseHandle(m_h);

    if (!b_isDrive && GetFileAttributesW(m_path.c_str()) & FILE_ATTRIBUTE_READONLY)
        m_isReadOnly = true;

    // Open file/disk
    if (!createFile((wchar_t*)m_path.c_str(), io_mode))
        return;

    // Get size for file
    LARGE_INTEGER Lsize;
    if (!b_isDrive)
    {
        auto res = GetFileSizeEx(m_h, &Lsize);
        if (res)
        {
            m_size = Lsize.QuadPart;
            m_totalSize = m_size;
            exists = m_size ? true : false;
        }
    }

    // Get available space on disk for file
    if (!b_isDrive)
    {
        std::size_t pos = m_path.find(base_nameW(m_path));
        std::wstring dir = m_path.substr(0, pos);
        if (dir.length() == 0)
        {
            wchar_t buffer[MAX_PATH];
            GetModuleFileNameW(nullptr, buffer, MAX_PATH);
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
    NxSplitFile *current = m_lastSplitFile, *next;
    while (nullptr != current)
    {
        next = current->next;
        DWORD lpdwFlags[100];
        if (GetHandleInformation(current->handle, lpdwFlags))
            CloseHandle(current->handle);

        delete current;
        current = next;
    }
    // Fix #36 (i'm sooooo dumb!)
    DWORD lpdwFlags[100];
    if (GetHandleInformation(m_h, lpdwFlags))
    {
        CloseHandle(m_h);
    }
}

void NxHandle::initHandle(int crypto_mode, NxPartition *partition)
{
    if(nullptr == parent)
    {
        m_off_start = 0;
        m_off_end = m_size - 1;
        m_off_max = m_size - 1;
        m_readAmount = 0;
        m_cur_block = 0;
        lp_CurrentPointer.QuadPart = 0;
        m_crypto = NO_CRYPTO;
        setPointer(0);

        if (crypto_mode == MD5_HASH && !m_isHashLocked)
        {
            m_crypto = crypto_mode;
            // Get handle to the crypto provider
            CryptAcquireContext(&h_WinCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
            // Create new hash
            CryptCreateHash(h_WinCryptProv, CALG_MD5, 0, 0, &m_md5_hash);
        }

        if(m_size)
            return;

        // Get size for file
        LARGE_INTEGER Lsize;
        if (!b_isDrive && GetFileSizeEx(m_h, &Lsize))
        {
            m_size = Lsize.QuadPart;
            m_totalSize = m_size;
            m_off_end = m_size - 1;
            m_off_max = m_size - 1;
            exists = m_size ? true : false;
        }
        return;
    }

    u64 tmp_size = nullptr == parent || !parent->size() || isSplitted() ? m_size : parent->size();
    m_off_start = (u64)parent->mmc_b0_lba_start * NX_BLOCKSIZE;
    m_off_end = m_off_start + tmp_size - 1;
    m_off_max = m_off_end;
    m_readAmount = 0;
    m_cur_block = 0;
    lp_CurrentPointer.QuadPart = 0;
    m_crypto = crypto_mode;

    if (nullptr != partition)
    {
         auto lbas = partition->lbaStart();
         m_off_start = ((u64)parent->mmc_b0_lba_start + (u64)partition->lbaStart()) * NX_BLOCKSIZE;
         m_off_end = m_off_start + (((u64)partition->lbaEnd() - (u64)partition->lbaStart() + 1) * NX_BLOCKSIZE) - 1;

        if(m_crypto == DECRYPT || m_crypto == ENCRYPT)
        {
            nxCrypto = partition->crypto();
        }
    }

    if (m_crypto == MD5_HASH && !m_isHashLocked)
    {
        // Get handle to the crypto provider
        CryptAcquireContext(&h_WinCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        // Create new hash
        CryptCreateHash(h_WinCryptProv, CALG_MD5, 0, 0, &m_md5_hash);
    }

    // Set pointer at start
    setPointer(0);
    

    dbg_printf("NxHandle::initHandle() set for %s, current pointer is %s - m_off_start = %s, m_off_end = %s, crypto_mode = %d\n",
        nullptr != partition ? partition->partitionName().c_str() : "NxStorage", n2hexstr(lp_CurrentPointer.QuadPart, 10).c_str(), 
        n2hexstr(m_off_start, 10).c_str(), n2hexstr(m_off_end, 10).c_str(), m_crypto);

}

splitFileName_t NxHandle::getSplitFileNameAttributes(std::wstring filepath)
{
    if (!filepath.length())
        filepath.append(m_path);

    wstring extension(get_extensionW((filepath)));
    wstring basename(remove_extensionW(filepath));

    if (extension.compare(basename) == 0)
        extension.erase();
    else if (!basename.compare(L"\\\\"))
    {
        basename = basename + extension;
        extension.erase();
    }

    // Look for an integer in path extension
    splitFileName_t fna;
    if (wcslen(extension.c_str()) > 1)
    {

        wstring number = extension.substr(1, wcslen(extension.c_str()));
        if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
        {
            // Extension is integer
            fna.f_number = std::stoi(number);
            fna.f_digits = wcslen(number.c_str());
            if (fna.f_digits <= 2) fna.f_type = 1;
        }
    }
    // Look for an integer in base name (2 digits max)
    if (fna.f_type == 0)
    {
        wstring number = basename.substr(wcslen(basename.c_str()) - 2, wcslen(basename.c_str()));
        if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
        {
            fna.f_number = std::stoi(number);
            fna.f_digits = 2;
            fna.f_type = 2;
        }
        else {
            number = basename.substr(wcslen(basename.c_str()) - 1, wcslen(basename.c_str()));
            if (std::string::npos != number.substr(0, 1).find_first_of(L"0123456789") && std::stoi(number) >= 0)
            {
                fna.f_number = std::stoi(number);
                fna.f_digits = 1;
                fna.f_type = 2;
            }
        }
    }

    return fna;
}

bool NxHandle::getNextSplitFile(std::wstring &next_file, std::wstring cur_filepath)
{
    if (!cur_filepath.length())
        cur_filepath.append(m_path);

    next_file.clear();

    splitFileName_t fna = getSplitFileNameAttributes(cur_filepath);

    if (!fna.f_type)
        return false;

    wstring extension(get_extensionW((cur_filepath)));
    wstring basename(remove_extensionW(cur_filepath));
    if (extension.compare(basename) == 0)
        extension.erase();
    else if (!basename.compare(L"\\\\"))
    {
        basename = basename + extension;
        extension.erase();
    }
    string mask("%0" + to_string(fna.f_digits) + "d");
    char new_number[10];
    sprintf_s(new_number, 10, mask.c_str(), ++fna.f_number);
    wstring wn_number = convertCharArrayToLPWSTR(new_number);
    if (fna.f_type == 1)
        next_file = basename + L"." + wn_number;
    else
        next_file = basename.substr(0, wcslen(basename.c_str()) - fna.f_digits) + wn_number + extension;

    return true;
}

bool NxHandle::getJoinFileName(std::wstring &join_name, std::wstring cur_filepath)
{
    splitFileName_t fna = getSplitFileNameAttributes(cur_filepath);

    if (!fna.f_type)
    {
        join_name = cur_filepath;
        return false;
    }
    join_name.clear();

    wstring extension(get_extensionW((cur_filepath)));
    wstring basename(remove_extensionW(cur_filepath));
    if (extension.compare(basename) == 0)
        extension.erase();
    else if (!basename.compare(L"\\\\"))
    {
        basename = basename + extension;
        extension.erase();
    }
    if (fna.f_type == 1)
        join_name = basename;
    else
        join_name = basename.substr(0, wcslen(basename.c_str()) - fna.f_digits + 1)+ extension;

    return true;
}

bool NxHandle::detectSplittedStorage()
{
    splitFileName_t fna = getSplitFileNameAttributes();

    // Not a valid split filename
    if (!fna.f_type)
        return false;

    int i = fna.f_number;
    m_splitFileCount = 0;
    LARGE_INTEGER Lsize;
    u64 s_size = 0;
    wstring path = m_path;

    clearHandle();

    // For each splitted file
    do {
        // Get handle
        HANDLE h;
        createFile(&path[0], GENERIC_READ, &h);

        if (!GetFileSizeEx(h, &Lsize))
            break;               

        // New NxSplitFile
        NxSplitFile *splitfile = reinterpret_cast<NxSplitFile *>(malloc(sizeof(NxSplitFile)));
        wcscpy(splitfile->file_path, path.c_str());
        splitfile->offset = s_size;
        splitfile->size = static_cast<u64>(Lsize.QuadPart);
        splitfile->handle = h;
        splitfile->next = m_lastSplitFile;
        m_lastSplitFile = splitfile;

        // First split file is current split file
        if (!m_splitFileCount)
            m_curSplitFile = splitfile;

        s_size += splitfile->size;

        ++m_splitFileCount;
        //clearHandle();

        // Format path to next file
        if (!getNextSplitFile(path, path))
            break;

    } while (file_exists(path.c_str()));

    // If more than one file found
    if (m_splitFileCount > 1)
    {
        // New handle size
        m_size = s_size;
        b_isSplitted = true;
        m_h = m_curSplitFile->handle;
        initHandle();
        return true;
    }
    else
    {
        // Get handle for original file
        createFile((wchar_t*)m_path.c_str(), GENERIC_READ);
        return false;
    }
}

bool NxHandle::createFile(wchar_t *path, unsigned long io_mode, HANDLE *h)
{
    if (io_mode != GENERIC_READ && io_mode != GENERIC_WRITE)
        return false;

    if (!h)
    {
        DWORD lpdwFlags[100];
        if (GetHandleInformation(m_h, lpdwFlags))
            CloseHandle(m_h);
    }

    HANDLE *handle = h ? h : &m_h;

    auto access = !b_isDrive && m_isReadOnly && io_mode != GENERIC_WRITE ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE;
    auto share = !b_isDrive && m_isReadOnly && io_mode != GENERIC_WRITE ? FILE_SHARE_READ : FILE_SHARE_READ | FILE_SHARE_WRITE;
    if (io_mode == GENERIC_READ)
        *handle = CreateFileW(path, access, share, nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);
    else
        *handle = CreateFileW(path, access, share, nullptr, CREATE_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    
    if (*handle == INVALID_HANDLE_VALUE)
    {
        dbg_wprintf(L"NxHandle::createFile() for %s ERROR %s\n", path, GetLastErrorAsString().c_str());
        CloseHandle(*handle);
        return false;
    }

    return true;
}

bool NxHandle::setPointer(u64 offset)
{
    if (b_isSplitted)
    {
        NxSplitFile *file = getSplitFile(m_off_start + offset);
        if (!file)
            return false;

        if (m_curSplitFile != file)
        {                        
            // Switch to next split file
            m_curSplitFile = file;
            m_h = file->handle;
        }

        u64 real_offset = m_off_start + offset - m_curSplitFile->offset;
        li_DistanceToMove.QuadPart = real_offset;
        if (SetFilePointerEx(m_h, li_DistanceToMove, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            return false;

        lp_CurrentPointer.QuadPart = m_curSplitFile->offset + real_offset;
    }
    else
    {
        li_DistanceToMove.QuadPart = m_off_start + offset;
        if (SetFilePointerEx(m_h, li_DistanceToMove, &lp_CurrentPointer, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
            return false;
    }

    //dbg_printf("NxHandle::setPointer(%s) real offset = %s\n", n2hexstr(offset, 12).c_str(), n2hexstr(m_off_start + offset, 12).c_str());
    return true;
}

void NxHandle::do_crypto(u8* buffer, u32 buff_size, u64 start_offset)
{
    if (!is_in(m_crypto, {ENCRYPT, DECRYPT}) || !nxCrypto)
        return;

    // Cluster block number
    size_t cur_block = start_offset / CLUSTER_SIZE;

    // Working buffer
    bool malloc_buff = buff_size < CLUSTER_SIZE || buff_size % CLUSTER_SIZE || start_offset / CLUSTER_SIZE;
    u8* t_buff;
    u32 t_buff_cl_size = buff_size / CLUSTER_SIZE;
    u64 t_buff_offset = 0;
    if (malloc_buff)
    {
        // Allocate working buffer (cluster aligned)
        u64 clus_off = (u64)cur_block * (u64)CLUSTER_SIZE; // Current cluster offset
        t_buff_offset = start_offset - clus_off; // Start offset for real data in tmp buff
        auto t_buff_size = t_buff_offset + buff_size; // Size of working buffer in bytes
        t_buff_cl_size = (u32)(t_buff_size / CLUSTER_SIZE); // Size of working buffer in clusters
        if (!t_buff_cl_size || t_buff_size % CLUSTER_SIZE)
            t_buff_cl_size++;
        t_buff = new u8[t_buff_cl_size*CLUSTER_SIZE];
        // Copy provided buffer in working buffer
        memcpy(&t_buff[t_buff_offset], buffer, buff_size);
    }
    else t_buff = buffer; // Use provided buffer if already cluster aligned


    //printf("Buffer before %s crypto :\n", m_crypto == ENCRYPT ? "ENCRYPT" : "DECRYPT");
    //hexStrPrint((u8*)buffer, 0x20);

    // Do crypto
    for (u32 i=0; i < t_buff_cl_size; i++)
        if (m_crypto == DECRYPT)
            nxCrypto->decrypt(&t_buff[i*CLUSTER_SIZE], cur_block++);
        else
            nxCrypto->encrypt(&t_buff[i*CLUSTER_SIZE], cur_block++);

    if (malloc_buff) {
        // Emplace back buffer data & free working buffer
        memcpy(buffer, &t_buff[t_buff_offset], buff_size);
        delete[] t_buff;
    }
    //printf("Buffer after %s crypto :\n", m_crypto == ENCRYPT ? "ENCRYPT" : "DECRYPT");
    //hexStrPrint((u8*)buffer, 0x20);
}

bool NxHandle::read(void *buffer, DWORD* br, DWORD length)
{
    if(br) *br = 0;

    auto init_pointer = virtual_currentPtr();

    // Set default buffer size 
    if (!length) 
        length = getDefaultBuffSize();

    // eof
    if (real_currentPtr() > m_off_end)
        return false;

    // Resize read length to prevent overflow
    if (real_currentPtr() + (u64)length > m_off_end + 1)
        length = m_off_end - real_currentPtr() + 1;

    // Read data to buffer
    DWORD bytesToReadTotal = length;
    DWORD bytesCount = 0;
    //std::lock_guard<std::mutex> lock(_read_write_mutex);
    while(bytesCount < bytesToReadTotal)
    {
        DWORD bytesToRead = bytesToReadTotal - bytesCount;
        if (b_isSplitted)
        {
            if (m_curSplitFile != getSplitFile(real_currentPtr()))
                setPointer(virtual_currentPtr()); // Switch to new splitted file

            // Split file overflow
            if (real_currentPtr() - m_curSplitFile->offset + bytesToRead > m_curSplitFile->size)
                bytesToRead = m_curSplitFile->size - real_currentPtr() - m_curSplitFile->offset;
        }
        DWORD bytesRead = 0;
        u8* u8_buff = reinterpret_cast<u8*>(buffer);
        if (!ReadFile(m_h, &u8_buff[bytesCount], bytesToRead, &bytesRead, nullptr))
        {
            dbg_printf("NxHandle::read ReadFile error %s\n", GetLastErrorAsString().c_str());
            return false;
        }
        if (!bytesRead)
            break;

        bytesCount += bytesRead;
        lp_CurrentPointer.QuadPart += bytesRead;
    }

    if (!bytesCount)
        return false;

    do_crypto((u8*)buffer, bytesCount, init_pointer);

    // Hash buffer
    if (m_crypto == MD5_HASH || m_isHashLocked)
        CryptHashData(m_md5_hash, (BYTE*)buffer, bytesCount, 0);

    if (br)
        *br = bytesCount;

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

bool NxHandle::write(void *in_buffer, DWORD* bw, DWORD length)
{    
    if (bw) *bw = 0;
    if (!length) length = getDefaultBuffSize();
    DWORD bytesWrite;

    // eof
    if (m_off_max && lp_CurrentPointer.QuadPart > m_off_max)
        return false;

    // Resize buffer if we'll reach eof
    if (m_off_end && lp_CurrentPointer.QuadPart + length > m_off_end)
        length -= lp_CurrentPointer.QuadPart + length - m_off_end - 1;

    bool encrypt = m_crypto == ENCRYPT;
    //std::lock_guard<std::mutex> lock(_read_write_mutex);
    void* buffer = encrypt ? malloc(length) : in_buffer;
    if (encrypt == ENCRYPT) {
        // We want to write encrypted data but we don't want input buffer to be encrypted !!!
        memcpy(buffer, in_buffer, length);
        do_crypto((u8*)buffer, length, virtual_currentPtr());
    }
    auto exit = [&](bool res) { if (encrypt) free(buffer); return res; };

    DWORD bytesToWriteTotal = length;
    DWORD bytesCount = 0;
    while(bytesCount < bytesToWriteTotal)
    {
        DWORD bytesToWrite = bytesToWriteTotal - bytesCount;
        if (b_isSplitted || m_chunksize)
        {
            // Switch to next out file
            if (m_chunksize && split_currentPtr() >= m_chunksize )
            {
                // Set path for new file
                if (!getNextSplitFile(m_path))
                    return exit(false);

                // Clear current handle then create new file
                clearHandle();
                if(!createFile((wchar_t*)m_path.c_str(), GENERIC_WRITE))
                    return exit(false);

                lp_CurrentPointer.QuadPart = 0;
            }

            if (m_curSplitFile != getSplitFile(real_currentPtr()))
                setPointer(virtual_currentPtr()); // Switch to new splitted file

            // Split file overflow ?
            if (m_curSplitFile && real_currentPtr() - m_curSplitFile->offset + bytesToWrite > m_curSplitFile->size)
                bytesToWrite = m_curSplitFile->size - real_currentPtr() - m_curSplitFile->offset;

            if (m_chunksize && split_currentPtr() + bytesToWrite > m_chunksize )
                bytesToWrite = (u32)m_chunksize - (u32)split_currentPtr();
        }

        u8* u8_buff = reinterpret_cast<u8*>(buffer);
        if (!WriteFile(m_h, &u8_buff[bytesCount], bytesToWrite, &bytesWrite, nullptr))
        {
            dbg_printf("NxHandle::wrtie WriteFile error %s\n", GetLastErrorAsString().c_str());
            return exit(false);
        }
        if (!bytesWrite)
            break;

        bytesCount += bytesWrite;
        lp_CurrentPointer.QuadPart += bytesWrite;
    }


    if (bw) *bw = bytesCount;
    return exit(true);
}

bool NxHandle::write(u64 offset, void *buffer, DWORD* bw, DWORD length)
{
    if ((offset % NX_BLOCKSIZE) && b_isDrive)
        return false;

    // Set new pointer if needed
    if (lp_CurrentPointer.QuadPart != m_off_start + offset)
    {
        if (!setPointer(offset))
            return false;
    }

    return write(buffer, bw, length);
}

bool NxHandle::write(u32 sector, void *buffer, DWORD* bw, DWORD length)
{
    u64 offset = (u64)sector * NX_BLOCKSIZE;
    return write(offset, buffer, bw, length);
}

bool NxHandle::hash(string storage_name, void(*updateProgress)(ProgressInfo))
{
    bool sendProgress = nullptr != updateProgress ? true : false;
    initHandle(MD5_HASH);
    DWORD bytesRead = 0;
    ProgressInfo pi;
    pi.mode = MD5_HASH;
    strcpy_s(pi.storage_name, storage_name.c_str());
    pi.begin_time = std::chrono::system_clock::now();
    pi.elapsed_seconds = 0;
    pi.bytesTotal = m_size;
    pi.bytesCount = 0;
    if (sendProgress) updateProgress(pi);
    u8* buff = new u8[DEFAULT_BUFF_SIZE];
    while (read(buff, &bytesRead, DEFAULT_BUFF_SIZE)) {
        pi.bytesCount += bytesRead;
        if (sendProgress) updateProgress(pi);
    }
    delete[] buff;

    return pi.bytesCount == pi.bytesTotal;
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

#define LOCK_TIMEOUT 1000 // 1 Seconds
#define LOCK_RETRIES 4

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

bool NxHandle::unlockVolume()
{
    DWORD dwBytesReturned;
    DWORD dwSleepAmount;
    int nTryCount;

    dwSleepAmount = LOCK_TIMEOUT / LOCK_RETRIES;

    // Do this in a loop until a timeout period has expired
    for (nTryCount = 0; nTryCount < LOCK_RETRIES; nTryCount++)
    {
        dbg_printf("try %d to unlock volume\n", nTryCount);
        if (DeviceIoControl(m_h,
            FSCTL_UNLOCK_VOLUME,
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

bool NxHandle::dismountAllVolumes()
{
    std::wstring drive(m_path);
    std::transform(drive.begin(), drive.end(), drive.begin(), ::toupper);
    std::size_t pos = drive.find(L"PHYSICALDRIVE");
    if (pos == std::string::npos)
        return false;

    int driveNumber = stoi(drive.substr(pos + 13, 2));
    std::vector<diskDescriptor> disks;
    GetDisks(&disks);
    for (diskDescriptor disk : disks)
    {
        if ((int)disk.diskNumber == driveNumber)
        {
            return DisMountAllVolumes(disk);
        }
    }
    return false;
}

bool NxHandle::getVolumeName(WCHAR *pVolumeName, u32 start_sector)
{
    std::wstring drive(m_path);
    std::transform(drive.begin(), drive.end(), drive.begin(), ::toupper);
    std::size_t pos = drive.find(L"PHYSICALDRIVE");
    if (pos == std::string::npos)
        return false;

    int driveNumber = stoi(drive.substr(pos + 13, 2));
    return GetVolumeName(driveNumber, (u64)start_sector * NX_BLOCKSIZE, pVolumeName);
}

void NxHandle::lockHash()
{
    CryptAcquireContext(&h_WinCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(h_WinCryptProv, CALG_MD5, 0, 0, &m_md5_hash);
    m_isHashLocked = true;
}


