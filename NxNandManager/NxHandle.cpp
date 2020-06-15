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
    std::string s_path(path);
    m_chunksize = chunksize;
    m_path = std::wstring(s_path.begin(), s_path.end());
    if (m_chunksize)
    {        
        splitFileName_t fna = getSplitFileNameAttributes(convertCharArrayToLPWSTR(path));
        if (!fna.f_type)
            m_path.append(L".00");

        m_firstPart_path = m_path;
    }
    createHandle(GENERIC_WRITE);
}

void NxHandle::createHandle(int io_mode)
{
    m_h = CreateFileW(m_path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (m_h != INVALID_HANDLE_VALUE)
    {
        // Get drive geometry        
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
    if (!createFile((wchar_t*)m_path.c_str(), io_mode))
        return;

    // Get size for file
    LARGE_INTEGER Lsize;
    if (!b_isDrive && GetFileSizeEx(m_h, &Lsize))
    {
        m_size = Lsize.QuadPart;
        m_totalSize = m_size;
        exists = m_size ? true : false;
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
    //clearHandle();
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
    if(nullptr == parent)
    {
        m_off_start = 0;
        m_off_end = m_size;
        m_off_max = m_size;
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
            m_off_end = m_size;
            m_off_max = m_size;
            exists = m_size ? true : false;
        }
        return;
    }

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
        if (!getNextSplitFile(path, path))
            break;

    } while (file_exists(path.c_str()));

    clearHandle();

    // Get handle for original file
    createFile((wchar_t*)m_path.c_str(), GENERIC_READ);

    // If more than one file found
    if (m_splitFileCount > 1)
    {
        // New handle size
        m_size = s_size;
        b_isSplitted = true;
        initHandle();
        return true;
    }
    else return false;
}

bool NxHandle::createFile(wchar_t *path, int io_mode)
{
    if (io_mode != GENERIC_READ && io_mode != GENERIC_WRITE)
        return false;

    DWORD lpdwFlags[100];
    if (GetHandleInformation(m_h, lpdwFlags))
    {
        CloseHandle(m_h);
    }

    if (io_mode == GENERIC_READ)
        m_h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    else
        m_h = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    
    if (m_h == INVALID_HANDLE_VALUE)
    {
        dbg_wprintf(L"NxHandle::createFile() for %s ERROR %s\n", path, GetLastErrorAsString().c_str());
        CloseHandle(m_h);
        return false;
    }    
    
    //if (b_isDrive && !dismountVolume())
    //    dbg_printf("failed to dismount volume\n");

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
            dbg_printf("NxHandle::read() - Switch to next split file at offset %s\n", n2hexstr(u64(lp_CurrentPointer.QuadPart - m_off_start), 10).c_str());
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

    // Resize buffer length before calling ReadFile (otherwise hekate's mass storage tool will disconnect)
    if (lp_CurrentPointer.QuadPart + (u64)length > m_off_end + 1)
    {
        length = m_off_end + 1 - lp_CurrentPointer.QuadPart;
    }

    if (!ReadFile(m_h, buffer, length, &bytesRead, NULL)) {
        dbg_printf("NxHandle::read ReadFile error %s\n", GetLastErrorAsString().c_str());
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
        {
            //dbg_printf("ENCRYPTED BUFFER :\n%s\n", hexStr((unsigned char*)buffer, length).c_str());
            nxCrypto->decrypt((unsigned char*)buffer, m_cur_block);
//            /dbg_printf("DECRYPTED BUFFER :\n%s\n", hexStr((unsigned char*)buffer, length).c_str());
        }
    }

    //dbg_printf("NxHandle::read done, %I32d bytes\n", bytesRead);

    lp_CurrentPointer.QuadPart += bytesRead;

    if (nullptr != br)
    {
        // Resize buffer length if eof is reached
        if (lp_CurrentPointer.QuadPart > m_off_end + 1)
        {
            u32 bytes = lp_CurrentPointer.QuadPart - m_off_end - 1;
            dbg_printf("Resize buffer original %I32d b, new %I32d b (cur_off = %s, m_off_end = %s)\n", bytesRead, bytes, 
                n2hexstr(lp_CurrentPointer.QuadPart, 10).c_str(), n2hexstr(m_off_end, 10).c_str());
            *br = bytesRead - bytes;
        }
        else *br = bytesRead;
    }

    // Hash buffer
    if (m_crypto == MD5_HASH || m_isHashLocked)
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
    if (m_off_max && lp_CurrentPointer.QuadPart > m_off_max) {
        return false;
    }


    // Encrypt buffer
    if (m_crypto == ENCRYPT && nxCrypto != nullptr && length == CLUSTER_SIZE)
    {
        m_cur_block = (lp_CurrentPointer.QuadPart - m_off_start) / CLUSTER_SIZE;
        nxCrypto->encrypt((unsigned char*)buffer, m_cur_block);

    }

    // Resize buffer if eof
    if (m_off_end && lp_CurrentPointer.QuadPart + length > m_off_end)
    {
        u32 bytes = lp_CurrentPointer.QuadPart + length - m_off_end - 1;
        length -= bytes;
        dbg_printf("NxHandle::write - buffer resized to %I32d bytes\n", length);
    }

    // Resize buffer if chunksize limit reached
    u32 sub_bytes = 0;
    void *sub_buffer_ptr = nullptr;
    if (m_chunksize && lp_CurrentPointer.QuadPart + length > m_chunksize )
    {
        u32 new_length = m_chunksize - lp_CurrentPointer.QuadPart;
        sub_bytes = length - new_length;
        length = new_length;
        sub_buffer_ptr = (char*)buffer + length;
    }

    if (!WriteFile(m_h, buffer, length, &bytesWrite, nullptr))
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

    // Switch to next out file
    if (m_chunksize && lp_CurrentPointer.QuadPart >= m_chunksize )
    {
        // Set path for new file
        if (!getNextSplitFile(m_path))
            return false;

        // Clear current handle then create new file
        clearHandle();
        if(!createFile((wchar_t*)m_path.c_str(), GENERIC_WRITE))
            return false;

        // Init cur pointer
        lp_CurrentPointer.QuadPart = 0;
    }

    // Write remaining bytes from buffer
    if (sub_bytes)
    {
        if (!WriteFile(m_h, sub_buffer_ptr, sub_bytes, &bytesWrite, nullptr))
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
        *bw += bytesWrite;
    }

    return true;
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

bool NxHandle::hash(u64* bytesCount)
{
    if (!*bytesCount)
    {
        initHandle(MD5_HASH);
        memset(m_md5_buffer, 0, DEFAULT_BUFF_SIZE);
    }

    DWORD bytesRead = 0;
    bool success = false;
    if (read(m_md5_buffer, &bytesRead, DEFAULT_BUFF_SIZE))
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
