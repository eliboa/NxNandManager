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

#include "NxPartition.h"

// Constructor
NxPartition::NxPartition(NxStorage *p, const char* p_name, u32 lba_start, u32 lba_end, u64 attrs)
{
    dbg_printf("NxPartition::NxPartition(parent, %s, lba_start=%I32d, lba_end=%I32d)\n", p_name, lba_start, lba_end);
    parent = p;
    nxHandle = parent->nxHandle;
    
    // Get partition name length
    int name_len = strlen(p_name) + 1;

    // Init member variables
    for (int i = 0; i < 37 || i < strlen(p_name) - 1; i++)
        m_name[i] = p_name[i];
    m_lba_start = lba_start;
    m_lba_end = lba_end;
    m_attrs = attrs;
    m_isEncrypted = false;
    m_bad_crypto = false;
    m_isValidPartition = false;
    m_type = UNKNOWN;
    nxCrypto = nullptr;

    for( NxPart part : NxPartArr )
    {
        std::string sm_name(m_name);
        std::transform(sm_name.begin(), sm_name.end(), sm_name.begin(), ::toupper);
        std::string sp_name = part.name;
        std::transform(sp_name.begin(), sp_name.end(), sp_name.begin(), ::toupper);

        if(!sm_name.compare(sp_name))
        {
            m_isValidPartition = true;
            m_isEncrypted = part.isEncrypted;
            m_type = part.type;            
            nxPart_info = part;

            // Look for decrypted partition
            if (parent != nullptr && m_isEncrypted)
            {
                u8 buff[NX_BLOCKSIZE];
                u64 off = lba_start * NX_BLOCKSIZE + part.magic_off;                
                int remain = off % NX_BLOCKSIZE; // Block align
                if (parent->nxHandle->read(off - remain, buff, nullptr, NX_BLOCKSIZE))
                {
                    if (!memcmp(&buff[remain], part.magic, strlen(part.magic)))
                        m_isEncrypted = false;
                }
            }
        }
    }

    if (parent != nullptr)
    {
        parent->partitions.push_back(this);        
    }
}

NxPartition::~NxPartition()
{
    if (nullptr != nxCrypto)
        delete nxCrypto;
}

bool NxPartition::setCrypto(char* crypto, char* tweak)
{
    if (!nxPart_info.isEncrypted)
        return false;

    if (nullptr != nxCrypto)
        delete nxCrypto;

    //dbg_printf("NxPartition::setCrypto() for %s\n", partitionName().c_str());
    
    m_bad_crypto = false;
    nxCrypto = new NxCrypto(crypto, tweak);   
    nxHandle->initHandle(isEncryptedPartition() ? DECRYPT : NO_CRYPTO, this);

    // Validate first cluster
    unsigned char first_cluster[CLUSTER_SIZE];
    if (nxPart_info.magic != nullptr && nxHandle->read(first_cluster, nullptr, CLUSTER_SIZE))
    {
        // Do magic
        if (memcmp(&first_cluster[nxPart_info.magic_off], nxPart_info.magic, strlen(nxPart_info.magic)))
            m_bad_crypto = true;
        else if(is_in(m_type, {USER, SYSTEM}))
        {
            // Save boot sector
            fat32::read_boot_sector(first_cluster, &m_fs);
            /*
            fat32::boot_sector *bs = (fat32::boot_sector *)(first_cluster);
            dbg_printf("PARTITION %s - 1 - bs->sectors_count = %I32d, bs->fat_size = %I32d, bs->rootdir_cluster_num = %I32d, bs->bs_first_copy_sector = %d\n", partitionName().c_str(),
                       bs->sectors_count, bs->fat_size, bs->rootdir_cluster_num, bs->bs_first_copy_sector);

            bs = (fat32::boot_sector *)(first_cluster + 0xC00);
            dbg_printf("PARTITION %s - 2 - bs->sectors_count = %I32d, bs->fat_size = %I32d, bs->rootdir_cluster_num = %I32d\n", partitionName().c_str(),
                       bs->sectors_count, bs->fat_size, bs->rootdir_cluster_num);

            u32 fat_size = fat32::getFatSize(lbaEnd() - lbaStart() + 1);
            u64 root_addr = (m_fs.reserved_sector_count * m_fs.bytes_per_sector) + (m_fs.num_fats * m_fs.fat_size * m_fs.bytes_per_sector);
            dbg_printf("PARTITION %s (size in sectors = %I32d, root_addr = %I64d, fat_size = %I32d, real_fat_size = %I32d, reserved = %I32d)\n",
                       partitionName().c_str(), lbaEnd() - lbaStart() + 1, root_addr, fat_size, m_fs.fat_size, m_fs.reserved_sector_count);
            */
            m_fsSet = true;
            freeSpace = fat32_getFreeSpace(&freeSpaceRaw, &availableTotSpace);
        }
    }

    //dbg_printf("NxPartition::setCrypto() ends %s %s\n", partitionName().c_str(), m_bad_crypto ? "BAD CRYPTO" : "GOOD CRYPTO");
    return m_bad_crypto ? false : true;
}

std::string NxPartition::partitionName()
{
    return std::string(m_name);
}

u32 NxPartition::lbaStart()
{
    return m_lba_start;
}

u32 NxPartition::lbaEnd()
{
    return m_lba_end;
}

u64 NxPartition::size() 
{
    if(m_lba_end - m_lba_start > 0)
        return (u64)(m_lba_end - m_lba_start + 1) * NX_BLOCKSIZE;
    else 
        return 0;
}

bool NxPartition::isValidPartition()
{
    return m_isValidPartition;
}

bool NxPartition::isEncryptedPartition() 
{    
    return m_isEncrypted;
}

int NxPartition::dump(NxHandle *outHandle, part_params_t par, void(*updateProgress)(ProgressInfo))
{
    // Crypto check
    if (par.crypto_mode == DECRYPT && !isEncryptedPartition())
        return ERR_CRYPTO_DECRYPTED_YET;
    if (par.crypto_mode == ENCRYPT && isEncryptedPartition())
        return ERR_CRYPTO_ENCRYPTED_YET;

    if (!(par.passThroughZero && is_in(type(), {SYSTEM, USER})))
        par.passThroughZero = false;

    if (is_in(par.crypto_mode, {ENCRYPT, DECRYPT}))
    {
        if (!parent->isCryptoSet())
            return ERR_CRYPTO_KEY_MISSING;

        if (badCrypto())
            return ERR_BAD_CRYPTO;
    }

    if (outHandle->exists)
        return ERR_FILE_ALREADY_EXISTS;

    ProgressInfo pi;
    bool sendProgress = nullptr != updateProgress ? true : false;
    std::wstring fwpath = outHandle->getPath();

    // Init input handle
    nxHandle->initHandle(par.crypto_mode, this);

    // Set new buffer
    size_t buff_size = par.passThroughZero ? CLUSTER_SIZE : (size_t)nxHandle->getDefaultBuffSize();
    BYTE* buffer = new BYTE[buff_size];
    memset(buffer, 0, buff_size);
    DWORD bytesRead = 0, bytesWrite = 0;

    // Error lambda func
    auto error = [&] (int rc)
    {
        if (nxHandle->isDrive())
            nxHandle->unlockVolume();

        parent->stopWork = false;
        delete [] buffer;
        return rc;
    };

    // Init ProgressInfo
    pi.bytesCount = 0;
    pi.bytesTotal = size();
    if (sendProgress)
    {
        pi.mode = COPY;
        sprintf(pi.storage_name, partitionName().c_str());
        pi.begin_time = std::chrono::system_clock::now();        
        if (par.isSubParam) pi.isSubProgressInfo = true;
        updateProgress(pi);
    }    

    // Copy
    u32 num_cluster = 0, cl_count = 0;
    bool isEmptyCluster = false;
    while (nxHandle->read(buffer, &bytesRead, (DWORD)buff_size))
    {
        if (parent->stopWork)
            return error(userAbort());

        if (par.passThroughZero)
        {
            if (!cl_count)
                isEmptyCluster = fat32_isFreeCluster(num_cluster, &cl_count);
            else
                cl_count--;
            if(isEmptyCluster)
                memset(buffer, 0, buff_size);
        }

        if (!outHandle->write(buffer, &bytesWrite, bytesRead))
            break;

        pi.bytesCount += bytesWrite;

        if (buff_size == CLUSTER_SIZE)
            num_cluster++;

        if (sendProgress)
            updateProgress(pi);
    }

    // Check completeness
    if (pi.bytesCount != pi.bytesTotal)
        return error(ERR_WHILE_COPY);

    // Compute & compare md5 hashes
    if (par.crypto_mode == MD5_HASH && !par.passThroughZero)
    {
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
            if(parent->stopWork)
                error(userAbort());

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

    delete[] buffer;
    return SUCCESS;
}

int NxPartition::restore(NxStorage* input, part_params_t par, void(*updateProgress)(ProgressInfo))
{
    // Get handle to input NxPartition
    NxPartition *input_part = input->getNxPartition(m_type);

    // Controls
    if (nullptr == input_part)
        return ERR_IN_PART_NOT_FOUND;

    if (par.crypto_mode == DECRYPT && !input_part->isEncryptedPartition())
        return ERR_CRYPTO_DECRYPTED_YET;

    if (par.crypto_mode == ENCRYPT && input_part->isEncryptedPartition())
        return ERR_CRYPTO_ENCRYPTED_YET;

    if (not_in(par.crypto_mode, { ENCRYPT, DECRYPT }) && isEncryptedPartition() && !input_part->isEncryptedPartition())
    {
        if (input->isCryptoSet() && input_part->crypto() != nullptr)
            par.crypto_mode = ENCRYPT;
        else return ERR_RESTORE_CRYPTO_MISSING;
    }
    if (not_in(par.crypto_mode, { ENCRYPT, DECRYPT }) && !isEncryptedPartition() && input_part->isEncryptedPartition())
    {
        if (input->isCryptoSet() && input_part->crypto() != nullptr)
            par.crypto_mode = DECRYPT;
        else return ERR_RESTORE_CRYPTO_MISSIN2;
    }
    if (input_part->size() > size())
        return ERR_IO_MISMATCH;

    ProgressInfo pi;
    bool sendProgress = nullptr != updateProgress ? true : false;

    // Lock output volume
    if (parent->isDrive())
        nxHandle->lockVolume();

    // Lock input volume
    if (input->isDrive())
        input->nxHandle->lockVolume();

    // Init handles for both input & output
    input->nxHandle->initHandle(par.crypto_mode, input_part);
    this->nxHandle->initHandle(NO_CRYPTO, this);

    // Set new buffer
    int buff_size = input->nxHandle->getDefaultBuffSize();
    BYTE* buffer = new BYTE[buff_size];
    memset(buffer, 0, buff_size);
    DWORD bytesRead = 0, bytesWrite = 0;

    // Init progress info
    pi.bytesCount = 0;
    pi.bytesTotal = input_part->size();
    if(sendProgress)
    {
        pi.mode = RESTORE;
        sprintf(pi.storage_name, partitionName().c_str());
        pi.begin_time = std::chrono::system_clock::now();
        if (par.isSubParam) pi.isSubProgressInfo = true;
        updateProgress(pi);
    }

    while(input->nxHandle->read(buffer, &bytesRead, buff_size))
    {
        if(parent->stopWork) return userAbort();

        if (!this->nxHandle->write(buffer, &bytesWrite, bytesRead))
            break;

        pi.bytesCount += bytesWrite;
        if (sendProgress) updateProgress(pi);
    }

    // Clean & unlock volume
    delete[] buffer;
    if (parent->isDrive())
        nxHandle->unlockVolume();
    if (input->isDrive())
        input->nxHandle->unlockVolume();

    // Check completeness
    if (pi.bytesCount != pi.bytesTotal)
        return ERR_WHILE_COPY;

    return SUCCESS;
}

int NxPartition::formatPartition(void(*updateProgress)(ProgressInfo))
{
    if (not_in(m_type, { SYSTEM, USER }))
        return ERR_FORMAT_BAD_PART;

    if (isEncryptedPartition())
    {
        if (!parent->isCryptoSet())
            return ERR_CRYPTO_KEY_MISSING;

        if (badCrypto())
            return ERR_BAD_CRYPTO;
    }

    bool sendProgress = nullptr != updateProgress ? true : false;
    BYTE buffer[CLUSTER_SIZE];
    DWORD bytesCount = 0, bytesWrite = 0;
    u32 cur_cluster_num = 1;

    nxHandle->initHandle(isEncryptedPartition() ? DECRYPT : NO_CRYPTO, this);

    // Read reserved sectors
    if (!nxHandle->read(buffer, &bytesCount, CLUSTER_SIZE))
        return ERR_WHILE_COPY;

    fat32::boot_sector *bs = (fat32::boot_sector *)(buffer);
    u32 fat_size_in_cluster = bs->fat_size / 32;
    int num_fats = bs->num_fats;

    ProgressInfo pi;
    pi.mode = FORMAT;
    sprintf(pi.storage_name, partitionName().c_str());
    pi.begin_time = std::chrono::system_clock::now();
    pi.bytesTotal = num_fats * fat_size_in_cluster * CLUSTER_SIZE + CLUSTER_SIZE;
    if (sendProgress) updateProgress(pi);

    // For each FAT
    for (int x(0); x < num_fats; x++)
    {
        // For each cluster in FAT
        for (u32 i(0); i < fat_size_in_cluster; i++)
        {
            memset(buffer, 0, CLUSTER_SIZE);
            // Write first 3 FAT entries (each entry is 4 bytes long)
            if (!i)
            {
                u8 first_entries[12] = { 0xf8, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0x0f, 0xff, 0xff, 0xff, 0x0f };
                memcpy(buffer, first_entries, ARRAYSIZE(first_entries));
            }

            if (isEncryptedPartition())
                crypto()->encrypt(buffer, cur_cluster_num++);

            if (!nxHandle->write(buffer, &bytesWrite, CLUSTER_SIZE))
                return ERR_WHILE_COPY;

            pi.bytesCount += bytesWrite;
            if (sendProgress) updateProgress(pi);
        }
    }

    // Write empty cluster for root dir
    memset(buffer, 0, CLUSTER_SIZE);
    if (isEncryptedPartition())
        crypto()->encrypt(buffer, cur_cluster_num++);

    if (!nxHandle->write(buffer, &bytesWrite, CLUSTER_SIZE))
        return ERR_WHILE_COPY;

    pi.bytesCount += bytesWrite;

    // Check completeness
    if (pi.bytesCount != pi.bytesTotal)
        return ERR_WHILE_COPY;

    if (sendProgress) updateProgress(pi);

    return SUCCESS;
}


// Get fat32 entries for given path
// If path is a file, only one entry is pushed back to entries vector
// Returns false when directory or file does not exist
bool NxPartition::fat32_dir(std::vector<fat32::dir_entry> *entries, const char *path)
{
    entries->clear();
    
    if (not_in(m_type, { SAFE, SYSTEM, USER }))
        return false;

    if (m_isEncrypted && (badCrypto() || !parent->isCryptoSet()))
        return false;

    NxHandle *nxHandle = parent->nxHandle;
    nxHandle->initHandle(isEncryptedPartition() ? DECRYPT : NO_CRYPTO, this);
    BYTE buff[CLUSTER_SIZE];

    // Read first cluster
    if (!nxHandle->read(buff, nullptr, CLUSTER_SIZE))
        return false;
    
    // Get root address
    fat32::fs_attr fs;
    fat32::read_boot_sector(buff, &fs);
    u64 root_addr = (fs.num_fats * fs.fat_size * fs.bytes_per_sector) + (fs.reserved_sector_count * fs.bytes_per_sector);
    
    // Read root cluster
    if (!nxHandle->read(root_addr, buff, nullptr, CLUSTER_SIZE))
        return false;
    
    // Get root entries    
    fat32::parse_dir_table(buff, entries);

    // path param is root dir
    if (entries->size() > 0 && (nullptr == path || (path[0] == '/' && strlen(path) == 1)))
        return true;

    // Explore path, one directory (*dir) after each other, from root
    char *cdir = strdup(path), *dir;
    while ((dir = strtok(cdir, "/")) != nullptr)
    {
        cdir = nullptr;
        bool found = false;
        for (fat32::dir_entry dir_entry : *entries)
        {
            // current dir found in entries
            if (!strcmp(dir, dir_entry.filename.c_str()))
            {
                // path is a file
                if (!dir_entry.is_directory)
                {
                    dir_entry.data_offset = fs.bytes_per_sector * ((dir_entry.entry.first_cluster - 2) * fs.sectors_per_cluster) + (fs.num_fats * fs.fat_size * fs.bytes_per_sector) + (fs.reserved_sector_count * fs.bytes_per_sector);                    
                    entries->clear();
                    entries->push_back(dir_entry);
                    return true;
                }

                // Read cluster for directory
                u64 next_cluster_off = fs.bytes_per_sector * ((dir_entry.entry.first_cluster - 2) * fs.sectors_per_cluster) + root_addr;
                if (!nxHandle->read(next_cluster_off, buff, nullptr, CLUSTER_SIZE))
                    return false;

                // Get next (or last) fat entries
                fat32::parse_dir_table(buff, entries);
                found = true;
                break;
            }
        }
        if (!found)
            return false;
    }
    return true;
}

// Get free space from free clusters count in FAT
u64 NxPartition::fat32_getFreeSpace(u64* contiguous, u64* available)
{
    if (not_in(m_type, { SAFE, SYSTEM, USER }) || !m_fsSet)
        return 0;

    nxHandle->initHandle(isEncryptedPartition() ? DECRYPT : NO_CRYPTO, this);
    BYTE buff[CLUSTER_SIZE];

    u64 data_size = size() - (u64)(m_fs.reserved_sector_count + m_fs.fat_size * m_fs.num_fats) * m_fs.bytes_per_sector;
    u32 fat_entries_count = 2 + (u32)(data_size / CLUSTER_SIZE);
    u32 cluster_free_count = 0, cluster_count = 0, first_empty_cluster = 0;
    int cluster_num = m_fs.fat_size * m_fs.bytes_per_sector / CLUSTER_SIZE;
    u32 count = 0, count_max = fat_entries_count * 4;
    unsigned char free_cluster[4] = { 0x00,0x00,0x00,0x00 };

    nxHandle->setPointer(CLUSTER_SIZE);
    // Iterate cluster map
    for (int i(1); i <= cluster_num; i++)
    {
        if (!nxHandle->read(buff, nullptr, CLUSTER_SIZE))
            return 0;

        u32 in_count = 0;
        while (count < count_max)
        {
            if (count < 8)
            {
                count += 8;
                in_count += 8;
                continue;
            }
            cluster_count++;
            if (!memcmp(&buff[in_count], free_cluster, 4))
            {
                cluster_free_count++;
                if (!first_empty_cluster) first_empty_cluster = cluster_count;
            }
            else first_empty_cluster = 0;
            count += 4;
            in_count += 4;
            if (in_count >= CLUSTER_SIZE)
                break;
        }
    }
    u32 free_cluster_count = cluster_count - first_empty_cluster;
    if (nullptr != contiguous)
        *contiguous = (u64)free_cluster_count * CLUSTER_SIZE;
    if (nullptr != available)
        *available = (u64)cluster_count * CLUSTER_SIZE;

    return (u64)cluster_free_count * CLUSTER_SIZE;
}

// Returns true if cluster number is a FAT32 available entry in FAT
// Cluster 0 is first cluster in partition (boot sector)
bool NxPartition::fat32_isFreeCluster(u32 cluster_num, u32 *clus_count)
{
    if (nullptr != clus_count) *clus_count = 0; // Safe init
    if (not_in(m_type, { SAFE, SYSTEM, USER }) || !m_fsSet)
        return false;
    if (m_isEncrypted && (badCrypto() || !parent->isCryptoSet()))
        return false;

    u32 cl_size = m_fs.sectors_per_cluster * m_fs.bytes_per_sector; // Cluster size
    u64 fat_addr = m_fs.reserved_sector_count * m_fs.bytes_per_sector; // FAT start offset
    // Root cluster number = reserved size + fat size * number of fats / cluster size
    u32 root_cluster = ((m_fs.reserved_sector_count * m_fs.bytes_per_sector) + (m_fs.num_fats * m_fs.fat_size * m_fs.bytes_per_sector)) / cl_size;

    // Return if cluster number is before root or out of range
    if (cluster_num < root_cluster || cluster_num > size() / cl_size)
        return false;

    // Get cluster number (entry) in FAT (2 reserved entries)
    cluster_num = cluster_num - root_cluster + 2;
    // offset (cluster aligned) for desired FAT entry (4 bytes per entry)
    u64 offset = ((fat_addr + cluster_num * 4) / cl_size) * cl_size;
    // offset in buffer for FAT entry
    u32 off_inBuff = (fat_addr + cluster_num * 4) % cl_size;

    // Save current pointer & crypto mode
    u64 cur_pointer = nxHandle->getCurrentPointer();
    int save_mode = nxHandle->getCryptoMode();

    nxHandle->setCrypto(isEncryptedPartition() ? DECRYPT : NO_CRYPTO);
    unsigned char buff[CLUSTER_SIZE];

    // Read cluster
    bool result = nxHandle->read(offset, buff, nullptr, CLUSTER_SIZE);

    // Set pointer & crypto mode back
    nxHandle->setPointer(cur_pointer);
    nxHandle->setCrypto(save_mode);

    if (!result)
        return false;

    // If entry in cluster map is free
    unsigned char free_cluster[4] = { 0x00,0x00,0x00,0x00 };
    if (!memcmp(&buff[off_inBuff], &free_cluster[0], 4))
        result = true;
    else
        result = false;

    // Get number of same type clusters following desired one
    if (nullptr != clus_count)
    {
        off_inBuff += 4;
        cluster_num = 0;
        while(off_inBuff < CLUSTER_SIZE)
        {
            bool isFree = !memcmp(&buff[off_inBuff], &free_cluster[0], 4);
            if (isFree == result)
                *clus_count += 1;
            else
                break;
            off_inBuff += 4;
        }
    }

    return result;
}

void NxPartition::clearHandles()
{
    //p_ofstream.close();
}
