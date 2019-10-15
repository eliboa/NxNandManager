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
        if(strcmp(part.name, m_name) == 0) 
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

    dbg_printf("NxPartition::setCrypto() for %s\n", partitionName().c_str());
    
    m_bad_crypto = false;
    nxCrypto = new NxCrypto(crypto, tweak);

    if (!isEncryptedPartition())
        return true;
    
    nxHandle->initHandle(DECRYPT, this);

    // Validate first cluster
    unsigned char first_cluster[CLUSTER_SIZE];
    if (nxPart_info.magic != nullptr && nxHandle->read(first_cluster, nullptr, CLUSTER_SIZE))
    {
        // Do magic
        if (memcmp(&first_cluster[nxPart_info.magic_off], nxPart_info.magic, strlen(nxPart_info.magic)))
            m_bad_crypto = true;
    }
    nxHandle->initHandle(NO_CRYPTO);

    return m_bad_crypto ? false : true;
}

std::string NxPartition::partitionName()
{
    return std::string(m_name).c_str();
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

int NxPartition::dumpToFile(const char *file, int crypto_mode, u64 *bytesCount)
{
    if (!*bytesCount)
    {        
        if (crypto_mode == DECRYPT && !m_isEncrypted)
            return ERR_CRYPTO_DECRYPTED_YET;

        if (crypto_mode == ENCRYPT && m_isEncrypted)
            return ERR_CRYPTO_ENCRYPTED_YET;

        std::ifstream infile(file);
        if (infile.good())
        {
            infile.close();
            return ERR_FILE_ALREADY_EXISTS;
        }

        p_ofstream = std::ofstream(file, std::ofstream::binary);
        nxHandle->initHandle(crypto_mode, this);
        m_buff_size = nxHandle->getDefaultBuffSize();
        m_buffer = new BYTE[m_buff_size];
        memset(m_buffer, 0, m_buff_size);
        dbg_printf("NxPartition::dumpToFile(file=%s, crypto_mode=%d, bytes_count=0)\n", file, crypto_mode);
    }    

    DWORD bytesRead = 0;
    if (!nxHandle->read(m_buffer, &bytesRead, m_buff_size))
    {
        p_ofstream.close();
        delete[] m_buffer;

        if (*bytesCount == size())
            return NO_MORE_BYTES_TO_COPY;

        return ERR_WHILE_COPY;
    }
    
    p_ofstream.write((char *)&m_buffer[0], bytesRead);
    *bytesCount += bytesRead;

    //dbg_printf("NxPartition::dumpToFile(%s, %d, %s)\n", file, crypto_mode, n2hexstr(*bytesCount, 8).c_str());
    return SUCCESS;
}

int NxPartition::restoreFromStorage(NxStorage* input, int crypto_mode, u64 *bytesCount)
{
    if (!*bytesCount)
    {        
        NxPartition *input_part = input->getNxPartition(m_type);

        // Controls
        if (nullptr == input_part)
            return ERR_IN_PART_NOT_FOUND;

        if (crypto_mode == DECRYPT && !input_part->isEncryptedPartition())
            return ERR_CRYPTO_DECRYPTED_YET;

        if (crypto_mode == ENCRYPT && input_part->isEncryptedPartition())
            return ERR_CRYPTO_ENCRYPTED_YET;

        if (not_in(crypto_mode, { ENCRYPT, DECRYPT }) && isEncryptedPartition() && !input_part->isEncryptedPartition())
            return ERR_RESTORE_CRYPTO_MISSING;

        if (not_in(crypto_mode, { ENCRYPT, DECRYPT }) && !isEncryptedPartition() && input_part->isEncryptedPartition())
            return ERR_RESTORE_CRYPTO_MISSIN2;

        if (input_part->size() > size())
            return ERR_IO_MISMATCH;

        // Init handles for both input & output
        input->nxHandle->initHandle(crypto_mode, input_part);
        this->nxHandle->initHandle(NO_CRYPTO, this);
        m_buff_size = input->nxHandle->getDefaultBuffSize();
        m_buffer = new BYTE[m_buff_size];
        memset(m_buffer, 0, m_buff_size);

        dbg_wprintf(L"NxPartition::restoreFromStorage(NxStorage=%s, crypto_mode=%d, bytes_count=0)\n", input->m_path, crypto_mode);
    }

    DWORD bytesRead = 0;
    if (!input->nxHandle->read(m_buffer, &bytesRead, m_buff_size))
    {
        delete[] m_buffer;
        return ERR_WHILE_COPY;
    }

    DWORD bytesWrite = 0;
    if (!this->nxHandle->write(m_buffer, &bytesWrite, bytesRead))
    {
        delete[] m_buffer;

        if(*bytesCount + bytesWrite != size())
            return ERR_WHILE_COPY;
    }

    *bytesCount += bytesWrite;

    if (*bytesCount == size())
        return NO_MORE_BYTES_TO_COPY;

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

    if (m_isEncrypted && (m_bad_crypto || nullptr == nxCrypto))
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