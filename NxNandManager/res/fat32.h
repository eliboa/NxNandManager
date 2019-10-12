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
 
#ifndef __fat32_h__
#define __fat32_h__

#include "utils.h"
#include <vector> 

using namespace std;

namespace fat32 {

    // FAT32 structures
    typedef struct fs_attr fs_attr;
    struct fs_attr {
        unsigned short bytes_per_sector;
        unsigned char sectors_per_cluster;
        unsigned char num_fats;
        unsigned short reserved_sector_count;
        unsigned int fat_size;
        unsigned short info_sector;
        char label[11];
    };

    typedef struct entry {
        char filename[11];
        unsigned char attributes;
        unsigned char reserved;
        unsigned char creation_ms;
        unsigned short creation_time;
        unsigned short creation_date;
        unsigned short last_access_time;
        unsigned short cluster_hi;
        unsigned short modified_time;
        unsigned short modified_date;
        unsigned short first_cluster;
        unsigned int file_size;
    } entry;

    typedef struct LFNentry {
        BYTE sequenceNo;
        BYTE fileName_Part1[10];
        BYTE fileattribute;
        BYTE reserved_1;
        BYTE checksum;
        BYTE fileName_Part2[12];
        BYTE FstClusLO[2];
        BYTE fileName_Part3[4];
    }LFN;

    typedef struct dir_entry dir_entry;
    struct dir_entry {
        std::string filename;
        bool is_directory = false;
        u64 data_offset;
        entry entry;
    };

    void read_boot_sector(BYTE *cluster, fs_attr *fat32_attr);
    void parse_dir_table(BYTE *cluster, std::vector<dir_entry> *entries);
    std::string get_long_filename(BYTE *buffer, int offset, int length);
}
#endif