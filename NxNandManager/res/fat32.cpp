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

#include "fat32.h"

void fat32::read_boot_sector(BYTE *cluster, fs_attr *fat32_attr)
{
    memcpy(&fat32_attr->bytes_per_sector, &cluster[0xB], 2);
    memcpy(&fat32_attr->sectors_per_cluster, &cluster[0xD], 1);
    memcpy(&fat32_attr->reserved_sector_count, &cluster[0xE], 2);
    memcpy(&fat32_attr->num_fats, &cluster[0x10], 1);
    memcpy(&fat32_attr->fat_size, &cluster[0x24], 4);
    memcpy(&fat32_attr->info_sector, &cluster[0x30], 2);
    memcpy(&fat32_attr->label, &cluster[0x47], 11);
    memcpy(&fat32_attr->sectors_count, &cluster[0x20], 4);
}

void fat32::parse_dir_table(BYTE *cluster, std::vector<dir_entry> *entries)
{
    entries->clear();
    int buf_off = 0, lfn_length = 0;
    while (buf_off < CLUSTER_SIZE)
    {
        entry entry;
        memcpy(&entry, &cluster[buf_off], 32);

        if (entry.filename[0] == 0x00 || entry.reserved != 0x00)
            break;

        if (entry.attributes == 0x0F)
            lfn_length++;

        if ((entry.attributes == 0x10 && entry.filename[0] != 0x2E) || entry.attributes == 0x20 || entry.attributes == 0x30) 
        {
            // Add new dir entry
            dir_entry dir;
            dir.entry = entry;

            if (entry.attributes == 0x10)
                dir.is_directory = true;

            // Get filename 
            dir.filename = entry.filename;
            if (lfn_length > 0)
                dir.filename = get_long_filename(cluster, buf_off, lfn_length);

            entries->push_back(dir);

            if (entry.attributes != 0x0F)
                lfn_length = 0;
        }
        buf_off += 32;
    }
}

// Get FAT32 long filename
std::string fat32::get_long_filename(BYTE *buffer, int offset, int length)
{
    unsigned char filename[40];
    int x = 0;
    for (int j = 1; j <= length; j++)
    {
        int off = offset - (j * 0x20);
        LFN lfn;
        memcpy(&lfn, &buffer[off], 0x20);

        for (int k = 0; k < sizeof(lfn.fileName_Part1); k = k + 2) {
            memcpy(&filename[x], &lfn.fileName_Part1[k], 1);
            x++;
        }
        for (int k = 0; k < sizeof(lfn.fileName_Part2); k = k + 2) {
            memcpy(&filename[x], &lfn.fileName_Part2[k], 1);
            x++;
        }
        for (int k = 0; k < sizeof(lfn.fileName_Part3); k = k + 2) {
            memcpy(&filename[x], &lfn.fileName_Part3[k], 1);
            x++;
        }
    }
    return std::string(reinterpret_cast<const char*>(filename));
}

// Get size of FAT for a given FAT32 volume size (in sector)
u32 fat32::getFatSize(u32 vol_size_in_sectors)
{
    u32 fat_size = (vol_size_in_sectors + 1 - 32) / ((256 * 32 + 2) / 2);
    u32 fat_size_in_clusters = fat_size / 32;
    if (fat_size % 32) fat_size_in_clusters++;

    return fat_size_in_clusters * 32;
}
