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

#ifndef __mbr_h__
#define __mbr_h__

#include "types.h"
#include "utils.h"
#include <windows.h>
#include <winioctl.h>

struct chs_t {
    u8 h;
    u8 s;
    u8 c;
};

struct mbr_part_t {
    u8 status;
    chs_t first_sector;
    u8 type;
    chs_t last_sector;
    u8 lba_start[4];
    u8 lba_count[4];
};


struct mbr_t {
    u8 bootstrap_area[0x1BE];
    mbr_part_t parts[4];
    u8 signature[2];
};

void LBAtoCHS(DISK_GEOMETRY pdg, u32 lba, chs_t &chs);
void CHStoLBA(DISK_GEOMETRY pdg, u32 &lba, chs_t chs);

static int chs_get_cylinder(chs_t* chs)
{
    return chs->c + ((chs->s >> 6) << 8);
}
static int chs_get_head(chs_t* chs)
{
    return chs->h;
}
static int chs_get_sector(chs_t* chs)
{
    return (chs->s & 0x3f) - 1;
}

#endif