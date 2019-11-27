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
#include "mbr.h"

void LBAtoCHS(DISK_GEOMETRY pdg, u32 lba, chs_t &chs)
{
    u32 c, temp, h, s;

    temp = (u32)pdg.TracksPerCylinder * pdg.SectorsPerTrack;
    c = lba / temp;
    temp = lba % temp;
    h = temp / pdg.SectorsPerTrack;
    s = temp % pdg.SectorsPerTrack + 1;

    chs.h = (unsigned char)h;
    chs.c = (unsigned char)c;
    chs.s = (unsigned char)s + (c >> 8 << 6);
}

void CHStoLBA(DISK_GEOMETRY pdg, u32 &lba, chs_t chs)
{
    u32 c, h, s;
    u32 hpc = pdg.TracksPerCylinder;
    u32 spt = pdg.SectorsPerTrack;
    c = chs_get_cylinder(&chs);
    h = chs_get_head(&chs);
    s = chs_get_sector(&chs);

    if (c > 1021)
        lba = 0;
    else if (s < 0)
        lba = 0;
    else
        lba = (c * hpc + h) * spt + s;
}