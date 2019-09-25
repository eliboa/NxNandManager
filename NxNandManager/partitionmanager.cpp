#include <stdio.h>
#include "partitionmanager.h"

/* ----------------------------------------------------------------------------- 
* Copyright (c) Elias Bachaalany <lallousz-x86@yahoo.com>
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
* ----------------------------------------------------------------------------- 

History
----------
07/07/2006 - First Public release

*/

// -----------------------------------------------------------------
// This function allows you to provide an external disk geometry.
// DiskGeometry is used to calculate from CHS to LBA and vise-versa
void CPartitionManager::SetDiskGeometry(DISK_GEOMETRY &dg)
{
  m_dg = dg;
}

// -----------------------------------------------------------------
// Converts from standard partition info to non std. partition info
void CPartitionManager::partition_t_to_partition_info(partition_t &pt, partition_info &pi)
{
  pi.is_active = (pt.boot_indicator == 0x80);
  
  CHStoCHS2(pt.start, pi.chs_start);
  CHStoCHS2(pt.end, pi.chs_end);

  //
  // Don't use CHS translation
  //pi.lba_end            = CHStoLBA(pt.end);
  //pi.lba_start          = CHStoLBA(pt.start);
  //

  pi.lba_start          = pt.sectors_before;
  pi.lba_end            = pi.lba_start + pt.number_of_sectors;

  pi.number_of_sectors  = pt.number_of_sectors;
  pi.sectors_before     = pt.sectors_before;
  pi.sys_id             = pt.system_indicator;
  pi.sys_name           = get_name_for_type(pi.sys_id);
}

// -----------------------------------------------------------------
// Clears the partitions chain and all the allocated memory which was
// in the form of a linked list
void CPartitionManager::ClearOldPartitionsInfo()
{
  partlist.clear();
}

// -----------------------------------------------------------------
// reads and builds the drive's partition table and all the chains
// if there are extended partitions this function will loop and retrieve them all
// in a form of a linked list
bool CPartitionManager::ReadPartitionTable(ULONGLONG sector)
{
  ClearOldPartitionsInfo();

  // Read master boot record from LBA 0
  mbr_t mbr;
  if (!ds.ReadSector(sector, &mbr))
    return false;

  // Not a valid MBR signature?
  if (mbr.signature != partition_signature)
    return false;

  // Partition info holder
  partition_info pi;

  for (size_t cnt=0;cnt<MAXPARTITIONS_COUNT;cnt++)
  {
    partition_t &part = mbr.parts[cnt];

    // No more partitions?
    if (IsEmptyPartition(&part))
      continue;

    // Convert from the standard partition information to our custom partition structure
    partition_t_to_partition_info(part, pi);

    // This is not a nested partition
    pi.parent_id = 0;

    if (!(IsExtendedPartitionId(pi.sys_id) && !m_bIncludeExtendedPartitionDefinitions))
      partlist.push_back(pi);


    // Is extended partition?
    if (IsExtendedPartitionId(pi.sys_id))
    {
      mbr_t mbr_e;

      bool bLoopMore = true;

      unsigned __int64 relativelba = 0;

      // We need this address since all extended partitions are relative to this address
      unsigned __int64 base_start = pi.lba_start;

      while (bLoopMore)
      {
        bLoopMore = false;

        // Read extended partition info
        ds.ReadSector(relativelba + base_start, &mbr_e);

        // not a valid partition?
        if (mbr_e.signature != partition_signature)
          break;

        for (int j=0;j<2;j++)
        {
          partition_t_to_partition_info(mbr_e.parts[j], pi);

          pi.lba_start = relativelba;

          if (IsExtendedPartitionId(mbr_e.parts[j].system_indicator))
          {
            relativelba = mbr_e.parts[j].sectors_before;
            pi.lba_start = 0;
            bLoopMore = true;

            if (m_bIncludeExtendedPartitionDefinitions == false)
              break;
          }
          else if (IsEmptyPartition(&mbr_e.parts[j]))
            break;

          pi.lba_start += base_start + mbr_e.parts[j].sectors_before;
          pi.lba_end    = pi.lba_start + mbr_e.parts[j].number_of_sectors;

          pi.parent_id = (int) cnt + 1;
          
          partlist.push_back(pi);
        }
      }
    }
  }
  return true;
}

// -----------------------------------------------------------------
// Checks whether the given system_id or partition id is an extended partition
bool CPartitionManager::IsExtendedPartitionId(unsigned char sys_id)
{
  return (sys_id == extended_partition_id) || 
         (sys_id == extended_ex_partition);
}

// -----------------------------------------------------------------
// Closes the physical disk and prevents further access w/o re-opening again
void CPartitionManager::Close()
{
  ds.Close();
}

// -----------------------------------------------------------------
// dtor - destroys previously allocated memory items
//
CPartitionManager::~CPartitionManager()
{
  ClearOldPartitionsInfo();
}

// -----------------------------------------------------------------
// ctor - simply initializes some member variables
//
CPartitionManager::CPartitionManager()
{
  memset(&m_dg, 0, sizeof(m_dg));
}

// -----------------------------------------------------------------
// Converts from a given LBA to CHS
//
void CPartitionManager::CHStoCHS2(chs_t &chs, chs2_t &chs2)
{
  /*
  Refer to INT13/AH=08

  Sector = bits 0-5, bit 6-7 = high part of Cyl
  Cyl    = 0-7 Low bits of Cyl

  Combine Bits 6-7 of Sector with 0-7 of Cyl to get full Cyl value of 8+2 bits
  */
  unsigned short chs_c = ((chs.s >> 6) << 8) | chs.c;
  unsigned char  chs_s = chs.s & 0x3F;

  chs2.c = chs_c;
  chs2.s = chs_s;
  chs2.h = chs.h;
}

/*
// -----------------------------------------------------------------
// Converts from a given LBA to CHS
//
__int64 CPartitionManager::CHStoLBA(chs_t &chs, partition_t *part)
{
  // Refer to INT13/AH=08

  // Sector = bits 0-5, bit 6-7 = high part of Cyl
  // Cyl    = 0-7 Low bits of Cyl

  // Combine Bits 6-7 of Sector with 0-7 of Cyl to get full Cyl value of 8+2 bits
  unsigned short chs_c = ((chs.s >> 6) << 8) | chs.c;
  unsigned char  chs_s = chs.s & 0x3F;

  // This formula won't compute a value bigger than 8GB
  // Given these max values:
  // chs_c = 1023
  // TracksPerCylinder = 255
  // chs_h = 255
  // chs_s = 63
  // SectorsPerTrack = 63
  return (__int64) (
                    (
                      ( (__int64) chs_c * (__int64) m_dg.TracksPerCylinder + (__int64) chs.h ) 
                      * (__int64) m_dg.SectorsPerTrack
                     ) + 
                     (__int64) chs_s - 1
                   );
}
*/

// -----------------------------------------------------------------
// Converts from a given LBA to CHS
//
void CPartitionManager::LBAtoCHS(DWORD lba, chs_t &chs)
{
  // ;;! untested
  DWORD c, temp, h, s;

  temp = (DWORD) m_dg.TracksPerCylinder * m_dg.SectorsPerTrack;
  c    = lba / temp;
  temp = lba % temp;
  h    = temp / m_dg.SectorsPerTrack;
  s    = temp % m_dg.SectorsPerTrack + 1;

  chs.h = (unsigned char) h;
  chs.c = (unsigned char) c;
  chs.s = (unsigned char) s;
}

// -----------------------------------------------------------------
// Opens a given physical drive and retrieves its geometry
bool CPartitionManager::Open(DWORD driveNo)
{
  if (!ds.OpenPhysicalDrive(driveNo))
    return false;

  if (!ds.GetDriveGeometry(m_dg))
  {
    ds.Close();
    return false;
  }

  return true;
}

//---------------------------------------------------------------------------
bool CPartitionManager::ReadPartitionTable(DWORD driveNo, ULONGLONG sector)
{
  bool b = Open(driveNo);
  if (b)
  {
    b = ReadPartitionTable(sector);
    Close();
  }
  return b;
}

//---------------------------------------------------------------------------
/*
 * DOS partition types
 *
 * Taken from fdisk/i386_sys_types.c and fdisk/common.h of
 * util-linux 2.11n (as packaged by Debian), Feb 08, 2003.
 *
 * Part of the info is also taken from PartInfo tool from PartitionMagic 8
*/
const system_identifier_t system_identifiers[] =
{
  {0x00, "Empty"},
  {0x01, "FAT12"},
  {0x02, "XENIX root"},
  {0x03, "XENIX usr"},
  {0x04, "FAT16 <32MB"},
  {0x05, "Extended"},
  {0x06, "FAT16B (>= 32 MB)"},
  {0x07, "Installable File System (NTFS, HPFS)"},
  {0x08, "AIX"},
  {0x09, "AIX bootable"},
  {0x0A, "OS/2 Boot Manager"},
  {0x0B, "Win95 FAT32"},
  {0x0C, "Win95 FAT32 (LBA)"},
  {0x0E, "Win95 FAT16 (LBA)"},
  {0x0F, "Win95 Extended (LBA)"},
  {0x10, "OPUS"},
  {0x11, "Hidden FAT12"},
  {0x12, "Compaq diagnostics"},
  {0x14, "Hidden FAT16 <32MB"},
  {0x16, "Hidden FAT16"},
  {0x17, "Hidden IFS (HPFS/NTFS)"},
  {0x18, "AST SmartSleep"},
  {0x1B, "Hidden Win95 FAT32"},
  {0x1C, "Hidden Win95 FAT32 (LBA)"},
  {0x1E, "Hidden Win95 FAT16 (LBA)"},
  {0x24, "NEC DOS"},
  {0x2C, "WildFile/Adaptec GOBack"},
  {0x39, "Plan 9"},
  {0x3C, "PowerQuest Recoverable Partition"},
  {0x40, "Venix 80286"},
  {0x41, "PPC PReP Boot"},
  {0x42, "Veritas Logical Disk Manager"},
  {0x4d, "QNX4.x"},
  {0x4e, "QNX4.x 2nd part"},
  {0x4f, "QNX4.x 3rd part"},
  {0x50, "OnTrack DM"},
  {0x51, "OnTrack DM6 Aux1"},
  {0x52, "CP/M"},
  {0x53, "OnTrack DM6 Aux3"},
  {0x54, "OnTrackDM6"},
  {0x55, "EZ-Drive"},
  {0x56, "Golden Bow"},
  {0x5c, "Priam Edisk"},
  {0x61, "SpeedStor"},
  {0x63, "GNU HURD or SysV"},
  {0x64, "Novell Netware 286"},
  {0x65, "Novell Netware (3.11 and 4.1)"},
  {0x66, "Novell Netware 386"},
  {0x70, "DiskSecure Multi-Boot"},
  {0x75, "PC/IX"},
  {0x78, "XOSL"},
  {0x80, "Old Minix"},
  {0x81, "Linux/Minix v1.4b+"},
  {0x82, "Linux swap / Solaris"},
  {0x83, "Linux native file system (Ext2/3)"},
  {0x84, "OS/2 hiding type 04h partition"},
  {0x85, "Linux extended"},
  {0x86, "NT FAT volume set"},
  {0x87, "NT IFS volume set"},
  {0x8e, "Linux LVM"},
  {0x93, "Amoeba/Hidden Linux native file system (Ext2/3)"},
  {0x94, "Amoeba BBT"},
  {0x9f, "BSD/OS"},
  {0xA0, "IBM Thinkpad hibernation"},
  {0xA5, "FreeBSD"},
  {0xA6, "OpenBSD"},
  {0xA7, "NeXTSTEP"},
  {0xA9, "NetBSD"},
  {0xB7, "BSDI fs"},
  {0xb8, "BSDI swap"},
  {0xbb, "Boot Wizard hidden"},
  {0xc1, "DRDOS / sec (FAT-12)"},
  {0xc4, "DRDOS / sec (FAT-16 < 32M)"},
  {0xc6, "Disabled NT FAT (FAT-16) volume set/DRDOS"},
  {0xc7, "Syrinx / Disabled NT IFS volume set"},
  {0xda, "Non-FS data"},
  {0xdb, "CP/M / CTOS / ..."},
  {0xde, "Dell Corporation diagnostic partition"},
  {0xdf, "BootIt"},
  {0xe1, "DOS access"},
  {0xe3, "DOS R/O"},
  {0xe4, "SpeedStor"},
  {0xeb, "BeOS fs"},
  {0xee, "EFI GPT"},
  {0xef, "EFI (FAT-12/16/32)"},
  {0xf0, "Linux/PA-RISC boot"},
  {0xf1, "SpeedStor"},
  {0xf4, "SpeedStor"},
  {0xf2, "DOS secondary"},
  {0xfd, "Linux raid autodetect"},
  {0xfe, "LANstep"},
  {0xff, "Bad Track Table"},
  {0, 0} // End-Of-Table
};

//---------------------------------------------------------------------------
const char *CPartitionManager::get_name_for_type(int type)
{
  for (int i = 0; system_identifiers[i].name; i++)
  {
    if (system_identifiers[i].type == type)
      return system_identifiers[i].name;
  }
  return "Unknown";
}