#ifndef __PARTITION_MANAGER__06042004__
#define __PARTITION_MANAGER__06042004__

#include <list>
#include <vector>

#ifdef __REMOTE__
#include "remotedisksector.h"
#else
#include "disksector.h"
#endif

#include <Windows.h>
#include <WinIoCtl.h>


/*
Reference 
--------------
  http://www.ntfs.com/partition-table.htm
  http://www.boot-us.com/gloss08.htm
  http://www.boot-us.com/gloss11.htm
*/

#pragma pack(1)

#define MAXPARTITIONS_COUNT 4

//---------------------------------------------------------------------------
struct system_identifier_t
{
  unsigned char type;
  const char *name;
};

extern const system_identifier_t system_identifiers[];

//---------------------------------------------------------------------------
// Standard CHS value as read from the MBR
struct chs_t
{
  unsigned char h;
  unsigned char s;
  unsigned char c;
};

//---------------------------------------------------------------------------
// My defined structure to store unrestricted CHS values
struct chs2_t
{
  unsigned long c;
  unsigned long h;
  unsigned long s;
};

//---------------------------------------------------------------------------
// Standard structure of a partition entry
struct partition_t
{
  unsigned char boot_indicator; // +1 
  chs_t start; // +3
  unsigned char system_indicator;
  chs_t end; // +3
  unsigned long sectors_before; // +4
  unsigned long number_of_sectors; // +4
};

//---------------------------------------------------------------------------
// The stucture of the MBR
struct mbr_t
{
  char code[512 - sizeof(partition_t)*MAXPARTITIONS_COUNT - 2];
  partition_t parts[MAXPARTITIONS_COUNT];
  unsigned short int signature;
};

//---------------------------------------------------------------------------
// Partition info
struct partition_info
{
  int parent_id;
  chs2_t chs_start;
  chs2_t chs_end;

  unsigned char sys_id;
  bool is_active;
  const char *sys_name;

  unsigned long sectors_before;
  unsigned long number_of_sectors;

  unsigned __int64 lba_start;
  unsigned __int64 lba_end;
};

typedef std::vector<partition_info> partition_info_list;

#pragma pack(push, 1)

//---------------------------------------------------------------------------
class CPartitionManager
{
private:
  DiskSector ds;
  DISK_GEOMETRY m_dg;

public:

  static const char *get_name_for_type(int type);

  enum
  {
    extended_partition_id = 5,
    extended_ex_partition = 15,
    partition_signature = 0xAA55
  } consts;

  void partition_t_to_partition_info(partition_t &pt, partition_info &pi);

  partition_info_list partlist;

  void clear_partition_info(partition_info &pi);
  
  bool IsEmptyPartition(partition_t *part)
  {
    return (part->boot_indicator == 0) && 
      (part->sectors_before == 0) && 
      (part->number_of_sectors == 0) &&
      (part->start.h == 0) && (part->start.s == 0) && (part->start.c == 0);
  }

  CPartitionManager();
  ~CPartitionManager();

  bool    Open(DWORD driveNo);
  void    Close();
  
  __int64 CHStoLBA(chs_t &chs, partition_t *part = 0);
  void    CHStoCHS2(chs_t &chs, chs2_t &chs2);
  void    LBAtoCHS(DWORD lba, chs_t &chs);

  bool    ReadPartitionTable(ULONGLONG sector = 0);
	bool    ReadPartitionTable(DWORD driveNo, ULONGLONG sector = 0);

  bool    m_bIncludeExtendedPartitionDefinitions;

  void SetDiskGeometry(DISK_GEOMETRY &dg);

  bool IsExtendedPartitionId(unsigned char sys_id);

  void ClearOldPartitionsInfo();
};

#pragma pack(pop)

#endif