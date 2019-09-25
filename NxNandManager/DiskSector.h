#ifndef __DISKSECTOR_02172004__INC__
#define __DISKSECTOR_02172004__INC__

#include <windows.h>
#include <WinIoCtl.h>

class DiskSectorRW
{
public:
  virtual bool GetDriveGeometry(DISK_GEOMETRY &) { return false; }
  virtual bool OpenPhysicalDrive(DWORD VolNumber) { return false; }
  virtual bool Open(char *vol) = 0;
  virtual void Close() = 0;
  virtual bool ReadSector(__int64 sector, char *Buffer, int sectorSize = 512) = 0;
  virtual bool WriteSector(__int64 sector, char *buffer, int sectorSize = 512) = 0;
  virtual bool GetDiskLength(ULONGLONG &) { return false; }
  virtual ~DiskSectorRW() { }
};

class DiskSectorWinNT : public DiskSectorRW
{
private:
  HANDLE m_hDisk;
public:
  ~DiskSectorWinNT();
  DiskSectorWinNT() : m_hDisk(INVALID_HANDLE_VALUE) { }
  bool OpenPhysicalDrive(DWORD VolNumber);
  bool Open(char *vol);
  void Close();
  bool ReadSector (__int64 sector, char *Buffer, int sectorSize = 512);
  bool WriteSector(__int64 sector, char *Buffer, int sectorSize = 512);
  bool GetDriveGeometry(DISK_GEOMETRY &);
  bool GetDiskLength(ULONGLONG &);
};

class DiskSectorWin9x : public DiskSectorRW
{
private:
  HANDLE m_hVmm32;
  bool m_bOpened;
  char m_chDrive;
  BYTE m_nDriveNo;
  bool m_bW9xOsr2AndAbove;
  bool m_bUseLocking;
public:

  ~DiskSectorWin9x();

  DiskSectorWin9x() : m_bUseLocking(false) { }
  bool Open(char *vol);
  void Close();
  bool ReadSector (__int64 sector, char *Buffer, int sectorSize = 512);
  bool WriteSector(__int64 sector, char *Buffer, int sectorSize = 512);
  
  static bool LockLogicalVolume (HANDLE hVWin32, BYTE   bDriveNum, BYTE   bLockLevel, WORD wPermissions);
  static bool UnlockLogicalVolume(HANDLE hVWin32, BYTE bDriveNum);  

  static bool ReadLogicalSectors (HANDLE hDev, BYTE   bDrive, DWORD  dwStartSector, WORD wSectors, LPBYTE lpSectBuff);
  static bool WriteLogicalSectors (HANDLE hDev, BYTE   bDrive, DWORD  dwStartSector, WORD   wSectors, LPBYTE lpSectBuff);

  static bool NewReadSectors(HANDLE hDev, BYTE   bDrive, DWORD  dwStartSector, WORD   wSectors, LPBYTE lpSectBuff);
  static bool NewWriteSectors(HANDLE hDev, BYTE   bDrive, DWORD  dwStartSector, WORD   wSectors, LPBYTE lpSectBuff);
};

class DiskSector
{
private:
  DiskSectorRW *util;
public:
  DiskSector();
  bool OpenPhysicalDrive(DWORD VolNumber);
  ~DiskSector();
  bool Open(char *vol);
  void Close();

  bool ReadSector(__int64 sector, char *Buffer, int sectorSize = 512);
  bool WriteSector(__int64 sector, char *buffer, int sectorSize = 512);

  bool ReadSector (__int64 sector, void *Buffer, int sectorSize = 512);
  bool WriteSector(__int64 sector, void *Buffer, int sectorSize = 512);

  bool GetDriveGeometry(DISK_GEOMETRY &);
  bool GetDiskLength(ULONGLONG &);

};
#endif