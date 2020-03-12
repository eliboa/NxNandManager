#include "win_ioctl.h"

bool compareVolByInt(const volumeDescriptor& a, const volumeDescriptor b)
{
    return a.diskNumber < b.diskNumber;
}

bool GetVolumeMountPoint(wchar_t* letter, LPWSTR volumeName)
{
    TCHAR I;
    TCHAR Drive[] = TEXT("a:\\");
    TCHAR Volume[MAX_PATH];
    wcscat(volumeName, L"\\\0");
    for (I = TEXT('a'); I < TEXT('z'); I++)
    {
        Drive[0] = I;
        if (GetVolumeNameForVolumeMountPoint(Drive, Volume, MAX_PATH) && !lstrcmp(Volume, volumeName))
        {
            *letter = I;
            return true;
        }
    }
    return false;
}

bool GetVolumeDescriptor(volumeDescriptor* vd, LPWSTR VolumeName)
{
    DWORD dwBytesReturned;
    HANDLE hHandle = CreateFile(VolumeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hHandle == INVALID_HANDLE_VALUE)
        return false;

    DISK_GEOMETRY pdg;
    if (!DeviceIoControl(hHandle, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pdg, sizeof(pdg), &dwBytesReturned, (LPOVERLAPPED)NULL))
        return false;

    STORAGE_PROPERTY_QUERY query;
    DWORD cbBytesReturned = 0;
    char local_buffer[10000];
    memset((void *)& query, 0, sizeof(query));
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;
    memset(local_buffer, 0, sizeof(local_buffer));

    if (!DeviceIoControl(hHandle, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &local_buffer[0], sizeof(local_buffer), &cbBytesReturned, nullptr))
        return false;

    STORAGE_DEVICE_DESCRIPTOR * descrip = (STORAGE_DEVICE_DESCRIPTOR *)& local_buffer;

    char productId[1000];
    char vendorId[1000];
    char serialNumber[1000];
    flipAndCodeBytes(local_buffer, descrip->VendorIdOffset, 0, vendorId);
    flipAndCodeBytes(local_buffer, descrip->ProductIdOffset, 0, productId);
    flipAndCodeBytes(local_buffer, descrip->SerialNumberOffset, 0, serialNumber);

    VOLUME_DISK_EXTENTS volumeDiskExtents;

    if (!DeviceIoControl(hHandle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, &volumeDiskExtents, sizeof(volumeDiskExtents), &dwBytesReturned, NULL))
        return false;

    PDISK_EXTENT pDiskExtent = &volumeDiskExtents.Extents[0];

    vd->removableMedia = descrip->RemovableMedia;
    vd->volumeName = std::wstring(VolumeName);
    vd->diskNumber = pDiskExtent->DiskNumber;
    vd->pId = std::string(productId);
    vd->vId = std::string(vendorId);    
    if (!vd->pId.find("UMS disk") && !vd->vId.find("Linux"))
        vd->vId.append(" (memloader)");
    vd->serialNumber = std::string(serialNumber);
    vd->diskSize = pdg.Cylinders.QuadPart * (ULONG)pdg.TracksPerCylinder * (ULONG)pdg.SectorsPerTrack * (ULONG)pdg.BytesPerSector;
    vd->diskStartOffset = pDiskExtent->StartingOffset.QuadPart;

    wchar_t mp;
    if (GetVolumeMountPoint(&mp, VolumeName))
        vd->mountPt = mp;

    GET_LENGTH_INFORMATION gli;
    if (DeviceIoControl(hHandle, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &gli, sizeof(gli), &dwBytesReturned, NULL))
    {
        vd->size = gli.Length.QuadPart;
    }



    DWORD dwSectPerClust, dwBytesPerSect, dwFreeClusters, dwTotalClusters;
    if(GetDiskFreeSpace(VolumeName, &dwSectPerClust, &dwBytesPerSect, &dwFreeClusters, &dwTotalClusters))
    {
        vd->volumeTotalBytes = (u64)dwTotalClusters * dwSectPerClust * dwBytesPerSect;
        vd->volumeFreeBytes = (u64)dwFreeClusters * dwSectPerClust * dwBytesPerSect;
    }

    if (!vd->volumeTotalBytes)
        vd->volumeTotalBytes = pDiskExtent->ExtentLength.QuadPart;

    return true;
}

void GetVolumes(std::vector<volumeDescriptor> *volumes)
{
    volumes->clear();
    HANDLE hVol = INVALID_HANDLE_VALUE;
    HANDLE hHandle = INVALID_HANDLE_VALUE;
    DWORD dwBytesReturned;
    WCHAR  VolumeName[MAX_PATH] = L"";

    hVol = FindFirstVolumeW(VolumeName, ARRAYSIZE(VolumeName));
    if (hVol == INVALID_HANDLE_VALUE)
        return;

    do {
        if (hHandle != INVALID_HANDLE_VALUE) CloseHandle(hHandle);

        size_t Index = wcslen(VolumeName) - 1;

        if (VolumeName[0] != L'\\' || VolumeName[1] != L'\\' || VolumeName[2] != L'?' || VolumeName[3] != L'\\' || VolumeName[Index] != L'\\')
            continue;

        VolumeName[Index] = L'\0'; //remove trailing backslash

        volumeDescriptor vd;
        if (GetVolumeDescriptor(&vd, VolumeName))
            volumes->push_back(vd);

    } while (FindNextVolumeW(hVol, VolumeName, ARRAYSIZE(VolumeName)));
    FindVolumeClose(hVol);
    if (hHandle != INVALID_HANDLE_VALUE) CloseHandle(hHandle);

    // Get offline drives (memloader sometimes mounts NAND as on offline drive)
    for (int drive = 0; drive < 26; drive++)
    {
        bool found = false;
        for (volumeDescriptor vol : *volumes) if (vol.diskNumber == drive) found = true;
        if (found)
            continue;

        swprintf_s(VolumeName, MAX_PATH, L"\\\\.\\PhysicalDrive%d", drive);

        volumeDescriptor vd;
        if (GetVolumeDescriptor(&vd, VolumeName))
            volumes->push_back(vd);
    }

    std::sort(volumes->begin(), volumes->end(), compareVolByInt);
}

void GetDisks(std::vector<diskDescriptor> *disks)
{
    disks->clear();
    std::vector<volumeDescriptor> volumes;
    GetVolumes(&volumes);
    for (volumeDescriptor vol : volumes)
    {
        diskDescriptor* disk = nullptr;
        if (disks->size() > 0)
        {
            for (int i(0); i <= disks->size() - 1; i++) 
            {
                if (disks->at(i).diskNumber == vol.diskNumber)
                {
                    disk = &disks->at(i);
                }
            }
        }
        if (nullptr == disk)
        {
            diskDescriptor new_disk;
            new_disk.diskNumber = vol.diskNumber;
            new_disk.pId = vol.pId;
            new_disk.vId = vol.vId;
            new_disk.serialNumber = vol.serialNumber;
            new_disk.size = vol.diskSize;
            new_disk.removableMedia = vol.removableMedia;
            disks->push_back(new_disk);
            disk = &disks->back();
        }

        if (vol.volumeName.find(L"\\\\.\\PhysicalDrive"))
            disk->volumes.push_back(vol);
    }
}

bool operator == (diskDescriptor a, diskDescriptor b)
{
    if (a.serialNumber == b.serialNumber && a.volumes.size() == b.volumes.size())
        return true;
    else
        return false;
};

bool operator == (const volumeDescriptor a, const volumeDescriptor b)
{
    if (a.volumeName == b.volumeName)
        return true;
    else
        return false;
};

bool GetVolumeName(DWORD diskNumber, u64 startOffset, WCHAR *pVolumeName, size_t size)
{
    std::vector<volumeDescriptor> volumes;
    GetVolumes(&volumes);
    for (volumeDescriptor vol : volumes)
    {
        if (vol.diskNumber == diskNumber && vol.diskStartOffset == startOffset)
        {
            memcpy(pVolumeName, vol.volumeName.c_str(), size);
            dbg_wprintf(L"GetVolumeName(diskNumber = %I32d, offset = %I64d, WCHAR *pVolumeName = %s, size = %I32d\n", diskNumber, startOffset, vol.volumeName.c_str(), size);
            return true;
        }
    }
    return false;
}

bool DisMountVolume(volumeDescriptor vd)
{
    DWORD dwBytesReturned;
    HANDLE hHandle = CreateFile(vd.volumeName.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hHandle == INVALID_HANDLE_VALUE)
        return false;

    bool result = DeviceIoControl(hHandle, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &dwBytesReturned, NULL);
    
    CloseHandle(hHandle);

    return result;
}

bool DisMountAllVolumes(diskDescriptor dd)
{
    bool result = true;
    for (volumeDescriptor vol : dd.volumes)
    {
        if (!DisMountVolume(vol))
            result = false;
    }
    return result;
}
