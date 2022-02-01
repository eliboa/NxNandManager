/*
  Dokan : user-mode file system library for Windows

  Copyright (C) 2019 Adrien J. <liryna.stark@gmail.com>
  Copyright (C) 2020 Google, Inc.
  Copyright (C) 2021 eliboa (eliboa@gmail.com)

  http://dokan-dev.github.io

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#include "../res/utils.h"
#include "virtual_fs.h"
#include <memory>
#include <vector>

using namespace std;

namespace virtual_fs {

virtual_fs::virtual_fs(NxPartition* part)
{
    partition = part;
    fs_filenodes = unique_ptr<::virtual_fs::fs_filenodes>(new ::virtual_fs::fs_filenodes());
    fs_filenodes->nx_part = partition;
    callback_func = nullptr;
}

int virtual_fs::populate()
{
    int res = SUCCESS;
    // Ensure FS is mounted for NxPartition
    if ((res = partition->mount_fs()))
        return res;

    vector<wstring> queue;
    DIR dp;
    FILINFO fno;
    int nodes_count = 0;

    // Populate file nodes (recursive scan)
    queue.push_back(L"\\"); // Enqueue root
    do {
        // Dequeue
        auto dir = queue.at(0);
        queue.erase(queue.begin());

        // Open & scan dir
        auto open = partition->f_opendir(&dp, dir.c_str()) == FR_OK;
        while(open && f_readdir(&dp, &fno) == FR_OK)
        {
            if (fno.fname[0] == '\0')
                break;

            bool isDir = fno.fattrib == FILE_ATTRIBUTE_DIRECTORY || (fno.fattrib == FILE_ATTRIBUTE_NX_ARCHIVE && !virtualize_nxa);
            auto filename = wstring(dir).append(dir.back() != L'\\' ? L"\\" : L"").append(fno.fname);

            NxFileFlag options = virtualize_nxa ? VirtualizeNXA : SimpleFile;
            NxFile *nxFile = isDir ? nullptr : new NxFile(partition, filename, options);
            if (nxFile && !nxFile->exists()) {
                delete nxFile;
                continue;
            }

            DWORD fattr = fno.fattrib;
            if (fno.fattrib == FILE_ATTRIBUTE_NX_ARCHIVE && virtualize_nxa)
                fattr = FILE_ATTRIBUTE_VIRTUAL;

            // File or direcory, create a node
            auto fileNode = make_shared<filenode>(filename.c_str(), isDir, fattr, nullptr, nxFile);

            // Set additional information
            FILETIME ft;
            DosDateTimeToFileTime(fno.fdate, fno.ftime, &ft);
            auto time = virtual_fs_helper::DDwLowHighToLlong(ft.dwLowDateTime, ft.dwHighDateTime);
            fileNode->times.set(time, time, time);
            fileNode->size = nxFile ? nxFile->size() : fno.fsize;

            // Add node
            fs_filenodes->add(fileNode);
            nodes_count++;

            // Enqueue if directory
            if (isDir)
                queue.push_back(filename);
        }
        f_closedir(&dp);
    }
    while (queue.size());
    return nodes_count;
}

void virtual_fs::run()
{
    DOKAN_OPTIONS dokan_options;
    ZeroMemory(&dokan_options, sizeof(DOKAN_OPTIONS));
    dokan_options.Version = DOKAN_VERSION;
    dokan_options.Options = DOKAN_OPTION_ALT_STREAM | DOKAN_OPTION_CASE_SENSITIVE;

    if(isdebug)
    {
        dokan_options.Options |= DOKAN_OPTION_STDERR | DOKAN_OPTION_DEBUG;
        //dokan_options.Options |= 16384;
    }

    // Mount type
    if (network_drive) {
        dokan_options.Options |= DOKAN_OPTION_NETWORK;
    if (unc_name[0]) {
      dokan_options.UNCName = unc_name;
    }
    if (enable_network_unmount) {
      dokan_options.Options |= DOKAN_OPTION_ENABLE_UNMOUNT_NETWORK_DRIVE;
    }
    } else if (removable_drive) {
        dokan_options.Options |= DOKAN_OPTION_REMOVABLE;
    } else {
        dokan_options.Options |= DOKAN_OPTION_MOUNT_MANAGER;
    }

    if (current_session && (dokan_options.Options & DOKAN_OPTION_MOUNT_MANAGER) == 0) {
        dokan_options.Options |= DOKAN_OPTION_CURRENT_SESSION;
    }

    dokan_options.ThreadCount = thread_number;
    dokan_options.Timeout = timeout;

    if (read_only || partition->nxHandle->isReadOnly())
        dokan_options.Options |= DOKAN_OPTION_WRITE_PROTECT;

    TCHAR driveLetter;
    if(!mount_point[0] && GetAvailableMountPoint(&driveLetter))
      mount_point[0] = driveLetter;

    fs_filenodes->mount_point[0] = mount_point[0];
    dokan_options.MountPoint = mount_point;
    dokan_options.GlobalContext = reinterpret_cast<ULONG64>(fs_filenodes.get());

    NTSTATUS status = DokanMain(&dokan_options, &virtual_fs_operations);

    if (callback_func)
        callback_func(status);

#if defined(ENABLE_GUI)
    emit dokan_callback((long)status);
#endif

}

virtual_fs::~virtual_fs() {
    DokanRemoveMountPoint(mount_point);
}

}  // namespace virtual_fs
