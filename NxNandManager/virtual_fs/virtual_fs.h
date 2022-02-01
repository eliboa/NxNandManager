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

#ifndef virtual_fs_H_
#define virtual_fs_H_
#include "../gui/gui.h"
#include <dokan/dokan.h>
#include <dokan/fileinfo.h>
#include "filenodes.h"
#include "virtual_fs_operations.h"
#include <winbase.h>
#include <iostream>
#include "../NxPartition.h"

#if defined(ENABLE_GUI)
#include <QObject>
#endif

namespace virtual_fs {
class fs_filenodes;

class virtual_fs
#if defined(ENABLE_GUI)
    : public QObject
{
    Q_OBJECT
#else
{
#endif
    public:

    virtual_fs(NxPartition* part);

    // Populate file nodes
    int populate();
    // Start the virtual filesystem
    void run();
    // Unmount the device when destructor is called
    virtual ~virtual_fs();


    // FileSystem mount options
    WCHAR mount_point[4] = L"\0:\\";
    WCHAR unc_name[MAX_PATH] = L"";
    USHORT thread_number = 4;
    bool network_drive = false;
    bool removable_drive = false;
    bool current_session = false;
    bool debug_log = false;
    bool enable_network_unmount = false;
    bool read_only = false;
    bool virtualize_nxa = false;
    ULONG timeout = 0;
    NxPartition *partition;

    void setDriveLetter(const wchar_t letter) { mount_point[0] = letter; }
    void setReadOnly(bool state = true) { read_only = state; }
    void(*callback_func)(NTSTATUS) = nullptr;
    void setCallBackFunction(void(*func_ptr)(NTSTATUS)) {
        callback_func = func_ptr;
    }

    // FileSystem context runtime
    std::unique_ptr<fs_filenodes> fs_filenodes;
#if defined(ENABLE_GUI)
signals:
    void dokan_callback(long res);
#endif
};
}  // namespace virtual_fs

#endif  // virtual_fs_H_
