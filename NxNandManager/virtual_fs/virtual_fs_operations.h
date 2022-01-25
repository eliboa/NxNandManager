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

#ifndef virtual_fs_OPERATIONS_H_
#define virtual_fs_OPERATIONS_H_

#include <dokan/dokan.h>

#include "filenodes.h"

namespace virtual_fs {
// virtual_fs Dokan API implementation.
extern DOKAN_OPERATIONS virtual_fs_operations;

// Helper getting the virtual_fs filenodes context at each Dokan API call.
#define GET_FS_INSTANCE \
  reinterpret_cast<fs_filenodes*>(dokanfileinfo->DokanOptions->GlobalContext)
#define GET_FILE_INSTANCE \
  reinterpret_cast<NxFile*>(dokanfileinfo->Context)
}  // namespace virtual_fs

#endif  // virtual_fs_OPERATIONS_H_
