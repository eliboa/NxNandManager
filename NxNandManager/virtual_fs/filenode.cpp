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

#include "filenode.h"
#include "../res/utils.h"


LONGLONG virtual_fs::filetimes::get_currenttime() {
  FILETIME t;
  GetSystemTimeAsFileTime(&t);
  return virtual_fs_helper::DDwLowHighToLlong(t.dwLowDateTime, t.dwHighDateTime);
}

namespace virtual_fs {
filenode::filenode(const std::wstring& filename, bool is_directory,
                   DWORD file_attr,
                   const PDOKAN_IO_SECURITY_CONTEXT security_context, NxFile* nxfile)
    : is_directory(is_directory), attributes(file_attr), _fileName(filename), _nxfile(nxfile) {
  // No lock need, FileNode is still not in a directory
  times.reset();

  if (security_context && security_context->AccessState.SecurityDescriptor) {
    dbg_wprintf(L"%s : Attach SecurityDescriptor\n", filename.c_str());
    security.SetDescriptor(security_context->AccessState.SecurityDescriptor);
  }
}
filenode::~filenode()
{
    delete_nxfile();
}

void filenode::delete_nxfile() {
    if (_nxfile)
        delete _nxfile;
}

DWORD filenode::read(LPVOID buffer, DWORD bufferlength, LONGLONG offset) {
  std::lock_guard<std::mutex> lock(_data_mutex);
  if (static_cast<size_t>(offset + bufferlength) > _data.size())
    bufferlength = (_data.size() > static_cast<size_t>(offset))
                       ? static_cast<DWORD>(_data.size() - offset)
                       : 0;
  if (bufferlength)
    memcpy(buffer, &_data[static_cast<size_t>(offset)], bufferlength);
  dbg_wprintf(L"Read %s : BufferLength %d Offset %ld\n", get_filename().c_str(),
               bufferlength, offset);
  return bufferlength;
}

DWORD filenode::write(LPCVOID buffer, DWORD number_of_bytes_to_write,
                      LONGLONG offset) {
  if (!number_of_bytes_to_write) return 0;

  std::lock_guard<std::mutex> lock(_data_mutex);
  if (static_cast<size_t>(offset + number_of_bytes_to_write) > _data.size())
    _data.resize(static_cast<size_t>(offset + number_of_bytes_to_write));

  dbg_wprintf(L"Write %s : NumberOfBytesToWrite %d Offset %ld\n", get_filename().c_str(),
               number_of_bytes_to_write, offset);
  memcpy(&_data[static_cast<size_t>(offset)], buffer, number_of_bytes_to_write);
  return number_of_bytes_to_write;
}

const LONGLONG filenode::get_filesize() {
  std::lock_guard<std::mutex> lock(_data_mutex);
  return size;
}

void filenode::set_endoffile(const LONGLONG& byte_offset) {
  std::lock_guard<std::mutex> lock(_data_mutex);
  //_data.resize(static_cast<size_t>(byte_offset));
  size = byte_offset;
}

const std::wstring filenode::get_filename() {
  std::lock_guard<std::mutex> lock(_fileName_mutex);
  return _fileName;
}

void filenode::set_filename(const std::wstring& f) {
  std::lock_guard<std::mutex> lock(_fileName_mutex);
  _fileName = f;
}

void filenode::add_stream(const std::shared_ptr<filenode>& stream) {
  std::lock_guard<std::mutex> lock(_data_mutex);
  _streams[stream->get_filename()] = stream;
}

void filenode::remove_stream(const std::shared_ptr<filenode>& stream) {
  std::lock_guard<std::mutex> lock(_data_mutex);
  _streams.erase(stream->get_filename());
}

std::unordered_map<std::wstring, std::shared_ptr<filenode> >
filenode::get_streams() {
  std::lock_guard<std::mutex> lock(_data_mutex);
  return _streams;
}
}  // namespace virtual_fs
