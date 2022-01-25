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

#ifndef virtual_fs_HELPER_H_
#define virtual_fs_HELPER_H_

#include <Windows.h>
#include <string>
#include "../NxFile.h"

std::wstring parent_path(const std::wstring & path);
std::wstring base_name(const std::wstring & path);
wstring virtual_path_to_nx_path(const wchar_t* path, NxPartition* part);
wstring nx_path_to_virtual_path(const wchar_t* path, NxPartition* part);
std::string dokanNtStatusToStr(NTSTATUS status);
int installDokanDriver(bool siletn = false);

static const std::wstring DataStreamNameStr;

namespace virtual_fs {
// virtual_fs helpers
class virtual_fs_helper {
 public:
  static inline LONGLONG FileTimeToLlong(const FILETIME& f) {
    return DDwLowHighToLlong(f.dwLowDateTime, f.dwHighDateTime);
  }

  static inline void LlongToFileTime(LONGLONG v, FILETIME& filetime) {
    LlongToDwLowHigh(v, filetime.dwLowDateTime, filetime.dwHighDateTime);
  }

  static inline LONGLONG DDwLowHighToLlong(const DWORD& low,
                                           const DWORD& high) {
    return static_cast<LONGLONG>(high) << 32 | low;
  }

  static inline void LlongToDwLowHigh(const LONGLONG& v, DWORD& low,
                                      DWORD& hight) {
    hight = v >> 32;
    low = static_cast<DWORD>(v);
  }


  // Remove the stream type from the filename
  // Stream type are not supported so we ignore / remove them.
  static inline void RemoveStreamType(std::wstring& filename) {
    // Remove $DATA stream if exist as it is the default / main stream.
    auto data_stream_pos = filename.rfind(DataStreamNameStr);
    if (data_stream_pos == (filename.length() - DataStreamNameStr.length()))
      filename = filename.substr(0, data_stream_pos);
    // TODO: Remove $INDEX_ALLOCATION & $BITMAP
  }

  // Return a pair containing for example for \foo:bar
  // first: filename: foo
  // second: alternated stream name: bar
  // If the filename do not contain an alternated stream, second is empty.
  static inline std::pair<std::wstring, std::wstring> GetStreamNames(
      const std::wstring& filename) {
    // real_fileName - foo or foo:bar    
    auto t = base_name(filename);
    const auto real_fileName = t;
    auto stream_pos = real_fileName.find(L":");
    // foo does not have alternated stream, return an empty alternated stream.
    if (stream_pos == std::string::npos)
      return std::pair<std::wstring, std::wstring>(real_fileName,
                                                   std::wstring());

    // foo:bar has an alternated stream
    // return first the file name and second the file stream name
    // first: foo - second: bar
    const auto main_stream = real_fileName.substr(0, stream_pos);
    ++stream_pos;
    const auto alternate_stream =
        real_fileName.substr(stream_pos, real_fileName.length() - stream_pos);
    return std::pair<std::wstring, std::wstring>(main_stream, alternate_stream);
  }

  // Return the filename without any stream informations.
  // <filename>:<stream name>:<stream type>
  static inline std::wstring GetFileName(
      const std::wstring& filename,
      const std::pair<std::wstring, std::wstring>& stream_names) {
    auto file_name = parent_path(filename);
    if (file_name != L"\\") {
      // std::filesystem::path(filename).parent_path()
      // return \ when filename is at root.
      file_name += L"\\";
    }
    file_name += stream_names.first;
    return file_name;
  }
};
}  // namespace virtual_fs

#endif /* virtual_fs_HELPER_H_ */
