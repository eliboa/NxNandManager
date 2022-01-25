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

#include "filenodes.h"
#include "../res/utils.h"
#include <sddl.h>

namespace virtual_fs {
fs_filenodes::fs_filenodes() {
    WCHAR buffer[1024];
    WCHAR final_buffer[2048];
    PTOKEN_USER user_token = NULL;
    PTOKEN_GROUPS groups_token = NULL;
    HANDLE token_handle;
    LPTSTR user_sid_str = NULL;
    LPTSTR group_sid_str = NULL;

    volumeSerial = randomDWORD();

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &token_handle) ==
      FALSE) {
    throw std::runtime_error("Failed init root resources");
    }

    DWORD return_length;
    if (!GetTokenInformation(token_handle, TokenUser, buffer, sizeof(buffer),
                           &return_length)) {
    CloseHandle(token_handle);
    throw std::runtime_error("Failed init root resources");
    }

    user_token = (PTOKEN_USER)buffer;
    if (!ConvertSidToStringSid(user_token->User.Sid, &user_sid_str)) {
    CloseHandle(token_handle);
    throw std::runtime_error("Failed init root resources");
    }

    if (!GetTokenInformation(token_handle, TokenGroups, buffer, sizeof(buffer),
                           &return_length)) {
    CloseHandle(token_handle);
    throw std::runtime_error("Failed init root resources");
    }

    groups_token = (PTOKEN_GROUPS)buffer;
    if (groups_token->GroupCount > 0) {
    if (!ConvertSidToStringSid(groups_token->Groups[0].Sid, &group_sid_str)) {
      CloseHandle(token_handle);
      throw std::runtime_error("Failed init root resources");
    }
    swprintf_s(buffer, 1024, L"O:%lsG:%ls", user_sid_str, group_sid_str);
    } else
    swprintf_s(buffer, 1024, L"O:%ls", user_sid_str);

    LocalFree(user_sid_str);
    LocalFree(group_sid_str);
    CloseHandle(token_handle);

    swprintf_s(final_buffer, 2048, L"%lsD:PAI(A;OICI;FA;;;AU)", buffer);

    PSECURITY_DESCRIPTOR security_descriptor = NULL;
    ULONG size = 0;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
          final_buffer, SDDL_REVISION_1, &security_descriptor, &size))
    throw std::runtime_error("Failed init root resources");

    auto fileNode = std::make_shared<filenode>(L"\\", true,
                                             FILE_ATTRIBUTE_DIRECTORY, nullptr);
    fileNode->security.SetDescriptor(security_descriptor);
    LocalFree(security_descriptor);

    _filenodes[L"\\"] = fileNode;
    _directoryPaths.emplace(L"\\", std::set<std::shared_ptr<filenode>>());
}
fs_filenodes::~fs_filenodes() {
}

void fs_filenodes::deleteNxFiles()
{
    std::lock_guard<std::recursive_mutex> lock(_filesnodes_mutex);
    for (auto f : _filenodes)
        f.second->delete_nxfile();
}

NTSTATUS fs_filenodes::add(const std::shared_ptr<filenode>& f) {
  std::lock_guard<std::recursive_mutex> lock(_filesnodes_mutex);

  if (f->fileindex == 0)  // previous init
    f->fileindex = _fs_fileindex_count++;
  const auto filename = f->get_filename();
  auto t = parent_path(filename);
  const auto parent_path = t;

  // Does target folder exist
  if (!_directoryPaths.count(parent_path)) {
    dbg_wprintf(L"Add: No directory: %s exist FilePath: %s\n", parent_path.c_str(),
                 filename.c_str());
    return STATUS_OBJECT_PATH_NOT_FOUND;
  }

  auto stream_names = virtual_fs_helper::GetStreamNames(filename);
  if (!stream_names.second.empty()) {
    dbg_wprintf(
        L"Add file: %s is an alternate stream %s and has %s as main stream\n",
        filename.c_str(), stream_names.second.c_str(), stream_names.first.c_str());
    auto main_stream_name =
        virtual_fs_helper::GetFileName(filename, stream_names);
    auto main_f = find(main_stream_name);
    if (!main_f) return STATUS_OBJECT_PATH_NOT_FOUND;
    main_f->add_stream(f);
    f->main_stream = main_f;
    f->fileindex = main_f->fileindex;
  }

  // If we have a folder, we add it to our directoryPaths
  if (f->is_directory && !_directoryPaths.count(filename))
    _directoryPaths.emplace(filename, std::set<std::shared_ptr<filenode>>());

  // Add our file to the fileNodes and directoryPaths
  _filenodes[filename] = f;
  _directoryPaths[parent_path].insert(f);

  dbg_wprintf(L"Add file: %ls in folder: %ls\n", filename.c_str(), parent_path.c_str());
  return STATUS_SUCCESS;
}

std::shared_ptr<filenode> fs_filenodes::find(const std::wstring& filename) {
  std::lock_guard<std::recursive_mutex> lock(_filesnodes_mutex);
  auto fileNode = _filenodes.find(filename);
  return (fileNode != _filenodes.end()) ? fileNode->second : nullptr;
}

std::set<std::shared_ptr<filenode>> fs_filenodes::list_folder(
    const std::wstring& fileName) {
  std::lock_guard<std::recursive_mutex> lock(_filesnodes_mutex);

  auto it = _directoryPaths.find(fileName);
  return (it != _directoryPaths.end()) ? it->second
                                       : std::set<std::shared_ptr<filenode>>();
}

void fs_filenodes::remove(const std::wstring& filename) {
  return remove(find(filename));
}

void fs_filenodes::remove(const std::shared_ptr<filenode>& f) {
  if (!f) return;

  std::lock_guard<std::recursive_mutex> lock(_filesnodes_mutex);
  auto fileName = f->get_filename();
  dbg_wprintf(L"Remove: %s\n", fileName.c_str());

  // Remove node from fileNodes and directoryPaths
  _filenodes.erase(fileName);

  _directoryPaths[parent_path(fileName)].erase(f);

  // if it was a directory we need to remove it from directoryPaths
  if (f->is_directory) {
    // but first we need to remove the directory content by looking recursively
    // into it
    auto files = list_folder(fileName);
    for (const auto& file : files) remove(file);

    _directoryPaths.erase(fileName);
  }

  // Cleanup streams
  if (f->main_stream) {
    // Is an alternate stream
    f->main_stream->remove_stream(f);
  } else {
    // Is a main stream
    // Remove possible alternate stream
    for (const auto& [stream_name, node] : f->get_streams())
      remove(stream_name);
  }
}

NTSTATUS fs_filenodes::move(const std::wstring& old_filename,
                            const std::wstring& new_filename,
                            BOOL replace_if_existing) {
  auto f = find(old_filename);
  auto new_f = find(new_filename);

  if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;

  // Cannot move to an existing destination without replace flag
  if (!replace_if_existing && new_f) return STATUS_OBJECT_NAME_COLLISION;

  // Cannot replace read only destination
  if (new_f && new_f->attributes & FILE_ATTRIBUTE_READONLY)
    return STATUS_ACCESS_DENIED;

  // If destination exist - Cannot move directory or replace a directory
  if (new_f && (f->is_directory || new_f->is_directory))
    return STATUS_ACCESS_DENIED;

  auto newParent_path = parent_path(new_filename);

  std::lock_guard<std::recursive_mutex> lock(_filesnodes_mutex);
  if (!_directoryPaths.count(newParent_path)) {
    dbg_wprintf(L"Move: No directory: %s exist FilePath: %s\n", newParent_path.c_str(),
                 new_filename.c_str());
    return STATUS_OBJECT_PATH_NOT_FOUND;
  }

  // Remove destination
  remove(new_f);

  // Update current node with new data
  const auto fileName = f->get_filename();
  auto oldParentPath = parent_path(fileName);
  f->set_filename(new_filename);

  // Move fileNode
  // 1 - by removing current not with oldName as key
  add(f);

  // 2 - If fileNode is a Dir we move content to destination
  if (f->is_directory) {
    // recurse remove sub folders/files
    auto files = list_folder(old_filename);
    for (const auto& file : files) {
      const auto sub_fileName = file->get_filename();
      auto newSubFileName = parent_path(new_filename).append(L"\\").append(base_name(sub_fileName));
      auto n = move(sub_fileName, newSubFileName, replace_if_existing);
      if (n != STATUS_SUCCESS) {
        dbg_wprintf(
            L"Move: Subfolder file move %s to %s replaceIfExisting %b failed: "
            L"%d\n",
            sub_fileName.c_str(), newSubFileName.c_str(), replace_if_existing, n);
        return n;  // That's bad...we have not done a full move
      }
    }

    // remove folder from directories
    _directoryPaths.erase(old_filename);
  }

  // 3 - Remove fileNode link with oldFilename
  _filenodes.erase(old_filename);
  if (oldParentPath != newParent_path)  // Same folder destination
    _directoryPaths[oldParentPath].erase(f);

  dbg_wprintf(L"Move file: %s to folder: %s\n", old_filename.c_str(), new_filename.c_str());
  return STATUS_SUCCESS;
}
}  // namespace virtual_fs
