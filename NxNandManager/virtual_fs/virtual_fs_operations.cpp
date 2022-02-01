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

#include "virtual_fs_operations.h"
#include "virtual_fs_helper.h"

#include <sddl.h>
#include <iostream>
#include <mutex>
#include <sstream>
#include <unordered_map>
#ifndef FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL
#define FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL  0x20000000
#endif
namespace virtual_fs {
static const DWORD g_volumserial = 0x19831116;


static NTSTATUS create_main_stream(fs_filenodes* fs_filenodes, const std::wstring& filename,
                const std::pair<std::wstring, std::wstring>& stream_names,
                DWORD file_attributes_and_flags, PDOKAN_IO_SECURITY_CONTEXT security_context)
{
    // When creating a new a alternated stream, we need to be sure
    // the main stream exist otherwise we create it.
    auto main_stream_name = virtual_fs_helper::GetFileName(filename, stream_names);
    if (!fs_filenodes->find(main_stream_name))
    {
        dbg_wprintf(L"create_main_stream: we create the maing stream %ls\n", main_stream_name.c_str());
        auto n = fs_filenodes->add(std::make_shared<filenode>(
            main_stream_name, false, file_attributes_and_flags, security_context));
        if (n != STATUS_SUCCESS) return n;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_createfile(LPCWSTR filename, PDOKAN_IO_SECURITY_CONTEXT security_context,
                 ACCESS_MASK desiredaccess, ULONG fileattributes, ULONG /*shareaccess*/,
                 ULONG createdisposition,  ULONG createoptions, PDOKAN_FILE_INFO dokanfileinfo)
{
    auto filenodes = GET_FS_INSTANCE;
    ACCESS_MASK generic_desiredaccess;
    DWORD creation_disposition;
    DWORD file_attributes_and_flags;
    dokanfileinfo->Context = 0;
    DokanMapKernelToUserCreateFileFlags(
      desiredaccess, fileattributes, createoptions, createdisposition,
      &generic_desiredaccess, &file_attributes_and_flags,
      &creation_disposition);

    auto filename_str = std::wstring(filename);
    virtual_fs_helper::RemoveStreamType(filename_str);

    auto f = filenodes->find(filename_str);
    auto stream_names = virtual_fs_helper::GetStreamNames(filename_str);
    auto nxp = filenodes->nx_part;
    //if (!dokanfileinfo->IsDirectory)
    //    dbg_wprintf(L"CreateFile: %ls with node: %b\n", filename_str.c_str(), (f != nullptr));

    // We only support filename length under 255.
    // See GetVolumeInformation - MaximumComponentLength
    if (stream_names.first.length() > 255) return STATUS_OBJECT_NAME_INVALID;

    // Windows will automatically try to create and access different system
    // directories.
    if (filename_str == L"\\System Volume Information" ||
      filename_str == L"\\$RECYCLE.BIN") {
    return STATUS_NO_SUCH_FILE;
    }

    if (f && f->is_directory) {
    if (createoptions & FILE_NON_DIRECTORY_FILE)
        return STATUS_FILE_IS_A_DIRECTORY;
        dokanfileinfo->IsDirectory = true;
    }


    // TODO Use AccessCheck to check security rights
    if (dokanfileinfo->IsDirectory) {
        //dbg_wprintf(L"CreateFile: %ls is a Directory\n", filename_str.c_str());

        if (creation_disposition == CREATE_NEW ||
            creation_disposition == OPEN_ALWAYS) {

            if (nxp->parent->nxHandle->isReadOnly())
                return STATUS_WMI_READ_ONLY;

            //dbg_wprintf(L"CreateFile: %ls create Directory\n", filename_str.c_str());
            // Cannot create a stream as directory.
            if (!stream_names.second.empty()) return STATUS_NOT_A_DIRECTORY;

            if (f) return STATUS_OBJECT_NAME_COLLISION;

            auto newfileNode = std::make_shared<filenode>(
              filename_str, true, FILE_ATTRIBUTE_DIRECTORY, security_context);

            if(nxp->f_mkdir(filename_str.c_str()))
              return STATUS_OBJECT_PATH_NOT_FOUND;

            return filenodes->add(newfileNode);
        }

        if (f && !f->is_directory) return STATUS_NOT_A_DIRECTORY;
        if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;

        //dbg_wprintf(L"CreateFile: %ls open Director\ny", filename_str.c_str());
    } else {
        //dbg_wprintf(L"CreateFile: %ls is a File\n", filename_str.c_str());

        if (nxp->parent->nxHandle->isReadOnly() && creation_disposition != OPEN_EXISTING)
            return STATUS_WMI_READ_ONLY;

        // Cannot overwrite an hidden or system file.
        if (f && (((!(file_attributes_and_flags & FILE_ATTRIBUTE_HIDDEN) &&
                    (f->attributes & FILE_ATTRIBUTE_HIDDEN)) ||
                   (!(file_attributes_and_flags & FILE_ATTRIBUTE_SYSTEM) &&
                    (f->attributes & FILE_ATTRIBUTE_SYSTEM))) &&
                  (creation_disposition == TRUNCATE_EXISTING ||
                   creation_disposition == CREATE_ALWAYS)))
          return STATUS_ACCESS_DENIED;

        // Cannot delete a file with readonly attributes.
        if ((f && (f->attributes & FILE_ATTRIBUTE_READONLY) ||
             (file_attributes_and_flags & FILE_ATTRIBUTE_READONLY)) &&
            (file_attributes_and_flags & FILE_FLAG_DELETE_ON_CLOSE))
          return STATUS_CANNOT_DELETE;

        // Cannot open a readonly file for writing.
        if ((creation_disposition == OPEN_ALWAYS ||
             creation_disposition == OPEN_EXISTING) &&
            f && (f->attributes & FILE_ATTRIBUTE_READONLY) &&
            desiredaccess & FILE_WRITE_DATA)
          return STATUS_ACCESS_DENIED;

        // Cannot overwrite an existing read only file.
        // FILE_SUPERSEDE can as it replace and not overwrite.
        if ((creation_disposition == CREATE_NEW ||
             (creation_disposition == CREATE_ALWAYS &&
              createdisposition != FILE_SUPERSEDE) ||
             creation_disposition == TRUNCATE_EXISTING) &&
            f && (f->attributes & FILE_ATTRIBUTE_READONLY))
          return STATUS_ACCESS_DENIED;

        if (creation_disposition == CREATE_NEW ||
            creation_disposition == CREATE_ALWAYS ||
            creation_disposition == OPEN_ALWAYS ||
            creation_disposition == TRUNCATE_EXISTING) {
          // Combines the file attributes and flags specified by
          // dwFlagsAndAttributes with FILE_ATTRIBUTE_ARCHIVE.
          file_attributes_and_flags |= FILE_ATTRIBUTE_ARCHIVE;
          // We merge the attributes with the existing file attributes
          // except for FILE_SUPERSEDE.
          if (f && createdisposition != FILE_SUPERSEDE)
            file_attributes_and_flags |= f->attributes;
          // Remove non specific attributes.
          file_attributes_and_flags &= ~FILE_ATTRIBUTE_STRICTLY_SEQUENTIAL;
          // FILE_ATTRIBUTE_NORMAL is override if any other attribute is set.
          file_attributes_and_flags &= ~FILE_ATTRIBUTE_NORMAL;
        }

        auto alloc_NxFile = [&](BYTE desiredAccess)
        {
            NxFile *ffile = f ? f->get_nxfile() : nullptr;
            NxFileFlag options = nxp->vfs()->virtualize_nxa ? VirtualizeNXA : SimpleFile;
            NxFile *file = new NxFile(nxp, ffile ? ffile->completePath().c_str() : filename_str.c_str(), options);
            if (!file->open(desiredAccess)) {
                delete file;
                file = nullptr;
                return file;
            }
            dokanfileinfo->Context = reinterpret_cast<ULONG64>(file);
            return file;
        };
        NxFile* nxFile = nullptr;
        switch (creation_disposition) {
            case CREATE_ALWAYS: {
                dbg_wprintf(L"CreateFile: %ls CREATE_ALWAYS\n", filename_str.c_str());
                /*
                 * Creates a new file, always.
                 *
                 * We handle FILE_SUPERSEDE here as it is converted to TRUNCATE_EXISTING
                 * by DokanMapKernelToUserCreateFileFlags.
                 */

                if (!stream_names.second.empty()) {
                  // The createfile is a alternate stream,
                  // we need to be sure main stream exist
                  auto n =
                      create_main_stream(filenodes, filename_str, stream_names,
                                         file_attributes_and_flags, security_context);
                  if (n != STATUS_SUCCESS) return n;
                }
                // Alloc new file handle
                else if (!(nxFile = alloc_NxFile(FA_CREATE_ALWAYS | FA_READ | FA_WRITE)))
                    return STATUS_OBJECT_PATH_INVALID;

                if (f) return STATUS_OBJECT_NAME_COLLISION;

                auto n = filenodes->add(std::make_shared<filenode>(filename_str, false, file_attributes_and_flags, security_context,
                                                                   nxFile ? new NxFile(nxp, nxFile->completePath().c_str(), nxp->vfs()->virtualize_nxa ? VirtualizeNXA : SimpleFile) : nullptr));
                if (n != STATUS_SUCCESS) return n;

              } break;
            case CREATE_NEW: {
                dbg_wprintf(L"CreateFile: %ls CREATE_ALWAYS\n", filename_str.c_str());
                /*
                 * Creates a new file, only if it does not already exist.
                 */
                if (f) return STATUS_OBJECT_NAME_COLLISION;

                if (!stream_names.second.empty()) {
                  // The createfile is a alternate stream,
                  // we need to be sure main stream exist
                  auto n =
                      create_main_stream(filenodes, filename_str, stream_names,
                                         file_attributes_and_flags, security_context);
                  if (n != STATUS_SUCCESS) return n;
                }
                // Alloc new file handle
                else if (!(nxFile = alloc_NxFile(FA_CREATE_NEW | FA_READ | FA_WRITE)))
                    return STATUS_OBJECT_PATH_INVALID;

                auto n = filenodes->add(std::make_shared<filenode>(filename_str, false, file_attributes_and_flags, security_context,
                                                                   nxFile ? new NxFile(nxp, nxFile->completePath().c_str(), nxp->vfs()->virtualize_nxa ? VirtualizeNXA : SimpleFile) : nullptr));
                if (n != STATUS_SUCCESS) return n;
              } break;
              case OPEN_ALWAYS: {
                dbg_wprintf(L"CreateFile: %ls OPEN_ALWAYS\n", filename_str.c_str());
                /*
                 * Opens a file, always.
                 */

                // Alloc new file handle
                if (!(nxFile = alloc_NxFile(FA_OPEN_ALWAYS | FA_READ | FA_WRITE)))
                    return STATUS_OBJECT_PATH_INVALID;

                if (!f) {
                    auto n = filenodes->add(std::make_shared<filenode>(
                      filename_str, false, file_attributes_and_flags,
                      security_context, nxFile ? new NxFile(nxp, nxFile->completePath().c_str(), nxp->vfs()->virtualize_nxa ? VirtualizeNXA : SimpleFile) : nullptr));
                    if (n != STATUS_SUCCESS) return n;
                } else {
                  if (desiredaccess & FILE_EXECUTE) {
                    f->times.lastaccess = filetimes::get_currenttime();
                  }
                }
              } break;
            case OPEN_EXISTING: {
                dbg_wprintf(L"CreateFile: %ls OPEN_EXISTING\n", filename_str.c_str());
                /*
                 * Opens a file or device, only if it exists.
                 * If the specified file or device does not exist, the function fails
                 * and the last-error code is set to ERROR_FILE_NOT_FOUND
                 */
                if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;

                // Alloc new file handle
                if (!alloc_NxFile(FA_OPEN_EXISTING | FA_WRITE | FA_READ))
                    return STATUS_OBJECT_NAME_NOT_FOUND;

                if (desiredaccess & FILE_EXECUTE) {
                  f->times.lastaccess = filetimes::get_currenttime();
                }

              } break;
              case TRUNCATE_EXISTING: {
                dbg_wprintf(L"CreateFile: %ls TRUNCATE_EXISTING\n", filename_str.c_str());
                /*
                 * Opens a file and truncates it so that its size is zero bytes, only if
                 * it exists. If the specified file does not exist, the function fails
                 * and the last-error code is set to ERROR_FILE_NOT_FOUND
                 */
                if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;

                // Alloc new file handle
                if (!(nxFile = alloc_NxFile(FA_OPEN_EXISTING | FA_WRITE | FA_READ)))
                    return STATUS_OBJECT_NAME_NOT_FOUND;

                nxFile->seek(0);
                nxFile->truncate();

                f->set_endoffile(0);
                f->times.lastaccess = f->times.lastwrite = filetimes::get_currenttime();
                f->attributes = file_attributes_and_flags;             

              } break;
              default:
                dbg_wprintf(L"CreateFile: %ls Unknown CreationDisposition %d\n",
                             filename_str.c_str(), creation_disposition);
                break;
            }
    }

    /*
    * CREATE_NEW && OPEN_ALWAYS
    * If the specified file exists, the function fails and the last-error code is
    * set to ERROR_FILE_EXISTS
    */
    if (f && (creation_disposition == CREATE_NEW ||
            creation_disposition == OPEN_ALWAYS))
    return STATUS_OBJECT_NAME_COLLISION;


    if (!dokanfileinfo->IsDirectory && isdebug)
        {
            wstring dbg;
            if (creation_disposition == CREATE_NEW)
                dbg.append(L"CREATE_NEW\n");
            if (creation_disposition == OPEN_ALWAYS)
                dbg.append(L"OPEN_ALWAYS\n");
            if (creation_disposition == OPEN_EXISTING)
                dbg.append(L"OPEN_EXISTING\n");
            if (creation_disposition == CREATE_ALWAYS)
                dbg.append(L"CREATE_ALWAYS\n");

            if (desiredaccess & FILE_WRITE_DATA)
                dbg.append(L"FILE_WRITE_DATA\n");
            if (desiredaccess & FILE_READ_DATA)
                dbg.append(L"FILE_READ_DATA\n");
            if (desiredaccess & FILE_APPEND_DATA)
                dbg.append(L"FILE_APPEND_DATA\n");
            if (desiredaccess & FILE_EXECUTE)
                dbg.append(L"FILE_EXECUTE\n");
            if (desiredaccess & FILE_APPEND_DATA)
                dbg.append(L"FILE_APPEND_DATA\n");
            if (desiredaccess & FILE_WRITE_ATTRIBUTES)
                dbg.append(L"FILE_WRITE_ATTRIBUTES\n");
            if (desiredaccess & FILE_GENERIC_READ)
                dbg.append(L"FILE_GENERIC_READ\n");
            if (desiredaccess & FILE_GENERIC_WRITE)
                dbg.append(L"FILE_GENERIC_WRITE\n");

            dbg_wprintf(L"### CreateFile %ls [Ctx ptr %ld]\n%ls", filename_str.c_str(), dokanfileinfo->Context, dbg.c_str());
        }

    return STATUS_SUCCESS;
}

static void DOKAN_CALLBACK virtual_fs_cleanup(LPCWSTR filename,
                                         PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto nxp = filenodes->nx_part;
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"Cleanup: %ls\n", filename_str.c_str());
  bool hasContext = dokanfileinfo->Context;
  if (dokanfileinfo->DeleteOnClose) {
      if (dokanfileinfo->IsDirectory) {
          dbg_printf("Delete on close, remove directory\n");
          nxp->f_unlink(filename_str.c_str());
      }
      else if (hasContext) {
        dbg_printf("Delete on close, remove nx file\n");
        GET_FILE_INSTANCE->remove();
      }
      else dbg_printf("Delete on close, NO CONTEXT\n");
      filenodes->remove(filename_str);
  }
  if (hasContext) {
      delete GET_FILE_INSTANCE;
      dokanfileinfo->Context = 0;
  }
}

static void DOKAN_CALLBACK virtual_fs_closeFile(LPCWSTR filename,
                                           PDOKAN_FILE_INFO dokanfileinfo) {

  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"CloseFile: %ls\n", filename_str.c_str());
  // Here we should release all resources from the createfile context if we had.
  if (dokanfileinfo->Context)
  {
      dbg_printf("ClodeFile has context, close nxFile\n");
      auto nxFile = GET_FILE_INSTANCE;
      nxFile->close();
  }
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_readfile(LPCWSTR filename, LPVOID buffer,
                                              DWORD bufferlength,
                                              LPDWORD readlength,
                                              LONGLONG offset,
                                              PDOKAN_FILE_INFO dokanfileinfo) {
    auto filenodes = GET_FS_INSTANCE;
    auto filename_str = std::wstring(filename);

    // Alternate stream
    if (filename_str.find_first_of(L":") != std::wstring::npos)
    {
        *readlength = bufferlength;
        return STATUS_SUCCESS;
    }
    auto f = filenodes->find(filename_str);
    if (!f || !dokanfileinfo->Context)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    auto nxFile = GET_FILE_INSTANCE;
    return nxFile->read((u64)offset, (void*)buffer, bufferlength, (u32*)readlength);
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_writefile(LPCWSTR filename, LPCVOID buffer,
                                               DWORD number_of_bytes_to_write,
                                               LPDWORD number_of_bytes_written,
                                               LONGLONG offset,
                                               PDOKAN_FILE_INFO dokanfileinfo) {

    auto filenodes = GET_FS_INSTANCE;
    auto filename_str = std::wstring(filename);

    // Alternate stream
    if (filename_str.find_first_of(L":") != std::wstring::npos)
    {
        *number_of_bytes_written = number_of_bytes_to_write;
        return STATUS_SUCCESS;
    }

    dbg_wprintf(L"WriteFile: %ls (Ctx: %I64d)\n", filename_str.c_str(), dokanfileinfo->Context);
    auto f = filenodes->find(filename_str);
    if (!f || !dokanfileinfo->Context)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    auto file_size = f->get_filesize();
    auto nxFile = GET_FILE_INSTANCE;

    if (!nxFile->isNXA() && file_size >= 0xFFFFFFFF) // FAT32 limit
        return STATUS_FILE_TOO_LARGE;

    // An Offset -1 is like the file was opened with FILE_APPEND_DATA
    // and we need to write at the end of the file.
    if (offset == -1) offset = file_size;

    if (dokanfileinfo->PagingIo) {
        // PagingIo cannot extend file size.
        // We return STATUS_SUCCESS when offset is beyond fileSize
        // and write the maximum we are allowed to.
        if (offset >= file_size) {
            dbg_wprintf(L"\tPagingIo Outside offset: %ld FileSize: %d\n", offset,
                       file_size);
            *number_of_bytes_written = 0;
            return STATUS_SUCCESS;
        }

        if ((offset + number_of_bytes_to_write) > file_size) {
            // resize the write length to not go beyond file size.
            LONGLONG bytes = file_size - offset;
            if (bytes >> 32) {
            number_of_bytes_to_write = static_cast<DWORD>(bytes & 0xFFFFFFFFUL);
            } else {
            number_of_bytes_to_write = static_cast<DWORD>(bytes);
            }
        }
        dbg_wprintf(L"\tPagingIo number_of_bytes_to_write: %d\n",
                     number_of_bytes_to_write);
    }

    auto res = nxFile->write((u64)offset, (void*)buffer, number_of_bytes_to_write, (u32*)number_of_bytes_written);

    if (offset + *number_of_bytes_written > f->size)
        f->set_endoffile(offset + *number_of_bytes_written);

    return res ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_flushfilebuffers(LPCWSTR filename, PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"FlushFileBuffers: %ls\n", filename_str.c_str());
  auto f = filenodes->find(filename_str);
  // Nothing to flush, we directly write the content into our buffer.

  /*if (f->main_stream) f = f->main_stream;*/
  f->times.lastaccess = f->times.lastwrite = filetimes::get_currenttime();

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_getfileInformation(LPCWSTR filename, LPBY_HANDLE_FILE_INFORMATION buffer,
                         PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"GetFileInformation: %ls (Ctx %I64d)\n", filename_str.c_str(), dokanfileinfo->Context);
  auto f = filenodes->find(filename_str);
  if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;
  buffer->dwFileAttributes = f->attributes;
  virtual_fs_helper::LlongToFileTime(f->times.creation, buffer->ftCreationTime);
  virtual_fs_helper::LlongToFileTime(f->times.lastaccess, buffer->ftLastAccessTime);
  virtual_fs_helper::LlongToFileTime(f->times.lastwrite, buffer->ftLastWriteTime);
  auto strLength = f->get_filesize();
  virtual_fs_helper::LlongToDwLowHigh(strLength, buffer->nFileSizeLow,
                                 buffer->nFileSizeHigh);
  virtual_fs_helper::LlongToDwLowHigh(f->fileindex, buffer->nFileIndexLow,
                                 buffer->nFileIndexHigh);
  // We do not track the number of links to the file so we return a fake value.
  buffer->nNumberOfLinks = 1;
  buffer->dwVolumeSerialNumber = g_volumserial;
    /*
  dbg_wprintf(
      L"GetFileInformation: %ls Attributes: %d Times: Creation %ld "
      L"LastAccess %ld LastWrite %ld FileSize %ld NumberOfLinks %d "
      L"VolumeSerialNumber %d",
      filename_str.c_str(), f->attributes, f->times.creation, f->times.lastaccess,
      f->times.lastwrite, strLength, buffer->nNumberOfLinks,
      buffer->dwVolumeSerialNumber);
    */
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_findfiles(LPCWSTR filename,
                                               PFillFindData fill_finddata,
                                               PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  auto files = filenodes->list_folder(filename_str);
  WIN32_FIND_DATAW findData;
  //dbg_wprintf(L"FindFiles: %ls\n", filename_str.c_str());
  ZeroMemory(&findData, sizeof(WIN32_FIND_DATAW));
  for (const auto& f : files) {
    if (f->main_stream) continue; // Do not list File Streams
    const auto fileNodeName = f->get_filename();
    //auto fileName = std::filesystem::path(fileNodeName).filename().wstring();
    auto fileName = base_name(fileNodeName);
    if (fileName.length() > MAX_PATH) continue;
    std::copy(fileName.begin(), fileName.end(), std::begin(findData.cFileName));
    findData.cFileName[fileName.length()] = '\0';
    findData.dwFileAttributes = f->attributes;
    virtual_fs_helper::LlongToFileTime(f->times.creation, findData.ftCreationTime);
    virtual_fs_helper::LlongToFileTime(f->times.lastaccess,
                                  findData.ftLastAccessTime);
    virtual_fs_helper::LlongToFileTime(f->times.lastwrite, findData.ftLastWriteTime);
    auto file_size = f->get_filesize();
    virtual_fs_helper::LlongToDwLowHigh(file_size, findData.nFileSizeLow,
                                   findData.nFileSizeHigh);

    //dbg_wprintf(L"FindFiles: %ls\n", filename_str.c_str());
    /*
    spdlog::info(
        L"FindFiles: {} fileNode: {} Attributes: {} Times: Creation {} "
        L"LastAccess {} LastWrite {} FileSize {}",
        filename_str, fileNodeName, findData.dwFileAttributes,
        f->times.creation, f->times.lastaccess, f->times.lastwrite, file_size);
        */
    fill_finddata(&findData, dokanfileinfo);
  }
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_setfileattributes(
    LPCWSTR filename, DWORD fileattributes, PDOKAN_FILE_INFO dokanfileinfo) {
    auto filenodes = GET_FS_INSTANCE;
    auto nxp = filenodes->nx_part;
    auto filename_str = std::wstring(filename);
    auto f = filenodes->find(filename_str);
    dbg_wprintf(L"SetFileAttributes: %ls fileattributes %d\n", filename_str.c_str(), fileattributes);
    if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;
    // No attributes need to be changed
    if (fileattributes == 0) return STATUS_SUCCESS;

    // FILE_ATTRIBUTE_NORMAL is override if any other attribute is set
    if (fileattributes & FILE_ATTRIBUTE_NORMAL &&
      (fileattributes & (fileattributes - 1)))
    fileattributes &= ~FILE_ATTRIBUTE_NORMAL;

    //f->attributes = fileattributes;
    if (fileattributes == FILE_ATTRIBUTE_ARCHIVE && f->is_directory)
      f->attributes = 0x30;
    if (!f->is_directory)
      f->attributes = fileattributes;

    if (!f->is_directory && dokanfileinfo->Context && !GET_FILE_INSTANCE->setFileAttr(f->attributes))
        return STATUS_OBJECT_NAME_NOT_FOUND;

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_setfiletime(LPCWSTR filename, CONST FILETIME* creationtime,
                  CONST FILETIME* lastaccesstime, CONST FILETIME* lastwritetime,
                  PDOKAN_FILE_INFO dokanfileinfo) {
    auto filenodes = GET_FS_INSTANCE;
    auto nxp = filenodes->nx_part;
    auto filename_str = std::wstring(filename);
    auto f = filenodes->find(filename_str);
    dbg_wprintf(L"SetFileTime: %ls\n", filename_str.c_str());
    if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (creationtime && !filetimes::empty(creationtime))
    f->times.creation = virtual_fs_helper::FileTimeToLlong(*creationtime);
    if (lastaccesstime && !filetimes::empty(lastaccesstime))
    f->times.lastaccess = virtual_fs_helper::FileTimeToLlong(*lastaccesstime);
    if (lastwritetime && !filetimes::empty(lastwritetime))
    f->times.lastwrite = virtual_fs_helper::FileTimeToLlong(*lastwritetime);

    if (!creationtime && filetimes::empty(creationtime))
        return STATUS_SUCCESS;

    if (dokanfileinfo->Context && !GET_FILE_INSTANCE->setFileTime(creationtime))
        return STATUS_OBJECT_NAME_NOT_FOUND;

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_deletefile(LPCWSTR filename, PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  auto f = filenodes->find(filename_str);
  dbg_wprintf(L"DeleteFile: %ls\n", filename_str.c_str());

  if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;

  if (f->is_directory) return STATUS_ACCESS_DENIED;

  auto nxp = filenodes->nx_part;
  if (nxp->parent->nxHandle->isReadOnly())
      return STATUS_WMI_READ_ONLY;

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_deletedirectory(LPCWSTR filename, PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"DeleteDirectory: %ls\n", filename_str.c_str());

  if (filenodes->list_folder(filename_str).size())
    return STATUS_DIRECTORY_NOT_EMPTY;

  auto nxp = filenodes->nx_part;
  if (nxp->parent->nxHandle->isReadOnly())
      return STATUS_WMI_READ_ONLY;

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_movefile(LPCWSTR filename,
                                              LPCWSTR new_filename,
                                              BOOL replace_if_existing,
                                              PDOKAN_FILE_INFO dokanfileinfo) {
    auto filenodes = GET_FS_INSTANCE;
    auto nxp = filenodes->nx_part;
    auto filename_str = std::wstring(filename);
    auto f = filenodes->find(filename_str);;
    if (!f)
         return STATUS_OBJECT_NAME_NOT_FOUND;

    auto new_filename_str = std::wstring(new_filename);
    auto new_f = filenodes->find(new_filename_str);

    dbg_wprintf(L"MoveFile: %ls to %ls\n", filename_str.c_str(), new_filename_str.c_str());

    if (!replace_if_existing && new_f)
        return STATUS_OBJECT_NAME_COLLISION;

    int res = FR_INVALID_OBJECT;
    if (dokanfileinfo->IsDirectory)
        res = nxp->f_rename(filename, new_filename);
    else
    {
        auto nxFile = f->get_nxfile();
        if (!nxFile)
            return STATUS_OBJECT_NAME_NOT_FOUND;

        if ((res = nxFile->rename(new_filename_str)) == FR_OK && dokanfileinfo->Context)
            GET_FILE_INSTANCE->setCompletePath(new_filename_str);
    }

    if (res != FR_OK)
        return STATUS_ACCESS_DENIED;

    dbg_wprintf(L"MoveFile: after %ls to %ls\n", filename_str.c_str(), new_filename_str.c_str());
    return filenodes->move(filename_str, new_filename_str, replace_if_existing);
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_setendoffile(
    LPCWSTR filename, LONGLONG ByteOffset, PDOKAN_FILE_INFO dokanfileinfo) {

    auto filenodes = GET_FS_INSTANCE;
    auto nxp = GET_FS_INSTANCE->nx_part;
    auto filename_str = std::wstring(filename);
    dbg_wprintf(L"SetEndOfFile: %ls ByteOffset %ld\n", filename_str.c_str(), ByteOffset);
    auto f = filenodes->find(filename_str);

    if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;

    if (ByteOffset < f->size && dokanfileinfo->Context)
    {
        auto nxFile = GET_FILE_INSTANCE;

        if (!nxFile->seek((u64)ByteOffset))
            return STATUS_OBJECT_NAME_NOT_FOUND;

        if (nxFile->truncate() != FR_OK)
            return STATUS_OBJECT_NAME_NOT_FOUND;
    }

    f->set_endoffile(ByteOffset);

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_setallocationsize(
    LPCWSTR filename, LONGLONG alloc_size, PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"SetAllocationSize: %ls AllocSize %d\n", filename_str.c_str(), alloc_size);
  auto f = filenodes->find(filename_str);

  if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;
  //f->set_endoffile(alloc_size);
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_lockfile(LPCWSTR filename,
                                              LONGLONG byte_offset,
                                              LONGLONG length,
                                              PDOKAN_FILE_INFO dokanfileinfo) {
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"LockFile: %ls ByteOffset %ld Length %d", filename_str.c_str(),
               byte_offset, length);
  return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_unlockfile(LPCWSTR filename, LONGLONG byte_offset, LONGLONG length,
                 PDOKAN_FILE_INFO dokanfileinfo) {
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"UnlockFile: %ls ByteOffset %ld Length %d\n", filename_str.c_str(),
               byte_offset, length);
  return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_getdiskfreespace(
    PULONGLONG free_bytes_available, PULONGLONG total_number_of_bytes,
    PULONGLONG total_number_of_free_bytes, PDOKAN_FILE_INFO dokanfileinfo) {
  //dbg_wprintf(L"GetDiskFreeSpace\n");
  auto nxp = GET_FS_INSTANCE->nx_part;
  auto fs = nxp->fs();
  u64 tb = (u64)fs->n_fatent * (u64)fs->csize * (u64)512;
  u64 fb = 0;
  if (!fs->free_clst || fs->free_clst == 0xFFFFFFFF)
  {
      DWORD free_clst;
      nxp->f_getfree(L"", &free_clst, &fs);
      tb = (u64)free_clst * (u64)fs->csize * (u64)512;
  }
  else fb = (u64)fs->free_clst * (u64)fs->csize * (u64)512;

  *free_bytes_available = (ULONGLONG)fb;
  *total_number_of_bytes = (ULONGLONG)tb;
  *total_number_of_free_bytes = (ULONGLONG)fb;
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_getvolumeinformation(
    LPWSTR volumename_buffer, DWORD volumename_size,
    LPDWORD volume_serialnumber, LPDWORD maximum_component_length,
    LPDWORD filesystem_flags, LPWSTR filesystem_name_buffer,
    DWORD filesystem_name_size, PDOKAN_FILE_INFO dokanfileinfo) {
  //dbg_wprintf(L"GetVolumeInformation\n");
    auto fileNodes = GET_FS_INSTANCE;
    auto nx_part = fileNodes->nx_part;
    std::wstring name(convertCharArrayToLPWSTR(nx_part->partitionName().c_str()));
    name.append(L" (NxNandManager)");
    wcscpy_s(volumename_buffer, volumename_size, name.c_str());
    *volume_serialnumber = fileNodes->volumeSerial;
    *maximum_component_length = 255;
    *filesystem_flags = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
                      FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
                      FILE_NAMED_STREAMS;

    wcscpy_s(filesystem_name_buffer, filesystem_name_size, L"FAT32");
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_mounted(PDOKAN_FILE_INFO dokanfileinfo) {
    auto mountPoint = GET_FS_INSTANCE->mount_point;
    auto nxp = GET_FS_INSTANCE->nx_part;
    nxp->setVolumeMountPoint(mountPoint);
    std::wstring m(mountPoint);
    transform(m.begin(), m.end(), m.begin(), towupper);
    wprintf(L"Partition %ls mounted (%ls)\n", convertCharArrayToLPWSTR(nxp->partitionName().c_str()), m.c_str());
    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_unmounted(PDOKAN_FILE_INFO dokanfileinfo) {
    auto nxp = GET_FS_INSTANCE->nx_part;
    nxp->setVolumeMountPoint(nullptr);
    printf("Partition %s unmounted\n", nxp->partitionName().c_str());

    return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_getfilesecurity(
    LPCWSTR filename, PSECURITY_INFORMATION security_information,
    PSECURITY_DESCRIPTOR security_descriptor, ULONG bufferlength,
    PULONG length_needed, PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  //dbg_wprintf(L"GetFileSecurity: %ls\n", filename_str.c_str());
  auto f = filenodes->find(filename_str);

  if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;

  std::lock_guard<std::mutex> lockFile(f->security);

  // This will make dokan library return a default security descriptor
  if (!f->security.descriptor) return STATUS_NOT_IMPLEMENTED;

  // We have a Security Descriptor but we need to extract only informations
  // requested 1 - Convert the Security Descriptor to SDDL string with the
  // informations requested
  LPTSTR pStringBuffer = NULL;
  if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
          f->security.descriptor.get(), SDDL_REVISION_1, *security_information,
          &pStringBuffer, NULL)) {
    return STATUS_NOT_IMPLEMENTED;
  }

  // 2 - Convert the SDDL string back to Security Descriptor
  PSECURITY_DESCRIPTOR SecurityDescriptorTmp = NULL;
  ULONG Size = 0;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
          pStringBuffer, SDDL_REVISION_1, &SecurityDescriptorTmp, &Size)) {
    LocalFree(pStringBuffer);
    return STATUS_NOT_IMPLEMENTED;
  }
  LocalFree(pStringBuffer);

  *length_needed = Size;
  if (Size > bufferlength) {
    LocalFree(SecurityDescriptorTmp);
    return STATUS_BUFFER_OVERFLOW;
  }

  // 3 - Copy the new SecurityDescriptor to destination
  memcpy(security_descriptor, SecurityDescriptorTmp, Size);
  LocalFree(SecurityDescriptorTmp);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK virtual_fs_setfilesecurity(
    LPCWSTR filename, PSECURITY_INFORMATION security_information,
    PSECURITY_DESCRIPTOR security_descriptor, ULONG /*bufferlength*/,
    PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"SetFileSecurity: %ls\n", filename_str.c_str());
  static GENERIC_MAPPING virtual_fs_mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                                          FILE_GENERIC_EXECUTE,
                                          FILE_ALL_ACCESS};
  auto f = filenodes->find(filename_str);

  if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;

  std::lock_guard<std::mutex> securityLock(f->security);

  // SetPrivateObjectSecurity - ObjectsSecurityDescriptor
  // The memory for the security descriptor must be allocated from the process
  // heap (GetProcessHeap) with the HeapAlloc function.
  // https://devblogs.microsoft.com/oldnewthing/20170727-00/?p=96705
  HANDLE pHeap = GetProcessHeap();
  PSECURITY_DESCRIPTOR heapSecurityDescriptor =
      HeapAlloc(pHeap, 0, f->security.descriptor_size);
  if (!heapSecurityDescriptor)
      return STATUS_INSUFFICIENT_RESOURCES;
  // Copy our current descriptor into heap memory
  memcpy(heapSecurityDescriptor, f->security.descriptor.get(),
         f->security.descriptor_size);

  if (!SetPrivateObjectSecurity(*security_information, security_descriptor,
                                &heapSecurityDescriptor, &virtual_fs_mapping, 0)) {
    HeapFree(pHeap, 0, heapSecurityDescriptor);
    return DokanNtStatusFromWin32(GetLastError());
  }

  f->security.SetDescriptor(heapSecurityDescriptor);
  HeapFree(pHeap, 0, heapSecurityDescriptor);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
virtual_fs_findstreams(LPCWSTR filename, PFillFindStreamData fill_findstreamdata,
                  PDOKAN_FILE_INFO dokanfileinfo) {
  auto filenodes = GET_FS_INSTANCE;
  auto filename_str = std::wstring(filename);
  dbg_wprintf(L"FindStreams: %ls\n", filename_str.c_str());
  auto f = filenodes->find(filename_str);

  if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;
  /*
  auto streams = f->get_streams();
  WIN32_FIND_STREAM_DATA stream_data;
  ZeroMemory(&stream_data, sizeof(WIN32_FIND_STREAM_DATA));
  if (!f->is_directory) {
    // Add the main stream name - \foo::$DATA by returning ::$DATA
    std::copy(DataStreamNameStr.begin(),
              DataStreamNameStr.end(),
              std::begin(stream_data.cStreamName) + 1);
    stream_data.cStreamName[0] = ':';
    stream_data.cStreamName[DataStreamNameStr.length() + 1] = L'\0';
    stream_data.StreamSize.QuadPart = f->get_filesize();
    fill_findstreamdata(&stream_data, dokanfileinfo);
  } else if (streams.empty()) {
    // The node is a directory without any alternate streams
    return STATUS_END_OF_FILE;
  }
  // Add the alternated stream attached
  // for \foo:bar we need to return in the form of bar:$DATA
  for (const auto& stream : streams) {
    auto stream_names = virtual_fs_helper::GetStreamNames(stream.first);
    if (stream_names.second.length() + DataStreamNameStr.length() +
            1 >
        sizeof(stream_data.cStreamName))
      continue;
    // Copy the filename foo
    std::copy(stream_names.second.begin(), stream_names.second.end(),
              std::begin(stream_data.cStreamName) + 1);
    // Concat :$DATA
    std::copy(
        DataStreamNameStr.begin(),
        DataStreamNameStr.end(),
        std::begin(stream_data.cStreamName) + stream_names.second.length() + 1);
    stream_data.cStreamName[0] = ':';
    stream_data.cStreamName[stream_names.second.length() +
                            DataStreamNameStr.length() + 1] = L'\0';
    stream_data.StreamSize.QuadPart = stream.second->get_filesize();
    dbg_wprintf(L"FindStreams: %ls StreamName: %ls Size: %d", filename_str.c_str(),
                 stream_names.second.c_str(), stream_data.StreamSize.QuadPart);
    fill_findstreamdata(&stream_data, dokanfileinfo);
  }
  */
  return STATUS_SUCCESS;
}

DOKAN_OPERATIONS virtual_fs_operations = {virtual_fs_createfile,
                                     virtual_fs_cleanup,
                                     virtual_fs_closeFile,
                                     virtual_fs_readfile,
                                     virtual_fs_writefile,
                                     virtual_fs_flushfilebuffers,
                                     virtual_fs_getfileInformation,
                                     virtual_fs_findfiles,
                                     nullptr,  // FindFilesWithPattern
                                     virtual_fs_setfileattributes,
                                     virtual_fs_setfiletime,
                                     virtual_fs_deletefile,
                                     virtual_fs_deletedirectory,
                                     virtual_fs_movefile,
                                     virtual_fs_setendoffile,
                                     virtual_fs_setallocationsize,
                                     virtual_fs_lockfile,
                                     virtual_fs_unlockfile,
                                     virtual_fs_getdiskfreespace,
                                     virtual_fs_getvolumeinformation,
                                     virtual_fs_mounted,
                                     virtual_fs_unmounted,
                                     virtual_fs_getfilesecurity,
                                     virtual_fs_setfilesecurity,
                                     virtual_fs_findstreams};
}  // namespace virtual_fs
