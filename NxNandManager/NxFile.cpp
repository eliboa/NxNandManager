#include "NxFile.h"

NxFile::NxFile(NxPartition* nxp, const wstring &name, NxFileFlag options)
 : m_nxp(nxp), m_options(options)
{
    memset(m_user_id, 0, 0x10);
    setCompletePath(name);
    _file_mutex = new std::mutex();

    // Controls
    FILINFO fno;
    if (!m_filename.length())
        m_fileStatus = NX_INVALID_PATH;
    else if (!is_valid_nxp())
        m_fileStatus = NX_INVALID_PART;
    else if (m_nxp->isEncryptedPartition() && (!m_nxp->crypto() || m_nxp->badCrypto()))
        m_fileStatus = NX_BAD_CRYPTO;
    else if (!m_nxp->is_mounted())
        m_fileStatus = NX_NO_FILESYSTEM;
    else if (m_nxp->f_stat(this->completePath().c_str(), &fno)) // fs access
        m_fileStatus = NX_NO_FILE;
    else if (fno.fattrib == FILE_ATTRIBUTE_DIRECTORY)
        m_fileStatus = NX_IS_DIRECTORY;
    else
        m_fileStatus = NX_FILE;

    if (m_fileStatus != NX_FILE)
        return;

    m_size = (u64) fno.fsize;
    m_fdate = fno.fdate;
    m_ftime = fno.ftime;
    m_fattrib = fno.fattrib;

    if (m_fattrib == FILE_ATTRIBUTE_NX_ARCHIVE)
    {
        // Nintendo archive
        // Data is stored in one or several files (00, 01, 02, etc) inside a directory
        m_fileType = NX_NCA;

        if (m_options & VirtualizeNXA)
        {
            m_size = 0;
            DIR dp;
            FILINFO sub_fno;
            if (m_nxp->f_opendir(&dp, this->completePath().c_str())) {
                m_fileStatus = NX_NO_FILE;
                return;
            }
            while (!m_nxp->f_readdir(&dp, &sub_fno) && sub_fno.fname[0]) {
                NxSplitOff f_entry;
                f_entry.off_start = m_size;
                f_entry.size = sub_fno.fsize;
                f_entry.file = wstring(sub_fno.fname);
                m_size += (u64)sub_fno.fsize;
                m_files.emplace_back(f_entry);
                dbg_wprintf(L"NxFile: new NxSplitOff for %ls, off_start= %I64D, size= %I64D",
                            sub_fno.fname, f_entry.off_start, f_entry.size);
            }
            f_closedir(&dp);

            if (!m_size)
                return;
        }

    }

    if (m_options & SetAdditionalInfo)
        setAdditionalInfo();

    if (isdebug) {
        auto nxpt = string(m_nxp->nxStorage()->getNxTypeAsStr(m_nxp->type()));
        dbg_wprintf(L"NxFile::NxFile(%ls, %ls) %ls size: %I64d\n", wstring(nxpt.begin(), nxpt.end()).c_str(),
                    completePath().c_str(), exists() ? L"VALID" : L"INVALID", m_size);
    }
}

NxFile::~NxFile()
{
    if (isOpen())
        close();

    delete _file_mutex;

    if (isdebug)
        dbg_wprintf(L"NxFile::~NxFile() for %ls\n", completePath().c_str());
}

void NxFile::setCompletePath(const wstring &name)
{
    if (!name.length())
        return;

    wstring tmp_name = name;
    // Unix style path
    std::replace(tmp_name.begin(), tmp_name.end(), '\\', '/');
    // Remove trailing backslash
    size_t pos = tmp_name.find_last_of(L"/");
    if(pos == tmp_name.length()-1)
        tmp_name.erase(tmp_name.length()-1);

    // Get filename & filepath
    std::wstring basename = base_nameW(tmp_name);
    m_filename = !basename.length() ? name : basename;
    if (basename.length()) {
        size_t pos = tmp_name.find_last_of(m_filename) - m_filename.length();
        if (pos>0) tmp_name.erase(tmp_name.begin() + (int)pos, tmp_name.end());
        m_filepath = tmp_name.length() ? tmp_name : L"/";
    } else m_filepath = L"/";
}

void NxFile::setAdditionalInfo()
{
    UINT br;

    if (!(m_options & VirtualizeNXA) && m_fileType == NX_NCA)
        return;

    if ((m_fileType == NX_NCA || endsWith(m_filename, wstring(L".nca"))) && m_size > 0x400) {
        m_fileType = NX_NCA;
        // Retrieve NCA information
        u8 header[0x200];
        if (this->open() && !this->read(0x200, (void*)header, 0x200,  &br) && br == 0x200)
        {
            nca_info_t* nca_info = (nca_info_t*)header;
            if (not_in(nca_info->magic, {(u32)MAGIC_NCA0, (u32)MAGIC_NCA2, (u32)MAGIC_NCA3}))
            {
                auto header_key = GetGenericKey(&m_nxp->nxStorage()->keyset, "header_key");
                if (header_key.size() < 64) {
                    this->close();
                    return;
                }
                char crypt[33];
                char tweak[33];
                strcpy_s(crypt, header_key.substr(0, 32).c_str());
                strcpy_s(tweak, header_key.substr(32, 32).c_str());
                NxCrypto crypto(crypt, tweak);
                crypto.setSectorSize(0x200);
                crypto.decrypt(&header[0], 1);

                if (not_in(nca_info->magic, {(u32)MAGIC_NCA0, (u32)MAGIC_NCA2, (u32)MAGIC_NCA3})) {
                    this->close();
                    m_fileType = NX_GENERIC;
                    return;
                }
            }
            this->m_title_id = nca_info->title_id;
            this->m_contentType = (NxContentType)nca_info->content_type;
        }
    }

    if (startsWith(m_filepath, wstring(L"/save")) && m_size > 0x6F0) {
        // Retrieve SAVE information
        u8 buffer[sizeof(save_extra_data_t)];
        if (this->open() && !this->read(0x100, (void*)buffer, 4,  &br) && br == 4)
        {
            u32 magic;
            memcpy(&magic, &buffer, sizeof(u32));
            if (magic != MAGIC_DISF) {
                this->close();
                return;
            }
            m_fileType = NX_SAVE;
            if (!this->read(0x6D8, (void*)buffer, sizeof(save_extra_data_t),  &br) && br == sizeof(save_extra_data_t)) {
                save_extra_data_t *extra_data = (save_extra_data_t*)buffer;
                this->m_title_id = extra_data->title_id;
                this->m_contentType = (NxContentType)(extra_data->save_data_type+6);
                memcpy(this->m_user_id, extra_data->user_id, 0x10);
            }
        }
    }
    this->close();
}

// Resize NxFile (NXA compatible)
// This function will : - allocate or truncate file in filesystem
//                      - set current pointer to EOF
int NxFile::resize(u64 new_size, bool set_cursor_for_write)
{
    auto exit = [&](int res) {
        if (isdebug) dbg_wprintf(L"NxFile::resize(%I64d) for %ls (%ls rc: %d, new_size: %I64d) [this=%I64d]\n", new_size,
                                 completePath().c_str(), res == FR_OK ? L"SUCCESS" : L"FAIL", res, m_size, (u64)this);
        return res;
    };


    if (m_size == new_size && (!isNXA() || !set_cursor_for_write)) // Size unchanged
        return exit(FR_OK);

    if (!isOpenAndValid())
        return exit(FR_NOT_READY);

    int res;
    auto previous_size = m_size;

    /// STANDARD FILE
    if (!isNXA())
    {
        if (new_size > 0xFFFF0000)
            return exit(FR_INVALID_PARAMETER);

        if (relativeOffset() != new_size && (res = f_lseek(&m_fp, (u32)new_size))) // Seek EOF
            return exit(res);

        m_size = new_size;

        if (new_size < previous_size && (res = f_truncate(&m_fp))) // Reduced size, truncate
            return exit(res);

        return exit(FR_OK);
    }

    /// FILE IS NXA
    if (new_size < previous_size)
    {
        // size reduced, delete some nxa files if necessary
        auto next_idx = getFileIxByOffset(new_size)+1;
        bool reopen = false;
        for (auto i = next_idx; i < m_files.size(); i++)
        {
            reopen = i == m_cur_file && !f_close(&m_fp); // Ensure file pointer is closed before delete
            auto path = completePath() + L"/" + m_files.at(i).file;
            m_nxp->f_unlink(path.c_str());
        }
        if (reopen)
            m_nxp->f_open(&m_fp, wstring(completePath() + L"/" + m_files.back().file).c_str(), m_openMode);

        m_files.resize(next_idx); // resize vector
    }

    auto new_split_file = [&](u32 size) {
        NxSplitOff f_entry;
        f_entry.off_start = m_files.back().off_start + m_files.back().size;
        f_entry.size = size;
        wchar_t buff[3];
        swprintf(buff, L"%02X", std::stoi(m_files.back().file)+1);
        f_entry.file = wstring(buff);
        f_close(&m_fp);
        FRESULT res;
        auto path = completePath() + L"/" + f_entry.file;

        if ((res = m_nxp->f_open(&m_fp, path.c_str(), FA_CREATE_NEW | FA_READ | FA_WRITE))) // Create new file
            return res;
        if (f_entry.size && (res = f_lseek(&m_fp, f_entry.size))) // Seek EOF (change FS size)
            return res;
        m_files.emplace_back(f_entry); // Append entry in file vector
        m_cur_file = m_files.size()-1; // Entry is current file
        return FR_OK;
    };

    auto relative_new_size = new_size - (u64)m_files.back().off_start; // new size relating to the last split file
    if (relative_new_size > 0xFFFF0000) // size exceeds 4GB
    {
        // New file(s) needed
        m_files.back().size = 0xFFFF0000;
        auto remaining = relative_new_size - 0xFFFF0000;
        // Add new split entries
        while (remaining) {
            if ((res = new_split_file(remaining > 0xFFFF0000 ? 0xFFFF0000 : (u32)remaining)))
                return exit(res);
            remaining -= m_files.back().size;
        }
    }

    auto last_idx = m_files.size()-1;
    // Switch to last split file if needed
    if (last_idx != m_cur_file) {
        f_close(&m_fp);
        auto path = completePath() + L"/" + m_files.at(last_idx).file;
        if ((res = m_nxp->f_open(&m_fp, path.c_str(), accessMode() == NX_READONLY ? FA_READ : FA_READ | FA_WRITE)))
            return exit(res);
        m_cur_file = last_idx;
    }

    m_files[m_cur_file].size = (u32)relative_new_size; // Set new size for entry
    m_size = new_size; // Change NxFile size

    // Add new entry if set_cursor_for_write & cur split max ofs reached
    if (relative_new_size == 0xFFFF0000 && set_cursor_for_write)
        return exit(new_split_file(0));

    if (relativeOffset() == relative_new_size)
        return exit(FR_OK);

    if ((res = f_lseek(&m_fp, (u32)relative_new_size))) // Seek EOF
        return exit(res);

    if (isdebug) dbg_wprintf(L"NxFile::resize() seek to eof. cur file: %ls, relative ofs: %I64d\n",
                             m_files.at(m_cur_file).file.c_str(), relativeOffset());

    f_truncate(&m_fp); // Truncate
    return exit(FR_OK);
}

bool NxFile::isValidOffset(u64 ofs)
{
    if (!isNXA())
        return ofs <= m_size;

    for (size_t i(0); i < m_files.size(); i++)
        if (ofs >= m_files.at(i).off_start && ofs <= m_files.at(i).off_end())
            return true;

    return false;
}

bool NxFile::is_valid_nxp()
{
    if (!m_nxp || not_in(m_nxp->type(), {USER, SYSTEM, SAFE, PRODINFOF})
               || !m_nxp->isGood()
               || !m_nxp->is_mounted())
        return false;
    return true;
}

bool NxFile::isOpenAndValid()
{
    if (!is_valid_nxp() || !isGood() || m_openStatus != NX_OPENED)
        return false;
    return true;
}

size_t NxFile::getFileIxByOffset(u64 offset)
{
    for (size_t i(0); i < m_files.size(); i++)
        if (offset >= m_files.at(i).off_start && offset <= m_files.at(i).off_end())
            return (int)i;
    return 0;
}

bool NxFile::ensure_nxa_file(u64 offset, NxAccessMode mode)
{

    if (!isNXA()) {
        dbg_printf("NxFile::ensure_nxa_file(%I64d) FAILED, not NXA\n", offset);
        return false;
    }
    else if (!(m_options & VirtualizeNXA))
        return true;

    if (!isValidOffset(offset)) // Offset is out of range
        return mode == NX_READONLY ? false : resize(offset, true) == FR_OK;

    // Offset is valid, switch file if necessary
    auto ix = getFileIxByOffset(offset);
    if (ix != m_cur_file) {
        f_close(&m_fp);
        auto path = wstring(this->completePath() + L"/" + m_files.at(ix).file);
        if (!m_nxp->f_open(&m_fp, path.c_str(), accessMode() == NX_READONLY ? FA_READ : FA_READ | FA_WRITE)) {
            m_cur_file = ix;
            dbg_wprintf(L"NxFile::ensure_nxa_file(%I64d) SWITCH TO %l (%d)s\n", path.c_str(), m_cur_file);
            return true;
        }
        dbg_wprintf(L"NxFile::ensure_nxa_file(%I64d) FAILED to open new_path %ls (ix: %d)\n",
                    offset, path.c_str(), ix);
        return false;
    }
    return true;
}

bool NxFile::open(BYTE mode)
{
    auto exit = [&](int res) {
        if (isdebug) {
            wstring os;
            openModeString(mode, os);
            dbg_wprintf(L"NxFile::open(%ls) for %ls (%ls rc: %d) [this=%I64d]\n",
                        os.c_str(), completePath().c_str(), res == FR_OK ? L"SUCCESS" : L"FAIL", res, (u64)this);
        }
        return (bool)(res == FR_OK);
    };    

    if (!is_valid_nxp())
        return exit(FR_INVALID_DRIVE);

    if (isOpen())
        return exit(FR_OK);

    std::lock_guard<std::mutex> lock(*_file_mutex);

    auto path = this->completePath();
    int res; bool nxa_init = false;
    bool isCreateNew = !exists(); // File does not exists, creation mode
    // Force appropriate flogs if not provided
    if (isCreateNew && !(mode & (FA_CREATE_ALWAYS | FA_OPEN_ALWAYS | FA_CREATE_NEW)))
        mode &= FA_CREATE_NEW;
    if (isCreateNew && !(mode & FA_WRITE))
        mode &= FA_WRITE;
    bool truncate_existing = !isCreateNew && (mode & FA_CREATE_ALWAYS);

    // NX ARCHIVE CREATION if filename matches *.nca & path starts with /Content
    if (isCreateNew && (m_options & VirtualizeNXA) && endsWith(m_filename, wstring(L".nca")) && startsWith(m_filepath, wstring(L"/Contents")))
    {
        // Create new dir for NCA
        if ((res = m_nxp->f_mkdir(path.c_str())))
            return exit(res);

        // Change file attr to NXA
        m_fattrib = FILE_ATTRIBUTE_NX_ARCHIVE;
        if ((res = m_nxp->f_chmod(path.c_str(), m_fattrib, 0x3F))) {
            m_nxp->f_unlink(path.c_str());
            return exit(res);
        }

        nxa_init = true;
        m_fileType = NX_NCA;
        NxSplitOff f_entry; // Create new split entry for NXA
        f_entry.off_start = 0;
        f_entry.size = 0;
        f_entry.file = L"00";
        m_files.emplace_back(f_entry);
    }

    if (isNXA())
        path.append(L"/" + m_files.at(0).file);

    if (!(res = m_nxp->f_open(&m_fp, path.c_str(), mode)))
    {
        // OPEN SUCCESS
        m_openStatus = NX_OPENED;
        m_fileStatus = NX_FILE;
        m_cur_file = 0;
        m_openMode = mode;
        if (!nxa_init && isCreateNew) {
            m_fattrib = FILE_ATTRIBUTE_NORMAL;
        }
        if (isCreateNew)
            f_sync(&m_fp); // Sync file if created
        if (truncate_existing)
            resize(0);
    }
    else
    {
        // OPEN FAILED
        if (nxa_init) // delete NXA if previously created
            m_nxp->f_unlink(completePath().c_str());
    }
    return exit(res);
}

bool NxFile::close()
{
    auto exit = [&](int res) {
        if (isdebug)
            dbg_wprintf(L"NxFile::close() for %ls (%ls rc: %d) [this=%I64d]\n",
                        completePath().c_str(), res == FR_OK ? L"SUCCESS" : L"FAIL", res, (u64)this);
        return res == FR_OK;
    };

    if (m_openStatus == NX_CLOSED)
        return exit(FR_OK);

    if (!isOpenAndValid())
        return exit(FR_INVALID_OBJECT);

    std::lock_guard<std::mutex> lock(*_file_mutex);

    int res = f_close(&m_fp);
    if (!res)
        m_openStatus = NX_CLOSED;

    return exit(res);
}

bool NxFile::seek(u64 offset, bool no_lock)
{
    auto exit = [&](int res) {
        if (isdebug && res)
            dbg_wprintf(L"NxFile::seek(%I64d) FAILED (res=%d) for %ls (relative Offset %I64d) [this=%I64d]\n",
                        offset, res, completePath().c_str(), relativeOffset(offset), (u64)this);
        return (bool)(res == FR_OK);
    };

    if (!isOpenAndValid())
        return exit(FR_NOT_READY);

    if (isNXA() && !ensure_nxa_file(offset))
        return exit(FR_NO_FILE);

    if (absoluteOffset() == offset) // no need to move current pointer
        return exit(FR_OK);

    if (!no_lock)
        std::lock_guard<std::mutex> lock(*_file_mutex);
    auto res = f_lseek(&m_fp, relativeOffset(offset)); // move current pointer

    if (!res && absoluteOffset() > m_size) // resize needed ?
        return exit(resize(absoluteOffset()));

    return exit(res);
}

int NxFile::truncate()
{
    auto exit = [&](int res) {
        if (res && isdebug)
            dbg_wprintf(L"NxFile::truncate() FAILED for %ls (result %d) [this=%I64d]\n",
                        completePath().c_str(), res, (u64)this);
        return res;
    };

    if (!isOpenAndValid())
        return exit(FR_INVALID_OBJECT);

    std::lock_guard<std::mutex> lock(*_file_mutex);
    return exit(resize(absoluteOffset()));
}

int NxFile::read(void* buff, UINT btr, UINT* br)
{
    auto exit = [&](int res) {
        if (res && isdebug)
            dbg_wprintf(L"NxFile::read(buff, btr=%I32d, br=%I32d) FAILED for %ls (result %d, current ofs: %I64d) [this=%I64d]\n",
                        btr, br ? *br : 0, completePath().c_str(), res, absoluteOffset(), (u64)this);
        return res;
    };

    *br = 0;

    if (!isOpenAndValid())
        return exit(FR_NOT_READY);

    u32 bytesCount = 0, bytesTotal = btr;
    int res = FR_OK;

    while (bytesCount < bytesTotal)
    {
        btr = bytesTotal - bytesCount;
        *br = 0;
        if (isNXA() && (m_options & VirtualizeNXA)) {
            if (!ensure_nxa_file(absoluteOffset(), NX_READONLY))
                break;

            u64 new_off = (u64) relativeOffset() + (u64)btr;
            if (new_off > (u64)curFile().size) {
                // Reduce amount of bytes to read if we'll reach eof (NXA)
                btr = curFile().size - relativeOffset();
            }
        }

        void* p = static_cast<u8*>(buff) + bytesCount;

        res = f_read(&m_fp, p, btr, br);

        bytesCount += *br;
        if (*br != btr)
            break;
    }

    *br = bytesCount;
    return exit(!*br && !res ? FR_NO_FILE : res);
}

int NxFile::read(u64 offset, void* buff, UINT btr, UINT* br)
{
    if (br)
        *br = 0;

    std::lock_guard<std::mutex> lock(*_file_mutex);

    if (!seek(offset, true))
            return FR_INVALID_OBJECT;

    return read(buff, btr, br);
}

int NxFile::write(const void* buff, UINT btw, UINT* bw)
{
    auto exit = [&](int res) {
        if (res && isdebug)
            dbg_wprintf(L"NxFile::write(buff, btw=%I32d, bw=%I32d) FAILED for %ls (result %d) [this=%I64d]\n",
                        btw, bw ? *bw : 0, completePath().c_str(), res, (u64)this);
        return res;
    };

    if (bw)
        *bw = 0;

    if (!isOpenAndValid())
        return exit(FR_INVALID_OBJECT);

    u32 btw_total = btw, bw_tmp = 0;
    int res;
    if (isNXA() && (m_options & VirtualizeNXA))
    {        
        if (!ensure_nxa_file(absoluteOffset()))
            return exit(FR_INVALID_PARAMETER);

        // Resize buffer if write will reach eof
        if ((u64)relativeOffset() + (u64)btw > 0xFFFF0000)
            btw = 0xFFFF0000 - relativeOffset();
    }

    res = f_write(&m_fp, buff, btw, &bw_tmp);

    *bw += bw_tmp;

    if (res == FR_OK && absoluteOffset() > m_size)  // Update file size
        resize(absoluteOffset());

    if (res == FR_OK && btw_total != btw)
    {
        if (!ensure_nxa_file(absoluteOffset()))
            return exit(FR_INVALID_PARAMETER);

        auto buf_size = btw_total - bw_tmp;
        void* p = static_cast<u8*>(const_cast<void *>(buff)) + bw_tmp;
        res = f_write(&m_fp, p, buf_size, &bw_tmp);
        *bw += bw_tmp;
        if (!res)
            resize(absoluteOffset());
    }
    /*
    // Resize after write
    if (res == FR_OK && absoluteOffset() > m_size) { // Update file size
        resize(absoluteOffset());
        if (isdebug)
            dbg_wprintf(L"NxFile::write(buff, btw=%I32d, bw=%I32d) and filesize changed to "
                        "%I64d SUCCESS for %ls (result %d) [this=%I64d]\n",
                        btw, bw ? *bw : 0, m_size, completePath().c_str(), res, (u64)this);
    }
    */
    return exit(!*bw && !res ? FR_NO_FILE : res);
}

int NxFile::write(u64 offset, const void* buff, UINT btw, UINT* bw)
{
    if (bw)
        *bw = 0;

    std::lock_guard<std::mutex> lock(*_file_mutex);

    if (!seek(offset, true))
            return FR_INVALID_OBJECT;

    return write(buff, btw, bw);
}

int NxFile::remove()
{
    auto exit = [&](int res) {
        if (isdebug)
            dbg_wprintf(L"NxFile::remove() %ls for %ls (result %d) [this=%I64d]\n",
                        res ? L"FAIL" : L"SUCCESS", completePath().c_str(), res, (u64)this);
        return res;
    };

    if (!is_valid_nxp() || !isGood())
        return exit(FR_INVALID_OBJECT);

    int res;
    if (isNXA() && (m_options & VirtualizeNXA)) {
        std::lock_guard<std::mutex> lock(*_file_mutex);
        resize(0); // truncate ensures deletion of extra nxa's files
        // Delete cur nxa file
        if ((res =  m_nxp->f_unlink(wstring(completePath() + L"/" + m_files.at(0).file).c_str())))
            return exit(res);
    }
    else close();

    std::lock_guard<std::mutex> lock(*_file_mutex);

    // Unlink file (or NXA dir)
    res = m_nxp->f_unlink(completePath().c_str());

    if (res == FR_OK) {
        m_fileStatus = NX_INVALID;
        m_size = 0;
        m_openStatus = NX_CLOSED;
        if (isNXA())
            m_files.clear();
    }
    return exit(res);
}

int NxFile::rename(const wstring &new_name)
{
    auto previous_name = completePath();
    auto exit = [&](int res) {
        if (res && isdebug)
            dbg_wprintf(L"NxFile::rename(new_name= %ls) FAILED for %ls (result %d) [this=%I64d]\n",
                        new_name.c_str(), previous_name.c_str(), res, (u64)this);
        return res;
    };

    if (!is_valid_nxp())
        return exit(FR_INVALID_OBJECT);

    std::lock_guard<std::mutex> lock(*_file_mutex);

    auto res = m_nxp->f_rename(completePath().c_str(), new_name.c_str());
    if (res == FR_OK)
        setCompletePath(new_name);

    return exit(res);
}

string NxFile::titleIDString() {
    if (!m_title_id)
        return string();

    u8 buff[8];
    u64 tid = __builtin_bswap64(m_title_id);
    memcpy(buff, &tid, 8);
    return hexStr(buff, 8);

}

string NxFile::userIDString() {
    return hexStr((u8*)m_user_id, 16);
}

int NxFile::getAddStringIxByKey(const string &key)
{
    for (size_t i(0); i < m_addStrings.size(); i++)
        if (m_addStrings.at(i).key == key)
            return (int) i;
    return -1;
}

void NxFile::setAdditionalString(const string &key, const string &value)
{
    auto ix = getAddStringIxByKey(key);
    if (ix >= 0)
        m_addStrings.at((size_t)ix).value = value;
    else {
        AdditionalString s;
        s.key = key;
        s.value = value;
        m_addStrings.emplace_back(s);
    }
}

string NxFile::getAdditionalString(const string &key)
{
    auto ix = getAddStringIxByKey(key);
    return ix >= 0 ? m_addStrings.at((size_t)ix).value : string();
}

string NxFile::contentTypeString()
{
    string str;
    switch (m_contentType) {
    case Program:
        str = "Program";
        break;
    case Meta:
        str = "Meta";
        break;
    case Control:
        str = "Control";
        break;
    case Manual:
        str = "Manual";
        break;
    case Data:
        str = "Data";
        break;
    case PublicData:
        str = "PublicData";
        break;
    case SystemSaveData:
        str = "SystemSaveData";
        break;
    case SaveData:
        str = "SaveData";
        break;
    case BcatDeliveryCacheStorage:
        str = "BcatDeliveryCacheStorage";
        break;
    case DeviceSaveData:
        str = "DeviceSaveData";
        break;
    case TemporaryStorage:
        str = "TemporaryStorage";
        break;
    case CacheStorage:
        str = "CacheStorage";
        break;
    default:
        str = "Unknown";
        break;
    }
    return str;
}

void NxFile::setContentType(string content_type)
{
    if (content_type == "Program")
        m_contentType = Program;
    else if (content_type == "Meta")
        m_contentType = Meta;
    else if (content_type == "Control")
        m_contentType = Control;
    else if (content_type == "Manual")
        m_contentType = Manual;
    else if (content_type == "Data")
        m_contentType = Data;
    else if (content_type == "PublicData")
        m_contentType = PublicData;
    else if (content_type == "SystemSaveData")
        m_contentType = SystemSaveData;
    else if (content_type == "SaveData")
        m_contentType = SaveData;
    else if (content_type == "BcatDeliveryCacheStorage")
        m_contentType = BcatDeliveryCacheStorage;
    else if (content_type == "DeviceSaveData")
        m_contentType = DeviceSaveData;
    else if (content_type == "TemporaryStorage")
        m_contentType = TemporaryStorage;
    else if (content_type == "CacheStorage")
        m_contentType = CacheStorage;
    else
        m_contentType = UnknownType;
}

string NxFile::normalizedTitleLabel()
{
    if (!hasAdditionalString("title_name"))
        return titleIDString();

    auto label = getAdditionalString("title_name");
    label.erase(std::remove_if(label.begin(), label.end(), [](const u8 & c){
        return !std::isalpha(c) && !std::isspace(c) && !std::isdigit(c);
    }), label.end());
    return label;
}

bool NxFile::setFileTime(const FILETIME* time)
{
    auto exit = [&](bool res) {
        if (!res && isdebug)
            dbg_wprintf(L"NxFile::setFileTime() FAILED for %ls [this=%I64d]\n", completePath().c_str(), (u64)this);
        return res;
    };

    if (!isOpenAndValid())
        return exit(false);

    FILINFO fno;
    if (m_nxp->f_stat(completePath().c_str(), &fno) != FR_OK)
        return exit(false);

    FileTimeToDosDateTime(time, &fno.fdate, &fno.ftime);

    bool is_open = isOpen();
    if (is_open)
        close();

    std::lock_guard<std::mutex> lock(*_file_mutex);

    if (m_nxp->f_utime(completePath().c_str(), &fno) != FR_OK)
        return exit(false);

    m_fdate = fno.fdate;
    m_ftime = fno.ftime;

    _file_mutex->unlock();
    if (is_open)
        open(m_openMode);

    return exit(true);
}

bool NxFile::setFileAttr(const BYTE fattr)
{
    auto exit = [&](bool res) {
        if (!res && isdebug)
            dbg_wprintf(L"NxFile::setFileAttr() FAILED for %ls [this=%I64d]\n", completePath().c_str(), (u64)this);
        return res;
    };

    if (!isOpenAndValid())
        return exit(false);


    bool is_open = isOpen();
    if (is_open)
        close();

    std::lock_guard<std::mutex> lock(*_file_mutex);

    if (m_nxp->f_chmod(completePath().c_str(), fattr, 0x3F) != FR_OK)
        return exit(false);

    m_fattrib = fattr;

    _file_mutex->unlock();
    if (is_open)
        open(m_openMode);

    return exit(true);
}

void openModeString(BYTE mode, wstring &open_str)
{
    open_str.clear();
    if (mode & FA_READ)
        open_str.append(L"FA_READ ");
    if (mode & FA_WRITE)
        open_str.append(L"FA_WRITE ");
    if (mode & FA_OPEN_EXISTING)
        open_str.append(L"FA_OPEN_EXISTING ");
    if (mode & FA_CREATE_NEW)
        open_str.append(L"FA_CREATE_NEW ");
    if (mode & FA_CREATE_ALWAYS)
        open_str.append(L"FA_CREATE_ALWAYS ");
    if (mode & FA_OPEN_ALWAYS)
        open_str.append(L"FA_OPEN_ALWAYS ");
    if (mode & FA_OPEN_APPEND)
        open_str.append(L"FA_OPEN_APPEND ");

    open_str = rtrimW(open_str);
}
