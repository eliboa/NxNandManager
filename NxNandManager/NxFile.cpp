#include "NxFile.h"

NxFile::NxFile(NxPartition* nxp, const wstring &name)
 : m_nxp(nxp)
{
    memset(m_user_id, 0, 0x10);
    if (name.length())
    {
        wstring tmp_name = name;
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
        m_fileStatus = NX_INVALID_PATH;
    else if (fno.fattrib == FILE_ATTRIBUTE_DIRECTORY)
        m_fileStatus = NX_IS_DIRECTORY;
    else
        m_fileStatus = NX_VALID;

    if (m_fileStatus != NX_VALID)
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
        m_size = 0;
        DIR dp;
        FILINFO sub_fno;
        if (m_nxp->f_opendir(&dp, this->completePath().c_str())) {
            m_fileStatus = NX_INVALID_PATH;
            return;
        }
        while (!f_readdir(&dp, &sub_fno) && sub_fno.fname[0]) {
            NxSplitOff f_entry;
            f_entry.off_start = m_size;
            f_entry.size = sub_fno.fsize;
            f_entry.file = wstring(sub_fno.fname);
            m_size += (u64)sub_fno.fsize;
            m_files.emplace_back(f_entry);
        }
        f_closedir(&dp);

        if (!m_size) {
            m_fileStatus = NX_INVALID_PATH;
            return;
        }
    }
    setAdditionalInfo();
}

void NxFile::setAdditionalInfo()
{
    UINT br;
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

bool NxFile::is_valid_nxp()
{
    if (!m_nxp || not_in(m_nxp->type(), {USER, SYSTEM, SAFE, PRODINFOF})
               || (m_nxp->isEncryptedPartition() && (!m_nxp->crypto() || m_nxp->badCrypto()))
               || !m_nxp->is_mounted())
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

bool NxFile::ensure_nxa_file(u64 offset)
{
    if (!isNXA())
        return false;

    // Switch file
    auto ix = getFileIxByOffset(offset);
    if (ix != m_cur_file) {
        f_close(&m_fp);
        auto path = wstring(this->completePath() + L"/" + m_files.at(ix).file);
        if (!f_open(&m_fp, path.c_str(), m_openMode)) {
            m_cur_file = ix;
            return true;
        }
        else return false;
    }
    return true;
}
bool NxFile::open(BYTE mode)
{
    if (m_fileStatus != NX_VALID || m_openStatus == NX_OPENED || !is_valid_nxp())
        return false;

    auto path = this->completePath();
    if (this->isNXA())
        path.append(L"/" + m_files.at(0).file);

    bool success = m_nxp->f_open(&m_fp, path.c_str(), mode) == FR_OK;
    if (success) {
        m_openStatus = NX_OPENED;
        m_cur_file = 0;
        m_openMode = mode;
    }
    return success;
}
bool NxFile::close()
{
    if (m_fileStatus != NX_VALID || m_openStatus == NX_CLOSED || !is_valid_nxp())
        return false;

    bool success = f_close(&m_fp) == FR_OK;
    if (success)
        m_openStatus = NX_CLOSED;

    return success;
}
bool NxFile::seek(u64 offset)
{
    if (m_fileStatus != NX_VALID || m_openStatus != NX_OPENED || !is_valid_nxp() || offset > m_size)
        return false;

    if (isNXA() && !ensure_nxa_file(offset))
        return false;

    return f_lseek(&m_fp, relativeOffset(offset)) == FR_OK;
}
int NxFile::read(void* buff, UINT btr, UINT* br)
{
    if (br)
        *br = 0;

    bool isValidNxp = is_valid_nxp();
    if (!isValidNxp || m_fileStatus != NX_VALID || m_openStatus != NX_OPENED)
    {
        if (!isValidNxp) m_fileStatus = NX_INVALID_PART;
        return !isValidNxp ? FR_INVALID_DRIVE : FR_INVALID_OBJECT;
    }

    if (isNXA())
    {
        if (!ensure_nxa_file(absoluteOffset()))
            return false;

        // Resize buffer this read will reach eof
        if (relativeOffset() + btr > curFile().size)
            btr = curFile().size - relativeOffset();
    }

    return f_read(&m_fp, buff, btr, br);
}
int NxFile::read(u64 offset, void* buff, UINT btr, UINT* br)
{
    if (br)
        *br = 0;

    bool isValidNxp = is_valid_nxp();
    if (!isValidNxp || m_fileStatus != NX_VALID || m_openStatus != NX_OPENED)
    {
        if (!isValidNxp) m_fileStatus = NX_INVALID_PART;
        return !isValidNxp ? FR_INVALID_DRIVE : FR_INVALID_OBJECT;
    }

    if (!seek(offset))
        return FR_INVALID_OBJECT;

    return f_read(&m_fp, buff, btr, br);
}
int NxFile::write(const void* buff, UINT btw, UINT* bw)
{
    if (bw)
        *bw = 0;

    bool isValidNxp = is_valid_nxp();
    if (!isValidNxp || m_fileStatus != NX_VALID || m_openStatus != NX_OPENED)
    {
        if (!isValidNxp) m_fileStatus = NX_INVALID_PART;
        return !isValidNxp ? FR_INVALID_DRIVE : FR_INVALID_OBJECT;
    }

    if (isNXA())
    {
        if (!ensure_nxa_file(absoluteOffset()))
            return false;

        // Resize buffer this write will reach eof
        if (relativeOffset() + btw > curFile().size)
            btw = curFile().size - relativeOffset();
    }

    return f_write(&m_fp, buff, btw, bw);
}
int NxFile::write(u64 offset, const void* buff, UINT btw, UINT* bw)
{
    if (bw)
        *bw = 0;

    bool isValidNxp = is_valid_nxp();
    if (!isValidNxp || m_fileStatus != NX_VALID || m_openStatus != NX_OPENED)
    {
        if (!isValidNxp) m_fileStatus = NX_INVALID_PART;
        return !isValidNxp ? FR_INVALID_DRIVE : FR_INVALID_OBJECT;
    }

    if (!seek(offset))
        return FR_INVALID_OBJECT;

    return f_write(&m_fp, buff, btw, bw);
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
