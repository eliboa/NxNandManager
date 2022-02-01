/*
 * Copyright (c) 2021 eliboa
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef NXFILE_H
#define NXFILE_H
#include "NxPartition.h"

using namespace std;

#define MAGIC_NCA3 0x3341434E /* "NCA3" */
#define MAGIC_NCA2 0x3241434E /* "NCA2" */
#define MAGIC_NCA0 0x3041434E /* "NCA0" */
#define MAGIC_DISF 0x46534944

// Nca structs (from hactool's sources)
typedef struct {
    uint8_t fixed_key_sig[0x100]; /* RSA-PSS signature over header with fixed key. */
    uint8_t npdm_key_sig[0x100]; /* RSA-PSS signature over header with key in NPDM. */
    uint32_t magic;
    uint8_t distribution; /* System vs gamecard. */
    uint8_t content_type;
    uint8_t crypto_type; /* Which keyblob (field 1) */
    uint8_t kaek_ind; /* Which kaek index? */
    uint64_t nca_size; /* Entire archive size. */
    uint64_t title_id;
    uint8_t _0x218[0x4]; /* Padding. */
    union {
        uint32_t sdk_version; /* What SDK was this built with? */
        struct {
            uint8_t sdk_revision;
            uint8_t sdk_micro;
            uint8_t sdk_minor;
            uint8_t sdk_major;
        };
    };
    uint8_t crypto_type2; /* Which keyblob (field 2) */
    uint8_t fixed_key_generation;
    uint8_t _0x222[0xE]; /* Padding. */
    uint8_t rights_id[0x10]; /* Rights ID (for titlekey crypto). */
    uint8_t section_entries[4][0x10]; /* Section entry metadata. */
    uint8_t section_hashes[4][0x20]; /* SHA-256 hashes for each section header. */
    uint8_t encrypted_keys[4][0x10]; /* Encrypted key area. */
    uint8_t _0x340[0xC0]; /* Padding. */
} nca_header_t;

typedef struct {
    uint32_t magic;
    uint8_t distribution; /* System vs gamecard. */
    uint8_t content_type;
    uint8_t crypto_type; /* Which keyblob (field 1) */
    uint8_t kaek_ind; /* Which kaek index? */
    uint64_t nca_size; /* Entire archive size. */
    uint64_t title_id;
    //size 0x18
} nca_info_t;

typedef struct {
    uint64_t title_id;
    uint8_t user_id[0x10];
    uint64_t save_id;
    uint8_t save_data_type;
    uint8_t _0x21[0x1F];
    uint64_t save_owner_id;
    uint64_t timestamp;
    uint64_t _0x50;
    uint64_t data_size;
    uint64_t journal_size;
    uint64_t commit_id;
} save_extra_data_t;

typedef enum {
    NX_FILE,
    NX_NO_FILE,
    NX_INVALID,
    NX_NO_FILESYSTEM,
    NX_INVALID_PART,
    NX_BAD_CRYPTO,
    NX_INVALID_PATH,
    NX_IS_DIRECTORY,
} NxFileStatus;

typedef enum {
    NX_OPENED,
    NX_CLOSED
} NxOpenStatus;

typedef enum {
    NX_GENERIC,
    NX_NCA,
    NX_SAVE,
} NxFileType;

typedef enum {
    NX_READONLY,
    NX_READ_WRITE,
} NxAccessMode;

typedef enum : uint8_t {
    Program, // 1->6: Nca content type
    Meta,
    Control,
    Manual,
    Data,
    PublicData,
    SystemSaveData, // 7->12: Save content type
    SaveData,
    BcatDeliveryCacheStorage,
    DeviceSaveData,
    TemporaryStorage,
    CacheStorage,
    UnknownType
} NxContentType;

struct NxSplitOff {
    u64 off_start;
    u32 size;
    wstring file;
    u64 off_end() { return off_start + (u64)size - 1; }
};

struct AdditionalString {
    string key;
    string value;
    bool operator==(const AdditionalString &a) const {
        return key == a.key;
    }
    bool operator<(const AdditionalString &a) const {
        return a.key < key;
    }
};

void openModeString(BYTE mode, wstring &open_str);

enum NxFileFlag {
    SimpleFile          = 0x01,
    SetAdditionalInfo   = 0x02,
    VirtualizeNXA       = 0x04,
};
DEFINE_ENUM_FLAG_OPERATORS(NxFileFlag)

class NxFile
{
public:
    NxFile(NxPartition* nxp, const wstring &name, NxFileFlag options = SetAdditionalInfo | VirtualizeNXA);
    ~NxFile();

private:
    NxPartition * m_nxp;
    wstring m_filename;
    wstring m_filepath;
    NxOpenStatus m_openStatus = NX_CLOSED;
    BYTE m_openMode = FA_READ;
    FIL m_fp;
    u8 m_options;

    u64  	m_size = 0;		/* File size */
    WORD	m_fdate;		/* Modified date */
    WORD	m_ftime;		/* Modified time */
    BYTE	m_fattrib;		/* File attribute */

    NxContentType m_contentType = UnknownType;
    u64 m_title_id = 0;
    u8  m_user_id[0x10];

    // NX ARCHIVE NCA
    size_t m_cur_file = 0;
    vector<NxSplitOff> m_files;

    // Variable strings
    vector<AdditionalString> m_addStrings;

    //Mutex
    std::mutex *_file_mutex;

protected:
    NxFileStatus m_fileStatus = NX_INVALID;
    NxFileType m_fileType = NX_GENERIC;

private:
    // Member functions
    void setAdditionalInfo();
    int resize(u64 size, bool set_cursor_for_write = false);

    // Helpers
    NxSplitOff curFile() { return m_files.at(m_cur_file); }
    NxSplitOff nextFile() { return m_files.at(m_cur_file+1); }
    bool ensure_nxa_file(u64 offset, NxAccessMode mode = NX_READ_WRITE);
    size_t getFileIxByOffset(u64 offset);
    int getAddStringIxByKey(const string &key);
    bool is_valid_nxp();
    bool isOpenAndValid();
    bool isValidOffset(u64 ofs);
    NxAccessMode accessMode() {return m_openMode & FA_WRITE ? NX_READ_WRITE : NX_READONLY; } // Current access mode

    // NXA
    // Relative offset from u64 offset
    u32 relativeOffset(u64 offset) {
        return !isNXA() ? (u32)offset : (u32)(offset - (u64)m_files.at(getFileIxByOffset(offset)).off_start);}
    // Relative current offset
    u32 relativeOffset() { return (u32)m_fp.fptr; }
    // Absolute offset for a give u32 offset inside current file
    u64 absoluteOffset(u32 offset) { return isNXA() ? curFile().off_start + offset : (u64)offset; }
    // Absolute current offset
    u64 absoluteOffset() { return isNXA() ? curFile().off_start + m_fp.fptr : (u64)m_fp.fptr; }

public:
    // Getters
    u64  size()  { return m_size; }
    WORD fdate() { return m_fdate; }
    WORD ftime() { return m_ftime; }
    BYTE fattr() { return m_fattrib; }
    wstring filename() { return m_filename; }
    wstring filepath() { return m_filepath; }
    wstring completePath() { return m_filepath + L"/" + m_filename; }
    u64 titleID() { return m_title_id; }
    u8* userID() { return m_user_id; }
    string titleIDString();
    string normalizedTitleLabel();
    string userIDString();
    NxContentType contentType() { return m_contentType; }
    string contentTypeString();
    string getAdditionalString(const string &key);
    NxPartition *nxp() { return m_nxp; }


    // Boolean
    bool exists() { return m_fileStatus == NX_FILE; }
    bool isGood() { return m_fileStatus == NX_FILE; }
    bool isOpen() { return m_openStatus == NX_OPENED; }
    bool isNXA()  { return m_fattrib == FILE_ATTRIBUTE_NX_ARCHIVE; }
    bool isNCA()  { return m_fileType == NX_NCA; }
    bool isSAVE() { return m_fileType == NX_SAVE; }
    bool hasUserID() { return *(u64*)m_user_id > 0; }
    bool hasAdditionalString(const string &key) {
        auto ix = getAddStringIxByKey(key); return ix >= 0 && m_addStrings.at((size_t)ix).value.length(); }

    // Setters
    void setAdditionalString(const string &key, const string &value);
    void setTitleID(u64 tid) { m_title_id = tid; }
    void setContentType(string content_type);
    bool setFileTime(const FILETIME* time);
    bool setFileAttr(const BYTE fattr);
    void setCompletePath(const wstring &path);

    // Member functions
    bool open(BYTE mode = FA_READ);
    bool close();
    bool seek(u64 offset, bool no_lock = false);
    int truncate();
    int read(void* buff, UINT btr, UINT* br);
    int read(u64 offset, void* buff, UINT btr, UINT* br);
    int write(const void* buff, UINT btw, UINT* bw);
    int write(u64 offset, const void* buff, UINT btw, UINT* bw);
    int remove();
    int rename(const wstring &new_name);
};

#endif // NXFILE_H
