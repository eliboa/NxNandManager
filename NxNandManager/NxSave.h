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

#ifndef NXSAVE_H
#define NXSAVE_H
#include "NxFile.h"
#include "res/hactool/ivfc.h"
#include "res/hactool/save.h"

class NxSave;

struct NxSaveFile {
    NxSave *parent;
    u32 idx = 0;
    string filename = "";
    string path = "";
    u32 parent_idx = 0;
    u64 size = 0;
    u32 start_block = 0;
    u32 next_file = 0;
    u32 next_sibling = 0;
    u32 next_dir = 0;
    bool is_directory = false;
    string completePath() { return endsWith(path, string("/")) ? path + filename : path + "/" + filename; }
};

enum ListMode {
    ListFilesOnly,
    ListDirectoriesOnly,
    ListAllFiles
};

void save_free_contexts(save_ctx_t *ctx);
class NxSave : public NxFile
{
public:
    NxSave(NxPartition* nxp, const wstring &name) : NxFile(nxp, name, SetAdditionalInfo) { save_init(); }
    NxSave(NxFile* f) : NxFile(f->nxp(), f->completePath(), SetAdditionalInfo) { save_init(); }
    ~NxSave() { if (init_done) save_free_contexts(&ctx); }

    vector<NxSaveFile> listFiles(ListMode mode = ListFilesOnly);
    u64 readSaveFile(NxSaveFile &file, void *buffer, u64 offset, u64 bytes_to_read);
    bool getSaveFile(NxSaveFile *file, const string &name);

private:
    save_ctx_t ctx;
    bool init_done = false;

    // Hactool functions
    void save_init();
    bool save_header(save_ctx_t *ctx);
    uint32_t save_remap_read(remap_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count);
    size_t save_ivfc_level_fread(ivfc_level_save_ctx_t *ctx, void *buffer, uint64_t offset, size_t count);
    uint32_t save_journal_storage_read(journal_storage_ctx_t *ctx, remap_storage_ctx_t *remap, void *buffer, uint64_t offset, size_t count);
    void save_ivfc_storage_read(integrity_verification_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count, int32_t verify);
    uint32_t save_allocation_table_storage_read(allocation_table_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count);
    uint32_t save_fs_list_get_capacity(save_filesystem_list_ctx_t *ctx);
    uint32_t save_fs_list_read_entry(save_filesystem_list_ctx_t *ctx, uint32_t index, save_fs_list_entry_t *entry);
    int save_fs_list_get_value(save_filesystem_list_ctx_t *ctx, uint32_t index, save_fs_list_entry_t *value);
    int save_hierarchical_file_table_find_next_file(hierarchical_save_file_table_ctx_t *ctx, save_find_position_t *position, save_file_info_t *info, char *name);
    int save_hierarchical_file_table_find_next_directory(hierarchical_save_file_table_ctx_t *ctx, save_find_position_t *position, char *name);
    uint32_t save_fs_get_index_from_key(save_filesystem_list_ctx_t *ctx, save_entry_key_t *key, uint32_t *prev_index);
    int save_hierarchical_file_table_find_path_recursive(hierarchical_save_file_table_ctx_t *ctx, save_entry_key_t *key, char *path);
    validity_t save_ivfc_validate(hierarchical_integrity_verification_storage_ctx_t *ctx, ivfc_save_hdr_t *ivfc);
    validity_t save_filesystem_verify(save_ctx_t *ctx);
    void save_ivfc_set_level_validities(hierarchical_integrity_verification_storage_ctx_t *ctx, ivfc_save_hdr_t *ivfc);
    validity_t check_memory_hash_table(FILE *f_in, unsigned char *hash_table, uint64_t data_ofs, uint64_t data_len, uint64_t block_size, int full_block);
    uint32_t save_duplex_storage_read(duplex_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count);
    int visit_save_dir(uint32_t dir_index, vector<NxSaveFile> &entries, const u32 parent_idx, const string parent_path);
    int visit_save_file(uint32_t file_index, vector<NxSaveFile> &entries, const u32 parent_idx, const string dir_path);
};

#endif // NXSAVE_H
