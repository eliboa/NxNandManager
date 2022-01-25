// Copyright SciresM (hactool)
// Modified by eliboa for NxNandManager

#include "NxSave.h"
#include "res/utils.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>
unsigned char *mx_hmac_sha256(const void *key, int keylen,
                              const unsigned char *data, int datalen,
                              unsigned char *result, unsigned int *resultlen) {
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

void aes_calculate_cmac(void *dst, void *src, size_t size, const void *key)
{
    size_t mactlen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), nullptr);
    CMAC_Update(ctx, src, size);
    CMAC_Final(ctx, (u8*)dst, &mactlen);
}

void sha256_hash_buffer(unsigned char *digest, const void *data, size_t l)
{
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, data, l);
    SHA256_Final(digest, &sha_ctx);
}


bool NxSave::save_header(save_ctx_t *ctx) {
    if (ctx->header.layout.magic != MAGIC_DISF || ctx->header.duplex_header.magic != MAGIC_DPFS ||
        ctx->header.data_ivfc_header.magic != MAGIC_IVFC || ctx->header.journal_header.magic != MAGIC_JNGL ||
        ctx->header.save_header.magic != MAGIC_SAVE || ctx->header.main_remap_header.magic != MAGIC_RMAP ||
        ctx->header.meta_remap_header.magic != MAGIC_RMAP) {
        return false;
    }

    ctx->data_ivfc_master = (uint8_t *)&ctx->header + ctx->header.layout.ivfc_master_hash_offset_a;
    ctx->fat_ivfc_master = (uint8_t *)&ctx->header + ctx->header.layout.fat_ivfc_master_hash_a;

    ctx->header.data_ivfc_header.num_levels = 5;

    if (ctx->header.layout.version >= 0x50000) {
        ctx->header.fat_ivfc_header.num_levels = 4;
    }

    ctx->header_hash_validity = check_memory_hash_table(ctx->file, ctx->header.layout.hash, 0x300, 0x3D00, 0x3D00, 0);
    return true;
}
void save_free_contexts(save_ctx_t *ctx) {
    for (unsigned int i = 0; i < ctx->data_remap_storage.header->map_segment_count; i++) {
        free(ctx->data_remap_storage.segments[i].entries);
    }
    free(ctx->data_remap_storage.segments);
    for (unsigned int i = 0; i < ctx->meta_remap_storage.header->map_segment_count; i++) {
        free(ctx->meta_remap_storage.segments[i].entries);
    }
    free(ctx->meta_remap_storage.segments);
    free(ctx->data_remap_storage.map_entries);
    free(ctx->meta_remap_storage.map_entries);
    free(ctx->duplex_storage.layers[0].bitmap.bitmap);
    free(ctx->duplex_storage.layers[1].bitmap.bitmap);
    free(ctx->duplex_storage.layers[1].bitmap_storage);
    for (unsigned int i = 1; i < 3; i++) {
        free(ctx->duplex_layers[i].data_a);
        free(ctx->duplex_layers[i].data_b);
    }
    free(ctx->journal_map_info.map_storage);
    free(ctx->journal_storage.map.entries);
    for (unsigned int i = 0; i < ctx->header.data_ivfc_header.num_levels - 1; i++) {
        free(ctx->core_data_ivfc_storage.integrity_storages[i].block_validities);
    }
    free(ctx->core_data_ivfc_storage.level_validities);
    if (ctx->header.layout.version >= 0x50000) {
        for (unsigned int i = 0; i < ctx->header.fat_ivfc_header.num_levels - 1; i++) {
            free(ctx->fat_ivfc_storage.integrity_storages[i].block_validities);
        }
    }
    if (ctx->fat_ivfc_storage.level_validities)
        free(ctx->fat_ivfc_storage.level_validities);
    free(ctx->fat_storage);
}
static inline void save_bitmap_set_bit(void *buffer, size_t bit_offset) {
    *((uint8_t *)buffer + (bit_offset >> 3)) |= 1 << (bit_offset & 7);
}

static inline void save_bitmap_clear_bit(void *buffer, size_t bit_offset) {
    *((uint8_t *)buffer + (bit_offset >> 3)) &= ~(uint8_t)(1 << (bit_offset & 7));
}

static inline uint8_t save_bitmap_check_bit(const void *buffer, size_t bit_offset) {
    return *((uint8_t *)buffer + (bit_offset >> 3)) & (1 << (bit_offset & 7));
}

void save_duplex_storage_init(duplex_storage_ctx_t *ctx, duplex_fs_layer_info_t *layer, void *bitmap, uint64_t bitmap_size) {
    ctx->data_a = layer->data_a;
    ctx->data_b = layer->data_b;
    ctx->bitmap_storage = (uint8_t *)bitmap;
    ctx->block_size = 1 << layer->info.block_size_power;

    ctx->bitmap.data = ctx->bitmap_storage;
    ctx->bitmap.bitmap = (uint8_t *)malloc(bitmap_size >> 3);

    uint32_t bits_remaining = bitmap_size;
    uint32_t bitmap_pos = 0;
    uint32_t *buffer_pos = (uint32_t *)bitmap;
    while (bits_remaining) {
        uint32_t bits_to_read = bits_remaining < 32 ? bits_remaining : 32;
        uint32_t val = *buffer_pos;
        for (uint32_t i = 0; i < bits_to_read; i++) {
            if (val & 0x80000000)
                save_bitmap_set_bit(ctx->bitmap.bitmap, bitmap_pos);
            else
                save_bitmap_clear_bit(ctx->bitmap.bitmap, bitmap_pos);
            bitmap_pos++;
            bits_remaining--;
            val <<= 1;
        }
        buffer_pos++;
    }
}

uint32_t NxSave::save_duplex_storage_read(duplex_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count) {
    uint64_t in_pos = offset;
    uint32_t out_pos = 0;
    uint32_t remaining = count;
    while (remaining) {
        uint32_t block_num = (uint32_t)(in_pos / ctx->block_size);
        uint32_t block_pos = (uint32_t)(in_pos % ctx->block_size);
        uint32_t bytes_to_read = ctx->block_size - block_pos < remaining ? ctx->block_size - block_pos : remaining;

        uint8_t *data = save_bitmap_check_bit(ctx->bitmap.bitmap, block_num) ? ctx->data_b : ctx->data_a;
        memcpy((uint8_t *)buffer + out_pos, data + in_pos, bytes_to_read);

        out_pos += bytes_to_read;
        in_pos += bytes_to_read;
        remaining -= bytes_to_read;
    }
    return out_pos;
}

remap_segment_ctx_t *remap_init_segments(remap_header_t *header, remap_entry_ctx_t *map_entries, uint32_t num_map_entries) {
    remap_segment_ctx_t *segments =  (remap_segment_ctx_t *)calloc(1, sizeof(remap_segment_ctx_t) * header->map_segment_count);
    unsigned int entry_idx = 0;

    for (unsigned int i = 0; i < header->map_segment_count; i++) {
        remap_segment_ctx_t *seg = &segments[i];
        seg->entry_count = 0;
        remap_entry_ctx_t **ptr = (remap_entry_ctx_t**)malloc(sizeof(remap_entry_ctx_t *) * (seg->entry_count + 1));
        if (!ptr) {
            fprintf(stderr, "Failed to allocate entries in remap storage!\n");
            exit(EXIT_FAILURE);
        }
        seg->entries = ptr;
        seg->entries[seg->entry_count++] = &map_entries[entry_idx];
        seg->offset = map_entries[entry_idx].virtual_offset;
        map_entries[entry_idx++].segment = seg;

        while (entry_idx < num_map_entries && map_entries[entry_idx - 1].virtual_offset_end == map_entries[entry_idx].virtual_offset) {
            map_entries[entry_idx].segment = seg;
            map_entries[entry_idx - 1].next = &map_entries[entry_idx];
            ptr = (remap_entry_ctx_t**)realloc(seg->entries, sizeof(remap_entry_ctx_t *) * (seg->entry_count + 1));
            if (!ptr) {
                fprintf(stderr, "Failed to reallocate entries in remap storage!\n");
                exit(EXIT_FAILURE);
            }
            seg->entries = ptr;
            seg->entries[seg->entry_count++] = &map_entries[entry_idx++];
        }
        seg->length = seg->entries[seg->entry_count - 1]->virtual_offset_end - seg->entries[0]->virtual_offset;
    }
    return segments;
}
remap_segment_ctx_t *save_remap_init_segments(remap_header_t *header, remap_entry_ctx_t *map_entries, uint32_t num_map_entries) {
    remap_segment_ctx_t *segments =  (remap_segment_ctx_t *)calloc(1, sizeof(remap_segment_ctx_t) * header->map_segment_count);
    unsigned int entry_idx = 0;

    for (unsigned int i = 0; i < header->map_segment_count; i++) {
        remap_segment_ctx_t *seg = &segments[i];
        seg->entry_count = 0;
        remap_entry_ctx_t **ptr = (remap_entry_ctx_t **)malloc(sizeof(remap_entry_ctx_t *) * (seg->entry_count + 1));
        if (!ptr) {
            fprintf(stderr, "Failed to allocate entries in remap storage!\n");
            exit(EXIT_FAILURE);
        }
        seg->entries = ptr;
        seg->entries[seg->entry_count++] = &map_entries[entry_idx];
        seg->offset = map_entries[entry_idx].virtual_offset;
        map_entries[entry_idx++].segment = seg;

        while (entry_idx < num_map_entries && map_entries[entry_idx - 1].virtual_offset_end == map_entries[entry_idx].virtual_offset) {
            map_entries[entry_idx].segment = seg;
            map_entries[entry_idx - 1].next = &map_entries[entry_idx];
            ptr = (remap_entry_ctx_t **)realloc(seg->entries, sizeof(remap_entry_ctx_t *) * (seg->entry_count + 1));
            if (!ptr) {
                fprintf(stderr, "Failed to reallocate entries in remap storage!\n");
                exit(EXIT_FAILURE);
            }
            seg->entries = ptr;
            seg->entries[seg->entry_count++] = &map_entries[entry_idx++];
        }
        seg->length = seg->entries[seg->entry_count - 1]->virtual_offset_end - seg->entries[0]->virtual_offset;
    }
    return segments;
}

void save_ivfc_storage_init(hierarchical_integrity_verification_storage_ctx_t *ctx, uint64_t master_hash_offset, ivfc_save_hdr_t *ivfc) {
    ivfc_level_save_ctx_t *levels = ctx->levels;
    levels[0].type = STORAGE_BYTES;
    levels[0].hash_offset = master_hash_offset;
    for (unsigned int i = 1; i < 4; i++) {
        ivfc_level_hdr_t *level = &ivfc->level_headers[i - 1];
        levels[i].type = STORAGE_REMAP;
        levels[i].data_offset = level->logical_offset;
        levels[i].data_size = level->hash_data_size;
    }
    if (ivfc->num_levels == 5) {
        ivfc_level_hdr_t *data_level = &ivfc->level_headers[ivfc->num_levels - 2];
        levels[ivfc->num_levels - 1].type = STORAGE_JOURNAL;
        levels[ivfc->num_levels - 1].data_offset = data_level->logical_offset;
        levels[ivfc->num_levels - 1].data_size = data_level->hash_data_size;
    }

    struct salt_source_t {
        char string[50];
        uint32_t length;
    };

    static const struct salt_source_t salt_sources[6] = {
        {"HierarchicalIntegrityVerificationStorage::Master", 48},
        {"HierarchicalIntegrityVerificationStorage::L1", 44},
        {"HierarchicalIntegrityVerificationStorage::L2", 44},
        {"HierarchicalIntegrityVerificationStorage::L3", 44},
        {"HierarchicalIntegrityVerificationStorage::L4", 44},
        {"HierarchicalIntegrityVerificationStorage::L5", 44}
    };
    integrity_verification_info_ctx_t init_info[ivfc->num_levels];

    init_info[0].data = &levels[0];
    init_info[0].block_size = 0;
    for (unsigned int i = 1; i < ivfc->num_levels; i++) {
        init_info[i].data = &levels[i];
        init_info[i].block_size = 1 << ivfc->level_headers[i - 1].block_size;
        //sha256_get_buffer_hmac(init_info[i].salt, salt_sources[i - 1].string, salt_sources[i - 1].length, ivfc->salt_source, 0x20);
        unsigned char *result = NULL;
        unsigned int resultlen = -1;
        result = mx_hmac_sha256(salt_sources[i - 1].string, salt_sources[i - 1].length, ivfc->salt_source, 0x20, result, &resultlen);
        memcpy_s(init_info[i].salt, 0x20, result, resultlen);
    }

    ctx->integrity_storages[0].next_level = NULL;
    ctx->level_validities = (validity_t**)malloc(sizeof(validity_t *) * (ivfc->num_levels - 1));
    for (unsigned int i = 1; i < ivfc->num_levels; i++) {
        integrity_verification_storage_ctx_t *level_data = &ctx->integrity_storages[i - 1];
        level_data->hash_storage = &levels[i - 1];
        level_data->base_storage = &levels[i];
        level_data->sector_size = init_info[i].block_size;
        level_data->_length = init_info[i].data->data_size;
        level_data->sector_count = (level_data->_length + level_data->sector_size - 1) / level_data->sector_size;
        memcpy(level_data->salt, init_info[i].salt, 0x20);
        level_data->block_validities = (validity_t*)calloc(1, sizeof(validity_t) * level_data->sector_count);
        ctx->level_validities[i - 1] = level_data->block_validities;
        if (i > 1) {
            level_data->next_level = &ctx->integrity_storages[i - 2];
        }
    }
    ctx->data_level = &levels[ivfc->num_levels - 1];
    ctx->_length = ctx->integrity_storages[ivfc->num_levels - 2]._length;
}

remap_entry_ctx_t *save_remap_get_map_entry(remap_storage_ctx_t *ctx, uint64_t offset) {
    uint32_t segment_idx = (uint32_t)(offset >> (64 - ctx->header->segment_bits));
    if (segment_idx < ctx->header->map_segment_count) {
        for (unsigned int i = 0; i < ctx->segments[segment_idx].entry_count; i++)
            if (ctx->segments[segment_idx].entries[i]->virtual_offset_end > offset)
                return ctx->segments[segment_idx].entries[i];
    }
    fprintf(stderr, "Remap offset %I64d out of range!\n", offset);
    exit(EXIT_FAILURE);
}

uint32_t save_allocation_table_read_entry_with_length(allocation_table_ctx_t *ctx, allocation_table_entry_t *entry) {
    uint32_t length = 1;
    uint32_t entry_index = allocation_table_block_to_entry_index(entry->next);

    allocation_table_entry_t *entries = (allocation_table_entry_t *)((uint8_t *)(ctx->base_storage) + entry_index * SAVE_FAT_ENTRY_SIZE);
    if ((entries[0].next & 0x80000000) == 0) {
        if (entries[0].prev & 0x80000000 && entries[0].prev != 0x80000000) {
            fprintf(stderr, "Invalid iterated range entry in allocation table!\n");
            exit(EXIT_FAILURE);
        }
    } else {
        length = entries[1].next - entry_index + 1;
    }

    if (allocation_table_is_list_end(&entries[0])) {
        entry->next = 0xFFFFFFFF;
    } else {
        entry->next = allocation_table_entry_index_to_block(allocation_table_get_next(&entries[0]));
    }

    if (allocation_table_is_list_start(&entries[0])) {
        entry->prev = 0xFFFFFFFF;
    } else {
        entry->prev = allocation_table_entry_index_to_block(allocation_table_get_prev(&entries[0]));
    }

    return length;
}

uint32_t save_allocation_table_get_list_length(allocation_table_ctx_t *ctx, uint32_t block_index) {
    allocation_table_entry_t entry;
    entry.next = block_index;
    uint32_t total_length = 0;
    uint32_t table_size = ctx->header->allocation_table_block_count;
    uint32_t nodes_iterated = 0;

    while (entry.next != 0xFFFFFFFF) {
        total_length += save_allocation_table_read_entry_with_length(ctx, &entry);
        nodes_iterated++;
        if (nodes_iterated > table_size) {
            fprintf(stderr, "Cycle detected in allocation table!\n");
            exit(EXIT_FAILURE);
        }
    }
    return total_length;
}

uint64_t save_allocation_table_get_free_space_size(save_filesystem_ctx_t *ctx) {
    uint32_t free_list_start = save_allocation_table_get_free_list_block_index(&ctx->allocation_table);

    if (free_list_start == 0xFFFFFFFF) return 0;

    return ctx->header->block_size * save_allocation_table_get_list_length(&ctx->allocation_table, free_list_start);
}

void save_allocation_table_iterator_begin(allocation_table_iterator_ctx_t *ctx, allocation_table_ctx_t *table, uint32_t initial_block) {
    ctx->fat = table;
    ctx->physical_block = initial_block;
    ctx->virtual_block = 0;

    allocation_table_entry_t entry;
    entry.next = initial_block;
    ctx->current_segment_size = save_allocation_table_read_entry_with_length(ctx->fat, &entry);
    ctx->next_block = entry.next;
    ctx->prev_block = entry.prev;

    if (ctx->prev_block != 0xFFFFFFFF) {
        fprintf(stderr, "Attempted to start FAT iteration from invalid block %I32d!\n", initial_block);
        exit(EXIT_FAILURE);
    }
}

int save_allocation_table_iterator_move_next(allocation_table_iterator_ctx_t *ctx) {
    if (ctx->next_block == 0xFFFFFFFF) return 0;

    ctx->virtual_block += ctx->current_segment_size;
    ctx->physical_block = ctx->next_block;

    allocation_table_entry_t entry;
    entry.next = ctx->next_block;
    ctx->current_segment_size = save_allocation_table_read_entry_with_length(ctx->fat, &entry);
    ctx->next_block = entry.next;
    ctx->prev_block = entry.prev;

    return 1;
}

int save_allocation_table_iterator_move_prev(allocation_table_iterator_ctx_t *ctx) {
    if (ctx->prev_block == 0xFFFFFFFF) return 0;

    ctx->physical_block = ctx->prev_block;

    allocation_table_entry_t entry;
    entry.next = ctx->prev_block;
    ctx->current_segment_size = save_allocation_table_read_entry_with_length(ctx->fat, &entry);
    ctx->next_block = entry.next;
    ctx->prev_block = entry.prev;

    ctx->virtual_block -= ctx->current_segment_size;

    return 1;
}

int save_allocation_table_iterator_seek(allocation_table_iterator_ctx_t *ctx, uint32_t block) {
    while (1) {
        if (block < ctx->virtual_block) {
            if (!save_allocation_table_iterator_move_prev(ctx)) return 0;
        } else if (block >= ctx->virtual_block + ctx->current_segment_size) {
            if (!save_allocation_table_iterator_move_next(ctx)) return 0;
        } else {
            return 1;
        }

    }
}

void save_open_fat_storage(save_filesystem_ctx_t *ctx, allocation_table_storage_ctx_t *storage_ctx, uint32_t block_index) {
    storage_ctx->base_storage = ctx->base_storage;
    storage_ctx->fat = &ctx->allocation_table;
    storage_ctx->block_size = (uint32_t)ctx->header->block_size;
    storage_ctx->initial_block = block_index;
    storage_ctx->_length = block_index == 0xFFFFFFFF ? 0 : save_allocation_table_get_list_length(storage_ctx->fat, block_index) * storage_ctx->block_size;
}

void save_filesystem_init(save_filesystem_ctx_t *ctx, void *fat, save_fs_header_t *save_fs_header, fat_header_t *fat_header) {
    ctx->allocation_table.base_storage = fat;
    ctx->allocation_table.header = fat_header;
    ctx->allocation_table.free_list_entry_index = 0;
    ctx->header = save_fs_header;

    save_open_fat_storage(ctx, &ctx->file_table.directory_table.storage, fat_header->directory_table_block);
    save_open_fat_storage(ctx, &ctx->file_table.file_table.storage, fat_header->file_table_block);
    ctx->file_table.file_table.free_list_head_index = 0;
    ctx->file_table.file_table.used_list_head_index = 1;
    ctx->file_table.directory_table.free_list_head_index = 0;
    ctx->file_table.directory_table.used_list_head_index = 1;
}
static void generate_kek(unsigned char *dst, const unsigned char *src, const unsigned char *master_key, const unsigned char *kek_seed, const unsigned char *key_seed)
{
    unsigned char kek[0x10];
    unsigned char src_kek[0x10];
    auto master_ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit(master_ctx, EVP_aes_128_ecb(), master_key, nullptr);
    EVP_CIPHER_CTX_set_padding(master_ctx, 0);
    /*

    auto kek_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(ctx_tweak, EVP_aes_128_ecb(), tweak_key.data(), nullptr);

    aes_ctx_t *master_ctx = new_aes_ctx(master_key, 0x10, AES_MODE_ECB);
    aes_decrypt(master_ctx, kek, kek_seed, 0x10);
    free_aes_ctx(master_ctx);

    aes_ctx_t *kek_ctx = new_aes_ctx(kek, 0x10, AES_MODE_ECB);
    aes_decrypt(kek_ctx, src_kek, src, 0x10);
    free_aes_ctx(kek_ctx);

    if (key_seed != NULL) {
        aes_ctx_t *key_ctx = new_aes_ctx(src_kek, 0x10, AES_MODE_ECB);
        aes_decrypt(key_ctx, dst, key_seed, 0x10);
        free_aes_ctx(key_ctx);
    } else {
        memcpy(dst, src_kek, 0x10);
    }
    */
};

void NxSave::save_init()
{
    if (!isSAVE() || !open(FA_READ))
        goto exit_error;

    UINT br;
    memset(&ctx, 0, sizeof(save_ctx_t));

    /* Try to parse Header A. */
    if (read(0, &ctx.header, sizeof(ctx.header), &br) || br != sizeof(ctx.header))
        goto exit_error;

    if (!save_header(&ctx))
        goto exit_error;

    if (ctx.header_hash_validity == VALIDITY_INVALID) {
        /* Try to parse Header B. */
        if (read(0x4000, &ctx.header, sizeof(ctx.header), &br) || br != sizeof(ctx.header))
            goto exit_error;

        if (!save_header(&ctx))
            goto exit_error;

        if (ctx.header_hash_validity == VALIDITY_INVALID)
            goto exit_error;
    }
    goto initialize;

exit_error:
    m_fileType = NX_GENERIC;
    NxFile::close();
    return;

initialize:
    init_done = true;
    /*
    auto save_mac_key_str = GetGenericKey(&nxp()->nxStorage()->keyset, "save_mac_key");
    u8 cmac[0x10];
    u8 save_mac_key[0x10];
    memset(cmac, 0, 0x10);
    auto s_key = save_mac_key_str.substr(0, 0x10);
    strcpy_s((char*)save_mac_key, s_key.c_str());
    bool b = parse_hex_key(save_mac_key, s_key.c_str(), 0x10);
    aes_calculate_cmac(cmac, &ctx.header.layout, sizeof(ctx.header.layout), save_mac_key);
    if (memcmp(cmac, &ctx.header.cmac, 0x10) == 0) {
        ctx.header_cmac_validity = VALIDITY_VALID;
    } else {
        ctx.header_cmac_validity = VALIDITY_INVALID;
    }
    */
    /* Initialize remap storages. */
    ctx.data_remap_storage.type = STORAGE_BYTES;
    ctx.data_remap_storage.base_storage_offset = ctx.header.layout.file_map_data_offset;
    ctx.data_remap_storage.header = &ctx.header.main_remap_header;
    ctx.data_remap_storage.map_entries = (remap_entry_ctx_t*)calloc(1, sizeof(remap_entry_ctx_t) * ctx.data_remap_storage.header->map_entry_count);
    ctx.data_remap_storage.file = ctx.file;
    seek(ctx.header.layout.file_map_entry_offset);
    for (unsigned int i = 0; i < ctx.data_remap_storage.header->map_entry_count; i++) {
        read(&ctx.data_remap_storage.map_entries[i], 0x20, &br);
        ctx.data_remap_storage.map_entries[i].physical_offset_end = ctx.data_remap_storage.map_entries[i].physical_offset + ctx.data_remap_storage.map_entries[i].size;
        ctx.data_remap_storage.map_entries[i].virtual_offset_end = ctx.data_remap_storage.map_entries[i].virtual_offset + ctx.data_remap_storage.map_entries[i].size;
    }


    /* Initialize data remap storage. */
    ctx.data_remap_storage.segments = remap_init_segments(ctx.data_remap_storage.header, ctx.data_remap_storage.map_entries, ctx.data_remap_storage.header->map_entry_count);

    /* Initialize duplex storage. */
    ctx.duplex_layers[0].data_a = (uint8_t *)&ctx.header + ctx.header.layout.duplex_master_offset_a;
    ctx.duplex_layers[0].data_b = (uint8_t *)&ctx.header + ctx.header.layout.duplex_master_offset_b;
    memcpy(&ctx.duplex_layers[0].info, &ctx.header.duplex_header.layers[0], sizeof(duplex_info_t));

    ctx.duplex_layers[1].data_a = (uint8_t *)malloc(ctx.header.layout.duplex_l1_size);
    save_remap_read(&ctx.data_remap_storage, ctx.duplex_layers[1].data_a, ctx.header.layout.duplex_l1_offset_a, ctx.header.layout.duplex_l1_size);
    ctx.duplex_layers[1].data_b = (uint8_t *)malloc(ctx.header.layout.duplex_l1_size);
    save_remap_read(&ctx.data_remap_storage, ctx.duplex_layers[1].data_b, ctx.header.layout.duplex_l1_offset_b, ctx.header.layout.duplex_l1_size);
    memcpy(&ctx.duplex_layers[1].info, &ctx.header.duplex_header.layers[1], sizeof(duplex_info_t));

    ctx.duplex_layers[2].data_a = (uint8_t *)malloc(ctx.header.layout.duplex_data_size);
    save_remap_read(&ctx.data_remap_storage, ctx.duplex_layers[2].data_a, ctx.header.layout.duplex_data_offset_a, ctx.header.layout.duplex_data_size);
    ctx.duplex_layers[2].data_b = (uint8_t *)malloc(ctx.header.layout.duplex_data_size);
    save_remap_read(&ctx.data_remap_storage, ctx.duplex_layers[2].data_b, ctx.header.layout.duplex_data_offset_b, ctx.header.layout.duplex_data_size);
    memcpy(&ctx.duplex_layers[2].info, &ctx.header.duplex_header.layers[2], sizeof(duplex_info_t));

    /* Initialize hierarchical duplex storage. */
    uint8_t *bitmap = ctx.header.layout.duplex_index == 1 ? ctx.duplex_layers[0].data_b : ctx.duplex_layers[0].data_a;
    save_duplex_storage_init(&ctx.duplex_storage.layers[0], &ctx.duplex_layers[1], bitmap, ctx.header.layout.duplex_master_size);
    ctx.duplex_storage.layers[0]._length = ctx.header.layout.duplex_l1_size;

    bitmap = (uint8_t *)malloc(ctx.duplex_storage.layers[0]._length);
    save_duplex_storage_read(&ctx.duplex_storage.layers[0], bitmap, 0, ctx.duplex_storage.layers[0]._length);
    save_duplex_storage_init(&ctx.duplex_storage.layers[1], &ctx.duplex_layers[2], bitmap, ctx.duplex_storage.layers[0]._length);
    ctx.duplex_storage.layers[1]._length = ctx.header.layout.duplex_data_size;

    ctx.duplex_storage.data_layer = ctx.duplex_storage.layers[1];

    /* Initialize meta remap storage. */
    ctx.meta_remap_storage.type = STORAGE_DUPLEX;
    ctx.meta_remap_storage.base_storage_offset = 0;
    ctx.meta_remap_storage.duplex = &ctx.duplex_storage.data_layer;
    ctx.meta_remap_storage.header = &ctx.header.meta_remap_header;
    ctx.meta_remap_storage.map_entries = (remap_entry_ctx_t*)malloc(sizeof(remap_entry_ctx_t) * ctx.meta_remap_storage.header->map_entry_count);
    ctx.meta_remap_storage.file = ctx.file;
    seek(ctx.header.layout.meta_map_entry_offset);
    for (unsigned int i = 0; i < ctx.meta_remap_storage.header->map_entry_count; i++) {
        read(&ctx.meta_remap_storage.map_entries[i], 0x20, &br);
        ctx.meta_remap_storage.map_entries[i].physical_offset_end = ctx.meta_remap_storage.map_entries[i].physical_offset + ctx.meta_remap_storage.map_entries[i].size;
        ctx.meta_remap_storage.map_entries[i].virtual_offset_end = ctx.meta_remap_storage.map_entries[i].virtual_offset + ctx.meta_remap_storage.map_entries[i].size;
    }

    ctx.meta_remap_storage.segments = save_remap_init_segments(ctx.meta_remap_storage.header, ctx.meta_remap_storage.map_entries, ctx.meta_remap_storage.header->map_entry_count);

    /* Initialize journal map. */
    ctx.journal_map_info.map_storage = (uint8_t *)malloc(ctx.header.layout.journal_map_table_size);
    u32* t = (u32*)&ctx.journal_map_info.map_storage + 0x20;
    save_remap_read(&ctx.meta_remap_storage, ctx.journal_map_info.map_storage, ctx.header.layout.journal_map_table_offset, ctx.header.layout.journal_map_table_size);

    /* Initialize journal storage. */
    ctx.journal_storage.header = &ctx.header.journal_header;
    ctx.journal_storage.journal_data_offset = ctx.header.layout.journal_data_offset;
    ctx.journal_storage._length = ctx.journal_storage.header->total_size - ctx.journal_storage.header->journal_size;
    ctx.journal_storage.file = ctx.file;
    ctx.journal_storage.map.header = &ctx.header.map_header;
    ctx.journal_storage.map.map_storage = ctx.journal_map_info.map_storage;
    ctx.journal_storage.map.entries = (journal_map_entry_t*)malloc(sizeof(journal_map_entry_t) * ctx.journal_storage.map.header->main_data_block_count);
    uint32_t *pos = (uint32_t *)ctx.journal_storage.map.map_storage;
    for (unsigned int i = 0; i < ctx.journal_storage.map.header->main_data_block_count; i++) {
        ctx.journal_storage.map.entries[i].virtual_index = i;
        ctx.journal_storage.map.entries[i].physical_index = *pos & 0x7FFFFFFF;
        pos += 2;
    }
    ctx.journal_storage.block_size = ctx.journal_storage.header->block_size;
    ctx.journal_storage._length = ctx.journal_storage.header->total_size - ctx.journal_storage.header->journal_size;

    /* Initialize core IVFC storage. */
    for (unsigned int i = 0; i < 5; i++) {
        ctx.core_data_ivfc_storage.levels[i].save_ctx = &ctx;
    }
    save_ivfc_storage_init(&ctx.core_data_ivfc_storage, ctx.header.layout.ivfc_master_hash_offset_a, &ctx.header.data_ivfc_header);

    /* Initialize FAT storage. */
    if (ctx.header.layout.version < 0x50000) {
        ctx.fat_storage = (uint8_t *)malloc(ctx.header.layout.fat_size);
        save_remap_read(&ctx.meta_remap_storage, ctx.fat_storage, ctx.header.layout.fat_offset, ctx.header.layout.fat_size);
    } else {
        for (unsigned int i = 0; i < 5; i++) {
            ctx.fat_ivfc_storage.levels[i].save_ctx = &ctx;
        }
        save_ivfc_storage_init(&ctx.fat_ivfc_storage, ctx.header.layout.fat_ivfc_master_hash_a, &ctx.header.fat_ivfc_header);
        ctx.fat_storage = (uint8_t *)malloc(ctx.fat_ivfc_storage._length);
        save_remap_read(&ctx.meta_remap_storage, ctx.fat_storage, ctx.header.fat_ivfc_header.level_headers[ctx.header.fat_ivfc_header.num_levels - 2].logical_offset, ctx.fat_ivfc_storage._length);
    }

    /* Initialize core save filesystem. */
    ctx.save_filesystem_core.base_storage = &ctx.core_data_ivfc_storage;
    save_filesystem_init(&ctx.save_filesystem_core, ctx.fat_storage, &ctx.header.save_header, &ctx.header.fat_header);

    NxFile::close();
}

bool NxSave::getSaveFile(NxSaveFile *file, const string &path)
{
    if (!isSAVE())
        return false;

    for (auto entry : listFiles(ListAllFiles)) if (entry.completePath() == path) {
        *file = entry;
        return true;
    }
    return false;
}


u64 NxSave::readSaveFile(NxSaveFile &file, void *buf, u64 ofs, u64 btr)
{
    if (!isSAVE())
        return 0;

    bool openClose = !NxFile::isOpen();
    if (openClose && !NxFile::open())
        return 0;

    allocation_table_storage_ctx_t storage;
    save_open_fat_storage(&ctx.save_filesystem_core, &storage, file.start_block);

    if (ofs + btr > file.size)
        btr = (u32)(file.size - ofs);

    if (btr <= 0)
        return 0;

    auto br = save_allocation_table_storage_read(&storage, buf, ofs, (u32)btr);
    if (openClose)
        NxFile::close();

    return br;
}

vector<NxSaveFile> NxSave::listFiles(ListMode mode)
{

    vector<NxSaveFile> files, r_files;
    if (!isSAVE())
        return files;

    bool openClose = !NxFile::isOpen();
    if (openClose && !NxFile::open())
        return files;

    auto exit = [&]() { if (openClose) NxFile::close(); return r_files; };

    save_entry_key_t key = {"", 0};
    u32 root_idx = save_fs_get_index_from_key(&ctx.save_filesystem_core.file_table.directory_table, &key, nullptr);
    if (root_idx == 0xFFFFFFFF)
        return exit();

    visit_save_dir(root_idx, files, root_idx, "");

    for (auto f : files)
        if ((f.is_directory && mode != ListFilesOnly) || (!f.is_directory && mode != ListDirectoriesOnly))
            r_files.push_back(f);

    return exit();
}


validity_t NxSave::save_ivfc_validate(hierarchical_integrity_verification_storage_ctx_t *ctx, ivfc_save_hdr_t *ivfc) {
    validity_t result = VALIDITY_VALID;
    for (unsigned int i = 0; i < ivfc->num_levels - 1 && result != VALIDITY_INVALID; i++) {
        integrity_verification_storage_ctx_t *storage = &ctx->integrity_storages[i];

        uint64_t block_size = storage->sector_size;
        uint32_t block_count = (uint32_t)((storage->_length + block_size - 1) / block_size);

        uint8_t *buffer = (uint8_t*)malloc(block_size);

        for (unsigned int j = 0; j < block_count; j++) {
            if (ctx->level_validities[ivfc->num_levels - 2][j] == VALIDITY_UNCHECKED) {
                uint32_t to_read = storage->_length - block_size * j < block_size ? storage->_length - block_size * j : block_size;
                save_ivfc_storage_read(storage, buffer, block_size * j, to_read, 1);
            }
            if (ctx->level_validities[ivfc->num_levels - 2][j] == VALIDITY_INVALID) {
                result = VALIDITY_INVALID;
                break;
            }
        }
        free(buffer);
    }

    return result;
}
uint32_t NxSave::save_fs_get_index_from_key(save_filesystem_list_ctx_t *ctx, save_entry_key_t *key, uint32_t *prev_index) {
    save_fs_list_entry_t entry;
    uint32_t capacity = save_fs_list_get_capacity(ctx);
    save_fs_list_read_entry(ctx, ctx->used_list_head_index, &entry);
    uint32_t prev;
    if (!prev_index) {
        prev_index = &prev;
    }
    *prev_index = ctx->used_list_head_index;
    uint32_t index = entry.next;
    while (index) {
        if (index > capacity) {
            fprintf(stderr, "Save entry index %d out of range!", index);
            exit(EXIT_FAILURE);
        }
        save_fs_list_read_entry(ctx, index, &entry);
        if (entry.parent == key->parent && !strcmp(entry.name, key->name)) {
            return index;
        }
        *prev_index = index;
        index = entry.next;
    }
    *prev_index = 0xFFFFFFFF;
    return 0xFFFFFFFF;
}

int NxSave::save_hierarchical_file_table_find_path_recursive(hierarchical_save_file_table_ctx_t *ctx, save_entry_key_t *key, char *path) {
    memcpy(key->name, path, SAVE_FS_LIST_MAX_NAME_LENGTH);
    key->parent = 0;
    char *pos = path;
    while (pos) {
        key->parent = save_fs_get_index_from_key(&ctx->directory_table, key, NULL);
        if (key->parent == 0xFFFFFFFF) return 0;
        pos = strchr(pos, '/');
    }
    return 1;
}

int NxSave::save_hierarchical_file_table_find_next_file(hierarchical_save_file_table_ctx_t *ctx, save_find_position_t *position, save_file_info_t *info, char *name) {
    if (position->next_file == 0) {
        return 0;
    }
    save_fs_list_entry_t entry;
    if(!save_fs_list_get_value(&ctx->file_table, position->next_file, &entry)) {
        return 0;
    }
    position->next_file = entry.value.next_sibling;
    memcpy(name, &entry.name, SAVE_FS_LIST_MAX_NAME_LENGTH);
    memcpy(info, &entry.value.save_file_info, sizeof(save_file_info_t));
    return 1;
}

int NxSave::save_hierarchical_file_table_find_next_directory(hierarchical_save_file_table_ctx_t *ctx, save_find_position_t *position, char *name) {
    if (position->next_directory == 0) {
        return 0;
    }
    save_fs_list_entry_t entry;
    if(!save_fs_list_get_value(&ctx->directory_table, position->next_directory, &entry)) {
        return 0;
    }
    position->next_directory = entry.value.next_sibling;
    memcpy(name, &entry.name, SAVE_FS_LIST_MAX_NAME_LENGTH);
    return 1;
}

void NxSave::save_ivfc_set_level_validities(hierarchical_integrity_verification_storage_ctx_t *ctx, ivfc_save_hdr_t *ivfc) {
    for (unsigned int i = 0; i < ivfc->num_levels - 1; i++) {
        validity_t level_validity = VALIDITY_VALID;
        for (unsigned int j = 0; j < ctx->integrity_storages[i].sector_count; j++) {
            if (ctx->level_validities[i][j] == VALIDITY_INVALID) {
                level_validity = VALIDITY_INVALID;
                break;
            }
            if (ctx->level_validities[i][j] == VALIDITY_UNCHECKED && level_validity != VALIDITY_INVALID) {
                level_validity = VALIDITY_UNCHECKED;
            }
        }
        ctx->levels[i].hash_validity = level_validity;
    }
}

validity_t NxSave::save_filesystem_verify(save_ctx_t *ctx) {
    validity_t journal_validity = save_ivfc_validate(&ctx->core_data_ivfc_storage, &ctx->header.data_ivfc_header);
    save_ivfc_set_level_validities(&ctx->core_data_ivfc_storage, &ctx->header.data_ivfc_header);

    if (!ctx->fat_ivfc_storage.levels[0].save_ctx) return journal_validity;

    validity_t fat_validity = save_ivfc_validate(&ctx->fat_ivfc_storage, &ctx->header.fat_ivfc_header);
    save_ivfc_set_level_validities(&ctx->fat_ivfc_storage, &ctx->header.fat_ivfc_header);

    if (journal_validity != VALIDITY_VALID) return journal_validity;
    if (fat_validity != VALIDITY_VALID) return fat_validity;

    return journal_validity;
}

uint32_t NxSave::save_remap_read(remap_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count) {
    remap_entry_ctx_t *entry = save_remap_get_map_entry(ctx, offset);
    uint64_t in_pos = offset;
    uint32_t out_pos = 0;
    uint32_t remaining = count;

    while (remaining) {
        uint64_t entry_pos = in_pos - entry->virtual_offset;
        uint32_t bytes_to_read = entry->virtual_offset_end - in_pos < remaining ? (uint32_t)(entry->virtual_offset_end - in_pos) : remaining;
        uint32_t br;
        switch (ctx->type) {
            case STORAGE_BYTES:
                seek(ctx->base_storage_offset + entry->physical_offset + entry_pos);
                read((uint8_t *)buffer + out_pos, bytes_to_read, &br);
                break;
            case STORAGE_DUPLEX:
                save_duplex_storage_read(ctx->duplex, (uint8_t *)buffer + out_pos, ctx->base_storage_offset + entry->physical_offset + entry_pos, bytes_to_read);
                break;
            default:
                break;
        }

        out_pos += bytes_to_read;
        in_pos += bytes_to_read;
        remaining -= bytes_to_read;

        if (in_pos >= entry->virtual_offset_end)
            entry = entry->next;
    }
    return out_pos;
}

size_t NxSave::save_ivfc_level_fread(ivfc_level_save_ctx_t *ctx, void *buffer, uint64_t offset, size_t count) {
    UINT br;
    switch (ctx->type) {
        case STORAGE_BYTES:
            seek(ctx->hash_offset + offset);
            read(buffer, count, &br);
            return br;
        case STORAGE_REMAP:
            save_remap_read(&ctx->save_ctx->meta_remap_storage, buffer, ctx->data_offset + offset, count);
            return count;
        case STORAGE_JOURNAL:
            save_journal_storage_read(&ctx->save_ctx->journal_storage, &ctx->save_ctx->data_remap_storage, buffer, ctx->data_offset + offset, count);
            return count;
        default:
            return 0;
    }
}
uint32_t NxSave::save_journal_storage_read(journal_storage_ctx_t *ctx, remap_storage_ctx_t *remap, void *buffer, uint64_t offset, size_t count) {
    uint64_t in_pos = offset;
    uint32_t out_pos = 0;
    uint32_t remaining = count;

    while (remaining) {
        uint32_t block_num = (uint32_t)(in_pos / ctx->block_size);
        uint32_t block_pos = (uint32_t)(in_pos % ctx->block_size);
        uint64_t physical_offset = ctx->map.entries[block_num].physical_index * ctx->block_size + block_pos;
        uint32_t bytes_to_read = ctx->block_size - block_pos < remaining ? ctx->block_size - block_pos : remaining;

        save_remap_read(remap, (uint8_t *)buffer + out_pos, ctx->journal_data_offset + physical_offset, bytes_to_read);

        out_pos += bytes_to_read;
        in_pos += bytes_to_read;
        remaining -= bytes_to_read;
    }
    return out_pos;
}

void NxSave::save_ivfc_storage_read(integrity_verification_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count, int32_t verify) {
    if (count > ctx->sector_size) {
        fprintf(stderr, "IVFC read exceeds sector size!\n");
        exit(EXIT_FAILURE);
    }

    uint64_t block_index = offset / ctx->sector_size;

    if (ctx->block_validities[block_index] == VALIDITY_INVALID && verify) {
        fprintf(stderr, "Hash error!\n");
        exit(EXIT_FAILURE);
    }

    uint8_t hash_buffer[0x20] = {0};
    uint8_t zeroes[0x20] = {0};
    uint64_t hash_pos = block_index * 0x20;
    if (ctx->next_level) {
        save_ivfc_storage_read(ctx->next_level, hash_buffer, hash_pos, 0x20, verify);
    } else {
        save_ivfc_level_fread(ctx->hash_storage, hash_buffer, hash_pos, 0x20);
    }

    if (!memcmp(hash_buffer, zeroes, 0x20)) {
        memset(buffer, 0, count);
        ctx->block_validities[block_index] = VALIDITY_VALID;
        return;
    }

    save_ivfc_level_fread(ctx->base_storage, buffer, offset, count);

    if (!(verify && ctx->block_validities[block_index] == VALIDITY_UNCHECKED)) {
        return;
    }

    uint8_t hash[0x20] = {0};
    uint8_t *data_buffer = (uint8_t*)calloc(1, ctx->sector_size);
    memcpy(data_buffer, buffer, count);

    /*
    sha_ctx_t *sha_ctx = new_sha_ctx(HASH_TYPE_SHA256, 0);
    sha_update(sha_ctx, ctx->salt, 0x20);
    sha_update(sha_ctx, data_buffer, ctx->sector_size);
    sha_get_hash(sha_ctx, hash);
    free_sha_ctx(sha_ctx);
    */
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, ctx->salt, 0x20);
    SHA256_Update(&sha_ctx, data_buffer, ctx->sector_size);
    SHA256_Final(hash, &sha_ctx);

    hash[0x1F] |= 0x80;

    free(data_buffer);
    if (memcmp(hash_buffer, hash, 0x20)) {
        ctx->block_validities[block_index] = VALIDITY_INVALID;
    } else {
        ctx->block_validities[block_index] = VALIDITY_VALID;
    }

    if (ctx->block_validities[block_index] == VALIDITY_INVALID && verify) {
        fprintf(stderr, "Hash error!\n");
        exit(EXIT_FAILURE);
    }
}
uint32_t NxSave::save_allocation_table_storage_read(allocation_table_storage_ctx_t *ctx, void *buffer, uint64_t offset, size_t count) {
    allocation_table_iterator_ctx_t iterator;
    save_allocation_table_iterator_begin(&iterator, ctx->fat, ctx->initial_block);
    uint64_t in_pos = offset;
    uint32_t out_pos = 0;
    uint32_t remaining = count;

    while (remaining) {
        uint32_t block_num = (uint32_t)(in_pos / ctx->block_size);
        save_allocation_table_iterator_seek(&iterator, block_num);

        uint32_t segment_pos = (uint32_t)(in_pos - (uint64_t)iterator.virtual_block * ctx->block_size);
        uint64_t physical_offset = iterator.physical_block * ctx->block_size + segment_pos;

        uint32_t remaining_in_segment = iterator.current_segment_size * ctx->block_size - segment_pos;
        uint32_t bytes_to_read = remaining < remaining_in_segment ? remaining : remaining_in_segment;

        uint32_t sector_size = ctx->base_storage->integrity_storages[3].sector_size;
        uint32_t chunk_remaining = bytes_to_read;
        for (unsigned int i = 0; i < bytes_to_read; i += sector_size) {
            uint32_t bytes_to_request = chunk_remaining < sector_size ? chunk_remaining : sector_size;
            save_ivfc_storage_read(&ctx->base_storage->integrity_storages[3], (uint8_t *)buffer + out_pos + i, physical_offset + i, bytes_to_request, 0);
            chunk_remaining -= bytes_to_request;
        }

        out_pos += bytes_to_read;
        in_pos += bytes_to_read;
        remaining -= bytes_to_read;
    }
    return out_pos;
}

uint32_t NxSave::save_fs_list_get_capacity(save_filesystem_list_ctx_t *ctx) {
    uint32_t capacity;
    save_allocation_table_storage_read(&ctx->storage, &capacity, 4, 4);
    return capacity;
}

uint32_t NxSave::save_fs_list_read_entry(save_filesystem_list_ctx_t *ctx, uint32_t index, save_fs_list_entry_t *entry) {
    return save_allocation_table_storage_read(&ctx->storage, entry, index * SAVE_FS_LIST_ENTRY_SIZE, SAVE_FS_LIST_ENTRY_SIZE);
}

int NxSave::save_fs_list_get_value(save_filesystem_list_ctx_t *ctx, uint32_t index, save_fs_list_entry_t *value) {
    if (index >= save_fs_list_get_capacity(ctx)) {
        return 0;
    }
    save_fs_list_read_entry(ctx, index, value);
    return 1;
}
validity_t NxSave::check_memory_hash_table(FILE *f_in, unsigned char *hash_table, uint64_t data_ofs, uint64_t data_len, uint64_t block_size, int full_block) {
    if (block_size == 0) {
        /* Block size of 0 is always invalid. */
        return VALIDITY_INVALID;
    }
    unsigned char cur_hash[0x20];
    uint64_t read_size = block_size;
    unsigned char *block = (u8*)malloc(block_size);
    if (block == NULL) {
        fprintf(stderr, "Failed to allocate hash block!\n");
        exit(EXIT_FAILURE);
    }
    u32 br;
    validity_t result = VALIDITY_VALID;
    unsigned char *cur_hash_table_entry = hash_table;
    for (uint64_t ofs = 0; ofs < data_len; ofs += read_size) {
        seek(ofs + data_ofs);
        if (ofs + read_size > data_len) {
            /* Last block... */
            memset(block, 0, read_size);
            read_size = data_len - ofs;
        }

        if (read(block, read_size, &br) || br != read_size) {
            fprintf(stderr, "Failed to read file!\n");
            exit(EXIT_FAILURE);
        }
        sha256_hash_buffer(cur_hash, block, full_block ? block_size : read_size);
        if (memcmp(cur_hash, cur_hash_table_entry, 0x20) != 0) {
            result = VALIDITY_INVALID;
            break;
        }
        cur_hash_table_entry += 0x20;
    }
    free(block);

    return result;
}



int NxSave::visit_save_file(uint32_t file_index, vector<NxSaveFile> &entries, const u32 parent_idx, const string dir_path) {
    save_fs_list_entry_t entry = {0, "", {0}, 0};
    if (!save_fs_list_get_value(&ctx.save_filesystem_core.file_table.file_table, file_index, &entry)) {
        return 0;
    }

    NxSaveFile file;
    file.parent = this;
    file.idx = file_index;
    file.filename = string(entry.name);
    file.path = dir_path;
    file.size = entry.value.save_file_info.length;
    file.parent_idx = entry.parent;
    file.start_block = entry.value.save_file_info.start_block;
    file.next_file = entry.value.save_find_position.next_file;
    file.next_dir = entry.value.save_find_position.next_directory;
    file.next_sibling = entry.value.next_sibling;
    file.is_directory = false;
    entries.push_back(file);

    int found_file = 1;
    if (entry.value.next_sibling) {
        return found_file | visit_save_file(entry.value.next_sibling, entries, parent_idx, dir_path);
    }
    return found_file;
}


int NxSave::visit_save_dir(uint32_t dir_index, vector<NxSaveFile> &entries, const u32 parent_idx, const string parent_path) {
    save_fs_list_entry_t entry = {0, "", {0}, 0};
    if (!save_fs_list_get_value(&ctx.save_filesystem_core.file_table.directory_table, dir_index, &entry)) {
        return 0;
    }

    NxSaveFile dir;
    dir.parent = this;
    dir.idx = dir_index;
    dir.filename = string(entry.name);
    dir.path = parent_path;
    dir.is_directory = true;
    if (parent_idx != dir_index)
        dir.parent_idx = parent_idx;
    entries.push_back(dir);

    u32 *cur_idx = new u32(dir_index);
    string *cur_path = new string(parent_path);
    if (strlen(entry.name)) {
        if (!endsWith(*cur_path, string("/")))
            cur_path->append("/");
        cur_path->append(entry.name);
    }
    int any_files = 0;
    if (entry.value.next_sibling) {
        any_files |= visit_save_dir(entry.value.next_sibling, entries, *cur_idx, parent_path);
    }
    if (entry.value.save_find_position.next_directory) {
        any_files |= visit_save_dir(entry.value.save_find_position.next_directory, entries, *cur_idx, *cur_path);
    }
    if (entry.value.save_find_position.next_file) {
        any_files |= visit_save_file(entry.value.save_find_position.next_file, entries, *cur_idx, *cur_path);
    }

    delete cur_path;
    delete cur_idx;
    return any_files;
}
