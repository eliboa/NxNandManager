#ifndef PROGRESS_INFO_H
#define PROGRESS_INFO_H

#include <vector>
#include "types.h"

typedef struct ProgressInfo ProgressInfo;
struct ProgressInfo {
    int mode;
    bool show = true;
    timepoint_t begin_time;
    int elapsed_seconds = 0;
    char storage_name[256];
    u64 bytesCount = 0;
    u64 bytesTotal = 0;
    int percent = 0;
    bool isSubProgressInfo = false;
};

typedef struct part_params_t part_params_t;
struct part_params_t {
    int nx_type = UNKNOWN;
    int crypto_mode = NO_CRYPTO;
    u32 new_size = 0;
    bool format = false;
    bool passThroughZero = false;
    bool zipOutput = false;
    bool isSubParam = false;
};

typedef struct params_t params_t;
struct params_t {
    int crypto_mode = NO_CRYPTO;
    bool rawnand_only = false;
    bool split_output = false;
    u64 chunksize = 0;
    int partition = UNKNOWN;
    bool passThroughZero = false;
    bool zipOutput = false;
    u32 user_new_size = 0;
    bool format_user = false;
    std::vector<part_params_t> parts;
    int emunand_type = 0;
    bool isSubParam = false;
    char boot0_path[260];
    char boot1_path[260];
};
part_params_t* GetPartParam(params_t *params, int nxType);

#endif // PROGRESS_INFO_H
