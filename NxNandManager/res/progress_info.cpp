#include "progress_info.h"

part_params_t* GetPartParam(params_t *params, int nxType)
{
    for(part_params_t &partPar : params->parts)
        if(partPar.nx_type == nxType)
            return &partPar;

    return nullptr;
}
