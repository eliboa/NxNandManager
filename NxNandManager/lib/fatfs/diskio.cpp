/*-----------------------------------------------------------------------*/
/* Low level disk I/O module SKELETON for FatFs     (C)ChaN, 2019        */
/*-----------------------------------------------------------------------*/
/* If a working storage control module is available, it should be        */
/* attached to the FatFs via a glue function rather than modifying it.   */
/* This is an example of glue functions to attach various exsisting      */
/* storage control modules to the FatFs module with a defined API.       */
/*-----------------------------------------------------------------------*/

//#include "ff.h"			/* Obtains integer types */
#include "diskio.h"		/* Declarations of disk functions */


static NXFS nxfs_arr[FF_VOLUMES];

int get_ix_by_nx_partition(NxPartition *nxp)
{
    for (int i(0); i < FF_VOLUMES; i++) if (nxfs_arr[i].nx_partition == nxp)
        return nxfs_arr[i].index;

    return 0;
}

NXFS* get_nxfs_by_ix(int index)
{
   if (index && index <= FF_VOLUMES)
       return &nxfs_arr[index-1];

   return nullptr;
}

int get_available_nxfs()
{
    for (int i(0); i < FF_VOLUMES; i++) if (nxfs_arr[i].index == 0)
        return i+1;

    return 0;
}

int nxfs_initialize(NxPartition* nx_partition, FATFS* fatfs)
{
    int ix = get_available_nxfs();
    if (!ix)
        return STA_NOINIT;

    nxfs_arr[ix-1].nx_partition = nx_partition;
    nxfs_arr[ix-1].fatfs = fatfs;
    nxfs_arr[ix-1].index = ix;
    // Create new handle
    nxfs_arr[ix-1].nx_handle = new NxHandle(nx_partition->nxStorage());
    if (nx_partition->nxHandle->isSplitted())
        nxfs_arr[ix-1].nx_handle->detectSplittedStorage();
    nxfs_arr[ix-1].nx_handle->initHandle(nx_partition->isEncryptedPartition() ? DECRYPT : NO_CRYPTO, nx_partition);
    return 0;
}

int nxfs_uninit(FATFS* fatfs)
{
    NXFS *fs = get_nxfs_by_ix(fatfs->pdrv);
    if (!fs || !fs->index || fs->index > FF_VOLUMES)
        return RES_PARERR;

    fs->nx_partition = nullptr;
    fs->fatfs = nullptr;
    fs->index = 0;
    delete fs->nx_handle;
    return 0;
}


/*-----------------------------------------------------------------------*/
/* Get Drive Status                                                      */
/*-----------------------------------------------------------------------*/

DSTATUS disk_status (
	BYTE pdrv		/* Physical drive nmuber to identify the drive */
)
{
    NXFS *fs = get_nxfs_by_ix(pdrv);
    if (fs != nullptr && fs->nx_partition != nullptr)
        return 0;
	return STA_NOINIT;
}



/*-----------------------------------------------------------------------*/
/* Inidialize a Drive                                                    */
/*-----------------------------------------------------------------------*/

DSTATUS disk_initialize (
	BYTE pdrv				/* Physical drive nmuber to identify the drive */
)
{
    /*
    DSTATUS ds = disk_status(pdrv);


    */
    return disk_status(pdrv);
}



/*-----------------------------------------------------------------------*/
/* Read Sector(s)                                                        */
/*-----------------------------------------------------------------------*/

DRESULT disk_read (
	BYTE pdrv,		/* Physical drive nmuber to identify the drive */
	BYTE *buff,		/* Data buffer to store read data */
	LBA_t sector,	/* Start sector in LBA */
	UINT count		/* Number of sectors to read */
)
{
    NXFS *fs = get_nxfs_by_ix(pdrv);
    if (fs == nullptr || fs->nx_partition == nullptr)
        return RES_PARERR;

    if (fs->nx_partition->isEncryptedPartition())
        fs->nx_handle->setCrypto(DECRYPT);

    if (!fs->nx_handle->read((u32)sector, (void*)buff, nullptr, count * NX_BLOCKSIZE))
        return RES_PARERR;

    return RES_OK;
}



/*-----------------------------------------------------------------------*/
/* Write Sector(s)                                                       */
/*-----------------------------------------------------------------------*/

#if FF_FS_READONLY == 0

DRESULT disk_write (
	BYTE pdrv,			/* Physical drive nmuber to identify the drive */
	const BYTE *buff,	/* Data to be written */
	LBA_t sector,		/* Start sector in LBA */
	UINT count			/* Number of sectors to write */
)
{
    NXFS *fs = get_nxfs_by_ix(pdrv);
    if (fs == nullptr || fs->nx_partition == nullptr)
        return RES_PARERR;

    if (fs->nx_partition->isEncryptedPartition())
        fs->nx_handle->setCrypto(ENCRYPT);

    DWORD bytesWrite = 0;
    if (!fs->nx_handle->write((u32)(sector), (void*)buff, &bytesWrite, count * NX_BLOCKSIZE))
        return RES_PARERR;

    return RES_OK;

}

#endif


/*-----------------------------------------------------------------------*/
/* Miscellaneous Functions                                               */
/*-----------------------------------------------------------------------*/

DRESULT disk_ioctl (
	BYTE pdrv,		/* Physical drive nmuber (0..) */
	BYTE cmd,		/* Control code */
	void *buff		/* Buffer to send/receive control data */
)
{	
    NXFS *fs = get_nxfs_by_ix(pdrv);
    if (fs == nullptr || fs->nx_partition == nullptr)
        return RES_OK;

    if (cmd == GET_SECTOR_COUNT)
    {
        u32 sector_count = fs->nx_partition->lbaEnd() - fs->nx_partition->lbaStart();
        memcpy(buff, &sector_count, sizeof (u32));
    }
    else if (cmd == GET_BLOCK_SIZE) {
        u32 blocksize = NX_BLOCKSIZE;
        memcpy(buff, &blocksize, sizeof (u32));
    }
    return RES_OK;
}

