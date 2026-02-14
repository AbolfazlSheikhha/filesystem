#ifndef DISK_IO_H
#define DISK_IO_H

#include "../common/fs_types.h"

void die(const char *msg);
void fs_sync_metadata(void);
void fs_read_block(uint32_t index, BlockOnDisk *blk);
void fs_write_block(uint32_t index, const BlockOnDisk *blk);
void fs_load_metadata(void);
void fs_format_new(void);
void fs_open_disk(void);

#endif /* DISK_IO_H */
