#ifndef FS_STATE_H
#define FS_STATE_H

#include "../common/fs_config.h"
#include "../common/fs_types.h"

// ------------ Global state in memory ------------
extern int disk_fd;
extern SuperBlock sb;
extern FileEntry file_table[FS_MAX_FILES];
extern UserEntry user_table[FS_MAX_USERS];
extern GroupEntry group_table[FS_MAX_GROUPS];
extern uint32_t max_data_blocks;

// Currently logged in user (default: root)
extern uint32_t current_uid;
extern uint32_t current_gid;

// Currently opened file (at most one at a time)
extern int current_file_index;
extern uint32_t current_file_flags;

// Free space bitmap
extern uint64_t free_bitmap[BITMAP_MAX_WORDS];
extern uint32_t bitmap_num_words;

#endif /* FS_STATE_H */
