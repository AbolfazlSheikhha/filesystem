#ifndef FS_LAYOUT_H
#define FS_LAYOUT_H

#include <sys/types.h>
#include "fs_config.h"
#include "fs_types.h"

// ------------ Disk Layout Offset Calculations ------------

static inline off_t superblock_offset(void) { return 0; }

static inline off_t usertable_offset(void) {
    return (off_t)sizeof(SuperBlock);
}

static inline off_t grouptable_offset(void) {
    return usertable_offset() + (off_t)sizeof(UserEntry) * FS_MAX_USERS;
}

static inline off_t filetable_offset(void) {
    return grouptable_offset() + (off_t)sizeof(GroupEntry) * FS_MAX_GROUPS;
}

static inline off_t dataarea_offset(void) {
    return filetable_offset() + (off_t)sizeof(FileEntry) * FS_MAX_FILES;
}

static inline off_t block_offset(uint32_t block_index) {
    return dataarea_offset() + (off_t)block_index * FS_BLOCK_SIZE;
}

#endif /* FS_LAYOUT_H */
