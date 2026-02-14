#ifndef FS_TYPES_H
#define FS_TYPES_H

#include <stdint.h>
#include "fs_config.h"

// bytes available for user data in each block
// (4 bytes reserved for "next block" pointer)
#define BLOCK_DATA_SIZE (FS_BLOCK_SIZE - sizeof(uint32_t))

// ------------ On-disk data structures ------------
#pragma pack(push, 1)

// User entry stored on disk
typedef struct {
    char     username[FS_USERNAME_MAX];
    uint32_t uid;                        // user ID
    uint32_t primary_gid;                // primary group ID
    uint32_t secondary_gids[FS_MAX_GROUPS_PER_USER]; // secondary groups
    uint8_t  num_secondary_groups;       // number of secondary groups
    uint8_t  in_use;                     // 1 if this entry is valid
} UserEntry;

// Group entry stored on disk
typedef struct {
    char     groupname[FS_GROUPNAME_MAX];
    uint32_t gid;                        // group ID
    uint8_t  in_use;                     // 1 if this entry is valid
} GroupEntry;

// Global filesystem metadata (lives at the beginning of filesys.db)
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t block_size;
    uint32_t disk_size;
    uint32_t last_allocated_block; // Kept for legacy compatibility, unused in new allocator
    uint32_t num_files;
    uint32_t root_dir_head;       // index of first FileEntry in linked list, or -1
    uint32_t num_users;           // number of users
    uint32_t num_groups;          // number of groups
    uint32_t next_uid;            // next available UID
    uint32_t next_gid;            // next available GID
} SuperBlock;

// Description of one file (metadata only, NOT the contents)
typedef struct {
    char     name[FS_FILENAME_MAX]; // null-terminated filename
    uint32_t type;                  // 0 = regular file (only type we use)
    uint32_t permissions;           // unix-style permission bits (rwxrwxrwx)
    uint32_t size;                  // current size of file in bytes
    uint32_t first_block;           // index of first data block or FS_INVALID_BLOCK
    int32_t  next_entry;            // linked-list index of next FileEntry or -1
    uint32_t owner_uid;             // owner user ID
    uint32_t owner_gid;             // owner group ID
    uint8_t  in_use;                // 1 if this entry is valid
} FileEntry;

// One data block on disk. First 4 bytes store index of next block.
typedef struct {
    uint32_t next_block;           // FS_INVALID_BLOCK if this is the last block
    uint8_t  data[BLOCK_DATA_SIZE];
} BlockOnDisk;

// Directory entry stored inside a directory's data blocks.
// A directory's data is simply an array of these entries.
typedef struct {
    char     name[FS_FILENAME_MAX]; // null-terminated entry name
    int32_t  file_index;            // index into file_table, or FS_INVALID_ENTRY if slot is free
} DirEntry;

// How many DirEntry structs fit in one block's data area
#define DIRENTS_PER_BLOCK  (BLOCK_DATA_SIZE / sizeof(DirEntry))

#pragma pack(pop)

#endif /* FS_TYPES_H */
