#ifndef FS_CONFIG_H
#define FS_CONFIG_H

// ------------ Configuration constants ------------
#define FS_DISK_FILE   "filesys.db"
#define FS_DISK_SIZE   (128 * 1024 * 1024)    // 128MB = 32K blocks of 4KB each
#define FS_BLOCK_SIZE  4096
#define FS_MAX_FILES   10000
#define FS_FILENAME_MAX 64
#define FS_MAGIC       0xDEADBEEF
#define FS_VERSION     2                // Updated version for user/group support
#define FS_INVALID_BLOCK 0xFFFFFFFFu    // "no block"

#define FLAG_CREATE    0x1              // open() flag: create file if missing
#define FLAG_WRITE     0x2              // open() flag: open for writing

// ------------ User and Group Management Constants ------------
#define FS_MAX_USERS   32
#define FS_MAX_GROUPS  32
#define FS_USERNAME_MAX 32
#define FS_GROUPNAME_MAX 32
#define FS_MAX_GROUPS_PER_USER 16       // max groups a user can belong to

// Permission bits (like Unix)
#define PERM_OWNER_READ   0400
#define PERM_OWNER_WRITE  0200
#define PERM_OWNER_EXEC   0100
#define PERM_GROUP_READ   0040
#define PERM_GROUP_WRITE  0020
#define PERM_GROUP_EXEC   0010
#define PERM_OTHER_READ   0004
#define PERM_OTHER_WRITE  0002
#define PERM_OTHER_EXEC   0001

// Root user ID
#define ROOT_UID 0
#define ROOT_GID 0

// ------------ Stress Test Configuration ------------
#define STRESS_NUM_FILES      5000
#define STRESS_NUM_OPS        25000
#define STRESS_MAX_WRITE_SIZE 4096
#define STRESS_MAX_FILE_SIZE  16384

// ------------ Free Space Management ------------
#define BITMAP_BITS_PER_WORD 64
#define BITMAP_MAX_WORDS ((FS_DISK_SIZE / FS_BLOCK_SIZE / BITMAP_BITS_PER_WORD) + 1)

#endif /* FS_CONFIG_H */
