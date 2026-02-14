#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

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

#pragma pack(pop)

// ------------ Free Space Management Structures ------------
// BITMASK-based free space management
// Each bit represents one block: 1 = free, 0 = used
#define BITMAP_BITS_PER_WORD 64
#define BITMAP_MAX_WORDS ((FS_DISK_SIZE / FS_BLOCK_SIZE / BITMAP_BITS_PER_WORD) + 1)
static uint64_t free_bitmap[BITMAP_MAX_WORDS];
static uint32_t bitmap_num_words = 0;  // actual number of words needed

// ------------ Global state in memory ------------
static int disk_fd = -1;
static SuperBlock sb;
static FileEntry file_table[FS_MAX_FILES];
static UserEntry user_table[FS_MAX_USERS];
static GroupEntry group_table[FS_MAX_GROUPS];
static uint32_t max_data_blocks = 0;

// Currently logged in user (default: root)
static uint32_t current_uid = ROOT_UID;
static uint32_t current_gid = ROOT_GID;

// Currently opened file (at most one at a time)
static int current_file_index = -1;     // index into file_table, -1 => none open
static uint32_t current_file_flags = 0; // flags passed to open()

// ------------ Forward Declarations ------------
static void fs_free_blocks(uint32_t start, uint32_t size);
static int fs_alloc_blocks(uint32_t count, uint32_t *out_start);
static void fs_rebuild_freelist(void);
static void fs_read_block(uint32_t index, BlockOnDisk *blk);
static void fs_write_block(uint32_t index, const BlockOnDisk *blk);
static off_t block_offset(uint32_t block_index);

// ------------ Helper Functions ------------
static off_t superblock_offset(void) { return 0; }
static off_t usertable_offset(void) {
    return (off_t)sizeof(SuperBlock);
}
static off_t grouptable_offset(void) {
    return usertable_offset() + (off_t)sizeof(UserEntry) * FS_MAX_USERS;
}
static off_t filetable_offset(void) {
    return grouptable_offset() + (off_t)sizeof(GroupEntry) * FS_MAX_GROUPS;
}
static off_t dataarea_offset(void) {
    return filetable_offset() + (off_t)sizeof(FileEntry) * FS_MAX_FILES;
}
static off_t block_offset(uint32_t block_index) {
    return dataarea_offset() + (off_t)block_index * FS_BLOCK_SIZE;
}

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Write superblock + user/group tables + file table back to disk
static void fs_sync_metadata(void) {
    if (pwrite(disk_fd, &sb, sizeof(sb), superblock_offset()) != (ssize_t)sizeof(sb)) {
        die("pwrite superblock");
    }
    if (pwrite(disk_fd, user_table, sizeof(user_table), usertable_offset()) != (ssize_t)sizeof(user_table)) {
        die("pwrite user_table");
    }
    if (pwrite(disk_fd, group_table, sizeof(group_table), grouptable_offset()) != (ssize_t)sizeof(group_table)) {
        die("pwrite group_table");
    }
    if (pwrite(disk_fd, file_table, sizeof(file_table), filetable_offset()) != (ssize_t)sizeof(file_table)) {
        die("pwrite file_table");
    }
    fsync(disk_fd);
}

// ------------ BITMASK-based Free Space Management Implementation ------------

// Helper: Set bit 'block' in bitmap (mark as free)
static inline void bitmap_set_free(uint32_t block) {
    uint32_t word = block / BITMAP_BITS_PER_WORD;
    uint32_t bit = block % BITMAP_BITS_PER_WORD;
    free_bitmap[word] |= (1ULL << bit);
}

// Helper: Clear bit 'block' in bitmap (mark as used)
static inline void bitmap_set_used(uint32_t block) {
    uint32_t word = block / BITMAP_BITS_PER_WORD;
    uint32_t bit = block % BITMAP_BITS_PER_WORD;
    free_bitmap[word] &= ~(1ULL << bit);
}

// Helper: Check if block is free
static inline int bitmap_is_free(uint32_t block) {
    uint32_t word = block / BITMAP_BITS_PER_WORD;
    uint32_t bit = block % BITMAP_BITS_PER_WORD;
    return (free_bitmap[word] >> bit) & 1;
}

// Free a range of blocks (mark as free in bitmap)
static void fs_free_blocks(uint32_t start, uint32_t size) {
    for (uint32_t i = 0; i < size; i++) {
        if (start + i < max_data_blocks) {
            bitmap_set_free(start + i);
        }
    }
}

// Allocate 'count' contiguous blocks using First-Fit strategy with bitmap
// Uses __builtin_ffsll for fast bit scanning
static int fs_alloc_blocks(uint32_t count, uint32_t *out_start) {
    if (count == 0) return -1;
    
    uint32_t consecutive = 0;
    uint32_t start_block = 0;
    
    // Fast path: scan word-by-word using __builtin_ffsll
    for (uint32_t word = 0; word < bitmap_num_words; word++) {
        uint64_t bits = free_bitmap[word];
        
        if (bits == 0) {
            // No free bits in this word, reset consecutive count
            consecutive = 0;
            continue;
        }
        
        // Check each bit in this word
        for (uint32_t bit = 0; bit < BITMAP_BITS_PER_WORD; bit++) {
            uint32_t block = word * BITMAP_BITS_PER_WORD + bit;
            if (block >= max_data_blocks) break;
            
            if ((bits >> bit) & 1) {
                // This block is free
                if (consecutive == 0) {
                    start_block = block;
                }
                consecutive++;
                
                if (consecutive >= count) {
                    // Found enough consecutive blocks, allocate them
                    *out_start = start_block;
                    for (uint32_t i = 0; i < count; i++) {
                        bitmap_set_used(start_block + i);
                    }
                    return 0; // Success
                }
            } else {
                // Block is used, reset consecutive count
                consecutive = 0;
            }
        }
    }
    
    return -1; // No contiguous space found
}

// Rebuild bitmap from file table (called on mount)
static void fs_rebuild_freelist(void) {
    // Initialize bitmap size
    bitmap_num_words = (max_data_blocks + BITMAP_BITS_PER_WORD - 1) / BITMAP_BITS_PER_WORD;
    
    // 1. Mark all blocks as free initially
    memset(free_bitmap, 0xFF, bitmap_num_words * sizeof(uint64_t));
    
    // 2. Clear bits beyond max_data_blocks (mark as used to avoid allocation)
    uint32_t last_valid_bit = max_data_blocks % BITMAP_BITS_PER_WORD;
    if (last_valid_bit != 0 && bitmap_num_words > 0) {
        // Clear upper bits in the last word
        free_bitmap[bitmap_num_words - 1] &= ((1ULL << last_valid_bit) - 1);
    }
    
    // 3. Mark blocks used by files as used (clear their bits)
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (file_table[i].in_use) {
            uint32_t idx = file_table[i].first_block;
            while (idx != FS_INVALID_BLOCK) {
                if (idx < max_data_blocks) {
                    bitmap_set_used(idx);
                }
                
                BlockOnDisk blk;
                if (pread(disk_fd, &blk, sizeof(blk), block_offset(idx)) != (ssize_t)sizeof(blk))
                    break;
                idx = blk.next_block;
            }
        }
    }
}

// ------------ Core Filesystem Initialization ------------

// Load metadata from an existing filesystem
static void fs_load_metadata(void) {
    if (pread(disk_fd, &sb, sizeof(sb), superblock_offset()) != (ssize_t)sizeof(sb)) {
        die("pread superblock");
    }
    if (sb.magic != FS_MAGIC) {
        fprintf(stderr, "Invalid filesystem magic. Maybe the disk is not initialised?\n");
        exit(EXIT_FAILURE);
    }
    if (pread(disk_fd, user_table, sizeof(user_table), usertable_offset()) != (ssize_t)sizeof(user_table)) {
        die("pread user_table");
    }
    if (pread(disk_fd, group_table, sizeof(group_table), grouptable_offset()) != (ssize_t)sizeof(group_table)) {
        die("pread group_table");
    }
    if (pread(disk_fd, file_table, sizeof(file_table), filetable_offset()) != (ssize_t)sizeof(file_table)) {
        die("pread file_table");
    }
    max_data_blocks = (FS_DISK_SIZE - (uint32_t)dataarea_offset()) / FS_BLOCK_SIZE;
    
    // Reconstruct freelist from the file usage map
    fs_rebuild_freelist();
}

// Format a brand-new filesystem in filesys.db
static void fs_format_new(void) {
    memset(&sb, 0, sizeof(sb));
    sb.magic = FS_MAGIC;
    sb.version = FS_VERSION;
    sb.block_size = FS_BLOCK_SIZE;
    sb.disk_size = FS_DISK_SIZE;
    sb.last_allocated_block = FS_INVALID_BLOCK;
    sb.num_files = 0;
    sb.root_dir_head = -1; // no files yet
    sb.num_users = 1;      // root user
    sb.num_groups = 1;     // root group
    sb.next_uid = 1;       // next available UID (0 is root)
    sb.next_gid = 1;       // next available GID (0 is root)
    
    memset(file_table, 0, sizeof(file_table));
    memset(user_table, 0, sizeof(user_table));
    memset(group_table, 0, sizeof(group_table));
    
    // Create root user
    strncpy(user_table[0].username, "root", FS_USERNAME_MAX - 1);
    user_table[0].uid = ROOT_UID;
    user_table[0].primary_gid = ROOT_GID;
    user_table[0].num_secondary_groups = 0;
    user_table[0].in_use = 1;
    
    // Create root group
    strncpy(group_table[0].groupname, "root", FS_GROUPNAME_MAX - 1);
    group_table[0].gid = ROOT_GID;
    group_table[0].in_use = 1;
    
    max_data_blocks = (FS_DISK_SIZE - (uint32_t)dataarea_offset()) / FS_BLOCK_SIZE;
    
    // Initialize bitmap - all blocks are free on a fresh format
    bitmap_num_words = (max_data_blocks + BITMAP_BITS_PER_WORD - 1) / BITMAP_BITS_PER_WORD;
    memset(free_bitmap, 0xFF, bitmap_num_words * sizeof(uint64_t));
    
    // Clear bits beyond max_data_blocks (mark as used to avoid allocation)
    uint32_t last_valid_bit = max_data_blocks % BITMAP_BITS_PER_WORD;
    if (last_valid_bit != 0 && bitmap_num_words > 0) {
        free_bitmap[bitmap_num_words - 1] &= ((1ULL << last_valid_bit) - 1);
    }
    
    fs_sync_metadata();
    
    printf("Filesystem formatted. Root user and group created.\n");
}

// Open or create the backing file and load/initialise the FS
static void fs_open_disk(void) {
    int flags = O_RDWR | O_CREAT;
    disk_fd = open(FS_DISK_FILE, flags, 0666);
    if (disk_fd < 0) die("open filesys.db");

    // Ensure the backing file has the configured size
    off_t size = lseek(disk_fd, 0, SEEK_END);
    if (size < 0) die("lseek filesys.db");
    if (size != FS_DISK_SIZE) {
        if (ftruncate(disk_fd, FS_DISK_SIZE) != 0)
            die("ftruncate filesys.db");
    }

    // Try to read existing superblock
    SuperBlock tmp;
    ssize_t n = pread(disk_fd, &tmp, sizeof(tmp), superblock_offset());
    if (n == (ssize_t)sizeof(tmp) && tmp.magic == FS_MAGIC) {
        fs_load_metadata();
    } else {
        fs_format_new();
    }
}

static void fs_read_block(uint32_t index, BlockOnDisk *blk) {
    if (index == FS_INVALID_BLOCK) {
        fprintf(stderr, "Attempted to read invalid block index\n");
        exit(EXIT_FAILURE);
    }
    if (pread(disk_fd, blk, sizeof(*blk), block_offset(index)) != (ssize_t)sizeof(*blk)) {
        die("pread block");
    }
}

static void fs_write_block(uint32_t index, const BlockOnDisk *blk) {
    if (pwrite(disk_fd, blk, sizeof(*blk), block_offset(index)) != (ssize_t)sizeof(*blk)) {
        die("pwrite block");
    }
}

// ------------ Internal File Operations ------------

// Allocate a new data block using the Freelist Allocator
static int fs_allocate_block(uint32_t *out_index) {
    if (fs_alloc_blocks(1, out_index) != 0) {
        return -1; // disk full
    }
    
    BlockOnDisk blk;
    blk.next_block = FS_INVALID_BLOCK;
    memset(blk.data, 0, sizeof(blk.data));

    if (pwrite(disk_fd, &blk, sizeof(blk), block_offset(*out_index)) != (ssize_t)sizeof(blk)) {
        die("pwrite new block");
    }
    
    fs_sync_metadata();
    return 0;
}

static int fs_find_file_by_name(const char *name) {
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (file_table[i].in_use && strncmp(file_table[i].name, name, FS_FILENAME_MAX) == 0) {
            return i;
        }
    }
    return -1;
}

static int fs_allocate_file_entry(const char *name, uint32_t type, uint32_t perm) {
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (!file_table[i].in_use) {
            FileEntry *fe = &file_table[i];
            memset(fe, 0, sizeof(*fe));
            strncpy(fe->name, name, FS_FILENAME_MAX - 1);
            fe->name[FS_FILENAME_MAX - 1] = '\0';
            fe->type = type;
            fe->permissions = perm;
            fe->size = 0;
            fe->first_block = FS_INVALID_BLOCK;
            fe->owner_uid = current_uid;     // Set owner to current user
            fe->owner_gid = current_gid;     // Set group to current user's group
            
            fe->next_entry = sb.root_dir_head;
            fe->in_use = 1;
            sb.root_dir_head = i;
            sb.num_files++;
            
            fs_sync_metadata();
            return i;
        }
    }
    return -1;
}

// ------------ User and Group Management Functions ------------

// Find user by username, returns index or -1
static int fs_find_user_by_name(const char *username) {
    for (int i = 0; i < FS_MAX_USERS; ++i) {
        if (user_table[i].in_use && strncmp(user_table[i].username, username, FS_USERNAME_MAX) == 0) {
            return i;
        }
    }
    return -1;
}

// Find user by UID, returns index or -1
static int fs_find_user_by_uid(uint32_t uid) {
    for (int i = 0; i < FS_MAX_USERS; ++i) {
        if (user_table[i].in_use && user_table[i].uid == uid) {
            return i;
        }
    }
    return -1;
}

// Find group by name, returns index or -1
static int fs_find_group_by_name(const char *groupname) {
    for (int i = 0; i < FS_MAX_GROUPS; ++i) {
        if (group_table[i].in_use && strncmp(group_table[i].groupname, groupname, FS_GROUPNAME_MAX) == 0) {
            return i;
        }
    }
    return -1;
}

// Find group by GID, returns index or -1
static int fs_find_group_by_gid(uint32_t gid) {
    for (int i = 0; i < FS_MAX_GROUPS; ++i) {
        if (group_table[i].in_use && group_table[i].gid == gid) {
            return i;
        }
    }
    return -1;
}

// Get username by UID
static const char* fs_get_username(uint32_t uid) {
    int idx = fs_find_user_by_uid(uid);
    if (idx >= 0) return user_table[idx].username;
    return "unknown";
}

// Get groupname by GID
static const char* fs_get_groupname(uint32_t gid) {
    int idx = fs_find_group_by_gid(gid);
    if (idx >= 0) return group_table[idx].groupname;
    return "unknown";
}

// Check if user is member of group
static int fs_user_in_group(uint32_t uid, uint32_t gid) {
    int user_idx = fs_find_user_by_uid(uid);
    if (user_idx < 0) return 0;
    
    UserEntry *user = &user_table[user_idx];
    
    // Check primary group
    if (user->primary_gid == gid) return 1;
    
    // Check secondary groups
    for (int i = 0; i < user->num_secondary_groups; ++i) {
        if (user->secondary_gids[i] == gid) return 1;
    }
    return 0;
}

// useradd <username> - Add a new user
static int cmd_useradd(const char *username) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can add users.\n");
        return -1;
    }
    
    if (fs_find_user_by_name(username) >= 0) {
        fprintf(stderr, "User '%s' already exists.\n", username);
        return -1;
    }
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < FS_MAX_USERS; ++i) {
        if (!user_table[i].in_use) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        fprintf(stderr, "Maximum number of users reached.\n");
        return -1;
    }
    
    // Create a group with same name as user
    int group_idx = fs_find_group_by_name(username);
    uint32_t new_gid;
    
    if (group_idx < 0) {
        // Create new group for user
        int gslot = -1;
        for (int i = 0; i < FS_MAX_GROUPS; ++i) {
            if (!group_table[i].in_use) {
                gslot = i;
                break;
            }
        }
        
        if (gslot < 0) {
            fprintf(stderr, "Maximum number of groups reached.\n");
            return -1;
        }
        
        new_gid = sb.next_gid++;
        strncpy(group_table[gslot].groupname, username, FS_GROUPNAME_MAX - 1);
        group_table[gslot].groupname[FS_GROUPNAME_MAX - 1] = '\0';
        group_table[gslot].gid = new_gid;
        group_table[gslot].in_use = 1;
        sb.num_groups++;
    } else {
        new_gid = group_table[group_idx].gid;
    }
    
    // Create user
    UserEntry *user = &user_table[slot];
    memset(user, 0, sizeof(*user));
    strncpy(user->username, username, FS_USERNAME_MAX - 1);
    user->username[FS_USERNAME_MAX - 1] = '\0';
    user->uid = sb.next_uid++;
    user->primary_gid = new_gid;
    user->num_secondary_groups = 0;
    user->in_use = 1;
    sb.num_users++;
    
    fs_sync_metadata();
    printf("User '%s' created with UID %u, GID %u.\n", username, user->uid, user->primary_gid);
    return 0;
}

// userdel <username> - Delete a user
static int cmd_userdel(const char *username) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can delete users.\n");
        return -1;
    }
    
    if (strcmp(username, "root") == 0) {
        fprintf(stderr, "Cannot delete root user.\n");
        return -1;
    }
    
    int idx = fs_find_user_by_name(username);
    if (idx < 0) {
        fprintf(stderr, "User '%s' not found.\n", username);
        return -1;
    }
    
    user_table[idx].in_use = 0;
    sb.num_users--;
    fs_sync_metadata();
    
    printf("User '%s' deleted.\n", username);
    return 0;
}

// groupadd <groupname> - Add a new group
static int cmd_groupadd(const char *groupname) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can add groups.\n");
        return -1;
    }
    
    if (fs_find_group_by_name(groupname) >= 0) {
        fprintf(stderr, "Group '%s' already exists.\n", groupname);
        return -1;
    }
    
    int slot = -1;
    for (int i = 0; i < FS_MAX_GROUPS; ++i) {
        if (!group_table[i].in_use) {
            slot = i;
            break;
        }
    }
    
    if (slot < 0) {
        fprintf(stderr, "Maximum number of groups reached.\n");
        return -1;
    }
    
    GroupEntry *group = &group_table[slot];
    strncpy(group->groupname, groupname, FS_GROUPNAME_MAX - 1);
    group->groupname[FS_GROUPNAME_MAX - 1] = '\0';
    group->gid = sb.next_gid++;
    group->in_use = 1;
    sb.num_groups++;
    
    fs_sync_metadata();
    printf("Group '%s' created with GID %u.\n", groupname, group->gid);
    return 0;
}

// groupdel <groupname> - Delete a group
static int cmd_groupdel(const char *groupname) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can delete groups.\n");
        return -1;
    }
    
    if (strcmp(groupname, "root") == 0) {
        fprintf(stderr, "Cannot delete root group.\n");
        return -1;
    }
    
    int idx = fs_find_group_by_name(groupname);
    if (idx < 0) {
        fprintf(stderr, "Group '%s' not found.\n", groupname);
        return -1;
    }
    
    group_table[idx].in_use = 0;
    sb.num_groups--;
    fs_sync_metadata();
    
    printf("Group '%s' deleted.\n", groupname);
    return 0;
}

// usermod -aG <group> <user> - Add user to group
static int cmd_usermod_aG(const char *groupname, const char *username) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can modify users.\n");
        return -1;
    }
    
    int user_idx = fs_find_user_by_name(username);
    if (user_idx < 0) {
        fprintf(stderr, "User '%s' not found.\n", username);
        return -1;
    }
    
    int group_idx = fs_find_group_by_name(groupname);
    if (group_idx < 0) {
        fprintf(stderr, "Group '%s' not found.\n", groupname);
        return -1;
    }
    
    UserEntry *user = &user_table[user_idx];
    uint32_t gid = group_table[group_idx].gid;
    
    // Check if already member
    if (fs_user_in_group(user->uid, gid)) {
        printf("User '%s' is already a member of group '%s'.\n", username, groupname);
        return 0;
    }
    
    if (user->num_secondary_groups >= FS_MAX_GROUPS_PER_USER) {
        fprintf(stderr, "User is already member of maximum number of groups.\n");
        return -1;
    }
    
    user->secondary_gids[user->num_secondary_groups++] = gid;
    fs_sync_metadata();
    
    printf("User '%s' added to group '%s'.\n", username, groupname);
    return 0;
}

// Switch user (su) command
static int cmd_su(const char *username) {
    int idx = fs_find_user_by_name(username);
    if (idx < 0) {
        fprintf(stderr, "User '%s' not found.\n", username);
        return -1;
    }
    
    current_uid = user_table[idx].uid;
    current_gid = user_table[idx].primary_gid;
    
    printf("Switched to user '%s' (UID: %u, GID: %u).\n", username, current_uid, current_gid);
    return 0;
}

// whoami command
static void cmd_whoami(void) {
    printf("%s\n", fs_get_username(current_uid));
}

// List all users
static void cmd_list_users(void) {
    printf("Users:\n");
    printf("  %-20s %-8s %-8s\n", "Username", "UID", "GID");
    printf("  %-20s %-8s %-8s\n", "--------", "---", "---");
    for (int i = 0; i < FS_MAX_USERS; ++i) {
        if (user_table[i].in_use) {
            printf("  %-20s %-8u %-8u\n", user_table[i].username, 
                   user_table[i].uid, user_table[i].primary_gid);
        }
    }
}

// List all groups
static void cmd_list_groups(void) {
    printf("Groups:\n");
    printf("  %-20s %-8s\n", "Groupname", "GID");
    printf("  %-20s %-8s\n", "---------", "---");
    for (int i = 0; i < FS_MAX_GROUPS; ++i) {
        if (group_table[i].in_use) {
            printf("  %-20s %-8u\n", group_table[i].groupname, group_table[i].gid);
        }
    }
}

// ------------ Permission Checking Functions ------------

// Check if current user can read file
static int can_read_file(FileEntry *fe) {
    if (current_uid == ROOT_UID) return 1; // root can do anything
    
    if (fe->owner_uid == current_uid) {
        return (fe->permissions & PERM_OWNER_READ) != 0;
    }
    
    if (fs_user_in_group(current_uid, fe->owner_gid)) {
        return (fe->permissions & PERM_GROUP_READ) != 0;
    }
    
    return (fe->permissions & PERM_OTHER_READ) != 0;
}

// Check if current user can write file
static int can_write_file(FileEntry *fe) {
    if (current_uid == ROOT_UID) return 1;
    
    if (fe->owner_uid == current_uid) {
        return (fe->permissions & PERM_OWNER_WRITE) != 0;
    }
    
    if (fs_user_in_group(current_uid, fe->owner_gid)) {
        return (fe->permissions & PERM_GROUP_WRITE) != 0;
    }
    
    return (fe->permissions & PERM_OTHER_WRITE) != 0;
}

// Convert octal mode to permission bits
static uint32_t parse_mode(const char *mode_str) {
    return (uint32_t)strtoul(mode_str, NULL, 8);
}

// Format permissions as rwxrwxrwx string
static void format_permissions(uint32_t perm, char *buf) {
    buf[0] = (perm & PERM_OWNER_READ)  ? 'r' : '-';
    buf[1] = (perm & PERM_OWNER_WRITE) ? 'w' : '-';
    buf[2] = (perm & PERM_OWNER_EXEC)  ? 'x' : '-';
    buf[3] = (perm & PERM_GROUP_READ)  ? 'r' : '-';
    buf[4] = (perm & PERM_GROUP_WRITE) ? 'w' : '-';
    buf[5] = (perm & PERM_GROUP_EXEC)  ? 'x' : '-';
    buf[6] = (perm & PERM_OTHER_READ)  ? 'r' : '-';
    buf[7] = (perm & PERM_OTHER_WRITE) ? 'w' : '-';
    buf[8] = (perm & PERM_OTHER_EXEC)  ? 'x' : '-';
    buf[9] = '\0';
}

// chmod <mode> <path> - Change file permissions
static int cmd_chmod(const char *mode_str, const char *path) {
    int idx = fs_find_file_by_name(path);
    if (idx < 0) {
        fprintf(stderr, "File '%s' not found.\n", path);
        return -1;
    }
    
    FileEntry *fe = &file_table[idx];
    
    // Only owner or root can chmod
    if (current_uid != ROOT_UID && current_uid != fe->owner_uid) {
        fprintf(stderr, "Permission denied: Only owner or root can change permissions.\n");
        return -1;
    }
    
    uint32_t new_mode = parse_mode(mode_str);
    fe->permissions = new_mode;
    fs_sync_metadata();
    
    char perm_str[10];
    format_permissions(new_mode, perm_str);
    printf("Permissions of '%s' changed to %s (%03o).\n", path, perm_str, new_mode);
    return 0;
}

// chown <user>:<group> <path> - Change file owner and group
static int cmd_chown(const char *owner_spec, const char *path) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can change ownership.\n");
        return -1;
    }
    
    int idx = fs_find_file_by_name(path);
    if (idx < 0) {
        fprintf(stderr, "File '%s' not found.\n", path);
        return -1;
    }
    
    FileEntry *fe = &file_table[idx];
    
    // Parse user:group
    char user_part[FS_USERNAME_MAX] = {0};
    char group_part[FS_GROUPNAME_MAX] = {0};
    
    const char *colon = strchr(owner_spec, ':');
    if (colon) {
        size_t user_len = colon - owner_spec;
        if (user_len > 0 && user_len < FS_USERNAME_MAX) {
            strncpy(user_part, owner_spec, user_len);
        }
        strncpy(group_part, colon + 1, FS_GROUPNAME_MAX - 1);
    } else {
        strncpy(user_part, owner_spec, FS_USERNAME_MAX - 1);
    }
    
    // Change user if specified
    if (strlen(user_part) > 0) {
        int user_idx = fs_find_user_by_name(user_part);
        if (user_idx < 0) {
            fprintf(stderr, "User '%s' not found.\n", user_part);
            return -1;
        }
        fe->owner_uid = user_table[user_idx].uid;
    }
    
    // Change group if specified
    if (strlen(group_part) > 0) {
        int group_idx = fs_find_group_by_name(group_part);
        if (group_idx < 0) {
            fprintf(stderr, "Group '%s' not found.\n", group_part);
            return -1;
        }
        fe->owner_gid = group_table[group_idx].gid;
    }
    
    fs_sync_metadata();
    printf("Ownership of '%s' changed to %s:%s.\n", path, 
           fs_get_username(fe->owner_uid), fs_get_groupname(fe->owner_gid));
    return 0;
}

// chgrp <group> <path> - Change file group
static int cmd_chgrp(const char *groupname, const char *path) {
    int idx = fs_find_file_by_name(path);
    if (idx < 0) {
        fprintf(stderr, "File '%s' not found.\n", path);
        return -1;
    }
    
    FileEntry *fe = &file_table[idx];
    
    // Only owner or root can chgrp (and owner must be member of new group)
    if (current_uid != ROOT_UID && current_uid != fe->owner_uid) {
        fprintf(stderr, "Permission denied: Only owner or root can change group.\n");
        return -1;
    }
    
    int group_idx = fs_find_group_by_name(groupname);
    if (group_idx < 0) {
        fprintf(stderr, "Group '%s' not found.\n", groupname);
        return -1;
    }
    
    uint32_t new_gid = group_table[group_idx].gid;
    
    // Non-root owner must be member of new group
    if (current_uid != ROOT_UID && !fs_user_in_group(current_uid, new_gid)) {
        fprintf(stderr, "Permission denied: You must be a member of '%s'.\n", groupname);
        return -1;
    }
    
    fe->owner_gid = new_gid;
    fs_sync_metadata();
    
    printf("Group of '%s' changed to '%s'.\n", path, groupname);
    return 0;
}

// getfacl <path> - Display file permissions and ownership
static int cmd_getfacl(const char *path) {
    int idx = fs_find_file_by_name(path);
    if (idx < 0) {
        fprintf(stderr, "File '%s' not found.\n", path);
        return -1;
    }
    
    FileEntry *fe = &file_table[idx];
    
    char perm_str[10];
    format_permissions(fe->permissions, perm_str);
    
    printf("# file: %s\n", fe->name);
    printf("# owner: %s\n", fs_get_username(fe->owner_uid));
    printf("# group: %s\n", fs_get_groupname(fe->owner_gid));
    printf("user::%c%c%c\n", 
           (fe->permissions & PERM_OWNER_READ) ? 'r' : '-',
           (fe->permissions & PERM_OWNER_WRITE) ? 'w' : '-',
           (fe->permissions & PERM_OWNER_EXEC) ? 'x' : '-');
    printf("group::%c%c%c\n",
           (fe->permissions & PERM_GROUP_READ) ? 'r' : '-',
           (fe->permissions & PERM_GROUP_WRITE) ? 'w' : '-',
           (fe->permissions & PERM_GROUP_EXEC) ? 'x' : '-');
    printf("other::%c%c%c\n",
           (fe->permissions & PERM_OTHER_READ) ? 'r' : '-',
           (fe->permissions & PERM_OTHER_WRITE) ? 'w' : '-',
           (fe->permissions & PERM_OTHER_EXEC) ? 'x' : '-');
    
    return 0;
}

static void fs_delete_file_entry(int index) {
    if (index < 0 || index >= FS_MAX_FILES) return;
    if (!file_table[index].in_use) return;

    // Free all blocks associated with this file
    uint32_t curr = file_table[index].first_block;
    while (curr != FS_INVALID_BLOCK) {
        BlockOnDisk blk;
        fs_read_block(curr, &blk);
        uint32_t next = blk.next_block;
        
        fs_free_blocks(curr, 1); // Return block to freelist
        
        curr = next;
    }

    // Unlink from file list
    if (sb.root_dir_head == (uint32_t)index) {
        sb.root_dir_head = file_table[index].next_entry;
    } else {
        int prev = sb.root_dir_head;
        while (prev >= 0 && prev < FS_MAX_FILES) {
            if (file_table[prev].next_entry == index) {
                file_table[prev].next_entry = file_table[index].next_entry;
                break;
            }
            prev = file_table[prev].next_entry;
        }
    }
    file_table[index].in_use = 0;
    sb.num_files--;
    fs_sync_metadata();
}

// Returns 0 on success, -1 if no space available
static int fs_ensure_capacity(FileEntry *fe, uint32_t required_size) {
    uint32_t data_per_block = BLOCK_DATA_SIZE;
    uint32_t count = 0;
    uint32_t last_index = FS_INVALID_BLOCK;
    uint32_t idx = fe->first_block;
    BlockOnDisk blk;

    while (idx != FS_INVALID_BLOCK) {
        fs_read_block(idx, &blk);
        last_index = idx;
        idx = blk.next_block;
        ++count;
    }

    uint64_t current_capacity = (uint64_t)count * data_per_block;
    if (current_capacity >= required_size) return 0;

    uint64_t additional = required_size - current_capacity;
    uint32_t blocks_to_add = (uint32_t)((additional + data_per_block - 1) / data_per_block);

    for (uint32_t i = 0; i < blocks_to_add; ++i) {
        uint32_t new_block_index;
        if (fs_allocate_block(&new_block_index) != 0) {
            return -1;
        }
        if (fe->first_block == FS_INVALID_BLOCK) {
            fe->first_block = new_block_index;
            last_index = new_block_index;
        } else {
            fs_read_block(last_index, &blk);
            blk.next_block = new_block_index;
            fs_write_block(last_index, &blk);
            last_index = new_block_index;
        }
    }
    fs_sync_metadata();
    return 0;
}

// ------------ Public API ------------

static int my_open(const char *filename, uint32_t flags) {
    if (current_file_index != -1) {
        fprintf(stderr, "A file is already open. Close it first.\n");
        return -1;
    }
    int idx = fs_find_file_by_name(filename);
    if (idx < 0) {
        if (!(flags & FLAG_CREATE)) {
            fprintf(stderr, "File '%s' not found and CREATE flag not set.\n", filename);
            return -1;
        }
        // Create file with default permissions rw-r--r-- (0644)
        idx = fs_allocate_file_entry(filename, 0, PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_GROUP_READ | PERM_OTHER_READ);
        if (idx < 0) {
            fprintf(stderr, "No free file entries available.\n");
            return -1;
        }
        printf("Created file '%s' (owner: %s, group: %s).\n", 
               filename, fs_get_username(current_uid), fs_get_groupname(current_gid));
    } else {
        // Check permissions for existing file
        FileEntry *fe = &file_table[idx];
        
        // Check read permission
        if (!can_read_file(fe)) {
            fprintf(stderr, "Permission denied: Cannot read file '%s'.\n", filename);
            return -1;
        }
        
        // Check write permission if WRITE flag is set
        if ((flags & FLAG_WRITE) && !can_write_file(fe)) {
            fprintf(stderr, "Permission denied: Cannot write to file '%s'.\n", filename);
            return -1;
        }
    }
    current_file_index = idx;
    current_file_flags = flags;
    printf("Opened file '%s' (index %d).\n", filename, idx);
    return 0;
}

static ssize_t my_read(uint32_t pos, uint32_t n_bytes, uint8_t *buffer) {
    if (current_file_index == -1) {
        fprintf(stderr, "No file is open.\n");
        return -1;
    }
    FileEntry *fe = &file_table[current_file_index];
    if (pos >= fe->size) return 0;
    if (pos + n_bytes > fe->size) n_bytes = fe->size - pos;

    uint32_t data_per_block = BLOCK_DATA_SIZE;
    uint32_t block_index_in_file = pos / data_per_block;
    uint32_t offset_in_block = pos % data_per_block;
    uint32_t idx = fe->first_block;
    BlockOnDisk blk;

    for (uint32_t i = 0; i < block_index_in_file; ++i) {
        if (idx == FS_INVALID_BLOCK) return 0;
        fs_read_block(idx, &blk);
        idx = blk.next_block;
    }

    size_t bytes_remaining = n_bytes;
    size_t total_read = 0;
    while (bytes_remaining > 0 && idx != FS_INVALID_BLOCK) {
        fs_read_block(idx, &blk);
        size_t chunk = data_per_block - offset_in_block;
        if (chunk > bytes_remaining) chunk = bytes_remaining;
        memcpy(buffer + total_read, blk.data + offset_in_block, chunk);
        total_read += chunk;
        bytes_remaining -= chunk;
        offset_in_block = 0;
        idx = blk.next_block;
    }
    return (ssize_t)total_read;
}

static ssize_t my_write(uint32_t pos, const uint8_t *buffer, uint32_t n_bytes) {
    if (current_file_index == -1) {
        fprintf(stderr, "No file is open.\n");
        return -1;
    }
    if (!(current_file_flags & FLAG_WRITE)) {
        fprintf(stderr, "File not opened with WRITE flag.\n");
        return -1;
    }
    FileEntry *fe = &file_table[current_file_index];
    uint32_t required_size = pos + n_bytes;
    if (fs_ensure_capacity(fe, required_size) != 0) {
        return 0;
    }

    uint32_t data_per_block = BLOCK_DATA_SIZE;
    uint32_t block_index_in_file = pos / data_per_block;
    uint32_t offset_in_block = pos % data_per_block;
    uint32_t idx = fe->first_block;
    BlockOnDisk blk;

    for (uint32_t i = 0; i < block_index_in_file; ++i) {
        fs_read_block(idx, &blk);
        idx = blk.next_block;
    }

    size_t bytes_remaining = n_bytes;
    size_t total_written = 0;
    while (bytes_remaining > 0 && idx != FS_INVALID_BLOCK) {
        fs_read_block(idx, &blk);
        size_t chunk = data_per_block - offset_in_block;
        if (chunk > bytes_remaining) chunk = bytes_remaining;
        memcpy(blk.data + offset_in_block, buffer + total_written, chunk);
        fs_write_block(idx, &blk);
        total_written += chunk;
        bytes_remaining -= chunk;
        offset_in_block = 0;
        idx = blk.next_block;
    }

    if (pos + n_bytes > fe->size) {
        fe->size = pos + n_bytes;
        fs_sync_metadata();
    }
    return (ssize_t)total_written;
}

static int my_shrink(uint32_t new_size) {
    if (current_file_index == -1) {
        fprintf(stderr, "No file is open.\n");
        return -1;
    }
    FileEntry *fe = &file_table[current_file_index];
    if (new_size >= fe->size) return 0;

    uint32_t data_per_block = BLOCK_DATA_SIZE;
    uint32_t required_blocks = (new_size + data_per_block - 1) / data_per_block;
    
    uint32_t idx = fe->first_block;
    BlockOnDisk blk;
    uint32_t block_count = 0;
    uint32_t last_kept = FS_INVALID_BLOCK;

    while (idx != FS_INVALID_BLOCK) {
        fs_read_block(idx, &blk);
        block_count++;
        if (block_count == required_blocks) {
            last_kept = idx;
            break;
        }
        if (required_blocks == 0) break;
        last_kept = idx;
        idx = blk.next_block;
    }

    uint32_t block_to_free = FS_INVALID_BLOCK;

    if (required_blocks == 0) {
        block_to_free = fe->first_block;
        fe->first_block = FS_INVALID_BLOCK;
    } else {
        // Read last_kept to find the next block (head of tail to free)
        fs_read_block(last_kept, &blk);
        block_to_free = blk.next_block;
        blk.next_block = FS_INVALID_BLOCK;
        fs_write_block(last_kept, &blk);
    }

    // Free the tail blocks
    while (block_to_free != FS_INVALID_BLOCK) {
        fs_read_block(block_to_free, &blk);
        uint32_t next = blk.next_block;
        
        fs_free_blocks(block_to_free, 1); // Return to freelist
        
        block_to_free = next;
    }

    fe->size = new_size;
    fs_sync_metadata();
    return 0;
}

static uint32_t my_get_file_stats(void) {
    if (current_file_index == -1) {
        fprintf(stderr, "No file is open.\n");
        return 0;
    }
    return file_table[current_file_index].size;
}

static int my_close(void) {
    if (current_file_index == -1) {
        fprintf(stderr, "No file is open.\n");
        return -1;
    }
    current_file_index = -1;
    current_file_flags = 0;
    return 0;
}

static int my_rm(void) {
    if (current_file_index == -1) {
        fprintf(stderr, "No file is open.\n");
        return -1;
    }
    
    FileEntry *fe = &file_table[current_file_index];
    
    // Only owner or root can delete a file
    if (current_uid != ROOT_UID && current_uid != fe->owner_uid) {
        fprintf(stderr, "Permission denied: Only owner or root can delete this file.\n");
        return -1;
    }
    
    printf("Deleted file '%s'.\n", fe->name);
    fs_delete_file_entry(current_file_index);
    current_file_index = -1;
    current_file_flags = 0;
    return 0;
}

static void my_get_fs_stats(void) {
    uint64_t meta_bytes = dataarea_offset();
    uint64_t usable_bytes = FS_DISK_SIZE - meta_bytes;
    
    // Approximate usage from file table
    uint64_t used_bytes = 0;
    for(int i=0; i<FS_MAX_FILES; i++) {
        if (file_table[i].in_use) {
            // Count blocks
             uint32_t count = 0;
             uint32_t idx = file_table[i].first_block;
             BlockOnDisk blk;
             while(idx != FS_INVALID_BLOCK) {
                 count++;
                 fs_read_block(idx, &blk);
                 idx = blk.next_block;
             }
             used_bytes += (uint64_t)count * FS_BLOCK_SIZE;
        }
    }

    uint64_t free_bytes = usable_bytes - used_bytes;

    printf("Filesystem stats:\n");
    printf("  Total usable space: %llu bytes\n", (unsigned long long)usable_bytes);
    printf("  Used space (approx): %llu bytes\n", (unsigned long long)used_bytes);
    printf("  Free space (approx): %llu bytes\n", (unsigned long long)free_bytes);
    printf("  Number of files: %u\n", sb.num_files);
}

// Visualization Command
static void cmd_viz(void) {
    uint32_t free_count = 0;
    int regions = 0;

    // Count free blocks and regions from bitmap
    int in_free_region = 0;
    for (uint32_t i = 0; i < max_data_blocks; i++) {
        if (bitmap_is_free(i)) {
            free_count++;
            if (!in_free_region) {
                regions++;
                in_free_region = 1;
            }
        } else {
            in_free_region = 0;
        }
    }

    uint32_t used_count = max_data_blocks - free_count;

    printf("\n");
    printf("   ___________________________________________________\n");
    printf("  |                                                   |\n");
    printf("  |              FILESYSTEM VISUALIZATION             |\n");
    printf("  |    ([\u2588] = Used block    [ ] = Free block)    |\n");
    printf("  |___________________________________________________|\n\n");

    printf("\nFilesystem Layout (Total %u blocks):\n", max_data_blocks);
    
    int width = 64;
    
    for(uint32_t i=0; i<max_data_blocks; i++) {
        if (i % width == 0) {
            if (i > 0) printf("|\n");
            printf("|");
        }
        
        printf("%s", bitmap_is_free(i) ? " " : "\u2588"); 
    }
    
    int remainder = max_data_blocks % width;
    if (remainder != 0) {
        for(int k=0; k < (width - remainder); k++) printf(" ");
    }
    printf("|\n");

    // Print free region table from bitmap
    printf("\n   %-4s | %-11s | %-11s | %-8s | %-9s\n", "No.", "Start Block", "End Block", "Size", "Size(KB)");
    printf("   -----|-------------|-------------|----------|----------\n");

    int idx = 1;
    uint32_t region_start = 0;
    int in_region = 0;
    for (uint32_t i = 0; i <= max_data_blocks; i++) {
        int is_free = (i < max_data_blocks) ? bitmap_is_free(i) : 0;
        if (is_free && !in_region) {
            region_start = i;
            in_region = 1;
        } else if (!is_free && in_region) {
            uint32_t region_end = i - 1;
            uint32_t size = region_end - region_start + 1;
            float size_kb = (size * FS_BLOCK_SIZE) / 1024.0f;
            printf("   %-4d | %-11u | %-11u | %-8u | %-9.2f\n", 
                   idx++, region_start, region_end, size, size_kb);
            in_region = 0;
        }
    }

    printf("\n   _____________________________________\n");
    printf("  |                SUMMARY              |\n");
    printf("  |-------------------------------------|\n");
    printf("  | Total Blocks: %-10u            |\n", max_data_blocks);
    printf("  | Used Blocks : %-10u (%5.1f%%)   |\n", used_count, (double)used_count*100.0/max_data_blocks);
    printf("  | Free Blocks : %-10u (%5.1f%%)   |\n", free_count, (double)free_count*100.0/max_data_blocks);
    printf("  | Free Regions: %-10d            |\n", regions);
    printf("  |_____________________________________|\n\n");
}

// ls command - list files with permissions
static void cmd_ls(void) {
    printf("Files in filesystem:\n");
    printf("  %-10s %-12s %-12s %8s  %-s\n", "Perms", "Owner", "Group", "Size", "Name");
    printf("  %-10s %-12s %-12s %8s  %-s\n", "----------", "------------", "------------", "--------", "----");
    
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (file_table[i].in_use) {
            FileEntry *fe = &file_table[i];
            char perm_str[11];
            perm_str[0] = '-'; // regular file
            format_permissions(fe->permissions, perm_str + 1);
            
            printf("  %-10s %-12s %-12s %8u  %s\n",
                   perm_str,
                   fs_get_username(fe->owner_uid),
                   fs_get_groupname(fe->owner_gid),
                   fe->size,
                   fe->name);
        }
    }
    printf("\nTotal files: %u\n", sb.num_files);
}

// ------------ Stress Test Function ------------
// Configuration for stress test
#define STRESS_NUM_FILES      5000       // Number of test files
#define STRESS_NUM_OPS        25000    // Total operations to perform
#define STRESS_MAX_WRITE_SIZE 4096      // Max bytes per write
#define STRESS_MAX_FILE_SIZE  16384     // Max file size before shrinking

static void stressTest(void) {
    printf("\n========================================\n");
    printf("       STRESS TEST STARTING\n");
    printf("========================================\n");
    printf("Configuration:\n");
    printf("  Files to create: %d\n", STRESS_NUM_FILES);
    printf("  Operations: %d\n", STRESS_NUM_OPS);
    printf("  Max write size: %d bytes\n", STRESS_MAX_WRITE_SIZE);
    printf("========================================\n\n");

    srand((unsigned int)time(NULL));
    
    // Track wall-clock timing using timespec
    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    
    // Statistics
    uint32_t creates = 0, deletes = 0, writes = 0, reads = 0, shrinks = 0;
    uint32_t failed_ops = 0;
    uint64_t bytes_written = 0, bytes_read = 0;
    
    // Track which files exist (by index 0 to STRESS_NUM_FILES-1)
    int *file_exists = calloc(STRESS_NUM_FILES, sizeof(int));
    uint32_t *file_sizes = calloc(STRESS_NUM_FILES, sizeof(uint32_t));
    if (!file_exists || !file_sizes) {
        fprintf(stderr, "Failed to allocate tracking arrays\n");
        return;
    }
    int num_existing_files = 0;
    
    // Pre-generate file names
    char (*filenames)[32] = malloc(STRESS_NUM_FILES * 32);
    if (!filenames) {
        fprintf(stderr, "Failed to allocate filenames\n");
        free(file_exists);
        free(file_sizes);
        return;
    }
    for (int i = 0; i < STRESS_NUM_FILES; i++) {
        snprintf(filenames[i], 32, "stress_file_%04d", i);
    }
    
    // Buffer for write/read operations
    uint8_t *buffer = malloc(STRESS_MAX_WRITE_SIZE + 1);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer\n");
        free(file_exists);
        free(file_sizes);
        free(filenames);
        return;
    }
    
    // Fill buffer with random data pattern
    for (int i = 0; i < STRESS_MAX_WRITE_SIZE; i++) {
        buffer[i] = (uint8_t)('A' + (i % 26));
    }
    
    // ============ PHASE 1: Create all files first ============
    printf("Phase 1: Creating %d files...\n", STRESS_NUM_FILES);
    int create_progress = STRESS_NUM_FILES / 10;
    for (int i = 0; i < STRESS_NUM_FILES; i++) {
        if (create_progress > 0 && i % create_progress == 0) {
            printf("  Creating files: %d%% (%d/%d)\n", 
                   (i * 100) / STRESS_NUM_FILES, i, STRESS_NUM_FILES);
        }
        if (my_open(filenames[i], FLAG_CREATE | FLAG_WRITE) == 0) {
            file_exists[i] = 1;
            file_sizes[i] = 0;
            num_existing_files++;
            creates++;
            my_close();
        } else {
            fprintf(stderr, "Failed to create file %s\n", filenames[i]);
        }
    }
    printf("  Created %d files.\n\n", creates);
    
    // ============ PHASE 2: Run random operations ============
    printf("Phase 2: Running %d random operations...\n", STRESS_NUM_OPS);
    
    int progress_interval = STRESS_NUM_OPS / 10;
    
    for (int op = 0; op < STRESS_NUM_OPS; op++) {
        // Progress indicator
        if (progress_interval > 0 && op % progress_interval == 0) {
            printf("  Progress: %d%% (%d/%d ops)\n", 
                   (op * 100) / STRESS_NUM_OPS, op, STRESS_NUM_OPS);
        }
        
        // Choose random operation: 25% read, 30% write, 20% shrink, 15% delete, 10% create
        int operation = rand() % 100;
        
        if (operation < 10) {
            // CREATE: 10% chance - create a new file (if slot available)
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }
            
            if (!file_exists[file_idx]) {
                if (my_open(filenames[file_idx], FLAG_CREATE | FLAG_WRITE) == 0) {
                    file_exists[file_idx] = 1;
                    file_sizes[file_idx] = 0;
                    num_existing_files++;
                    creates++;
                    my_close();
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++; // All slots taken
            }
        }
        else if (operation < 25 && num_existing_files > 1) {
            // DELETE: 15% chance (keep at least 1 file)
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (!file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }
            
            if (file_exists[file_idx]) {
                if (my_open(filenames[file_idx], FLAG_WRITE) == 0) {
                    if (my_rm() == 0) {
                        file_exists[file_idx] = 0;
                        file_sizes[file_idx] = 0;
                        num_existing_files--;
                        deletes++;
                    } else {
                        my_close();
                        failed_ops++;
                    }
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++;
            }
        }
        else if (operation < 55) {
            // WRITE: 30% chance
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (!file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }
            
            if (file_exists[file_idx]) {
                if (my_open(filenames[file_idx], FLAG_WRITE) == 0) {
                    uint32_t pos = rand() % (file_sizes[file_idx] + 1);
                    uint32_t len = (rand() % STRESS_MAX_WRITE_SIZE) + 1;
                    
                    ssize_t written = my_write(pos, buffer, len);
                    if (written > 0) {
                        writes++;
                        bytes_written += written;
                        if (pos + (uint32_t)written > file_sizes[file_idx]) {
                            file_sizes[file_idx] = pos + (uint32_t)written;
                        }
                    } else {
                        failed_ops++;
                    }
                    my_close();
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++;
            }
        }
        else if (operation < 80) {
            // READ: 25% chance
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (!file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }
            
            if (file_exists[file_idx] && file_sizes[file_idx] > 0) {
                if (my_open(filenames[file_idx], 0) == 0) {
                    uint32_t pos = rand() % file_sizes[file_idx];
                    uint32_t len = (rand() % STRESS_MAX_WRITE_SIZE) + 1;
                    
                    uint8_t *read_buf = malloc(len);
                    if (read_buf) {
                        ssize_t r = my_read(pos, len, read_buf);
                        if (r > 0) {
                            reads++;
                            bytes_read += r;
                        } else {
                            failed_ops++;
                        }
                        free(read_buf);
                    } else {
                        failed_ops++;
                    }
                    my_close();
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++;
            }
        }
        else {
            // SHRINK: 20% chance
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (!file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }
            
            if (file_exists[file_idx] && file_sizes[file_idx] > 0) {
                if (my_open(filenames[file_idx], FLAG_WRITE) == 0) {
                    uint32_t new_size = rand() % file_sizes[file_idx];
                    if (my_shrink(new_size) == 0) {
                        file_sizes[file_idx] = new_size;
                        shrinks++;
                    } else {
                        failed_ops++;
                    }
                    my_close();
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++;
            }
        }
    }
    
    // ============ PHASE 3: Cleanup ============
    printf("\nPhase 3: Cleaning up test files...\n");
    for (int i = 0; i < STRESS_NUM_FILES; i++) {
        if (file_exists[i]) {
            if (my_open(filenames[i], FLAG_WRITE) == 0) {
                my_rm();
            }
        }
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    double elapsed = (end_ts.tv_sec - start_ts.tv_sec) + 
                     (end_ts.tv_nsec - start_ts.tv_nsec) / 1e9;
    
    free(buffer);
    free(file_exists);
    free(file_sizes);
    free(filenames);
    
    uint32_t total_successful = creates + deletes + writes + reads + shrinks;
    
    printf("\n========================================\n");
    printf("       STRESS TEST COMPLETE\n");
    printf("========================================\n");
    printf("Results:\n");
    printf("  Wall-clock time: %.2f seconds\n", elapsed);
    printf("  Successful ops/sec: %.0f\n", total_successful / elapsed);
    printf("\nPhase 1 - Initial file creation:\n");
    printf("  Files created: %d\n", STRESS_NUM_FILES);
    printf("\nPhase 2 - Random operations breakdown:\n");
    printf("  Creates: %u\n", creates - STRESS_NUM_FILES);
    printf("  Deletes: %u\n", deletes);
    printf("  Writes:  %u (%.2f MB written)\n", writes, bytes_written / (1024.0 * 1024.0));
    printf("  Reads:   %u (%.2f MB read)\n", reads, bytes_read / (1024.0 * 1024.0));
    printf("  Shrinks: %u\n", shrinks);
    printf("  -----------------------\n");
    printf("  Total phase 2 ops: %u (successful) + %u (failed) = %u\n", 
           total_successful - STRESS_NUM_FILES, failed_ops, 
           total_successful - STRESS_NUM_FILES + failed_ops);
    printf("========================================\n\n");
}


static void print_help(void) {
    printf("\n=== File Management System Commands ===\n\n");
    
    printf("File Operations:\n");
    printf("  open <name> <flags>   - flags bitmask: 1=CREATE, 2=WRITE\n");
    printf("  read <pos> <n>        - read n bytes from current file starting at pos\n");
    printf("  write <pos> <text>    - write the given text starting at pos\n");
    printf("  shrink <new_size>     - truncate current file to new_size bytes\n");
    printf("  get_file_stats        - print size of current file\n");
    printf("  rm                    - delete current file (must be open)\n");
    printf("  close                 - close current file\n");
    printf("  ls                    - list all files with permissions\n\n");
    
    printf("User Management:\n");
    printf("  useradd <username>    - create a new user\n");
    printf("  userdel <username>    - delete a user\n");
    printf("  usermod -aG <group> <user> - add user to group\n");
    printf("  users                 - list all users\n");
    printf("  su <username>         - switch to user\n");
    printf("  whoami                - show current user\n\n");
    
    printf("Group Management:\n");
    printf("  groupadd <groupname>  - create a new group\n");
    printf("  groupdel <groupname>  - delete a group\n");
    printf("  groups                - list all groups\n\n");
    
    printf("Permission Management:\n");
    printf("  chmod <mode> <path>   - change file permissions (octal mode, e.g., 755)\n");
    printf("  chown <user>:<group> <path> - change file owner and group\n");
    printf("  chgrp <group> <path>  - change file group\n");
    printf("  getfacl <path>        - show file permissions and ownership\n\n");
    
    printf("Filesystem:\n");
    printf("  get_fs_stats          - show filesystem statistics\n");
    printf("  viz                   - visualize free space linked list\n");
    printf("  stressTest            - run performance stress test\n");
    printf("  help                  - show this help\n");
    printf("  exit                  - quit the program\n\n");
}

int main(void) {
    fs_open_disk();
    printf("Simple user-space filesystem demo. Backing file: %s\n", FS_DISK_FILE);
    printf("Logged in as: %s (UID: %u)\n", fs_get_username(current_uid), current_uid);
    print_help();

    char line[512];
    while (1) {
        printf("%s@fs> ", fs_get_username(current_uid));
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        line[strcspn(line, "\n")] = '\0';
        char *cmd = strtok(line, " \t");
        if (!cmd) continue;

        if (strcmp(cmd, "open") == 0) {
            char *name = strtok(NULL, " \t");
            char *flags_str = strtok(NULL, " \t");
            if (!name || !flags_str) {
                printf("Usage: open <name> <flags>\n");
                continue;
            }
            uint32_t flags = (uint32_t)strtoul(flags_str, NULL, 0);
            my_open(name, flags);
        } else if (strcmp(cmd, "read") == 0) {
            char *pos_str = strtok(NULL, " \t");
            char *n_str = strtok(NULL, " \t");
            if (!pos_str || !n_str) {
                printf("Usage: read <pos> <n_bytes>\n");
                continue;
            }
            uint32_t pos = (uint32_t)strtoul(pos_str, NULL, 0);
            uint32_t n = (uint32_t)strtoul(n_str, NULL, 0);
            uint8_t *buf = malloc(n + 1);
            if (!buf) die("malloc read buffer");
            ssize_t r = my_read(pos, n, buf);
            if (r >= 0) {
                buf[r] = '\0';
                printf("Read %zd bytes: '%s'\n", r, buf);
            }
            free(buf);
        } else if (strcmp(cmd, "write") == 0) {
            char *pos_str = strtok(NULL, " \t");
            char *text = strtok(NULL, "");
            if (!pos_str || !text) {
                printf("Usage: write <pos> <text>\n");
                continue;
            }
            uint32_t pos = (uint32_t)strtoul(pos_str, NULL, 0);
            size_t len = strlen(text);
            ssize_t w = my_write(pos, (const uint8_t *)text, (uint32_t)len);
            if (w >= 0) printf("Wrote %zd bytes.\n", w);
        } else if (strcmp(cmd, "shrink") == 0) {
            char *size_str = strtok(NULL, " \t");
            if (!size_str) {
                printf("Usage: shrink <new_size>\n");
                continue;
            }
            uint32_t new_size = (uint32_t)strtoul(size_str, NULL, 0);
            my_shrink(new_size);
        } else if (strcmp(cmd, "get_file_stats") == 0) {
            uint32_t sz = my_get_file_stats();
            if (current_file_index != -1)
                printf("Current file size: %u bytes\n", sz);
        } else if (strcmp(cmd, "rm") == 0) {
            my_rm();
        } else if (strcmp(cmd, "close") == 0) {
            my_close();
        } else if (strcmp(cmd, "ls") == 0) {
            cmd_ls();
        } else if (strcmp(cmd, "get_fs_stats") == 0) {
            my_get_fs_stats();
        } else if (strcmp(cmd, "viz") == 0) {
            cmd_viz();
        } else if (strcmp(cmd, "stressTest") == 0) {
            stressTest();
        // User management commands
        } else if (strcmp(cmd, "useradd") == 0) {
            char *username = strtok(NULL, " \t");
            if (!username) {
                printf("Usage: useradd <username>\n");
                continue;
            }
            cmd_useradd(username);
        } else if (strcmp(cmd, "userdel") == 0) {
            char *username = strtok(NULL, " \t");
            if (!username) {
                printf("Usage: userdel <username>\n");
                continue;
            }
            cmd_userdel(username);
        } else if (strcmp(cmd, "usermod") == 0) {
            char *flag = strtok(NULL, " \t");
            if (!flag || strcmp(flag, "-aG") != 0) {
                printf("Usage: usermod -aG <group> <user>\n");
                continue;
            }
            char *groupname = strtok(NULL, " \t");
            char *username = strtok(NULL, " \t");
            if (!groupname || !username) {
                printf("Usage: usermod -aG <group> <user>\n");
                continue;
            }
            cmd_usermod_aG(groupname, username);
        } else if (strcmp(cmd, "users") == 0) {
            cmd_list_users();
        } else if (strcmp(cmd, "su") == 0) {
            char *username = strtok(NULL, " \t");
            if (!username) {
                printf("Usage: su <username>\n");
                continue;
            }
            cmd_su(username);
        } else if (strcmp(cmd, "whoami") == 0) {
            cmd_whoami();
        // Group management commands
        } else if (strcmp(cmd, "groupadd") == 0) {
            char *groupname = strtok(NULL, " \t");
            if (!groupname) {
                printf("Usage: groupadd <groupname>\n");
                continue;
            }
            cmd_groupadd(groupname);
        } else if (strcmp(cmd, "groupdel") == 0) {
            char *groupname = strtok(NULL, " \t");
            if (!groupname) {
                printf("Usage: groupdel <groupname>\n");
                continue;
            }
            cmd_groupdel(groupname);
        } else if (strcmp(cmd, "groups") == 0) {
            cmd_list_groups();
        // Permission management commands
        } else if (strcmp(cmd, "chmod") == 0) {
            char *mode = strtok(NULL, " \t");
            char *path = strtok(NULL, " \t");
            if (!mode || !path) {
                printf("Usage: chmod <mode> <path>\n");
                continue;
            }
            cmd_chmod(mode, path);
        } else if (strcmp(cmd, "chown") == 0) {
            char *owner = strtok(NULL, " \t");
            char *path = strtok(NULL, " \t");
            if (!owner || !path) {
                printf("Usage: chown <user>:<group> <path>\n");
                continue;
            }
            cmd_chown(owner, path);
        } else if (strcmp(cmd, "chgrp") == 0) {
            char *group = strtok(NULL, " \t");
            char *path = strtok(NULL, " \t");
            if (!group || !path) {
                printf("Usage: chgrp <group> <path>\n");
                continue;
            }
            cmd_chgrp(group, path);
        } else if (strcmp(cmd, "getfacl") == 0) {
            char *path = strtok(NULL, " \t");
            if (!path) {
                printf("Usage: getfacl <path>\n");
                continue;
            }
            cmd_getfacl(path);
        } else if (strcmp(cmd, "help") == 0) {
            print_help();
        } else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            break;
        } else {
            printf("Unknown command. Type 'help' for a list.\n");
        }
    }

    if (disk_fd >= 0) close(disk_fd);
    return 0;
}
