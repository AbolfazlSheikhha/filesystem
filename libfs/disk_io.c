#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "disk_io.h"
#include "fs_state.h"
#include "bitmap.h"
#include "../common/fs_config.h"
#include "../common/fs_layout.h"

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Write superblock + user/group tables + file table back to disk
void fs_sync_metadata(void) {
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

void fs_read_block(uint32_t index, BlockOnDisk *blk) {
    if (index == FS_INVALID_BLOCK) {
        fprintf(stderr, "Attempted to read invalid block index\n");
        exit(EXIT_FAILURE);
    }
    if (pread(disk_fd, blk, sizeof(*blk), block_offset(index)) != (ssize_t)sizeof(*blk)) {
        die("pread block");
    }
}

void fs_write_block(uint32_t index, const BlockOnDisk *blk) {
    if (pwrite(disk_fd, blk, sizeof(*blk), block_offset(index)) != (ssize_t)sizeof(*blk)) {
        die("pwrite block");
    }
}

// Load metadata from an existing filesystem
void fs_load_metadata(void) {
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

    // Locate root directory in file_table
    root_dir_index = -1;
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (file_table[i].in_use && file_table[i].type == FS_TYPE_DIRECTORY &&
            strcmp(file_table[i].name, "/") == 0) {
            root_dir_index = i;
            break;
        }
    }
    if (root_dir_index < 0) {
        fprintf(stderr, "Warning: root directory not found in filesystem.\n");
    }
}

// Format a brand-new filesystem in filesys.db
void fs_format_new(void) {
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
    bitmap_init_all_free();

    // Create root directory "/" as file_table[0]
    FileEntry *root = &file_table[0];
    memset(root, 0, sizeof(*root));
    strncpy(root->name, "/", FS_FILENAME_MAX - 1);
    root->type = FS_TYPE_DIRECTORY;
    root->permissions = PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_OWNER_EXEC |
                        PERM_GROUP_READ | PERM_GROUP_EXEC |
                        PERM_OTHER_READ | PERM_OTHER_EXEC;  // 0755
    root->size = 0;
    root->first_block = FS_INVALID_BLOCK;
    root->next_entry = -1;
    root->owner_uid = ROOT_UID;
    root->owner_gid = ROOT_GID;
    root->in_use = 1;

    sb.root_dir_head = 0;
    sb.num_files = 1;
    root_dir_index = 0;

    fs_sync_metadata();

    printf("Filesystem formatted. Root user, group, and root directory created.\n");
}

// Open or create the backing file and load/initialise the FS
void fs_open_disk(void) {
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
