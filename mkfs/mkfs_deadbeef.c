/*
 * mkfs.deadbeef — standalone formatting tool for the deadbeef filesystem
 *
 * Usage:
 *   mkfs_deadbeef <filename> [size_in_MB]
 *
 * Creates (or overwrites) <filename> with a fresh deadbeef filesystem.
 * Default disk size is 128 MB if not specified.
 *
 * The tool is self-contained: it does NOT link against libfs and uses
 * only the shared header definitions from common/.
 */

#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "../common/fs_config.h"
#include "../common/fs_types.h"
#include "../common/fs_layout.h"

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s <filename> [size_in_MB]\n"
        "\n"
        "  filename    Path to the disk image file to create.\n"
        "  size_in_MB  Optional disk size in megabytes (default: %d).\n"
        "              Must be at least 1 MB.\n",
        prog, FS_DISK_SIZE / (1024 * 1024));
    exit(EXIT_FAILURE);
}

/* ------------------------------------------------------------------ */
/*  Format                                                             */
/* ------------------------------------------------------------------ */

static void format_disk(const char *path, uint32_t disk_size) {

    /* ---------- compute layout ---------- */
    off_t data_start = (off_t)sizeof(SuperBlock)
                     + (off_t)sizeof(UserEntry)  * FS_MAX_USERS
                     + (off_t)sizeof(GroupEntry)  * FS_MAX_GROUPS
                     + (off_t)sizeof(FileEntry)   * FS_MAX_FILES;
    uint32_t max_blocks = (disk_size - (uint32_t)data_start) / FS_BLOCK_SIZE;

    printf("mkfs.deadbeef: formatting '%s'\n", path);
    printf("  Disk size       : %u bytes (%u MB)\n", disk_size, disk_size / (1024 * 1024));
    printf("  Block size      : %u bytes\n", (unsigned)FS_BLOCK_SIZE);
    printf("  Metadata area   : %ld bytes\n", (long)data_start);
    printf("  Data blocks     : %u\n", max_blocks);
    printf("  Max files       : %u\n", (unsigned)FS_MAX_FILES);
    printf("  Max users       : %u\n", (unsigned)FS_MAX_USERS);
    printf("  Max groups      : %u\n", (unsigned)FS_MAX_GROUPS);

    /* ---------- create / truncate file ---------- */
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) die("open");

    if (ftruncate(fd, (off_t)disk_size) != 0) die("ftruncate");

    /* ---------- prepare superblock ---------- */
    SuperBlock sb;
    memset(&sb, 0, sizeof(sb));
    sb.magic              = FS_MAGIC;
    sb.version            = FS_VERSION;
    sb.block_size         = FS_BLOCK_SIZE;
    sb.disk_size          = disk_size;
    sb.last_allocated_block = FS_INVALID_BLOCK;
    sb.num_files          = 1;           /* root directory */
    sb.root_dir_head      = 0;           /* file_table[0] is root dir */
    sb.num_users          = 1;           /* root user */
    sb.num_groups         = 1;           /* root group */
    sb.next_uid           = 1;
    sb.next_gid           = 1;

    /* ---------- prepare user table ---------- */
    UserEntry user_table[FS_MAX_USERS];
    memset(user_table, 0, sizeof(user_table));
    strncpy(user_table[0].username, "root", FS_USERNAME_MAX - 1);
    user_table[0].uid              = ROOT_UID;
    user_table[0].primary_gid      = ROOT_GID;
    user_table[0].num_secondary_groups = 0;
    user_table[0].in_use           = 1;

    /* ---------- prepare group table ---------- */
    GroupEntry group_table[FS_MAX_GROUPS];
    memset(group_table, 0, sizeof(group_table));
    strncpy(group_table[0].groupname, "root", FS_GROUPNAME_MAX - 1);
    group_table[0].gid    = ROOT_GID;
    group_table[0].in_use = 1;

    /* ---------- prepare file table ---------- */
    /* Allocate on the heap — it can be quite large (10000 entries). */
    FileEntry *file_table = calloc(FS_MAX_FILES, sizeof(FileEntry));
    if (!file_table) die("calloc file_table");

    /* Root directory "/" is file_table[0] */
    FileEntry *root = &file_table[0];
    strncpy(root->name, "/", FS_FILENAME_MAX - 1);
    root->type        = FS_TYPE_DIRECTORY;
    root->permissions = PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_OWNER_EXEC |
                        PERM_GROUP_READ | PERM_GROUP_EXEC |
                        PERM_OTHER_READ | PERM_OTHER_EXEC;   /* 0755 */
    root->size        = 0;
    root->first_block = FS_INVALID_BLOCK;
    root->next_entry  = -1;
    root->owner_uid   = ROOT_UID;
    root->owner_gid   = ROOT_GID;
    root->in_use      = 1;

    /* ---------- write everything to disk ---------- */
    if (pwrite(fd, &sb, sizeof(sb), superblock_offset()) != (ssize_t)sizeof(sb))
        die("pwrite superblock");

    if (pwrite(fd, user_table, sizeof(user_table), usertable_offset()) != (ssize_t)sizeof(user_table))
        die("pwrite user_table");

    if (pwrite(fd, group_table, sizeof(group_table), grouptable_offset()) != (ssize_t)sizeof(group_table))
        die("pwrite group_table");

    ssize_t ft_size = (ssize_t)(sizeof(FileEntry) * FS_MAX_FILES);
    if (pwrite(fd, file_table, (size_t)ft_size, filetable_offset()) != ft_size)
        die("pwrite file_table");

    fsync(fd);
    close(fd);
    free(file_table);

    printf("\nFilesystem formatted successfully.\n");
    printf("  Magic      : 0x%08X (DEADBEEF)\n", sb.magic);
    printf("  Version    : %u\n", sb.version);
    printf("  Root dir   : file_table[0]  \"/\"\n");
    printf("  Root user  : uid=%u  gid=%u\n", ROOT_UID, ROOT_GID);
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3) {
        usage(argv[0]);
    }

    const char *filename = argv[1];
    uint32_t disk_size = FS_DISK_SIZE;         /* default: 128 MB */

    if (argc == 3) {
        long mb = strtol(argv[2], NULL, 10);
        if (mb < 1 || mb > 4096) {
            fprintf(stderr, "Error: size must be between 1 and 4096 MB.\n");
            return EXIT_FAILURE;
        }
        disk_size = (uint32_t)(mb * 1024 * 1024);
    }

    /* Sanity: metadata must fit */
    off_t meta = (off_t)sizeof(SuperBlock)
               + (off_t)sizeof(UserEntry)  * FS_MAX_USERS
               + (off_t)sizeof(GroupEntry)  * FS_MAX_GROUPS
               + (off_t)sizeof(FileEntry)   * FS_MAX_FILES;
    if ((off_t)disk_size <= meta + FS_BLOCK_SIZE) {
        fprintf(stderr, "Error: disk size too small to hold metadata + at least 1 block.\n");
        return EXIT_FAILURE;
    }

    format_disk(filename, disk_size);
    return EXIT_SUCCESS;
}
