#include <stdio.h>
#include <string.h>
#include "viz.h"
#include "fs_state.h"
#include "disk_io.h"
#include "bitmap.h"
#include "user.h"
#include "dir.h"
#include "../common/fs_config.h"

// Visualization Command
void cmd_viz(void) {
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

    for (uint32_t i = 0; i < max_data_blocks; i++) {
        if (i % width == 0) {
            if (i > 0) printf("|\n");
            printf("|");
        }

        printf("%s", bitmap_is_free(i) ? " " : "\u2588");
    }

    int remainder = max_data_blocks % width;
    if (remainder != 0) {
        for (int k = 0; k < (width - remainder); k++) printf(" ");
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
    printf("  | Used Blocks : %-10u (%5.1f%%)   |\n", used_count, (double)used_count * 100.0 / max_data_blocks);
    printf("  | Free Blocks : %-10u (%5.1f%%)   |\n", free_count, (double)free_count * 100.0 / max_data_blocks);
    printf("  | Free Regions: %-10d            |\n", regions);
    printf("  |_____________________________________|\n\n");
}

// ls command - list directory contents
void cmd_ls(const char *dir_path) {
    // Determine which directory to list
    int dir_idx;
    char abs_path[1024];

    if (!dir_path) {
        dir_idx = cwd_index;
        strncpy(abs_path, cwd_path, sizeof(abs_path) - 1);
        abs_path[sizeof(abs_path) - 1] = '\0';
    } else {
        make_absolute(dir_path, abs_path, sizeof(abs_path));
        dir_idx = resolve_path(abs_path);
        if (dir_idx < 0) {
            fprintf(stderr, "ls: cannot access '%s': No such file or directory\n", abs_path);
            return;
        }
        if (file_table[dir_idx].type != FS_TYPE_DIRECTORY) {
            // If it's a regular file, just show that one file
            FileEntry *fe = &file_table[dir_idx];
            char perm_str[11];
            perm_str[0] = '-';
            format_permissions(fe->permissions, perm_str + 1);
            printf("  %-10s %-12s %-12s %8u  %s\n",
                   perm_str,
                   fs_get_username(fe->owner_uid),
                   fs_get_groupname(fe->owner_gid),
                   fe->size,
                   fe->name);
            return;
        }
    }

    if (dir_idx < 0 || !file_table[dir_idx].in_use) {
        fprintf(stderr, "ls: directory not found\n");
        return;
    }

    printf("Directory: %s\n", abs_path);
    printf("  %-10s %-12s %-12s %8s  %-s\n", "Perms", "Owner", "Group", "Size", "Name");
    printf("  %-10s %-12s %-12s %8s  %-s\n", "----------", "------------", "------------", "--------", "----");

    // Walk the directory's data blocks and print each entry
    FileEntry *dir = &file_table[dir_idx];
    uint32_t blk_idx = dir->first_block;
    BlockOnDisk blk;
    uint32_t count = 0;

    while (blk_idx != FS_INVALID_BLOCK) {
        fs_read_block(blk_idx, &blk);
        DirEntry *entries = (DirEntry *)blk.data;

        for (uint32_t i = 0; i < DIRENTS_PER_BLOCK; i++) {
            if (entries[i].file_index == FS_INVALID_ENTRY) continue;
            int fi = entries[i].file_index;
            if (fi < 0 || fi >= FS_MAX_FILES || !file_table[fi].in_use) continue;

            FileEntry *fe = &file_table[fi];
            char perm_str[11];
            perm_str[0] = (fe->type == FS_TYPE_DIRECTORY) ? 'd' : '-';
            format_permissions(fe->permissions, perm_str + 1);

            printf("  %-10s %-12s %-12s %8u  %s\n",
                   perm_str,
                   fs_get_username(fe->owner_uid),
                   fs_get_groupname(fe->owner_gid),
                   fe->size,
                   entries[i].name);
            count++;
        }
        blk_idx = blk.next_block;
    }

    printf("\nTotal entries: %u\n", count);
}
