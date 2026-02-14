#include <stdio.h>
#include "viz.h"
#include "fs_state.h"
#include "bitmap.h"
#include "user.h"
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

// ls command - list files with permissions
void cmd_ls(void) {
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
