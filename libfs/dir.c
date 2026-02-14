#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dir.h"
#include "fs_state.h"
#include "disk_io.h"
#include "bitmap.h"
#include "../common/fs_config.h"
#include "../common/fs_layout.h"

// ------------ Directory Entry Operations ------------

// Find an entry by name inside a directory. Returns file_table index or -1.
int dir_find_entry(int dir_index, const char *name) {
    if (dir_index < 0 || dir_index >= FS_MAX_FILES) return -1;
    FileEntry *dir = &file_table[dir_index];
    if (!dir->in_use || dir->type != FS_TYPE_DIRECTORY) return -1;

    uint32_t blk_idx = dir->first_block;
    BlockOnDisk blk;

    while (blk_idx != FS_INVALID_BLOCK) {
        fs_read_block(blk_idx, &blk);
        DirEntry *entries = (DirEntry *)blk.data;

        for (uint32_t i = 0; i < DIRENTS_PER_BLOCK; i++) {
            if (entries[i].file_index != FS_INVALID_ENTRY &&
                strncmp(entries[i].name, name, FS_FILENAME_MAX) == 0) {
                return entries[i].file_index;
            }
        }
        blk_idx = blk.next_block;
    }
    return -1;
}

// Add an entry to a directory. Scans for a free slot; allocates a new block if needed.
int dir_add_entry(int dir_index, const char *name, int file_index) {
    if (dir_index < 0 || dir_index >= FS_MAX_FILES) return -1;
    FileEntry *dir = &file_table[dir_index];
    if (!dir->in_use || dir->type != FS_TYPE_DIRECTORY) return -1;

    // Check for duplicate name
    if (dir_find_entry(dir_index, name) >= 0) {
        fprintf(stderr, "Entry '%s' already exists in directory.\n", name);
        return -1;
    }

    // Scan existing blocks for a free slot
    uint32_t blk_idx = dir->first_block;
    uint32_t prev_blk = FS_INVALID_BLOCK;
    BlockOnDisk blk;

    while (blk_idx != FS_INVALID_BLOCK) {
        fs_read_block(blk_idx, &blk);
        DirEntry *entries = (DirEntry *)blk.data;

        for (uint32_t i = 0; i < DIRENTS_PER_BLOCK; i++) {
            if (entries[i].file_index == FS_INVALID_ENTRY) {
                // Found a free slot
                memset(entries[i].name, 0, FS_FILENAME_MAX);
                strncpy(entries[i].name, name, FS_FILENAME_MAX - 1);
                entries[i].file_index = file_index;
                fs_write_block(blk_idx, &blk);

                // Update directory size if needed
                // size tracks total number of active entries
                dir->size++;
                fs_sync_metadata();
                return 0;
            }
        }
        prev_blk = blk_idx;
        blk_idx = blk.next_block;
    }

    // No free slot found — allocate a new block for the directory
    uint32_t new_blk;
    if (fs_allocate_block(&new_blk) != 0) {
        fprintf(stderr, "Cannot allocate block for directory.\n");
        return -1;
    }

    // Initialize the new block with empty DirEntry slots
    fs_read_block(new_blk, &blk);
    DirEntry *entries = (DirEntry *)blk.data;
    for (uint32_t i = 0; i < DIRENTS_PER_BLOCK; i++) {
        memset(entries[i].name, 0, FS_FILENAME_MAX);
        entries[i].file_index = FS_INVALID_ENTRY;
    }

    // Write the first entry
    strncpy(entries[0].name, name, FS_FILENAME_MAX - 1);
    entries[0].file_index = file_index;
    blk.next_block = FS_INVALID_BLOCK;
    fs_write_block(new_blk, &blk);

    // Link the new block into the directory's chain
    if (dir->first_block == FS_INVALID_BLOCK) {
        dir->first_block = new_blk;
    } else {
        BlockOnDisk prev;
        fs_read_block(prev_blk, &prev);
        prev.next_block = new_blk;
        fs_write_block(prev_blk, &prev);
    }

    dir->size++;
    fs_sync_metadata();
    return 0;
}

// Remove the entry with the given name from a directory.
int dir_remove_entry(int dir_index, const char *name) {
    if (dir_index < 0 || dir_index >= FS_MAX_FILES) return -1;
    FileEntry *dir = &file_table[dir_index];
    if (!dir->in_use || dir->type != FS_TYPE_DIRECTORY) return -1;

    uint32_t blk_idx = dir->first_block;
    BlockOnDisk blk;

    while (blk_idx != FS_INVALID_BLOCK) {
        fs_read_block(blk_idx, &blk);
        DirEntry *entries = (DirEntry *)blk.data;

        for (uint32_t i = 0; i < DIRENTS_PER_BLOCK; i++) {
            if (entries[i].file_index != FS_INVALID_ENTRY &&
                strncmp(entries[i].name, name, FS_FILENAME_MAX) == 0) {
                // Clear the slot
                memset(entries[i].name, 0, FS_FILENAME_MAX);
                entries[i].file_index = FS_INVALID_ENTRY;
                fs_write_block(blk_idx, &blk);

                dir->size--;
                fs_sync_metadata();
                return 0;
            }
        }
        blk_idx = blk.next_block;
    }

    fprintf(stderr, "Entry '%s' not found in directory.\n", name);
    return -1;
}

// Create a new subdirectory inside parent_dir_index.
int dir_mkdir(int parent_dir_index, const char *name) {
    if (parent_dir_index < 0 || parent_dir_index >= FS_MAX_FILES) return -1;
    FileEntry *parent = &file_table[parent_dir_index];
    if (!parent->in_use || parent->type != FS_TYPE_DIRECTORY) return -1;

    // Check for duplicate
    if (dir_find_entry(parent_dir_index, name) >= 0) {
        fprintf(stderr, "Directory '%s' already exists.\n", name);
        return -1;
    }

    // Find a free file_table slot
    int slot = -1;
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (!file_table[i].in_use) {
            slot = i;
            break;
        }
    }
    if (slot < 0) {
        fprintf(stderr, "No free file entries for mkdir.\n");
        return -1;
    }

    // Initialize the new directory entry in file_table
    FileEntry *fe = &file_table[slot];
    memset(fe, 0, sizeof(*fe));
    strncpy(fe->name, name, FS_FILENAME_MAX - 1);
    fe->name[FS_FILENAME_MAX - 1] = '\0';
    fe->type = FS_TYPE_DIRECTORY;
    fe->permissions = PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_OWNER_EXEC |
                      PERM_GROUP_READ | PERM_GROUP_EXEC |
                      PERM_OTHER_READ | PERM_OTHER_EXEC;  // 0755
    fe->size = 0;
    fe->first_block = FS_INVALID_BLOCK;
    fe->owner_uid = current_uid;
    fe->owner_gid = current_gid;
    fe->next_entry = sb.root_dir_head;
    fe->in_use = 1;
    sb.root_dir_head = slot;
    sb.num_files++;

    // Add entry to parent directory
    if (dir_add_entry(parent_dir_index, name, slot) != 0) {
        // Rollback
        fe->in_use = 0;
        sb.num_files--;
        fs_sync_metadata();
        return -1;
    }

    fs_sync_metadata();
    return slot;
}
