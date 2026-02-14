#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "file_ops.h"
#include "fs_state.h"
#include "disk_io.h"
#include "bitmap.h"
#include "user.h"
#include "dir.h"
#include "../common/fs_config.h"
#include "../common/fs_layout.h"

// ------------ Internal helpers ------------

static int fs_allocate_file_entry(const char *name, uint32_t type, uint32_t perm, int parent_dir) {
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
            fe->owner_uid = current_uid;
            fe->owner_gid = current_gid;

            fe->next_entry = sb.root_dir_head;
            fe->in_use = 1;
            sb.root_dir_head = i;
            sb.num_files++;

            // Add entry to parent directory
            if (parent_dir >= 0) {
                if (dir_add_entry(parent_dir, name, i) != 0) {
                    // Rollback
                    fe->in_use = 0;
                    sb.num_files--;
                    return -1;
                }
            }

            fs_sync_metadata();
            return i;
        }
    }
    return -1;
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

        fs_free_blocks(curr, 1);

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
    // Remove from parent directory dirent
    // Search all directories for an entry pointing to this index
    for (int d = 0; d < FS_MAX_FILES; ++d) {
        if (file_table[d].in_use && file_table[d].type == FS_TYPE_DIRECTORY) {
            // Try to remove - dir_remove_entry will just return -1 if not found
            uint32_t blk_idx = file_table[d].first_block;
            BlockOnDisk dblk;
            while (blk_idx != FS_INVALID_BLOCK) {
                fs_read_block(blk_idx, &dblk);
                DirEntry *entries = (DirEntry *)dblk.data;
                for (uint32_t j = 0; j < DIRENTS_PER_BLOCK; j++) {
                    if (entries[j].file_index == index) {
                        memset(entries[j].name, 0, FS_FILENAME_MAX);
                        entries[j].file_index = FS_INVALID_ENTRY;
                        fs_write_block(blk_idx, &dblk);
                        file_table[d].size--;
                        goto dirent_removed;
                    }
                }
                blk_idx = dblk.next_block;
            }
        }
    }
dirent_removed:

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

int my_open(const char *path, uint32_t flags) {
    if (current_file_index != -1) {
        fprintf(stderr, "A file is already open. Close it first.\n");
        return -1;
    }

    // Build absolute path from cwd if relative
    char abs_path[1024];
    make_absolute(path, abs_path, sizeof(abs_path));

    // Try to resolve the full path first
    int idx = resolve_path(abs_path);
    if (idx < 0) {
        if (!(flags & FLAG_CREATE)) {
            fprintf(stderr, "File '%s' not found and CREATE flag not set.\n", abs_path);
            return -1;
        }
        // Resolve parent directory and extract basename
        int parent_dir;
        char basename[FS_FILENAME_MAX];
        if (resolve_path_parent(abs_path, &parent_dir, basename) != 0) {
            fprintf(stderr, "Cannot resolve parent directory of '%s'.\n", abs_path);
            return -1;
        }
        // Create file with default permissions rw-r--r-- (0644)
        idx = fs_allocate_file_entry(basename, FS_TYPE_REGULAR,
                PERM_OWNER_READ | PERM_OWNER_WRITE | PERM_GROUP_READ | PERM_OTHER_READ,
                parent_dir);
        if (idx < 0) {
            fprintf(stderr, "No free file entries available.\n");
            return -1;
        }
        printf("Created file '%s' (owner: %s, group: %s).\n",
               abs_path, fs_get_username(current_uid), fs_get_groupname(current_gid));
    } else {
        // Check permissions for existing file
        FileEntry *fe = &file_table[idx];

        // Check read permission
        if (!can_read_file(fe)) {
            fprintf(stderr, "Permission denied: Cannot read file '%s'.\n", abs_path);
            return -1;
        }

        // Check write permission if WRITE flag is set
        if ((flags & FLAG_WRITE) && !can_write_file(fe)) {
            fprintf(stderr, "Permission denied: Cannot write to file '%s'.\n", abs_path);
            return -1;
        }
    }
    current_file_index = idx;
    current_file_flags = flags;
    printf("Opened file '%s' (index %d).\n", abs_path, idx);
    return 0;
}

ssize_t my_read(uint32_t pos, uint32_t n_bytes, uint8_t *buffer) {
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

ssize_t my_write(uint32_t pos, const uint8_t *buffer, uint32_t n_bytes) {
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

int my_shrink(uint32_t new_size) {
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

        fs_free_blocks(block_to_free, 1);

        block_to_free = next;
    }

    fe->size = new_size;
    fs_sync_metadata();
    return 0;
}

uint32_t my_get_file_stats(void) {
    if (current_file_index == -1) {
        fprintf(stderr, "No file is open.\n");
        return 0;
    }
    return file_table[current_file_index].size;
}

int my_close(void) {
    if (current_file_index == -1) {
        fprintf(stderr, "No file is open.\n");
        return -1;
    }
    current_file_index = -1;
    current_file_flags = 0;
    return 0;
}

int my_rm(void) {
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

void my_get_fs_stats(void) {
    uint64_t meta_bytes = dataarea_offset();
    uint64_t usable_bytes = FS_DISK_SIZE - meta_bytes;

    // Approximate usage from file table
    uint64_t used_bytes = 0;
    for (int i = 0; i < FS_MAX_FILES; i++) {
        if (file_table[i].in_use) {
            // Count blocks
            uint32_t count = 0;
            uint32_t idx = file_table[i].first_block;
            BlockOnDisk blk;
            while (idx != FS_INVALID_BLOCK) {
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
