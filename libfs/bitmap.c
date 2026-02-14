#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "bitmap.h"
#include "fs_state.h"
#include "disk_io.h"
#include "../common/fs_config.h"
#include "../common/fs_layout.h"

// Free a range of blocks (mark as free in bitmap)
void fs_free_blocks(uint32_t start, uint32_t size) {
    for (uint32_t i = 0; i < size; i++) {
        if (start + i < max_data_blocks) {
            bitmap_set_free(start + i);
        }
    }
}

// Allocate 'count' contiguous blocks using First-Fit strategy with bitmap
// Uses __builtin_ffsll for fast bit scanning
int fs_alloc_blocks(uint32_t count, uint32_t *out_start) {
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

// Allocate a new data block using the Freelist Allocator
int fs_allocate_block(uint32_t *out_index) {
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

// Rebuild bitmap from file table (called on mount)
void fs_rebuild_freelist(void) {
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

// Initialize bitmap for a freshly formatted filesystem
void bitmap_init_all_free(void) {
    bitmap_num_words = (max_data_blocks + BITMAP_BITS_PER_WORD - 1) / BITMAP_BITS_PER_WORD;
    memset(free_bitmap, 0xFF, bitmap_num_words * sizeof(uint64_t));

    // Clear bits beyond max_data_blocks
    uint32_t last_valid_bit = max_data_blocks % BITMAP_BITS_PER_WORD;
    if (last_valid_bit != 0 && bitmap_num_words > 0) {
        free_bitmap[bitmap_num_words - 1] &= ((1ULL << last_valid_bit) - 1);
    }
}
