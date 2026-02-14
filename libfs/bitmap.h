#ifndef BITMAP_H
#define BITMAP_H

#include <stdint.h>

// Bitmap helpers
static inline void bitmap_set_free(uint32_t block) {
    extern uint64_t free_bitmap[];
    uint32_t word = block / 64;
    uint32_t bit  = block % 64;
    free_bitmap[word] |= (1ULL << bit);
}

static inline void bitmap_set_used(uint32_t block) {
    extern uint64_t free_bitmap[];
    uint32_t word = block / 64;
    uint32_t bit  = block % 64;
    free_bitmap[word] &= ~(1ULL << bit);
}

static inline int bitmap_is_free(uint32_t block) {
    extern uint64_t free_bitmap[];
    uint32_t word = block / 64;
    uint32_t bit  = block % 64;
    return (free_bitmap[word] >> bit) & 1;
}

// Block-level operations
void fs_free_blocks(uint32_t start, uint32_t size);
int  fs_alloc_blocks(uint32_t count, uint32_t *out_start);
int  fs_allocate_block(uint32_t *out_index);
void fs_rebuild_freelist(void);
void bitmap_init_all_free(void);

#endif /* BITMAP_H */
