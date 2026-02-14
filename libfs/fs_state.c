#include "fs_state.h"

// ------------ Global state definitions ------------
int disk_fd = -1;
SuperBlock sb;
FileEntry file_table[FS_MAX_FILES];
UserEntry user_table[FS_MAX_USERS];
GroupEntry group_table[FS_MAX_GROUPS];
uint32_t max_data_blocks = 0;

uint32_t current_uid = ROOT_UID;
uint32_t current_gid = ROOT_GID;

int current_file_index = -1;
uint32_t current_file_flags = 0;

int root_dir_index = -1;

int cwd_index = -1;
char cwd_path[1024] = "/";

uint64_t free_bitmap[BITMAP_MAX_WORDS];
uint32_t bitmap_num_words = 0;
