#ifndef DIR_H
#define DIR_H

#include <stdint.h>

// Add an entry (name → file_index) to a directory's data blocks.
// Returns 0 on success, -1 on failure.
int dir_add_entry(int dir_index, const char *name, int file_index);

// Remove the entry with the given name from a directory's data blocks.
// Returns 0 on success, -1 if not found.
int dir_remove_entry(int dir_index, const char *name);

// Find an entry by name in a directory. Returns the file_table index, or -1.
int dir_find_entry(int dir_index, const char *name);

// Create a new directory inside parent_dir_index with the given name.
// Returns the file_table index of the new directory, or -1 on failure.
int dir_mkdir(int parent_dir_index, const char *name);

#endif /* DIR_H */
