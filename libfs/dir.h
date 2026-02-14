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

// Resolve an absolute path (e.g. "/foo/bar/baz") to a file_table index.
// Returns the file_table index of the final component, or -1 on failure.
int resolve_path(const char *path);

// Resolve all components of a path except the last one.
// Stores the parent directory index in *parent_out and copies the
// basename (last component) into basename_out (must be >= FS_FILENAME_MAX).
// Returns 0 on success, -1 on failure.
int resolve_path_parent(const char *path, int *parent_out, char *basename_out);

// Build an absolute path from a user-supplied path.
// If path starts with '/', it is absolute; otherwise it is joined with cwd_path.
// Result is written to abs_out (must be >= 1024 bytes).
void make_absolute(const char *path, char *abs_out, size_t abs_size);

#endif /* DIR_H */
