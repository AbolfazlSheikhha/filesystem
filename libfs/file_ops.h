#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <stdint.h>
#include <sys/types.h>

int      my_open(const char *filename, uint32_t flags);
ssize_t  my_read(uint32_t pos, uint32_t n_bytes, uint8_t *buffer);
ssize_t  my_write(uint32_t pos, const uint8_t *buffer, uint32_t n_bytes);
int      my_shrink(uint32_t new_size);
uint32_t my_get_file_stats(void);
int      my_close(void);
int      my_rm(void);
int      my_cp(const char *src_path, const char *dst_path);
int      my_mv(const char *src_path, const char *dst_path);
void     my_get_fs_stats(void);

#endif /* FILE_OPS_H */
