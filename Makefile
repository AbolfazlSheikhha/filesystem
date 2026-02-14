CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g

LIBFS_SRC = libfs/fs_state.c libfs/disk_io.c libfs/bitmap.c \
            libfs/file_ops.c libfs/user.c libfs/viz.c libfs/dir.c
CLI_SRC   = cli/cli.c
MKFS_SRC  = mkfs/mkfs_deadbeef.c

.PHONY: all clean

all: deadbeef_cli mkfs_deadbeef

deadbeef_cli: $(CLI_SRC) $(LIBFS_SRC)
	$(CC) $(CFLAGS) -o $@ $^ -lm

mkfs_deadbeef: $(MKFS_SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f deadbeef_cli mkfs_deadbeef filesys.db
