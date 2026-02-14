CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g

LIBFS_SRC = libfs/fs_state.c libfs/disk_io.c libfs/bitmap.c \
            libfs/file_ops.c libfs/user.c libfs/viz.c
CLI_SRC   = cli/cli.c

.PHONY: all clean

all: deadbeef_cli

deadbeef_cli: $(CLI_SRC) $(LIBFS_SRC)
	$(CC) $(CFLAGS) -o $@ $^ -lm

clean:
	rm -f deadbeef_cli filesys.db
