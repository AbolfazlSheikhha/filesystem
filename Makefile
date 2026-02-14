CC      = gcc
CFLAGS  = -Wall -Wextra -std=c11 -g

MKFS_SRC = mkfs/mkfs_deadbeef.c

.PHONY: all clean lkm lkm-clean

all: mkfs_deadbeef lkm

mkfs_deadbeef: $(MKFS_SRC)
	$(CC) $(CFLAGS) -o $@ $^

lkm:
	$(MAKE) -C lkm

lkm-clean:
	$(MAKE) -C lkm clean

clean: lkm-clean
	rm -f mkfs_deadbeef filesys.db
