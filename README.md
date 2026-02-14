# Deadbeef Filesystem

A custom Linux filesystem implemented as a kernel module (LKM).

## Project Structure

```
.
├── common/           # Shared header definitions (on-disk format)
│   ├── fs_config.h   # Constants (block size, max files, etc.)
│   ├── fs_types.h    # On-disk structures (SuperBlock, FileEntry, etc.)
│   └── fs_layout.h   # Disk layout helpers
├── mkfs/             # Filesystem formatter
│   └── mkfs_deadbeef.c
├── lkm/              # Linux Kernel Module
│   ├── deadbeef_fs.c # Full VFS implementation
│   └── Makefile
├── docs/             # Documentation
└── Makefile
```

## Features

### Core (Part 3)
- **Bitmap-based free block management** — efficient space allocation
- **Variable-length files** — linked block chains with 4092 bytes/block
- **Directory support** — hierarchical filesystem with nested directories
- **Full VFS integration** — works with standard Linux tools (ls, cat, cp, mkdir, rm, etc.)

### Bonus
- **B1: Multi-user locking** — reader/writer semaphores for concurrent access
- **B2: Linux permissions** — chmod, chown, truncate with persistence
- **B3: O(1) block addressing** — in-memory block map eliminates O(n) chain walks

## On-Disk Format

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 44 B | SuperBlock (magic, version, disk size, etc.) |
| 44 | 3392 B | User table (32 × 106 B) |
| 3436 | 1184 B | Group table (32 × 37 B) |
| 4620 | 930000 B | File table (10000 × 93 B) |
| 934620 | ... | Data blocks (4096 B each) |

- **Magic**: `0xDEADBEEF`
- **Version**: 3
- **Block structure**: 4-byte `next_block` pointer + 4092 bytes data

## Building

```bash
# Build everything (mkfs + LKM)
make

# Or separately
make mkfs_deadbeef
make lkm
```

### Dependencies
- Linux kernel headers: `linux-headers-$(uname -r)`
- GCC

## Usage

### 1. Create a disk image
```bash
dd if=/dev/zero of=/tmp/deadbeef.img bs=1M count=64
./mkfs_deadbeef /tmp/deadbeef.img
```

### 2. Load the kernel module
```bash
sudo insmod lkm/deadbeef_fs.ko
```

### 3. Mount the filesystem
```bash
sudo mkdir -p /mnt/deadbeef
sudo losetup /dev/loop0 /tmp/deadbeef.img
sudo mount -t deadbeef /dev/loop0 /mnt/deadbeef
```

### 4. Use standard tools
```bash
ls -la /mnt/deadbeef/
echo "Hello" > /mnt/deadbeef/test.txt
cat /mnt/deadbeef/test.txt
mkdir /mnt/deadbeef/subdir
cp /mnt/deadbeef/test.txt /mnt/deadbeef/subdir/
chmod 600 /mnt/deadbeef/test.txt
```

### 5. Unmount and cleanup
```bash
sudo umount /mnt/deadbeef
sudo losetup -d /dev/loop0
sudo rmmod deadbeef_fs
```

## Testing

```bash
# Format, mount, test, unmount
dd if=/dev/zero of=/tmp/test.img bs=1M count=4
./mkfs_deadbeef /tmp/test.img
sudo insmod lkm/deadbeef_fs.ko
sudo losetup /dev/loop100 /tmp/test.img
sudo mount -t deadbeef /dev/loop100 /mnt/deadbeef_test

# Run tests...
ls -la /mnt/deadbeef_test/
echo "test" | sudo tee /mnt/deadbeef_test/file.txt
cat /mnt/deadbeef_test/file.txt

# Cleanup
sudo umount /mnt/deadbeef_test
sudo losetup -d /dev/loop100
sudo rmmod deadbeef_fs
```

## Documentation

See `docs/` for detailed documentation:
- [On-disk format](docs/ondisk_format.md)
- [mkfs formatter](docs/part2_mkfs.md)
- [LKM skeleton](docs/part3_1_lkm_skeleton.md)
- [Super operations & mount](docs/part3_2_fill_super_mount.md)
- [Inode operations](docs/part3_3_inode_operations.md)
- [File operations](docs/part3_4_file_operations.md)
- [Directory operations](docs/part3_5_dir_operations.md)
- [Multi-user locking (bonus)](docs/bonus_b1_multiuser_locking.md)
- [Linux permissions (bonus)](docs/bonus_b2_linux_permissions.md)
- [O(1) block addressing (bonus)](docs/bonus_b3_block_addressing.md)

## License

GPL-2.0 (required for Linux kernel modules)
