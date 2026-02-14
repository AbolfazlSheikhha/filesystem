// SPDX-License-Identifier: GPL-2.0
/*
 * deadbeef_fs.c — Linux Kernel Module for the deadbeef filesystem
 *
 * Mounts a deadbeef-formatted block device image and exposes it
 * through the Linux VFS.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abolfazl");
MODULE_DESCRIPTION("Deadbeef filesystem kernel module");

/* ================================================================
 *  On-disk constants (must match common/fs_config.h)
 * ================================================================ */

#define DEADBEEF_MAGIC              0xDEADBEEF
#define DEADBEEF_VERSION            3
#define DEADBEEF_BLOCK_SIZE         4096
#define DEADBEEF_MAX_FILES          10000
#define DEADBEEF_FILENAME_MAX       64
#define DEADBEEF_INVALID_BLOCK      0xFFFFFFFFu
#define DEADBEEF_INVALID_ENTRY      (-1)

#define DEADBEEF_TYPE_REGULAR       0
#define DEADBEEF_TYPE_DIRECTORY     1

#define DEADBEEF_MAX_USERS          32
#define DEADBEEF_MAX_GROUPS         32
#define DEADBEEF_USERNAME_MAX       32
#define DEADBEEF_GROUPNAME_MAX      32
#define DEADBEEF_MAX_GROUPS_PER_USER 16

#define DEADBEEF_BLOCK_DATA_SIZE    (DEADBEEF_BLOCK_SIZE - sizeof(u32))
#define DEADBEEF_BITMAP_BITS_PER_WORD 64

/* ================================================================
 *  On-disk structures (must match common/fs_types.h, #pragma pack(1))
 * ================================================================ */

struct deadbeef_disk_sb {
	u32 magic;
	u32 version;
	u32 block_size;
	u32 disk_size;
	u32 last_allocated_block;
	u32 num_files;
	u32 root_dir_head;
	u32 num_users;
	u32 num_groups;
	u32 next_uid;
	u32 next_gid;
} __packed;

struct deadbeef_disk_user {
	char username[DEADBEEF_USERNAME_MAX];
	u32  uid;
	u32  primary_gid;
	u32  secondary_gids[DEADBEEF_MAX_GROUPS_PER_USER];
	u8   num_secondary_groups;
	u8   in_use;
} __packed;

struct deadbeef_disk_group {
	char groupname[DEADBEEF_GROUPNAME_MAX];
	u32  gid;
	u8   in_use;
} __packed;

struct deadbeef_disk_file {
	char name[DEADBEEF_FILENAME_MAX];
	u32  type;
	u32  permissions;
	u32  size;
	u32  first_block;
	s32  next_entry;
	u32  owner_uid;
	u32  owner_gid;
	u8   in_use;
} __packed;

struct deadbeef_disk_block {
	u32 next_block;
	u8  data[DEADBEEF_BLOCK_DATA_SIZE];
} __packed;

struct deadbeef_disk_dirent {
	char name[DEADBEEF_FILENAME_MAX];
	s32  file_index;
} __packed;

#define DEADBEEF_DIRENTS_PER_BLOCK \
	(DEADBEEF_BLOCK_DATA_SIZE / sizeof(struct deadbeef_disk_dirent))

/* ================================================================
 *  Forward declarations
 * ================================================================ */

static int deadbeef_fill_super(struct super_block *sb, void *data, int silent);

/* ================================================================
 *  Mount / Unmount
 * ================================================================ */

static struct dentry *deadbeef_mount(struct file_system_type *fs_type,
				     int flags, const char *dev_name,
				     void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, deadbeef_fill_super);
}

static void deadbeef_kill_sb(struct super_block *sb)
{
	kill_block_super(sb);
}

/* ================================================================
 *  fill_super  (stub — to be implemented in 3.2)
 * ================================================================ */

static int deadbeef_fill_super(struct super_block *sb, void *data, int silent)
{
	pr_err("deadbeef: fill_super not yet implemented\n");
	return -ENOSYS;
}

/* ================================================================
 *  Filesystem type registration
 * ================================================================ */

static struct file_system_type deadbeef_fs_type = {
	.owner    = THIS_MODULE,
	.name     = "deadbeef",
	.mount    = deadbeef_mount,
	.kill_sb  = deadbeef_kill_sb,
	.fs_flags = FS_REQUIRES_DEV,
};

/* ================================================================
 *  Module init / exit
 * ================================================================ */

static int __init deadbeef_init(void)
{
	int ret;

	ret = register_filesystem(&deadbeef_fs_type);
	if (ret == 0)
		pr_info("deadbeef: filesystem registered\n");
	else
		pr_err("deadbeef: failed to register filesystem (%d)\n", ret);
	return ret;
}

static void __exit deadbeef_exit(void)
{
	unregister_filesystem(&deadbeef_fs_type);
	pr_info("deadbeef: filesystem unregistered\n");
}

module_init(deadbeef_init);
module_exit(deadbeef_exit);
