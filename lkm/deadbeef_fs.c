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
#include <linux/buffer_head.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/statfs.h>
#include <linux/vmalloc.h>

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
 *  In-memory structures
 * ================================================================ */

struct deadbeef_sb_info {
	struct deadbeef_disk_sb dsb;
	struct deadbeef_disk_file *file_table;
	int    root_dir_index;
	loff_t data_area_offset;
	u32    max_data_blocks;
	u64   *free_bitmap;
	u32    bitmap_num_words;
	struct mutex lock;           /* protects file_table & bitmap */
};

struct deadbeef_inode_info {
	int          file_index;     /* index into file_table */
	struct inode vfs_inode;
};

/* ================================================================
 *  Inline helpers
 * ================================================================ */

static inline struct deadbeef_sb_info *DEADBEEF_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct deadbeef_inode_info *DEADBEEF_I(struct inode *inode)
{
	return container_of(inode, struct deadbeef_inode_info, vfs_inode);
}

static inline ino_t deadbeef_ino(int file_index)
{
	return (ino_t)(file_index + 1);
}

/* ================================================================
 *  Disk layout offset helpers
 * ================================================================ */

static loff_t deadbeef_sb_offset(void)
{
	return 0;
}

static loff_t deadbeef_filetable_offset(void)
{
	return (loff_t)sizeof(struct deadbeef_disk_sb)
	     + (loff_t)sizeof(struct deadbeef_disk_user)  * DEADBEEF_MAX_USERS
	     + (loff_t)sizeof(struct deadbeef_disk_group) * DEADBEEF_MAX_GROUPS;
}

static loff_t deadbeef_dataarea_offset(void)
{
	return deadbeef_filetable_offset()
	     + (loff_t)sizeof(struct deadbeef_disk_file) * DEADBEEF_MAX_FILES;
}

static loff_t deadbeef_block_offset(u32 block_index)
{
	return deadbeef_dataarea_offset()
	     + (loff_t)block_index * DEADBEEF_BLOCK_SIZE;
}

/* ================================================================
 *  Raw device I/O  (byte-level access over buffer_head)
 * ================================================================ */

static int deadbeef_dev_read(struct super_block *sb, void *buf,
			     size_t len, loff_t off)
{
	struct buffer_head *bh;
	unsigned int blk_bits = sb->s_blocksize_bits;
	unsigned int blk_size = sb->s_blocksize;

	while (len > 0) {
		sector_t sec = off >> blk_bits;
		unsigned in_off = off & (blk_size - 1);
		unsigned chunk  = blk_size - in_off;
		if (chunk > len)
			chunk = (unsigned)len;

		bh = sb_bread(sb, sec);
		if (!bh)
			return -EIO;
		memcpy(buf, bh->b_data + in_off, chunk);
		brelse(bh);

		buf  = (char *)buf + chunk;
		off += chunk;
		len -= chunk;
	}
	return 0;
}

static int deadbeef_dev_write(struct super_block *sb, const void *buf,
			      size_t len, loff_t off)
{
	struct buffer_head *bh;
	unsigned int blk_bits = sb->s_blocksize_bits;
	unsigned int blk_size = sb->s_blocksize;

	while (len > 0) {
		sector_t sec = off >> blk_bits;
		unsigned in_off = off & (blk_size - 1);
		unsigned chunk  = blk_size - in_off;
		if (chunk > len)
			chunk = (unsigned)len;

		bh = sb_bread(sb, sec);
		if (!bh)
			return -EIO;
		memcpy(bh->b_data + in_off, buf, chunk);
		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);

		buf  = (const char *)buf + chunk;
		off += chunk;
		len -= chunk;
	}
	return 0;
}

/* Convenience: read/write a single on-disk data block */

static int deadbeef_read_block(struct super_block *sb, u32 idx,
			       struct deadbeef_disk_block *blk)
{
	if (idx == DEADBEEF_INVALID_BLOCK)
		return -EINVAL;
	return deadbeef_dev_read(sb, blk, sizeof(*blk),
				 deadbeef_block_offset(idx));
}

static int deadbeef_write_block(struct super_block *sb, u32 idx,
				const struct deadbeef_disk_block *blk)
{
	return deadbeef_dev_write(sb, blk, sizeof(*blk),
				  deadbeef_block_offset(idx));
}

/* Sync superblock + file_table back to device */
static void deadbeef_sync_metadata(struct super_block *sb)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);

	deadbeef_dev_write(sb, &sbi->dsb, sizeof(sbi->dsb),
			   deadbeef_sb_offset());
	deadbeef_dev_write(sb, sbi->file_table,
			   sizeof(struct deadbeef_disk_file) * DEADBEEF_MAX_FILES,
			   deadbeef_filetable_offset());
}

/* ================================================================
 *  Bitmap  (free-block management, mirrors userspace bitmap.c)
 * ================================================================ */

static inline void deadbeef_bitmap_set_free(struct deadbeef_sb_info *sbi, u32 b)
{
	sbi->free_bitmap[b / 64] |= (1ULL << (b % 64));
}

static inline void deadbeef_bitmap_set_used(struct deadbeef_sb_info *sbi, u32 b)
{
	sbi->free_bitmap[b / 64] &= ~(1ULL << (b % 64));
}

/* Rebuild free bitmap by walking every file's block chain */
static int deadbeef_rebuild_bitmap(struct super_block *sb)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	int i;

	sbi->bitmap_num_words = (sbi->max_data_blocks + 63) / 64;
	sbi->free_bitmap = kvzalloc(sbi->bitmap_num_words * sizeof(u64),
				    GFP_KERNEL);
	if (!sbi->free_bitmap)
		return -ENOMEM;

	/* All free initially */
	memset(sbi->free_bitmap, 0xFF, sbi->bitmap_num_words * sizeof(u64));

	/* Clear bits beyond max_data_blocks */
	{
		u32 tail = sbi->max_data_blocks % 64;
		if (tail && sbi->bitmap_num_words > 0)
			sbi->free_bitmap[sbi->bitmap_num_words - 1] &=
				((1ULL << tail) - 1);
	}

	/* Walk every file's block chain → mark used */
	for (i = 0; i < DEADBEEF_MAX_FILES; i++) {
		struct deadbeef_disk_file *fe = &sbi->file_table[i];
		struct deadbeef_disk_block *blk;
		u32 idx;
		if (!fe->in_use)
			continue;

		blk = kmalloc(sizeof(*blk), GFP_KERNEL);
		if (!blk) {
			kvfree(sbi->free_bitmap);
			return -ENOMEM;
		}

		idx = fe->first_block;
		while (idx != DEADBEEF_INVALID_BLOCK) {
			if (idx >= sbi->max_data_blocks)
				break;
			deadbeef_bitmap_set_used(sbi, idx);
			if (deadbeef_read_block(sb, idx, blk))
				break;
			idx = blk->next_block;
		}
		kfree(blk);
	}
	return 0;
}

/* Allocate a single data block; returns 0 on success, index in *out */
static int deadbeef_alloc_block(struct super_block *sb, u32 *out)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_disk_block blk;
	u32 w, b;

	for (w = 0; w < sbi->bitmap_num_words; w++) {
		if (sbi->free_bitmap[w] == 0)
			continue;
		for (b = 0; b < 64; b++) {
			u32 idx = w * 64 + b;
			if (idx >= sbi->max_data_blocks)
				return -ENOSPC;
			if ((sbi->free_bitmap[w] >> b) & 1) {
				deadbeef_bitmap_set_used(sbi, idx);
				memset(&blk, 0, sizeof(blk));
				blk.next_block = DEADBEEF_INVALID_BLOCK;
				deadbeef_write_block(sb, idx, &blk);
				*out = idx;
				return 0;
			}
		}
	}
	return -ENOSPC;
}

/* Free a single data block */
static void deadbeef_free_block(struct super_block *sb, u32 idx)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	if (idx < sbi->max_data_blocks)
		deadbeef_bitmap_set_free(sbi, idx);
}

/* Free an entire chain of blocks */
static void deadbeef_free_chain(struct super_block *sb, u32 start)
{
	struct deadbeef_disk_block blk;
	u32 idx = start;

	while (idx != DEADBEEF_INVALID_BLOCK) {
		u32 next;
		if (deadbeef_read_block(sb, idx, &blk))
			break;
		next = blk.next_block;
		deadbeef_free_block(sb, idx);
		idx = next;
	}
}

/* ================================================================
 *  Inode cache
 * ================================================================ */

static struct kmem_cache *deadbeef_inode_cachep;

static struct inode *deadbeef_alloc_inode(struct super_block *sb)
{
	struct deadbeef_inode_info *di;

	di = alloc_inode_sb(sb, deadbeef_inode_cachep, GFP_KERNEL);
	if (!di)
		return NULL;
	return &di->vfs_inode;
}

static void deadbeef_free_inode(struct inode *inode)
{
	kmem_cache_free(deadbeef_inode_cachep, DEADBEEF_I(inode));
}

static void deadbeef_inode_init_once(void *obj)
{
	struct deadbeef_inode_info *di = obj;
	inode_init_once(&di->vfs_inode);
}

/* ================================================================
 *  Forward declarations for operations (stubs for now)
 * ================================================================ */

static const struct inode_operations deadbeef_dir_iops;
static const struct inode_operations deadbeef_file_iops;
static const struct file_operations  deadbeef_dir_fops;
static const struct file_operations  deadbeef_file_fops;

/* ================================================================
 *  deadbeef_iget — build a VFS inode from a file_table entry
 * ================================================================ */

static struct inode *deadbeef_iget(struct super_block *sb, int file_index)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_disk_file *fe;
	struct inode *inode;
	struct deadbeef_inode_info *di;

	if (file_index < 0 || file_index >= DEADBEEF_MAX_FILES)
		return ERR_PTR(-EINVAL);
	fe = &sbi->file_table[file_index];
	if (!fe->in_use)
		return ERR_PTR(-ESTALE);

	inode = iget_locked(sb, deadbeef_ino(file_index));
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;  /* already in cache */

	di = DEADBEEF_I(inode);
	di->file_index = file_index;

	inode->i_ino = deadbeef_ino(file_index);
	i_uid_write(inode, fe->owner_uid);
	i_gid_write(inode, fe->owner_gid);
	inode->i_size = fe->size;

	/* Set timestamps to mount time */
	simple_inode_init_ts(inode);

	if (fe->type == DEADBEEF_TYPE_DIRECTORY) {
		inode->i_mode = S_IFDIR | (fe->permissions & 0777);
		inode->i_op   = &deadbeef_dir_iops;
		inode->i_fop  = &deadbeef_dir_fops;
		set_nlink(inode, 2);
	} else {
		inode->i_mode = S_IFREG | (fe->permissions & 0777);
		inode->i_op   = &deadbeef_file_iops;
		inode->i_fop  = &deadbeef_file_fops;
		set_nlink(inode, 1);
	}

	unlock_new_inode(inode);
	return inode;
}

/* ================================================================
 *  (Stub) operation tables — filled in parts 3.3–3.5
 * ================================================================ */

static const struct inode_operations deadbeef_dir_iops = {
	/* lookup, create, mkdir, unlink, rmdir → part 3.3 */
};

static const struct inode_operations deadbeef_file_iops = {
	.setattr = simple_setattr,
	.getattr = simple_getattr,
};

static const struct file_operations deadbeef_dir_fops = {
	.owner  = THIS_MODULE,
	.llseek = generic_file_llseek,
	.read   = generic_read_dir,
	/* iterate_shared → part 3.5 */
};

static const struct file_operations deadbeef_file_fops = {
	.owner  = THIS_MODULE,
	.llseek = generic_file_llseek,
	/* read_iter, write_iter → part 3.4 */
};

/* ================================================================
 *  Super operations
 * ================================================================ */

static void deadbeef_put_super(struct super_block *sb)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);

	if (!sbi)
		return;

	deadbeef_sync_metadata(sb);
	kvfree(sbi->file_table);
	kvfree(sbi->free_bitmap);
	kfree(sbi);
	sb->s_fs_info = NULL;
}

static int deadbeef_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	u32 free_blocks = 0, w;

	for (w = 0; w < sbi->bitmap_num_words; w++)
		free_blocks += hweight64(sbi->free_bitmap[w]);

	buf->f_type    = DEADBEEF_MAGIC;
	buf->f_bsize   = DEADBEEF_BLOCK_SIZE;
	buf->f_blocks  = sbi->max_data_blocks;
	buf->f_bfree   = free_blocks;
	buf->f_bavail  = free_blocks;
	buf->f_files   = DEADBEEF_MAX_FILES;
	buf->f_ffree   = DEADBEEF_MAX_FILES - sbi->dsb.num_files;
	buf->f_namelen = DEADBEEF_FILENAME_MAX - 1;
	return 0;
}

static const struct super_operations deadbeef_super_ops = {
	.alloc_inode = deadbeef_alloc_inode,
	.free_inode  = deadbeef_free_inode,
	.put_super   = deadbeef_put_super,
	.statfs      = deadbeef_statfs,
};

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
 *  fill_super — read metadata from device, create root inode
 * ================================================================ */

static int deadbeef_fill_super(struct super_block *sb, void *data, int silent)
{
	struct deadbeef_sb_info *sbi;
	struct deadbeef_disk_sb dsb;
	struct inode *root_inode;
	int ret, i;

	/* Use 512-byte sectors for byte-granular I/O (our metadata is not
	 * aligned to DEADBEEF_BLOCK_SIZE) */
	if (!sb_set_blocksize(sb, 512)) {
		pr_err("deadbeef: cannot set block size to 512\n");
		return -EINVAL;
	}

	/* --- Read & validate on-disk superblock --- */
	ret = deadbeef_dev_read(sb, &dsb, sizeof(dsb), deadbeef_sb_offset());
	if (ret) {
		pr_err("deadbeef: cannot read superblock\n");
		return ret;
	}
	if (dsb.magic != DEADBEEF_MAGIC) {
		if (!silent)
			pr_err("deadbeef: bad magic 0x%08X\n", dsb.magic);
		return -EINVAL;
	}
	pr_info("deadbeef: magic OK, version %u, disk %u bytes\n",
		dsb.version, dsb.disk_size);

	/* --- Allocate in-memory superblock info --- */
	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->dsb = dsb;
	mutex_init(&sbi->lock);
	sbi->data_area_offset = deadbeef_dataarea_offset();
	sbi->max_data_blocks  = (dsb.disk_size - (u32)sbi->data_area_offset)
				/ DEADBEEF_BLOCK_SIZE;

	/* --- Read the entire file_table into RAM --- */
	sbi->file_table = kvmalloc(sizeof(struct deadbeef_disk_file)
				   * DEADBEEF_MAX_FILES, GFP_KERNEL);
	if (!sbi->file_table) {
		kfree(sbi);
		return -ENOMEM;
	}
	ret = deadbeef_dev_read(sb, sbi->file_table,
				sizeof(struct deadbeef_disk_file)
				* DEADBEEF_MAX_FILES,
				deadbeef_filetable_offset());
	if (ret) {
		pr_err("deadbeef: cannot read file table\n");
		kvfree(sbi->file_table);
		kfree(sbi);
		return ret;
	}

	/* --- Locate root directory (name == "/") --- */
	sbi->root_dir_index = -1;
	for (i = 0; i < DEADBEEF_MAX_FILES; i++) {
		if (sbi->file_table[i].in_use &&
		    sbi->file_table[i].type == DEADBEEF_TYPE_DIRECTORY &&
		    strncmp(sbi->file_table[i].name, "/",
			    DEADBEEF_FILENAME_MAX) == 0) {
			sbi->root_dir_index = i;
			break;
		}
	}
	if (sbi->root_dir_index < 0) {
		pr_err("deadbeef: root directory not found\n");
		kvfree(sbi->file_table);
		kfree(sbi);
		return -EINVAL;
	}

	/* --- Wire up VFS super_block --- */
	sb->s_fs_info  = sbi;
	sb->s_magic    = DEADBEEF_MAGIC;
	sb->s_op       = &deadbeef_super_ops;
	sb->s_maxbytes = MAX_LFS_FILESIZE;

	/* --- Rebuild free-block bitmap --- */
	ret = deadbeef_rebuild_bitmap(sb);
	if (ret) {
		kvfree(sbi->file_table);
		kfree(sbi);
		return ret;
	}

	/* --- Create VFS root inode --- */
	root_inode = deadbeef_iget(sb, sbi->root_dir_index);
	if (IS_ERR(root_inode)) {
		kvfree(sbi->free_bitmap);
		kvfree(sbi->file_table);
		kfree(sbi);
		return PTR_ERR(root_inode);
	}

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		kvfree(sbi->free_bitmap);
		kvfree(sbi->file_table);
		kfree(sbi);
		return -ENOMEM;
	}

	pr_info("deadbeef: mounted — %u files, %u data blocks\n",
		dsb.num_files, sbi->max_data_blocks);
	return 0;
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

	deadbeef_inode_cachep = kmem_cache_create("deadbeef_inode",
			sizeof(struct deadbeef_inode_info), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_ACCOUNT,
			deadbeef_inode_init_once);
	if (!deadbeef_inode_cachep)
		return -ENOMEM;

	ret = register_filesystem(&deadbeef_fs_type);
	if (ret) {
		kmem_cache_destroy(deadbeef_inode_cachep);
		pr_err("deadbeef: failed to register filesystem (%d)\n", ret);
		return ret;
	}
	pr_info("deadbeef: filesystem registered\n");
	return 0;
}

static void __exit deadbeef_exit(void)
{
	unregister_filesystem(&deadbeef_fs_type);
	rcu_barrier();
	kmem_cache_destroy(deadbeef_inode_cachep);
	pr_info("deadbeef: filesystem unregistered\n");
}

module_init(deadbeef_init);
module_exit(deadbeef_exit);
