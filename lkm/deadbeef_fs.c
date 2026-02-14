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
#include <linux/rwsem.h>
#include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/statfs.h>
#include <linux/vmalloc.h>
#include <linux/cred.h>

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
	struct rw_semaphore meta_rwsem; /* protects file_table & bitmap */
};

struct deadbeef_inode_info {
	int                 file_index;   /* index into file_table */
	struct rw_semaphore  data_rwsem;   /* per-file concurrent access */
	struct inode         vfs_inode;
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
	struct deadbeef_disk_block *blk;
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
				blk = kzalloc(sizeof(*blk), GFP_KERNEL);
				if (!blk)
					return -ENOMEM;
				blk->next_block = DEADBEEF_INVALID_BLOCK;
				deadbeef_write_block(sb, idx, blk);
				kfree(blk);
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
	struct deadbeef_disk_block *blk;
	u32 idx = start;

	if (idx == DEADBEEF_INVALID_BLOCK)
		return;

	blk = kmalloc(sizeof(*blk), GFP_KERNEL);
	if (!blk)
		return;

	while (idx != DEADBEEF_INVALID_BLOCK) {
		u32 next;
		if (deadbeef_read_block(sb, idx, blk))
			break;
		next = blk->next_block;
		deadbeef_free_block(sb, idx);
		idx = next;
	}
	kfree(blk);
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
 *  Forward declarations for operations
 * ================================================================ */

static struct dentry *deadbeef_lookup(struct inode *dir, struct dentry *dentry,
				      unsigned int flags);
static int deadbeef_create(struct mnt_idmap *idmap, struct inode *dir,
			   struct dentry *dentry, umode_t mode, bool excl);
static int deadbeef_mkdir(struct mnt_idmap *idmap, struct inode *dir,
			  struct dentry *dentry, umode_t mode);
static int deadbeef_unlink(struct inode *dir, struct dentry *dentry);
static int deadbeef_rmdir(struct inode *dir, struct dentry *dentry);

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
	init_rwsem(&di->data_rwsem);

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
 *  Directory helpers  (operate on file_table entries on disk)
 * ================================================================ */

/* Find entry by name inside a directory; returns file_table index or -1 */
static int deadbeef_dir_find(struct super_block *sb, int dir_index,
			     const char *name)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_disk_file *dir;
	struct deadbeef_disk_block *blk;
	u32 blk_idx;

	if (dir_index < 0 || dir_index >= DEADBEEF_MAX_FILES)
		return -1;
	dir = &sbi->file_table[dir_index];
	if (!dir->in_use || dir->type != DEADBEEF_TYPE_DIRECTORY)
		return -1;

	blk = kmalloc(sizeof(*blk), GFP_KERNEL);
	if (!blk)
		return -1;

	blk_idx = dir->first_block;
	while (blk_idx != DEADBEEF_INVALID_BLOCK) {
		struct deadbeef_disk_dirent *de;
		u32 i;
		if (deadbeef_read_block(sb, blk_idx, blk))
			break;
		de = (struct deadbeef_disk_dirent *)blk->data;
		for (i = 0; i < DEADBEEF_DIRENTS_PER_BLOCK; i++) {
			if (de[i].file_index != DEADBEEF_INVALID_ENTRY &&
			    strncmp(de[i].name, name,
				    DEADBEEF_FILENAME_MAX) == 0) {
				int ret = de[i].file_index;
				kfree(blk);
				return ret;
			}
		}
		blk_idx = blk->next_block;
	}
	kfree(blk);
	return -1;
}

/* Add (name → file_index) to a directory's data blocks */
static int deadbeef_dir_add(struct super_block *sb, int dir_index,
			    const char *name, int file_index)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_disk_file *dir;
	struct deadbeef_disk_block *blk;
	u32 blk_idx, prev_blk = DEADBEEF_INVALID_BLOCK;

	if (dir_index < 0 || dir_index >= DEADBEEF_MAX_FILES)
		return -EINVAL;
	dir = &sbi->file_table[dir_index];
	if (!dir->in_use || dir->type != DEADBEEF_TYPE_DIRECTORY)
		return -ENOTDIR;
	if (deadbeef_dir_find(sb, dir_index, name) >= 0)
		return -EEXIST;

	blk = kmalloc(sizeof(*blk), GFP_KERNEL);
	if (!blk)
		return -ENOMEM;

	/* Scan existing blocks for free slot */
	blk_idx = dir->first_block;
	while (blk_idx != DEADBEEF_INVALID_BLOCK) {
		struct deadbeef_disk_dirent *de;
		u32 i;
		if (deadbeef_read_block(sb, blk_idx, blk))
			break;
		de = (struct deadbeef_disk_dirent *)blk->data;
		for (i = 0; i < DEADBEEF_DIRENTS_PER_BLOCK; i++) {
			if (de[i].file_index == DEADBEEF_INVALID_ENTRY) {
				memset(de[i].name, 0, DEADBEEF_FILENAME_MAX);
				strncpy(de[i].name, name,
					DEADBEEF_FILENAME_MAX - 1);
				de[i].file_index = file_index;
				deadbeef_write_block(sb, blk_idx, blk);
				dir->size++;
				deadbeef_sync_metadata(sb);
				kfree(blk);
				return 0;
			}
		}
		prev_blk = blk_idx;
		blk_idx = blk->next_block;
	}

	/* No free slot — allocate a new block */
	{
		u32 new_blk_idx;
		struct deadbeef_disk_dirent *de;
		u32 i;
		int ret = deadbeef_alloc_block(sb, &new_blk_idx);
		if (ret) {
			kfree(blk);
			return -ENOSPC;
		}

		if (deadbeef_read_block(sb, new_blk_idx, blk)) {
			kfree(blk);
			return -EIO;
		}
		de = (struct deadbeef_disk_dirent *)blk->data;
		for (i = 0; i < DEADBEEF_DIRENTS_PER_BLOCK; i++) {
			memset(de[i].name, 0, DEADBEEF_FILENAME_MAX);
			de[i].file_index = DEADBEEF_INVALID_ENTRY;
		}
		strncpy(de[0].name, name, DEADBEEF_FILENAME_MAX - 1);
		de[0].file_index = file_index;
		blk->next_block = DEADBEEF_INVALID_BLOCK;
		deadbeef_write_block(sb, new_blk_idx, blk);

		if (dir->first_block == DEADBEEF_INVALID_BLOCK) {
			dir->first_block = new_blk_idx;
		} else {
			struct deadbeef_disk_block *prev;
			prev = kmalloc(sizeof(*prev), GFP_KERNEL);
			if (!prev) {
				kfree(blk);
				return -ENOMEM;
			}
			if (deadbeef_read_block(sb, prev_blk, prev) == 0) {
				prev->next_block = new_blk_idx;
				deadbeef_write_block(sb, prev_blk, prev);
			}
			kfree(prev);
		}

		dir->size++;
		deadbeef_sync_metadata(sb);
	}
	kfree(blk);
	return 0;
}

/* Remove entry by name from a directory's data blocks */
static int deadbeef_dir_remove(struct super_block *sb, int dir_index,
			       const char *name)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_disk_file *dir;
	struct deadbeef_disk_block *blk;
	u32 blk_idx;

	if (dir_index < 0 || dir_index >= DEADBEEF_MAX_FILES)
		return -EINVAL;
	dir = &sbi->file_table[dir_index];
	if (!dir->in_use || dir->type != DEADBEEF_TYPE_DIRECTORY)
		return -ENOTDIR;

	blk = kmalloc(sizeof(*blk), GFP_KERNEL);
	if (!blk)
		return -ENOMEM;

	blk_idx = dir->first_block;
	while (blk_idx != DEADBEEF_INVALID_BLOCK) {
		struct deadbeef_disk_dirent *de;
		u32 i;
		if (deadbeef_read_block(sb, blk_idx, blk))
			break;
		de = (struct deadbeef_disk_dirent *)blk->data;
		for (i = 0; i < DEADBEEF_DIRENTS_PER_BLOCK; i++) {
			if (de[i].file_index != DEADBEEF_INVALID_ENTRY &&
			    strncmp(de[i].name, name,
				    DEADBEEF_FILENAME_MAX) == 0) {
				memset(de[i].name, 0, DEADBEEF_FILENAME_MAX);
				de[i].file_index = DEADBEEF_INVALID_ENTRY;
				deadbeef_write_block(sb, blk_idx, blk);
				dir->size--;
				deadbeef_sync_metadata(sb);
				kfree(blk);
				return 0;
			}
		}
		blk_idx = blk->next_block;
	}
	kfree(blk);
	return -ENOENT;
}

/* ================================================================
 *  Inode operations: lookup, create, mkdir, unlink, rmdir
 * ================================================================ */

static struct dentry *deadbeef_lookup(struct inode *dir, struct dentry *dentry,
				      unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct deadbeef_inode_info *di = DEADBEEF_I(dir);
	struct inode *inode = NULL;
	int file_index;

	if (dentry->d_name.len >= DEADBEEF_FILENAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	file_index = deadbeef_dir_find(sb, di->file_index,
				       dentry->d_name.name);
	if (file_index >= 0) {
		inode = deadbeef_iget(sb, file_index);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}
	return d_splice_alias(inode, dentry);
}

static int deadbeef_create(struct mnt_idmap *idmap, struct inode *dir,
			   struct dentry *dentry, umode_t mode, bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_inode_info *di = DEADBEEF_I(dir);
	struct deadbeef_disk_file *fe;
	struct inode *inode;
	int slot, ret;

	down_write(&sbi->meta_rwsem);
	for (slot = 0; slot < DEADBEEF_MAX_FILES; slot++) {
		if (!sbi->file_table[slot].in_use)
			break;
	}
	if (slot >= DEADBEEF_MAX_FILES) {
		up_write(&sbi->meta_rwsem);
		return -ENOSPC;
	}

	fe = &sbi->file_table[slot];
	memset(fe, 0, sizeof(*fe));
	strncpy(fe->name, dentry->d_name.name, DEADBEEF_FILENAME_MAX - 1);
	fe->type        = DEADBEEF_TYPE_REGULAR;
	fe->permissions = mode & 0777;
	fe->size        = 0;
	fe->first_block = DEADBEEF_INVALID_BLOCK;
	fe->next_entry  = sbi->dsb.root_dir_head;
	fe->owner_uid   = from_kuid(&init_user_ns, current_fsuid());
	fe->owner_gid   = from_kgid(&init_user_ns, current_fsgid());
	fe->in_use      = 1;
	sbi->dsb.root_dir_head = slot;
	sbi->dsb.num_files++;

	ret = deadbeef_dir_add(sb, di->file_index,
			       dentry->d_name.name, slot);
	if (ret) {
		fe->in_use = 0;
		sbi->dsb.num_files--;
		up_write(&sbi->meta_rwsem);
		return ret;
	}
	deadbeef_sync_metadata(sb);
	up_write(&sbi->meta_rwsem);

	inode = deadbeef_iget(sb, slot);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);
	return 0;
}

static int deadbeef_mkdir(struct mnt_idmap *idmap, struct inode *dir,
			  struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_inode_info *di = DEADBEEF_I(dir);
	struct deadbeef_disk_file *fe;
	struct inode *inode;
	int slot, ret;

	down_write(&sbi->meta_rwsem);
	for (slot = 0; slot < DEADBEEF_MAX_FILES; slot++) {
		if (!sbi->file_table[slot].in_use)
			break;
	}
	if (slot >= DEADBEEF_MAX_FILES) {
		up_write(&sbi->meta_rwsem);
		return -ENOSPC;
	}

	fe = &sbi->file_table[slot];
	memset(fe, 0, sizeof(*fe));
	strncpy(fe->name, dentry->d_name.name, DEADBEEF_FILENAME_MAX - 1);
	fe->type        = DEADBEEF_TYPE_DIRECTORY;
	fe->permissions = mode & 0777;
	fe->size        = 0;
	fe->first_block = DEADBEEF_INVALID_BLOCK;
	fe->next_entry  = sbi->dsb.root_dir_head;
	fe->owner_uid   = from_kuid(&init_user_ns, current_fsuid());
	fe->owner_gid   = from_kgid(&init_user_ns, current_fsgid());
	fe->in_use      = 1;
	sbi->dsb.root_dir_head = slot;
	sbi->dsb.num_files++;

	ret = deadbeef_dir_add(sb, di->file_index,
			       dentry->d_name.name, slot);
	if (ret) {
		fe->in_use = 0;
		sbi->dsb.num_files--;
		up_write(&sbi->meta_rwsem);
		return ret;
	}
	deadbeef_sync_metadata(sb);
	inode_inc_link_count(dir);
	up_write(&sbi->meta_rwsem);

	inode = deadbeef_iget(sb, slot);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	d_instantiate(dentry, inode);
	return 0;
}

/* Helper: free all blocks and mark file_table entry unused */
static void deadbeef_delete_entry(struct super_block *sb, int index)
{
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_disk_file *fe = &sbi->file_table[index];
	int prev;

	deadbeef_free_chain(sb, fe->first_block);

	/* Unlink from global file list */
	if ((int)sbi->dsb.root_dir_head == index) {
		sbi->dsb.root_dir_head = fe->next_entry;
	} else {
		prev = sbi->dsb.root_dir_head;
		while (prev >= 0 && prev < DEADBEEF_MAX_FILES) {
			if (sbi->file_table[prev].next_entry == index) {
				sbi->file_table[prev].next_entry =
					fe->next_entry;
				break;
			}
			prev = sbi->file_table[prev].next_entry;
		}
	}

	fe->in_use = 0;
	sbi->dsb.num_files--;
}

static int deadbeef_unlink(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_inode_info *di_dir = DEADBEEF_I(dir);
	struct inode *inode = d_inode(dentry);
	struct deadbeef_inode_info *di = DEADBEEF_I(inode);

	down_write(&sbi->meta_rwsem);
	deadbeef_dir_remove(sb, di_dir->file_index, dentry->d_name.name);
	deadbeef_delete_entry(sb, di->file_index);
	deadbeef_sync_metadata(sb);
	up_write(&sbi->meta_rwsem);

	inode_dec_link_count(inode);
	return 0;
}

static int deadbeef_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_inode_info *di_dir = DEADBEEF_I(dir);
	struct inode *inode = d_inode(dentry);
	struct deadbeef_inode_info *di = DEADBEEF_I(inode);
	struct deadbeef_disk_file *fe = &sbi->file_table[di->file_index];

	if (fe->size > 0)
		return -ENOTEMPTY;

	down_write(&sbi->meta_rwsem);
	deadbeef_dir_remove(sb, di_dir->file_index, dentry->d_name.name);
	deadbeef_delete_entry(sb, di->file_index);
	deadbeef_sync_metadata(sb);
	inode_dec_link_count(dir);
	up_write(&sbi->meta_rwsem);

	inode_dec_link_count(inode);
	return 0;
}

/* ================================================================
 *  File operations: read_iter, write_iter
 * ================================================================ */

/* Ensure a file has enough allocated blocks for required_size bytes */
static int deadbeef_ensure_capacity(struct super_block *sb,
				    struct deadbeef_disk_file *fe,
				    u32 required_size)
{
	u32 data_per_block = DEADBEEF_BLOCK_DATA_SIZE;
	u32 count = 0, last = DEADBEEF_INVALID_BLOCK, idx;
	u64 current_cap, additional;
	u32 blocks_to_add, i;
	struct deadbeef_disk_block *blk;

	blk = kmalloc(sizeof(*blk), GFP_KERNEL);
	if (!blk)
		return -ENOMEM;

	idx = fe->first_block;
	while (idx != DEADBEEF_INVALID_BLOCK) {
		if (deadbeef_read_block(sb, idx, blk)) {
			kfree(blk);
			return -EIO;
		}
		last = idx;
		idx = blk->next_block;
		count++;
	}

	current_cap = (u64)count * data_per_block;
	if (current_cap >= required_size) {
		kfree(blk);
		return 0;
	}

	additional = required_size - current_cap;
	blocks_to_add = (u32)((additional + data_per_block - 1) / data_per_block);

	for (i = 0; i < blocks_to_add; i++) {
		u32 new_idx;
		int ret = deadbeef_alloc_block(sb, &new_idx);
		if (ret) {
			kfree(blk);
			return -ENOSPC;
		}

		if (fe->first_block == DEADBEEF_INVALID_BLOCK) {
			fe->first_block = new_idx;
		} else {
			if (deadbeef_read_block(sb, last, blk)) {
				kfree(blk);
				return -EIO;
			}
			blk->next_block = new_idx;
			deadbeef_write_block(sb, last, blk);
		}
		last = new_idx;
	}

	kfree(blk);
	return 0;
}

static ssize_t deadbeef_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct super_block *sb = inode->i_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_inode_info *di = DEADBEEF_I(inode);
	struct deadbeef_disk_file *fe = &sbi->file_table[di->file_index];
	struct deadbeef_disk_block *blk;
	loff_t pos = iocb->ki_pos;
	size_t count = iov_iter_count(to);
	u32 data_per_block = DEADBEEF_BLOCK_DATA_SIZE;
	u32 blk_in_file, off_in_blk, idx;
	size_t total = 0;
	u32 i;

	if (pos >= fe->size)
		return 0;
	if (pos + count > fe->size)
		count = fe->size - pos;
	if (count == 0)
		return 0;

	blk = kmalloc(sizeof(*blk), GFP_KERNEL);
	if (!blk)
		return -ENOMEM;

	down_read(&sbi->meta_rwsem);
	down_read(&di->data_rwsem);

	blk_in_file = (u32)pos / data_per_block;
	off_in_blk  = (u32)pos % data_per_block;
	idx = fe->first_block;

	/* Skip to the right block */
	for (i = 0; i < blk_in_file && idx != DEADBEEF_INVALID_BLOCK; i++) {
		if (deadbeef_read_block(sb, idx, blk)) {
			up_read(&di->data_rwsem);
			up_read(&sbi->meta_rwsem);
			kfree(blk);
			return -EIO;
		}
		idx = blk->next_block;
	}

	while (count > 0 && idx != DEADBEEF_INVALID_BLOCK) {
		size_t chunk, copied;
		if (deadbeef_read_block(sb, idx, blk)) {
			up_read(&di->data_rwsem);
			up_read(&sbi->meta_rwsem);
			kfree(blk);
			return total > 0 ? (ssize_t)total : -EIO;
		}
		chunk = data_per_block - off_in_blk;
		if (chunk > count)
			chunk = count;
		copied = copy_to_iter(blk->data + off_in_blk, chunk, to);
		total += copied;
		count -= copied;
		if (copied < chunk)
			break;
		off_in_blk = 0;
		idx = blk->next_block;
	}

	up_read(&di->data_rwsem);
	up_read(&sbi->meta_rwsem);
	kfree(blk);
	iocb->ki_pos += total;
	return (ssize_t)total;
}

static ssize_t deadbeef_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct super_block *sb = inode->i_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_inode_info *di = DEADBEEF_I(inode);
	struct deadbeef_disk_file *fe = &sbi->file_table[di->file_index];
	struct deadbeef_disk_block *blk;
	loff_t pos;
	size_t count = iov_iter_count(from);
	u32 data_per_block = DEADBEEF_BLOCK_DATA_SIZE;
	u32 required, blk_in_file, off_in_blk, idx;
	size_t total = 0;
	u32 i;
	int ret;

	if (count == 0)
		return 0;

	blk = kmalloc(sizeof(*blk), GFP_KERNEL);
	if (!blk)
		return -ENOMEM;

	down_write(&sbi->meta_rwsem);
	down_write(&di->data_rwsem);

	/* Handle O_APPEND */
	if (iocb->ki_filp->f_flags & O_APPEND)
		iocb->ki_pos = fe->size;
	pos = iocb->ki_pos;

	required = (u32)(pos + count);
	ret = deadbeef_ensure_capacity(sb, fe, required);
	if (ret) {
		up_write(&di->data_rwsem);
		up_write(&sbi->meta_rwsem);
		kfree(blk);
		return ret;
	}

	blk_in_file = (u32)pos / data_per_block;
	off_in_blk  = (u32)pos % data_per_block;
	idx = fe->first_block;

	for (i = 0; i < blk_in_file && idx != DEADBEEF_INVALID_BLOCK; i++) {
		if (deadbeef_read_block(sb, idx, blk)) {
			up_write(&di->data_rwsem);
			up_write(&sbi->meta_rwsem);
			kfree(blk);
			return -EIO;
		}
		idx = blk->next_block;
	}

	while (count > 0 && idx != DEADBEEF_INVALID_BLOCK) {
		size_t chunk, copied;
		if (deadbeef_read_block(sb, idx, blk)) {
			up_write(&di->data_rwsem);
			up_write(&sbi->meta_rwsem);
			kfree(blk);
			return total > 0 ? (ssize_t)total : -EIO;
		}
		chunk = data_per_block - off_in_blk;
		if (chunk > count)
			chunk = count;
		copied = copy_from_iter(blk->data + off_in_blk, chunk, from);
		if (copied > 0)
			deadbeef_write_block(sb, idx, blk);
		total += copied;
		count -= copied;
		if (copied < chunk)
			break;
		off_in_blk = 0;
		idx = blk->next_block;
	}

	if ((u32)(pos + total) > fe->size)
		fe->size = (u32)(pos + total);
	inode->i_size = fe->size;
	deadbeef_sync_metadata(sb);

	up_write(&di->data_rwsem);
	up_write(&sbi->meta_rwsem);
	kfree(blk);
	iocb->ki_pos += total;
	return (ssize_t)total;
}

/* ================================================================
 *  Directory file operations: iterate_shared (readdir / ls)
 * ================================================================ */

static int deadbeef_iterate(struct file *filp, struct dir_context *ctx)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_inode_info *di = DEADBEEF_I(inode);
	struct deadbeef_disk_file *dir_fe = &sbi->file_table[di->file_index];
	struct deadbeef_disk_block *blk;
	u32 blk_idx;
	u32 slot = 0;

	/* Emit . and .. */
	if (!dir_emit_dots(filp, ctx))
		return 0;

	blk = kmalloc(sizeof(*blk), GFP_KERNEL);
	if (!blk)
		return -ENOMEM;

	down_read(&sbi->meta_rwsem);
	down_read(&di->data_rwsem);
	blk_idx = dir_fe->first_block;

	while (blk_idx != DEADBEEF_INVALID_BLOCK) {
		struct deadbeef_disk_dirent *de;
		u32 i;

		if (deadbeef_read_block(sb, blk_idx, blk))
			break;
		de = (struct deadbeef_disk_dirent *)blk->data;

		for (i = 0; i < DEADBEEF_DIRENTS_PER_BLOCK; i++, slot++) {
			int fidx;
			unsigned char dtype;

			if (de[i].file_index == DEADBEEF_INVALID_ENTRY)
				continue;

			/* Skip entries already past ctx->pos */
			if (slot + 2 < ctx->pos)
				continue;

			fidx = de[i].file_index;
			dtype = DT_UNKNOWN;
			if (fidx >= 0 && fidx < DEADBEEF_MAX_FILES &&
			    sbi->file_table[fidx].in_use) {
				dtype = (sbi->file_table[fidx].type ==
					 DEADBEEF_TYPE_DIRECTORY)
					? DT_DIR : DT_REG;
			}

			if (!dir_emit(ctx, de[i].name,
				      strnlen(de[i].name,
					      DEADBEEF_FILENAME_MAX),
				      deadbeef_ino(fidx), dtype)) {
				up_read(&di->data_rwsem);
				up_read(&sbi->meta_rwsem);
				kfree(blk);
				return 0;
			}
			ctx->pos = slot + 3;
		}
		blk_idx = blk->next_block;
	}

	up_read(&di->data_rwsem);
	up_read(&sbi->meta_rwsem);
	kfree(blk);
	return 0;
}

/* ================================================================
 *  setattr — persist chmod / chown / truncate to disk
 * ================================================================ */

/* Truncate a file to new_size.  Caller holds meta_rwsem exclusive. */
static int deadbeef_truncate(struct super_block *sb,
			     struct deadbeef_disk_file *fe,
			     u32 new_size)
{
	u32 data_per_block = DEADBEEF_BLOCK_DATA_SIZE;

	if (new_size > fe->size) {
		/* Growing — allocate more blocks and zero-fill */
		int ret = deadbeef_ensure_capacity(sb, fe, new_size);
		if (ret)
			return ret;
	} else if (new_size == 0) {
		/* Truncate to zero — free all blocks */
		deadbeef_free_chain(sb, fe->first_block);
		fe->first_block = DEADBEEF_INVALID_BLOCK;
	} else {
		/* Shrinking — keep only the needed blocks, free the rest */
		u32 keep_blocks = (new_size + data_per_block - 1) / data_per_block;
		u32 blk_idx = fe->first_block, prev = DEADBEEF_INVALID_BLOCK;
		u32 i;
		struct deadbeef_disk_block *blk;

		blk = kmalloc(sizeof(*blk), GFP_KERNEL);
		if (!blk)
			return -ENOMEM;

		for (i = 0; i < keep_blocks; i++) {
			if (blk_idx == DEADBEEF_INVALID_BLOCK)
				break;
			if (deadbeef_read_block(sb, blk_idx, blk)) {
				kfree(blk);
				return -EIO;
			}
			prev = blk_idx;
			blk_idx = blk->next_block;
		}

		/* Sever the chain after the last kept block */
		if (prev != DEADBEEF_INVALID_BLOCK) {
			if (deadbeef_read_block(sb, prev, blk)) {
				kfree(blk);
				return -EIO;
			}
			blk->next_block = DEADBEEF_INVALID_BLOCK;
			deadbeef_write_block(sb, prev, blk);
		}

		/* Free everything after */
		deadbeef_free_chain(sb, blk_idx);
		kfree(blk);
	}

	fe->size = new_size;
	return 0;
}

static int deadbeef_setattr(struct mnt_idmap *idmap, struct dentry *dentry,
			    struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	struct super_block *sb = inode->i_sb;
	struct deadbeef_sb_info *sbi = DEADBEEF_SB(sb);
	struct deadbeef_inode_info *di = DEADBEEF_I(inode);
	struct deadbeef_disk_file *fe;
	int ret;

	ret = setattr_prepare(idmap, dentry, attr);
	if (ret)
		return ret;

	down_write(&sbi->meta_rwsem);
	fe = &sbi->file_table[di->file_index];

	if (attr->ia_valid & ATTR_SIZE) {
		down_write(&di->data_rwsem);
		ret = deadbeef_truncate(sb, fe, (u32)attr->ia_size);
		if (ret) {
			up_write(&di->data_rwsem);
			up_write(&sbi->meta_rwsem);
			return ret;
		}
		i_size_write(inode, fe->size);
		up_write(&di->data_rwsem);
	}

	if (attr->ia_valid & ATTR_MODE) {
		fe->permissions = attr->ia_mode & 0777;
		inode->i_mode = (inode->i_mode & S_IFMT) | fe->permissions;
	}

	if (attr->ia_valid & ATTR_UID) {
		fe->owner_uid = from_kuid(&init_user_ns, attr->ia_uid);
		i_uid_write(inode, fe->owner_uid);
	}

	if (attr->ia_valid & ATTR_GID) {
		fe->owner_gid = from_kgid(&init_user_ns, attr->ia_gid);
		i_gid_write(inode, fe->owner_gid);
	}

	deadbeef_sync_metadata(sb);
	up_write(&sbi->meta_rwsem);

	setattr_copy(idmap, inode, attr);
	return 0;
}

/* ================================================================
 *  Operation tables
 * ================================================================ */

static const struct inode_operations deadbeef_dir_iops = {
	.lookup  = deadbeef_lookup,
	.create  = deadbeef_create,
	.mkdir   = deadbeef_mkdir,
	.unlink  = deadbeef_unlink,
	.rmdir   = deadbeef_rmdir,
	.setattr = deadbeef_setattr,
	.getattr = simple_getattr,
};

static const struct inode_operations deadbeef_file_iops = {
	.setattr = deadbeef_setattr,
	.getattr = simple_getattr,
};

static const struct file_operations deadbeef_dir_fops = {
	.owner          = THIS_MODULE,
	.llseek         = generic_file_llseek,
	.read           = generic_read_dir,
	.iterate_shared = deadbeef_iterate,
};

static const struct file_operations deadbeef_file_fops = {
	.owner      = THIS_MODULE,
	.llseek     = generic_file_llseek,
	.read_iter  = deadbeef_read_iter,
	.write_iter = deadbeef_write_iter,
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
	init_rwsem(&sbi->meta_rwsem);
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
