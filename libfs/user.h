#ifndef USER_H
#define USER_H

#include <stdint.h>
#include "../common/fs_types.h"

// Lookup functions
int fs_find_user_by_name(const char *username);
int fs_find_user_by_uid(uint32_t uid);
int fs_find_group_by_name(const char *groupname);
int fs_find_group_by_gid(uint32_t gid);
const char* fs_get_username(uint32_t uid);
const char* fs_get_groupname(uint32_t gid);
int fs_user_in_group(uint32_t uid, uint32_t gid);

// Permission checking
int can_read_file(FileEntry *fe);
int can_write_file(FileEntry *fe);
uint32_t parse_mode(const char *mode_str);
void format_permissions(uint32_t perm, char *buf);

// User/group management commands
int  cmd_useradd(const char *username);
int  cmd_userdel(const char *username);
int  cmd_groupadd(const char *groupname);
int  cmd_groupdel(const char *groupname);
int  cmd_usermod_aG(const char *groupname, const char *username);
int  cmd_su(const char *username);
void cmd_whoami(void);
void cmd_list_users(void);
void cmd_list_groups(void);

// Permission management commands
int cmd_chmod(const char *mode_str, const char *path);
int cmd_chown(const char *owner_spec, const char *path);
int cmd_chgrp(const char *groupname, const char *path);
int cmd_getfacl(const char *path);

#endif /* USER_H */
