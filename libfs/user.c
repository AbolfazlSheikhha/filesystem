#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "user.h"
#include "fs_state.h"
#include "disk_io.h"
#include "../common/fs_config.h"

// ------------ Lookup Functions ------------

int fs_find_user_by_name(const char *username) {
    for (int i = 0; i < FS_MAX_USERS; ++i) {
        if (user_table[i].in_use && strncmp(user_table[i].username, username, FS_USERNAME_MAX) == 0) {
            return i;
        }
    }
    return -1;
}

int fs_find_user_by_uid(uint32_t uid) {
    for (int i = 0; i < FS_MAX_USERS; ++i) {
        if (user_table[i].in_use && user_table[i].uid == uid) {
            return i;
        }
    }
    return -1;
}

int fs_find_group_by_name(const char *groupname) {
    for (int i = 0; i < FS_MAX_GROUPS; ++i) {
        if (group_table[i].in_use && strncmp(group_table[i].groupname, groupname, FS_GROUPNAME_MAX) == 0) {
            return i;
        }
    }
    return -1;
}

int fs_find_group_by_gid(uint32_t gid) {
    for (int i = 0; i < FS_MAX_GROUPS; ++i) {
        if (group_table[i].in_use && group_table[i].gid == gid) {
            return i;
        }
    }
    return -1;
}

const char* fs_get_username(uint32_t uid) {
    int idx = fs_find_user_by_uid(uid);
    if (idx >= 0) return user_table[idx].username;
    return "unknown";
}

const char* fs_get_groupname(uint32_t gid) {
    int idx = fs_find_group_by_gid(gid);
    if (idx >= 0) return group_table[idx].groupname;
    return "unknown";
}

int fs_user_in_group(uint32_t uid, uint32_t gid) {
    int user_idx = fs_find_user_by_uid(uid);
    if (user_idx < 0) return 0;

    UserEntry *user = &user_table[user_idx];

    // Check primary group
    if (user->primary_gid == gid) return 1;

    // Check secondary groups
    for (int i = 0; i < user->num_secondary_groups; ++i) {
        if (user->secondary_gids[i] == gid) return 1;
    }
    return 0;
}

// ------------ Permission Checking ------------

int can_read_file(FileEntry *fe) {
    if (current_uid == ROOT_UID) return 1;

    if (fe->owner_uid == current_uid) {
        return (fe->permissions & PERM_OWNER_READ) != 0;
    }

    if (fs_user_in_group(current_uid, fe->owner_gid)) {
        return (fe->permissions & PERM_GROUP_READ) != 0;
    }

    return (fe->permissions & PERM_OTHER_READ) != 0;
}

int can_write_file(FileEntry *fe) {
    if (current_uid == ROOT_UID) return 1;

    if (fe->owner_uid == current_uid) {
        return (fe->permissions & PERM_OWNER_WRITE) != 0;
    }

    if (fs_user_in_group(current_uid, fe->owner_gid)) {
        return (fe->permissions & PERM_GROUP_WRITE) != 0;
    }

    return (fe->permissions & PERM_OTHER_WRITE) != 0;
}

uint32_t parse_mode(const char *mode_str) {
    return (uint32_t)strtoul(mode_str, NULL, 8);
}

void format_permissions(uint32_t perm, char *buf) {
    buf[0] = (perm & PERM_OWNER_READ)  ? 'r' : '-';
    buf[1] = (perm & PERM_OWNER_WRITE) ? 'w' : '-';
    buf[2] = (perm & PERM_OWNER_EXEC)  ? 'x' : '-';
    buf[3] = (perm & PERM_GROUP_READ)  ? 'r' : '-';
    buf[4] = (perm & PERM_GROUP_WRITE) ? 'w' : '-';
    buf[5] = (perm & PERM_GROUP_EXEC)  ? 'x' : '-';
    buf[6] = (perm & PERM_OTHER_READ)  ? 'r' : '-';
    buf[7] = (perm & PERM_OTHER_WRITE) ? 'w' : '-';
    buf[8] = (perm & PERM_OTHER_EXEC)  ? 'x' : '-';
    buf[9] = '\0';
}

// ------------ User Management Commands ------------

int cmd_useradd(const char *username) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can add users.\n");
        return -1;
    }

    if (fs_find_user_by_name(username) >= 0) {
        fprintf(stderr, "User '%s' already exists.\n", username);
        return -1;
    }

    // Find free slot
    int slot = -1;
    for (int i = 0; i < FS_MAX_USERS; ++i) {
        if (!user_table[i].in_use) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        fprintf(stderr, "Maximum number of users reached.\n");
        return -1;
    }

    // Create a group with same name as user
    int group_idx = fs_find_group_by_name(username);
    uint32_t new_gid;

    if (group_idx < 0) {
        // Create new group for user
        int gslot = -1;
        for (int i = 0; i < FS_MAX_GROUPS; ++i) {
            if (!group_table[i].in_use) {
                gslot = i;
                break;
            }
        }

        if (gslot < 0) {
            fprintf(stderr, "Maximum number of groups reached.\n");
            return -1;
        }

        new_gid = sb.next_gid++;
        strncpy(group_table[gslot].groupname, username, FS_GROUPNAME_MAX - 1);
        group_table[gslot].groupname[FS_GROUPNAME_MAX - 1] = '\0';
        group_table[gslot].gid = new_gid;
        group_table[gslot].in_use = 1;
        sb.num_groups++;
    } else {
        new_gid = group_table[group_idx].gid;
    }

    // Create user
    UserEntry *user = &user_table[slot];
    memset(user, 0, sizeof(*user));
    strncpy(user->username, username, FS_USERNAME_MAX - 1);
    user->username[FS_USERNAME_MAX - 1] = '\0';
    user->uid = sb.next_uid++;
    user->primary_gid = new_gid;
    user->num_secondary_groups = 0;
    user->in_use = 1;
    sb.num_users++;

    fs_sync_metadata();
    printf("User '%s' created with UID %u, GID %u.\n", username, user->uid, user->primary_gid);
    return 0;
}

int cmd_userdel(const char *username) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can delete users.\n");
        return -1;
    }

    if (strcmp(username, "root") == 0) {
        fprintf(stderr, "Cannot delete root user.\n");
        return -1;
    }

    int idx = fs_find_user_by_name(username);
    if (idx < 0) {
        fprintf(stderr, "User '%s' not found.\n", username);
        return -1;
    }

    user_table[idx].in_use = 0;
    sb.num_users--;
    fs_sync_metadata();

    printf("User '%s' deleted.\n", username);
    return 0;
}

int cmd_groupadd(const char *groupname) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can add groups.\n");
        return -1;
    }

    if (fs_find_group_by_name(groupname) >= 0) {
        fprintf(stderr, "Group '%s' already exists.\n", groupname);
        return -1;
    }

    int slot = -1;
    for (int i = 0; i < FS_MAX_GROUPS; ++i) {
        if (!group_table[i].in_use) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        fprintf(stderr, "Maximum number of groups reached.\n");
        return -1;
    }

    GroupEntry *group = &group_table[slot];
    strncpy(group->groupname, groupname, FS_GROUPNAME_MAX - 1);
    group->groupname[FS_GROUPNAME_MAX - 1] = '\0';
    group->gid = sb.next_gid++;
    group->in_use = 1;
    sb.num_groups++;

    fs_sync_metadata();
    printf("Group '%s' created with GID %u.\n", groupname, group->gid);
    return 0;
}

int cmd_groupdel(const char *groupname) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can delete groups.\n");
        return -1;
    }

    if (strcmp(groupname, "root") == 0) {
        fprintf(stderr, "Cannot delete root group.\n");
        return -1;
    }

    int idx = fs_find_group_by_name(groupname);
    if (idx < 0) {
        fprintf(stderr, "Group '%s' not found.\n", groupname);
        return -1;
    }

    group_table[idx].in_use = 0;
    sb.num_groups--;
    fs_sync_metadata();

    printf("Group '%s' deleted.\n", groupname);
    return 0;
}

int cmd_usermod_aG(const char *groupname, const char *username) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can modify users.\n");
        return -1;
    }

    int user_idx = fs_find_user_by_name(username);
    if (user_idx < 0) {
        fprintf(stderr, "User '%s' not found.\n", username);
        return -1;
    }

    int group_idx = fs_find_group_by_name(groupname);
    if (group_idx < 0) {
        fprintf(stderr, "Group '%s' not found.\n", groupname);
        return -1;
    }

    UserEntry *user = &user_table[user_idx];
    uint32_t gid = group_table[group_idx].gid;

    // Check if already member
    if (fs_user_in_group(user->uid, gid)) {
        printf("User '%s' is already a member of group '%s'.\n", username, groupname);
        return 0;
    }

    if (user->num_secondary_groups >= FS_MAX_GROUPS_PER_USER) {
        fprintf(stderr, "User is already member of maximum number of groups.\n");
        return -1;
    }

    user->secondary_gids[user->num_secondary_groups++] = gid;
    fs_sync_metadata();

    printf("User '%s' added to group '%s'.\n", username, groupname);
    return 0;
}

int cmd_su(const char *username) {
    int idx = fs_find_user_by_name(username);
    if (idx < 0) {
        fprintf(stderr, "User '%s' not found.\n", username);
        return -1;
    }

    current_uid = user_table[idx].uid;
    current_gid = user_table[idx].primary_gid;

    printf("Switched to user '%s' (UID: %u, GID: %u).\n", username, current_uid, current_gid);
    return 0;
}

void cmd_whoami(void) {
    printf("%s\n", fs_get_username(current_uid));
}

void cmd_list_users(void) {
    printf("Users:\n");
    printf("  %-20s %-8s %-8s\n", "Username", "UID", "GID");
    printf("  %-20s %-8s %-8s\n", "--------", "---", "---");
    for (int i = 0; i < FS_MAX_USERS; ++i) {
        if (user_table[i].in_use) {
            printf("  %-20s %-8u %-8u\n", user_table[i].username,
                   user_table[i].uid, user_table[i].primary_gid);
        }
    }
}

void cmd_list_groups(void) {
    printf("Groups:\n");
    printf("  %-20s %-8s\n", "Groupname", "GID");
    printf("  %-20s %-8s\n", "---------", "---");
    for (int i = 0; i < FS_MAX_GROUPS; ++i) {
        if (group_table[i].in_use) {
            printf("  %-20s %-8u\n", group_table[i].groupname, group_table[i].gid);
        }
    }
}

// ------------ Permission Management Commands ------------

int cmd_chmod(const char *mode_str, const char *path) {
    // Find file by name (flat lookup for now)
    int idx = -1;
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (file_table[i].in_use && strncmp(file_table[i].name, path, FS_FILENAME_MAX) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        fprintf(stderr, "File '%s' not found.\n", path);
        return -1;
    }

    FileEntry *fe = &file_table[idx];

    // Only owner or root can chmod
    if (current_uid != ROOT_UID && current_uid != fe->owner_uid) {
        fprintf(stderr, "Permission denied: Only owner or root can change permissions.\n");
        return -1;
    }

    uint32_t new_mode = parse_mode(mode_str);
    fe->permissions = new_mode;
    fs_sync_metadata();

    char perm_str[10];
    format_permissions(new_mode, perm_str);
    printf("Permissions of '%s' changed to %s (%03o).\n", path, perm_str, new_mode);
    return 0;
}

int cmd_chown(const char *owner_spec, const char *path) {
    if (current_uid != ROOT_UID) {
        fprintf(stderr, "Permission denied: Only root can change ownership.\n");
        return -1;
    }

    int idx = -1;
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (file_table[i].in_use && strncmp(file_table[i].name, path, FS_FILENAME_MAX) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        fprintf(stderr, "File '%s' not found.\n", path);
        return -1;
    }

    FileEntry *fe = &file_table[idx];

    // Parse user:group
    char user_part[FS_USERNAME_MAX] = {0};
    char group_part[FS_GROUPNAME_MAX] = {0};

    const char *colon = strchr(owner_spec, ':');
    if (colon) {
        size_t user_len = colon - owner_spec;
        if (user_len > 0 && user_len < FS_USERNAME_MAX) {
            strncpy(user_part, owner_spec, user_len);
        }
        strncpy(group_part, colon + 1, FS_GROUPNAME_MAX - 1);
    } else {
        strncpy(user_part, owner_spec, FS_USERNAME_MAX - 1);
    }

    // Change user if specified
    if (strlen(user_part) > 0) {
        int user_idx = fs_find_user_by_name(user_part);
        if (user_idx < 0) {
            fprintf(stderr, "User '%s' not found.\n", user_part);
            return -1;
        }
        fe->owner_uid = user_table[user_idx].uid;
    }

    // Change group if specified
    if (strlen(group_part) > 0) {
        int group_idx = fs_find_group_by_name(group_part);
        if (group_idx < 0) {
            fprintf(stderr, "Group '%s' not found.\n", group_part);
            return -1;
        }
        fe->owner_gid = group_table[group_idx].gid;
    }

    fs_sync_metadata();
    printf("Ownership of '%s' changed to %s:%s.\n", path,
           fs_get_username(fe->owner_uid), fs_get_groupname(fe->owner_gid));
    return 0;
}

int cmd_chgrp(const char *groupname, const char *path) {
    int idx = -1;
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (file_table[i].in_use && strncmp(file_table[i].name, path, FS_FILENAME_MAX) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        fprintf(stderr, "File '%s' not found.\n", path);
        return -1;
    }

    FileEntry *fe = &file_table[idx];

    // Only owner or root can chgrp (and owner must be member of new group)
    if (current_uid != ROOT_UID && current_uid != fe->owner_uid) {
        fprintf(stderr, "Permission denied: Only owner or root can change group.\n");
        return -1;
    }

    int group_idx = fs_find_group_by_name(groupname);
    if (group_idx < 0) {
        fprintf(stderr, "Group '%s' not found.\n", groupname);
        return -1;
    }

    uint32_t new_gid = group_table[group_idx].gid;

    // Non-root owner must be member of new group
    if (current_uid != ROOT_UID && !fs_user_in_group(current_uid, new_gid)) {
        fprintf(stderr, "Permission denied: You must be a member of '%s'.\n", groupname);
        return -1;
    }

    fe->owner_gid = new_gid;
    fs_sync_metadata();

    printf("Group of '%s' changed to '%s'.\n", path, groupname);
    return 0;
}

int cmd_getfacl(const char *path) {
    int idx = -1;
    for (int i = 0; i < FS_MAX_FILES; ++i) {
        if (file_table[i].in_use && strncmp(file_table[i].name, path, FS_FILENAME_MAX) == 0) {
            idx = i;
            break;
        }
    }
    if (idx < 0) {
        fprintf(stderr, "File '%s' not found.\n", path);
        return -1;
    }

    FileEntry *fe = &file_table[idx];

    printf("# file: %s\n", fe->name);
    printf("# owner: %s\n", fs_get_username(fe->owner_uid));
    printf("# group: %s\n", fs_get_groupname(fe->owner_gid));
    printf("user::%c%c%c\n",
           (fe->permissions & PERM_OWNER_READ) ? 'r' : '-',
           (fe->permissions & PERM_OWNER_WRITE) ? 'w' : '-',
           (fe->permissions & PERM_OWNER_EXEC) ? 'x' : '-');
    printf("group::%c%c%c\n",
           (fe->permissions & PERM_GROUP_READ) ? 'r' : '-',
           (fe->permissions & PERM_GROUP_WRITE) ? 'w' : '-',
           (fe->permissions & PERM_GROUP_EXEC) ? 'x' : '-');
    printf("other::%c%c%c\n",
           (fe->permissions & PERM_OTHER_READ) ? 'r' : '-',
           (fe->permissions & PERM_OTHER_WRITE) ? 'w' : '-',
           (fe->permissions & PERM_OTHER_EXEC) ? 'x' : '-');

    return 0;
}
