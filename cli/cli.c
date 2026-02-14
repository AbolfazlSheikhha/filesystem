#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "../common/fs_config.h"
#include "../common/fs_types.h"
#include "../libfs/fs_state.h"
#include "../libfs/disk_io.h"
#include "../libfs/file_ops.h"
#include "../libfs/user.h"
#include "../libfs/viz.h"
#include "../libfs/dir.h"

// ------------ Stress Test Function ------------

static void stressTest(void) {
    printf("\n========================================\n");
    printf("       STRESS TEST STARTING\n");
    printf("========================================\n");
    printf("Configuration:\n");
    printf("  Files to create: %d\n", STRESS_NUM_FILES);
    printf("  Operations: %d\n", STRESS_NUM_OPS);
    printf("  Max write size: %d bytes\n", STRESS_MAX_WRITE_SIZE);
    printf("========================================\n\n");

    srand((unsigned int)time(NULL));

    // Track wall-clock timing using timespec
    struct timespec start_ts, end_ts;
    clock_gettime(CLOCK_MONOTONIC, &start_ts);

    // Statistics
    uint32_t creates = 0, deletes = 0, writes = 0, reads = 0, shrinks = 0;
    uint32_t failed_ops = 0;
    uint64_t bytes_written = 0, bytes_read = 0;

    // Track which files exist (by index 0 to STRESS_NUM_FILES-1)
    int *file_exists = calloc(STRESS_NUM_FILES, sizeof(int));
    uint32_t *file_sizes = calloc(STRESS_NUM_FILES, sizeof(uint32_t));
    if (!file_exists || !file_sizes) {
        fprintf(stderr, "Failed to allocate tracking arrays\n");
        return;
    }
    int num_existing_files = 0;

    // Pre-generate file names
    char (*filenames)[32] = malloc(STRESS_NUM_FILES * 32);
    if (!filenames) {
        fprintf(stderr, "Failed to allocate filenames\n");
        free(file_exists);
        free(file_sizes);
        return;
    }
    for (int i = 0; i < STRESS_NUM_FILES; i++) {
        snprintf(filenames[i], 32, "stress_file_%04d", i);
    }

    // Buffer for write/read operations
    uint8_t *buffer = malloc(STRESS_MAX_WRITE_SIZE + 1);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate buffer\n");
        free(file_exists);
        free(file_sizes);
        free(filenames);
        return;
    }

    // Fill buffer with random data pattern
    for (int i = 0; i < STRESS_MAX_WRITE_SIZE; i++) {
        buffer[i] = (uint8_t)('A' + (i % 26));
    }

    // ============ PHASE 1: Create all files first ============
    printf("Phase 1: Creating %d files...\n", STRESS_NUM_FILES);
    int create_progress = STRESS_NUM_FILES / 10;
    for (int i = 0; i < STRESS_NUM_FILES; i++) {
        if (create_progress > 0 && i % create_progress == 0) {
            printf("  Creating files: %d%% (%d/%d)\n",
                   (i * 100) / STRESS_NUM_FILES, i, STRESS_NUM_FILES);
        }
        if (my_open(filenames[i], FLAG_CREATE | FLAG_WRITE) == 0) {
            file_exists[i] = 1;
            file_sizes[i] = 0;
            num_existing_files++;
            creates++;
            my_close();
        } else {
            fprintf(stderr, "Failed to create file %s\n", filenames[i]);
        }
    }
    printf("  Created %d files.\n\n", creates);

    // ============ PHASE 2: Run random operations ============
    printf("Phase 2: Running %d random operations...\n", STRESS_NUM_OPS);

    int progress_interval = STRESS_NUM_OPS / 10;

    for (int op = 0; op < STRESS_NUM_OPS; op++) {
        // Progress indicator
        if (progress_interval > 0 && op % progress_interval == 0) {
            printf("  Progress: %d%% (%d/%d ops)\n",
                   (op * 100) / STRESS_NUM_OPS, op, STRESS_NUM_OPS);
        }

        // Choose random operation: 25% read, 30% write, 20% shrink, 15% delete, 10% create
        int operation = rand() % 100;

        if (operation < 10) {
            // CREATE: 10% chance - create a new file (if slot available)
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }

            if (!file_exists[file_idx]) {
                if (my_open(filenames[file_idx], FLAG_CREATE | FLAG_WRITE) == 0) {
                    file_exists[file_idx] = 1;
                    file_sizes[file_idx] = 0;
                    num_existing_files++;
                    creates++;
                    my_close();
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++; // All slots taken
            }
        }
        else if (operation < 25 && num_existing_files > 1) {
            // DELETE: 15% chance (keep at least 1 file)
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (!file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }

            if (file_exists[file_idx]) {
                if (my_open(filenames[file_idx], FLAG_WRITE) == 0) {
                    if (my_rm() == 0) {
                        file_exists[file_idx] = 0;
                        file_sizes[file_idx] = 0;
                        num_existing_files--;
                        deletes++;
                    } else {
                        my_close();
                        failed_ops++;
                    }
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++;
            }
        }
        else if (operation < 55) {
            // WRITE: 30% chance
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (!file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }

            if (file_exists[file_idx]) {
                if (my_open(filenames[file_idx], FLAG_WRITE) == 0) {
                    uint32_t wpos = rand() % (file_sizes[file_idx] + 1);
                    uint32_t wlen = (rand() % STRESS_MAX_WRITE_SIZE) + 1;

                    ssize_t written = my_write(wpos, buffer, wlen);
                    if (written > 0) {
                        writes++;
                        bytes_written += written;
                        if (wpos + (uint32_t)written > file_sizes[file_idx]) {
                            file_sizes[file_idx] = wpos + (uint32_t)written;
                        }
                    } else {
                        failed_ops++;
                    }
                    my_close();
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++;
            }
        }
        else if (operation < 80) {
            // READ: 25% chance
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (!file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }

            if (file_exists[file_idx] && file_sizes[file_idx] > 0) {
                if (my_open(filenames[file_idx], 0) == 0) {
                    uint32_t rpos = rand() % file_sizes[file_idx];
                    uint32_t rlen = (rand() % STRESS_MAX_WRITE_SIZE) + 1;

                    uint8_t *read_buf = malloc(rlen);
                    if (read_buf) {
                        ssize_t r = my_read(rpos, rlen, read_buf);
                        if (r > 0) {
                            reads++;
                            bytes_read += r;
                        } else {
                            failed_ops++;
                        }
                        free(read_buf);
                    } else {
                        failed_ops++;
                    }
                    my_close();
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++;
            }
        }
        else {
            // SHRINK: 20% chance
            int file_idx = rand() % STRESS_NUM_FILES;
            int attempts = 0;
            while (!file_exists[file_idx] && attempts < STRESS_NUM_FILES) {
                file_idx = (file_idx + 1) % STRESS_NUM_FILES;
                attempts++;
            }

            if (file_exists[file_idx] && file_sizes[file_idx] > 0) {
                if (my_open(filenames[file_idx], FLAG_WRITE) == 0) {
                    uint32_t new_size = rand() % file_sizes[file_idx];
                    if (my_shrink(new_size) == 0) {
                        file_sizes[file_idx] = new_size;
                        shrinks++;
                    } else {
                        failed_ops++;
                    }
                    my_close();
                } else {
                    failed_ops++;
                }
            } else {
                failed_ops++;
            }
        }
    }

    // ============ PHASE 3: Cleanup ============
    printf("\nPhase 3: Cleaning up test files...\n");
    for (int i = 0; i < STRESS_NUM_FILES; i++) {
        if (file_exists[i]) {
            if (my_open(filenames[i], FLAG_WRITE) == 0) {
                my_rm();
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end_ts);
    double elapsed = (end_ts.tv_sec - start_ts.tv_sec) +
                     (end_ts.tv_nsec - start_ts.tv_nsec) / 1e9;

    free(buffer);
    free(file_exists);
    free(file_sizes);
    free(filenames);

    uint32_t total_successful = creates + deletes + writes + reads + shrinks;

    printf("\n========================================\n");
    printf("       STRESS TEST COMPLETE\n");
    printf("========================================\n");
    printf("Results:\n");
    printf("  Wall-clock time: %.2f seconds\n", elapsed);
    printf("  Successful ops/sec: %.0f\n", total_successful / elapsed);
    printf("\nPhase 1 - Initial file creation:\n");
    printf("  Files created: %d\n", STRESS_NUM_FILES);
    printf("\nPhase 2 - Random operations breakdown:\n");
    printf("  Creates: %u\n", creates - STRESS_NUM_FILES);
    printf("  Deletes: %u\n", deletes);
    printf("  Writes:  %u (%.2f MB written)\n", writes, bytes_written / (1024.0 * 1024.0));
    printf("  Reads:   %u (%.2f MB read)\n", reads, bytes_read / (1024.0 * 1024.0));
    printf("  Shrinks: %u\n", shrinks);
    printf("  -----------------------\n");
    printf("  Total phase 2 ops: %u (successful) + %u (failed) = %u\n",
           total_successful - STRESS_NUM_FILES, failed_ops,
           total_successful - STRESS_NUM_FILES + failed_ops);
    printf("========================================\n\n");
}

// ------------ Help & Main ------------

static void print_help(void) {
    printf("\n=== File Management System Commands ===\n\n");

    printf("File Operations:\n");
    printf("  open <path> <flags>   - flags bitmask: 1=CREATE, 2=WRITE\n");
    printf("  read <pos> <n>        - read n bytes from current file starting at pos\n");
    printf("  write <pos> <text>    - write the given text starting at pos\n");
    printf("  shrink <new_size>     - truncate current file to new_size bytes\n");
    printf("  get_file_stats        - print size of current file\n");
    printf("  rm                    - delete current file (must be open)\n");
    printf("  cp <src> <dst>        - copy a file\n");
    printf("  mv <src> <dst>        - move/rename a file or directory\n");
    printf("  close                 - close current file\n");
    printf("  ls [path]             - list directory contents (default: cwd)\n");
    printf("  mkdir <path>          - create a directory (e.g. /sub/dir)\n");
    printf("  cd [path]             - change directory (no arg = root)\n");
    printf("  pwd                   - print working directory\n\n");

    printf("User Management:\n");
    printf("  useradd <username>    - create a new user\n");
    printf("  userdel <username>    - delete a user\n");
    printf("  usermod -aG <group> <user> - add user to group\n");
    printf("  users                 - list all users\n");
    printf("  su <username>         - switch to user\n");
    printf("  whoami                - show current user\n\n");

    printf("Group Management:\n");
    printf("  groupadd <groupname>  - create a new group\n");
    printf("  groupdel <groupname>  - delete a group\n");
    printf("  groups                - list all groups\n\n");

    printf("Permission Management:\n");
    printf("  chmod <mode> <path>   - change file permissions (octal mode, e.g., 755)\n");
    printf("  chown <user>:<group> <path> - change file owner and group\n");
    printf("  chgrp <group> <path>  - change file group\n");
    printf("  getfacl <path>        - show file permissions and ownership\n\n");

    printf("Filesystem:\n");
    printf("  get_fs_stats          - show filesystem statistics\n");
    printf("  viz                   - visualize free space linked list\n");
    printf("  stressTest            - run performance stress test\n");
    printf("  help                  - show this help\n");
    printf("  exit                  - quit the program\n\n");
}

int main(void) {
    fs_open_disk();
    printf("Simple user-space filesystem demo. Backing file: %s\n", FS_DISK_FILE);
    printf("Logged in as: %s (UID: %u)\n", fs_get_username(current_uid), current_uid);
    print_help();

    char line[512];
    while (1) {
        printf("%s@fs:%s> ", fs_get_username(current_uid), cwd_path);
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin)) break;

        line[strcspn(line, "\n")] = '\0';
        char *cmd = strtok(line, " \t");
        if (!cmd) continue;

        if (strcmp(cmd, "open") == 0) {
            char *name = strtok(NULL, " \t");
            char *flags_str = strtok(NULL, " \t");
            if (!name || !flags_str) {
                printf("Usage: open <path> <flags>\n");
                continue;
            }
            uint32_t flags = (uint32_t)strtoul(flags_str, NULL, 0);
            my_open(name, flags);
        } else if (strcmp(cmd, "read") == 0) {
            char *pos_str = strtok(NULL, " \t");
            char *n_str = strtok(NULL, " \t");
            if (!pos_str || !n_str) {
                printf("Usage: read <pos> <n_bytes>\n");
                continue;
            }
            uint32_t pos = (uint32_t)strtoul(pos_str, NULL, 0);
            uint32_t n = (uint32_t)strtoul(n_str, NULL, 0);
            uint8_t *buf = malloc(n + 1);
            if (!buf) die("malloc read buffer");
            ssize_t r = my_read(pos, n, buf);
            if (r >= 0) {
                buf[r] = '\0';
                printf("Read %zd bytes: '%s'\n", r, buf);
            }
            free(buf);
        } else if (strcmp(cmd, "write") == 0) {
            char *pos_str = strtok(NULL, " \t");
            char *text = strtok(NULL, "");
            if (!pos_str || !text) {
                printf("Usage: write <pos> <text>\n");
                continue;
            }
            uint32_t pos = (uint32_t)strtoul(pos_str, NULL, 0);
            size_t len = strlen(text);
            ssize_t w = my_write(pos, (const uint8_t *)text, (uint32_t)len);
            if (w >= 0) printf("Wrote %zd bytes.\n", w);
        } else if (strcmp(cmd, "shrink") == 0) {
            char *size_str = strtok(NULL, " \t");
            if (!size_str) {
                printf("Usage: shrink <new_size>\n");
                continue;
            }
            uint32_t new_size = (uint32_t)strtoul(size_str, NULL, 0);
            my_shrink(new_size);
        } else if (strcmp(cmd, "get_file_stats") == 0) {
            uint32_t sz = my_get_file_stats();
            if (current_file_index != -1)
                printf("Current file size: %u bytes\n", sz);
        } else if (strcmp(cmd, "rm") == 0) {
            my_rm();
        } else if (strcmp(cmd, "cp") == 0) {
            char *src = strtok(NULL, " \t");
            char *dst = strtok(NULL, " \t");
            if (!src || !dst) {
                printf("Usage: cp <source> <destination>\n");
                continue;
            }
            my_cp(src, dst);
        } else if (strcmp(cmd, "mv") == 0) {
            char *src = strtok(NULL, " \t");
            char *dst = strtok(NULL, " \t");
            if (!src || !dst) {
                printf("Usage: mv <source> <destination>\n");
                continue;
            }
            my_mv(src, dst);
        } else if (strcmp(cmd, "close") == 0) {
            my_close();
        } else if (strcmp(cmd, "ls") == 0) {
            char *path = strtok(NULL, " \t");
            cmd_ls(path);  // NULL means cwd
        } else if (strcmp(cmd, "pwd") == 0) {
            printf("%s\n", cwd_path);
        } else if (strcmp(cmd, "get_fs_stats") == 0) {
            my_get_fs_stats();
        } else if (strcmp(cmd, "viz") == 0) {
            cmd_viz();
        } else if (strcmp(cmd, "stressTest") == 0) {
            stressTest();
        } else if (strcmp(cmd, "mkdir") == 0) {
            char *path = strtok(NULL, " \t");
            if (!path) {
                printf("Usage: mkdir <path>\n");
                continue;
            }
            char abs_path[1024];
            make_absolute(path, abs_path, sizeof(abs_path));
            int parent_dir;
            char basename[FS_FILENAME_MAX];
            if (resolve_path_parent(abs_path, &parent_dir, basename) != 0) {
                fprintf(stderr, "Cannot resolve parent of '%s'.\n", abs_path);
                continue;
            }
            int idx = dir_mkdir(parent_dir, basename);
            if (idx >= 0) {
                printf("Directory '%s' created.\n", abs_path);
            }
        } else if (strcmp(cmd, "cd") == 0) {
            char *path = strtok(NULL, " \t");
            if (!path) {
                // cd with no arg → go to root
                cwd_index = root_dir_index;
                strncpy(cwd_path, "/", sizeof(cwd_path));
                continue;
            }
            char abs_path[1024];
            make_absolute(path, abs_path, sizeof(abs_path));
            int target = resolve_path(abs_path);
            if (target < 0) {
                fprintf(stderr, "cd: '%s' not found.\n", abs_path);
                continue;
            }
            if (file_table[target].type != FS_TYPE_DIRECTORY) {
                fprintf(stderr, "cd: '%s' is not a directory.\n", abs_path);
                continue;
            }
            cwd_index = target;
            strncpy(cwd_path, abs_path, sizeof(cwd_path) - 1);
            cwd_path[sizeof(cwd_path) - 1] = '\0';
        // User management commands
        } else if (strcmp(cmd, "useradd") == 0) {
            char *username = strtok(NULL, " \t");
            if (!username) {
                printf("Usage: useradd <username>\n");
                continue;
            }
            cmd_useradd(username);
        } else if (strcmp(cmd, "userdel") == 0) {
            char *username = strtok(NULL, " \t");
            if (!username) {
                printf("Usage: userdel <username>\n");
                continue;
            }
            cmd_userdel(username);
        } else if (strcmp(cmd, "usermod") == 0) {
            char *flag = strtok(NULL, " \t");
            if (!flag || strcmp(flag, "-aG") != 0) {
                printf("Usage: usermod -aG <group> <user>\n");
                continue;
            }
            char *groupname = strtok(NULL, " \t");
            char *username = strtok(NULL, " \t");
            if (!groupname || !username) {
                printf("Usage: usermod -aG <group> <user>\n");
                continue;
            }
            cmd_usermod_aG(groupname, username);
        } else if (strcmp(cmd, "users") == 0) {
            cmd_list_users();
        } else if (strcmp(cmd, "su") == 0) {
            char *username = strtok(NULL, " \t");
            if (!username) {
                printf("Usage: su <username>\n");
                continue;
            }
            cmd_su(username);
        } else if (strcmp(cmd, "whoami") == 0) {
            cmd_whoami();
        // Group management commands
        } else if (strcmp(cmd, "groupadd") == 0) {
            char *groupname = strtok(NULL, " \t");
            if (!groupname) {
                printf("Usage: groupadd <groupname>\n");
                continue;
            }
            cmd_groupadd(groupname);
        } else if (strcmp(cmd, "groupdel") == 0) {
            char *groupname = strtok(NULL, " \t");
            if (!groupname) {
                printf("Usage: groupdel <groupname>\n");
                continue;
            }
            cmd_groupdel(groupname);
        } else if (strcmp(cmd, "groups") == 0) {
            cmd_list_groups();
        // Permission management commands
        } else if (strcmp(cmd, "chmod") == 0) {
            char *mode = strtok(NULL, " \t");
            char *path = strtok(NULL, " \t");
            if (!mode || !path) {
                printf("Usage: chmod <mode> <path>\n");
                continue;
            }
            cmd_chmod(mode, path);
        } else if (strcmp(cmd, "chown") == 0) {
            char *owner = strtok(NULL, " \t");
            char *path = strtok(NULL, " \t");
            if (!owner || !path) {
                printf("Usage: chown <user>:<group> <path>\n");
                continue;
            }
            cmd_chown(owner, path);
        } else if (strcmp(cmd, "chgrp") == 0) {
            char *group = strtok(NULL, " \t");
            char *path = strtok(NULL, " \t");
            if (!group || !path) {
                printf("Usage: chgrp <group> <path>\n");
                continue;
            }
            cmd_chgrp(group, path);
        } else if (strcmp(cmd, "getfacl") == 0) {
            char *path = strtok(NULL, " \t");
            if (!path) {
                printf("Usage: getfacl <path>\n");
                continue;
            }
            cmd_getfacl(path);
        } else if (strcmp(cmd, "help") == 0) {
            print_help();
        } else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            break;
        } else {
            printf("Unknown command. Type 'help' for a list.\n");
        }
    }

    if (disk_fd >= 0) close(disk_fd);
    return 0;
}
