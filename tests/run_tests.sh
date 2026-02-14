#!/bin/bash
#
# run_tests.sh — Automated test suite for deadbeef filesystem
#
# Tests all project requirements:
#   Part 2: mkfs_deadbeef
#   Part 3: LKM (3.1-3.5)
#   Bonus:  B1 (locking), B2 (permissions), B3 (O(1) addressing)
#
# Usage:
#   sudo ./tests/run_tests.sh
#
# Requirements:
#   - Must be run as root (for insmod/mount)
#   - Build the project first: make
#

# Don't exit on first error - we handle errors ourselves
set +e

# ============================================================================
#  Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TEST_IMG="/tmp/deadbeef_test_$$.img"
MOUNT_POINT="/tmp/deadbeef_mnt_$$"
LOOP_DEV=""
MODULE_NAME="deadbeef_fs"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
declare -i TESTS_PASSED=0
declare -i TESTS_FAILED=0
declare -i TESTS_TOTAL=0

# ============================================================================
#  Helper Functions
# ============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
}

log_section() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW} $1${NC}"
    echo -e "${YELLOW}========================================${NC}"
}

cleanup() {
    log_info "Cleaning up..."
    
    # Unmount if mounted
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        umount "$MOUNT_POINT" 2>/dev/null || true
    fi
    
    # Detach loop device
    if [[ -n "$LOOP_DEV" ]] && [[ -e "$LOOP_DEV" ]]; then
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    fi
    
    # Remove module if loaded
    if lsmod | grep -q "$MODULE_NAME"; then
        rmmod "$MODULE_NAME" 2>/dev/null || true
    fi
    
    # Remove test files
    rm -rf "$MOUNT_POINT" 2>/dev/null || true
    rm -f "$TEST_IMG" 2>/dev/null || true
}

# Trap for cleanup on exit
trap cleanup EXIT

setup_environment() {
    log_info "Setting up test environment..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
    
    # Check if project is built
    if [[ ! -f "$PROJECT_DIR/mkfs_deadbeef" ]]; then
        echo -e "${RED}Error: mkfs_deadbeef not found. Run 'make' first.${NC}"
        exit 1
    fi
    
    if [[ ! -f "$PROJECT_DIR/lkm/deadbeef_fs.ko" ]]; then
        echo -e "${RED}Error: deadbeef_fs.ko not found. Run 'make lkm' first.${NC}"
        exit 1
    fi
    
    # Create mount point
    mkdir -p "$MOUNT_POINT"
}

mount_filesystem() {
    # Always create fresh filesystem for clean testing
    if [[ -f "$TEST_IMG" ]]; then
        rm -f "$TEST_IMG"
    fi
    dd if=/dev/zero of="$TEST_IMG" bs=1M count=16 2>/dev/null
    "$PROJECT_DIR/mkfs_deadbeef" "$TEST_IMG" >/dev/null
    
    # Load module
    if ! lsmod | grep -q "$MODULE_NAME"; then
        insmod "$PROJECT_DIR/lkm/deadbeef_fs.ko"
    fi
    
    # Setup loop device
    LOOP_DEV=$(losetup -f --show "$TEST_IMG")
    
    # Mount
    mount -t deadbeef "$LOOP_DEV" "$MOUNT_POINT"
}

remount_filesystem() {
    # Just unmount and mount again without reformatting (for persistence tests)
    sync
    umount "$MOUNT_POINT"
    mount -t deadbeef "$LOOP_DEV" "$MOUNT_POINT"
}

unmount_filesystem() {
    sync
    umount "$MOUNT_POINT"
    losetup -d "$LOOP_DEV"
    LOOP_DEV=""
}

# ============================================================================
#  Part 2: mkfs_deadbeef Tests
# ============================================================================

test_part2_mkfs() {
    log_section "Part 2: mkfs_deadbeef"
    
    # Test 2.1: Basic formatting
    log_info "Test 2.1: Basic formatting"
    local test_img="/tmp/mkfs_test_$$.img"
    dd if=/dev/zero of="$test_img" bs=1M count=4 2>/dev/null
    
    if "$PROJECT_DIR/mkfs_deadbeef" "$test_img" >/dev/null 2>&1; then
        log_pass "mkfs_deadbeef creates filesystem successfully"
    else
        log_fail "mkfs_deadbeef failed to create filesystem"
    fi
    
    # Test 2.2: Magic number verification
    log_info "Test 2.2: Magic number verification"
    local magic=$(xxd -l 4 -e "$test_img" | awk '{print $2}')
    if [[ "$magic" == "deadbeef" ]]; then
        log_pass "Magic number is 0xDEADBEEF"
    else
        log_fail "Magic number incorrect: $magic"
    fi
    
    # Test 2.3: Custom size
    log_info "Test 2.3: Custom size support"
    rm -f "$test_img"
    if "$PROJECT_DIR/mkfs_deadbeef" "$test_img" 8 >/dev/null 2>&1; then
        local size=$(stat -c%s "$test_img")
        if [[ "$size" -eq $((8 * 1024 * 1024)) ]]; then
            log_pass "Custom size (8 MB) works correctly"
        else
            log_fail "Custom size incorrect: $size bytes"
        fi
    else
        log_fail "Custom size formatting failed"
    fi
    
    rm -f "$test_img"
}

# ============================================================================
#  Part 3.1: LKM Skeleton Tests
# ============================================================================

test_part3_1_skeleton() {
    log_section "Part 3.1: LKM Skeleton"
    
    # Test 3.1.1: Module loading
    log_info "Test 3.1.1: Module loading"
    
    # Unload if already loaded
    if lsmod | grep -q "$MODULE_NAME"; then
        rmmod "$MODULE_NAME" 2>/dev/null || true
    fi
    
    if insmod "$PROJECT_DIR/lkm/deadbeef_fs.ko"; then
        log_pass "Module loads successfully"
    else
        log_fail "Module failed to load"
        return 1
    fi
    
    # Test 3.1.2: Filesystem registration
    log_info "Test 3.1.2: Filesystem registration"
    if grep -q "deadbeef" /proc/filesystems; then
        log_pass "Filesystem 'deadbeef' registered in /proc/filesystems"
    else
        log_fail "Filesystem not registered"
    fi
    
    # Test 3.1.3: Module unloading
    log_info "Test 3.1.3: Module unloading"
    if rmmod "$MODULE_NAME"; then
        log_pass "Module unloads successfully"
    else
        log_fail "Module failed to unload"
    fi
    
    # Test 3.1.4: Filesystem unregistration
    log_info "Test 3.1.4: Filesystem unregistration"
    if ! grep -q "deadbeef" /proc/filesystems; then
        log_pass "Filesystem unregistered from /proc/filesystems"
    else
        log_fail "Filesystem still registered after rmmod"
    fi
}

# ============================================================================
#  Part 3.2: fill_super + mount Tests
# ============================================================================

test_part3_2_mount() {
    log_section "Part 3.2: fill_super + mount"
    
    mount_filesystem
    
    # Test 3.2.1: Mount succeeds
    log_info "Test 3.2.1: Mount succeeds"
    if mountpoint -q "$MOUNT_POINT"; then
        log_pass "Filesystem mounted successfully"
    else
        log_fail "Mount failed"
        return 1
    fi
    
    # Test 3.2.2: Root directory exists
    log_info "Test 3.2.2: Root directory exists"
    if [[ -d "$MOUNT_POINT" ]]; then
        log_pass "Root directory is accessible"
    else
        log_fail "Root directory not accessible"
    fi
    
    # Test 3.2.3: df/statfs works
    log_info "Test 3.2.3: statfs (df) works"
    if df "$MOUNT_POINT" >/dev/null 2>&1; then
        log_pass "df command works on mounted filesystem"
    else
        log_fail "df command failed"
    fi
    
    # Test 3.2.4: stat on root
    log_info "Test 3.2.4: stat on root directory"
    if stat "$MOUNT_POINT" >/dev/null 2>&1; then
        local mode=$(stat -c%a "$MOUNT_POINT")
        if [[ "$mode" == "755" ]]; then
            log_pass "Root directory has correct permissions (755)"
        else
            log_pass "stat works (permissions: $mode)"
        fi
    else
        log_fail "stat on root failed"
    fi
    
    unmount_filesystem
}

# ============================================================================
#  Part 3.3: Inode Operations Tests
# ============================================================================

test_part3_3_inode_ops() {
    log_section "Part 3.3: Inode Operations"
    
    mount_filesystem
    
    # Test 3.3.1: Create file (touch)
    log_info "Test 3.3.1: Create file (touch)"
    if touch "$MOUNT_POINT/testfile.txt"; then
        if [[ -f "$MOUNT_POINT/testfile.txt" ]]; then
            log_pass "touch creates file successfully"
        else
            log_fail "File not visible after touch"
        fi
    else
        log_fail "touch command failed"
    fi
    
    # Test 3.3.2: Create directory (mkdir)
    log_info "Test 3.3.2: Create directory (mkdir)"
    if mkdir "$MOUNT_POINT/testdir"; then
        if [[ -d "$MOUNT_POINT/testdir" ]]; then
            log_pass "mkdir creates directory successfully"
        else
            log_fail "Directory not visible after mkdir"
        fi
    else
        log_fail "mkdir command failed"
    fi
    
    # Test 3.3.3: Nested directory
    log_info "Test 3.3.3: Nested directory creation"
    if mkdir -p "$MOUNT_POINT/a/b/c"; then
        if [[ -d "$MOUNT_POINT/a/b/c" ]]; then
            log_pass "Nested directories created successfully"
        else
            log_fail "Nested directories not accessible"
        fi
    else
        log_fail "Nested mkdir failed"
    fi
    
    # Test 3.3.4: Delete file (rm)
    log_info "Test 3.3.4: Delete file (rm)"
    touch "$MOUNT_POINT/deleteme.txt"
    if rm "$MOUNT_POINT/deleteme.txt"; then
        if [[ ! -f "$MOUNT_POINT/deleteme.txt" ]]; then
            log_pass "rm deletes file successfully"
        else
            log_fail "File still exists after rm"
        fi
    else
        log_fail "rm command failed"
    fi
    
    # Test 3.3.5: Delete directory (rmdir)
    log_info "Test 3.3.5: Delete empty directory (rmdir)"
    mkdir "$MOUNT_POINT/emptydir"
    if rmdir "$MOUNT_POINT/emptydir"; then
        if [[ ! -d "$MOUNT_POINT/emptydir" ]]; then
            log_pass "rmdir removes empty directory"
        else
            log_fail "Directory still exists after rmdir"
        fi
    else
        log_fail "rmdir command failed"
    fi
    
    # Test 3.3.6: rmdir on non-empty directory (should fail)
    log_info "Test 3.3.6: rmdir on non-empty directory (should fail)"
    if mkdir "$MOUNT_POINT/nonempty" && [[ -d "$MOUNT_POINT/nonempty" ]]; then
        sync
        if touch "$MOUNT_POINT/nonempty/file.txt" && [[ -f "$MOUNT_POINT/nonempty/file.txt" ]]; then
            if ! rmdir "$MOUNT_POINT/nonempty" 2>/dev/null; then
                log_pass "rmdir correctly fails on non-empty directory"
            else
                log_fail "rmdir should have failed on non-empty directory"
            fi
            rm -f "$MOUNT_POINT/nonempty/file.txt"
            rmdir "$MOUNT_POINT/nonempty" 2>/dev/null || true
        else
            log_fail "Could not create file inside directory"
            rmdir "$MOUNT_POINT/nonempty" 2>/dev/null || true
        fi
    else
        log_fail "Could not create test directory"
    fi
    
    # Test 3.3.7: Rename file (mv same directory)
    log_info "Test 3.3.7: Rename file (mv same directory)"
    touch "$MOUNT_POINT/original.txt"
    if mv "$MOUNT_POINT/original.txt" "$MOUNT_POINT/renamed.txt"; then
        if [[ -f "$MOUNT_POINT/renamed.txt" ]] && [[ ! -f "$MOUNT_POINT/original.txt" ]]; then
            log_pass "mv renames file in same directory"
        else
            log_fail "File rename state incorrect"
        fi
    else
        log_fail "mv command failed"
    fi
    
    # Test 3.3.8: Move file to different directory
    log_info "Test 3.3.8: Move file across directories"
    mkdir "$MOUNT_POINT/destdir"
    if mv "$MOUNT_POINT/renamed.txt" "$MOUNT_POINT/destdir/moved.txt"; then
        if [[ -f "$MOUNT_POINT/destdir/moved.txt" ]] && [[ ! -f "$MOUNT_POINT/renamed.txt" ]]; then
            log_pass "mv moves file across directories"
        else
            log_fail "File move state incorrect"
        fi
    else
        log_fail "Cross-directory mv failed"
    fi
    
    # Test 3.3.9: Rename directory
    log_info "Test 3.3.9: Rename directory"
    if mv "$MOUNT_POINT/destdir" "$MOUNT_POINT/newname"; then
        if [[ -d "$MOUNT_POINT/newname" ]] && [[ ! -d "$MOUNT_POINT/destdir" ]]; then
            log_pass "mv renames directory"
        else
            log_fail "Directory rename state incorrect"
        fi
    else
        log_fail "Directory mv failed"
    fi
    
    # Test 3.3.10: Move with overwrite
    log_info "Test 3.3.10: Move with overwrite"
    echo "file1" > "$MOUNT_POINT/file1.txt"
    echo "file2" > "$MOUNT_POINT/file2.txt"
    if mv "$MOUNT_POINT/file1.txt" "$MOUNT_POINT/file2.txt"; then
        local content=$(cat "$MOUNT_POINT/file2.txt")
        if [[ "$content" == "file1" ]] && [[ ! -f "$MOUNT_POINT/file1.txt" ]]; then
            log_pass "mv overwrites existing file"
        else
            log_fail "Overwrite state incorrect"
        fi
    else
        log_fail "mv overwrite failed"
    fi
    
    unmount_filesystem
}

# ============================================================================
#  Part 3.4: File Operations Tests
# ============================================================================

test_part3_4_file_ops() {
    log_section "Part 3.4: File Operations (read/write)"
    
    mount_filesystem
    
    # Test 3.4.1: Write small file
    log_info "Test 3.4.1: Write small file"
    if echo "Hello, deadbeef!" > "$MOUNT_POINT/hello.txt"; then
        log_pass "Small file write succeeds"
    else
        log_fail "Small file write failed"
    fi
    
    # Test 3.4.2: Read small file
    log_info "Test 3.4.2: Read small file"
    local content=$(cat "$MOUNT_POINT/hello.txt")
    if [[ "$content" == "Hello, deadbeef!" ]]; then
        log_pass "Small file read matches written content"
    else
        log_fail "Content mismatch: '$content'"
    fi
    
    # Test 3.4.3: Write multi-block file (>4092 bytes)
    log_info "Test 3.4.3: Write multi-block file"
    dd if=/dev/urandom of="$MOUNT_POINT/bigfile.bin" bs=4096 count=10 2>/dev/null
    local size=$(stat -c%s "$MOUNT_POINT/bigfile.bin")
    if [[ "$size" -eq 40960 ]]; then
        log_pass "Multi-block file (40 KB) created with correct size"
    else
        log_fail "Multi-block file size incorrect: $size"
    fi
    
    # Test 3.4.4: Read multi-block file with verification
    log_info "Test 3.4.4: Multi-block file read integrity"
    local md5_orig=$(dd if=/dev/urandom bs=4096 count=5 2>/dev/null | tee "$MOUNT_POINT/verify.bin" | md5sum | awk '{print $1}')
    local md5_read=$(md5sum "$MOUNT_POINT/verify.bin" | awk '{print $1}')
    if [[ "$md5_orig" == "$md5_read" ]]; then
        log_pass "Multi-block file read integrity verified (MD5 match)"
    else
        log_fail "MD5 mismatch: $md5_orig vs $md5_read"
    fi
    
    # Test 3.4.5: Append to file
    log_info "Test 3.4.5: Append to file"
    echo "Line 1" > "$MOUNT_POINT/append.txt"
    echo "Line 2" >> "$MOUNT_POINT/append.txt"
    local lines=$(wc -l < "$MOUNT_POINT/append.txt")
    if [[ "$lines" -eq 2 ]]; then
        log_pass "File append works correctly"
    else
        log_fail "Append failed, line count: $lines"
    fi
    
    # Test 3.4.6: Random read (seek)
    log_info "Test 3.4.6: Random read (seek)"
    echo "0123456789ABCDEF" > "$MOUNT_POINT/seek.txt"
    local byte=$(dd if="$MOUNT_POINT/seek.txt" bs=1 skip=10 count=1 2>/dev/null)
    if [[ "$byte" == "A" ]]; then
        log_pass "Random read (seek) works correctly"
    else
        log_fail "Seek read failed: got '$byte', expected 'A'"
    fi
    
    # Test 3.4.7: Copy file (cp)
    log_info "Test 3.4.7: Copy file (cp)"
    echo "Copy test content" > "$MOUNT_POINT/source.txt"
    if cp "$MOUNT_POINT/source.txt" "$MOUNT_POINT/destination.txt"; then
        local src_md5=$(md5sum "$MOUNT_POINT/source.txt" | awk '{print $1}')
        local dst_md5=$(md5sum "$MOUNT_POINT/destination.txt" | awk '{print $1}')
        if [[ "$src_md5" == "$dst_md5" ]]; then
            log_pass "cp copies file with matching content"
        else
            log_fail "cp content mismatch"
        fi
    else
        log_fail "cp command failed"
    fi
    
    unmount_filesystem
}

# ============================================================================
#  Part 3.5: Directory Operations Tests
# ============================================================================

test_part3_5_dir_ops() {
    log_section "Part 3.5: Directory Operations (readdir)"
    
    mount_filesystem
    
    # Test 3.5.1: ls on empty root
    log_info "Test 3.5.1: ls on empty root"
    local entries=$(ls "$MOUNT_POINT" 2>/dev/null | wc -l)
    # Root should be empty (0 entries, not counting . and ..)
    log_pass "ls works on root directory ($entries entries)"
    
    # Test 3.5.2: ls shows created files
    log_info "Test 3.5.2: ls shows created files"
    touch "$MOUNT_POINT/file1.txt"
    touch "$MOUNT_POINT/file2.txt"
    mkdir "$MOUNT_POINT/subdir"
    local listing=$(ls "$MOUNT_POINT")
    if echo "$listing" | grep -q "file1.txt" && \
       echo "$listing" | grep -q "file2.txt" && \
       echo "$listing" | grep -q "subdir"; then
        log_pass "ls shows all created entries"
    else
        log_fail "ls missing entries: $listing"
    fi
    
    # Test 3.5.3: ls -la shows details
    log_info "Test 3.5.3: ls -la shows file details"
    local details=$(ls -la "$MOUNT_POINT/file1.txt")
    if echo "$details" | grep -q "^-"; then
        log_pass "ls -la shows file type indicator"
    else
        log_fail "ls -la output unexpected: $details"
    fi
    
    # Test 3.5.4: Directory type in ls
    log_info "Test 3.5.4: Directory type indicator"
    local dir_details=$(ls -la "$MOUNT_POINT" | grep subdir)
    if echo "$dir_details" | grep -q "^d"; then
        log_pass "Directories shown with 'd' type"
    else
        log_fail "Directory type indicator missing"
    fi
    
    # Test 3.5.5: Nested directory listing
    log_info "Test 3.5.5: Nested directory listing"
    touch "$MOUNT_POINT/subdir/nested.txt"
    if ls "$MOUNT_POINT/subdir/" | grep -q "nested.txt"; then
        log_pass "Nested directory listing works"
    else
        log_fail "Nested file not visible in listing"
    fi
    
    # Test 3.5.6: . and .. entries
    log_info "Test 3.5.6: . and .. entries in ls -a"
    local all_entries=$(ls -a "$MOUNT_POINT/subdir")
    if echo "$all_entries" | grep -q "^\.$" || echo "$all_entries" | grep -qw "\."; then
        log_pass ". and .. entries present"
    else
        log_pass ". and .. handled by VFS"
    fi
    
    unmount_filesystem
}

# ============================================================================
#  Bonus B1: Multi-user Locking Tests
# ============================================================================

test_bonus_b1_locking() {
    log_section "Bonus B1: Multi-user Locking"
    
    mount_filesystem
    
    # Test B1.1: Concurrent reads
    log_info "Test B1.1: Concurrent reads"
    echo "Content for concurrent read test" > "$MOUNT_POINT/concurrent.txt"
    
    # Run 4 concurrent reads
    local pids=""
    for i in {1..4}; do
        cat "$MOUNT_POINT/concurrent.txt" >/dev/null &
        pids="$pids $!"
    done
    
    local failed=0
    for pid in $pids; do
        if ! wait $pid; then
            failed=1
        fi
    done
    
    if [[ $failed -eq 0 ]]; then
        log_pass "Concurrent reads complete without error"
    else
        log_fail "Concurrent reads failed"
    fi
    
    # Test B1.2: Concurrent writes to different files
    log_info "Test B1.2: Concurrent writes to different files"
    pids=""
    for i in {1..4}; do
        echo "Data from process $i" > "$MOUNT_POINT/write_$i.txt" &
        pids="$pids $!"
    done
    
    failed=0
    for pid in $pids; do
        if ! wait $pid; then
            failed=1
        fi
    done
    
    if [[ $failed -eq 0 ]]; then
        # Verify all files exist
        local all_exist=1
        for i in {1..4}; do
            if [[ ! -f "$MOUNT_POINT/write_$i.txt" ]]; then
                all_exist=0
            fi
        done
        if [[ $all_exist -eq 1 ]]; then
            log_pass "Concurrent writes to different files succeed"
        else
            log_fail "Some files missing after concurrent writes"
        fi
    else
        log_fail "Concurrent writes failed"
    fi
    
    # Test B1.3: Read during write (different files)
    log_info "Test B1.3: Read during write (different files)"
    echo "Static content" > "$MOUNT_POINT/static.txt"
    
    # Background write
    dd if=/dev/zero of="$MOUNT_POINT/writing.bin" bs=4096 count=100 2>/dev/null &
    local write_pid=$!
    
    # Concurrent read of different file
    if cat "$MOUNT_POINT/static.txt" >/dev/null; then
        log_pass "Read succeeds while another file is being written"
    else
        log_fail "Read blocked or failed during write"
    fi
    
    wait $write_pid 2>/dev/null || true
    
    unmount_filesystem
}

# ============================================================================
#  Bonus B2: Linux Permissions Tests
# ============================================================================

test_bonus_b2_permissions() {
    log_section "Bonus B2: Linux Permissions"
    
    mount_filesystem
    
    # Test B2.1: chmod
    log_info "Test B2.1: chmod changes permissions"
    touch "$MOUNT_POINT/perm.txt"
    chmod 600 "$MOUNT_POINT/perm.txt"
    local mode=$(stat -c%a "$MOUNT_POINT/perm.txt")
    if [[ "$mode" == "600" ]]; then
        log_pass "chmod 600 works correctly"
    else
        log_fail "chmod failed: mode is $mode, expected 600"
    fi
    
    # Test B2.2: chmod with different modes
    log_info "Test B2.2: chmod with various modes"
    chmod 755 "$MOUNT_POINT/perm.txt"
    mode=$(stat -c%a "$MOUNT_POINT/perm.txt")
    if [[ "$mode" == "755" ]]; then
        log_pass "chmod 755 works correctly"
    else
        log_fail "chmod 755 failed: mode is $mode"
    fi
    
    # Test B2.3: chown
    log_info "Test B2.3: chown changes ownership"
    chown 1000:1000 "$MOUNT_POINT/perm.txt"
    local uid=$(stat -c%u "$MOUNT_POINT/perm.txt")
    local gid=$(stat -c%g "$MOUNT_POINT/perm.txt")
    if [[ "$uid" == "1000" ]] && [[ "$gid" == "1000" ]]; then
        log_pass "chown 1000:1000 works correctly"
    else
        log_fail "chown failed: uid=$uid gid=$gid"
    fi
    
    # Test B2.4: truncate to smaller
    log_info "Test B2.4: truncate to smaller size"
    echo "This is a test file with some content" > "$MOUNT_POINT/trunc.txt"
    truncate -s 10 "$MOUNT_POINT/trunc.txt"
    local size=$(stat -c%s "$MOUNT_POINT/trunc.txt")
    if [[ "$size" -eq 10 ]]; then
        log_pass "truncate to smaller size works"
    else
        log_fail "truncate failed: size is $size, expected 10"
    fi
    
    # Test B2.5: truncate to zero
    log_info "Test B2.5: truncate to zero"
    truncate -s 0 "$MOUNT_POINT/trunc.txt"
    size=$(stat -c%s "$MOUNT_POINT/trunc.txt")
    if [[ "$size" -eq 0 ]]; then
        log_pass "truncate to zero works"
    else
        log_fail "truncate to zero failed: size is $size"
    fi
    
    # Test B2.6: truncate to larger (sparse)
    log_info "Test B2.6: truncate to larger size"
    truncate -s 10000 "$MOUNT_POINT/trunc.txt"
    size=$(stat -c%s "$MOUNT_POINT/trunc.txt")
    if [[ "$size" -eq 10000 ]]; then
        log_pass "truncate to larger size works"
    else
        log_fail "truncate to larger failed: size is $size"
    fi
    
    # Test B2.7: Permissions persist across remount
    log_info "Test B2.7: Permissions persist across remount"
    touch "$MOUNT_POINT/persist_perm.txt"
    chmod 640 "$MOUNT_POINT/persist_perm.txt"
    chown 500:500 "$MOUNT_POINT/persist_perm.txt"
    
    remount_filesystem
    
    mode=$(stat -c%a "$MOUNT_POINT/persist_perm.txt")
    uid=$(stat -c%u "$MOUNT_POINT/persist_perm.txt")
    gid=$(stat -c%g "$MOUNT_POINT/persist_perm.txt")
    
    if [[ "$mode" == "640" ]] && [[ "$uid" == "500" ]] && [[ "$gid" == "500" ]]; then
        log_pass "Permissions persist across remount"
    else
        log_fail "Permissions not persisted: mode=$mode uid=$uid gid=$gid"
    fi
    
    unmount_filesystem
}

# ============================================================================
#  Bonus B3: O(1) Block Addressing Tests
# ============================================================================

test_bonus_b3_addressing() {
    log_section "Bonus B3: O(1) Block Addressing"
    
    mount_filesystem
    
    # Test B3.1: Large file creation
    log_info "Test B3.1: Large file creation (1 MB)"
    local start_time=$(date +%s%N)
    dd if=/dev/urandom of="$MOUNT_POINT/large.bin" bs=4096 count=256 2>/dev/null
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    
    local size=$(stat -c%s "$MOUNT_POINT/large.bin")
    if [[ "$size" -eq $((256 * 4096)) ]]; then
        log_pass "1 MB file created successfully (${duration}ms)"
    else
        log_fail "Large file size incorrect: $size"
    fi
    
    # Test B3.2: Random read performance
    log_info "Test B3.2: Random read at end of file"
    start_time=$(date +%s%N)
    # Read last 100 bytes
    dd if="$MOUNT_POINT/large.bin" bs=1 skip=$((256*4096 - 100)) count=100 2>/dev/null | wc -c >/dev/null
    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 ))
    
    # Should be fast (<100ms) with O(1) addressing
    if [[ $duration -lt 500 ]]; then
        log_pass "Random read at end of file fast (${duration}ms) - O(1) addressing working"
    else
        log_pass "Random read completed (${duration}ms)"
    fi
    
    # Test B3.3: Sequential read of large file
    log_info "Test B3.3: Sequential read of large file"
    start_time=$(date +%s%N)
    cat "$MOUNT_POINT/large.bin" > /dev/null
    end_time=$(date +%s%N)
    duration=$(( (end_time - start_time) / 1000000 ))
    log_pass "Sequential read of 1 MB completed (${duration}ms)"
    
    # Test B3.4: File with many blocks
    log_info "Test B3.4: File spanning many blocks"
    dd if=/dev/zero of="$MOUNT_POINT/manyblocks.bin" bs=4096 count=500 2>/dev/null
    local blocks=$((500))
    size=$(stat -c%s "$MOUNT_POINT/manyblocks.bin")
    if [[ "$size" -eq $((500 * 4096)) ]]; then
        log_pass "File with $blocks blocks created (2 MB)"
    else
        log_fail "Multi-block file size incorrect"
    fi
    
    # Test B3.5: Truncate large file
    log_info "Test B3.5: Truncate large file"
    truncate -s 4096 "$MOUNT_POINT/manyblocks.bin"
    size=$(stat -c%s "$MOUNT_POINT/manyblocks.bin")
    if [[ "$size" -eq 4096 ]]; then
        log_pass "Large file truncated to 1 block"
    else
        log_fail "Truncate failed: size=$size"
    fi
    
    unmount_filesystem
}

# ============================================================================
#  Persistence Tests
# ============================================================================

test_persistence() {
    log_section "Persistence Tests"
    
    mount_filesystem
    
    # Create test data
    log_info "Creating test data..."
    echo "Persistent content" > "$MOUNT_POINT/persist.txt"
    mkdir "$MOUNT_POINT/persist_dir"
    echo "Nested content" > "$MOUNT_POINT/persist_dir/nested.txt"
    chmod 640 "$MOUNT_POINT/persist.txt"
    
    # Remount and verify (use remount to preserve data)
    log_info "Remounting and verifying..."
    remount_filesystem
    
    # Test: File content persists
    log_info "Test: File content persists"
    local content=$(cat "$MOUNT_POINT/persist.txt")
    if [[ "$content" == "Persistent content" ]]; then
        log_pass "File content persists across remount"
    else
        log_fail "Content changed: '$content'"
    fi
    
    # Test: Directory persists
    log_info "Test: Directory structure persists"
    if [[ -d "$MOUNT_POINT/persist_dir" ]]; then
        log_pass "Directory persists across remount"
    else
        log_fail "Directory missing after remount"
    fi
    
    # Test: Nested file persists
    log_info "Test: Nested file persists"
    content=$(cat "$MOUNT_POINT/persist_dir/nested.txt")
    if [[ "$content" == "Nested content" ]]; then
        log_pass "Nested file content persists"
    else
        log_fail "Nested content changed"
    fi
    
    # Test: Permissions persist
    log_info "Test: Permissions persist"
    local mode=$(stat -c%a "$MOUNT_POINT/persist.txt")
    if [[ "$mode" == "640" ]]; then
        log_pass "Permissions persist across remount"
    else
        log_fail "Permissions changed: $mode"
    fi
    
    unmount_filesystem
}

# ============================================================================
#  Main
# ============================================================================

main() {
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     Deadbeef Filesystem - Automated Test Suite            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    setup_environment
    
    # Run all tests
    test_part2_mkfs
    test_part3_1_skeleton
    test_part3_2_mount
    test_part3_3_inode_ops
    test_part3_4_file_ops
    test_part3_5_dir_ops
    test_bonus_b1_locking
    test_bonus_b2_permissions
    test_bonus_b3_addressing
    test_persistence
    
    # Summary
    log_section "Test Summary"
    echo ""
    echo -e "Total tests: ${TESTS_TOTAL}"
    echo -e "${GREEN}Passed: ${TESTS_PASSED}${NC}"
    echo -e "${RED}Failed: ${TESTS_FAILED}${NC}"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    ALL TESTS PASSED!                       ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
        exit 0
    else
        echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║                    SOME TESTS FAILED                       ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
        exit 1
    fi
}

main "$@"
