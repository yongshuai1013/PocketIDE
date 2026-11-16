#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_script_launch.h"

struct fake_words {
    uint32_t base;
    uint32_t values[GUEST_SCRIPT_MAX_ORIGINAL_ARGV_WORDS];
    size_t count;
    int fail;
};

static int read_fake_word(void *context, uint32_t address, uint32_t *value) {
    struct fake_words *memory = context;
    if (memory->fail || address < memory->base ||
        (address - memory->base) % sizeof(uint32_t) != 0) return -1;
    size_t index = (address - memory->base) / sizeof(uint32_t);
    if (index >= memory->count) return -1;
    *value = memory->values[index];
    return 0;
}

static void make_dir(const char *path) {
    assert(mkdir(path, 0700) == 0);
}

static void join_path(char *out, size_t capacity, const char *left, const char *right) {
    int n = snprintf(out, capacity, "%s/%s", left, right);
    assert(n > 0 && (size_t)n < capacity);
}

static void write_script(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0550);
    assert(fd >= 0);
    static const char script[] = "#!/system/bin/sh\nexit 0\n";
    assert(write(fd, script, sizeof(script) - 1) == (ssize_t)(sizeof(script) - 1));
    assert(fchmod(fd, 0550) == 0);
    assert(close(fd) == 0);
}

static void assert_shared_route_markers(void) {
    FILE *capture = tmpfile();
    assert(capture != NULL);
    fflush(stdout);
    int saved_stdout = dup(STDOUT_FILENO);
    assert(saved_stdout >= 0);
    assert(dup2(fileno(capture), STDOUT_FILENO) == STDOUT_FILENO);

    guest_script_log_exec_route(101, 13, GUEST_API10_SHELL_PATH,
                                GUEST_API10_GOLDFISH_SCRIPT, 2);
    guest_script_log_launch_event(101, 13, GUEST_API10_SHELL_PATH,
                                  GUEST_API10_GOLDFISH_SCRIPT, 198);
    assert(fflush(stdout) == 0);
    assert(dup2(saved_stdout, STDOUT_FILENO) == STDOUT_FILENO);
    assert(close(saved_stdout) == 0);

    assert(fseek(capture, 0, SEEK_SET) == 0);
    char log[2048] = {0};
    size_t bytes = fread(log, 1, sizeof(log) - 1, capture);
    assert(!ferror(capture) && bytes > 0);
    assert(fclose(capture) == 0);
    assert(strstr(log, "GUEST SCRIPT EXEC ROUTE: host-pid=101 guest-pid=13 guest-shell=/system/bin/sh script=/system/etc/init.goldfish.sh") != NULL);
    assert(strstr(log, "forwarded-extra-args=2 shell-elf=verified-API10-ARM32 patched-linker=fd-198 host-shell-exec=0 same-tracee=1") != NULL);
    assert(strstr(log, "GUEST SCRIPT LAUNCH EVENT: host-pid=101 guest-pid=13 guest-shell=/system/bin/sh script=/system/etc/init.goldfish.sh; original API10 linker entered via fd=198; shell-main-entry=unobserved") != NULL);
}

static void test_guest_script_path_and_symlink_containment(void) {
    char tmp[] = "/tmp/gingervm-script-launch.XXXXXX";
    char *base = mkdtemp(tmp);
    assert(base != NULL);

    char root[PATH_MAX], images[PATH_MAX], system[PATH_MAX], etc[PATH_MAX];
    char script[PATH_MAX], other[PATH_MAX], outside[PATH_MAX], link_path[PATH_MAX];
    join_path(root, sizeof(root), base, "guest"); make_dir(root);
    join_path(images, sizeof(images), root, ".images"); make_dir(images);
    join_path(system, sizeof(system), images, "system"); make_dir(system);
    join_path(etc, sizeof(etc), system, "etc"); make_dir(etc);
    join_path(script, sizeof(script), etc, "init.goldfish.sh"); write_script(script);
    join_path(other, sizeof(other), etc, "other.sh"); write_script(other);
    join_path(outside, sizeof(outside), base, "outside.sh"); write_script(outside);
    join_path(link_path, sizeof(link_path), etc, "init-link.sh");

    char canonical_root[PATH_MAX], canonical_system[PATH_MAX], canonical_script[PATH_MAX];
    assert(realpath(root, canonical_root) != NULL);
    assert(realpath(system, canonical_system) != NULL);
    assert(realpath(script, canonical_script) != NULL);
    struct stat script_stat;
    assert(lstat(script, &script_stat) == 0 && S_ISREG(script_stat.st_mode));
    assert((script_stat.st_mode & 07777) == 0550);
    assert(guest_script_path_is_whitelisted(GUEST_API10_GOLDFISH_SCRIPT));
    assert(!guest_script_path_is_whitelisted("/system/etc/../etc/init.goldfish.sh"));
    assert(!guest_script_path_is_whitelisted("/tmp/outside.sh"));
    assert(guest_script_file_is_authorized(GUEST_API10_GOLDFISH_SCRIPT,
        canonical_root, canonical_system, canonical_script, 1));
    assert(guest_script_mode_is_executable((uint32_t)script_stat.st_mode));
    assert(!guest_script_mode_is_executable(0644));
    static const char approved_shebang[] = "#!/system/bin/sh\n";
    static const char rejected_shebang[] = "#!/bin/sh\n";
    assert(guest_script_has_approved_shebang(approved_shebang, sizeof(approved_shebang) - 1));
    assert(!guest_script_has_approved_shebang(rejected_shebang, sizeof(rejected_shebang) - 1));
    int route_authorized = guest_script_launch_is_authorized(
        GUEST_API10_GOLDFISH_SCRIPT, canonical_root, canonical_system,
        canonical_script, 1, (uint32_t)script_stat.st_mode,
        approved_shebang, sizeof(approved_shebang) - 1);
    assert(route_authorized);
    if (route_authorized) assert_shared_route_markers();
    assert(!guest_script_launch_is_authorized(
        "/system/etc/../etc/init.goldfish.sh", canonical_root, canonical_system,
        canonical_script, 1, (uint32_t)script_stat.st_mode,
        approved_shebang, sizeof(approved_shebang) - 1));
    assert(!guest_script_launch_is_authorized(
        GUEST_API10_GOLDFISH_SCRIPT, canonical_root, canonical_system,
        canonical_script, 1, 0644, approved_shebang, sizeof(approved_shebang) - 1));
    assert(!guest_script_launch_is_authorized(
        GUEST_API10_GOLDFISH_SCRIPT, canonical_root, canonical_system,
        canonical_script, 1, (uint32_t)script_stat.st_mode,
        rejected_shebang, sizeof(rejected_shebang) - 1));
    assert(!guest_script_file_is_authorized("/system/etc/../etc/init.goldfish.sh",
        canonical_root, canonical_system, canonical_script, 1));
    assert(!guest_script_file_is_authorized(GUEST_API10_GOLDFISH_SCRIPT,
        canonical_root, canonical_system, canonical_script, 0));

    assert(symlink(outside, link_path) == 0);
    char resolved_link[PATH_MAX];
    assert(realpath(link_path, resolved_link) != NULL);
    assert(!guest_script_file_is_authorized(GUEST_API10_GOLDFISH_SCRIPT,
        canonical_root, canonical_system, resolved_link, 0));
    assert(!guest_script_launch_is_authorized(GUEST_API10_GOLDFISH_SCRIPT,
        canonical_root, canonical_system, resolved_link, 0,
        (uint32_t)script_stat.st_mode, approved_shebang, sizeof(approved_shebang) - 1));
    assert(unlink(link_path) == 0);

    assert(symlink(other, link_path) == 0);
    assert(realpath(link_path, resolved_link) != NULL);
    assert(guest_script_path_within(resolved_link, canonical_system));
    assert(!guest_script_file_is_authorized(GUEST_API10_GOLDFISH_SCRIPT,
        canonical_root, canonical_system, resolved_link, 0));

    unlink(link_path); unlink(script); unlink(other); unlink(outside);
    rmdir(etc); rmdir(system); rmdir(images); rmdir(root); rmdir(base);
}

static void test_original_argv_collection(void) {
    struct fake_words memory = {
        .base = 0x1000,
        .values = {0x2000, 0x3000, 0x4000, 0},
        .count = 4,
    };
    uint32_t preserved[GUEST_SCRIPT_MAX_PRESERVED_ARGS] = {0};
    size_t preserved_count = 0;
    assert(guest_script_collect_preserved_args(memory.base, read_fake_word,
        &memory, preserved, GUEST_SCRIPT_MAX_PRESERVED_ARGS, &preserved_count) == 0);
    assert(preserved_count == 2);
    assert(preserved[0] == 0x3000 && preserved[1] == 0x4000);

    assert(guest_script_collect_preserved_args(0, read_fake_word, &memory,
        preserved, GUEST_SCRIPT_MAX_PRESERVED_ARGS, &preserved_count) == 0);
    assert(preserved_count == 0);
    memory.fail = 1;
    assert(guest_script_collect_preserved_args(memory.base, read_fake_word,
        &memory, preserved, GUEST_SCRIPT_MAX_PRESERVED_ARGS, &preserved_count) == -EFAULT);
    memory.fail = 0;

    for (size_t i = 0; i < GUEST_SCRIPT_MAX_ORIGINAL_ARGV_WORDS; ++i)
        memory.values[i] = 0x5000u + (uint32_t)(i * 4u);
    memory.count = GUEST_SCRIPT_MAX_ORIGINAL_ARGV_WORDS;
    assert(guest_script_collect_preserved_args(memory.base, read_fake_word,
        &memory, preserved, GUEST_SCRIPT_MAX_PRESERVED_ARGS, &preserved_count) == -E2BIG);
}

static void test_shell_launcher_argv_layout(void) {
    const uint32_t extra[] = {0x21000, 0x22000};
    const char *native_shell = "/data/app/libgingervm_exec_patched_bin_sh.so";
    struct guest_script_argv_plan plan;
    assert(guest_script_plan_argv(0x70000000, native_shell, extra, 2, &plan) == 0);
    assert(plan.exec_path_address == 0x70000000);
    assert(plan.shell_argv0_address == plan.exec_path_address + strlen(native_shell) + 1);
    assert(plan.argv_words[0] == plan.shell_argv0_address);
    assert(plan.argv_words[1] == plan.script_argv1_address);
    assert(plan.argv_words[2] == extra[0] && plan.argv_words[3] == extra[1]);
    assert(plan.argv_words[4] == 0 && plan.argc == 4);
    assert(plan.total_bytes <= GUEST_SCRIPT_LAUNCH_MAX_BYTES);
    uint32_t too_many[GUEST_SCRIPT_MAX_PRESERVED_ARGS + 1u] = {1};
    assert(guest_script_plan_argv(0x70000000, native_shell, too_many,
        GUEST_SCRIPT_MAX_PRESERVED_ARGS + 1u, &plan) == -E2BIG);
    assert(guest_script_plan_argv(UINT32_MAX - 8u, native_shell, NULL, 0, &plan) == -E2BIG);
    assert(guest_script_plan_argv(0x70000000, "relative/sh", NULL, 0, &plan) == -EINVAL);
}

int main(void) {
    test_guest_script_path_and_symlink_containment();
    test_original_argv_collection();
    test_shell_launcher_argv_layout();
    puts("guest script launch integration regression: PASS (0550 authorized API10 path, no symlink escape, shared route/launch markers, guest-shell argv, bounded arguments)");
    return 0;
}
