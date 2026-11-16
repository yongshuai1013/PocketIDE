#ifndef GINGERVM_GUEST_SCRIPT_LAUNCH_H
#define GINGERVM_GUEST_SCRIPT_LAUNCH_H

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GUEST_API10_GOLDFISH_SCRIPT "/system/etc/init.goldfish.sh"
#define GUEST_API10_SHELL_PATH "/system/bin/sh"
#define GUEST_SCRIPT_MAX_PRESERVED_ARGS 62u
#define GUEST_SCRIPT_MAX_ORIGINAL_ARGV_WORDS 64u
#define GUEST_SCRIPT_MAX_ARGV_WORDS (GUEST_SCRIPT_MAX_PRESERVED_ARGS + 3u)
#define GUEST_SCRIPT_LAUNCH_MAX_BYTES 2048u

struct guest_script_argv_plan {
    uint32_t exec_path_address;
    uint32_t shell_argv0_address;
    uint32_t script_argv1_address;
    uint32_t argv_address;
    uint32_t argv_words[GUEST_SCRIPT_MAX_ARGV_WORDS];
    size_t argc;
    size_t total_bytes;
};

typedef int (*guest_script_read_word_fn)(void *context, uint32_t address,
                                         uint32_t *value);

static inline int guest_script_path_is_whitelisted(const char *guest_path) {
    return guest_path && strcmp(guest_path, GUEST_API10_GOLDFISH_SCRIPT) == 0;
}

static inline int guest_script_mode_is_executable(uint32_t mode) {
    return (mode & 0111u) != 0;
}

static inline int guest_script_has_approved_shebang(const char *bytes, size_t length) {
    static const char expected[] = "#!/system/bin/sh\n";
    return bytes && length == sizeof(expected) - 1 &&
           memcmp(bytes, expected, sizeof(expected) - 1) == 0;
}

static inline void guest_script_log_exec_route(int host_pid, int guest_pid,
                                               const char *guest_shell,
                                               const char *script,
                                               size_t forwarded_extra_args) {
    printf("GUEST SCRIPT EXEC ROUTE: host-pid=%d guest-pid=%d guest-shell=%s script=%s argv0=%s argv1=%s forwarded-extra-args=%zu shell-elf=verified-API10-ARM32 patched-linker=fd-198 host-shell-exec=0 same-tracee=1\n",
           host_pid, guest_pid, guest_shell, script, GUEST_API10_SHELL_PATH,
           GUEST_API10_GOLDFISH_SCRIPT, forwarded_extra_args);
}

static inline void guest_script_log_launch_event(int host_pid, int guest_pid,
                                                 const char *guest_shell,
                                                 const char *script,
                                                 int linker_fd) {
    printf("GUEST SCRIPT LAUNCH EVENT: host-pid=%d guest-pid=%d guest-shell=%s script=%s; original API10 linker entered via fd=%d; shell-main-entry=unobserved\n",
           host_pid, guest_pid, guest_shell, script, linker_fd);
}

static inline int guest_script_path_within(const char *path, const char *root) {
    if (!path || !root || root[0] != '/' || path[0] != '/') return 0;
    size_t root_length = strlen(root);
    return strncmp(path, root, root_length) == 0 &&
           (path[root_length] == '\0' || path[root_length] == '/');
}

/* resolved_script must come from the opened file descriptor, not a lexical join. */
static inline int guest_script_file_is_authorized(const char *guest_path,
                                                   const char *canonical_guest_root,
                                                   const char *canonical_system_root,
                                                   const char *resolved_script,
                                                   int regular_nosymlink) {
    if (!guest_script_path_is_whitelisted(guest_path) || !regular_nosymlink ||
        !canonical_guest_root || !canonical_system_root || !resolved_script ||
        !guest_script_path_within(canonical_system_root, canonical_guest_root) ||
        !guest_script_path_within(resolved_script, canonical_system_root))
        return 0;

    char expected[PATH_MAX];
    int n = snprintf(expected, sizeof(expected), "%s/etc/init.goldfish.sh",
                     canonical_system_root);
    if (n <= 0 || (size_t)n >= sizeof(expected)) return 0;
    return strcmp(resolved_script, expected) == 0;
}

static inline int guest_script_launch_is_authorized(const char *guest_path,
                                                     const char *canonical_guest_root,
                                                     const char *canonical_system_root,
                                                     const char *resolved_script,
                                                     int regular_nosymlink,
                                                     uint32_t mode,
                                                     const char *shebang,
                                                     size_t shebang_length) {
    return guest_script_file_is_authorized(guest_path, canonical_guest_root,
               canonical_system_root, resolved_script, regular_nosymlink) &&
           guest_script_mode_is_executable(mode) &&
           guest_script_has_approved_shebang(shebang, shebang_length);
}

/* Collect argv[1..] only; kernel shebang semantics replace the original argv[0]. */
static inline int guest_script_collect_preserved_args(uint32_t original_argv,
                                                       guest_script_read_word_fn read_word,
                                                       void *context,
                                                       uint32_t *preserved,
                                                       size_t preserved_capacity,
                                                       size_t *preserved_count) {
    if (!preserved_count || (!preserved && preserved_capacity != 0)) return -EINVAL;
    *preserved_count = 0;
    if (original_argv == 0) return 0;
    if (!read_word) return -EINVAL;

    for (size_t index = 0; index < GUEST_SCRIPT_MAX_ORIGINAL_ARGV_WORDS; ++index) {
        uint64_t address64 = (uint64_t)original_argv + index * sizeof(uint32_t);
        if (address64 > UINT32_MAX) return -EFAULT;
        uint32_t value = 0;
        if (read_word(context, (uint32_t)address64, &value) != 0) return -EFAULT;
        if (value == 0) return 0;
        if (index == 0) continue;
        if (*preserved_count >= preserved_capacity ||
            *preserved_count >= GUEST_SCRIPT_MAX_PRESERVED_ARGS)
            return -E2BIG;
        preserved[(*preserved_count)++] = value;
    }
    return -E2BIG;
}

static inline int guest_script_plan_argv(uint32_t scratch_address,
                                         const char *native_shell_path,
                                         const uint32_t *preserved_args,
                                         size_t preserved_count,
                                         struct guest_script_argv_plan *plan) {
    if (!native_shell_path || native_shell_path[0] != '/' || !plan ||
        (!preserved_args && preserved_count != 0)) return -EINVAL;
    if (preserved_count > GUEST_SCRIPT_MAX_PRESERVED_ARGS) return -E2BIG;

    size_t exec_bytes = strlen(native_shell_path) + 1;
    size_t shell_arg_bytes = sizeof(GUEST_API10_SHELL_PATH);
    size_t script_arg_bytes = sizeof(GUEST_API10_GOLDFISH_SCRIPT);
    uint64_t shell_arg0 = (uint64_t)scratch_address + exec_bytes;
    uint64_t script_arg1 = shell_arg0 + shell_arg_bytes;
    uint64_t argv_address = (script_arg1 + script_arg_bytes + 3u) & ~UINT64_C(3);
    size_t argc = preserved_count + 2u;
    uint64_t end = argv_address + (argc + 1u) * sizeof(uint32_t);
    uint64_t total = end - scratch_address;
    if (end > UINT32_MAX || total > GUEST_SCRIPT_LAUNCH_MAX_BYTES) return -E2BIG;

    memset(plan, 0, sizeof(*plan));
    plan->exec_path_address = scratch_address;
    plan->shell_argv0_address = (uint32_t)shell_arg0;
    plan->script_argv1_address = (uint32_t)script_arg1;
    plan->argv_address = (uint32_t)argv_address;
    plan->argc = argc;
    plan->total_bytes = (size_t)total;
    plan->argv_words[0] = plan->shell_argv0_address;
    plan->argv_words[1] = plan->script_argv1_address;
    for (size_t i = 0; i < preserved_count; ++i) {
        if (preserved_args[i] == 0) return -EINVAL;
        plan->argv_words[i + 2u] = preserved_args[i];
    }
    plan->argv_words[argc] = 0;
    return 0;
}

#endif
