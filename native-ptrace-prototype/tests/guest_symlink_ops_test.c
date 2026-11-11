#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../app/src/main/cpp/guest_symlink_ops.h"

static void make_dir(const char *path) {
    assert(mkdir(path, 0700) == 0 || errno == EEXIST);
}

static void write_file(const char *path, const char *contents) {
    FILE *file = fopen(path, "w");
    assert(file != NULL);
    assert(fputs(contents, file) >= 0);
    assert(fclose(file) == 0);
}

int main(void) {
    char base[] = "/tmp/gingervm-symlink-XXXXXX";
    char *temp = mkdtemp(base);
    assert(temp != NULL);

    char root[PATH_MAX], image[PATH_MAX], system_dir[PATH_MAX];
    char system_etc[PATH_MAX], system_lib[PATH_MAX], native_root[PATH_MAX];
    char native_lib[PATH_MAX], outside[PATH_MAX], outside_file[PATH_MAX];
    char link_etc[PATH_MAX], link_native[PATH_MAX], escape_link[PATH_MAX];
    char parent_link[PATH_MAX], parent_escape[PATH_MAX], target_escape[PATH_MAX];
    char sibling[PATH_MAX], sibling_link[PATH_MAX], traversal_link[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/guest", temp) > 0);
    assert(snprintf(image, sizeof(image), "%s/.images", root) > 0);
    assert(snprintf(system_dir, sizeof(system_dir), "%s/system", image) > 0);
    assert(snprintf(system_etc, sizeof(system_etc), "%s/etc", system_dir) > 0);
    assert(snprintf(system_lib, sizeof(system_lib), "%s/lib", system_dir) > 0);
    assert(snprintf(native_root, sizeof(native_root), "%s/native", temp) > 0);
    assert(snprintf(native_lib, sizeof(native_lib), "%s/libguest.so", native_root) > 0);
    assert(snprintf(outside, sizeof(outside), "%s/outside", temp) > 0);
    assert(snprintf(outside_file, sizeof(outside_file), "%s/secret", outside) > 0);
    assert(snprintf(link_etc, sizeof(link_etc), "%s/etc", root) > 0);
    assert(snprintf(link_native, sizeof(link_native), "%s/libguest.so", system_lib) > 0);
    assert(snprintf(escape_link, sizeof(escape_link), "%s/escape", root) > 0);
    assert(snprintf(parent_link, sizeof(parent_link), "%s/outside-parent", root) > 0);
    assert(snprintf(parent_escape, sizeof(parent_escape), "%s/new-link", parent_link) > 0);
    assert(snprintf(target_escape, sizeof(target_escape), "%s/secret", escape_link) > 0);
    assert(snprintf(sibling, sizeof(sibling), "%s/guest-sibling", temp) > 0);
    assert(snprintf(sibling_link, sizeof(sibling_link), "%s/link", sibling) > 0);
    assert(snprintf(traversal_link, sizeof(traversal_link), "%s/../outside/new-link", root) > 0);

    make_dir(root);
    make_dir(image);
    make_dir(system_dir);
    make_dir(system_etc);
    make_dir(system_lib);
    make_dir(native_root);
    make_dir(outside);
    make_dir(sibling);
    write_file(native_lib, "native guest payload");
    write_file(outside_file, "must remain untouched");

    char mapped_target[PATH_MAX];
    assert(snprintf(mapped_target, sizeof(mapped_target), "%s", system_etc) > 0);
    assert(guest_symlink_create_app_private(mapped_target, link_etc, root, native_root) == 0);
    struct stat st;
    assert(lstat(link_etc, &st) == 0 && S_ISLNK(st.st_mode));
    char actual_target[PATH_MAX];
    ssize_t got = readlink(link_etc, actual_target, sizeof(actual_target) - 1);
    assert(got > 0);
    actual_target[got] = '\0';
    char expected_target[PATH_MAX];
    assert(realpath(system_etc, expected_target) != NULL);
    assert(strcmp(actual_target, expected_target) == 0);
    char resolved_link[PATH_MAX];
    assert(realpath(link_etc, resolved_link) != NULL);
    assert(strcmp(resolved_link, expected_target) == 0);
    assert(guest_symlink_create_app_private(mapped_target, link_etc, root, native_root) == -EEXIST);

    assert(guest_symlink_create_app_private(native_lib, link_native, root, native_root) == 0);
    assert(lstat(link_native, &st) == 0 && S_ISLNK(st.st_mode));
    got = readlink(link_native, actual_target, sizeof(actual_target) - 1);
    assert(got > 0);
    actual_target[got] = '\0';
    assert(strcmp(actual_target, native_lib) == 0);

    assert(symlink(outside, escape_link) == 0);
    assert(symlink(outside, parent_link) == 0);
    assert(guest_symlink_create_app_private(target_escape, link_etc, root, native_root) == -EACCES);
    assert(guest_symlink_create_app_private(system_etc, parent_escape, root, native_root) == -EACCES);
    assert(guest_symlink_create_app_private(outside_file, link_etc, root, native_root) == -EACCES);
    assert(guest_symlink_create_app_private(system_etc, sibling_link, root, native_root) == -EACCES);
    assert(guest_symlink_create_app_private("relative/target", link_etc, root, native_root) == -EACCES);
    assert(guest_symlink_create_app_private("/../outside/secret", link_etc, root, native_root) == -EACCES);
    assert(guest_symlink_create_app_private(system_etc, traversal_link, root, native_root) == -EACCES);

    assert(lstat(outside_file, &st) == 0 && S_ISREG(st.st_mode));
    char should_not_exist[PATH_MAX];
    assert(snprintf(should_not_exist, sizeof(should_not_exist), "%s/new-link", outside) > 0);
    assert(lstat(should_not_exist, &st) != 0 && errno == ENOENT);

    unlink(link_etc);
    unlink(link_native);
    unlink(escape_link);
    unlink(parent_link);
    unlink(native_lib);
    unlink(outside_file);
    rmdir(system_etc);
    rmdir(system_lib);
    rmdir(system_dir);
    rmdir(image);
    rmdir(native_root);
    rmdir(outside);
    rmdir(sibling);
    rmdir(root);
    rmdir(temp);

    puts("app-private guest symlink regression: PASS (guest and native targets remain confined; parent/target escapes and traversal fail closed; symlink creation is descriptor-relative)");
    return 0;
}
