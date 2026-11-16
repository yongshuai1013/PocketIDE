#include <assert.h>
#include <stdio.h>

#include "../app/src/main/cpp/guest_entry_probe.h"

int main(void) {
    assert(guest_entry_mapping_matches("/guest/system/bin/sh", "/guest/system/bin/sh", "r-xp"));
    assert(guest_entry_mapping_matches("/guest/system/bin/sh (deleted)",
                                       "/guest/system/bin/sh", "r-xp"));
    assert(!guest_entry_mapping_matches("/guest/system/bin/sh", "/guest/system/bin/sh", "rw-p"));
    assert(!guest_entry_mapping_matches("/guest/system/bin/sh", "/guest/system/bin/sh", "r--p"));
    assert(!guest_entry_mapping_matches("/guest/system/bin/shadow", "/guest/system/bin/sh", "r-xp"));
    assert(!guest_entry_mapping_matches("/guest/system/bin/linker", "/guest/system/bin/sh", "r-xp"));
    assert(!guest_entry_mapping_matches("[anon]", "/guest/system/bin/sh", "r-xp"));
    puts("guest target ELF entry mapping regression: PASS (exact executable module only)");
    return 0;
}
