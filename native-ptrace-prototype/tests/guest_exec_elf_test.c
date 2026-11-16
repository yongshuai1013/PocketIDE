#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../app/src/main/cpp/guest_exec_elf.h"

int main(int argc, char **argv) {
    assert(argc == 3);
    char interp[256];
    int rc = guest_elf32_arm_interpreter(argv[1], interp, sizeof(interp));
    assert(rc == 0 && interp[0] == '\0');
    rc = guest_elf32_arm_interpreter(argv[2], interp, sizeof(interp));
    assert(rc == 1);
    assert(strcmp(interp, "/system/bin/linker") == 0);
    uint16_t elf_type = 0;
    uint32_t entry = 0;
    assert(guest_elf32_arm_entrypoint(argv[2], &elf_type, &entry) == 0);
    assert(elf_type == ET_EXEC && entry != 0u);
    puts("guest ELF exec regression: PASS (official /init static; app_process PT_INTERP and bounded executable e_entry metadata verified; no C main inference)");
    return 0;
}
