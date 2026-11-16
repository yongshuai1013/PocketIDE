#ifndef GINGERVM_GUEST_EXEC_ELF_H
#define GINGERVM_GUEST_EXEC_ELF_H

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Returns 0 for a static ELF32 ARM executable, 1 for a dynamic ELF32 ARM
 * executable (interpreter copied to out), or a negative errno for invalid or
 * inaccessible input. This only inspects a file; it never executes it. */
static inline int guest_elf32_arm_interpreter(const char *path, char *out, size_t capacity) {
    if (!path || !out || capacity == 0) return -EINVAL;
    out[0] = '\0';
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -errno;

    struct stat st;
    Elf32_Ehdr eh;
    int rc = -ENOEXEC;
    if (fstat(fd, &st) != 0) { rc = -errno; goto done; }
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(eh) ||
        pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) goto done;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS32 || eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_machine != EM_ARM || eh.e_ehsize != sizeof(Elf32_Ehdr) ||
        eh.e_phentsize != sizeof(Elf32_Phdr) || eh.e_phnum == 0 || eh.e_phnum > 128) goto done;
    uint64_t ph_end = (uint64_t)eh.e_phoff + (uint64_t)eh.e_phnum * sizeof(Elf32_Phdr);
    if (ph_end > (uint64_t)st.st_size) goto done;

    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf32_Phdr ph;
        off_t offset = (off_t)eh.e_phoff + (off_t)i * (off_t)sizeof(ph);
        if (pread(fd, &ph, sizeof(ph), offset) != (ssize_t)sizeof(ph)) goto done;
        if (ph.p_type != PT_INTERP) continue;
        if (ph.p_filesz < 2 || ph.p_filesz > capacity ||
            (uint64_t)ph.p_offset + ph.p_filesz > (uint64_t)st.st_size) goto done;
        if (pread(fd, out, ph.p_filesz, (off_t)ph.p_offset) != (ssize_t)ph.p_filesz) {
            out[0] = '\0'; goto done;
        }
        if (out[ph.p_filesz - 1] != '\0' || out[0] != '/') {
            out[0] = '\0'; goto done;
        }
        rc = 1;
        goto done;
    }
    rc = 0;

done:
    close(fd);
    return rc;
}

/* Read entry metadata for a contained, already verified guest payload. This
 * proves only the ELF-declared entry address, not that the tracee reached C main. */
static inline int guest_elf32_arm_entrypoint(const char *path,
                                             uint16_t *out_type,
                                             uint32_t *out_entry) {
    if (!path || !out_type || !out_entry) return -EINVAL;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -errno;
    struct stat st;
    Elf32_Ehdr eh;
    int rc = -ENOEXEC;
    if (fstat(fd, &st) != 0) { rc = -errno; goto done; }
    if (!S_ISREG(st.st_mode) || st.st_size < (off_t)sizeof(eh) ||
        pread(fd, &eh, sizeof(eh), 0) != (ssize_t)sizeof(eh)) goto done;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS32 || eh.e_ident[EI_DATA] != ELFDATA2LSB ||
        eh.e_machine != EM_ARM || eh.e_ehsize != sizeof(Elf32_Ehdr) ||
        (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) ||
        eh.e_phentsize != sizeof(Elf32_Phdr) || eh.e_phnum == 0 || eh.e_phnum > 128)
        goto done;
    uint64_t ph_end = (uint64_t)eh.e_phoff +
        (uint64_t)eh.e_phnum * (uint64_t)sizeof(Elf32_Phdr);
    if (ph_end > (uint64_t)st.st_size) goto done;
    int entry_executable = 0;
    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf32_Phdr ph;
        off_t offset = (off_t)eh.e_phoff + (off_t)i * (off_t)sizeof(ph);
        if (pread(fd, &ph, sizeof(ph), offset) != (ssize_t)sizeof(ph)) goto done;
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X)) continue;
        uint64_t start = ph.p_vaddr;
        uint64_t end = start + ph.p_memsz;
        if (end >= start && eh.e_entry >= start && (uint64_t)eh.e_entry < end)
            entry_executable = 1;
    }
    if (!entry_executable) goto done;
    *out_type = eh.e_type;
    *out_entry = eh.e_entry;
    rc = 0;
done:
    close(fd);
    return rc;
}

#endif
