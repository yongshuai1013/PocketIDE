extern volatile int ginger_bionic_shared_data;
extern int ginger_bionic_shared_function(void);

static inline int guest_syscall3(int number, int arg0, int arg1, int arg2) {
    register int r0 __asm__("r0") = arg0;
    register int r1 __asm__("r1") = arg1;
    register int r2 __asm__("r2") = arg2;
    register int r7 __asm__("r7") = number;
    __asm__ volatile("svc #0"
                     : "+r"(r0)
                     : "r"(r1), "r"(r2), "r"(r7)
                     : "memory", "cc");
    return r0;
}

__attribute__((noreturn)) void _start(void) {
    static const char marker[] = "AOSP Bionic loaded DT_NEEDED shared library\n";
    static const char marker_path[] = "/tmp/gingervm-bionic-needed.txt";
    int shared_data = ginger_bionic_shared_data;
    int status = shared_data == 41 ? 0 : 100 + shared_data;
    if (status == 0 && ginger_bionic_shared_function() != 42) {
        status = 12;
    }
    if (status == 0) {
        int fd = guest_syscall3(5, (int)marker_path, 1 | 0x40 | 0x200, 0600);
        if (fd < 0 || guest_syscall3(4, fd, (int)marker, sizeof(marker) - 1) !=
                          (int)(sizeof(marker) - 1)) {
            status = 2;
        }
        if (fd >= 0) {
            guest_syscall3(6, fd, 0, 0);
        }
    }
    guest_syscall3(1, status, 0, 0);
    __builtin_unreachable();
}
