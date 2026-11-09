extern volatile int ginger_copy_value;
int ginger_check_relative_pointer(void);

void _start(void) {
    int status = (ginger_copy_value == 42 && ginger_check_relative_pointer() == 42) ? 0 : 1;
    register int result __asm__("r0") = status;
    register int syscall_number __asm__("r7") = 1;
    __asm__ volatile("svc #0" : "+r"(result) : "r"(syscall_number) : "memory");
    __builtin_unreachable();
}
