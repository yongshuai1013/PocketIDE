extern volatile int ginger_shared_data;
extern int ginger_shared_function(void);

__attribute__((noreturn)) void _start(void) {
    int status = (ginger_shared_data == 41 && ginger_shared_function() == 42) ? 0 : 1;
    register int r0 __asm__("r0") = status;
    register int r7 __asm__("r7") = 1;
    __asm__ volatile("svc #0" : : "r"(r0), "r"(r7) : "memory");
    __builtin_unreachable();
}
