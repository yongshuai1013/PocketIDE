/*
 * Android 2.3.7-style emulated TLS probe.
 *
 * Clang lowers __thread accesses to __emutls_get_address on this target;
 * Gingerbread Bionic does not use native PT_TLS. This intentionally tiny
 * single-thread helper implements only the compiler-rt control-block ABI
 * needed by this probe. It is not a pthread-capable compiler-rt replacement.
 */
typedef unsigned int u32;

typedef struct {
    u32 size;
    u32 align;
    union {
        u32 index;
        void *address;
    } object;
    void *value;
} emutls_control;

static unsigned char tls_arena[4096] __attribute__((aligned(16)));
static u32 tls_arena_used;

void *__emutls_get_address(emutls_control *control) {
    if (control->object.address != (void *)0) {
        return control->object.address;
    }

    u32 alignment = control->align < 4 ? 4 : control->align;
    if ((alignment & (alignment - 1)) != 0 || alignment > 256) {
        return (void *)0;
    }

    u32 offset = (tls_arena_used + alignment - 1) & ~(alignment - 1);
    if (offset + control->size > sizeof(tls_arena)) {
        return (void *)0;
    }

    unsigned char *destination = &tls_arena[offset];
    const unsigned char *initial_value = (const unsigned char *)control->value;
    for (u32 index = 0; index < control->size; ++index) {
        destination[index] = initial_value ? initial_value[index] : 0;
    }

    tls_arena_used = offset + control->size;
    control->object.address = destination;
    return destination;
}

__thread int initialized = 41;
__thread int zeroed;
__thread unsigned char aligned_tls[16] __attribute__((aligned(16)));

__attribute__((noreturn)) static void finish(int status) {
    register int r0 __asm__("r0") = status;
    register int r7 __asm__("r7") = 1;
    __asm__ volatile("svc #0" : "+r"(r0) : "r"(r7) : "memory");
    __builtin_unreachable();
}

void _start(void) {
    initialized += 1;
    zeroed = initialized + 1;
    aligned_tls[0] = 0x5a;
    __asm__ volatile("" ::: "memory");

    if (initialized == 42 && zeroed == 43 && aligned_tls[0] == 0x5a &&
        (((u32)aligned_tls & 15) == 0)) {
        finish(0);
    }
    finish(1);
}
